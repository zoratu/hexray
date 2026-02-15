//! Indirect call resolution analysis.
//!
//! This module provides analysis to resolve indirect calls (calls through registers
//! or memory) to their possible target functions.
//!
//! # Supported Patterns
//!
//! - **GOT/PLT calls**: `call [rip+offset]` resolving to external functions via GOT
//! - **Vtable calls**: `call [rax+offset]` where rax points to a vtable
//! - **Constant propagation**: Following register values to find constant call targets
//! - **Cross-reference analysis**: Finding all writes to the call target location
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::IndirectCallResolver;
//!
//! let resolver = IndirectCallResolver::new()
//!     .with_got_entries(&got_entries)
//!     .with_symbols(&symbols);
//!
//! let results = resolver.analyze(&instructions);
//! for info in results {
//!     println!("Call at {:#x} -> {:?}", info.call_site, info.possible_targets);
//! }
//! ```

use std::collections::{HashMap, HashSet};

use hexray_core::{ControlFlow, IndexMode, Instruction, Operand, Operation, Symbol};

use crate::dataflow::{ConstState, ConstValue, Location};
use crate::xrefs::{XrefDatabase, XrefType};

/// Information about a resolved indirect call.
#[derive(Debug, Clone)]
pub struct IndirectCallInfo {
    /// Address of the call instruction.
    pub call_site: u64,
    /// Possible target addresses of the call.
    pub possible_targets: Vec<u64>,
    /// How the target was resolved.
    pub resolution_method: ResolutionMethod,
    /// Confidence level in the resolution.
    pub confidence: Confidence,
    /// The call target operand (for display/debugging).
    pub target_operand: Option<CallTarget>,
}

impl IndirectCallInfo {
    /// Creates a new unresolved indirect call info.
    pub fn unresolved(call_site: u64, target_operand: Option<CallTarget>) -> Self {
        Self {
            call_site,
            possible_targets: Vec::new(),
            resolution_method: ResolutionMethod::Unknown,
            confidence: Confidence::None,
            target_operand,
        }
    }

    /// Returns true if this call was successfully resolved.
    pub fn is_resolved(&self) -> bool {
        !self.possible_targets.is_empty()
    }

    /// Returns the single resolved target, if exactly one target was found.
    pub fn single_target(&self) -> Option<u64> {
        if self.possible_targets.len() == 1 {
            Some(self.possible_targets[0])
        } else {
            None
        }
    }
}

/// How an indirect call target was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionMethod {
    /// Resolved via Global Offset Table / Procedure Linkage Table.
    GotPlt,
    /// Resolved via vtable analysis.
    Vtable,
    /// Resolved via constant propagation (tracking register values).
    ConstantProp,
    /// Resolved via data flow analysis.
    DataFlow,
    /// Resolved via cross-reference analysis.
    CrossReference,
    /// Multiple resolution methods contributed.
    Combined,
    /// Could not be resolved.
    Unknown,
}

/// Confidence level in the resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// No confidence (unresolved).
    None,
    /// Low confidence (heuristic-based).
    Low,
    /// Medium confidence (dataflow analysis).
    Medium,
    /// High confidence (GOT/PLT or proven constant).
    High,
}

/// Represents the target of an indirect call.
#[derive(Debug, Clone)]
pub enum CallTarget {
    /// Register call: `call rax`
    Register {
        /// Register ID.
        reg_id: u16,
        /// Register name (for display).
        reg_name: String,
    },
    /// Memory call: `call [addr]` or `call [base+offset]`
    Memory {
        /// Base register ID (if any).
        base_reg: Option<u16>,
        /// Index register ID (if any).
        index_reg: Option<u16>,
        /// Scale factor for index.
        scale: u8,
        /// Displacement/offset.
        displacement: i64,
        /// Whether this is PC-relative.
        is_rip_relative: bool,
    },
}

impl CallTarget {
    /// Creates a CallTarget from an instruction's operand.
    pub fn from_instruction(instr: &Instruction) -> Option<Self> {
        // Look for the call target in operands
        for operand in &instr.operands {
            match operand {
                Operand::Register(reg) => {
                    return Some(CallTarget::Register {
                        reg_id: reg.id,
                        reg_name: reg.name().to_string(),
                    });
                }
                Operand::Memory(mem) => {
                    // Check if this is RIP-relative (x86_64)
                    let is_rip_relative = mem
                        .base
                        .as_ref()
                        .map(|r| r.id == 16) // RIP = 16 in x86_64
                        .unwrap_or(false);

                    return Some(CallTarget::Memory {
                        base_reg: mem.base.as_ref().map(|r| r.id),
                        index_reg: mem.index.as_ref().map(|r| r.id),
                        scale: mem.scale,
                        displacement: mem.displacement,
                        is_rip_relative,
                    });
                }
                _ => continue,
            }
        }
        None
    }
}

/// Entry in the Global Offset Table for resolving external calls.
#[derive(Debug, Clone)]
pub struct GotEntry {
    /// Address of the GOT entry.
    pub got_address: u64,
    /// Name of the external symbol.
    pub symbol_name: String,
    /// Address of the actual function (if resolved).
    pub resolved_address: Option<u64>,
}

/// Resolver for indirect calls.
///
/// This struct combines multiple resolution strategies to determine
/// the possible targets of indirect calls.
pub struct IndirectCallResolver {
    /// GOT entries indexed by address.
    got_entries: HashMap<u64, GotEntry>,
    /// Symbol table indexed by address.
    symbols: HashMap<u64, Symbol>,
    /// Symbol table indexed by name.
    symbols_by_name: HashMap<String, u64>,
    /// Known function addresses.
    function_addresses: HashSet<u64>,
    /// Cross-reference database for data flow tracking.
    xrefs: Option<XrefDatabase>,
    /// PLT section address range (start, end).
    plt_range: Option<(u64, u64)>,
    /// GOT section address range (start, end).
    got_range: Option<(u64, u64)>,
}

impl Default for IndirectCallResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl IndirectCallResolver {
    /// Creates a new empty resolver.
    pub fn new() -> Self {
        Self {
            got_entries: HashMap::new(),
            symbols: HashMap::new(),
            symbols_by_name: HashMap::new(),
            function_addresses: HashSet::new(),
            xrefs: None,
            plt_range: None,
            got_range: None,
        }
    }

    /// Adds GOT entries for external function resolution.
    pub fn with_got_entries(mut self, entries: &[GotEntry]) -> Self {
        for entry in entries {
            self.got_entries.insert(entry.got_address, entry.clone());
        }
        self
    }

    /// Adds symbols for target resolution.
    pub fn with_symbols(mut self, symbols: &[Symbol]) -> Self {
        for sym in symbols {
            self.symbols.insert(sym.address, sym.clone());
            if !sym.name.is_empty() {
                self.symbols_by_name.insert(sym.name.clone(), sym.address);
            }
            if sym.is_function() && sym.is_defined() {
                self.function_addresses.insert(sym.address);
            }
        }
        self
    }

    /// Adds known function addresses.
    pub fn with_functions(mut self, addresses: &[u64]) -> Self {
        self.function_addresses.extend(addresses);
        self
    }

    /// Sets the cross-reference database for data flow analysis.
    pub fn with_xrefs(mut self, xrefs: XrefDatabase) -> Self {
        self.xrefs = Some(xrefs);
        self
    }

    /// Sets the PLT section address range.
    pub fn with_plt_range(mut self, start: u64, end: u64) -> Self {
        self.plt_range = Some((start, end));
        self
    }

    /// Sets the GOT section address range.
    pub fn with_got_range(mut self, start: u64, end: u64) -> Self {
        self.got_range = Some((start, end));
        self
    }

    /// Analyzes a sequence of instructions to resolve indirect calls.
    pub fn analyze(&self, instructions: &[Instruction]) -> Vec<IndirectCallInfo> {
        let mut results = Vec::new();

        // Process instructions one by one, building constant state incrementally
        // This ensures we capture the state AT the point of each indirect call
        let mut const_state = ConstState::new();

        for instr in instructions {
            if let ControlFlow::IndirectCall { .. } = &instr.control_flow {
                // Capture state BEFORE processing this call
                let target = CallTarget::from_instruction(instr);
                let mut info = IndirectCallInfo::unresolved(instr.address, target.clone());

                // Try each resolution strategy in order of precision
                if let Some(resolved) = self.try_got_plt_resolution(instr) {
                    info = resolved;
                } else if let Some(resolved) =
                    self.try_constant_prop_resolution(instr, &const_state)
                {
                    info = resolved;
                } else if let Some(resolved) = self.try_vtable_resolution(instr, &const_state) {
                    info = resolved;
                } else if let Some(resolved) = self.try_xref_resolution(instr) {
                    info = resolved;
                }

                // Preserve the target operand info
                if info.target_operand.is_none() {
                    info.target_operand = target;
                }

                results.push(info);
            }

            // Update state AFTER processing the call (for subsequent instructions)
            self.apply_instruction_to_state(instr, &mut const_state);
        }

        results
    }

    /// Analyzes a single indirect call instruction.
    pub fn analyze_single(
        &self,
        instr: &Instruction,
        context: Option<&ConstState>,
    ) -> IndirectCallInfo {
        let target = CallTarget::from_instruction(instr);

        // Try each resolution strategy
        if let Some(resolved) = self.try_got_plt_resolution(instr) {
            return resolved;
        }

        if let Some(state) = context {
            if let Some(resolved) = self.try_constant_prop_resolution(instr, state) {
                return resolved;
            }
            if let Some(resolved) = self.try_vtable_resolution(instr, state) {
                return resolved;
            }
        }

        if let Some(resolved) = self.try_xref_resolution(instr) {
            return resolved;
        }

        IndirectCallInfo::unresolved(instr.address, target)
    }

    /// Tries to resolve an indirect call via GOT/PLT.
    ///
    /// This handles patterns like:
    /// - `call [rip+offset]` -> GOT entry -> external function
    /// - `call [got_address]` -> external function
    fn try_got_plt_resolution(&self, instr: &Instruction) -> Option<IndirectCallInfo> {
        let target = CallTarget::from_instruction(instr)?;

        match target {
            CallTarget::Memory {
                base_reg: Some(16),
                displacement,
                is_rip_relative: true,
                ..
            } => {
                // RIP-relative addressing: effective address = RIP + displacement
                // RIP points to the next instruction
                let effective_addr =
                    (instr.address + instr.size as u64).wrapping_add(displacement as u64);

                // Check if this points into the GOT
                if let Some(entry) = self.got_entries.get(&effective_addr) {
                    let resolved_addr = entry
                        .resolved_address
                        .or_else(|| self.symbols_by_name.get(&entry.symbol_name).copied());

                    return Some(IndirectCallInfo {
                        call_site: instr.address,
                        possible_targets: resolved_addr.into_iter().collect(),
                        resolution_method: ResolutionMethod::GotPlt,
                        confidence: Confidence::High,
                        target_operand: Some(target),
                    });
                }

                // Check if this is in the GOT range
                if let Some((got_start, got_end)) = self.got_range {
                    if effective_addr >= got_start && effective_addr < got_end {
                        // This is a GOT access, but we don't have the entry
                        return Some(IndirectCallInfo {
                            call_site: instr.address,
                            possible_targets: Vec::new(),
                            resolution_method: ResolutionMethod::GotPlt,
                            confidence: Confidence::Low,
                            target_operand: Some(target),
                        });
                    }
                }
            }
            CallTarget::Memory {
                base_reg: None,
                index_reg: None,
                displacement,
                ..
            } => {
                // Absolute address
                let addr = displacement as u64;
                if let Some(entry) = self.got_entries.get(&addr) {
                    let resolved_addr = entry
                        .resolved_address
                        .or_else(|| self.symbols_by_name.get(&entry.symbol_name).copied());

                    return Some(IndirectCallInfo {
                        call_site: instr.address,
                        possible_targets: resolved_addr.into_iter().collect(),
                        resolution_method: ResolutionMethod::GotPlt,
                        confidence: Confidence::High,
                        target_operand: Some(target),
                    });
                }
            }
            _ => {}
        }

        None
    }

    /// Tries to resolve an indirect call via constant propagation.
    ///
    /// This handles patterns like:
    /// - `mov rax, func_addr; call rax`
    /// - `lea rax, [func]; call rax`
    fn try_constant_prop_resolution(
        &self,
        instr: &Instruction,
        state: &ConstState,
    ) -> Option<IndirectCallInfo> {
        let target = CallTarget::from_instruction(instr)?;

        if let CallTarget::Register { reg_id, .. } = target {
            let loc = Location::Register(reg_id);
            if let ConstValue::Constant(addr) = state.get(&loc) {
                let addr = addr as u64;

                // Verify this is a valid function address
                let is_valid = self.function_addresses.contains(&addr)
                    || self.symbols.get(&addr).is_some_and(|s| s.is_function());

                let confidence = if is_valid {
                    Confidence::High
                } else {
                    Confidence::Medium
                };

                return Some(IndirectCallInfo {
                    call_site: instr.address,
                    possible_targets: vec![addr],
                    resolution_method: ResolutionMethod::ConstantProp,
                    confidence,
                    target_operand: Some(target),
                });
            }
        }

        None
    }

    /// Tries to resolve an indirect call via vtable analysis.
    ///
    /// This handles patterns like:
    /// - `mov rax, [rbx]; call [rax+offset]` (vtable call)
    fn try_vtable_resolution(
        &self,
        instr: &Instruction,
        state: &ConstState,
    ) -> Option<IndirectCallInfo> {
        let target = CallTarget::from_instruction(instr)?;

        if let CallTarget::Memory {
            base_reg: Some(base_id),
            displacement,
            is_rip_relative: false,
            ..
        } = target
        {
            let loc = Location::Register(base_id);
            if let ConstValue::Constant(vtable_addr) = state.get(&loc) {
                // Calculate the effective address in the vtable
                let slot_addr = (vtable_addr as u64).wrapping_add(displacement as u64);

                // Look up the function pointer in the symbol table
                if let Some(sym) = self.symbols.get(&slot_addr) {
                    if sym.is_function() {
                        return Some(IndirectCallInfo {
                            call_site: instr.address,
                            possible_targets: vec![sym.address],
                            resolution_method: ResolutionMethod::Vtable,
                            confidence: Confidence::Medium,
                            target_operand: Some(target),
                        });
                    }
                }

                // Even without a symbol, we might know this is a vtable slot
                // Return with low confidence if the offset looks like a vtable
                if displacement >= 0 && displacement % 8 == 0 && displacement < 256 * 8 {
                    return Some(IndirectCallInfo {
                        call_site: instr.address,
                        possible_targets: Vec::new(),
                        resolution_method: ResolutionMethod::Vtable,
                        confidence: Confidence::Low,
                        target_operand: Some(target),
                    });
                }
            }
        }

        None
    }

    /// Tries to resolve an indirect call via cross-reference analysis.
    ///
    /// This looks at all writes to the call target location to find
    /// possible function pointers.
    fn try_xref_resolution(&self, instr: &Instruction) -> Option<IndirectCallInfo> {
        let xrefs = self.xrefs.as_ref()?;
        let target = CallTarget::from_instruction(instr)?;

        if let CallTarget::Memory {
            base_reg: None,
            index_reg: None,
            displacement,
            ..
        } = &target
        {
            // Absolute memory address - find all writes to this location
            let addr = *displacement as u64;
            let writes = xrefs.refs_to(addr);

            let mut targets = Vec::new();
            for xref in writes.iter().filter(|x| x.xref_type == XrefType::DataWrite) {
                // The write's source might be a function address
                if self.function_addresses.contains(&xref.from) {
                    targets.push(xref.from);
                }
            }

            if !targets.is_empty() {
                return Some(IndirectCallInfo {
                    call_site: instr.address,
                    possible_targets: targets,
                    resolution_method: ResolutionMethod::CrossReference,
                    confidence: Confidence::Medium,
                    target_operand: Some(target),
                });
            }
        }

        None
    }

    /// Performs simple constant propagation through an instruction sequence.
    ///
    /// This computes the final constant state after all instructions execute.
    /// For indirect call analysis, use `analyze()` which captures state at each call point.
    pub fn propagate_constants(&self, instructions: &[Instruction]) -> ConstState {
        let mut state = ConstState::new();

        for instr in instructions {
            self.apply_instruction_to_state(instr, &mut state);
        }

        state
    }

    /// Updates constant propagation state based on an instruction.
    fn apply_instruction_to_state(&self, instr: &Instruction, state: &mut ConstState) {
        match instr.operation {
            // Move: dest = src
            Operation::Move => {
                if instr.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&instr.operands[0]) {
                        let src_val = self.evaluate_operand(&instr.operands[1], state);
                        state.set(dest_loc, src_val);
                    }
                }
            }

            // LEA: dest = address
            Operation::LoadEffectiveAddress => {
                if instr.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&instr.operands[0]) {
                        // LEA loads the effective address, not the memory content
                        let src_val = self.evaluate_lea_operand(&instr.operands[1], instr, state);
                        state.set(dest_loc, src_val);
                    }
                }
            }

            // Load: dest = [mem]
            Operation::Load => {
                if instr.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&instr.operands[0]) {
                        // Memory loads are generally not constant
                        state.set(dest_loc, ConstValue::NotConstant);
                    }
                }
            }

            // Binary operations
            Operation::Add
            | Operation::Sub
            | Operation::Mul
            | Operation::And
            | Operation::Or
            | Operation::Xor => {
                if instr.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&instr.operands[0]) {
                        let (left_val, right_val) = if instr.operands.len() >= 3 {
                            (
                                self.evaluate_operand(&instr.operands[1], state),
                                self.evaluate_operand(&instr.operands[2], state),
                            )
                        } else {
                            (
                                self.evaluate_operand(&instr.operands[0], state),
                                self.evaluate_operand(&instr.operands[1], state),
                            )
                        };

                        let result = evaluate_binary_op(instr.operation, left_val, right_val);
                        state.set(dest_loc, result);
                    }
                }
            }

            // Call clobbers return register
            Operation::Call => {
                state.set(Location::Register(0), ConstValue::NotConstant); // rax/x0
            }

            // Other operations conservatively clobber destination
            _ => {
                if !instr.operands.is_empty() {
                    if let Some(dest_loc) = operand_to_location(&instr.operands[0]) {
                        state.set(dest_loc, ConstValue::NotConstant);
                    }
                }
            }
        }
    }

    /// Evaluates an operand to get its constant value.
    fn evaluate_operand(&self, operand: &Operand, state: &ConstState) -> ConstValue {
        match operand {
            Operand::Immediate(imm) => ConstValue::Constant(imm.value),
            Operand::Register(reg) => state.get(&Location::Register(reg.id)),
            Operand::Memory(_) => ConstValue::NotConstant,
            Operand::PcRelative { target, .. } => ConstValue::Constant(*target as i128),
        }
    }

    /// Evaluates an LEA operand to get the effective address.
    fn evaluate_lea_operand(
        &self,
        operand: &Operand,
        instr: &Instruction,
        state: &ConstState,
    ) -> ConstValue {
        match operand {
            Operand::Memory(mem) => {
                // LEA [base + index*scale + disp]
                let mut addr: i128 = mem.displacement as i128;

                // Check for RIP-relative
                if let Some(ref base) = mem.base {
                    if base.id == 16 {
                        // RIP-relative: use next instruction address
                        addr += (instr.address + instr.size as u64) as i128;
                    } else {
                        // Regular base register
                        match state.get(&Location::Register(base.id)) {
                            ConstValue::Constant(v) => addr += v,
                            _ => return ConstValue::NotConstant,
                        }
                    }
                }

                // Add index * scale
                if let Some(ref index) = mem.index {
                    match state.get(&Location::Register(index.id)) {
                        ConstValue::Constant(v) => addr += v * mem.scale as i128,
                        _ => return ConstValue::NotConstant,
                    }
                }

                ConstValue::Constant(addr)
            }
            Operand::PcRelative { target, .. } => ConstValue::Constant(*target as i128),
            _ => ConstValue::NotConstant,
        }
    }
}

/// Converts an operand to a location if it's a register.
fn operand_to_location(operand: &Operand) -> Option<Location> {
    match operand {
        Operand::Register(reg) => Some(Location::Register(reg.id)),
        _ => None,
    }
}

/// Evaluates a binary operation with known operand values.
fn evaluate_binary_op(op: Operation, left: ConstValue, right: ConstValue) -> ConstValue {
    match (left, right) {
        (ConstValue::Constant(l), ConstValue::Constant(r)) => {
            let result = match op {
                Operation::Add => l.wrapping_add(r),
                Operation::Sub => l.wrapping_sub(r),
                Operation::Mul => l.wrapping_mul(r),
                Operation::And => l & r,
                Operation::Or => l | r,
                Operation::Xor => l ^ r,
                _ => return ConstValue::NotConstant,
            };
            ConstValue::Constant(result)
        }
        (ConstValue::Unknown, _) | (_, ConstValue::Unknown) => ConstValue::Unknown,
        _ => ConstValue::NotConstant,
    }
}

/// Builder for GOT entries from ELF relocations.
pub struct GotEntryBuilder {
    entries: Vec<GotEntry>,
}

impl Default for GotEntryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GotEntryBuilder {
    /// Creates a new builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a GOT entry.
    pub fn add_entry(
        &mut self,
        got_address: u64,
        symbol_name: String,
        resolved_address: Option<u64>,
    ) {
        self.entries.push(GotEntry {
            got_address,
            symbol_name,
            resolved_address,
        });
    }

    /// Builds the GOT entry list.
    pub fn build(self) -> Vec<GotEntry> {
        self.entries
    }
}

/// Statistics about indirect call resolution.
#[derive(Debug, Clone, Default)]
pub struct ResolutionStats {
    /// Total number of indirect calls analyzed.
    pub total_calls: usize,
    /// Number of calls resolved via GOT/PLT.
    pub got_plt_resolved: usize,
    /// Number of calls resolved via constant propagation.
    pub const_prop_resolved: usize,
    /// Number of calls resolved via vtable analysis.
    pub vtable_resolved: usize,
    /// Number of calls resolved via cross-references.
    pub xref_resolved: usize,
    /// Number of unresolved calls.
    pub unresolved: usize,
}

impl ResolutionStats {
    /// Computes statistics from a list of resolution results.
    pub fn from_results(results: &[IndirectCallInfo]) -> Self {
        let mut stats = Self {
            total_calls: results.len(),
            ..Self::default()
        };

        for info in results {
            if !info.is_resolved() {
                stats.unresolved += 1;
                continue;
            }

            match info.resolution_method {
                ResolutionMethod::GotPlt => stats.got_plt_resolved += 1,
                ResolutionMethod::ConstantProp => stats.const_prop_resolved += 1,
                ResolutionMethod::Vtable => stats.vtable_resolved += 1,
                ResolutionMethod::CrossReference => stats.xref_resolved += 1,
                _ => stats.unresolved += 1,
            }
        }

        stats
    }

    /// Returns the total number of resolved calls.
    pub fn total_resolved(&self) -> usize {
        self.got_plt_resolved + self.const_prop_resolved + self.vtable_resolved + self.xref_resolved
    }

    /// Returns the resolution rate as a percentage.
    pub fn resolution_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            (self.total_resolved() as f64 / self.total_calls as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{Architecture, Immediate, MemoryRef, Operation, Register, RegisterClass};

    fn make_register(id: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    fn make_indirect_call_reg(addr: u64, reg_id: u16) -> Instruction {
        Instruction {
            address: addr,
            size: 2,
            bytes: vec![0xff, 0xd0 + reg_id as u8],
            operation: Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![Operand::Register(make_register(reg_id))],
            control_flow: ControlFlow::IndirectCall {
                return_addr: addr + 2,
            },
            reads: vec![make_register(reg_id)],
            writes: vec![],
        }
    }

    fn make_indirect_call_mem(addr: u64, base_id: u16, disp: i64) -> Instruction {
        let base_reg = make_register(base_id);
        Instruction {
            address: addr,
            size: 3,
            bytes: vec![0xff, 0x50 + base_id as u8, disp as u8],
            operation: Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![Operand::Memory(MemoryRef {
                base: Some(base_reg),
                index: None,
                scale: 1,
                displacement: disp,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
            })],
            control_flow: ControlFlow::IndirectCall {
                return_addr: addr + 3,
            },
            reads: vec![base_reg],
            writes: vec![],
        }
    }

    fn make_rip_relative_call(addr: u64, disp: i64) -> Instruction {
        let rip_reg = Register::new(Architecture::X86_64, RegisterClass::ProgramCounter, 16, 64);
        Instruction {
            address: addr,
            size: 6,
            bytes: vec![0xff, 0x15, 0, 0, 0, 0], // call [rip+disp]
            operation: Operation::Call,
            mnemonic: "call".to_string(),
            operands: vec![Operand::Memory(MemoryRef {
                base: Some(rip_reg),
                index: None,
                scale: 1,
                displacement: disp,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
            })],
            control_flow: ControlFlow::IndirectCall {
                return_addr: addr + 6,
            },
            reads: vec![],
            writes: vec![],
        }
    }

    fn make_mov_imm(addr: u64, dest_id: u16, imm_value: i128) -> Instruction {
        Instruction {
            address: addr,
            size: 10,
            bytes: vec![0x48, 0xb8], // mov rax, imm64
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(make_register(dest_id)),
                Operand::Immediate(Immediate {
                    value: imm_value,
                    size: 64,
                    signed: false,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![make_register(dest_id)],
        }
    }

    #[test]
    fn test_indirect_call_info_creation() {
        let target = CallTarget::Register {
            reg_id: 0,
            reg_name: "rax".to_string(),
        };
        let info = IndirectCallInfo::unresolved(0x1000, Some(target));

        assert_eq!(info.call_site, 0x1000);
        assert!(info.possible_targets.is_empty());
        assert!(!info.is_resolved());
        assert!(info.single_target().is_none());
    }

    #[test]
    fn test_call_target_from_register_call() {
        let instr = make_indirect_call_reg(0x1000, 0); // call rax
        let target = CallTarget::from_instruction(&instr);

        assert!(target.is_some());
        match target.unwrap() {
            CallTarget::Register { reg_id, .. } => assert_eq!(reg_id, 0),
            _ => panic!("Expected register target"),
        }
    }

    #[test]
    fn test_call_target_from_memory_call() {
        let instr = make_indirect_call_mem(0x1000, 3, 8); // call [rbx+8]
        let target = CallTarget::from_instruction(&instr);

        assert!(target.is_some());
        match target.unwrap() {
            CallTarget::Memory {
                base_reg,
                displacement,
                ..
            } => {
                assert_eq!(base_reg, Some(3));
                assert_eq!(displacement, 8);
            }
            _ => panic!("Expected memory target"),
        }
    }

    #[test]
    fn test_got_plt_resolution() {
        let mut builder = GotEntryBuilder::new();
        builder.add_entry(0x4000, "printf".to_string(), Some(0x7fff1234));

        let resolver = IndirectCallResolver::new().with_got_entries(&builder.build());

        // call [rip+offset] where rip+offset points to GOT
        // addr=0x1000, size=6, so RIP at call = 0x1006
        // We need 0x1006 + disp = 0x4000, so disp = 0x2ffa
        let disp = 0x4000i64 - 0x1006i64;
        let instr = make_rip_relative_call(0x1000, disp);

        let result = resolver.analyze_single(&instr, None);

        assert!(result.is_resolved());
        assert_eq!(result.possible_targets, vec![0x7fff1234]);
        assert_eq!(result.resolution_method, ResolutionMethod::GotPlt);
        assert_eq!(result.confidence, Confidence::High);
    }

    #[test]
    fn test_constant_prop_resolution() {
        let resolver = IndirectCallResolver::new().with_functions(&[0x2000]);

        let instructions = vec![
            make_mov_imm(0x1000, 0, 0x2000),   // mov rax, 0x2000
            make_indirect_call_reg(0x100a, 0), // call rax
        ];

        let results = resolver.analyze(&instructions);

        assert_eq!(results.len(), 1);
        let info = &results[0];
        assert!(info.is_resolved());
        assert_eq!(info.possible_targets, vec![0x2000]);
        assert_eq!(info.resolution_method, ResolutionMethod::ConstantProp);
        assert_eq!(info.confidence, Confidence::High);
    }

    #[test]
    fn test_resolution_stats() {
        let results = vec![
            IndirectCallInfo {
                call_site: 0x1000,
                possible_targets: vec![0x2000],
                resolution_method: ResolutionMethod::GotPlt,
                confidence: Confidence::High,
                target_operand: None,
            },
            IndirectCallInfo {
                call_site: 0x1010,
                possible_targets: vec![0x3000],
                resolution_method: ResolutionMethod::ConstantProp,
                confidence: Confidence::High,
                target_operand: None,
            },
            IndirectCallInfo {
                call_site: 0x1020,
                possible_targets: Vec::new(),
                resolution_method: ResolutionMethod::Unknown,
                confidence: Confidence::None,
                target_operand: None,
            },
        ];

        let stats = ResolutionStats::from_results(&results);

        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.got_plt_resolved, 1);
        assert_eq!(stats.const_prop_resolved, 1);
        assert_eq!(stats.unresolved, 1);
        assert_eq!(stats.total_resolved(), 2);
        assert!((stats.resolution_rate() - 66.67).abs() < 0.1);
    }

    #[test]
    fn test_unresolved_call() {
        let resolver = IndirectCallResolver::new();

        let instr = make_indirect_call_reg(0x1000, 0); // call rax
        let result = resolver.analyze_single(&instr, None);

        assert!(!result.is_resolved());
        assert_eq!(result.resolution_method, ResolutionMethod::Unknown);
        assert_eq!(result.confidence, Confidence::None);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::None < Confidence::Low);
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn test_got_entry_builder() {
        let mut builder = GotEntryBuilder::new();
        builder.add_entry(0x4000, "malloc".to_string(), None);
        builder.add_entry(0x4008, "free".to_string(), Some(0x7fff0000));

        let entries = builder.build();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].got_address, 0x4000);
        assert_eq!(entries[0].symbol_name, "malloc");
        assert!(entries[0].resolved_address.is_none());
        assert_eq!(entries[1].got_address, 0x4008);
        assert_eq!(entries[1].resolved_address, Some(0x7fff0000));
    }

    #[test]
    fn test_vtable_detection() {
        let resolver = IndirectCallResolver::new();

        // call [rax+16] looks like a vtable call
        let instr = make_indirect_call_mem(0x1000, 0, 16);
        let target = CallTarget::from_instruction(&instr);

        match target.as_ref().unwrap() {
            CallTarget::Memory {
                base_reg,
                displacement,
                ..
            } => {
                assert_eq!(*base_reg, Some(0)); // rax
                assert_eq!(*displacement, 16);
            }
            _ => panic!("Expected memory target"),
        }

        // Without vtable info, this should be unresolved
        let result = resolver.analyze_single(&instr, None);
        assert!(!result.is_resolved());
    }
}
