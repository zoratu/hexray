//! Stack canary (stack protector) detection.
//!
//! Stack canaries are security features that detect buffer overflows:
//! - A random value is placed between local variables and the return address
//! - The value is checked before function return
//! - If modified (indicating stack corruption), `__stack_chk_fail` is called
//!
//! This module detects stack canary patterns in disassembled code and provides
//! information useful for decompilation (to annotate canary variables).
//!
//! # Platform Patterns
//!
//! ## x86_64 Linux (GCC)
//! ```text
//! mov rax, fs:0x28           ; Load canary from TLS
//! mov [rbp-8], rax           ; Store on stack
//! ...
//! mov rax, [rbp-8]           ; Load from stack
//! xor rax, fs:0x28           ; Compare with TLS (xor sets ZF if equal)
//! jne .fail                  ; If different, fail
//! ...
//! .fail:
//! call __stack_chk_fail
//! ```
//!
//! ## x86_64 macOS
//! ```text
//! mov rax, [rip+___stack_chk_guard]
//! mov [rbp-8], rax
//! ...
//! cmp rax, [rip+___stack_chk_guard]
//! jne .fail
//! ```
//!
//! ## ARM64 (both Linux and macOS)
//! ```text
//! adrp x8, __stack_chk_guard@PAGE
//! ldr x8, [x8, __stack_chk_guard@PAGEOFF]
//! str x8, [sp, #offset]
//! ...
//! ldr x9, [sp, #offset]
//! ldr x8, [x8, __stack_chk_guard@PAGEOFF]  ; or from same register
//! cmp x8, x9
//! b.ne .fail
//! ```

use std::collections::HashMap;

use hexray_core::{
    register::x86, Architecture, BasicBlockId, ControlFlow, ControlFlowGraph, Instruction, Operand,
    Operation,
};

/// Information about detected stack canary protection in a function.
#[derive(Debug, Clone)]
pub struct StackCanaryInfo {
    /// Address of the function containing this canary.
    pub function_addr: u64,
    /// Where the canary value comes from.
    pub canary_source: CanarySource,
    /// Stack offset where the canary is stored (relative to frame pointer).
    pub stack_offset: i64,
    /// Address of the instruction that stores the canary on the stack.
    pub store_addr: u64,
    /// Address of the instruction that loads the canary for checking.
    pub check_load_addr: Option<u64>,
    /// Address of the comparison instruction.
    pub check_compare_addr: Option<u64>,
    /// Address of the conditional branch after comparison.
    pub check_branch_addr: Option<u64>,
    /// Address of `__stack_chk_fail` call if detected.
    pub fail_call_addr: Option<u64>,
    /// Target address of `__stack_chk_fail` if known.
    pub fail_target: Option<u64>,
}

/// Source of the stack canary value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanarySource {
    /// Thread-local storage offset (Linux x86_64: fs:offset).
    TlsOffset {
        /// Segment register used (fs or gs).
        segment: SegmentRegister,
        /// Offset within the segment.
        offset: i64,
    },
    /// Global symbol reference (macOS: ___stack_chk_guard).
    GlobalSymbol {
        /// Name of the global symbol.
        name: String,
        /// Address of the symbol if known.
        address: Option<u64>,
    },
    /// PC-relative address (used for position-independent code).
    PcRelative {
        /// Offset from instruction pointer.
        offset: i64,
        /// Resolved address if known.
        address: Option<u64>,
    },
}

/// Segment registers used for TLS access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentRegister {
    /// FS segment (Linux x86_64 TLS).
    Fs,
    /// GS segment (Windows x86_64 TLS, Linux x86 TLS).
    Gs,
}

impl std::fmt::Display for CanarySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TlsOffset { segment, offset } => {
                let seg_name = match segment {
                    SegmentRegister::Fs => "fs",
                    SegmentRegister::Gs => "gs",
                };
                write!(f, "{}:{:#x}", seg_name, offset)
            }
            Self::GlobalSymbol { name, .. } => write!(f, "{}", name),
            Self::PcRelative {
                address: Some(addr),
                ..
            } => write!(f, "[{:#x}]", addr),
            Self::PcRelative { offset, .. } => write!(f, "[rip+{:#x}]", offset),
        }
    }
}

/// Detector for stack canary patterns in functions.
pub struct StackCanaryDetector {
    /// Architecture of the binary.
    arch: Architecture,
    /// Known `__stack_chk_fail` addresses.
    fail_addresses: Vec<u64>,
    /// Known `__stack_chk_guard` addresses.
    guard_addresses: Vec<u64>,
    /// Symbol name to address mapping.
    symbols: HashMap<String, u64>,
}

impl StackCanaryDetector {
    /// Creates a new stack canary detector.
    pub fn new(arch: Architecture) -> Self {
        Self {
            arch,
            fail_addresses: Vec::new(),
            guard_addresses: Vec::new(),
            symbols: HashMap::new(),
        }
    }

    /// Registers a known `__stack_chk_fail` address.
    pub fn add_fail_address(&mut self, addr: u64) {
        self.fail_addresses.push(addr);
    }

    /// Registers a known `__stack_chk_guard` address.
    pub fn add_guard_address(&mut self, addr: u64) {
        self.guard_addresses.push(addr);
    }

    /// Registers a symbol name to address mapping.
    pub fn add_symbol(&mut self, name: &str, addr: u64) {
        self.symbols.insert(name.to_string(), addr);

        // Auto-detect stack canary related symbols
        if name.contains("__stack_chk_fail") {
            self.fail_addresses.push(addr);
        }
        if name.contains("__stack_chk_guard") || name.contains("___stack_chk_guard") {
            self.guard_addresses.push(addr);
        }
    }

    /// Detects stack canary usage in a control flow graph.
    ///
    /// Returns `Some(StackCanaryInfo)` if a canary pattern is detected.
    pub fn detect(&self, cfg: &ControlFlowGraph) -> Option<StackCanaryInfo> {
        match self.arch {
            Architecture::X86_64 | Architecture::X86 => self.detect_x86(cfg),
            Architecture::Arm64 => self.detect_arm64(cfg),
            _ => None,
        }
    }

    /// Detects x86/x86_64 stack canary patterns.
    fn detect_x86(&self, cfg: &ControlFlowGraph) -> Option<StackCanaryInfo> {
        let entry_block = cfg.entry_block()?;
        let function_addr = entry_block.start;

        // Phase 1: Find canary load and store in prologue
        let (canary_source, store_addr, stack_offset) = self.find_x86_canary_store(cfg)?;

        // Phase 2: Find canary check near function exit(s)
        let check_info = self.find_x86_canary_check(cfg, &canary_source, stack_offset);

        Some(StackCanaryInfo {
            function_addr,
            canary_source,
            stack_offset,
            store_addr,
            check_load_addr: check_info.as_ref().map(|c| c.load_addr),
            check_compare_addr: check_info.as_ref().map(|c| c.compare_addr),
            check_branch_addr: check_info.as_ref().and_then(|c| c.branch_addr),
            fail_call_addr: check_info.as_ref().and_then(|c| c.fail_call_addr),
            fail_target: check_info.and_then(|c| c.fail_target),
        })
    }

    /// Finds the canary store instruction in x86 function prologue.
    fn find_x86_canary_store(&self, cfg: &ControlFlowGraph) -> Option<(CanarySource, u64, i64)> {
        // Check the first few blocks for canary setup
        for block_id in cfg.block_ids().take(3) {
            let block = cfg.block(block_id)?;

            // Look for fs:0x28 access pattern (Linux)
            for (idx, instr) in block.instructions.iter().enumerate() {
                if let Some((source, offset)) = self.check_x86_fs_canary_load(instr) {
                    // Next instruction should be a store to stack
                    if let Some(store_instr) = block.instructions.get(idx + 1) {
                        if let Some(stack_off) = self.check_x86_stack_store(store_instr) {
                            return Some((source, store_instr.address, stack_off));
                        }
                    }
                    // The load and store might be the same instruction for some patterns
                    if let Some(stack_off) = self.check_x86_stack_store(instr) {
                        return Some((
                            CanarySource::TlsOffset {
                                segment: SegmentRegister::Fs,
                                offset,
                            },
                            instr.address,
                            stack_off,
                        ));
                    }
                }

                // Look for ___stack_chk_guard access pattern (macOS / PC-relative)
                if let Some((source, offset)) = self.check_x86_global_canary_load(instr) {
                    // Next instruction should be a store to stack
                    if let Some(store_instr) = block.instructions.get(idx + 1) {
                        if let Some(stack_off) = self.check_x86_stack_store(store_instr) {
                            return Some((source, store_instr.address, stack_off));
                        }
                    }
                    // Return even without finding store - we found the canary load
                    return Some((source, instr.address, offset));
                }
            }
        }

        None
    }

    /// Checks if an instruction loads the canary from TLS (fs:0x28).
    fn check_x86_fs_canary_load(&self, instr: &Instruction) -> Option<(CanarySource, i64)> {
        // Look for MOV reg, fs:0x28 or similar patterns
        if !matches!(instr.operation, Operation::Move | Operation::Load) {
            return None;
        }

        // Check for memory operand with FS segment
        for operand in &instr.operands {
            if let Operand::Memory(mem) = operand {
                if let Some(segment) = &mem.segment {
                    // Check if it's the FS segment register
                    if segment.id == x86::FS {
                        // Common canary offsets
                        let offset = mem.displacement;
                        if offset == 0x28 || offset == 0x14 {
                            return Some((
                                CanarySource::TlsOffset {
                                    segment: SegmentRegister::Fs,
                                    offset,
                                },
                                offset,
                            ));
                        }
                    }
                    // Check for GS segment (Windows)
                    if segment.id == x86::GS {
                        let offset = mem.displacement;
                        return Some((
                            CanarySource::TlsOffset {
                                segment: SegmentRegister::Gs,
                                offset,
                            },
                            offset,
                        ));
                    }
                }
            }
        }

        None
    }

    /// Checks if an instruction loads the canary from a global symbol.
    fn check_x86_global_canary_load(&self, instr: &Instruction) -> Option<(CanarySource, i64)> {
        if !matches!(instr.operation, Operation::Move | Operation::Load) {
            return None;
        }

        for operand in &instr.operands {
            if let Operand::Memory(mem) = operand {
                // Check for RIP-relative addressing (PC-relative)
                if let Some(base) = &mem.base {
                    if base.id == x86::RIP {
                        // This is a RIP-relative access
                        let resolved_addr = instr
                            .address
                            .wrapping_add(instr.size as u64)
                            .wrapping_add(mem.displacement as u64);

                        // Check if this matches a known guard address
                        if self.guard_addresses.contains(&resolved_addr) {
                            return Some((
                                CanarySource::GlobalSymbol {
                                    name: "___stack_chk_guard".to_string(),
                                    address: Some(resolved_addr),
                                },
                                mem.displacement,
                            ));
                        }

                        // Even without knowing the symbol, return PC-relative source
                        return Some((
                            CanarySource::PcRelative {
                                offset: mem.displacement,
                                address: Some(resolved_addr),
                            },
                            mem.displacement,
                        ));
                    }
                }
            }
        }

        None
    }

    /// Checks if an instruction stores a value to the stack.
    fn check_x86_stack_store(&self, instr: &Instruction) -> Option<i64> {
        if !matches!(instr.operation, Operation::Move | Operation::Store) {
            return None;
        }

        // First operand should be memory (destination)
        if let Some(Operand::Memory(mem)) = instr.operands.first() {
            // Check if base is RBP or RSP
            if let Some(base) = &mem.base {
                if base.id == x86::RBP || base.id == x86::RSP {
                    return Some(mem.displacement);
                }
            }
        }

        None
    }

    /// Finds the canary check sequence.
    fn find_x86_canary_check(
        &self,
        cfg: &ControlFlowGraph,
        expected_source: &CanarySource,
        expected_stack_offset: i64,
    ) -> Option<CanaryCheckInfo> {
        // Look through all blocks for the check pattern
        for block in cfg.blocks() {
            let instructions = &block.instructions;

            for (idx, instr) in instructions.iter().enumerate() {
                // Look for XOR or CMP with the canary source
                let is_canary_check =
                    matches!(&instr.operation, Operation::Xor | Operation::Compare);

                if !is_canary_check {
                    continue;
                }

                // Check if this involves the expected source
                let involves_canary =
                    self.instruction_involves_canary_source(instr, expected_source);
                if !involves_canary {
                    // Also check if it involves the stack offset
                    let involves_stack = instr.operands.iter().any(|op| {
                        if let Operand::Memory(mem) = op {
                            if let Some(base) = &mem.base {
                                if (base.id == x86::RBP || base.id == x86::RSP)
                                    && mem.displacement == expected_stack_offset
                                {
                                    return true;
                                }
                            }
                        }
                        false
                    });
                    if !involves_stack {
                        continue;
                    }
                }

                // Found a likely canary check
                let mut check_info = CanaryCheckInfo {
                    load_addr: instr.address,
                    compare_addr: instr.address,
                    branch_addr: None,
                    fail_call_addr: None,
                    fail_target: None,
                };

                // Look for following conditional branch
                for following in instructions.iter().skip(idx + 1).take(3) {
                    if matches!(
                        following.control_flow,
                        ControlFlow::ConditionalBranch { .. }
                    ) {
                        check_info.branch_addr = Some(following.address);

                        // Check if branch target is __stack_chk_fail
                        if let ControlFlow::ConditionalBranch { target, .. } =
                            &following.control_flow
                        {
                            if self.fail_addresses.contains(target) {
                                check_info.fail_call_addr = Some(*target);
                                check_info.fail_target = Some(*target);
                            }
                        }
                        break;
                    }
                }

                // Also check for call to __stack_chk_fail in subsequent blocks
                if check_info.fail_target.is_none() {
                    check_info.fail_target = self.find_fail_call_in_successors(cfg, block.id);
                }

                return Some(check_info);
            }
        }

        None
    }

    /// Checks if an instruction involves the canary source.
    fn instruction_involves_canary_source(
        &self,
        instr: &Instruction,
        source: &CanarySource,
    ) -> bool {
        for operand in &instr.operands {
            match (operand, source) {
                (Operand::Memory(mem), CanarySource::TlsOffset { segment, offset }) => {
                    if let Some(seg_reg) = &mem.segment {
                        let expected_id = match segment {
                            SegmentRegister::Fs => x86::FS,
                            SegmentRegister::Gs => x86::GS,
                        };
                        if seg_reg.id == expected_id && mem.displacement == *offset {
                            return true;
                        }
                    }
                }
                (
                    Operand::Memory(mem),
                    CanarySource::PcRelative {
                        address: Some(addr),
                        ..
                    },
                ) => {
                    if let Some(base) = &mem.base {
                        if base.id == x86::RIP {
                            let resolved = instr
                                .address
                                .wrapping_add(instr.size as u64)
                                .wrapping_add(mem.displacement as u64);
                            if resolved == *addr {
                                return true;
                            }
                        }
                    }
                }
                (
                    Operand::Memory(mem),
                    CanarySource::GlobalSymbol {
                        address: Some(addr),
                        ..
                    },
                ) => {
                    if let Some(base) = &mem.base {
                        if base.id == x86::RIP {
                            let resolved = instr
                                .address
                                .wrapping_add(instr.size as u64)
                                .wrapping_add(mem.displacement as u64);
                            if resolved == *addr {
                                return true;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Looks for __stack_chk_fail call in successor blocks.
    fn find_fail_call_in_successors(
        &self,
        cfg: &ControlFlowGraph,
        start: BasicBlockId,
    ) -> Option<u64> {
        // Check immediate successors
        for succ_id in cfg.successors(start) {
            if let Some(succ_block) = cfg.block(*succ_id) {
                for instr in &succ_block.instructions {
                    if instr.is_call() {
                        if let ControlFlow::Call { target, .. } = &instr.control_flow {
                            if self.fail_addresses.contains(target) {
                                return Some(*target);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Detects ARM64 stack canary patterns.
    fn detect_arm64(&self, cfg: &ControlFlowGraph) -> Option<StackCanaryInfo> {
        let entry_block = cfg.entry_block()?;
        let function_addr = entry_block.start;

        // Phase 1: Find canary load and store in prologue
        let (canary_source, store_addr, stack_offset) = self.find_arm64_canary_store(cfg)?;

        // Phase 2: Find canary check near function exit(s)
        let check_info = self.find_arm64_canary_check(cfg, stack_offset);

        Some(StackCanaryInfo {
            function_addr,
            canary_source,
            stack_offset,
            store_addr,
            check_load_addr: check_info.as_ref().map(|c| c.load_addr),
            check_compare_addr: check_info.as_ref().map(|c| c.compare_addr),
            check_branch_addr: check_info.as_ref().and_then(|c| c.branch_addr),
            fail_call_addr: check_info.as_ref().and_then(|c| c.fail_call_addr),
            fail_target: check_info.and_then(|c| c.fail_target),
        })
    }

    /// Finds the canary store instruction in ARM64 function prologue.
    fn find_arm64_canary_store(&self, cfg: &ControlFlowGraph) -> Option<(CanarySource, u64, i64)> {
        // On ARM64, the pattern is typically:
        // adrp x8, __stack_chk_guard@PAGE
        // ldr x8, [x8, __stack_chk_guard@PAGEOFF]
        // str x8, [sp, #offset]

        for block_id in cfg.block_ids().take(3) {
            let block = cfg.block(block_id)?;

            for (idx, instr) in block.instructions.iter().enumerate() {
                // Look for ADRP instruction (page address load)
                if instr.mnemonic.starts_with("adrp") {
                    // Check following instructions for ldr + str pattern
                    if let Some(ldr_instr) = block.instructions.get(idx + 1) {
                        if ldr_instr.mnemonic.starts_with("ldr") {
                            // Look for str instruction
                            if let Some(str_instr) = block.instructions.get(idx + 2) {
                                if str_instr.mnemonic.starts_with("str") {
                                    if let Some(stack_offset) =
                                        self.get_arm64_stack_offset(str_instr)
                                    {
                                        // Try to get the target address from ADRP
                                        let source = if let Some(target) =
                                            self.get_arm64_adrp_target(instr)
                                        {
                                            if self.guard_addresses.contains(&target) {
                                                CanarySource::GlobalSymbol {
                                                    name: "__stack_chk_guard".to_string(),
                                                    address: Some(target),
                                                }
                                            } else {
                                                CanarySource::PcRelative {
                                                    offset: 0,
                                                    address: Some(target),
                                                }
                                            }
                                        } else {
                                            CanarySource::GlobalSymbol {
                                                name: "__stack_chk_guard".to_string(),
                                                address: None,
                                            }
                                        };

                                        return Some((source, str_instr.address, stack_offset));
                                    }
                                }
                            }
                        }
                    }
                }

                // Also look for direct ldr from guard (if page already set up)
                if instr.mnemonic.starts_with("ldr") {
                    // Check if this could be loading the guard
                    if let Some(str_instr) = block.instructions.get(idx + 1) {
                        if str_instr.mnemonic.starts_with("str") {
                            if let Some(stack_offset) = self.get_arm64_stack_offset(str_instr) {
                                return Some((
                                    CanarySource::GlobalSymbol {
                                        name: "__stack_chk_guard".to_string(),
                                        address: None,
                                    },
                                    str_instr.address,
                                    stack_offset,
                                ));
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Gets the stack offset from an ARM64 store instruction.
    fn get_arm64_stack_offset(&self, instr: &Instruction) -> Option<i64> {
        // Look for str Xn, [sp, #offset] pattern
        if let Some(Operand::Memory(mem)) = instr.operands.get(1) {
            if let Some(base) = &mem.base {
                // SP on ARM64 has id 31
                if base.id == 31 {
                    return Some(mem.displacement);
                }
            }
        }
        None
    }

    /// Gets the target address from an ARM64 ADRP instruction.
    fn get_arm64_adrp_target(&self, instr: &Instruction) -> Option<u64> {
        // ADRP loads a page-aligned address
        if let Some(Operand::Immediate(imm)) = instr.operands.get(1) {
            // ADRP target is PC-relative, page-aligned
            let page = instr.address & !0xFFF;
            let offset = (imm.value as i64) << 12;
            return Some((page as i64 + offset) as u64);
        }

        // Also check PcRelative operand
        if let Some(Operand::PcRelative { target, .. }) = instr.operands.get(1) {
            return Some(*target);
        }

        None
    }

    /// Finds the canary check sequence for ARM64.
    fn find_arm64_canary_check(
        &self,
        cfg: &ControlFlowGraph,
        expected_stack_offset: i64,
    ) -> Option<CanaryCheckInfo> {
        // Look for ldr + cmp + b.ne pattern
        for block in cfg.blocks() {
            let instructions = &block.instructions;

            for (idx, instr) in instructions.iter().enumerate() {
                // Look for cmp instruction
                if !instr.mnemonic.starts_with("cmp") {
                    continue;
                }

                // Check if previous instruction loads from the expected stack offset
                if idx > 0 {
                    if let Some(load_instr) = instructions.get(idx - 1) {
                        if load_instr.mnemonic.starts_with("ldr") {
                            if let Some(offset) = self.get_arm64_stack_offset(load_instr) {
                                if offset == expected_stack_offset {
                                    let mut check_info = CanaryCheckInfo {
                                        load_addr: load_instr.address,
                                        compare_addr: instr.address,
                                        branch_addr: None,
                                        fail_call_addr: None,
                                        fail_target: None,
                                    };

                                    // Look for b.ne following the cmp
                                    for following in instructions.iter().skip(idx + 1).take(3) {
                                        if following.mnemonic.starts_with("b.ne")
                                            || following.mnemonic.starts_with("bne")
                                        {
                                            check_info.branch_addr = Some(following.address);

                                            // Check branch target
                                            if let ControlFlow::ConditionalBranch {
                                                target, ..
                                            } = &following.control_flow
                                            {
                                                if self.fail_addresses.contains(target) {
                                                    check_info.fail_target = Some(*target);
                                                }
                                            }
                                            break;
                                        }
                                    }

                                    // Check successors for fail call
                                    if check_info.fail_target.is_none() {
                                        check_info.fail_target =
                                            self.find_fail_call_in_successors(cfg, block.id);
                                    }

                                    return Some(check_info);
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Checks if a function has stack canary protection.
    ///
    /// This is a fast check that doesn't provide full details.
    pub fn has_canary(&self, cfg: &ControlFlowGraph) -> bool {
        self.detect(cfg).is_some()
    }

    /// Returns the stack offset used for the canary variable.
    ///
    /// This can be used during decompilation to recognize and name
    /// the canary variable appropriately.
    pub fn get_canary_stack_offset(&self, cfg: &ControlFlowGraph) -> Option<i64> {
        self.detect(cfg).map(|info| info.stack_offset)
    }
}

/// Internal structure for canary check information.
#[derive(Debug)]
struct CanaryCheckInfo {
    load_addr: u64,
    compare_addr: u64,
    branch_addr: Option<u64>,
    fail_call_addr: Option<u64>,
    fail_target: Option<u64>,
}

/// Result of analyzing a binary for stack canary usage.
#[derive(Debug, Default)]
pub struct StackCanaryAnalysis {
    /// Functions with detected stack canary protection.
    pub protected_functions: Vec<StackCanaryInfo>,
    /// Address of `__stack_chk_fail` if found.
    pub fail_address: Option<u64>,
    /// Address of `__stack_chk_guard` if found.
    pub guard_address: Option<u64>,
}

impl StackCanaryAnalysis {
    /// Creates a new empty analysis result.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if any functions have stack canary protection.
    pub fn has_protected_functions(&self) -> bool {
        !self.protected_functions.is_empty()
    }

    /// Returns the number of protected functions.
    pub fn protected_count(&self) -> usize {
        self.protected_functions.len()
    }

    /// Checks if a specific function address is protected.
    pub fn is_function_protected(&self, addr: u64) -> bool {
        self.protected_functions
            .iter()
            .any(|f| f.function_addr == addr)
    }

    /// Gets the canary info for a specific function.
    pub fn get_function_info(&self, addr: u64) -> Option<&StackCanaryInfo> {
        self.protected_functions
            .iter()
            .find(|f| f.function_addr == addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::Register;
    use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, MemoryRef, Operand};

    fn make_x86_register(id: u16, size: u16) -> Register {
        Register::new(
            Architecture::X86_64,
            hexray_core::RegisterClass::General,
            id,
            size,
        )
    }

    fn make_fs_register() -> Register {
        Register::new(
            Architecture::X86_64,
            hexray_core::RegisterClass::Segment,
            x86::FS,
            16,
        )
    }

    #[test]
    fn test_canary_source_display() {
        let tls = CanarySource::TlsOffset {
            segment: SegmentRegister::Fs,
            offset: 0x28,
        };
        assert_eq!(format!("{}", tls), "fs:0x28");

        let global = CanarySource::GlobalSymbol {
            name: "___stack_chk_guard".to_string(),
            address: Some(0x1000),
        };
        assert_eq!(format!("{}", global), "___stack_chk_guard");

        let pc_rel = CanarySource::PcRelative {
            offset: 0x100,
            address: Some(0x2000),
        };
        assert_eq!(format!("{}", pc_rel), "[0x2000]");
    }

    #[test]
    fn test_detector_symbol_registration() {
        let mut detector = StackCanaryDetector::new(Architecture::X86_64);

        detector.add_symbol("__stack_chk_fail", 0x1000);
        detector.add_symbol("___stack_chk_guard", 0x2000);

        assert!(detector.fail_addresses.contains(&0x1000));
        assert!(detector.guard_addresses.contains(&0x2000));
    }

    #[test]
    fn test_x86_fs_canary_detection() {
        let detector = StackCanaryDetector::new(Architecture::X86_64);

        // Create instruction: mov rax, fs:0x28
        let fs_reg = make_fs_register();
        let mem_ref = MemoryRef {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x28,
            size: 8,
            segment: Some(fs_reg),
            broadcast: false,
        };

        let mut instr = Instruction::new(
            0x1000,
            7,
            vec![0x64, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00],
            "mov",
        );
        instr.operation = Operation::Move;
        instr.operands = vec![
            Operand::Register(make_x86_register(x86::RAX, 64)),
            Operand::Memory(mem_ref),
        ];

        let result = detector.check_x86_fs_canary_load(&instr);
        assert!(result.is_some());

        let (source, offset) = result.unwrap();
        assert_eq!(offset, 0x28);
        match source {
            CanarySource::TlsOffset {
                segment: SegmentRegister::Fs,
                offset: 0x28,
            } => {}
            _ => panic!("Expected TLS offset source"),
        }
    }

    #[test]
    fn test_x86_stack_store_detection() {
        let detector = StackCanaryDetector::new(Architecture::X86_64);

        // Create instruction: mov [rbp-8], rax
        let mem_ref = MemoryRef {
            base: Some(make_x86_register(x86::RBP, 64)),
            index: None,
            scale: 1,
            displacement: -8,
            size: 8,
            segment: None,
            broadcast: false,
        };

        let mut instr = Instruction::new(0x1007, 4, vec![0x48, 0x89, 0x45, 0xf8], "mov");
        instr.operation = Operation::Move;
        instr.operands = vec![
            Operand::Memory(mem_ref),
            Operand::Register(make_x86_register(x86::RAX, 64)),
        ];

        let result = detector.check_x86_stack_store(&instr);
        assert_eq!(result, Some(-8));
    }

    #[test]
    fn test_stack_canary_analysis() {
        let mut analysis = StackCanaryAnalysis::new();

        assert!(!analysis.has_protected_functions());
        assert_eq!(analysis.protected_count(), 0);

        analysis.protected_functions.push(StackCanaryInfo {
            function_addr: 0x1000,
            canary_source: CanarySource::TlsOffset {
                segment: SegmentRegister::Fs,
                offset: 0x28,
            },
            stack_offset: -8,
            store_addr: 0x1010,
            check_load_addr: Some(0x1050),
            check_compare_addr: Some(0x1054),
            check_branch_addr: Some(0x1058),
            fail_call_addr: Some(0x1060),
            fail_target: Some(0x2000),
        });

        assert!(analysis.has_protected_functions());
        assert_eq!(analysis.protected_count(), 1);
        assert!(analysis.is_function_protected(0x1000));
        assert!(!analysis.is_function_protected(0x2000));

        let info = analysis.get_function_info(0x1000).unwrap();
        assert_eq!(info.stack_offset, -8);
    }

    #[test]
    fn test_full_cfg_detection() {
        let mut detector = StackCanaryDetector::new(Architecture::X86_64);
        detector.add_fail_address(0x3000);

        // Build a simple CFG with canary pattern
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        // Entry block with canary load and store
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        // mov rax, fs:0x28
        let fs_reg = make_fs_register();
        let fs_mem = MemoryRef {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x28,
            size: 8,
            segment: Some(fs_reg),
            broadcast: false,
        };
        let mut load_instr = Instruction::new(0x1000, 7, vec![0; 7], "mov");
        load_instr.operation = Operation::Move;
        load_instr.operands = vec![
            Operand::Register(make_x86_register(x86::RAX, 64)),
            Operand::Memory(fs_mem.clone()),
        ];
        bb0.push_instruction(load_instr);

        // mov [rbp-8], rax
        let stack_mem = MemoryRef {
            base: Some(make_x86_register(x86::RBP, 64)),
            index: None,
            scale: 1,
            displacement: -8,
            size: 8,
            segment: None,
            broadcast: false,
        };
        let mut store_instr = Instruction::new(0x1007, 4, vec![0; 4], "mov");
        store_instr.operation = Operation::Move;
        store_instr.operands = vec![
            Operand::Memory(stack_mem.clone()),
            Operand::Register(make_x86_register(x86::RAX, 64)),
        ];
        bb0.push_instruction(store_instr);

        bb0.terminator = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        // Check block with xor and conditional branch
        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1020);

        // mov rax, [rbp-8]
        let mut reload_instr = Instruction::new(0x1020, 4, vec![0; 4], "mov");
        reload_instr.operation = Operation::Move;
        reload_instr.operands = vec![
            Operand::Register(make_x86_register(x86::RAX, 64)),
            Operand::Memory(stack_mem.clone()),
        ];
        bb1.push_instruction(reload_instr);

        // xor rax, fs:0x28
        let mut xor_instr = Instruction::new(0x1024, 7, vec![0; 7], "xor");
        xor_instr.operation = Operation::Xor;
        xor_instr.operands = vec![
            Operand::Register(make_x86_register(x86::RAX, 64)),
            Operand::Memory(fs_mem),
        ];
        bb1.push_instruction(xor_instr);

        // jne __stack_chk_fail
        let mut jne_instr = Instruction::new(0x102b, 6, vec![0; 6], "jne");
        jne_instr.operation = Operation::ConditionalJump;
        jne_instr.control_flow = ControlFlow::ConditionalBranch {
            target: 0x3000,
            condition: hexray_core::Condition::NotEqual,
            fallthrough: 0x1031,
        };
        bb1.push_instruction(jne_instr);

        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        // Fail block
        let bb2 = BasicBlock::new(BasicBlockId::new(2), 0x3000);
        cfg.add_block(bb2);

        // Normal return block
        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1031);
        let mut ret_instr = Instruction::new(0x1031, 1, vec![0xc3], "ret");
        ret_instr.operation = Operation::Return;
        ret_instr.control_flow = ControlFlow::Return;
        bb3.push_instruction(ret_instr);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        // Add edges
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));

        // Detect canary
        let result = detector.detect(&cfg);
        assert!(result.is_some(), "Should detect canary pattern");

        let info = result.unwrap();
        assert_eq!(info.function_addr, 0x1000);
        assert_eq!(info.stack_offset, -8);
        assert_eq!(info.store_addr, 0x1007);

        match &info.canary_source {
            CanarySource::TlsOffset {
                segment: SegmentRegister::Fs,
                offset: 0x28,
            } => {}
            other => panic!("Unexpected canary source: {:?}", other),
        }

        // Check that canary check was found
        assert!(info.check_compare_addr.is_some());
    }
}
