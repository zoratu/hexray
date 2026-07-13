//! Switch statement recovery for the decompiler.
//!
//! This module detects and recovers switch statements from compiled code patterns:
//!
//! 1. **Jump tables**: Compare value, then indirect jump through table
//!    - Common in optimized x86_64/ARM64 code
//!    - Pattern: cmp val, N; ja default; lea table; movsxd offset; jmp [table + offset]
//!
//! 2. **Binary search trees**: Nested if-else comparisons
//!    - Used when values are sparse or jump table would be too large
//!    - Pattern: compare middle value, branch left or right tree
//!
//! 3. **Linear search (if-else chains)**: Sequential comparisons
//!    - Already handled in structurer.rs via `detect_switch_statements`
//!    - This module focuses on the more complex patterns

use hexray_core::{
    BasicBlock, BasicBlockId, BlockTerminator, ControlFlowGraph, Operand, Operation,
};
use std::collections::{HashMap, HashSet};

use super::expression::{BinOpKind, Expr, ExprKind};
use super::structurer::StructuredNode;
use super::BinaryDataContext;

/// Whether a register is the STACK pointer (x86 `rsp`/`esp`/`sp`, aarch64 `sp`). A
/// bounds-check comparison never targets it, so a prologue `sub rsp, K` must not be mistaken
/// for a jump-table bounds check. The frame pointer (`rbp`/`x29`) is deliberately NOT
/// excluded: with the frame pointer omitted it is an ordinary callee-saved register that can
/// legitimately hold the switch index (`cmp ebp, 3; ja default`).
fn is_stack_pointer(name: &str) -> bool {
    matches!(name.to_lowercase().as_str(), "rsp" | "esp" | "sp")
}

/// Information about a detected switch statement.
#[derive(Debug, Clone)]
pub struct SwitchInfo {
    /// The expression being switched on.
    pub switch_value: Expr,
    /// Mapping of case values to target block IDs.
    pub cases: Vec<(Vec<i128>, BasicBlockId)>,
    /// Default case block ID.
    pub default: Option<BasicBlockId>,
    /// The kind of switch detected.
    pub kind: SwitchKind,
}

/// The type of switch pattern detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchKind {
    /// Jump table: indirect jump through address table.
    JumpTable,
    /// Binary search tree: nested comparisons.
    BinarySearch,
    /// Linear if-else chain (handled elsewhere).
    IfElseChain,
}

/// Jump table information extracted from binary analysis.
#[derive(Debug, Clone)]
pub struct JumpTableInfo {
    /// Base address of the jump table.
    pub table_base: u64,
    /// Size of each entry in bytes (typically 4 for relative offsets).
    pub entry_size: u8,
    /// Number of entries in the table.
    pub entry_count: u32,
    /// Whether entries are relative offsets or absolute addresses.
    pub is_relative: bool,
    /// Minimum case value (the switch value is compared against this).
    pub min_value: i64,
    /// Maximum case value.
    pub max_value: i64,
}

/// Switch statement recovery analyzer.
pub struct SwitchRecovery<'a> {
    cfg: &'a ControlFlowGraph,
    /// Binary data for reading jump tables (optional, legacy single-section).
    binary_data: Option<&'a [u8]>,
    /// Base address of the binary data section (legacy single-section).
    data_base: u64,
    /// Binary data context for multi-section lookup (preferred).
    binary_ctx: Option<&'a BinaryDataContext>,
}

impl<'a> SwitchRecovery<'a> {
    /// Creates a new switch recovery analyzer.
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            binary_data: None,
            data_base: 0,
            binary_ctx: None,
        }
    }

    /// Sets the binary data for jump table reading (single section, legacy API).
    pub fn with_binary_data(mut self, data: &'a [u8], base: u64) -> Self {
        self.binary_data = Some(data);
        self.data_base = base;
        self
    }

    /// Sets the binary data context for jump table reading (multi-section, preferred).
    pub fn with_binary_context(mut self, ctx: &'a BinaryDataContext) -> Self {
        self.binary_ctx = Some(ctx);
        self
    }

    /// Attempts to recover a switch statement starting from the given block.
    ///
    /// This analyzes the block's terminator and preceding instructions to detect
    /// switch patterns like jump tables or binary search trees.
    pub fn try_recover_switch(&self, block_id: BasicBlockId) -> Option<SwitchInfo> {
        let block = self.cfg.block(block_id)?;

        // First, try to detect a jump table pattern
        if let Some(switch_info) = self.try_detect_jump_table(block) {
            return Some(switch_info);
        }

        // Next, try to detect a binary search pattern
        if let Some(switch_info) = self.try_detect_binary_search(block_id) {
            return Some(switch_info);
        }

        None
    }

    /// Recover a jump-table switch ONLY when its entries were actually read from binary
    /// data — never the deduplicated `possible_targets` fallback used by
    /// [`Self::try_recover_switch`]. The fallback collapses duplicate table entries (states
    /// sharing a resume block) into unique targets with sequential labels, dropping states;
    /// callers that must not mislabel states (e.g. coroutine resume-dispatch recovery) use
    /// this to require the complete, correctly-grouped case labels.
    ///
    /// When the table is explicitly BOUNDED (a real `cmp idx, N; ja default` bounds check
    /// sized it), every one of its `N+1` entries must map to a block: if `read_jump_table`
    /// dropped any (e.g. a target with no CFG block), the read is incomplete and would
    /// silently omit a state, so this returns `None` rather than a truncated switch.
    pub fn try_recover_switch_read_from_binary(&self, block_id: BasicBlockId) -> Option<SwitchInfo> {
        let block = self.cfg.block(block_id)?;
        if !matches!(block.terminator, BlockTerminator::IndirectJump { .. }) {
            return None;
        }
        let (switch_var, bound_check, table_info, bounds_checked) =
            self.analyze_jump_table_block(block)?;
        let cases = self.read_jump_table(&table_info)?;
        // A REAL bounds check pins the exact entry count, so require all of those entries to
        // have mapped — no bounded state may be silently dropped. (Keyed off the actual
        // presence of a `cmp`/`sub`, NOT `entry_count < 256`: a genuine `cmp idx, 255` also
        // sizes 256 entries yet must still be checked.) Without a bounds check the entry count
        // is an over-approximation — trailing garbage entries legitimately drop out — so
        // completeness is instead the caller's dense-`0..N-1` contiguity requirement.
        if bounds_checked {
            let mapped: usize = cases.iter().map(|(values, _)| values.len()).sum();
            if mapped != table_info.entry_count as usize {
                return None;
            }
        }
        Some(SwitchInfo {
            switch_value: switch_var,
            cases,
            default: bound_check.map(|(_, default)| default),
            kind: SwitchKind::JumpTable,
        })
    }

    /// Detects a jump table switch pattern.
    ///
    /// Jump table pattern (x86_64):
    /// ```text
    /// cmp eax, N          ; Check upper bound
    /// ja default_case     ; Jump to default if out of range
    /// lea rcx, [rip+table]; Load table base address
    /// movsxd rax, [rcx+rax*4] ; Load relative offset from table
    /// add rax, rcx        ; Compute absolute address
    /// jmp rax             ; Indirect jump to case
    /// ```
    ///
    /// ARM64 pattern:
    /// ```text
    /// cmp w0, #N          ; Check upper bound
    /// b.hi default_case   ; Branch to default if out of range
    /// adrp x1, table      ; Load table page address
    /// add x1, x1, :lo12:table ; Add page offset
    /// ldrb w0, [x1, w0, uxtw] ; Load offset from table
    /// adr x2, base        ; Load base address
    /// add x0, x2, w0, sxtb ; Compute target address
    /// br x0               ; Indirect branch
    /// ```
    fn try_detect_jump_table(&self, block: &BasicBlock) -> Option<SwitchInfo> {
        // Look for an indirect jump terminator
        let (_target_operand, possible_targets) = match &block.terminator {
            BlockTerminator::IndirectJump {
                target,
                possible_targets,
            } => (target, possible_targets),
            _ => return None,
        };

        // Analyze the block to find the comparison and table access pattern
        let (switch_var, bound_check, table_info, _bounds_checked) =
            self.analyze_jump_table_block(block)?;

        // Try to read actual case values from the jump table (requires binary data).
        // This gives us the correct case values instead of just sequential indices.
        let cases = if let Some(cases) = self.read_jump_table(&table_info) {
            cases
        } else if !possible_targets.is_empty() {
            // Fall back to using possible targets with sequential indices.
            // This happens when binary data isn't available.
            possible_targets
                .iter()
                .enumerate()
                .map(|(i, &target)| {
                    let value = table_info.min_value + i as i64;
                    (vec![value as i128], target)
                })
                .collect()
        } else {
            return None;
        };

        Some(SwitchInfo {
            switch_value: switch_var,
            cases,
            default: bound_check.map(|(_, default)| default),
            kind: SwitchKind::JumpTable,
        })
    }

    /// Analyzes a block to extract jump table information.
    ///
    /// Returns (switch_variable, (max_value, default_block), jump_table_info, bounds_checked).
    /// `bounds_checked` is true only when a real `cmp`/`sub` bounds check sized the table (the
    /// returned `(max_value, default_block)` otherwise falls back to a 255/entry-0 default).
    #[allow(clippy::type_complexity)]
    fn analyze_jump_table_block(
        &self,
        block: &BasicBlock,
    ) -> Option<(Expr, Option<(i64, BasicBlockId)>, JumpTableInfo, bool)> {
        let mut switch_var: Option<Expr> = None;
        let mut bound_check: Option<(i64, BasicBlockId)> = None;
        let mut table_base: Option<u64> = None;
        let mut entry_size: u8 = 4; // Default to 4-byte entries
        let mut is_relative = true;

        // Helper function to scan a block for patterns
        // We scan in reverse to find the comparison closest to the branch (the actual bounds check)
        let scan_block = |block: &BasicBlock,
                          switch_var: &mut Option<Expr>,
                          bound_check: &mut Option<(i64, BasicBlockId)>,
                          table_base: &mut Option<u64>,
                          entry_size: &mut u8,
                          is_relative: &mut bool| {
            // First pass (forward): find table base and entry size
            for inst in &block.instructions {
                match inst.operation {
                    // Look for LEA (table base address)
                    Operation::LoadEffectiveAddress => {
                        if inst.operands.len() >= 2 {
                            match &inst.operands[1] {
                                Operand::PcRelative { target, .. } => {
                                    *table_base = Some(*target);
                                    *is_relative = true;
                                }
                                // Also handle memory operand with PC-relative base
                                Operand::Memory(mem) => {
                                    if let Some(ref base_reg) = mem.base {
                                        // Check if base is the program counter (RIP on x86_64)
                                        if base_reg.name().to_lowercase() == "rip"
                                            || base_reg.id == 16
                                        {
                                            // Calculate absolute address from instruction address + displacement
                                            let inst_end = inst.address + inst.bytes.len() as u64;
                                            let target =
                                                inst_end.wrapping_add(mem.displacement as u64);
                                            *table_base = Some(target);
                                            *is_relative = true;
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }

                    // Look for load with scaled index (table access)
                    Operation::Load | Operation::Move => {
                        if let Some(Operand::Memory(mem)) = inst.operands.get(1) {
                            if mem.index.is_some() && mem.scale > 1 {
                                *entry_size = mem.scale;
                            }
                            if table_base.is_none() {
                                if let Some(base) = Self::extract_absolute_table_base(mem) {
                                    *table_base = Some(base);
                                    *is_relative = false;
                                }
                            }
                        }
                    }

                    _ => {}
                }
            }

            // Second pass (reverse): find the bounds check comparison closest to terminator
            // This avoids picking up stack frame setup instructions like "sub $0x10, %rsp"
            let mut cmp_register_name: Option<String> = None;
            let mut cmp_operand: Option<Operand> = None;

            for inst in block.instructions.iter().rev() {
                match inst.operation {
                    // Look for comparison (bounds check) - but only if we don't have one yet
                    Operation::Compare | Operation::Sub => {
                        // A bounds check compares the SWITCH VALUE; a prologue `sub rsp, K`
                        // is NOT one, even though its immediate is small — exclude ops on the
                        // stack pointer so they aren't mistaken for a bound. (The frame
                        // pointer is left in play: it can be a general-purpose index register.)
                        let on_stack_ptr = matches!(
                            inst.operands.first(),
                            Some(Operand::Register(reg)) if is_stack_pointer(reg.name())
                        );
                        if bound_check.is_none() && !on_stack_ptr && inst.operands.len() >= 2 {
                            // Check if second operand is an immediate that looks like a small switch bound
                            // (large values like stack frame size should be ignored)
                            if let Operand::Immediate(imm) = &inst.operands[1] {
                                let value = imm.value as i64;
                                // Reasonable switch bounds are typically < 256
                                // Stack frame sizes are often multiples of 8 or 16 (like 0x10, 0x20, etc)
                                if (0..256).contains(&value) {
                                    *bound_check = Some((value, BasicBlockId::new(0)));
                                    cmp_operand = inst.operands.first().cloned();
                                    // Remember which register is being compared
                                    if let Operand::Register(reg) = &inst.operands[0] {
                                        cmp_register_name = Some(reg.name().to_string());
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }

            // If we found a comparison, try to trace back to find the actual switch value
            // Look for a load/move that defines the comparison register
            if let Some(ref reg_name) = cmp_register_name {
                // Scan forward through instructions to find the definition of the comparison register
                for inst in &block.instructions {
                    match inst.operation {
                        Operation::Load | Operation::Move => {
                            // Check if this instruction defines the comparison register
                            if let Some(Operand::Register(dst)) = inst.operands.first() {
                                let dst_name = dst.name().to_string();
                                // Check if this defines our register (handle eax/rax aliasing)
                                if dst_name == *reg_name
                                    || (dst_name == "eax" && reg_name == "rax")
                                    || (dst_name == "rax" && reg_name == "eax")
                                {
                                    // Found the definition - use the source as switch value
                                    if let Some(src) = inst.operands.get(1) {
                                        *switch_var = Some(Expr::from_operand(src));
                                        break;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }

                // If we still don't have a switch_var, use the register directly
                // but try to make it a named argument if it's a calling convention register
                if switch_var.is_none() {
                    let var_name = match reg_name.as_str() {
                        "edi" | "rdi" => "arg0".to_string(),
                        "esi" | "rsi" => "arg1".to_string(),
                        "edx" | "rdx" => "arg2".to_string(),
                        "ecx" | "rcx" => "arg3".to_string(),
                        "r8d" | "r8" => "arg4".to_string(),
                        "r9d" | "r9" => "arg5".to_string(),
                        // ARM64 registers
                        "w0" | "x0" => "arg0".to_string(),
                        "w1" | "x1" => "arg1".to_string(),
                        _ => reg_name.clone(),
                    };
                    *switch_var = Some(Expr::var(super::expression::Variable {
                        name: var_name,
                        kind: super::expression::VarKind::Temp(0),
                        size: 4,
                    }));
                }
            } else if switch_var.is_none() {
                if let Some(operand) = cmp_operand.as_ref() {
                    *switch_var = Some(Expr::from_operand(operand));
                }
            }
        };

        // Scan the current block
        scan_block(
            block,
            &mut switch_var,
            &mut bound_check,
            &mut table_base,
            &mut entry_size,
            &mut is_relative,
        );

        // If we didn't find a bounds check, look at predecessor blocks
        // The common pattern is: predecessor has bounds check, this block has the jump
        if bound_check.is_none() {
            let preds = self.cfg.predecessors(block.id);
            for &pred_id in preds {
                if let Some(pred_block) = self.cfg.block(pred_id) {
                    scan_block(
                        pred_block,
                        &mut switch_var,
                        &mut bound_check,
                        &mut table_base,
                        &mut entry_size,
                        &mut is_relative,
                    );
                    if bound_check.is_some() {
                        // Check if predecessor has conditional branch - default is the other target
                        if let BlockTerminator::ConditionalBranch {
                            true_target,
                            false_target,
                            ..
                        } = &pred_block.terminator
                        {
                            // The default block is the one that's NOT the indirect jump block
                            let default_target = if *true_target == block.id {
                                *false_target
                            } else {
                                *true_target
                            };
                            if let Some((max_val, _)) = bound_check {
                                bound_check = Some((max_val, default_target));
                            }
                        }
                        break;
                    }
                }
            }
        }

        // We need at least the table base to proceed
        let table_base = table_base?;

        // Construct jump table info
        let bounds_checked = bound_check.is_some();
        let (max_value, default_block) = bound_check.unwrap_or((255, BasicBlockId::new(0)));
        let table_info = JumpTableInfo {
            table_base,
            entry_size,
            entry_count: (max_value + 1) as u32,
            is_relative,
            min_value: 0,
            max_value,
        };

        // If we found bounds check but not switch_var, create a generic one
        let switch_var = switch_var.unwrap_or_else(|| {
            Expr::var(super::expression::Variable {
                name: "val".to_string(),
                kind: super::expression::VarKind::Temp(0),
                size: 4,
            })
        });

        Some((
            switch_var,
            Some((max_value, default_block)),
            table_info,
            bounds_checked,
        ))
    }

    fn extract_absolute_table_base(mem: &hexray_core::MemoryRef) -> Option<u64> {
        if mem.base.is_none()
            && mem.index.is_some()
            && mem.displacement > 0x1000
            && mem.displacement < i64::MAX
        {
            Some(mem.displacement as u64)
        } else {
            None
        }
    }

    /// Reads case targets from a jump table in binary data.
    fn read_jump_table(&self, info: &JumpTableInfo) -> Option<Vec<(Vec<i128>, BasicBlockId)>> {
        // Get the data slice and base address - try binary_ctx first, then legacy method
        let (data, data_base) = if let Some(ctx) = self.binary_ctx {
            ctx.section_containing(info.table_base)?
        } else if let Some(data) = self.binary_data {
            (data, self.data_base)
        } else {
            return None;
        };

        // Calculate offset into data
        if info.table_base < data_base {
            return None;
        }
        let offset = (info.table_base - data_base) as usize;

        if offset >= data.len() {
            return None;
        }

        let mut cases = Vec::new();
        let mut target_to_values: HashMap<u64, Vec<i128>> = HashMap::new();

        for i in 0..info.entry_count {
            let entry_offset = offset + (i as usize * info.entry_size as usize);
            if entry_offset + (info.entry_size as usize) > data.len() {
                break;
            }

            // Read entry based on size and type
            let target = match (info.entry_size, info.is_relative) {
                (4, true) => {
                    // 4-byte relative offset
                    let bytes = &data[entry_offset..entry_offset + 4];
                    let rel_offset = i32::from_le_bytes(bytes.try_into().ok()?);
                    info.table_base.wrapping_add(rel_offset as u64)
                }
                (4, false) => {
                    // 4-byte absolute address
                    let bytes = &data[entry_offset..entry_offset + 4];
                    u32::from_le_bytes(bytes.try_into().ok()?) as u64
                }
                (8, false) => {
                    // 8-byte absolute address
                    let bytes = &data[entry_offset..entry_offset + 8];
                    u64::from_le_bytes(bytes.try_into().ok()?)
                }
                (1, true) => {
                    // 1-byte relative offset (compact table)
                    let rel_offset = data[entry_offset] as i8;
                    info.table_base.wrapping_add(rel_offset as u64)
                }
                _ => continue,
            };

            let case_value = info.min_value + i as i64;
            target_to_values
                .entry(target)
                .or_default()
                .push(case_value as i128);
        }

        // Convert to case list, grouping values with same target
        // We need to map addresses to BasicBlockIds, which requires CFG info
        // For now, create synthetic block IDs based on target addresses
        for (target_addr, values) in target_to_values {
            // Try to find the block containing this address
            if let Some(block) = self.cfg.block_containing(target_addr) {
                cases.push((values, block.id));
            }
        }

        if cases.is_empty() {
            None
        } else {
            Some(cases)
        }
    }

    /// Detects a binary search switch pattern.
    ///
    /// Binary search pattern:
    /// ```text
    /// if (x < mid) {
    ///     if (x < left_mid) {
    ///         case_a...
    ///     } else {
    ///         case_b...
    ///     }
    /// } else {
    ///     if (x < right_mid) {
    ///         case_c...
    ///     } else {
    ///         case_d...
    ///     }
    /// }
    /// ```
    ///
    /// This creates a balanced tree of comparisons on the same variable.
    fn try_detect_binary_search(&self, start_block: BasicBlockId) -> Option<SwitchInfo> {
        let mut cases: Vec<(i128, BasicBlockId)> = Vec::new();
        let mut default_block: Option<BasicBlockId> = None;

        // Collect all comparison blocks and their relationships
        let comparisons = self.collect_comparisons(start_block, &mut HashSet::new())?;

        if comparisons.is_empty() {
            return None;
        }

        // All comparisons must be on the same variable
        let first_var_key = comparisons.first().map(|c| &c.var_key)?;
        if !comparisons.iter().all(|c| &c.var_key == first_var_key) {
            return None;
        }

        // Need at least 2 comparisons for binary search pattern
        if comparisons.len() < 2 {
            return None;
        }

        let switch_var = comparisons.first().map(|c| c.var_expr.clone());

        // Extract case values and targets from the comparison tree
        for cmp in &comparisons {
            match cmp.comparison {
                ComparisonType::Equal(val) => {
                    cases.push((val, cmp.true_target));
                }
                ComparisonType::Less(_) | ComparisonType::LessOrEqual(_) => {
                    // These are pivot comparisons in binary search
                    // The actual cases come from the leaf nodes (Equal comparisons)
                }
                ComparisonType::Greater(_) | ComparisonType::GreaterOrEqual(_) => {
                    // Similar to Less - these are pivot comparisons
                }
            }

            // Check for default block (the fallthrough when no case matches)
            if cmp.false_target != BasicBlockId::new(0) {
                default_block = Some(cmp.false_target);
            }
        }

        // Only detect as switch if we have enough equality comparisons
        if cases.len() < 2 {
            return None;
        }

        // Sort cases by value
        cases.sort_by_key(|(val, _)| *val);

        // Convert to switch info format
        let switch_cases = cases
            .into_iter()
            .map(|(val, target)| (vec![val], target))
            .collect();

        Some(SwitchInfo {
            switch_value: switch_var?,
            cases: switch_cases,
            default: default_block,
            kind: SwitchKind::BinarySearch,
        })
    }

    /// Collects all comparison nodes in a potential binary search tree.
    fn collect_comparisons(
        &self,
        block_id: BasicBlockId,
        visited: &mut HashSet<BasicBlockId>,
    ) -> Option<Vec<ComparisonInfo>> {
        if visited.contains(&block_id) {
            return Some(Vec::new());
        }
        visited.insert(block_id);

        let block = self.cfg.block(block_id)?;

        // Check for conditional branch
        let (condition, true_target, false_target) = match &block.terminator {
            BlockTerminator::ConditionalBranch {
                condition,
                true_target,
                false_target,
            } => (condition, *true_target, *false_target),
            _ => return Some(Vec::new()), // Not a comparison block
        };

        // Extract comparison info from the block
        let cmp_info = self.extract_comparison(block, *condition, true_target, false_target)?;

        let mut result = vec![cmp_info];

        // Recursively collect from both branches
        if let Some(mut true_cmps) = self.collect_comparisons(true_target, visited) {
            result.append(&mut true_cmps);
        }
        if let Some(mut false_cmps) = self.collect_comparisons(false_target, visited) {
            result.append(&mut false_cmps);
        }

        Some(result)
    }

    /// Extracts comparison information from a block.
    fn extract_comparison(
        &self,
        block: &BasicBlock,
        condition: hexray_core::Condition,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
    ) -> Option<ComparisonInfo> {
        use hexray_core::Condition;

        // Find the compare instruction
        let cmp_inst = block.instructions.iter().rev().find(|inst| {
            matches!(
                inst.operation,
                Operation::Compare | Operation::Test | Operation::Sub
            )
        })?;

        if cmp_inst.operands.len() < 2 {
            return None;
        }

        let left = Expr::from_operand(&cmp_inst.operands[0]);
        let right = &cmp_inst.operands[1];

        // Get the value being compared
        let compare_value = match right {
            Operand::Immediate(imm) => imm.value,
            _ => return None, // Only handle comparisons against constants
        };

        // Get variable key for grouping
        let var_key = get_expr_var_key(&left)?;

        // Determine comparison type based on condition
        let comparison = match condition {
            Condition::Equal => ComparisonType::Equal(compare_value),
            Condition::Less => ComparisonType::Less(compare_value),
            Condition::LessOrEqual => ComparisonType::LessOrEqual(compare_value),
            Condition::Greater => ComparisonType::Greater(compare_value),
            Condition::GreaterOrEqual => ComparisonType::GreaterOrEqual(compare_value),
            Condition::Below => ComparisonType::Less(compare_value), // Unsigned
            Condition::BelowOrEqual => ComparisonType::LessOrEqual(compare_value),
            Condition::Above => ComparisonType::Greater(compare_value),
            Condition::AboveOrEqual => ComparisonType::GreaterOrEqual(compare_value),
            _ => return None,
        };

        Some(ComparisonInfo {
            var_key,
            var_expr: left,
            comparison,
            true_target,
            false_target,
        })
    }
}

/// Information about a comparison in a binary search tree.
#[derive(Debug, Clone)]
struct ComparisonInfo {
    /// Variable key for grouping.
    var_key: String,
    /// The expression being compared.
    var_expr: Expr,
    /// The type of comparison.
    comparison: ComparisonType,
    /// Target when comparison is true.
    true_target: BasicBlockId,
    /// Target when comparison is false.
    false_target: BasicBlockId,
}

/// Types of comparisons in a switch pattern.
/// The comparison values are stored for future use in range-based case detection.
/// Currently only Equal values are extracted; other comparison values are tracked
/// for future support of range-based switch cases (e.g., case 1..5:).
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // Inner values tracked for future range-case support
enum ComparisonType {
    Equal(i128),
    Less(i128),
    LessOrEqual(i128),
    Greater(i128),
    GreaterOrEqual(i128),
}

/// Get a unique key for a variable expression (for grouping comparisons).
fn get_expr_var_key(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        ExprKind::Deref { addr, .. } => {
            // Stack variable pattern
            get_stack_slot_key(addr)
        }
        _ => None,
    }
}

/// Extract a key for a stack slot address.
fn get_stack_slot_key(addr: &Expr) -> Option<String> {
    match &addr.kind {
        ExprKind::Var(var) => {
            if is_frame_register(&var.name) {
                Some("stack_0".to_string())
            } else {
                None
            }
        }
        ExprKind::BinOp { op, left, right } => {
            if let ExprKind::Var(base) = &left.kind {
                if is_frame_register(&base.name) {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        let actual_offset = match op {
                            BinOpKind::Add => *offset,
                            BinOpKind::Sub => -*offset,
                            _ => return None,
                        };
                        return Some(format!("stack_{}", actual_offset));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if a register is a frame/stack pointer.
fn is_frame_register(name: &str) -> bool {
    matches!(
        name,
        "rbp" | "ebp" | "bp" | "sp" | "rsp" | "esp" | "x29" | "fp"
    )
}

/// Converts a SwitchInfo to a StructuredNode::Switch.
#[allow(dead_code)]
pub fn switch_info_to_node(
    switch_info: SwitchInfo,
    _cfg: &ControlFlowGraph,
    structure_region: impl Fn(BasicBlockId) -> Vec<StructuredNode>,
) -> StructuredNode {
    let cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = switch_info
        .cases
        .into_iter()
        .map(|(values, target)| {
            let body = structure_region(target);
            (values, body)
        })
        .collect();

    let default = switch_info.default.map(structure_region);

    StructuredNode::Switch {
        value: switch_info.switch_value,
        cases,
        default,
    }
}

/// Analyzes a CFG to find all potential switch statements.
///
/// This is called during the structuring phase to identify blocks
/// that should be treated as switch statements rather than if-else chains.
#[allow(dead_code)]
pub fn find_switch_candidates(cfg: &ControlFlowGraph) -> Vec<(BasicBlockId, SwitchInfo)> {
    let recovery = SwitchRecovery::new(cfg);
    let mut candidates = Vec::new();

    for block_id in cfg.block_ids() {
        if let Some(switch_info) = recovery.try_recover_switch(block_id) {
            candidates.push((block_id, switch_info));
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_switch_recovery_creation() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let recovery = SwitchRecovery::new(&cfg);
        // Just verify it compiles and runs
        assert!(recovery.try_recover_switch(BasicBlockId::new(0)).is_none());
    }

    #[test]
    fn test_get_expr_var_key() {
        use super::super::expression::Variable;

        // Test simple variable
        let var = Expr::var(Variable::reg("eax", 4));
        assert_eq!(get_expr_var_key(&var), Some("eax".to_string()));

        // Test stack variable
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let offset = Expr::int(-8);
        let addr = Expr::binop(BinOpKind::Add, rbp, offset);
        let stack_var = Expr::deref(addr, 4);
        assert_eq!(get_expr_var_key(&stack_var), Some("stack_-8".to_string()));
    }

    #[test]
    fn test_is_frame_register() {
        assert!(is_frame_register("rbp"));
        assert!(is_frame_register("rsp"));
        assert!(is_frame_register("x29"));
        assert!(is_frame_register("sp"));
        assert!(!is_frame_register("rax"));
        assert!(!is_frame_register("x0"));
    }

    #[test]
    fn test_switch_kind() {
        assert_eq!(SwitchKind::JumpTable, SwitchKind::JumpTable);
        assert_ne!(SwitchKind::JumpTable, SwitchKind::BinarySearch);
    }

    #[test]
    fn test_jump_table_info() {
        let info = JumpTableInfo {
            table_base: 0x1000,
            entry_size: 4,
            entry_count: 10,
            is_relative: true,
            min_value: 0,
            max_value: 9,
        };

        assert_eq!(info.table_base, 0x1000);
        assert_eq!(info.entry_count, 10);
        assert_eq!(info.max_value - info.min_value + 1, 10);
    }

    #[test]
    fn test_comparison_type() {
        let eq = ComparisonType::Equal(5);
        let lt = ComparisonType::Less(10);

        match eq {
            ComparisonType::Equal(v) => assert_eq!(v, 5),
            _ => panic!("Expected Equal"),
        }

        match lt {
            ComparisonType::Less(v) => assert_eq!(v, 10),
            _ => panic!("Expected Less"),
        }
    }

    #[test]
    fn test_switch_info_creation() {
        use super::super::expression::Variable;

        let switch_info = SwitchInfo {
            switch_value: Expr::var(Variable::reg("eax", 4)),
            cases: vec![
                (vec![0], BasicBlockId::new(1)),
                (vec![1], BasicBlockId::new(2)),
                (vec![2, 3], BasicBlockId::new(3)), // Multiple values to same case
            ],
            default: Some(BasicBlockId::new(4)),
            kind: SwitchKind::JumpTable,
        };

        assert_eq!(switch_info.cases.len(), 3);
        assert_eq!(switch_info.kind, SwitchKind::JumpTable);
        assert!(switch_info.default.is_some());
    }

    #[test]
    fn test_with_binary_data() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let data = vec![0u8; 64];
        let recovery = SwitchRecovery::new(&cfg).with_binary_data(&data, 0x1000);

        // Verify we can create a recovery with binary data
        assert!(recovery.try_recover_switch(BasicBlockId::new(0)).is_none());
    }

    #[test]
    fn test_get_stack_slot_key() {
        use super::super::expression::Variable;

        // Test rbp + positive offset (argument)
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let pos_offset = Expr::int(16);
        let arg_addr = Expr::binop(BinOpKind::Add, rbp, pos_offset);
        assert_eq!(get_stack_slot_key(&arg_addr), Some("stack_16".to_string()));

        // Test rbp - negative offset (local variable)
        let rbp2 = Expr::var(Variable::reg("rbp", 8));
        let neg_offset = Expr::int(32);
        let local_addr = Expr::binop(BinOpKind::Sub, rbp2, neg_offset);
        assert_eq!(
            get_stack_slot_key(&local_addr),
            Some("stack_-32".to_string())
        );
    }

    #[test]
    fn test_find_switch_candidates_empty_cfg() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let candidates = find_switch_candidates(&cfg);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_analyze_jump_table_block_handles_absolute_sib_table_and_memory_switch_var() {
        use hexray_core::{
            Architecture, BasicBlock, BlockTerminator, Instruction, MemoryRef, Operand, Operation,
            Register, RegisterClass,
        };

        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut pred = BasicBlock::new(BasicBlockId::new(0), 0x401141);
        pred.instructions.push(
            Instruction::new(0x401141, 4, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -4, 4)),
                    Operand::imm_unsigned(7, 32),
                ]),
        );
        pred.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Above,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(pred);

        let mut jump = BasicBlock::new(BasicBlockId::new(1), 0x401147);
        jump.instructions.push(
            Instruction::new(0x401147, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -4, 4)),
                ]),
        );
        jump.instructions.push(
            Instruction::new(0x40114a, 8, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::sib(None, Some(rax), 8, 0x402008, 8)),
                ]),
        );
        jump.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(jump);

        let mut default = BasicBlock::new(BasicBlockId::new(2), 0x40118d);
        default.terminator = BlockTerminator::Return;
        cfg.add_block(default);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));

        let recovery = SwitchRecovery::new(&cfg);
        let block = cfg.block(BasicBlockId::new(1)).expect("jump table block");
        let (switch_var, bound_check, table_info, bounds_checked) = recovery
            .analyze_jump_table_block(block)
            .expect("jump table should be recognized");
        assert!(bounds_checked, "a real cmp bounds check was present");

        assert_eq!(table_info.table_base, 0x402008);
        assert_eq!(table_info.entry_size, 8);
        assert!(!table_info.is_relative);
        assert_eq!(bound_check, Some((7, BasicBlockId::new(2))));
        assert!(
            format!("{switch_var}").contains("rbp + -0x4"),
            "expected switch value to come from the compared stack slot, got {switch_var}"
        );
    }

    /// Build a bounded (`cmp idx, 2`) 3-entry absolute jump table whose entries are `targets`
    /// (8-byte addresses). Returns the CFG plus a binary context holding the table.
    #[cfg(test)]
    fn bounded_jump_table(targets: [u64; 3]) -> (ControlFlowGraph, super::super::BinaryDataContext) {
        use hexray_core::{
            Architecture, BasicBlock, BlockTerminator, Instruction, MemoryRef, Operand, Operation,
            Register, RegisterClass,
        };
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut pred = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        pred.push_instruction(
            Instruction::new(0x1000, 4, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -4, 4)),
                    Operand::imm_unsigned(2, 32),
                ]),
        );
        pred.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Above,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(pred);

        let mut jump = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        jump.push_instruction(
            Instruction::new(0x1010, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -4, 4)),
                ]),
        );
        jump.push_instruction(
            Instruction::new(0x1013, 8, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::sib(None, Some(rax), 8, 0x402008, 8)),
                ]),
        );
        jump.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(jump);

        let mut default = BasicBlock::new(BasicBlockId::new(2), 0x40118d);
        default.terminator = BlockTerminator::Return;
        cfg.add_block(default);
        // Edges so the bounds-check predecessor is found (sizes the table to 3 entries).
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));

        // Resume-state blocks the table can point at.
        for (i, id) in [3u32, 4].into_iter().enumerate() {
            let start = 0x500000 + (i as u64) * 0x10;
            let mut b = BasicBlock::new(BasicBlockId::new(id), start);
            b.end = start + 1;
            cfg.add_block(b);
        }

        let mut data = vec![0u8; 3 * 8];
        for (i, &t) in targets.iter().enumerate() {
            data[i * 8..i * 8 + 8].copy_from_slice(&t.to_le_bytes());
        }
        let mut ctx = super::super::BinaryDataContext::new();
        ctx.add_section(0x402008, data);
        (cfg, ctx)
    }

    #[test]
    fn prologue_sub_rsp_is_not_a_table_bound() {
        // An unbounded table whose only `sub` is a prologue `sub rsp, 0x70` must NOT be
        // treated as bounded (which would wrongly demand 0x71 mapped entries). The 2-entry
        // read must still resolve.
        use hexray_core::{
            Architecture, BasicBlock, BlockTerminator, Instruction, MemoryRef, Operand, Operation,
            Register, RegisterClass,
        };
        let (rbp, rsp, eax, rax) = (
            Register::new(Architecture::X86_64, RegisterClass::General, 5, 64),
            Register::new(Architecture::X86_64, RegisterClass::General, 4, 64),
            Register::new(Architecture::X86_64, RegisterClass::General, 0, 32),
            Register::new(Architecture::X86_64, RegisterClass::General, 0, 64),
        );
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        // entry: sub rsp, 0x70 ; jmp dispatch  (prologue only, no real bounds check)
        let mut entry = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        entry.push_instruction(
            Instruction::new(0x1000, 7, vec![], "sub")
                .with_operation(Operation::Sub)
                .with_operands(vec![Operand::Register(rsp), Operand::imm_unsigned(0x70, 32)]),
        );
        entry.terminator = BlockTerminator::Jump { target: BasicBlockId::new(1) };
        cfg.add_block(entry);
        // dispatch: mov eax,[rbp-4] ; mov rax,[0x402008 + rax*8] ; jmp rax
        let mut jump = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        jump.push_instruction(
            Instruction::new(0x1010, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -4, 4)),
                ]),
        );
        jump.push_instruction(
            Instruction::new(0x1013, 8, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::sib(None, Some(rax), 8, 0x402008, 8)),
                ]),
        );
        jump.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(jump);
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        for (i, id) in [2u32, 3].into_iter().enumerate() {
            let start = 0x500000 + (i as u64) * 0x10;
            let mut b = BasicBlock::new(BasicBlockId::new(id), start);
            b.end = start + 1;
            cfg.add_block(b);
        }
        let mut data = vec![0u8; 3 * 8];
        data[0..8].copy_from_slice(&0x500000u64.to_le_bytes());
        data[8..16].copy_from_slice(&0x500010u64.to_le_bytes());
        let mut ctx = super::super::BinaryDataContext::new();
        ctx.add_section(0x402008, data);

        let recovery = SwitchRecovery::new(&cfg).with_binary_context(&ctx);
        let (_, _, _, bounds_checked) = recovery
            .analyze_jump_table_block(cfg.block(BasicBlockId::new(1)).unwrap())
            .expect("recognized");
        assert!(!bounds_checked, "a prologue sub rsp must not count as a bounds check");
        assert!(
            recovery
                .try_recover_switch_read_from_binary(BasicBlockId::new(1))
                .is_some(),
            "the 2-entry table must resolve despite the prologue sub"
        );
    }

    #[test]
    fn rbp_as_index_bounds_check_is_kept() {
        // With the frame pointer omitted, `rbp`/`ebp` is a general-purpose register that can
        // hold the switch index. `cmp ebp, 3` in a predecessor is a real bounds check and must
        // still be recognized (max_value 3, real default), not discarded like `sub rsp`.
        use hexray_core::{
            Architecture, BasicBlock, BlockTerminator, Instruction, MemoryRef, Operand, Operation,
            Register, RegisterClass,
        };
        let ebp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 32);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut pred = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        pred.push_instruction(
            Instruction::new(0x1000, 3, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(ebp), Operand::imm_unsigned(3, 32)]),
        );
        pred.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Above,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(pred);
        let mut jump = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        jump.push_instruction(
            Instruction::new(0x1010, 8, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::sib(None, Some(rax), 8, 0x402008, 8)),
                ]),
        );
        jump.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(jump);
        let mut default = BasicBlock::new(BasicBlockId::new(2), 0x2000);
        default.terminator = BlockTerminator::Return;
        cfg.add_block(default);
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));

        let recovery = SwitchRecovery::new(&cfg);
        let (_, bound_check, table_info, bounds_checked) = recovery
            .analyze_jump_table_block(cfg.block(BasicBlockId::new(1)).unwrap())
            .expect("recognized");
        assert!(bounds_checked, "cmp ebp, 3 is a real bounds check");
        assert_eq!(bound_check, Some((3, BasicBlockId::new(2))));
        assert_eq!(table_info.entry_count, 4);
    }

    #[test]
    fn read_from_binary_declines_bounded_table_with_unmapped_entry() {
        // A bounded 3-entry table (`cmp idx, 2`) where entry 2 points at an address with no
        // block: the read is incomplete (a bounded state is dropped), so it must decline.
        let (cfg, ctx) = bounded_jump_table([0x500000, 0x500010, 0xdead_beef]);
        let recovery = SwitchRecovery::new(&cfg).with_binary_context(&ctx);
        assert!(
            recovery
                .try_recover_switch_read_from_binary(BasicBlockId::new(1))
                .is_none(),
            "an incomplete bounded table read must decline"
        );
    }

    #[test]
    fn read_from_binary_accepts_bounded_table_all_entries_mapped() {
        // All 3 bounded entries map (state 2 shares state 0's block): recovery succeeds.
        let (cfg, ctx) = bounded_jump_table([0x500000, 0x500010, 0x500000]);
        let recovery = SwitchRecovery::new(&cfg).with_binary_context(&ctx);
        let info = recovery
            .try_recover_switch_read_from_binary(BasicBlockId::new(1))
            .expect("complete bounded table should resolve");
        let labels: usize = info.cases.iter().map(|(v, _)| v.len()).sum();
        assert_eq!(labels, 3, "all three bounded entries must be present");
    }

    #[test]
    fn test_switch_kind_variants() {
        // Test all switch kind variants
        let jt = SwitchKind::JumpTable;
        let bs = SwitchKind::BinarySearch;
        let ie = SwitchKind::IfElseChain;

        assert_ne!(jt, bs);
        assert_ne!(jt, ie);
        assert_ne!(bs, ie);
    }
}
