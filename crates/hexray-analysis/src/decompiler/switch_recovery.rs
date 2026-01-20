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
    /// Binary data for reading jump tables (optional).
    binary_data: Option<&'a [u8]>,
    /// Base address of the binary data section.
    data_base: u64,
}

impl<'a> SwitchRecovery<'a> {
    /// Creates a new switch recovery analyzer.
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            binary_data: None,
            data_base: 0,
        }
    }

    /// Sets the binary data for jump table reading.
    pub fn with_binary_data(mut self, data: &'a [u8], base: u64) -> Self {
        self.binary_data = Some(data);
        self.data_base = base;
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
        let (switch_var, bound_check, table_info) = self.analyze_jump_table_block(block)?;

        // If we have possible targets from CFG analysis, use those
        let cases = if !possible_targets.is_empty() {
            possible_targets
                .iter()
                .enumerate()
                .map(|(i, &target)| {
                    let value = table_info.min_value + i as i64;
                    (vec![value as i128], target)
                })
                .collect()
        } else if let Some(cases) = self.read_jump_table(&table_info) {
            cases
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
    /// Returns (switch_variable, (max_value, default_block), jump_table_info)
    #[allow(clippy::type_complexity)]
    fn analyze_jump_table_block(
        &self,
        block: &BasicBlock,
    ) -> Option<(Expr, Option<(i64, BasicBlockId)>, JumpTableInfo)> {
        let mut switch_var: Option<Expr> = None;
        let mut bound_check: Option<(i64, BasicBlockId)> = None;
        let mut table_base: Option<u64> = None;
        let mut entry_size: u8 = 4; // Default to 4-byte entries
        let is_relative = true;

        // Scan instructions for patterns
        for inst in &block.instructions {
            match inst.operation {
                // Look for comparison (bounds check)
                Operation::Compare => {
                    if inst.operands.len() >= 2 {
                        switch_var = Some(Expr::from_operand(&inst.operands[0]));
                        if let Operand::Immediate(imm) = &inst.operands[1] {
                            // The comparison value is the maximum case value
                            bound_check = Some((imm.value as i64, BasicBlockId::new(0)));
                            // Default block TBD
                        }
                    }
                }

                // Look for LEA (table base address)
                Operation::LoadEffectiveAddress => {
                    if inst.operands.len() >= 2 {
                        if let Operand::PcRelative { target, .. } = &inst.operands[1] {
                            table_base = Some(*target);
                        }
                    }
                }

                // Look for load with scaled index (table access)
                Operation::Load | Operation::Move => {
                    if let Some(Operand::Memory(mem)) = inst.operands.get(1) {
                        if mem.index.is_some() && mem.scale > 1 {
                            entry_size = mem.scale;
                        }
                    }
                }

                _ => {}
            }
        }

        let switch_var = switch_var?;

        // Construct jump table info
        let (max_value, default_block) = bound_check.unwrap_or((255, BasicBlockId::new(0)));
        let table_info = JumpTableInfo {
            table_base: table_base.unwrap_or(0),
            entry_size,
            entry_count: (max_value + 1) as u32,
            is_relative,
            min_value: 0,
            max_value,
        };

        Some((switch_var, Some((max_value, default_block)), table_info))
    }

    /// Reads case targets from a jump table in binary data.
    fn read_jump_table(&self, info: &JumpTableInfo) -> Option<Vec<(Vec<i128>, BasicBlockId)>> {
        let data = self.binary_data?;

        // Calculate offset into data
        if info.table_base < self.data_base {
            return None;
        }
        let offset = (info.table_base - self.data_base) as usize;

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
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
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
