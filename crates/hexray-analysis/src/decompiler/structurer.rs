//! Control flow structuring.
//!
//! Transforms a CFG into structured control flow (if/else, while, for, etc.).

#![allow(dead_code)]

use hexray_core::{
    cfg::Loop, BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph, IndexMode,
    Instruction, Operand, Operation,
};
use std::collections::{HashMap, HashSet};

use super::abi::{
    get_arg_register_index, is_argument_register, is_callee_saved_register, is_return_register,
    is_temp_register,
};
use super::dead_store::collect_all_uses;
use super::expression::{resolve_adrp_patterns, BinOpKind, Expr};
use super::for_loop_detection::{detect_for_loops, get_expr_var_key};
use super::short_circuit::detect_short_circuit;
use super::switch_recovery::SwitchRecovery;
use super::BinaryDataContext;

/// A structured representation of control flow.
#[derive(Debug)]
pub struct StructuredCfg {
    /// The structured body.
    pub body: Vec<StructuredNode>,
    /// The original CFG entry (for reference).
    pub cfg_entry: BasicBlockId,
}

/// A structured control flow node.
#[derive(Debug, Clone)]
pub enum StructuredNode {
    /// A basic block (sequence of statements).
    Block {
        id: BasicBlockId,
        statements: Vec<Expr>,
        address_range: (u64, u64),
    },

    /// If statement (with optional else).
    If {
        condition: Expr,
        then_body: Vec<StructuredNode>,
        else_body: Option<Vec<StructuredNode>>,
    },

    /// While loop.
    While {
        condition: Expr,
        body: Vec<StructuredNode>,
        /// Loop header block ID (for continue detection).
        header: Option<BasicBlockId>,
        /// Loop exit block ID (for break detection).
        exit_block: Option<BasicBlockId>,
    },

    /// Do-while loop.
    DoWhile {
        body: Vec<StructuredNode>,
        condition: Expr,
        /// Loop header block ID (for continue detection).
        header: Option<BasicBlockId>,
        /// Loop exit block ID (for break detection).
        exit_block: Option<BasicBlockId>,
    },

    /// For loop (recognized from while with init/update).
    For {
        init: Option<Expr>,
        condition: Expr,
        update: Option<Expr>,
        body: Vec<StructuredNode>,
        /// Loop header block ID (for continue detection).
        header: Option<BasicBlockId>,
        /// Loop exit block ID (for break detection).
        exit_block: Option<BasicBlockId>,
    },

    /// Infinite loop.
    Loop {
        body: Vec<StructuredNode>,
        /// Loop header block ID (for continue detection).
        header: Option<BasicBlockId>,
        /// Loop exit block ID (for break detection).
        exit_block: Option<BasicBlockId>,
    },

    /// Break statement.
    Break,

    /// Continue statement.
    Continue,

    /// Return statement.
    Return(Option<Expr>),

    /// Goto (for irreducible control flow).
    Goto(BasicBlockId),

    /// Label (target of goto).
    Label(BasicBlockId),

    /// Switch statement.
    Switch {
        value: Expr,
        cases: Vec<(Vec<i128>, Vec<StructuredNode>)>,
        default: Option<Vec<StructuredNode>>,
    },

    /// Sequence of nodes.
    Sequence(Vec<StructuredNode>),

    /// Raw expression/statement.
    Expr(Expr),

    /// Try-catch block (C++ exception handling).
    TryCatch {
        /// The protected code block.
        try_body: Vec<StructuredNode>,
        /// Catch handlers with their type and body.
        /// The String is the exception type (or None for catch-all).
        catch_handlers: Vec<CatchHandler>,
    },
}

/// A catch handler in a try-catch block.
#[derive(Debug, Clone)]
pub struct CatchHandler {
    /// Exception type being caught (None for catch-all `catch(...)`).
    pub exception_type: Option<String>,
    /// Variable name for the caught exception (e.g., "e" in `catch(Exception& e)`).
    pub variable_name: Option<String>,
    /// Handler body.
    pub body: Vec<StructuredNode>,
    /// Landing pad address (for debugging/comments).
    pub landing_pad: u64,
}

/// Loop detection information.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub header: BasicBlockId,
    pub back_edges: Vec<BasicBlockId>,
    pub body: HashSet<BasicBlockId>,
    pub kind: LoopKind,
    pub exit_blocks: Vec<BasicBlockId>,
}

/// Kind of loop detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopKind {
    /// While loop (condition at top).
    While,
    /// Do-while loop (condition at bottom).
    DoWhile,
    /// Infinite loop (no exit condition).
    Infinite,
    /// For loop (init, condition, update pattern).
    For,
}

impl StructuredCfg {
    /// Creates a structured CFG from an unstructured one with default configuration.
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        Self::from_cfg_with_config(cfg, &super::config::DecompilerConfig::default())
    }

    /// Creates a structured CFG with custom configuration.
    pub fn from_cfg_with_config(
        cfg: &ControlFlowGraph,
        config: &super::config::DecompilerConfig,
    ) -> Self {
        use super::config::OptimizationPass;

        let mut structurer = Structurer::new(cfg);
        let mut body = structurer.structure();

        // Post-process to propagate arguments into function calls (before copy propagation)
        if config.is_pass_enabled(OptimizationPass::CallArgPropagation) {
            body = propagate_call_args(body);
        }

        // Post-process to merge return value captures across block boundaries
        if config.is_pass_enabled(OptimizationPass::ReturnValueMerge) {
            body = merge_return_value_captures(body);
        }

        // Post-process to eliminate temporary register patterns
        if config.is_pass_enabled(OptimizationPass::TempSimplification) {
            body = simplify_statements(body);
        }

        // Post-process to detect for loops from while loops with init/update
        if config.is_pass_enabled(OptimizationPass::ForLoopDetection) {
            body = detect_for_loops(body);
        }

        // Post-process to hoist loop-invariant computations
        if config.is_pass_enabled(OptimizationPass::LoopInvariantHoisting) {
            body = super::loop_invariant::hoist_loop_invariants(body);
        }

        // Post-process to detect memcpy/memset patterns in for loops
        if config.is_pass_enabled(OptimizationPass::LoopPatternDetection) {
            body = super::loop_pattern_detection::detect_loop_patterns(body);
        }

        // Post-process to canonicalize loop forms
        if config.is_pass_enabled(OptimizationPass::LoopCanonicalization) {
            body = super::loop_canonicalization::canonicalize_loops(body);
        }

        // Post-process to detect memset/array initialization idioms
        if config.is_pass_enabled(OptimizationPass::MemsetIdiomDetection) {
            body = super::memset_idiom::detect_init_patterns(body);
        }

        // Post-process to detect switch statements from if-else chains
        if config.is_pass_enabled(OptimizationPass::SwitchDetection) {
            body = detect_switch_statements(body);
        }

        // Post-process to detect short-circuit boolean patterns (a && b, a || b)
        if config.is_pass_enabled(OptimizationPass::ShortCircuitDetection) {
            body = detect_short_circuit(body);
        }

        // Post-process to handle irreducible CFG regions
        // Should run BEFORE goto conversion to ensure irreducible gotos are preserved
        if config.is_pass_enabled(OptimizationPass::IrreducibleHandling) {
            body = super::irreducible_cfg::handle_irreducible_regions(cfg, body);
        }

        // Post-process to convert gotos to break/continue where applicable
        if config.is_pass_enabled(OptimizationPass::GotoConversion) {
            body = convert_gotos_to_break_continue(body, None);
            // Second pass: convert global gotos (in orphan labeled blocks) to continue
            // when they target loop headers (common in getopt/switch patterns)
            let loop_headers = collect_loop_headers(&body);
            body = convert_global_gotos_to_continue(body, &loop_headers);
            // Third pass: convert gotos in switch cases to break when they target
            // a common exit point (common in option parsing switches)
            body = convert_switch_gotos_to_break(body);
            // Fourth pass: convert gotos to labeled cleanup blocks into inlined cleanup
            body = convert_cleanup_gotos(body);
            // Fifth pass: convert gotos to return labels into direct returns
            body = convert_gotos_to_early_returns(body);
            // Sixth pass: convert multi-level escape gotos to breaks
            body = convert_multilevel_breaks(body);
            // Seventh pass: structure shared exit paths
            body = structure_shared_exits(body);
            // Eighth pass: remove orphan labels that no longer have gotos
            body = remove_orphan_labels(body);
            // Final cleanup: remove gotos to non-existent labels
            body = remove_orphan_gotos(body);
            // Remove orphan continues (outside any loop context)
            body = remove_orphan_continues(body);
        }

        // Post-process to flatten nested if-else into guard clauses
        if config.is_pass_enabled(OptimizationPass::GuardClauseFlattening) {
            body = flatten_guard_clauses(body);
        }

        // Post-process for constant folding and propagation
        if config.is_pass_enabled(OptimizationPass::ConstantPropagation) {
            body = super::constant_propagation::propagate_constants(body);
        }

        // Post-process to simplify expressions (constant folding, algebraic simplifications)
        if config.is_pass_enabled(OptimizationPass::ExpressionSimplification) {
            body = simplify_expressions(body);
        }

        // Post-process to detect string function patterns (strlen, strcpy, etc.)
        if config.is_pass_enabled(OptimizationPass::StringPatternDetection) {
            body = super::string_patterns::detect_string_patterns(body);
            body = simplify_strcmp_switch_patterns(body);
        }

        // Post-process to simplify architecture-specific patterns (CSEL, min/max, abs)
        if config.is_pass_enabled(OptimizationPass::ArchPatternSimplification) {
            body = super::arch_patterns::simplify_arch_patterns(body);
        }

        // Post-process to eliminate dead stores
        if config.is_pass_enabled(OptimizationPass::DeadStoreElimination) {
            body = super::dead_store::eliminate_dead_stores(body);
        }

        // Post-process to infer better variable names
        if config.is_pass_enabled(OptimizationPass::VariableNaming) {
            body = super::variable_naming::suggest_variable_names(body);
        }

        Self {
            body,
            cfg_entry: cfg.entry,
        }
    }

    /// Creates a structured CFG with custom configuration and binary data for jump table reconstruction.
    pub fn from_cfg_with_config_and_binary_data(
        cfg: &ControlFlowGraph,
        config: &super::config::DecompilerConfig,
        binary_data: Option<&BinaryDataContext>,
    ) -> Self {
        use super::config::OptimizationPass;

        let mut structurer = Structurer::new_with_binary_data(cfg, binary_data);
        let mut body = structurer.structure();

        // Post-process to propagate arguments into function calls (before copy propagation)
        if config.is_pass_enabled(OptimizationPass::CallArgPropagation) {
            body = propagate_call_args(body);
        }

        // Post-process to merge return value captures across block boundaries
        if config.is_pass_enabled(OptimizationPass::ReturnValueMerge) {
            body = merge_return_value_captures(body);
        }

        // Post-process to eliminate temporary register patterns
        if config.is_pass_enabled(OptimizationPass::TempSimplification) {
            body = simplify_statements(body);
        }

        // Post-process to detect for loops from while loops with init/update
        if config.is_pass_enabled(OptimizationPass::ForLoopDetection) {
            body = detect_for_loops(body);
        }

        // Post-process to hoist loop-invariant computations
        if config.is_pass_enabled(OptimizationPass::LoopInvariantHoisting) {
            body = super::loop_invariant::hoist_loop_invariants(body);
        }

        // Post-process to detect memcpy/memset patterns in for loops
        if config.is_pass_enabled(OptimizationPass::LoopPatternDetection) {
            body = super::loop_pattern_detection::detect_loop_patterns(body);
        }

        // Post-process to canonicalize loop forms
        if config.is_pass_enabled(OptimizationPass::LoopCanonicalization) {
            body = super::loop_canonicalization::canonicalize_loops(body);
        }

        // Post-process to detect memset/array initialization idioms
        if config.is_pass_enabled(OptimizationPass::MemsetIdiomDetection) {
            body = super::memset_idiom::detect_init_patterns(body);
        }

        // Post-process to detect switch statements from if-else chains
        if config.is_pass_enabled(OptimizationPass::SwitchDetection) {
            body = detect_switch_statements(body);
        }

        // Post-process to detect short-circuit boolean patterns (a && b, a || b)
        if config.is_pass_enabled(OptimizationPass::ShortCircuitDetection) {
            body = detect_short_circuit(body);
        }

        // Post-process to handle irreducible CFG regions
        // Should run BEFORE goto conversion to ensure irreducible gotos are preserved
        if config.is_pass_enabled(OptimizationPass::IrreducibleHandling) {
            body = super::irreducible_cfg::handle_irreducible_regions(cfg, body);
        }

        // Post-process to convert gotos to break/continue where applicable
        if config.is_pass_enabled(OptimizationPass::GotoConversion) {
            body = convert_gotos_to_break_continue(body, None);
            // Second pass: convert global gotos (in orphan labeled blocks) to continue
            // when they target loop headers (common in getopt/switch patterns)
            let loop_headers = collect_loop_headers(&body);
            body = convert_global_gotos_to_continue(body, &loop_headers);
            // Third pass: convert gotos in switch cases to break when they target
            // a common exit point (common in option parsing switches)
            body = convert_switch_gotos_to_break(body);
            // Fourth pass: convert gotos to labeled cleanup blocks into inlined cleanup
            body = convert_cleanup_gotos(body);
            // Fifth pass: convert gotos to return labels into direct returns
            body = convert_gotos_to_early_returns(body);
            // Sixth pass: convert multi-level escape gotos to breaks
            body = convert_multilevel_breaks(body);
            // Seventh pass: structure shared exit paths
            body = structure_shared_exits(body);
            // Eighth pass: remove orphan labels that no longer have gotos
            body = remove_orphan_labels(body);
            // Final cleanup: remove gotos to non-existent labels
            body = remove_orphan_gotos(body);
            // Remove orphan continues (outside any loop context)
            body = remove_orphan_continues(body);
        }

        // Post-process to flatten nested if-else into guard clauses
        if config.is_pass_enabled(OptimizationPass::GuardClauseFlattening) {
            body = flatten_guard_clauses(body);
        }

        // Post-process for constant folding and propagation
        if config.is_pass_enabled(OptimizationPass::ConstantPropagation) {
            body = super::constant_propagation::propagate_constants(body);
        }

        // Post-process to simplify expressions (constant folding, algebraic simplifications)
        if config.is_pass_enabled(OptimizationPass::ExpressionSimplification) {
            body = simplify_expressions(body);
        }

        // Post-process to detect string function patterns (strlen, strcpy, etc.)
        if config.is_pass_enabled(OptimizationPass::StringPatternDetection) {
            body = super::string_patterns::detect_string_patterns(body);
            body = simplify_strcmp_switch_patterns(body);
        }

        // Post-process to simplify architecture-specific patterns (CSEL, min/max, abs)
        if config.is_pass_enabled(OptimizationPass::ArchPatternSimplification) {
            body = super::arch_patterns::simplify_arch_patterns(body);
        }

        // Post-process to eliminate dead stores
        if config.is_pass_enabled(OptimizationPass::DeadStoreElimination) {
            body = super::dead_store::eliminate_dead_stores(body);
        }

        // Post-process to infer better variable names
        if config.is_pass_enabled(OptimizationPass::VariableNaming) {
            body = super::variable_naming::suggest_variable_names(body);
        }

        Self {
            body,
            cfg_entry: cfg.entry,
        }
    }

    /// Returns the structured body.
    pub fn body(&self) -> &[StructuredNode] {
        &self.body
    }
}

/// Control flow structuring algorithm.
struct Structurer<'a> {
    cfg: &'a ControlFlowGraph,
    loops: Vec<Loop>,
    loop_headers: HashSet<BasicBlockId>,
    loop_info: HashMap<BasicBlockId, LoopInfo>,
    visited: HashSet<BasicBlockId>,
    processed: HashSet<BasicBlockId>,
    /// Blocks with multiple predecessors that should be emitted with labels.
    multi_pred_blocks: HashSet<BasicBlockId>,
    /// Blocks that are allowed to be inlined even if they have multiple predecessors.
    /// This is used for join points after if-else structures.
    inline_allowed: HashSet<BasicBlockId>,
    /// Irreducible CFG analysis results.
    irreducible_analysis: super::irreducible_cfg::IrreducibleCfgAnalysis,
    /// Binary data context for jump table reconstruction.
    binary_data: Option<&'a BinaryDataContext>,
}

impl<'a> Structurer<'a> {
    fn new(cfg: &'a ControlFlowGraph) -> Self {
        let loops = cfg.find_loops();
        let mut loop_headers = HashSet::new();
        let mut loop_info = HashMap::new();

        for lp in &loops {
            loop_headers.insert(lp.header);

            let body_set: HashSet<_> = lp.body.iter().copied().collect();
            let exit_blocks = Self::find_loop_exits(cfg, &body_set);
            let kind = Self::classify_loop(cfg, lp, &body_set);

            loop_info.insert(
                lp.header,
                LoopInfo {
                    header: lp.header,
                    back_edges: vec![lp.back_edge],
                    body: body_set,
                    kind,
                    exit_blocks,
                },
            );
        }

        // Find blocks with multiple predecessors that are "cleanup targets"
        // These are blocks that have jumps coming FROM addresses AFTER them
        // (indicating error cleanup patterns where later code jumps back to earlier cleanup)
        let mut multi_pred_blocks = HashSet::new();
        for block_id in cfg.block_ids() {
            let preds = cfg.predecessors(block_id);
            if preds.len() < 2 || loop_headers.contains(&block_id) {
                continue;
            }

            // Get this block's start address
            let block_addr = cfg.block(block_id).map(|b| b.start).unwrap_or(0);

            // Count how many predecessors have higher addresses (backward jumps to this block)
            let backward_jumps = preds
                .iter()
                .filter(|&&pred_id| {
                    cfg.block(pred_id)
                        .map(|b| b.start > block_addr)
                        .unwrap_or(false)
                })
                .count();

            // If multiple paths jump backward to this block, it's a cleanup target
            if backward_jumps >= 2 {
                multi_pred_blocks.insert(block_id);
            }
        }

        // Perform dominance-based irreducible CFG detection
        let irreducible_analysis = super::irreducible_cfg::IrreducibleCfgAnalysis::analyze(cfg);

        // Mark ALL entry points of irreducible regions for labeling.
        // Even the suggested header needs a label if it's targeted by a goto
        // from within the irreducible region (back edges).
        for region in &irreducible_analysis.regions {
            for &entry in &region.entry_points {
                multi_pred_blocks.insert(entry);
            }
        }

        Self {
            cfg,
            loops,
            loop_headers,
            loop_info,
            visited: HashSet::new(),
            processed: HashSet::new(),
            multi_pred_blocks,
            inline_allowed: HashSet::new(),
            irreducible_analysis,
            binary_data: None,
        }
    }

    fn new_with_binary_data(
        cfg: &'a ControlFlowGraph,
        binary_data: Option<&'a BinaryDataContext>,
    ) -> Self {
        let mut structurer = Self::new(cfg);
        structurer.binary_data = binary_data;
        structurer
    }

    /// Checks if a block (and its successors) eventually return with just cleanup calls.
    /// Returns the return value expression if it does, None otherwise.
    fn get_return_expr_if_pure_return(&self, block_id: BasicBlockId) -> Option<Expr> {
        self.get_return_expr_following_chain(block_id, &mut HashSet::new())
    }

    /// Helper that follows the chain of blocks to find the return expression.
    fn get_return_expr_following_chain(
        &self,
        block_id: BasicBlockId,
        visited: &mut HashSet<BasicBlockId>,
    ) -> Option<Expr> {
        // Prevent infinite loops
        if visited.contains(&block_id) {
            return None;
        }
        visited.insert(block_id);

        let block = self.cfg.block(block_id)?;

        // Check terminator type
        match &block.terminator {
            BlockTerminator::Return => {
                // This is a pure return block - extract return value
                self.extract_return_value(block)
            }
            BlockTerminator::Call { return_block, .. } => {
                // This is a cleanup call block - check if the next block eventually returns
                // Only allow if block contains just the call (cleanup pattern)
                if self.is_cleanup_block(block) {
                    self.get_return_expr_following_chain(*return_block, visited)
                } else {
                    None
                }
            }
            BlockTerminator::Jump { target } => {
                // Follow the jump
                self.get_return_expr_following_chain(*target, visited)
            }
            BlockTerminator::Fallthrough { target } => {
                // Follow fallthrough
                self.get_return_expr_following_chain(*target, visited)
            }
            _ => None,
        }
    }

    /// Extracts the return value from a pure return block.
    fn extract_return_value(&self, block: &BasicBlock) -> Option<Expr> {
        let mut return_value: Option<Expr> = None;

        for inst in &block.instructions {
            // Check for return value setup: eax/rax/x0/w0 = something (Move or Load)
            if matches!(inst.operation, Operation::Move | Operation::Load)
                && inst.operands.len() >= 2
            {
                if let hexray_core::Operand::Register(dst) = &inst.operands[0] {
                    let dst_name = dst.name().to_lowercase();
                    if matches!(dst_name.as_str(), "eax" | "rax" | "x0" | "w0" | "a0") {
                        return_value = Some(Expr::from_operand_with_inst(&inst.operands[1], inst));
                        continue;
                    }
                }
            }
            // Skip epilogue instructions and jump/ret
            if matches!(
                inst.operation,
                Operation::Pop | Operation::Push | Operation::Jump | Operation::Return
            ) {
                continue;
            }
            // Skip nop and endbr
            if inst.mnemonic.starts_with("nop") || inst.mnemonic.starts_with("endbr") {
                continue;
            }
            // Skip ARM64 stack cleanup: add sp, sp, #imm
            if matches!(inst.operation, Operation::Add) && inst.operands.len() >= 2 {
                if let hexray_core::Operand::Register(dst) = &inst.operands[0] {
                    let dst_name = dst.name().to_lowercase();
                    if dst_name == "sp" || dst_name == "rsp" {
                        continue;
                    }
                }
            }
            // Skip ARM64 ldp for callee-saved registers (x29, x30, etc.)
            if inst.mnemonic.to_lowercase() == "ldp" {
                continue;
            }
            // Any other instruction means not a simple return block
            return None;
        }

        // Return the captured value, or default to the return register
        Some(return_value.unwrap_or_else(|| {
            Expr::var(super::expression::Variable {
                name: "x0".to_string(),
                kind: super::expression::VarKind::Register(0),
                size: 8,
            })
        }))
    }

    /// Checks if a block is a cleanup block (just a call, no other logic).
    fn is_cleanup_block(&self, block: &BasicBlock) -> bool {
        // A cleanup block typically has just a call instruction
        // Allow call + maybe some prologue/epilogue
        for inst in &block.instructions {
            if inst.is_call() {
                continue;
            }
            // Allow nop, endbr, push, pop
            if matches!(inst.operation, Operation::Push | Operation::Pop) {
                continue;
            }
            if inst.mnemonic.starts_with("nop") || inst.mnemonic.starts_with("endbr") {
                continue;
            }
            // Any other instruction means not a simple cleanup block
            return false;
        }
        true
    }

    fn find_loop_exits(cfg: &ControlFlowGraph, body: &HashSet<BasicBlockId>) -> Vec<BasicBlockId> {
        let mut exits_set = HashSet::new();
        for &block in body {
            for &succ in cfg.successors(block) {
                if !body.contains(&succ) {
                    exits_set.insert(succ);
                }
            }
        }
        exits_set.into_iter().collect()
    }

    fn classify_loop(cfg: &ControlFlowGraph, lp: &Loop, body: &HashSet<BasicBlockId>) -> LoopKind {
        let header_block = cfg.block(lp.header);
        let back_edge_block = cfg.block(lp.back_edge);

        // Check if header has a conditional branch out of the loop (while loop)
        if let Some(block) = header_block {
            if let BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
                ..
            } = &block.terminator
            {
                let true_in_loop = body.contains(true_target);
                let false_in_loop = body.contains(false_target);
                if true_in_loop != false_in_loop {
                    return LoopKind::While;
                }
            }
        }

        // Check if back edge block has a conditional branch (do-while loop)
        if let Some(block) = back_edge_block {
            if let BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
                ..
            } = &block.terminator
            {
                if *true_target == lp.header || *false_target == lp.header {
                    return LoopKind::DoWhile;
                }
            }
        }

        // Default to infinite loop if no exit condition found
        LoopKind::Infinite
    }

    fn structure(&mut self) -> Vec<StructuredNode> {
        let mut result = self.structure_region(self.cfg.entry, None);

        // Emit ALL unprocessed blocks as labeled sections, not just multi_pred_blocks.
        // This is crucial for irreducible CFGs where some blocks may not be reachable
        // through normal structured control flow but are still part of the function.
        // Sort by address for consistent, deterministic output.
        let all_block_ids: Vec<_> = self.cfg.block_ids().collect();

        let mut unprocessed: Vec<_> = all_block_ids
            .iter()
            .filter(|b| !self.processed.contains(b))
            .copied()
            .collect();
        unprocessed.sort_by_key(|b| self.cfg.block(*b).map(|blk| blk.start).unwrap_or(0));

        for block_id in unprocessed {
            // Re-check if still unprocessed - previous iterations may have processed this block
            // as part of structuring another block (e.g., if-else branches)
            if self.processed.contains(&block_id) {
                continue;
            }

            // Add label for the block
            result.push(StructuredNode::Label(block_id));

            // Structure from this block
            let block_nodes = self.structure_region(block_id, None);
            result.extend(block_nodes);
        }

        result
    }

    fn structure_region(
        &mut self,
        start: BasicBlockId,
        end: Option<BasicBlockId>,
    ) -> Vec<StructuredNode> {
        let mut result = Vec::new();
        let mut current = Some(start);

        while let Some(block_id) = current {
            // Stop if we've reached the end of this region
            if end == Some(block_id) {
                break;
            }

            // If this is a multi-predecessor block (shared target) and not the first block,
            // emit a goto and let it be handled as a labeled block later.
            // However, skip this if the block is marked as "inline allowed" (e.g., join points
            // after if-else structures that should be processed inline).
            if self.multi_pred_blocks.contains(&block_id)
                && block_id != start
                && !self.inline_allowed.contains(&block_id)
            {
                // Check if target is a pure return block - if so, emit return instead of goto
                if let Some(ret_expr) = self.get_return_expr_if_pure_return(block_id) {
                    result.push(StructuredNode::Return(Some(ret_expr)));
                } else {
                    result.push(StructuredNode::Goto(block_id));
                }
                break;
            }

            // Prevent infinite loops in structuring
            if self.processed.contains(&block_id) {
                // Check if target is a pure return block - if so, emit return instead of goto
                if let Some(ret_expr) = self.get_return_expr_if_pure_return(block_id) {
                    result.push(StructuredNode::Return(Some(ret_expr)));
                } else {
                    result.push(StructuredNode::Goto(block_id));
                }
                break;
            }

            // Check if this is a loop header
            if self.loop_headers.contains(&block_id) && !self.visited.contains(&block_id) {
                self.visited.insert(block_id);
                // Mark the loop header as processed so it won't be emitted as an orphan block
                self.processed.insert(block_id);
                let loop_node = self.structure_loop(block_id);
                result.push(loop_node);

                // Find where to continue after the loop
                if let Some(info) = self.loop_info.get(&block_id) {
                    if let Some(&exit) = info.exit_blocks.first() {
                        current = Some(exit);
                        continue;
                    }
                }
                break;
            }

            let block = match self.cfg.block(block_id) {
                Some(b) => b,
                None => break,
            };

            self.processed.insert(block_id);

            // Convert block instructions to expressions
            let statements = self.block_to_statements(block_id);
            let address_range = (block.start, block.end);

            // Handle based on terminator
            match &block.terminator {
                BlockTerminator::Return => {
                    // Check if last statement is an assignment to return register (eax/rax)
                    // If so, extract it as the return value
                    // Note: extract_return_value applies copy propagation internally
                    let (filtered_stmts, return_value) = extract_return_value(statements);

                    if !filtered_stmts.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements: filtered_stmts,
                            address_range,
                        });
                    }
                    result.push(StructuredNode::Return(return_value));
                    break;
                }

                BlockTerminator::Unreachable => {
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    break;
                }

                BlockTerminator::Jump { target } | BlockTerminator::Fallthrough { target } => {
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    current = Some(*target);
                }

                BlockTerminator::ConditionalBranch {
                    condition,
                    true_target,
                    false_target,
                } => {
                    // Add block statements first
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }

                    // Structure the if/else
                    let if_node = self.structure_if_else(
                        *condition,
                        *true_target,
                        *false_target,
                        end,
                        block_id,
                        block,
                    );
                    result.push(if_node);

                    // Find join point and continue
                    let join = self.find_join_point(*true_target, *false_target, end);

                    // Mark the join point as inline-allowed so we don't emit a goto to it.
                    // This is the natural continuation after the if-else structure.
                    // HOWEVER, don't mark irreducible entry points as inline-allowed, since
                    // they have gotos targeting them from other places in the code.
                    if let Some(join_id) = join {
                        let is_irreducible_entry = self
                            .irreducible_analysis
                            .regions
                            .iter()
                            .any(|r| r.entry_points.contains(&join_id));
                        if !is_irreducible_entry {
                            self.inline_allowed.insert(join_id);
                        }
                    }

                    current = join;
                }

                BlockTerminator::Call { return_block, .. } => {
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    current = Some(*return_block);
                }

                BlockTerminator::IndirectJump {
                    possible_targets, ..
                } => {
                    // Try to recover a switch statement from the indirect jump
                    let mut switch_recovery = SwitchRecovery::new(self.cfg);
                    if let Some(bin_ctx) = self.binary_data {
                        switch_recovery = switch_recovery.with_binary_context(bin_ctx);
                    }
                    if let Some(switch_info) = switch_recovery.try_recover_switch(block_id) {
                        // Successfully detected a switch pattern
                        // Add block statements first
                        if !statements.is_empty() {
                            result.push(StructuredNode::Block {
                                id: block_id,
                                statements,
                                address_range,
                            });
                        }

                        // Structure the switch cases
                        let switch_node = self.structure_switch_from_recovery(switch_info);
                        result.push(switch_node);
                        break;
                    }

                    // If switch recovery failed but we have possible_targets, try to structure them
                    if !possible_targets.is_empty() {
                        if !statements.is_empty() {
                            result.push(StructuredNode::Block {
                                id: block_id,
                                statements,
                                address_range,
                            });
                        }
                        // Emit a basic switch with unknown values, using indices
                        let switch_expr = Expr::unknown("switch_value".to_string());
                        let cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = possible_targets
                            .iter()
                            .enumerate()
                            .map(|(i, &target)| {
                                let body = self.structure_region(target, end);
                                (vec![i as i128], body)
                            })
                            .collect();
                        result.push(StructuredNode::Switch {
                            value: switch_expr,
                            cases,
                            default: None,
                        });
                        break;
                    }

                    // Fallback: emit block and break
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    break;
                }

                BlockTerminator::Unknown => {
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    // Try to continue with successors
                    let succs = self.cfg.successors(block_id);
                    current = succs.first().copied();
                }
            }
        }

        result
    }

    fn structure_loop(&mut self, header: BasicBlockId) -> StructuredNode {
        let info = match self.loop_info.get(&header).cloned() {
            Some(i) => i,
            None => return StructuredNode::Goto(header),
        };

        // Get the primary exit block (first one, if any)
        let exit_block = info.exit_blocks.first().copied();

        match info.kind {
            LoopKind::While => {
                // Get condition from header's conditional branch
                let (condition, body_start) = self.get_while_condition(header, &info);
                let body = if let Some(start) = body_start {
                    if start == header {
                        // Self-loop: the header IS the body. Use structure_loop_body
                        // to include the header's statements in the body.
                        self.structure_loop_body(header, &info)
                    } else {
                        self.structure_region(start, Some(header))
                    }
                } else {
                    vec![]
                };

                StructuredNode::While {
                    condition,
                    body,
                    header: Some(header),
                    exit_block,
                }
            }

            LoopKind::DoWhile => {
                // Body is the loop content, condition at the end
                let (condition, _) = self.get_dowhile_condition(&info);
                let body = self.structure_loop_body(header, &info);

                StructuredNode::DoWhile {
                    body,
                    condition,
                    header: Some(header),
                    exit_block,
                }
            }

            LoopKind::Infinite => {
                let body = self.structure_loop_body(header, &info);
                StructuredNode::Loop {
                    body,
                    header: Some(header),
                    exit_block,
                }
            }

            LoopKind::For => {
                // Try to extract init, condition, update
                let (condition, body_start) = self.get_while_condition(header, &info);
                let body = if let Some(start) = body_start {
                    self.structure_region(start, Some(header))
                } else {
                    vec![]
                };

                // For simplicity, emit as while (init/update detection is complex)
                StructuredNode::While {
                    condition,
                    body,
                    header: Some(header),
                    exit_block,
                }
            }
        }
    }

    fn structure_loop_body(
        &mut self,
        header: BasicBlockId,
        info: &LoopInfo,
    ) -> Vec<StructuredNode> {
        let block = match self.cfg.block(header) {
            Some(b) => b,
            None => return vec![],
        };

        let statements = self.block_to_statements(header);
        let mut result = vec![];

        if !statements.is_empty() {
            result.push(StructuredNode::Block {
                id: header,
                statements,
                address_range: (block.start, block.end),
            });
        }

        // Continue with successors that are in the loop
        let succs: Vec<_> = self
            .cfg
            .successors(header)
            .iter()
            .filter(|s| info.body.contains(s) && **s != header)
            .copied()
            .collect();

        if let Some(&next) = succs.first() {
            let mut rest = self.structure_region(next, Some(header));
            result.append(&mut rest);
        }

        result
    }

    fn get_while_condition(
        &self,
        header: BasicBlockId,
        info: &LoopInfo,
    ) -> (Expr, Option<BasicBlockId>) {
        let block = match self.cfg.block(header) {
            Some(b) => b,
            None => return (Expr::int(1), None),
        };

        if let BlockTerminator::ConditionalBranch {
            condition,
            true_target,
            false_target,
            ..
        } = &block.terminator
        {
            let true_in_loop = info.body.contains(true_target);
            let false_in_loop = info.body.contains(false_target);

            let cond_expr = self.rewrite_condition_call_return_alias(
                header,
                condition_to_expr_with_block(*condition, block),
            );

            if true_in_loop && !false_in_loop {
                // Condition true -> stay in loop
                (cond_expr, Some(*true_target))
            } else if !true_in_loop && false_in_loop {
                // Condition false -> stay in loop (invert)
                (negate_condition(cond_expr), Some(*false_target))
            } else {
                (cond_expr, Some(*true_target))
            }
        } else {
            (Expr::int(1), self.cfg.successors(header).first().copied())
        }
    }

    fn get_dowhile_condition(&self, info: &LoopInfo) -> (Expr, BasicBlockId) {
        for &back_edge in &info.back_edges {
            let block = match self.cfg.block(back_edge) {
                Some(b) => b,
                None => continue,
            };

            if let BlockTerminator::ConditionalBranch {
                condition,
                true_target,
                false_target,
                ..
            } = &block.terminator
            {
                let cond_expr = self.rewrite_condition_call_return_alias(
                    back_edge,
                    condition_to_expr_with_block(*condition, block),
                );
                if *true_target == info.header {
                    return (cond_expr, back_edge);
                } else if *false_target == info.header {
                    return (negate_condition(cond_expr), back_edge);
                }
            }
        }

        (Expr::int(1), info.header)
    }

    fn structure_if_else(
        &mut self,
        condition: Condition,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
        region_end: Option<BasicBlockId>,
        block_id: BasicBlockId,
        block: &BasicBlock,
    ) -> StructuredNode {
        let cond_expr = self.rewrite_condition_call_return_alias(
            block_id,
            condition_to_expr_with_block(condition, block),
        );

        // Find join point
        let join = self.find_join_point(true_target, false_target, region_end);

        // Structure then branch
        let then_body = self.structure_region(true_target, join);

        // Structure else branch (if it's not the join point)
        let else_body = if join != Some(false_target) {
            let body = self.structure_region(false_target, join);
            if body.is_empty() {
                None
            } else {
                Some(body)
            }
        } else {
            None
        };

        StructuredNode::If {
            condition: cond_expr,
            then_body,
            else_body,
        }
    }

    /// In blocks entered from a call-terminated predecessor, treat arg0/x0/w0
    /// as a call return value alias in condition expressions.
    fn rewrite_condition_call_return_alias(&self, block_id: BasicBlockId, expr: Expr) -> Expr {
        use super::expression::{VarKind, Variable};

        let preds = self.cfg.predecessors(block_id);
        if preds.len() != 1 {
            return expr;
        }
        let pred = preds[0];
        let Some(pred_block) = self.cfg.block(pred) else {
            return expr;
        };
        let Some(last_inst) = pred_block.instructions.last() else {
            return expr;
        };
        if !last_inst.is_call() {
            return expr;
        }

        let replacement = Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: "ret_0".to_string(),
            size: 8,
        });
        let aliases = vec![
            "arg0".to_string(),
            "x0".to_string(),
            "w0".to_string(),
            "a0".to_string(),
        ];
        substitute_return_register_uses(expr, &aliases, &replacement)
    }

    /// Structures a switch statement from recovered switch information.
    fn structure_switch_from_recovery(
        &mut self,
        switch_info: super::switch_recovery::SwitchInfo,
    ) -> StructuredNode {
        // Find the join point where all switch cases converge
        // This prevents cases from including code from subsequent cases
        let switch_end = self.find_switch_join_point(&switch_info);

        // Structure each case body, stopping at the join point
        let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = switch_info
            .cases
            .into_iter()
            .map(|(values, target)| {
                let body = self.structure_region(target, switch_end);
                (values, body)
            })
            .collect();

        // Sort cases by their minimum value for readability
        cases.sort_by_key(|(values, _)| values.iter().min().copied().unwrap_or(0));

        // Structure the default case if present
        // But skip if it's already been processed (e.g., by the bounds check if-else)
        let default = switch_info.default.and_then(|target| {
            if self.processed.contains(&target) {
                // Default was already structured by bounds check, skip it
                None
            } else {
                Some(self.structure_region(target, switch_end))
            }
        });

        StructuredNode::Switch {
            value: switch_info.switch_value,
            cases,
            default,
        }
    }

    /// Find the common join point where all switch cases converge.
    fn find_switch_join_point(
        &self,
        switch_info: &super::switch_recovery::SwitchInfo,
    ) -> Option<BasicBlockId> {
        // Collect all case targets (including default)
        let mut targets: Vec<BasicBlockId> = switch_info
            .cases
            .iter()
            .map(|(_, target)| *target)
            .collect();
        if let Some(default) = switch_info.default {
            targets.push(default);
        }

        if targets.is_empty() {
            return None;
        }

        // Find blocks reachable from each target
        let mut reachable_sets: Vec<HashSet<BasicBlockId>> = Vec::new();
        for target in &targets {
            let mut reachable = HashSet::new();
            self.collect_reachable(*target, &mut reachable, None);
            reachable_sets.push(reachable);
        }

        // Find blocks reachable from ALL targets (intersection)
        if reachable_sets.is_empty() {
            return None;
        }

        let mut common = reachable_sets[0].clone();
        for set in reachable_sets.iter().skip(1) {
            common = common.intersection(set).copied().collect();
        }

        // Remove the case blocks themselves from candidates
        for target in &targets {
            common.remove(target);
        }

        if common.is_empty() {
            return None;
        }

        // Return the first one in reverse post-order (closest to switch)
        let rpo = self.cfg.reverse_post_order();
        rpo.into_iter().find(|&block| common.contains(&block))
    }

    fn find_join_point(
        &self,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
        region_end: Option<BasicBlockId>,
    ) -> Option<BasicBlockId> {
        // Use dominator information to find where paths converge
        let _dominators = self.cfg.compute_dominators();

        // Find blocks reachable from both branches
        let mut true_reachable = HashSet::new();
        let mut false_reachable = HashSet::new();

        self.collect_reachable(true_target, &mut true_reachable, region_end);
        self.collect_reachable(false_target, &mut false_reachable, region_end);

        // Find common reachable blocks
        let common: Vec<_> = true_reachable
            .intersection(&false_reachable)
            .copied()
            .collect();

        // Return the first one in reverse post-order (closest to branches)
        let rpo = self.cfg.reverse_post_order();
        for block in rpo {
            if common.contains(&block) {
                return Some(block);
            }
        }

        region_end
    }

    fn collect_reachable(
        &self,
        start: BasicBlockId,
        reachable: &mut HashSet<BasicBlockId>,
        end: Option<BasicBlockId>,
    ) {
        let mut worklist = vec![start];

        while let Some(block) = worklist.pop() {
            if Some(block) == end || !reachable.insert(block) {
                continue;
            }
            for &succ in self.cfg.successors(block) {
                worklist.push(succ);
            }
        }
    }

    fn block_to_statements(&self, block_id: BasicBlockId) -> Vec<Expr> {
        let block = match self.cfg.block(block_id) {
            Some(b) => b,
            None => return vec![],
        };

        // Check if block ends with conditional branch
        let has_conditional_branch =
            matches!(block.terminator, BlockTerminator::ConditionalBranch { .. });

        // Find the index of the compare instruction if the block ends with a conditional
        let compare_idx = if has_conditional_branch {
            block.instructions.iter().rposition(|inst| {
                matches!(
                    inst.operation,
                    Operation::Compare | Operation::Test | Operation::Sub
                )
            })
        } else {
            None
        };

        let exprs: Vec<Expr> = block
            .instructions
            .iter()
            .enumerate()
            .filter(|(idx, inst)| {
                // Skip branch instructions, but keep calls
                if inst.is_branch() && !inst.is_call() {
                    return false;
                }
                // Skip the compare/subs instruction if it's used for a conditional branch
                if let Some(cmp_idx) = compare_idx {
                    if *idx == cmp_idx {
                        return false;
                    }
                }
                true
            })
            .flat_map(|(_, inst)| {
                // Special handling for SETcc and CMOVcc to use block context
                let main_expr = match inst.operation {
                    Operation::SetConditional => lift_setcc_with_context(inst, block),
                    Operation::ConditionalMove => lift_cmovcc_with_context(inst, block),
                    _ => Expr::from_instruction(inst),
                };

                // Generate writeback expressions for post-indexed loads/stores
                let writeback = generate_writeback_expr(inst);

                if let Some(wb) = writeback {
                    vec![main_expr, wb]
                } else {
                    vec![main_expr]
                }
            })
            .collect();

        // Resolve ADRP + ADD patterns (ARM64 PC-relative addressing)
        resolve_adrp_patterns(exprs)
    }
}

/// Try to extract condition from ARM64 CBZ/CBNZ/TBZ/TBNZ instructions.
///
/// These instructions have the comparison built into the branch:
/// - CBZ reg, target: branch if reg == 0
/// - CBNZ reg, target: branch if reg != 0
/// - TBZ reg, #bit, target: branch if bit is clear
/// - TBNZ reg, #bit, target: branch if bit is set
fn try_extract_arm64_branch_condition(
    block: &BasicBlock,
    op: BinOpKind,
    reg_values: &HashMap<String, Expr>,
) -> Option<Expr> {
    // Find the last ConditionalJump instruction (CBZ/CBNZ/TBZ/TBNZ)
    let branch_inst = block
        .instructions
        .iter()
        .rev()
        .find(|inst| matches!(inst.operation, Operation::ConditionalJump))?;

    let mnemonic = branch_inst.mnemonic.to_lowercase();

    // Check for CBZ/CBNZ (Compare and Branch if Zero/Not Zero)
    if mnemonic == "cbz" || mnemonic == "cbnz" {
        // Operands: [reg, pc_rel_target]
        if !branch_inst.operands.is_empty() {
            let reg_expr = substitute_register_in_expr(
                Expr::from_operand_with_inst(&branch_inst.operands[0], branch_inst),
                reg_values,
            );
            // CBZ: reg == 0, CBNZ: reg != 0
            // The condition (Equal/NotEqual) is already encoded, so just use op
            return Some(Expr::binop(op, reg_expr, Expr::int(0)));
        }
    }

    // Check for TBZ/TBNZ (Test and Branch if Zero/Not Zero)
    if mnemonic == "tbz" || mnemonic == "tbnz" {
        // Operands: [reg, bit_pos, pc_rel_target]
        if branch_inst.operands.len() >= 2 {
            let reg_expr = substitute_register_in_expr(
                Expr::from_operand_with_inst(&branch_inst.operands[0], branch_inst),
                reg_values,
            );

            // Extract bit position
            if let hexray_core::Operand::Immediate(imm) = &branch_inst.operands[1] {
                let bit_pos = imm.value;
                // Create bit test expression: (reg >> bit_pos) & 1
                let shifted = Expr::binop(BinOpKind::Shr, reg_expr, Expr::int(bit_pos));
                let masked = Expr::binop(BinOpKind::And, shifted, Expr::int(1));
                // TBZ: bit == 0, TBNZ: bit != 0
                return Some(Expr::binop(op, masked, Expr::int(0)));
            }
        }
    }

    None
}

/// Checks if an instruction sets CPU flags that can be used for conditional branches.
/// Returns true for comparison instructions (CMP, TEST), arithmetic operations (ADD, SUB, INC, DEC),
/// and logical operations (AND, OR, XOR) that affect condition codes.
fn is_flag_setting_instruction(inst: &Instruction) -> bool {
    match inst.operation {
        // Explicit comparison instructions
        Operation::Compare | Operation::Test => true,

        // Arithmetic operations that set flags
        Operation::Add | Operation::Sub | Operation::Inc | Operation::Dec | Operation::Neg => true,

        // Logical operations - on ARM64 only set flags with 's' suffix, on x86 always set flags
        Operation::And | Operation::Or | Operation::Xor => {
            // Check if this is ARM instruction with 's' suffix (ANDS, ORRS, EORS)
            // or x86 instruction (and, or, xor)
            inst.mnemonic.ends_with('s')
                || inst.mnemonic == "and"
                || inst.mnemonic == "or"
                || inst.mnemonic == "xor"
        }

        // Shift operations that set flags
        Operation::Shl | Operation::Shr | Operation::Sar => true,

        _ => false,
    }
}

/// Converts a Condition to an Expr, extracting operands from the block's compare instruction.
/// Also substitutes register names with their values from preceding MOV instructions.
fn condition_to_expr_with_block(cond: Condition, block: &BasicBlock) -> Expr {
    // Find the last compare in the block (no address limit)
    condition_to_expr_before_address(cond, block, None)
}

/// Converts a Condition to an Expr, finding the compare instruction before the given address.
/// This is needed for ARM64 CMP+CSEL chains where each CSEL uses a different preceding CMP.
fn condition_to_expr_before_address(
    cond: Condition,
    block: &BasicBlock,
    before_addr: Option<u64>,
) -> Expr {
    let op = match cond {
        Condition::Equal => BinOpKind::Eq,
        Condition::NotEqual => BinOpKind::Ne,
        Condition::Less => BinOpKind::Lt,
        Condition::LessOrEqual => BinOpKind::Le,
        Condition::Greater => BinOpKind::Gt,
        Condition::GreaterOrEqual => BinOpKind::Ge,
        Condition::Below => BinOpKind::ULt,
        Condition::BelowOrEqual => BinOpKind::ULe,
        Condition::Above => BinOpKind::UGt,
        Condition::AboveOrEqual => BinOpKind::UGe,
        // Sign/NotSign: after CMP x, y, MI is set when x - y < 0 (signed)
        Condition::Sign => BinOpKind::Lt,
        Condition::NotSign => BinOpKind::Ge,
        _ => BinOpKind::Ne, // Default for flag-based conditions
    };

    // Build a map of register values from MOV instructions before the compare
    let reg_values = build_register_value_map(block);

    // Check for ARM64 CBZ/CBNZ/TBZ/TBNZ instructions first
    // These have the comparison built into the branch instruction itself
    if let Some(cond_expr) = try_extract_arm64_branch_condition(block, op, &reg_values) {
        return cond_expr;
    }

    // Find the last flag-setting instruction in the block (before the given address if specified)
    // This includes CMP, TEST, SUB, NEG, ADD, INC, DEC, AND, OR, XOR, and shift operations
    let compare_inst = block
        .instructions
        .iter()
        .rev()
        .filter(|inst| {
            // If before_addr is specified, only consider instructions before that address
            before_addr.map_or(true, |addr| inst.address < addr)
        })
        .find(|inst| is_flag_setting_instruction(inst));

    if let Some(inst) = compare_inst {
        // For NEG instructions, flags reflect the negated result
        // neg eax: SF set if (-eax) < 0, i.e., eax > 0
        // For Sign condition after NEG, we need "operand > 0" (or < 0 for inverted)
        if matches!(inst.operation, Operation::Neg) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            // NEG sets SF if result is negative, meaning original was positive
            // So Sign (SF) after NEG means original > 0
            let neg_op = match cond {
                Condition::Sign => BinOpKind::Gt,    // SF set means orig > 0
                Condition::NotSign => BinOpKind::Le, // SF clear means orig <= 0
                _ => op,                             // Use default mapping for other conditions
            };
            return Expr::binop(neg_op, operand, Expr::int(0));
        }

        // INC/DEC: compare result against 0
        if matches!(inst.operation, Operation::Inc | Operation::Dec) && !inst.operands.is_empty() {
            let operand = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let adjustment = if matches!(inst.operation, Operation::Inc) {
                1
            } else {
                -1
            };
            let result = Expr::binop(BinOpKind::Add, operand, Expr::int(adjustment));
            return Expr::binop(op, result, Expr::int(0));
        }

        // ADD (3 operands): ARM64 ADDS
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Add) {
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, src1, src2);
            return Expr::binop(op, result, Expr::int(0));
        }

        // ADD (2 operands): x86 ADD
        if inst.operands.len() == 2 && matches!(inst.operation, Operation::Add) {
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let result = Expr::binop(BinOpKind::Add, dst, src);
            return Expr::binop(op, result, Expr::int(0));
        }

        // For SUB/SUBS instructions (ARM64), operands are [dst, src1, src2]
        // The comparison is between src1 and src2
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Sub) {
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let right = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            return Expr::binop(op, left, right);
        } else if inst.operands.len() >= 3
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            // ARM64: ANDS/ORRS/EORS dst, src1, src2
            let src1 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );
            let src2 = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[2], inst),
                &reg_values,
            );
            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, src1, src2);
            return Expr::binop(op, result, Expr::int(0));
        } else if inst.operands.len() == 2
            && matches!(
                inst.operation,
                Operation::And | Operation::Or | Operation::Xor
            )
        {
            // x86: AND/OR/XOR dst, src
            let dst = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let src = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );

            // Special case: XOR reg, reg clears to 0
            if matches!(inst.operation, Operation::Xor) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, Expr::int(0), Expr::int(0));
            }

            let binop_kind = match inst.operation {
                Operation::And => BinOpKind::And,
                Operation::Or => BinOpKind::Or,
                Operation::Xor => BinOpKind::Xor,
                _ => unreachable!(),
            };
            let result = Expr::binop(binop_kind, dst, src);
            return Expr::binop(op, result, Expr::int(0));
        } else if inst.operands.len() >= 2 {
            // For CMP/TEST instructions, operands are [src1, src2]
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            let right = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[1], inst),
                &reg_values,
            );

            // Special case: TEST reg, reg (same register) is a zero check
            // test eax, eax; je → jump if eax == 0
            // test eax, eax; jne → jump if eax != 0
            if matches!(inst.operation, Operation::Test) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, left, Expr::int(0));
            }

            return Expr::binop(op, left, right);
        } else if inst.operands.len() == 1 {
            // Compare against zero (common for test/cmp with single operand)
            let left = substitute_register_in_expr(
                Expr::from_operand_with_inst(&inst.operands[0], inst),
                &reg_values,
            );
            return Expr::binop(op, left, Expr::int(0));
        }
    }

    // Fallback: show condition check on flags if no compare found
    // This is more informative than generic placeholders
    let flag_name = match cond {
        Condition::Equal | Condition::NotEqual => "ZF",
        Condition::Less | Condition::GreaterOrEqual => "SF^OF",
        Condition::Greater | Condition::LessOrEqual => "SF^OF|ZF",
        Condition::Below | Condition::AboveOrEqual => "CF",
        Condition::Above | Condition::BelowOrEqual => "CF|ZF",
        Condition::Sign | Condition::NotSign => "SF",
        Condition::Overflow | Condition::NotOverflow => "OF",
        Condition::Parity | Condition::NotParity => "PF",
        _ => "flags",
    };
    Expr::binop(op, Expr::unknown(flag_name), Expr::int(0))
}

/// Builds a map of register names to their values from MOV/LDR instructions in a block.
/// This is used to substitute register names in conditions with meaningful variable names.
///
/// Special handling for return value captures: when the block starts with `mov dest, ret_reg`,
/// we map the return register (eax/rax/x0) to the destination register. This ensures
/// that conditions like `test eax, eax` display as `if (ebx == 0)` when we've merged
/// the call into `ebx = func()`.
fn build_register_value_map(block: &BasicBlock) -> HashMap<String, Expr> {
    use super::expression::{VarKind, Variable};
    use hexray_core::Operand;

    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut at_block_start = true;
    let mut saw_call = false;
    let mut ret_capture_counter: u32 = 0;

    for inst in &block.instructions {
        // Track if we've seen a call instruction
        if inst.is_call() {
            saw_call = true;
            // Model call return register as a unique temporary to avoid reusing arg names.
            let temp_name = format!("ret_{}", ret_capture_counter);
            ret_capture_counter += 1;
            let ret_var64 = Expr::var(Variable {
                name: temp_name.clone(),
                kind: VarKind::Temp(ret_capture_counter),
                size: 8,
            });
            let ret_var32 = Expr::var(Variable {
                name: temp_name.clone(),
                kind: VarKind::Temp(ret_capture_counter),
                size: 4,
            });
            reg_values.insert("rax".to_string(), ret_var64.clone());
            reg_values.insert("eax".to_string(), ret_var32.clone());
            reg_values.insert("x0".to_string(), ret_var64);
            reg_values.insert("w0".to_string(), ret_var32.clone());
            reg_values.insert("a0".to_string(), ret_var32);
            reg_values.insert(
                "arg0".to_string(),
                Expr::var(Variable {
                    name: temp_name,
                    kind: VarKind::Temp(ret_capture_counter),
                    size: 8,
                }),
            );
            at_block_start = false;
            continue;
        }

        // Look for MOV instructions (x86-64)
        if matches!(inst.operation, Operation::Move) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();

                // Check if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand_with_inst(&inst.operands[1], inst);
                    reg_values.insert(dst_name, value);
                    at_block_start = false;
                }
                // Check for return value capture: mov dest, ret_reg at block start or after call
                // At block start, the previous block likely ended with a call
                // Only substitute if destination is a callee-saved register (indicating
                // the value is being preserved across calls, not just temporarily stored)
                else if at_block_start || saw_call {
                    if let Operand::Register(src_reg) = &inst.operands[1] {
                        let src_name = src_reg.name().to_lowercase();
                        // Return registers: eax/rax (x86-64), x0/w0 (ARM64)
                        if matches!(src_name.as_str(), "eax" | "rax" | "x0" | "w0") {
                            // Only substitute if destination is callee-saved
                            // x86-64: rbx, rbp, r12-r15 (and their 32-bit variants)
                            // ARM64: x19-x28
                            if is_callee_saved_register(&dst_name) {
                                // Map the return register to the destination variable
                                // So `eax` in conditions becomes `ebx` when we have `mov ebx, eax`
                                let dest_var = super::expression::Variable {
                                    name: dst_name.clone(),
                                    kind: super::expression::VarKind::Register(dst_reg.id),
                                    size: (dst_reg.size / 8) as u8,
                                };
                                reg_values.insert(src_name, Expr::var(dest_var));
                            }
                            at_block_start = false;
                            saw_call = false;
                        }
                    }
                }
            }
        }

        // Look for LDR instructions (ARM64): ldr reg, [sp, #offset]
        if matches!(inst.operation, Operation::Load) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source (memory)
            if let Operand::Register(reg) = &inst.operands[0] {
                let reg_name = reg.name().to_lowercase();
                // Track if source is a memory operand (stack variable or global)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand_with_inst(&inst.operands[1], inst);
                    reg_values.insert(reg_name, value);
                }
            }
            at_block_start = false;
        }

        // Reset saw_call after any non-move instruction (except test/cmp which follow immediately)
        if !matches!(
            inst.operation,
            Operation::Move | Operation::Compare | Operation::Test
        ) {
            saw_call = false;
            at_block_start = false;
        }
    }

    reg_values
}

/// Substitutes register references in an expression with their known values.
fn substitute_register_in_expr(expr: Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    use super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(v) => {
            // Check if this variable name is a register we have a value for
            let lower_name = v.name.to_lowercase();
            if let Some(value) = reg_values.get(&lower_name) {
                value.clone()
            } else {
                expr
            }
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_register_in_expr((**left).clone(), reg_values),
            substitute_register_in_expr((**right).clone(), reg_values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(
            *op,
            substitute_register_in_expr((**operand).clone(), reg_values),
        ),
        ExprKind::Deref { addr, size } => Expr::deref(
            substitute_register_in_expr((**addr).clone(), reg_values),
            *size,
        ),
        _ => expr,
    }
}

/// Simple condition conversion without block context (fallback).
fn condition_to_expr(cond: Condition) -> Expr {
    let op = match cond {
        Condition::Equal => BinOpKind::Eq,
        Condition::NotEqual => BinOpKind::Ne,
        Condition::Less => BinOpKind::Lt,
        Condition::LessOrEqual => BinOpKind::Le,
        Condition::Greater => BinOpKind::Gt,
        Condition::GreaterOrEqual => BinOpKind::Ge,
        Condition::Below => BinOpKind::ULt,
        Condition::BelowOrEqual => BinOpKind::ULe,
        Condition::Above => BinOpKind::UGt,
        Condition::AboveOrEqual => BinOpKind::UGe,
        _ => BinOpKind::Ne,
    };
    // Fallback: show condition check on flags
    let flag_name = match cond {
        Condition::Equal | Condition::NotEqual => "ZF",
        Condition::Less | Condition::GreaterOrEqual => "SF^OF",
        Condition::Greater | Condition::LessOrEqual => "SF^OF|ZF",
        Condition::Below | Condition::AboveOrEqual => "CF",
        Condition::Above | Condition::BelowOrEqual => "CF|ZF",
        Condition::Sign | Condition::NotSign => "SF",
        Condition::Overflow | Condition::NotOverflow => "OF",
        Condition::Parity | Condition::NotParity => "PF",
        _ => "flags",
    };
    Expr::binop(op, Expr::unknown(flag_name), Expr::int(0))
}

/// Negates a condition expression.
fn negate_condition(expr: Expr) -> Expr {
    match &expr.kind {
        super::expression::ExprKind::BinOp { op, left, right } => {
            let negated_op = match op {
                BinOpKind::Eq => Some(BinOpKind::Ne),
                BinOpKind::Ne => Some(BinOpKind::Eq),
                BinOpKind::Lt => Some(BinOpKind::Ge),
                BinOpKind::Le => Some(BinOpKind::Gt),
                BinOpKind::Gt => Some(BinOpKind::Le),
                BinOpKind::Ge => Some(BinOpKind::Lt),
                BinOpKind::ULt => Some(BinOpKind::UGe),
                BinOpKind::ULe => Some(BinOpKind::UGt),
                BinOpKind::UGt => Some(BinOpKind::ULe),
                BinOpKind::UGe => Some(BinOpKind::ULt),
                _ => None,
            };
            if let Some(negated) = negated_op {
                Expr::binop(negated, (**left).clone(), (**right).clone())
            } else {
                Expr::unary(super::expression::UnaryOpKind::LogicalNot, expr)
            }
        }
        _ => Expr::unary(super::expression::UnaryOpKind::LogicalNot, expr),
    }
}

/// Parses the condition suffix from a SETcc or CMOVcc mnemonic.
/// Returns None if the mnemonic doesn't have a recognized condition suffix.
fn parse_condition_from_mnemonic(mnemonic: &str) -> Option<Condition> {
    // Handle ARM64 style: cset.eq, cinc.ne, csetm.mi, etc.
    if let Some(dot_pos) = mnemonic.find('.') {
        let prefix = &mnemonic[..dot_pos];
        let suffix = &mnemonic[dot_pos + 1..];
        // Check for ARM64 conditional instructions
        if matches!(
            prefix,
            "cset" | "csetm" | "cinc" | "cinv" | "cneg" | "csel" | "csinc" | "csinv" | "csneg"
        ) {
            return parse_arm64_condition(suffix);
        }
    }

    // Handle x86 style: sete, cmovne, etc.
    let suffix = if let Some(s) = mnemonic.strip_prefix("set") {
        s
    } else if let Some(s) = mnemonic.strip_prefix("cmov") {
        s
    } else {
        return None;
    };

    // Map x86 suffix to Condition
    match suffix {
        "e" | "z" => Some(Condition::Equal),
        "ne" | "nz" => Some(Condition::NotEqual),
        "l" | "nge" => Some(Condition::Less),
        "le" | "ng" => Some(Condition::LessOrEqual),
        "g" | "nle" => Some(Condition::Greater),
        "ge" | "nl" => Some(Condition::GreaterOrEqual),
        "b" | "c" | "nae" => Some(Condition::Below),
        "be" | "na" => Some(Condition::BelowOrEqual),
        "a" | "nbe" => Some(Condition::Above),
        "ae" | "nc" | "nb" => Some(Condition::AboveOrEqual),
        "s" => Some(Condition::Sign),
        "ns" => Some(Condition::NotSign),
        "o" => Some(Condition::Overflow),
        "no" => Some(Condition::NotOverflow),
        "p" | "pe" => Some(Condition::Parity),
        "np" | "po" => Some(Condition::NotParity),
        _ => None,
    }
}

/// Parse ARM64 condition code suffixes
fn parse_arm64_condition(suffix: &str) -> Option<Condition> {
    match suffix {
        "eq" => Some(Condition::Equal),
        "ne" => Some(Condition::NotEqual),
        "lt" => Some(Condition::Less),
        "le" => Some(Condition::LessOrEqual),
        "gt" => Some(Condition::Greater),
        "ge" => Some(Condition::GreaterOrEqual),
        // Unsigned comparisons
        "lo" | "cc" => Some(Condition::Below), // Carry Clear = Below
        "ls" => Some(Condition::BelowOrEqual), // Lower or Same
        "hi" => Some(Condition::Above),        // Higher
        "hs" | "cs" => Some(Condition::AboveOrEqual), // Carry Set = Above or Equal
        // Sign/overflow
        "mi" => Some(Condition::Sign),        // Negative (minus)
        "pl" => Some(Condition::NotSign),     // Positive or zero (plus)
        "vs" => Some(Condition::Overflow),    // Overflow set
        "vc" => Some(Condition::NotOverflow), // Overflow clear
        // "al" (always) shouldn't appear in cset - just ignore it
        _ => None,
    }
}

/// Generates a writeback expression for post-indexed load/store instructions.
///
/// For ARM64 post-indexed addressing like `ldrb w9, [x8], #1`:
/// - The main load is: w9 = *x8
/// - The writeback is: x8 = x8 + 1
///
/// Returns None if no writeback is needed.
fn generate_writeback_expr(inst: &hexray_core::Instruction) -> Option<Expr> {
    use super::expression::{ExprKind, VarKind, Variable};

    // Check if this is a load or store operation
    if !matches!(inst.operation, Operation::Load | Operation::Store) {
        return None;
    }

    // Find the memory operand with pre/post-indexed mode
    for operand in &inst.operands {
        if let Operand::Memory(mem) = operand {
            if mem.index_mode == IndexMode::Post || mem.index_mode == IndexMode::Pre {
                // Both pre and post-indexed have writeback: base = base + displacement
                if let Some(base_reg) = &mem.base {
                    let base_name = base_reg.name().to_lowercase();
                    let base_var = Expr {
                        kind: ExprKind::Var(Variable {
                            name: base_name.clone(),
                            kind: VarKind::Register(base_reg.id),
                            size: (base_reg.size / 8) as u8,
                        }),
                    };

                    // Create: base = base + displacement
                    let offset_expr = Expr::int(mem.displacement as i128);
                    let add_expr = Expr::binop(BinOpKind::Add, base_var.clone(), offset_expr);
                    return Some(Expr::assign(base_var, add_expr));
                }
            }
        }
    }

    None
}

/// Lifts a SETcc instruction with block context to get the actual comparison.
/// Returns an expression like: dest = (left op right)
/// For ARM64 CSEL: dest = cond ? src1 : src2
fn lift_setcc_with_context(inst: &hexray_core::Instruction, block: &BasicBlock) -> Expr {
    let dest = if !inst.operands.is_empty() {
        Expr::from_operand_with_inst(&inst.operands[0], inst)
    } else {
        Expr::unknown(&inst.mnemonic)
    };

    // Check for ARM64 conditional instructions
    let mnem_lower = inst.mnemonic.to_lowercase();
    if let Some(dot_pos) = mnem_lower.find('.') {
        let prefix = &mnem_lower[..dot_pos];

        // CSEL/CSINC/CSINV/CSNEG have 3 operands: rd, rn, rm
        // rd = cond ? rn : rm (or variant)
        if matches!(prefix, "csel" | "csinc" | "csinv" | "csneg") && inst.operands.len() >= 3 {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
                let then_expr = Expr::from_operand_with_inst(&inst.operands[1], inst);
                let else_expr = Expr::from_operand_with_inst(&inst.operands[2], inst);

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(else_expr),
                        },
                    },
                );
            }
        }

        // CINC/CINV/CNEG have 2 operands: rd, rn
        // cinc: rd = cond ? rn+1 : rn
        // cinv: rd = cond ? ~rn : rn
        // cneg: rd = cond ? -rn : rn
        if matches!(prefix, "cinc" | "cinv" | "cneg") && inst.operands.len() >= 2 {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));
                let src_expr = Expr::from_operand_with_inst(&inst.operands[1], inst);

                let then_expr = match prefix {
                    "cinc" => Expr::binop(
                        super::expression::BinOpKind::Add,
                        src_expr.clone(),
                        Expr::int(1),
                    ),
                    "cinv" => Expr::unary(super::expression::UnaryOpKind::Not, src_expr.clone()),
                    "cneg" => Expr::unary(super::expression::UnaryOpKind::Neg, src_expr.clone()),
                    _ => src_expr.clone(),
                };

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_expr),
                            else_expr: Box::new(src_expr),
                        },
                    },
                );
            }
        }

        // CSET/CSETM have 1 operand: rd
        // cset: rd = cond ? 1 : 0
        // csetm: rd = cond ? -1 : 0
        if matches!(prefix, "cset" | "csetm") && !inst.operands.is_empty() {
            if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
                let cond_expr = condition_to_expr_before_address(cond, block, Some(inst.address));

                let (then_val, else_val) = if prefix == "csetm" {
                    (Expr::int(-1), Expr::int(0))
                } else {
                    (Expr::int(1), Expr::int(0))
                };

                return Expr::assign(
                    dest,
                    Expr {
                        kind: super::expression::ExprKind::Conditional {
                            cond: Box::new(cond_expr),
                            then_expr: Box::new(then_val),
                            else_expr: Box::new(else_val),
                        },
                    },
                );
            }
        }
    }

    // Try to parse condition from mnemonic (for CSET, SETcc, etc.)
    if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
        // Get the comparison expression using the block context
        let cond_expr = condition_to_expr_with_block(cond, block);
        // Assign the boolean result to the destination
        Expr::assign(dest, cond_expr)
    } else {
        // Fallback: emit as function call if we can't parse the condition
        Expr::assign(
            dest,
            Expr::call(
                super::expression::CallTarget::Named(inst.mnemonic.clone()),
                vec![],
            ),
        )
    }
}

/// Lifts a CMOVcc instruction with block context.
/// Returns an expression like: dest = condition ? src : dest
/// For simplicity, we emit: if (condition) dest = src
fn lift_cmovcc_with_context(inst: &hexray_core::Instruction, block: &BasicBlock) -> Expr {
    if inst.operands.len() < 2 {
        return Expr::unknown(&inst.mnemonic);
    }

    let dest = Expr::from_operand_with_inst(&inst.operands[0], inst);
    let src = Expr::from_operand_with_inst(&inst.operands[1], inst);

    // Try to parse condition from mnemonic
    if let Some(cond) = parse_condition_from_mnemonic(&inst.mnemonic) {
        // Get the comparison expression
        let cond_expr = condition_to_expr_with_block(cond, block);
        // Emit as conditional: dest = (cond) ? src : dest
        Expr::assign(
            dest.clone(),
            Expr {
                kind: super::expression::ExprKind::Conditional {
                    cond: Box::new(cond_expr),
                    then_expr: Box::new(src),
                    else_expr: Box::new(dest),
                },
            },
        )
    } else {
        // Fallback: emit as function call
        Expr::assign(
            dest,
            Expr::call(
                super::expression::CallTarget::Named(inst.mnemonic.clone()),
                vec![src],
            ),
        )
    }
}

/// Extracts the return value from a return register assignment near the end of the block.
/// Returns the filtered statements (without the return value assignment) and the return value.
/// Looks backwards through statements to find the last assignment to a return register,
/// skipping over prologue/epilogue statements like pop(rbp).
fn extract_return_value(statements: Vec<Expr>) -> (Vec<Expr>, Option<Expr>) {
    use super::expression::ExprKind;

    // First pass: build a map of temp register values for substitution
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    for stmt in &statements {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if is_temp_register(&v.name) {
                    // Substitute known values in RHS before storing
                    let substituted_rhs = substitute_vars(rhs, &reg_values);
                    reg_values.insert(v.name.clone(), substituted_rhs);
                }
            }
        }
    }

    let mut return_value = None;
    let mut indices_to_remove = Vec::new();

    // Search backwards for an assignment to a return register, collecting epilogue statements
    for i in (0..statements.len()).rev() {
        let stmt = &statements[i];

        // Check for return register assignment
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                // Check if this is assigning to a return register
                // x86: eax (32-bit), rax (64-bit)
                // ARM64: w0 (32-bit), x0 (64-bit)
                // RISC-V: a0
                let is_return_reg = matches!(v.name.as_str(), "eax" | "rax" | "w0" | "x0" | "a0");
                if is_return_reg {
                    // Use the fully substituted value from reg_values if available,
                    // otherwise substitute the RHS directly
                    return_value = Some(
                        reg_values
                            .get(&v.name)
                            .cloned()
                            .unwrap_or_else(|| substitute_vars(rhs, &reg_values)),
                    );
                    indices_to_remove.push(i);
                    break;
                }

                // ARM64 epilogue: frame pointer (x29) and link register (x30) restoration
                if v.name == "x29" || v.name == "x30" {
                    indices_to_remove.push(i);
                    continue;
                }

                // Stack pointer adjustments (sp/rsp = sp/rsp +/- X)
                let is_stack_ptr = v.name == "sp" || v.name == "rsp";
                if is_stack_ptr {
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(base) = &left.kind {
                            if base.name == "sp" || base.name == "rsp" {
                                indices_to_remove.push(i);
                                continue;
                            }
                        }
                    }
                }

                // Skip other temp register assignments (they'll be removed by propagate_copies later)
                if is_temp_register(&v.name) {
                    indices_to_remove.push(i);
                    continue;
                }
            }
        }

        // x86 epilogue: push/pop calls
        if let ExprKind::Call {
            target: super::expression::CallTarget::Named(name),
            ..
        } = &stmt.kind
        {
            if name == "push" || name == "pop" {
                indices_to_remove.push(i);
                continue;
            }
        }

        // If we hit a non-epilogue statement that's not a return reg assignment, stop
        break;
    }

    // Remove collected statements (in reverse order to preserve indices)
    let mut statements = statements;
    for i in indices_to_remove {
        statements.remove(i);
    }

    (statements, return_value)
}

/// Simplifies statements by performing copy propagation on temporary registers.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
fn simplify_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: collect all GotRef assignments
    let global_refs = collect_global_refs(&nodes);

    // Second pass: copy propagation per-block (keeps temp assignments for now)
    let nodes: Vec<_> = nodes.into_iter().map(simplify_node_copies).collect();

    // Third pass: propagate temp register values into conditions
    let nodes = propagate_temps_to_conditions(nodes);

    // Fourth pass: substitute global refs everywhere (including conditions).
    // This must run before removing temp assignments so block-local GOT aliases
    // (e.g., x8 = stdout/stderr) are still available for substitution.
    let nodes: Vec<_> = nodes
        .into_iter()
        .map(|node| substitute_globals_in_node(node, &global_refs))
        .collect();

    // Fifth pass: remove temp register assignments that have been propagated.
    let nodes = remove_temp_assignments(nodes);

    // Sixth pass: simplify all conditions (convert | to ||, & to && for comparisons, etc.)
    nodes.into_iter().map(simplify_conditions_in_node).collect()
}

/// Simplifies conditions in all nodes (convert | to ||, & to && for comparisons, etc.)
fn simplify_conditions_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: condition.simplify(),
            then_body: then_body
                .into_iter()
                .map(simplify_conditions_in_node)
                .collect(),
            else_body: else_body.map(|e| e.into_iter().map(simplify_conditions_in_node).collect()),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: condition.simplify(),
            body: body.into_iter().map(simplify_conditions_in_node).collect(),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: body.into_iter().map(simplify_conditions_in_node).collect(),
            condition: condition.simplify(),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(|e| e.simplify()),
            condition: condition.simplify(),
            update: update.map(|e| e.simplify()),
            body: body.into_iter().map(simplify_conditions_in_node).collect(),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: body.into_iter().map(simplify_conditions_in_node).collect(),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: value.simplify(),
            cases: cases
                .into_iter()
                .map(|(vals, body)| {
                    (
                        vals,
                        body.into_iter().map(simplify_conditions_in_node).collect(),
                    )
                })
                .collect(),
            default: default.map(|d| d.into_iter().map(simplify_conditions_in_node).collect()),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(nodes.into_iter().map(simplify_conditions_in_node).collect())
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: try_body
                .into_iter()
                .map(simplify_conditions_in_node)
                .collect(),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: h
                        .body
                        .into_iter()
                        .map(simplify_conditions_in_node)
                        .collect(),
                    ..h
                })
                .collect(),
        },
        // Other nodes don't have conditions to simplify
        other => other,
    }
}

/// Removes temp register assignments from all blocks that are not used elsewhere.
/// Uses liveness analysis to avoid removing temp assignments that are actually used
/// (e.g., loop accumulators).
fn remove_temp_assignments(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: collect all variable uses in the entire tree
    let mut uses = HashSet::new();
    collect_all_uses(&nodes, &mut uses);

    // Second pass: remove only temp assignments where the variable is not used
    nodes
        .into_iter()
        .map(|node| remove_temp_assignments_in_node(node, &uses))
        .collect()
}

/// Removes temp register assignments from a single node.
fn remove_temp_assignments_in_node(node: StructuredNode, uses: &HashSet<String>) -> StructuredNode {
    use super::expression::ExprKind;

    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements: Vec<_> = statements
                .into_iter()
                .filter(|stmt| {
                    if let ExprKind::Assign { lhs, .. } = &stmt.kind {
                        if let ExprKind::Var(v) = &lhs.kind {
                            // Don't remove argument register assignments - they may be setting up
                            // arguments for tail calls that appear as indirect jumps
                            if is_argument_register(&v.name) {
                                return true; // Keep argument register assignments
                            }
                            // Only remove temp assignments if the variable is NOT used elsewhere
                            if is_temp_register(&v.name) && !uses.contains(&v.name) {
                                return false; // Remove unused temp assignment
                            }
                        }
                    }
                    true
                })
                .collect();
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: then_body
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
            else_body: else_body.map(|e| {
                e.into_iter()
                    .map(|n| remove_temp_assignments_in_node(n, uses))
                    .collect()
            }),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: body
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: body
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: body
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: body
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| {
                    (
                        vals,
                        body.into_iter()
                            .map(|n| remove_temp_assignments_in_node(n, uses))
                            .collect(),
                    )
                })
                .collect(),
            default: default.map(|d| {
                d.into_iter()
                    .map(|n| remove_temp_assignments_in_node(n, uses))
                    .collect()
            }),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
            nodes
                .into_iter()
                .map(|n| remove_temp_assignments_in_node(n, uses))
                .collect(),
        ),
        other => other,
    }
}

/// Propagates temp register values from blocks into conditions of following control structures.
/// This handles patterns like:
///   tmp_a = x == 1;
///   if (tmp_a) { ... }
/// Transforming them to:
///   if (x == 1) { ... }
fn propagate_temps_to_conditions(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Treat the node list like a Sequence: propagate temps forward
    propagate_temps_in_node_list(nodes)
}

/// Propagates temps through a list of nodes, carrying temp values forward.
fn propagate_temps_in_node_list(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::with_capacity(nodes.len());
    let mut temps: HashMap<String, Expr> = HashMap::new();

    for node in nodes {
        // First, recursively process the node
        let node = propagate_temps_in_node(node);

        // Substitute current temps into conditions of this node
        let node = substitute_temps_in_conditions(node, &temps);

        // Collect temps from this node for subsequent nodes
        collect_temps_from_node(&node, &mut temps);

        result.push(node);
    }

    result
}

/// Propagates temp register values in a single node (without carrying forward temps).
/// This is used by the sequential propagation to recursively process nested structures.
fn propagate_temps_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        // For DoWhile, the body executes before the condition, so we can propagate
        // temp values from the body into the condition
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let body = propagate_temps_to_conditions(body);
            // Collect temp values from the body
            let temps = collect_temps_from_nodes(&body);
            // Substitute in condition
            let condition = substitute_vars(&condition, &temps);
            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            }
        }
        // For Sequences, use the sequential propagation
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(propagate_temps_in_node_list(nodes))
        }
        // Recursively process children for other structures
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: propagate_temps_to_conditions(then_body),
            else_body: else_body.map(propagate_temps_to_conditions),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: propagate_temps_to_conditions(body),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: propagate_temps_to_conditions(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: propagate_temps_to_conditions(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, propagate_temps_to_conditions(body)))
                .collect(),
            default: default.map(propagate_temps_to_conditions),
        },
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements,
            address_range,
        },
        // Pass through other nodes unchanged
        other => other,
    }
}

/// Collects temp register values from a list of nodes.
fn collect_temps_from_nodes(nodes: &[StructuredNode]) -> HashMap<String, Expr> {
    let mut temps = HashMap::new();
    for node in nodes {
        collect_temps_from_node(node, &mut temps);
    }
    temps
}

/// Collects temp register values from a single node.
fn collect_temps_from_node(node: &StructuredNode, temps: &mut HashMap<String, Expr>) {
    use super::expression::ExprKind;

    if let StructuredNode::Block { statements, .. } = node {
        for stmt in statements {
            match &stmt.kind {
                ExprKind::Assign { lhs, rhs } => {
                    if let ExprKind::Var(v) = &lhs.kind {
                        if is_temp_register(&v.name) {
                            // Substitute existing temps in the RHS
                            let rhs_substituted = substitute_vars(rhs, temps);
                            temps.insert(v.name.clone(), rhs_substituted);
                        }
                    }
                }
                ExprKind::CompoundAssign { op, lhs, rhs } => {
                    // Handle x |= y as x = x | y, etc.
                    if let ExprKind::Var(v) = &lhs.kind {
                        if is_temp_register(&v.name) {
                            // Get current value (or use the var itself if not tracked)
                            let lhs_val = temps
                                .get(&v.name)
                                .cloned()
                                .unwrap_or_else(|| (**lhs).clone());
                            let rhs_substituted = substitute_vars(rhs, temps);
                            // Build the compound expression
                            let new_val = Expr::binop(*op, lhs_val, rhs_substituted);
                            temps.insert(v.name.clone(), new_val);
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Substitutes temp values into conditions of a node.
fn substitute_temps_in_conditions(
    node: StructuredNode,
    temps: &HashMap<String, Expr>,
) -> StructuredNode {
    if temps.is_empty() {
        return node;
    }

    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: substitute_vars(&condition, temps),
            then_body,
            else_body,
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: substitute_vars(&condition, temps),
            body,
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body,
            condition: substitute_vars(&condition, temps),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(|e| substitute_vars(&e, temps)),
            condition: substitute_vars(&condition, temps),
            update: update.map(|e| substitute_vars(&e, temps)),
            body,
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: substitute_vars(&value, temps),
            cases,
            default,
        },
        // Other nodes don't have conditions to substitute
        other => other,
    }
}

/// Collect GotRef assignments from all blocks.
fn collect_global_refs(nodes: &[StructuredNode]) -> HashMap<String, Expr> {
    let mut global_refs = HashMap::new();

    for node in nodes {
        collect_global_refs_from_node(node, &mut global_refs);
    }

    global_refs
}

fn collect_global_refs_from_node(node: &StructuredNode, global_refs: &mut HashMap<String, Expr>) {
    use super::expression::ExprKind;

    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                    if let ExprKind::GotRef { .. } = &rhs.kind {
                        if let ExprKind::Var(lhs_var) = &lhs.kind {
                            // Don't track GotRef assignments to return registers - they're
                            // frequently clobbered by function calls, leading to incorrect
                            // substitution of return values with global names.
                            if !is_return_register(&lhs_var.name) {
                                global_refs.insert(lhs_var.name.clone(), (**rhs).clone());
                            }
                        }
                    }
                }
            }
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_global_refs_from_node(n, global_refs);
            }
            if let Some(else_nodes) = else_body {
                for n in else_nodes {
                    collect_global_refs_from_node(n, global_refs);
                }
            }
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::Loop { body, .. } => {
            for n in body {
                collect_global_refs_from_node(n, global_refs);
            }
        }
        StructuredNode::For { body, .. } => {
            for n in body {
                collect_global_refs_from_node(n, global_refs);
            }
        }
        StructuredNode::Sequence(nodes) => {
            for n in nodes {
                collect_global_refs_from_node(n, global_refs);
            }
        }
        _ => {}
    }
}

/// Substitutes global refs in a node (statements and conditions).
fn substitute_globals_in_node(
    node: StructuredNode,
    global_refs: &HashMap<String, Expr>,
) -> StructuredNode {
    use super::expression::ExprKind;

    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            // Build block-local GotRef aliases so per-block temporaries (e.g., x8)
            // are substituted correctly without leaking across sibling blocks.
            // Process statements in order, invalidating refs when they're clobbered.
            let mut scoped_refs = global_refs.clone();
            let mut result_stmts = Vec::with_capacity(statements.len());

            for stmt in statements {
                // First, check if this statement invalidates any refs
                if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                    if let ExprKind::GotRef { .. } = &rhs.kind {
                        // This is a GotRef assignment - track it (but not for return regs)
                        if let ExprKind::Var(lhs_var) = &lhs.kind {
                            if !is_return_register(&lhs_var.name) {
                                scoped_refs.insert(lhs_var.name.clone(), (**rhs).clone());
                            }
                        }
                    } else if let ExprKind::Var(lhs_var) = &lhs.kind {
                        // Non-GotRef assignment to a variable - invalidate that var
                        scoped_refs.remove(&lhs_var.name);
                    }
                } else if let ExprKind::Call { .. } = &stmt.kind {
                    // Function calls clobber return registers - invalidate them
                    // x86-64: rax/eax, ARM64: x0/w0, RISC-V: a0
                    for reg in &["rax", "eax", "x0", "w0", "a0"] {
                        scoped_refs.remove(*reg);
                    }
                }

                // Substitute refs in the statement
                let subst_stmt = substitute_global_refs(&stmt, &scoped_refs);

                // Remove GotRef assignments (they've been propagated)
                if let ExprKind::Assign { rhs, .. } = &subst_stmt.kind {
                    if let ExprKind::GotRef { .. } = &rhs.kind {
                        continue;
                    }
                }
                result_stmts.push(subst_stmt);
            }

            StructuredNode::Block {
                id,
                statements: result_stmts,
                address_range,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: substitute_global_refs(&condition, global_refs),
            then_body: then_body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            else_body: else_body.map(|nodes| {
                nodes
                    .into_iter()
                    .map(|n| substitute_globals_in_node(n, global_refs))
                    .collect()
            }),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: substitute_global_refs(&condition, global_refs),
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            condition: substitute_global_refs(&condition, global_refs),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(|e| substitute_global_refs(&e, global_refs)),
            condition: substitute_global_refs(&condition, global_refs),
            update: update.map(|e| substitute_global_refs(&e, global_refs)),
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
            nodes
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
        ),
        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(substitute_global_refs(&expr, global_refs)))
        }
        other => other,
    }
}

fn simplify_node_copies(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = propagate_copies(statements);
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: then_body.into_iter().map(simplify_node_copies).collect(),
            else_body: else_body.map(|nodes| nodes.into_iter().map(simplify_node_copies).collect()),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: body.into_iter().map(simplify_node_copies).collect(),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: body.into_iter().map(simplify_node_copies).collect(),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: body.into_iter().map(simplify_node_copies).collect(),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: body.into_iter().map(simplify_node_copies).collect(),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, body.into_iter().map(simplify_node_copies).collect()))
                .collect(),
            default: default.map(|nodes| nodes.into_iter().map(simplify_node_copies).collect()),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(nodes.into_iter().map(simplify_node_copies).collect())
        }
        // Pass through other nodes unchanged
        other => other,
    }
}

/// Performs copy propagation on a list of statements.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
/// Note: Temp register assignments are kept for now so that propagate_temps_to_conditions
/// can use them for substituting into conditions. They will be removed later.
fn propagate_copies(statements: Vec<Expr>) -> Vec<Expr> {
    use super::expression::ExprKind;

    // Track the last value assigned to each temp register
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for stmt in statements.into_iter() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            // Always substitute known register values in the RHS
            let new_rhs = substitute_vars(rhs, &reg_values);

            // Check if LHS is a temp register
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if is_temp_register(&lhs_var.name) {
                    // Track this assignment for future substitution
                    reg_values.insert(lhs_var.name.clone(), new_rhs.clone());
                    // Emit with substituted RHS (keep the assignment for now)
                    result.push(Expr::assign((**lhs).clone(), new_rhs));
                    continue;
                }
            }

            // Non-temp LHS (memory location or non-temp register): emit with substitution
            result.push(Expr::assign((**lhs).clone(), new_rhs));
            continue;
        }
        // Non-assignment statement: pass through
        result.push(stmt);
    }

    result
}

/// Substitute variable references with their GotRef values.
fn substitute_global_refs(expr: &Expr, global_refs: &HashMap<String, Expr>) -> Expr {
    use super::expression::{CallTarget, ExprKind};

    match &expr.kind {
        // Don't substitute in push/pop - these are prologue/epilogue
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "push" || name == "pop" {
                    return expr.clone();
                }
            }
            // For other calls, substitute in args
            let new_args: Vec<_> = args
                .iter()
                .map(|a| substitute_global_refs(a, global_refs))
                .collect();
            let new_target = match target {
                CallTarget::Indirect(e) => {
                    CallTarget::Indirect(Box::new(substitute_global_refs(e, global_refs)))
                }
                CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
                    got_address: *got_address,
                    expr: Box::new(substitute_global_refs(expr, global_refs)),
                },
                other => other.clone(),
            };
            Expr::call(new_target, new_args)
        }
        ExprKind::Var(v) => {
            if let Some(value) = global_refs.get(&v.name) {
                value.clone()
            } else {
                expr.clone()
            }
        }
        ExprKind::Deref { addr, size } => {
            let new_addr = substitute_global_refs(addr, global_refs);
            Expr::deref(new_addr, *size)
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_global_refs(left, global_refs),
            substitute_global_refs(right, global_refs),
        ),
        ExprKind::UnaryOp { op, operand } => {
            Expr::unary(*op, substitute_global_refs(operand, global_refs))
        }
        ExprKind::Assign { lhs, rhs } => {
            // Never rewrite a plain variable assignment target (`x = ...`) into
            // a global symbol (`stdout = ...`). Only substitute in RHS and
            // non-variable lvalues like dereference targets.
            let new_lhs = if matches!(lhs.kind, ExprKind::Var(_)) {
                (**lhs).clone()
            } else {
                substitute_global_refs(lhs, global_refs)
            };
            Expr::assign(new_lhs, substitute_global_refs(rhs, global_refs))
        }
        _ => expr.clone(),
    }
}

/// Substitute variable references with their known values and simplify.
fn substitute_vars(expr: &Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    use super::expression::ExprKind;

    let result = match &expr.kind {
        ExprKind::Var(v) => {
            if let Some(value) = reg_values.get(&v.name) {
                value.clone()
            } else {
                expr.clone()
            }
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_vars(left, reg_values),
            substitute_vars(right, reg_values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(*op, substitute_vars(operand, reg_values)),
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_vars(lhs, reg_values),
            substitute_vars(rhs, reg_values),
        ),
        ExprKind::Deref { addr, size } => Expr::deref(substitute_vars(addr, reg_values), *size),
        _ => expr.clone(),
    };
    // Simplify after substitution to handle boolean patterns like (x == 1) != 1 → x != 1
    result.simplify()
}

/// Recursively propagates function call arguments through structured nodes.
fn propagate_call_args(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(propagate_call_args_node).collect()
}

fn propagate_call_args_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = propagate_args_in_block(statements);
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: propagate_call_args(then_body),
            else_body: else_body.map(propagate_call_args),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: propagate_call_args(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: propagate_call_args(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: propagate_call_args(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: propagate_call_args(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, propagate_call_args(body)))
                .collect(),
            default: default.map(propagate_call_args),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(propagate_call_args(nodes)),
        other => other,
    }
}

/// Propagates arguments into function calls within a block.
/// Transforms patterns like:
///   edi = 5;
///   func();
/// Into:
///   func(5);
fn propagate_args_in_block(statements: Vec<Expr>) -> Vec<Expr> {
    use super::expression::ExprKind;

    // Track argument register values and their statement indices
    let mut arg_values: HashMap<String, (usize, Expr)> = HashMap::new();
    let mut to_remove: HashSet<usize> = HashSet::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for (i, stmt) in statements.into_iter().enumerate() {
        // Check if this is an assignment to an argument register
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if get_arg_register_index(&v.name).is_some() {
                    // Track this argument value along with its statement index
                    arg_values.insert(v.name.clone(), (i, (**rhs).clone()));
                    result.push(stmt);
                    continue;
                }
            }
        }

        // Check if this is a function call (not push/pop/syscall/etc.)
        if let ExprKind::Call { target, args } = &stmt.kind {
            if is_real_function_call(target) && args.is_empty() {
                // Try to extract arguments from tracked registers
                let new_args = extract_call_arguments_with_indices(&arg_values);
                if !new_args.0.is_empty() {
                    // Mark the used arg assignments for removal
                    for idx in new_args.1 {
                        to_remove.insert(idx);
                    }
                    // Create a new call with arguments
                    let new_call = Expr::call(target.clone(), new_args.0);
                    result.push(new_call);
                    // Clear argument tracking after the call
                    arg_values.clear();
                    continue;
                }
            }
        }

        // Check if this is an assignment with a call on RHS (return value capture)
        // Pattern: func(); var = eax; -> var = func();
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &rhs.kind {
                if is_return_register(&v.name) {
                    // Check if previous statement was a call
                    if let Some(prev) = result.last() {
                        if let ExprKind::Call { target, args } = &prev.kind {
                            if is_real_function_call(target) {
                                // Merge: replace the call with an assignment
                                let call_expr = Expr::call(target.clone(), args.clone());
                                let assign = Expr::assign((**lhs).clone(), call_expr);
                                result.pop(); // Remove the bare call
                                result.push(assign);
                                continue;
                            }
                        }
                    }
                }
            }
        }

        // Pass through other statements
        result.push(stmt);
    }

    // Filter out argument register assignments that were actually propagated into calls
    result
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| !to_remove.contains(idx))
        .map(|(_, stmt)| stmt)
        .collect()
}

/// Checks if a call target is a "real" function call (not push/pop/syscall etc.)
fn is_real_function_call(target: &super::expression::CallTarget) -> bool {
    use super::expression::CallTarget;
    match target {
        CallTarget::Named(name) => !matches!(
            name.as_str(),
            "push" | "pop" | "syscall" | "int" | "halt" | "swap" | "rol" | "ror"
        ),
        CallTarget::Direct { .. } | CallTarget::Indirect(_) | CallTarget::IndirectGot { .. } => {
            true
        }
    }
}

/// Extracts function arguments from tracked argument registers.
fn extract_call_arguments(arg_values: &HashMap<String, Expr>) -> Vec<Expr> {
    let mut args: Vec<(usize, Expr)> = Vec::new();

    for (reg_name, value) in arg_values {
        if let Some(idx) = get_arg_register_index(reg_name) {
            args.push((idx, value.clone()));
        }
    }

    // Sort by argument index
    args.sort_by_key(|(idx, _)| *idx);

    // Only include contiguous arguments starting from 0
    let mut result = Vec::new();
    for (expected_idx, (actual_idx, value)) in args.into_iter().enumerate() {
        if actual_idx == expected_idx {
            result.push(value);
        } else {
            break;
        }
    }

    result
}

/// Extracts call arguments and returns (arguments, statement_indices_used).
/// The statement indices are used to track which arg assignments should be removed.
fn extract_call_arguments_with_indices(
    arg_values: &HashMap<String, (usize, Expr)>,
) -> (Vec<Expr>, Vec<usize>) {
    let mut args: Vec<(usize, usize, Expr)> = Vec::new(); // (arg_idx, stmt_idx, value)

    for (reg_name, (stmt_idx, value)) in arg_values {
        if let Some(arg_idx) = get_arg_register_index(reg_name) {
            args.push((arg_idx, *stmt_idx, value.clone()));
        }
    }

    // Sort by argument index
    args.sort_by_key(|(arg_idx, _, _)| *arg_idx);

    // Only include contiguous arguments starting from 0
    let mut result = Vec::new();
    let mut used_indices = Vec::new();
    for (expected_idx, (actual_idx, stmt_idx, value)) in args.into_iter().enumerate() {
        if actual_idx == expected_idx {
            result.push(value);
            used_indices.push(stmt_idx);
        } else {
            break;
        }
    }

    (result, used_indices)
}

/// Merges return value captures across basic block boundaries.
/// Transforms patterns where:
///   Block1: ...; func();
///   Block2: var = eax; ...
/// Into:
///   Block1: ...
///   Block2: var = func(); ...
fn merge_return_value_captures(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut capture_counter = 0u32;
    merge_return_value_captures_with_counter(nodes, &mut capture_counter)
}

fn merge_return_value_captures_with_counter(
    nodes: Vec<StructuredNode>,
    capture_counter: &mut u32,
) -> Vec<StructuredNode> {
    use super::expression::ExprKind;

    let mut result: Vec<StructuredNode> = Vec::with_capacity(nodes.len());

    for node in nodes {
        // First, recursively process nested structures
        let node = merge_return_value_captures_node(node, capture_counter);

        // Check if we should merge with the previous block
        if let StructuredNode::Block {
            id,
            mut statements,
            address_range,
        } = node
        {
            // Check if first statement is `var = eax` (return value capture)
            if !statements.is_empty() {
                let should_merge = if let ExprKind::Assign { lhs: _, rhs } = &statements[0].kind {
                    if let ExprKind::Var(v) = &rhs.kind {
                        if is_return_register(&v.name) {
                            // Check if previous node is a block ending with a call
                            if let Some(StructuredNode::Block {
                                statements: prev_stmts,
                                ..
                            }) = result.last()
                            {
                                if let Some(last_stmt) = prev_stmts.last() {
                                    if let ExprKind::Call { target, .. } = &last_stmt.kind {
                                        is_real_function_call(target)
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };

                if should_merge {
                    // Pop the previous block
                    if let Some(StructuredNode::Block {
                        id: prev_id,
                        statements: mut prev_stmts,
                        address_range: prev_range,
                    }) = result.pop()
                    {
                        // Extract the call from the previous block
                        if let Some(last_stmt) = prev_stmts.pop() {
                            if let ExprKind::Call { target, args } = &last_stmt.kind {
                                // Get the LHS from current block's first statement
                                if let ExprKind::Assign { lhs, .. } = &statements[0].kind {
                                    // Create the merged assignment
                                    let call_expr = Expr::call(target.clone(), args.clone());
                                    let assign = Expr::assign((**lhs).clone(), call_expr);

                                    // Put the modified previous block back (if not empty)
                                    if !prev_stmts.is_empty() {
                                        result.push(StructuredNode::Block {
                                            id: prev_id,
                                            statements: prev_stmts,
                                            address_range: prev_range,
                                        });
                                    }

                                    // Replace first statement with the merged assignment
                                    statements[0] = assign;
                                }
                            }
                        }
                    }
                }
            }
            let statements = capture_return_register_uses_in_block(statements, capture_counter);
            result.push(StructuredNode::Block {
                id,
                statements,
                address_range,
            });
        } else {
            result.push(node);
        }
    }

    result
}

/// Recursively applies return value capture merging to nested structures.
fn merge_return_value_captures_node(
    node: StructuredNode,
    capture_counter: &mut u32,
) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: merge_return_value_captures_with_counter(then_body, capture_counter),
            else_body: else_body
                .map(|nodes| merge_return_value_captures_with_counter(nodes, capture_counter)),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: merge_return_value_captures_with_counter(body, capture_counter),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: merge_return_value_captures_with_counter(body, capture_counter),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: merge_return_value_captures_with_counter(body, capture_counter),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: merge_return_value_captures_with_counter(body, capture_counter),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| {
                    (
                        vals,
                        merge_return_value_captures_with_counter(body, capture_counter),
                    )
                })
                .collect(),
            default: default
                .map(|nodes| merge_return_value_captures_with_counter(nodes, capture_counter)),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
            merge_return_value_captures_with_counter(nodes, capture_counter),
        ),
        other => other,
    }
}

fn capture_return_register_uses_in_block(
    statements: Vec<Expr>,
    capture_counter: &mut u32,
) -> Vec<Expr> {
    use super::expression::{ExprKind, VarKind, Variable};

    let mut stmts = statements;
    let mut i = 0usize;

    while i + 1 < stmts.len() {
        let call_target = match &stmts[i].kind {
            ExprKind::Call { target, .. } if is_real_function_call(target) => Some(target),
            _ => None,
        };
        if call_target.is_none() {
            i += 1;
            continue;
        }

        let next_regs = collect_return_register_uses(&stmts[i + 1]);
        if next_regs.is_empty() {
            i += 1;
            continue;
        }

        let primary_reg = next_regs
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| "x0".to_string());
        let aliases = return_register_aliases(&primary_reg);
        let reg_size = if matches!(primary_reg.as_str(), "eax" | "w0") {
            4
        } else {
            8
        };

        let temp_name = format!("ret_{}", *capture_counter);
        *capture_counter += 1;
        let temp_var = Variable {
            kind: VarKind::Temp(*capture_counter),
            name: temp_name,
            size: reg_size,
        };
        let temp_expr = Expr::var(temp_var.clone());

        let capture_stmt = Expr::assign(
            temp_expr.clone(),
            Expr::var(Variable {
                kind: VarKind::Register(0),
                name: primary_reg,
                size: reg_size,
            }),
        );

        // Insert capture immediately after call.
        stmts.insert(i + 1, capture_stmt);

        // Rewrite uses in subsequent statements until clobber/new call.
        let mut j = i + 2;
        while j < stmts.len() {
            if j > i + 2 {
                if let ExprKind::Call { target, .. } = &stmts[j].kind {
                    if is_real_function_call(target) {
                        break;
                    }
                }
            }
            if statement_clobbers_return_register(&stmts[j], &aliases) {
                break;
            }
            stmts[j] = substitute_return_register_uses(stmts[j].clone(), &aliases, &temp_expr);
            j += 1;
        }

        i = j;
    }

    stmts
}

fn return_register_aliases(reg_name: &str) -> Vec<String> {
    match reg_name {
        "eax" | "rax" => vec!["eax".to_string(), "rax".to_string()],
        "w0" | "x0" | "arg0" => vec!["w0".to_string(), "x0".to_string(), "arg0".to_string()],
        "a0" => vec!["a0".to_string()],
        _ => vec![reg_name.to_string()],
    }
}

fn collect_return_register_uses(stmt: &Expr) -> HashSet<String> {
    use super::expression::ExprKind;

    fn walk(expr: &Expr, out: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                let name = v.name.to_lowercase();
                if is_return_register(&name) || name == "arg0" {
                    out.insert(name);
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                walk(left, out);
                walk(right, out);
            }
            ExprKind::UnaryOp { operand, .. } => walk(operand, out),
            ExprKind::Deref { addr, .. } => walk(addr, out),
            ExprKind::AddressOf(inner) => walk(inner, out),
            ExprKind::ArrayAccess { base, index, .. } => {
                walk(base, out);
                walk(index, out);
            }
            ExprKind::FieldAccess { base, .. } => walk(base, out),
            ExprKind::Call { args, .. } => {
                for arg in args {
                    walk(arg, out);
                }
            }
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                walk(lhs, out);
                walk(rhs, out);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                walk(cond, out);
                walk(then_expr, out);
                walk(else_expr, out);
            }
            ExprKind::Cast { expr, .. } => walk(expr, out),
            ExprKind::BitField { expr, .. } => walk(expr, out),
            ExprKind::Phi(values) => {
                for value in values {
                    walk(value, out);
                }
            }
            _ => {}
        }
    }

    let mut out = HashSet::new();
    walk(stmt, &mut out);
    out
}

fn statement_clobbers_return_register(stmt: &Expr, aliases: &[String]) -> bool {
    use super::expression::ExprKind;
    match &stmt.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
            if let ExprKind::Var(v) = &lhs.kind {
                aliases.iter().any(|n| *n == v.name.to_lowercase())
            } else {
                false
            }
        }
        _ => false,
    }
}

fn substitute_return_register_uses(expr: Expr, aliases: &[String], replacement: &Expr) -> Expr {
    use super::expression::ExprKind;

    fn sub(expr: Expr, aliases: &[String], replacement: &Expr, in_plain_lhs: bool) -> Expr {
        match expr.kind {
            ExprKind::Var(v) => {
                let lower = v.name.to_lowercase();
                if !in_plain_lhs && aliases.contains(&lower) {
                    replacement.clone()
                } else {
                    Expr::var(v)
                }
            }
            ExprKind::BinOp { op, left, right } => Expr::binop(
                op,
                sub(*left, aliases, replacement, false),
                sub(*right, aliases, replacement, false),
            ),
            ExprKind::UnaryOp { op, operand } => {
                Expr::unary(op, sub(*operand, aliases, replacement, false))
            }
            ExprKind::Deref { addr, size } => {
                Expr::deref(sub(*addr, aliases, replacement, false), size)
            }
            ExprKind::AddressOf(inner) => {
                Expr::address_of(sub(*inner, aliases, replacement, false))
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => Expr::array_access(
                sub(*base, aliases, replacement, false),
                sub(*index, aliases, replacement, false),
                element_size,
            ),
            ExprKind::FieldAccess {
                base,
                field_name,
                offset,
            } => Expr::field_access(sub(*base, aliases, replacement, false), field_name, offset),
            ExprKind::Call { target, args } => Expr::call(
                target,
                args.into_iter()
                    .map(|a| sub(a, aliases, replacement, false))
                    .collect(),
            ),
            ExprKind::Assign { lhs, rhs } => {
                let lhs_is_plain_var = matches!(lhs.kind, ExprKind::Var(_));
                Expr::assign(
                    sub(*lhs, aliases, replacement, lhs_is_plain_var),
                    sub(*rhs, aliases, replacement, false),
                )
            }
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                let lhs_is_plain_var = matches!(lhs.kind, ExprKind::Var(_));
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op,
                        lhs: Box::new(sub(*lhs, aliases, replacement, lhs_is_plain_var)),
                        rhs: Box::new(sub(*rhs, aliases, replacement, false)),
                    },
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => Expr {
                kind: ExprKind::Conditional {
                    cond: Box::new(sub(*cond, aliases, replacement, false)),
                    then_expr: Box::new(sub(*then_expr, aliases, replacement, false)),
                    else_expr: Box::new(sub(*else_expr, aliases, replacement, false)),
                },
            },
            ExprKind::Cast {
                expr,
                to_size,
                signed,
            } => Expr {
                kind: ExprKind::Cast {
                    expr: Box::new(sub(*expr, aliases, replacement, false)),
                    to_size,
                    signed,
                },
            },
            ExprKind::BitField { expr, start, width } => Expr {
                kind: ExprKind::BitField {
                    expr: Box::new(sub(*expr, aliases, replacement, false)),
                    start,
                    width,
                },
            },
            ExprKind::Phi(values) => Expr {
                kind: ExprKind::Phi(
                    values
                        .into_iter()
                        .map(|v| sub(v, aliases, replacement, false))
                        .collect(),
                ),
            },
            ExprKind::IntLit(n) => Expr::int(n),
            ExprKind::Unknown(name) => Expr::unknown(name),
            ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr,
                is_deref,
            } => Expr {
                kind: ExprKind::GotRef {
                    address,
                    instruction_address,
                    size,
                    display_expr: Box::new(sub(*display_expr, aliases, replacement, false)),
                    is_deref,
                },
            },
        }
    }

    sub(expr, aliases, replacement, false)
}

/// Post-processes nodes to detect switch statements from chains of if-else.
fn detect_switch_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        let node = detect_switch_in_node(node);
        result.push(node);
    }

    result
}

/// Rewrites common option-parsing pattern:
///   `tmp = strcmp(x, "..."); switch (tmp) { case 0: ... default: ... }`
/// into:
///   `if (strcmp(x, "...") == 0) { ... } else { ... }`
fn simplify_strcmp_switch_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First recurse into children.
    let recursed: Vec<StructuredNode> = nodes
        .into_iter()
        .map(simplify_strcmp_switch_in_node)
        .collect();

    // Then rewrite adjacent node pairs at this level.
    let mut out = Vec::with_capacity(recursed.len());
    let mut i = 0usize;
    while i < recursed.len() {
        if i + 1 < recursed.len() {
            if let Some(mut rewritten) =
                rewrite_strcmp_switch_pair(recursed[i].clone(), recursed[i + 1].clone())
            {
                out.append(&mut rewritten);
                i += 2;
                continue;
            }
        }
        out.push(recursed[i].clone());
        i += 1;
    }

    out
}

fn simplify_strcmp_switch_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: simplify_strcmp_switch_patterns(then_body),
            else_body: else_body.map(simplify_strcmp_switch_patterns),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: simplify_strcmp_switch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_strcmp_switch_patterns(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: simplify_strcmp_switch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_strcmp_switch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, simplify_strcmp_switch_patterns(body)))
                .collect(),
            default: default.map(simplify_strcmp_switch_patterns),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(simplify_strcmp_switch_patterns(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: simplify_strcmp_switch_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: simplify_strcmp_switch_patterns(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn rewrite_strcmp_switch_pair(
    first: StructuredNode,
    second: StructuredNode,
) -> Option<Vec<StructuredNode>> {
    // Extract `tmp = strcmp(...);` from first node.
    let (remaining_first, cmp_var, cmp_call) = extract_strcmp_assignment(first)?;

    // Extract `switch(tmp)` with only `case 0` (+ optional default) from second.
    let (then_body, else_body) = extract_zero_case_switch(&second, &cmp_var)?;

    let condition = Expr::binop(BinOpKind::Eq, cmp_call, Expr::int(0));
    let if_node = StructuredNode::If {
        condition,
        then_body,
        else_body,
    };

    let mut out = Vec::new();
    if let Some(node) = remaining_first {
        out.push(node);
    }
    out.push(if_node);
    Some(out)
}

fn extract_strcmp_assignment(
    node: StructuredNode,
) -> Option<(Option<StructuredNode>, String, Expr)> {
    // Support either:
    //   Expr(tmp = strcmp(...))
    // or
    //   Block { ..., tmp = strcmp(...) } (assignment must be last stmt)
    match node {
        StructuredNode::Expr(expr) => {
            let (var, call) = match_strcmp_assign(&expr)?;
            Some((None, var, call))
        }
        StructuredNode::Block {
            id,
            mut statements,
            address_range,
        } => {
            let last = statements.last()?.clone();
            let (var, call) = match_strcmp_assign(&last)?;
            statements.pop();
            let remaining = if statements.is_empty() {
                None
            } else {
                Some(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                })
            };
            Some((remaining, var, call))
        }
        _ => None,
    }
}

fn match_strcmp_assign(expr: &Expr) -> Option<(String, Expr)> {
    if let super::expression::ExprKind::Assign { lhs, rhs } = &expr.kind {
        if let super::expression::ExprKind::Var(v) = &lhs.kind {
            if let super::expression::ExprKind::Call {
                target: super::expression::CallTarget::Named(name),
                ..
            } = &rhs.kind
            {
                let lower = name.to_lowercase();
                if matches!(
                    lower.as_str(),
                    "strcmp" | "strncmp" | "strcasecmp" | "strncasecmp"
                ) {
                    return Some((v.name.clone(), (**rhs).clone()));
                }
            }
        }
    }
    None
}

fn extract_zero_case_switch(
    node: &StructuredNode,
    expected_var: &str,
) -> Option<(Vec<StructuredNode>, Option<Vec<StructuredNode>>)> {
    let StructuredNode::Switch {
        value,
        cases,
        default,
    } = node
    else {
        return None;
    };

    let super::expression::ExprKind::Var(v) = &value.kind else {
        return None;
    };
    if v.name != expected_var {
        return None;
    }

    // Only handle single-case switches where the case is exactly value 0.
    if cases.len() != 1 {
        return None;
    }
    let (vals, body) = &cases[0];
    if vals.len() != 1 || vals[0] != 0 {
        return None;
    }

    Some((body.clone(), default.clone()))
}

/// Detect switch patterns in a single node and its children.
fn detect_switch_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            // Try to extract a switch from this if-else chain
            if let Some(switch_node) = try_extract_switch(&condition, &then_body, &else_body) {
                return switch_node;
            }

            // Otherwise, recursively process children
            StructuredNode::If {
                condition,
                then_body: detect_switch_statements(then_body),
                else_body: else_body.map(detect_switch_statements),
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: detect_switch_statements(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: detect_switch_statements(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_switch_statements(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: detect_switch_statements(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_switch_statements(body)))
                .collect(),
            default: default.map(detect_switch_statements),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(detect_switch_statements(nodes))
        }
        other => other,
    }
}

/// Try to extract a switch statement from an if-else chain.
/// Returns Some(Switch) if successful, None if the pattern doesn't match.
///
/// Handles two patterns:
/// 1. `if (x == A) { caseA } else if (x == B) { caseB } ...` (== pattern)
/// 2. `if (x != A) { if (x != B) { ... } else { caseB } } else { caseA }` (!= pattern)
fn try_extract_switch(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<StructuredNode> {
    // First, try to extract range condition (x >= min && x <= max)
    if let Some(range_info) = extract_switch_range_info(condition) {
        let values: Vec<i128> = (range_info.start..=range_info.end).collect();
        // For range conditions, we start with that case and continue checking else chain
        let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = vec![(values, then_body.to_vec())];
        let mut current_else = else_body.clone();
        let switch_var_key = range_info.var_key.clone();
        let switch_var_expr = range_info.var_expr.clone();

        // Walk down the else chain looking for more cases (range or equality)
        while let Some(ref else_nodes) = current_else {
            let mut found_if = false;
            for node in else_nodes {
                if let StructuredNode::If {
                    condition: else_cond,
                    then_body: else_then,
                    else_body: nested_else,
                } = node
                {
                    if let Some((var_key, _, values)) = extract_switch_case_or_range(else_cond) {
                        if var_key == switch_var_key {
                            cases.push((values, else_then.to_vec()));
                            current_else = nested_else.clone();
                            found_if = true;
                            break;
                        }
                    }
                }
            }
            if !found_if {
                break;
            }
        }

        // Need at least 2 cases for range-based switches (the range might cover many values)
        if cases.len() >= 2 || cases.iter().map(|(v, _)| v.len()).sum::<usize>() >= 3 {
            let default = current_else.map(detect_switch_statements);
            let final_cases = cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_switch_statements(body)))
                .collect();
            return Some(StructuredNode::Switch {
                value: switch_var_expr,
                cases: final_cases,
                default,
            });
        }
    }

    // Check if condition is a comparison against a literal (== or != pattern)
    let first_info = extract_switch_case_info(condition)?;

    // Determine if we're dealing with == or != patterns
    if first_info.negated {
        // != pattern: case body is in else, rest of chain is in then
        return try_extract_switch_negated(&first_info, then_body, else_body);
    }

    // == pattern: case body is in then, rest of chain is in else
    // Start collecting cases
    let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> =
        vec![(vec![first_info.value], then_body.to_vec())];
    let mut current_else = else_body.clone();
    let mut switch_var_key = first_info.var_key.clone();
    let mut switch_var_expr = first_info.var_expr.clone();
    let first_var_expr = first_info.var_expr.clone(); // Save original for mismatch case
    let mut first_var_mismatch = false;

    // Walk down the else chain
    while let Some(ref else_nodes) = current_else {
        // Find an If node in the else body (may be preceded by Block nodes)
        let mut found_if = false;
        for node in else_nodes {
            if let StructuredNode::If {
                condition: else_cond,
                then_body: else_then,
                else_body: nested_else,
            } = node
            {
                // Check if this condition matches our switch variable
                // Try both equality and range patterns
                if let Some((var_key, var_expr, values)) = extract_switch_case_or_range(else_cond) {
                    // If this is the second case and variable differs, switch to the new variable
                    // This handles cases where the first condition uses the original parameter
                    // but subsequent conditions use a copy
                    if cases.len() == 1 && var_key != switch_var_key {
                        // Change to the new variable for subsequent checks
                        switch_var_key = var_key.clone();
                        switch_var_expr = var_expr.clone();
                        first_var_mismatch = true;
                    }

                    if var_key == switch_var_key {
                        cases.push((values, else_then.to_vec()));
                        current_else = nested_else.clone();
                        found_if = true;
                        break;
                    }
                }
            }
        }

        if !found_if {
            // This else doesn't contain a matching If - it becomes the default case
            break;
        }
    }

    // Need at least 3 cases to be worth converting to switch
    // If first var mismatched, we need at least 4 cases (first case won't be included)
    let min_cases = if first_var_mismatch { 4 } else { 3 };
    if cases.len() < min_cases {
        return None;
    }

    // If first var mismatched, exclude the first case from the switch
    let (final_cases, first_case) = if first_var_mismatch {
        let mut iter = cases.into_iter();
        let first = iter.next();
        (iter.collect::<Vec<_>>(), first)
    } else {
        (cases, None)
    };

    // Process the default case
    let default = current_else.map(detect_switch_statements);

    // Recursively process case bodies
    let final_cases = final_cases
        .into_iter()
        .map(|(vals, body)| (vals, detect_switch_statements(body)))
        .collect();

    let switch_node = StructuredNode::Switch {
        value: switch_var_expr.clone(),
        cases: final_cases,
        default,
    };

    // If we had a first case mismatch, wrap the switch in an if-else
    if let Some((first_vals, first_body)) = first_case {
        use super::expression::BinOpKind;
        let first_condition = Expr::binop(
            BinOpKind::Eq,
            first_var_expr.clone(),
            Expr::int(first_vals[0]),
        );
        Some(StructuredNode::If {
            condition: first_condition,
            then_body: detect_switch_statements(first_body),
            else_body: Some(vec![switch_node]),
        })
    } else {
        Some(switch_node)
    }
}

/// Try to extract a switch statement from a != pattern if-else chain.
///
/// Pattern: `if (x != A) { if (x != B) { default } else { caseB } } else { caseA }`
/// This is the inverted form where case bodies are in the else branches.
fn try_extract_switch_negated(
    first_info: &SwitchCaseInfo,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<StructuredNode> {
    // For != pattern, the case body is in the else branch
    let first_case_body = else_body.as_ref()?.clone();

    let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> =
        vec![(vec![first_info.value], first_case_body)];
    let switch_var_key = first_info.var_key.clone();
    let switch_var_expr = first_info.var_expr.clone();

    // The then_body contains the rest of the chain
    let mut current_then = then_body.to_vec();

    // Walk down the then chain (which is nested != comparisons)
    loop {
        // Find an If node in the then body
        let mut found_if = false;

        // Look for a single If node (possibly with some preceding statements)
        for node in &current_then {
            if let StructuredNode::If {
                condition: inner_cond,
                then_body: inner_then,
                else_body: inner_else,
            } = node
            {
                // Check if this condition is a != comparison on our switch variable
                if let Some(info) = extract_switch_case_info(inner_cond) {
                    if info.negated && info.var_key == switch_var_key {
                        // Case body is in else
                        if let Some(case_body) = inner_else {
                            cases.push((vec![info.value], case_body.clone()));
                            current_then = inner_then.clone();
                            found_if = true;
                            break;
                        }
                    }
                }
            }
        }

        if !found_if {
            // No more matching != patterns - current_then becomes the default
            break;
        }
    }

    // Need at least 3 cases to be worth converting to switch
    if cases.len() < 3 {
        return None;
    }

    // The remaining then_body is the default case (when none of the values matched)
    let default = if current_then.is_empty() {
        None
    } else {
        Some(detect_switch_statements(current_then))
    };

    // Recursively process case bodies
    let final_cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = cases
        .into_iter()
        .map(|(vals, body)| (vals, detect_switch_statements(body)))
        .collect();

    Some(StructuredNode::Switch {
        value: switch_var_expr,
        cases: final_cases,
        default,
    })
}

/// Result of extracting a switch case condition.
/// Contains the variable key, variable expression, comparison value, and whether it's negated.
struct SwitchCaseInfo {
    var_key: String,
    var_expr: Expr,
    value: i128,
    /// If true, condition is `var != N`, case body is in else branch.
    negated: bool,
}

/// Result of extracting a range-based switch case condition.
/// Contains the variable key, variable expression, and the range bounds.
struct SwitchRangeInfo {
    var_key: String,
    var_expr: Expr,
    /// Inclusive start of the range.
    start: i128,
    /// Inclusive end of the range.
    end: i128,
}

/// Maximum size for a range to be expanded into individual case values.
/// Ranges larger than this will not be converted to switch cases to avoid
/// creating massive switch statements.
const MAX_SWITCH_RANGE_SIZE: i128 = 256;

/// Try to extract a range condition from an expression.
///
/// Detects patterns like:
/// - `x >= min && x <= max`
/// - `x > min - 1 && x < max + 1`
/// - `min <= x && x <= max`
///
/// Returns (var_key, var_expr, start, end) for the inclusive range [start, end].
fn extract_switch_range_info(condition: &Expr) -> Option<SwitchRangeInfo> {
    use super::expression::BinOpKind;
    use super::expression::ExprKind;

    // Look for logical AND of two comparisons
    if let ExprKind::BinOp {
        op: BinOpKind::LogicalAnd,
        left,
        right,
    } = &condition.kind
    {
        // Try to extract bounds from both sides
        let left_bound = extract_range_bound(left);
        let right_bound = extract_range_bound(right);

        if let (Some(lb), Some(rb)) = (left_bound, right_bound) {
            // Both must reference the same variable
            if lb.var_key != rb.var_key {
                return None;
            }

            // Determine which is the lower and which is the upper bound
            let (start, end) = match (lb.is_lower, rb.is_lower) {
                (true, false) => (lb.value, rb.value), // x >= start && x <= end
                (false, true) => (rb.value, lb.value), // x <= end && x >= start
                _ => return None,                      // Both are same type - not a valid range
            };

            // Sanity check: start should be <= end and range should be reasonable
            if start > end {
                return None;
            }

            let range_size = end.saturating_sub(start).saturating_add(1);
            if range_size > MAX_SWITCH_RANGE_SIZE {
                return None;
            }

            return Some(SwitchRangeInfo {
                var_key: lb.var_key,
                var_expr: lb.var_expr,
                start,
                end,
            });
        }
    }

    None
}

/// Information about a single bound in a range condition.
struct RangeBoundInfo {
    var_key: String,
    var_expr: Expr,
    value: i128,
    /// True if this is a lower bound (x >= N or x > N)
    is_lower: bool,
}

/// Extract a range bound from a comparison expression.
/// Handles: x >= N, x > N, x <= N, x < N, N <= x, N < x, N >= x, N > x
fn extract_range_bound(expr: &Expr) -> Option<RangeBoundInfo> {
    use super::expression::BinOpKind;
    use super::expression::ExprKind;

    if let ExprKind::BinOp { op, left, right } = &expr.kind {
        // x op N
        if let Some(key) = get_expr_var_key(left) {
            if let ExprKind::IntLit(n) = right.kind {
                let (value, is_lower) = match op {
                    BinOpKind::Ge => (n, true),      // x >= n: lower bound, inclusive
                    BinOpKind::Gt => (n + 1, true),  // x > n: lower bound is n+1
                    BinOpKind::Le => (n, false),     // x <= n: upper bound, inclusive
                    BinOpKind::Lt => (n - 1, false), // x < n: upper bound is n-1
                    _ => return None,
                };
                return Some(RangeBoundInfo {
                    var_key: key,
                    var_expr: (**left).clone(),
                    value,
                    is_lower,
                });
            }
        }
        // N op x (reversed)
        if let Some(key) = get_expr_var_key(right) {
            if let ExprKind::IntLit(n) = left.kind {
                let (value, is_lower) = match op {
                    BinOpKind::Le => (n, true),      // n <= x: lower bound, inclusive
                    BinOpKind::Lt => (n + 1, true),  // n < x: lower bound is n+1
                    BinOpKind::Ge => (n, false),     // n >= x: upper bound, inclusive
                    BinOpKind::Gt => (n - 1, false), // n > x: upper bound is n-1
                    _ => return None,
                };
                return Some(RangeBoundInfo {
                    var_key: key,
                    var_expr: (**right).clone(),
                    value,
                    is_lower,
                });
            }
        }
    }

    None
}

/// Try to extract a switch case or range from a condition.
/// First tries exact match (var == N), then range match (x >= min && x <= max).
/// Returns (var_key, var_expr, values) where values is a Vec of all case values.
fn extract_switch_case_or_range(condition: &Expr) -> Option<(String, Expr, Vec<i128>)> {
    // First try exact equality
    if let Some((key, expr, value)) = extract_switch_case(condition) {
        return Some((key, expr, vec![value]));
    }

    // Then try range
    if let Some(range_info) = extract_switch_range_info(condition) {
        let values: Vec<i128> = (range_info.start..=range_info.end).collect();
        return Some((range_info.var_key, range_info.var_expr, values));
    }

    None
}

/// Extract switch case from a condition: var == N or var != N
/// Returns the case info if it matches the pattern.
fn extract_switch_case_info(condition: &Expr) -> Option<SwitchCaseInfo> {
    use super::expression::BinOpKind;
    use super::expression::ExprKind;

    if let ExprKind::BinOp { op, left, right } = &condition.kind {
        let negated = match op {
            BinOpKind::Eq => false,
            BinOpKind::Ne => true,
            _ => return None,
        };

        // var == N or var != N
        if let Some(key) = get_expr_var_key(left) {
            if let ExprKind::IntLit(n) = right.kind {
                return Some(SwitchCaseInfo {
                    var_key: key,
                    var_expr: (**left).clone(),
                    value: n,
                    negated,
                });
            }
        }
        // N == var or N != var (reversed)
        if let Some(key) = get_expr_var_key(right) {
            if let ExprKind::IntLit(n) = left.kind {
                return Some(SwitchCaseInfo {
                    var_key: key,
                    var_expr: (**right).clone(),
                    value: n,
                    negated,
                });
            }
        }
    }

    None
}

/// Extract switch case from a condition: var == N (legacy wrapper)
/// Returns (variable_key, variable_expr, value) if it matches the pattern.
fn extract_switch_case(condition: &Expr) -> Option<(String, Expr, i128)> {
    let info = extract_switch_case_info(condition)?;
    // Only return for == patterns (legacy behavior)
    if !info.negated {
        Some((info.var_key, info.var_expr, info.value))
    } else {
        None
    }
}

/// Create a switch value expression from a variable key.
/// The key is the variable name returned by get_expr_var_key.
fn create_switch_value(var_key: &str) -> Expr {
    use super::expression::{Expr as E, VarKind, Variable};

    // The key is typically a variable name like "var_0", "stack_4", etc.
    // Create a simple variable expression with that name
    E::var(Variable {
        kind: VarKind::Temp(0),
        name: var_key.to_string(),
        size: 4,
    })
}

/// Create a comparison expression: var == value
fn create_comparison(var_key: &str, value: i128) -> Expr {
    use super::expression::{BinOpKind, Expr as E};

    let var_expr = create_switch_value(var_key);
    let val_expr = E::int(value);
    E::binop(BinOpKind::Eq, var_expr, val_expr)
}

/// Context for tracking the current loop during goto-to-break/continue conversion.
#[derive(Clone)]
struct LoopContext {
    /// Block ID of the loop header (for continue detection).
    header: BasicBlockId,
    /// Block ID of the loop exit (for break detection).
    exit_block: Option<BasicBlockId>,
}

/// Converts goto statements to break/continue where applicable.
///
/// This pass runs after the main structuring and converts:
/// - `goto loop_header` inside a loop body → `continue`
/// - Gotos that exit a loop are handled specially (could become break in some cases)
fn convert_gotos_to_break_continue(
    nodes: Vec<StructuredNode>,
    current_loop: Option<&LoopContext>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| convert_gotos_in_node(node, current_loop))
        .collect()
}

/// Converts gotos in a single node.
fn convert_gotos_in_node(
    node: StructuredNode,
    current_loop: Option<&LoopContext>,
) -> StructuredNode {
    match node {
        // For loops, create a new loop context for the body using the stored header
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            // Create a loop context from the stored header and exit block
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::While {
                condition,
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::DoWhile {
                body: convert_gotos_in_loop_body(body, ctx),
                condition,
                header,
                exit_block,
            }
        }
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::Loop {
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            let loop_ctx = header.map(|h| LoopContext {
                header: h,
                exit_block,
            });
            let ctx = loop_ctx.as_ref().or(current_loop);
            StructuredNode::For {
                init,
                condition,
                update,
                body: convert_gotos_in_loop_body(body, ctx),
                header,
                exit_block,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_gotos_to_break_continue(then_body, current_loop),
            else_body: else_body.map(|e| convert_gotos_to_break_continue(e, current_loop)),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, convert_gotos_to_break_continue(body, current_loop)))
                .collect(),
            default: default.map(|d| convert_gotos_to_break_continue(d, current_loop)),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_gotos_to_break_continue(nodes, current_loop))
        }
        // Check if this goto should become break or continue
        StructuredNode::Goto(target) => {
            if let Some(ctx) = current_loop {
                if target == ctx.header {
                    // Goto to loop header = continue
                    return StructuredNode::Continue;
                }
                // Check if goto targets the loop exit block = break
                if let Some(exit) = ctx.exit_block {
                    if target == exit {
                        return StructuredNode::Break;
                    }
                }
            }
            StructuredNode::Goto(target)
        }
        // Other nodes pass through unchanged
        other => other,
    }
}

/// Converts gotos in a loop body, using the provided loop context.
fn convert_gotos_in_loop_body(
    body: Vec<StructuredNode>,
    loop_ctx: Option<&LoopContext>,
) -> Vec<StructuredNode> {
    // Use the provided loop context to detect break/continue opportunities.
    convert_gotos_to_break_continue(body, loop_ctx)
}

/// Collects all loop headers from the structured nodes.
/// This is used for the global goto-to-continue conversion pass.
fn collect_loop_headers(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut headers = HashSet::new();
    for node in nodes {
        collect_loop_headers_in_node(node, &mut headers);
    }
    headers
}

fn collect_loop_headers_in_node(node: &StructuredNode, headers: &mut HashSet<BasicBlockId>) {
    match node {
        StructuredNode::While { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::DoWhile { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::Loop { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::For { body, header, .. } => {
            if let Some(h) = header {
                headers.insert(*h);
            }
            for n in body {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_loop_headers_in_node(n, headers);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for n in body {
                    collect_loop_headers_in_node(n, headers);
                }
            }
            if let Some(d) = default {
                for n in d {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        StructuredNode::Sequence(nodes) => {
            for n in nodes {
                collect_loop_headers_in_node(n, headers);
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                collect_loop_headers_in_node(n, headers);
            }
            for handler in catch_handlers {
                for n in &handler.body {
                    collect_loop_headers_in_node(n, headers);
                }
            }
        }
        _ => {}
    }
}

/// Converts gotos at the global level (orphan labeled blocks) to continue
/// when they target loop headers.
/// This handles patterns like getopt switch cases that goto back to the loop start.
fn convert_global_gotos_to_continue(
    nodes: Vec<StructuredNode>,
    loop_headers: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| convert_global_goto_in_node(node, loop_headers))
        .collect()
}

fn convert_global_goto_in_node(
    node: StructuredNode,
    loop_headers: &HashSet<BasicBlockId>,
) -> StructuredNode {
    match node {
        // Convert goto to continue if it targets a loop header
        StructuredNode::Goto(target) => {
            if loop_headers.contains(&target) {
                StructuredNode::Continue
            } else {
                StructuredNode::Goto(target)
            }
        }
        // Recursively process labeled blocks (these are the orphan switch cases)
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements,
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_global_gotos_to_continue(then_body, loop_headers),
            else_body: else_body.map(|e| convert_global_gotos_to_continue(e, loop_headers)),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_global_gotos_to_continue(nodes, loop_headers))
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, convert_global_gotos_to_continue(body, loop_headers)))
                .collect(),
            default: default.map(|d| convert_global_gotos_to_continue(d, loop_headers)),
        },
        // Other nodes pass through (loops are already handled by the normal pass)
        other => other,
    }
}

/// Converts gotos in switch cases to break statements when they target
/// a block that comes after the switch.
/// This handles patterns where switch cases use goto to exit to a common point.
fn convert_switch_gotos_to_break(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: identify switches followed by labels
    // Those labels are switch exit points and gotos to them should be breaks
    let mut switch_exits = HashSet::new();
    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Switch { .. } = &nodes[i] {
            // Check if there's a label after the switch
            if i + 1 < nodes.len() {
                if let StructuredNode::Label(label_id) = &nodes[i + 1] {
                    switch_exits.insert(*label_id);
                }
            }
        }
        i += 1;
    }

    // Also find common goto targets within switches
    for node in &nodes {
        if let StructuredNode::Switch { cases, default, .. } = node {
            let common_target = find_common_goto_target(cases, default);
            if let Some(target) = common_target {
                switch_exits.insert(target);
            }
        }
    }

    // Second pass: convert gotos in switches
    nodes
        .into_iter()
        .map(|node| convert_switch_gotos_in_node(node, &switch_exits))
        .collect()
}

/// Finds a common goto target used by multiple switch cases.
fn find_common_goto_target(
    cases: &[(Vec<i128>, Vec<StructuredNode>)],
    default: &Option<Vec<StructuredNode>>,
) -> Option<BasicBlockId> {
    let mut target_counts: HashMap<BasicBlockId, usize> = HashMap::new();

    for (_, body) in cases {
        if let Some(target) = get_trailing_goto(body) {
            *target_counts.entry(target).or_insert(0) += 1;
        }
    }

    if let Some(body) = default {
        if let Some(target) = get_trailing_goto(body) {
            *target_counts.entry(target).or_insert(0) += 1;
        }
    }

    // Return the most common target if it appears in at least 2 cases
    target_counts
        .into_iter()
        .filter(|(_, count)| *count >= 2)
        .max_by_key(|(_, count)| *count)
        .map(|(target, _)| target)
}

/// Gets the trailing goto target from a node sequence.
fn get_trailing_goto(nodes: &[StructuredNode]) -> Option<BasicBlockId> {
    if let Some(last) = nodes.last() {
        match last {
            StructuredNode::Goto(target) => Some(*target),
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                // Check if both branches end with the same goto
                let then_target = get_trailing_goto(then_body);
                let else_target = else_body.as_ref().and_then(|e| get_trailing_goto(e));
                if then_target == else_target {
                    then_target
                } else {
                    None
                }
            }
            _ => None,
        }
    } else {
        None
    }
}

fn convert_switch_gotos_in_node(
    node: StructuredNode,
    switch_exits: &HashSet<BasicBlockId>,
) -> StructuredNode {
    match node {
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            // For each case, convert gotos to the switch exit into breaks
            let converted_cases = cases
                .into_iter()
                .map(|(vals, body)| {
                    let new_body = convert_gotos_to_break_in_body(body, switch_exits);
                    (vals, new_body)
                })
                .collect();

            let converted_default =
                default.map(|d| convert_gotos_to_break_in_body(d, switch_exits));

            StructuredNode::Switch {
                value,
                cases: converted_cases,
                default: converted_default,
            }
        }
        // Recurse into other structures
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: convert_switch_gotos_to_break(then_body),
            else_body: else_body.map(convert_switch_gotos_to_break),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: convert_switch_gotos_to_break(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: convert_switch_gotos_to_break(body),
            condition,
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: convert_switch_gotos_to_break(body),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: convert_switch_gotos_to_break(body),
            header,
            exit_block,
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(convert_switch_gotos_to_break(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: convert_switch_gotos_to_break(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: convert_switch_gotos_to_break(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn convert_gotos_to_break_in_body(
    nodes: Vec<StructuredNode>,
    switch_exits: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| match node {
            StructuredNode::Goto(target) if switch_exits.contains(&target) => StructuredNode::Break,
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: convert_gotos_to_break_in_body(then_body, switch_exits),
                else_body: else_body.map(|e| convert_gotos_to_break_in_body(e, switch_exits)),
            },
            StructuredNode::Sequence(nodes) => {
                StructuredNode::Sequence(convert_gotos_to_break_in_body(nodes, switch_exits))
            }
            other => other,
        })
        .collect()
}

// ============================================================================
// Advanced Goto Reduction Passes
// ============================================================================

/// Converts gotos to labeled cleanup blocks into structured cleanup patterns.
///
/// This handles patterns like:
/// ```text
///     if (error) goto cleanup;
///     // normal code
///   cleanup:
///     close(fd);
///     return -1;
/// ```
///
/// Converting to:
/// ```text
///     if (error) {
///         close(fd);
///         return -1;
///     }
///     // normal code
/// ```
pub fn convert_cleanup_gotos(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Identify labeled cleanup blocks (labels followed by cleanup code then return/break)
    let cleanup_blocks = identify_cleanup_blocks(&nodes);

    if cleanup_blocks.is_empty() {
        return nodes;
    }

    // Step 2: Inline cleanup blocks at goto sites and remove original labels
    inline_cleanup_blocks(nodes, &cleanup_blocks)
}

/// Identifies labeled blocks that are cleanup patterns.
/// A cleanup block is a label followed by code ending in return/break.
fn identify_cleanup_blocks(nodes: &[StructuredNode]) -> HashMap<BasicBlockId, Vec<StructuredNode>> {
    let mut cleanup_blocks = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        // Look for Label followed by cleanup code
        if let StructuredNode::Label(label_id) = &nodes[i] {
            // Collect the cleanup body until we hit another label or end
            let mut cleanup_body = Vec::new();
            let mut j = i + 1;
            let mut ends_with_terminator = false;

            while j < nodes.len() {
                match &nodes[j] {
                    StructuredNode::Label(_) => break,
                    node => {
                        let terminates = node_terminates(node);
                        cleanup_body.push(nodes[j].clone());
                        if terminates {
                            ends_with_terminator = true;
                            break;
                        }
                    }
                }
                j += 1;
            }

            // Only treat as cleanup if it terminates and is reasonably short
            if ends_with_terminator && cleanup_body.len() <= 5 {
                cleanup_blocks.insert(*label_id, cleanup_body);
            }
        }
        i += 1;
    }

    cleanup_blocks
}

/// Checks if a single node terminates control flow.
fn node_terminates(node: &StructuredNode) -> bool {
    match node {
        StructuredNode::Return(_) => true,
        StructuredNode::Break => true,
        StructuredNode::Continue => true,
        StructuredNode::Goto(_) => true,
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => body_terminates(then_body) && else_body.as_ref().is_some_and(|e| body_terminates(e)),
        StructuredNode::Block { statements, .. } => statements.last().is_some_and(is_noreturn_call),
        _ => false,
    }
}

/// Inlines cleanup blocks at goto sites and removes original labels.
fn inline_cleanup_blocks(
    nodes: Vec<StructuredNode>,
    cleanup_blocks: &HashMap<BasicBlockId, Vec<StructuredNode>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            // Replace goto to cleanup with inlined cleanup code
            StructuredNode::Goto(target) if cleanup_blocks.contains_key(&target) => {
                let cleanup = cleanup_blocks.get(&target).unwrap();
                result.extend(cleanup.clone());
            }

            // Remove labels that have been inlined (keep if there are non-inlined gotos)
            StructuredNode::Label(label_id) if cleanup_blocks.contains_key(&label_id) => {
                // Skip the label - it's being inlined
            }

            // Recurse into compound structures
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: inline_cleanup_blocks(then_body, cleanup_blocks),
                    else_body: else_body.map(|e| inline_cleanup_blocks(e, cleanup_blocks)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: inline_cleanup_blocks(body, cleanup_blocks),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, inline_cleanup_blocks(body, cleanup_blocks)))
                        .collect(),
                    default: default.map(|d| inline_cleanup_blocks(d, cleanup_blocks)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let converted = inline_cleanup_blocks(seq, cleanup_blocks);
                // Flatten sequences
                result.extend(converted);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: inline_cleanup_blocks(try_body, cleanup_blocks),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: inline_cleanup_blocks(h.body, cleanup_blocks),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts gotos that target blocks containing only a return into direct returns.
///
/// This handles patterns like:
/// ```text
///     if (cond) goto ret_label;
///     ...
///   ret_label:
///     return x;
/// ```
///
/// Converting to:
/// ```text
///     if (cond) return x;
///     ...
/// ```
pub fn convert_gotos_to_early_returns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Identify labels that just contain a return
    let return_labels = identify_return_labels(&nodes);

    if return_labels.is_empty() {
        return nodes;
    }

    // Step 2: Replace gotos with returns and remove the original labels
    convert_gotos_to_returns_impl(nodes, &return_labels)
}

/// Identifies labels that are followed only by a return statement.
fn identify_return_labels(nodes: &[StructuredNode]) -> HashMap<BasicBlockId, Option<Expr>> {
    let mut return_labels = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Label(label_id) = &nodes[i] {
            // Check what follows the label
            if i + 1 < nodes.len() {
                match &nodes[i + 1] {
                    StructuredNode::Return(expr) => {
                        return_labels.insert(*label_id, expr.clone());
                    }
                    StructuredNode::Block { statements, .. } => {
                        // Check if block just contains return value setup
                        if statements.is_empty() && i + 2 < nodes.len() {
                            if let StructuredNode::Return(expr) = &nodes[i + 2] {
                                return_labels.insert(*label_id, expr.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        i += 1;
    }

    return_labels
}

/// Converts gotos to return labels into direct returns.
fn convert_gotos_to_returns_impl(
    nodes: Vec<StructuredNode>,
    return_labels: &HashMap<BasicBlockId, Option<Expr>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();
    let mut skip_next_return = false;

    for node in nodes {
        if skip_next_return {
            if matches!(node, StructuredNode::Return(_)) {
                skip_next_return = false;
                continue;
            }
            skip_next_return = false;
        }

        match node {
            // Replace goto to return label with direct return
            StructuredNode::Goto(target) if return_labels.contains_key(&target) => {
                let ret_expr = return_labels.get(&target).unwrap();
                result.push(StructuredNode::Return(ret_expr.clone()));
            }

            // Remove labels that have been converted (but keep if referenced elsewhere)
            StructuredNode::Label(label_id) if return_labels.contains_key(&label_id) => {
                skip_next_return = true;
                // Skip label and following return
            }

            // Recurse into compound structures
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: convert_gotos_to_returns_impl(then_body, return_labels),
                    else_body: else_body.map(|e| convert_gotos_to_returns_impl(e, return_labels)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: convert_gotos_to_returns_impl(body, return_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| {
                            (vals, convert_gotos_to_returns_impl(body, return_labels))
                        })
                        .collect(),
                    default: default.map(|d| convert_gotos_to_returns_impl(d, return_labels)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.push(StructuredNode::Sequence(convert_gotos_to_returns_impl(
                    seq,
                    return_labels,
                )));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: convert_gotos_to_returns_impl(try_body, return_labels),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: convert_gotos_to_returns_impl(h.body, return_labels),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Removes orphan labels that have no gotos targeting them.
///
/// After other goto reduction passes, some labels may no longer be needed.
/// This pass removes them and integrates their code into the normal flow.
pub fn remove_orphan_labels(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Step 1: Collect all goto targets
    let goto_targets = collect_goto_targets(&nodes);

    // Step 2: Remove labels not in the target set
    remove_unused_labels(nodes, &goto_targets)
}

/// Collects all goto targets from the structured nodes.
fn collect_goto_targets(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut targets = HashSet::new();

    for node in nodes {
        collect_goto_targets_in_node(node, &mut targets);
    }

    targets
}

fn collect_goto_targets_in_node(node: &StructuredNode, targets: &mut HashSet<BasicBlockId>) {
    match node {
        StructuredNode::Goto(target) => {
            targets.insert(*target);
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_goto_targets_in_node(n, targets);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::Loop { body, .. }
        | StructuredNode::For { body, .. } => {
            for n in body {
                collect_goto_targets_in_node(n, targets);
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for n in body {
                    collect_goto_targets_in_node(n, targets);
                }
            }
            if let Some(d) = default {
                for n in d {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        StructuredNode::Sequence(seq) => {
            for n in seq {
                collect_goto_targets_in_node(n, targets);
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for n in try_body {
                collect_goto_targets_in_node(n, targets);
            }
            for h in catch_handlers {
                for n in &h.body {
                    collect_goto_targets_in_node(n, targets);
                }
            }
        }
        _ => {}
    }
}

/// Removes labels not targeted by any goto.
fn remove_unused_labels(
    nodes: Vec<StructuredNode>,
    goto_targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::Label(label_id) if !goto_targets.contains(&label_id) => {
                // Skip orphan label
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: remove_unused_labels(then_body, goto_targets),
                    else_body: else_body.map(|e| remove_unused_labels(e, goto_targets)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: remove_unused_labels(body, goto_targets),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: remove_unused_labels(body, goto_targets),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, remove_unused_labels(body, goto_targets)))
                        .collect(),
                    default: default.map(|d| remove_unused_labels(d, goto_targets)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let cleaned = remove_unused_labels(seq, goto_targets);
                result.extend(cleaned);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: remove_unused_labels(try_body, goto_targets),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: remove_unused_labels(h.body, goto_targets),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts multi-level break patterns (gotos that escape nested loops)
/// into flag variables or early returns where possible.
///
/// This handles patterns like:
/// ```text
///   while (cond1) {
///     while (cond2) {
///       if (error) goto outer_exit;
///     }
///   }
/// outer_exit:
///   // code
/// ```
///
/// Converting to:
/// ```text
///   bool break_outer = false;
///   while (cond1 && !break_outer) {
///     while (cond2) {
///       if (error) { break_outer = true; break; }
///     }
///     if (break_outer) break;
///   }
///   // code
/// ```
pub fn convert_multilevel_breaks(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Identify gotos that escape multiple loop levels
    let multilevel_gotos = find_multilevel_escape_gotos(&nodes);

    if multilevel_gotos.is_empty() {
        return nodes;
    }

    // For simple cases where the goto target is just after the outer loop,
    // convert to break instead of flag variable
    convert_multilevel_to_break(nodes, &multilevel_gotos)
}

/// Finds gotos that escape multiple nesting levels.
fn find_multilevel_escape_gotos(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut escaping = HashSet::new();

    // Find labels that appear after loops at top level
    let mut label_positions: HashMap<BasicBlockId, usize> = HashMap::new();
    for (i, node) in nodes.iter().enumerate() {
        if let StructuredNode::Label(id) = node {
            label_positions.insert(*id, i);
        }
    }

    // Find gotos inside nested loops that target these labels
    for (i, node) in nodes.iter().enumerate() {
        match node {
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                // Check for gotos inside the loop that escape to labels after this loop
                find_escaping_gotos_in_loop(body, &label_positions, i, &mut escaping);
            }
            _ => {}
        }
    }

    escaping
}

/// Finds gotos in a loop body that escape to labels defined outside.
fn find_escaping_gotos_in_loop(
    body: &[StructuredNode],
    label_positions: &HashMap<BasicBlockId, usize>,
    loop_pos: usize,
    escaping: &mut HashSet<BasicBlockId>,
) {
    for node in body {
        match node {
            StructuredNode::Goto(target) => {
                // If this goto targets a label after the loop, it's an escape
                if let Some(&label_pos) = label_positions.get(target) {
                    if label_pos > loop_pos {
                        escaping.insert(*target);
                    }
                }
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                find_escaping_gotos_in_loop(then_body, label_positions, loop_pos, escaping);
                if let Some(eb) = else_body {
                    find_escaping_gotos_in_loop(eb, label_positions, loop_pos, escaping);
                }
            }
            StructuredNode::While { body: inner, .. }
            | StructuredNode::DoWhile { body: inner, .. }
            | StructuredNode::Loop { body: inner, .. }
            | StructuredNode::For { body: inner, .. } => {
                // Nested loop - these gotos escape multiple levels
                find_escaping_gotos_in_loop(inner, label_positions, loop_pos, escaping);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    find_escaping_gotos_in_loop(case_body, label_positions, loop_pos, escaping);
                }
                if let Some(d) = default {
                    find_escaping_gotos_in_loop(d, label_positions, loop_pos, escaping);
                }
            }
            StructuredNode::Sequence(seq) => {
                find_escaping_gotos_in_loop(seq, label_positions, loop_pos, escaping);
            }
            _ => {}
        }
    }
}

/// Converts multilevel escape gotos to break statements.
fn convert_multilevel_to_break(
    nodes: Vec<StructuredNode>,
    targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                // Convert gotos to targets in the body to breaks
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::While {
                    condition,
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::DoWhile {
                    body: new_body,
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                let new_body = convert_escaping_gotos_to_break(body, targets);
                result.push(StructuredNode::Loop {
                    body: new_body,
                    header,
                    exit_block,
                });
            }

            // Remove labels that are now break targets
            StructuredNode::Label(id) if targets.contains(&id) => {
                // Keep the label for now - remove_orphan_labels will clean it up
                // if no gotos remain
                result.push(StructuredNode::Label(id));
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: convert_multilevel_to_break(then_body, targets),
                    else_body: else_body.map(|e| convert_multilevel_to_break(e, targets)),
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, convert_multilevel_to_break(body, targets)))
                        .collect(),
                    default: default.map(|d| convert_multilevel_to_break(d, targets)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.extend(convert_multilevel_to_break(seq, targets));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: convert_multilevel_to_break(try_body, targets),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: convert_multilevel_to_break(h.body, targets),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Converts gotos to escape targets into breaks.
fn convert_escaping_gotos_to_break(
    nodes: Vec<StructuredNode>,
    targets: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| match node {
            StructuredNode::Goto(target) if targets.contains(&target) => StructuredNode::Break,

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: convert_escaping_gotos_to_break(then_body, targets),
                else_body: else_body.map(|e| convert_escaping_gotos_to_break(e, targets)),
            },

            // Don't recurse into nested loops - those need their own exit handling
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition,
                body: convert_escaping_gotos_to_break(body, targets),
                header,
                exit_block,
            },

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: convert_escaping_gotos_to_break(body, targets),
                condition,
                header,
                exit_block,
            },

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => StructuredNode::For {
                init,
                condition,
                update,
                body: convert_escaping_gotos_to_break(body, targets),
                header,
                exit_block,
            },

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: convert_escaping_gotos_to_break(body, targets),
                header,
                exit_block,
            },

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => StructuredNode::Switch {
                value,
                cases: cases
                    .into_iter()
                    .map(|(vals, body)| (vals, convert_escaping_gotos_to_break(body, targets)))
                    .collect(),
                default: default.map(|d| convert_escaping_gotos_to_break(d, targets)),
            },

            StructuredNode::Sequence(seq) => {
                StructuredNode::Sequence(convert_escaping_gotos_to_break(seq, targets))
            }

            other => other,
        })
        .collect()
}

/// Structures shared exit paths by detecting when multiple gotos target the same block.
///
/// This identifies patterns where different code paths converge and restructures
/// them to avoid gotos where possible.
pub fn structure_shared_exits(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // Count how many gotos target each label
    let mut goto_counts: HashMap<BasicBlockId, usize> = HashMap::new();
    count_goto_targets(&nodes, &mut goto_counts);

    // For labels with multiple gotos, keep them
    // For labels with single gotos, try to inline
    let single_target_labels: HashSet<BasicBlockId> = goto_counts
        .iter()
        .filter(|(_, &count)| count == 1)
        .map(|(&id, _)| id)
        .collect();

    if single_target_labels.is_empty() {
        return nodes;
    }

    // Find the content of single-target labels and inline them
    let label_contents = extract_label_contents(&nodes, &single_target_labels);
    inline_single_target_labels(nodes, &label_contents)
}

/// Counts gotos to each target.
fn count_goto_targets(nodes: &[StructuredNode], counts: &mut HashMap<BasicBlockId, usize>) {
    for node in nodes {
        match node {
            StructuredNode::Goto(target) => {
                *counts.entry(*target).or_insert(0) += 1;
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                count_goto_targets(then_body, counts);
                if let Some(eb) = else_body {
                    count_goto_targets(eb, counts);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                count_goto_targets(body, counts);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    count_goto_targets(body, counts);
                }
                if let Some(d) = default {
                    count_goto_targets(d, counts);
                }
            }
            StructuredNode::Sequence(seq) => {
                count_goto_targets(seq, counts);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                count_goto_targets(try_body, counts);
                for h in catch_handlers {
                    count_goto_targets(&h.body, counts);
                }
            }
            _ => {}
        }
    }
}

/// Extracts the content following single-target labels.
fn extract_label_contents(
    nodes: &[StructuredNode],
    targets: &HashSet<BasicBlockId>,
) -> HashMap<BasicBlockId, Vec<StructuredNode>> {
    let mut contents = HashMap::new();

    let mut i = 0;
    while i < nodes.len() {
        if let StructuredNode::Label(label_id) = &nodes[i] {
            if targets.contains(label_id) {
                // Collect everything after this label until the next label or end
                let mut content = Vec::new();
                let mut j = i + 1;
                while j < nodes.len() {
                    if matches!(nodes[j], StructuredNode::Label(_)) {
                        break;
                    }
                    content.push(nodes[j].clone());
                    j += 1;
                }
                if !content.is_empty() {
                    contents.insert(*label_id, content);
                }
            }
        }
        i += 1;
    }

    contents
}

/// Inlines single-target labels.
fn inline_single_target_labels(
    nodes: Vec<StructuredNode>,
    contents: &HashMap<BasicBlockId, Vec<StructuredNode>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::Goto(target) if contents.contains_key(&target) => {
                // Replace goto with inlined content
                result.extend(contents.get(&target).unwrap().clone());
            }

            // Skip single-target labels and their content (already inlined)
            StructuredNode::Label(id) if contents.contains_key(&id) => {
                // Skip - content is inlined at goto site
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: inline_single_target_labels(then_body, contents),
                    else_body: else_body.map(|e| inline_single_target_labels(e, contents)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: inline_single_target_labels(body, contents),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: inline_single_target_labels(body, contents),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, inline_single_target_labels(body, contents)))
                        .collect(),
                    default: default.map(|d| inline_single_target_labels(d, contents)),
                });
            }

            StructuredNode::Sequence(seq) => {
                result.extend(inline_single_target_labels(seq, contents));
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: inline_single_target_labels(try_body, contents),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: inline_single_target_labels(h.body, contents),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Removes orphan gotos - gotos that target blocks with no corresponding labels.
///
/// These gotos are effectively unreachable or targets blocks that were inlined
/// elsewhere. The goto statements are removed if:
/// 1. The goto appears as the last statement in a sequence (dead code after loop exit)
/// 2. The goto appears right before code that will execute anyway (fallthrough)
///
/// For gotos that can't be removed, we leave them with a comment indicating
/// they're unresolved.
pub fn remove_orphan_gotos(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First, collect all labels that exist
    let existing_labels = collect_all_labels(&nodes);

    // Then, remove gotos to non-existent labels
    remove_gotos_without_labels(nodes, &existing_labels)
}

/// Collects all Label node targets from the structure.
fn collect_all_labels(nodes: &[StructuredNode]) -> HashSet<BasicBlockId> {
    let mut labels = HashSet::new();

    for node in nodes {
        match node {
            StructuredNode::Label(id) => {
                labels.insert(*id);
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                labels.extend(collect_all_labels(then_body));
                if let Some(eb) = else_body {
                    labels.extend(collect_all_labels(eb));
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                labels.extend(collect_all_labels(body));
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    labels.extend(collect_all_labels(body));
                }
                if let Some(d) = default {
                    labels.extend(collect_all_labels(d));
                }
            }
            StructuredNode::Sequence(seq) => {
                labels.extend(collect_all_labels(seq));
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                labels.extend(collect_all_labels(try_body));
                for h in catch_handlers {
                    labels.extend(collect_all_labels(&h.body));
                }
            }
            _ => {}
        }
    }

    labels
}

/// Removes gotos that don't have corresponding labels.
fn remove_gotos_without_labels(
    nodes: Vec<StructuredNode>,
    existing_labels: &HashSet<BasicBlockId>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            // Skip gotos to non-existent labels
            StructuredNode::Goto(target) if !existing_labels.contains(&target) => {
                // Skip this goto - it targets a non-existent label
                // This likely means the target was inlined elsewhere
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                let new_then = remove_gotos_without_labels(then_body, existing_labels);
                let new_else = else_body.map(|e| remove_gotos_without_labels(e, existing_labels));

                // Always emit the If structure - even with empty bodies, the condition may have side effects
                // and we want to preserve the control flow structure
                result.push(StructuredNode::If {
                    condition,
                    then_body: new_then,
                    else_body: new_else,
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::While {
                    condition,
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: remove_gotos_without_labels(body, existing_labels),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: remove_gotos_without_labels(body, existing_labels),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| {
                            (vals, remove_gotos_without_labels(body, existing_labels))
                        })
                        .collect(),
                    default: default.map(|d| remove_gotos_without_labels(d, existing_labels)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let cleaned = remove_gotos_without_labels(seq, existing_labels);
                result.extend(cleaned);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: remove_gotos_without_labels(try_body, existing_labels),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: remove_gotos_without_labels(h.body, existing_labels),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

// ============================================================================
// End of Goto Reduction Passes
// ============================================================================

/// Removes orphan continue statements that appear outside any loop context.
/// These are typically from switch cases that weren't properly integrated
/// into the switch structure.
pub fn remove_orphan_continues(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // At top level, we're not inside a loop
    remove_continues_impl(nodes, false)
}

/// Implementation of orphan continue removal.
/// `in_loop` tracks whether we're inside a loop context where continue is valid.
fn remove_continues_impl(nodes: Vec<StructuredNode>, in_loop: bool) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        match node {
            // Skip continue if we're not in a loop - it's orphan
            StructuredNode::Continue if !in_loop => {
                // Also skip any remaining nodes after the orphan continue
                // as they are unreachable
                break;
            }

            // Skip break if we're not in a loop/switch - it's orphan
            StructuredNode::Break if !in_loop => {
                break;
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                result.push(StructuredNode::If {
                    condition,
                    then_body: remove_continues_impl(then_body, in_loop),
                    else_body: else_body.map(|e| remove_continues_impl(e, in_loop)),
                });
            }

            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => {
                // Inside while body, continue is valid
                result.push(StructuredNode::While {
                    condition,
                    body: remove_continues_impl(body, true),
                    header,
                    exit_block,
                });
            }

            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::DoWhile {
                    body: remove_continues_impl(body, true),
                    condition,
                    header,
                    exit_block,
                });
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: remove_continues_impl(body, true),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => {
                result.push(StructuredNode::Loop {
                    body: remove_continues_impl(body, true),
                    header,
                    exit_block,
                });
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                // In switch cases, break is valid but continue is only valid if we're in a loop
                result.push(StructuredNode::Switch {
                    value,
                    cases: cases
                        .into_iter()
                        .map(|(vals, body)| (vals, remove_continues_impl(body, in_loop)))
                        .collect(),
                    default: default.map(|d| remove_continues_impl(d, in_loop)),
                });
            }

            StructuredNode::Sequence(seq) => {
                let cleaned = remove_continues_impl(seq, in_loop);
                result.extend(cleaned);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                result.push(StructuredNode::TryCatch {
                    try_body: remove_continues_impl(try_body, in_loop),
                    catch_handlers: catch_handlers
                        .into_iter()
                        .map(|h| CatchHandler {
                            body: remove_continues_impl(h.body, in_loop),
                            ..h
                        })
                        .collect(),
                });
            }

            other => result.push(other),
        }
    }

    result
}

/// Simplifies all expressions in the structured nodes using constant folding
/// and algebraic simplifications.
fn simplify_expressions(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(simplify_expressions_in_node)
        .collect()
}

/// Simplifies expressions in a single node.
fn simplify_expressions_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let simplified_statements =
                statements.into_iter().map(|expr| expr.simplify()).collect();
            StructuredNode::Block {
                id,
                statements: simplified_statements,
                address_range,
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: condition.simplify(),
            then_body: simplify_expressions(then_body),
            else_body: else_body.map(simplify_expressions),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: condition.simplify(),
            body: simplify_expressions(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_expressions(body),
            condition: condition.simplify(),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(|e| e.simplify()),
            condition: condition.simplify(),
            update: update.map(|e| e.simplify()),
            body: simplify_expressions(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_expressions(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: value.simplify(),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, simplify_expressions(body)))
                .collect(),
            default: default.map(simplify_expressions),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(simplify_expressions(nodes)),
        StructuredNode::Return(Some(expr)) => StructuredNode::Return(Some(expr.simplify())),
        StructuredNode::Expr(expr) => StructuredNode::Expr(expr.simplify()),
        // Other nodes pass through unchanged
        other => other,
    }
}

/// Flattens deeply nested if-else structures into guard clause style.
///
/// Transforms patterns like:
/// ```text
/// if (cond1) {
///     if (cond2) {
///         // actual work
///     } else {
///         return;
///     }
/// } else {
///     return;
/// }
/// ```
/// Into:
/// ```text
/// if (!cond1) {
///     return;
/// }
/// if (!cond2) {
///     return;
/// }
/// // actual work
/// ```
///
/// This significantly reduces nesting depth and improves readability.
pub fn flatten_guard_clauses(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();

    for node in nodes {
        flatten_node_into(&mut result, node);
    }

    result
}

/// Flattens a single node and appends results to the output vector.
fn flatten_node_into(output: &mut Vec<StructuredNode>, node: StructuredNode) {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            // First, recursively flatten both branches
            let then_body = flatten_guard_clauses(then_body);
            let else_body = else_body.map(flatten_guard_clauses);

            // Check if then_body terminates (ends with return/break/continue/goto)
            let then_terminates = body_terminates(&then_body);
            let else_terminates = else_body.as_ref().is_some_and(|e| body_terminates(e));
            let else_non_empty = else_body.as_ref().is_some_and(|e| !e.is_empty());

            // Case 1: then terminates, else has non-empty content that continues
            // Transform: if (cond) { return; } else { stuff } -> if (cond) { return; } stuff
            if then_terminates && else_non_empty && !else_terminates {
                let else_nodes = else_body.unwrap();
                // Emit the guard clause (if with terminating body, no else)
                output.push(StructuredNode::If {
                    condition,
                    then_body,
                    else_body: None,
                });
                // Flatten and append the else content as siblings
                for node in else_nodes {
                    flatten_node_into(output, node);
                }
            }
            // Case 2: else terminates, then has content that continues
            // Transform: if (cond) { stuff } else { return; } -> if (!cond) { return; } stuff
            else if else_terminates && !then_terminates && !then_body.is_empty() {
                let else_nodes = else_body.unwrap();
                // Emit the guard clause with negated condition
                output.push(StructuredNode::If {
                    condition: condition.negate(),
                    then_body: else_nodes,
                    else_body: None,
                });
                // Flatten and append the then content as siblings
                for node in then_body {
                    flatten_node_into(output, node);
                }
            }
            // Case 3: Neither case applies, keep the if structure but with flattened bodies
            else {
                output.push(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                });
            }
        }

        // Recursively process other compound nodes
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            output.push(StructuredNode::While {
                condition,
                body: flatten_guard_clauses(body),
                header,
                exit_block,
            });
        }

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            output.push(StructuredNode::DoWhile {
                body: flatten_guard_clauses(body),
                condition,
                header,
                exit_block,
            });
        }

        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            output.push(StructuredNode::For {
                init,
                condition,
                update,
                body: flatten_guard_clauses(body),
                header,
                exit_block,
            });
        }

        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            output.push(StructuredNode::Loop {
                body: flatten_guard_clauses(body),
                header,
                exit_block,
            });
        }

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            output.push(StructuredNode::Switch {
                value,
                cases: cases
                    .into_iter()
                    .map(|(vals, body)| (vals, flatten_guard_clauses(body)))
                    .collect(),
                default: default.map(flatten_guard_clauses),
            });
        }

        StructuredNode::Sequence(nodes) => {
            // Flatten the sequence contents directly into output
            for node in flatten_guard_clauses(nodes) {
                output.push(node);
            }
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            output.push(StructuredNode::TryCatch {
                try_body: flatten_guard_clauses(try_body),
                catch_handlers: catch_handlers
                    .into_iter()
                    .map(|h| CatchHandler {
                        body: flatten_guard_clauses(h.body),
                        ..h
                    })
                    .collect(),
            });
        }

        // Pass through simple nodes unchanged
        other => output.push(other),
    }
}

/// Checks if a body of statements terminates (ends with return/break/continue/goto/noreturn call).
fn body_terminates(body: &[StructuredNode]) -> bool {
    if body.is_empty() {
        return false;
    }

    // Check the last node
    match body.last() {
        Some(StructuredNode::Return(_)) => true,
        Some(StructuredNode::Break) => true,
        Some(StructuredNode::Continue) => true,
        Some(StructuredNode::Goto(_)) => true,
        // An if terminates if BOTH branches terminate
        Some(StructuredNode::If {
            then_body,
            else_body: Some(else_body),
            ..
        }) => body_terminates(then_body) && body_terminates(else_body),
        // A sequence terminates if its contents terminate
        Some(StructuredNode::Sequence(nodes)) => body_terminates(nodes),
        // Check for noreturn function calls (exit, abort, etc.)
        Some(StructuredNode::Expr(expr)) => is_noreturn_call(expr),
        Some(StructuredNode::Block { statements, .. }) => {
            // Check if block ends with a noreturn call
            statements.last().is_some_and(is_noreturn_call)
        }
        _ => false,
    }
}

/// Checks if an expression is a call to a noreturn function.
fn is_noreturn_call(expr: &Expr) -> bool {
    use super::expression::{CallTarget, ExprKind};

    match &expr.kind {
        ExprKind::Call {
            target: CallTarget::Named(name),
            ..
        } => is_noreturn_function(name),
        ExprKind::Assign { rhs, .. } => {
            // Check if RHS is a noreturn call (shouldn't normally happen, but be safe)
            is_noreturn_call(rhs)
        }
        _ => false,
    }
}

/// Checks if a function name is a known noreturn function.
fn is_noreturn_function(name: &str) -> bool {
    // Strip leading underscore(s) for comparison
    let name = name.trim_start_matches('_');

    matches!(
        name,
        "exit"
            | "Exit"
            | "abort"
            | "err"
            | "errx"
            | "verr"
            | "verrx"
            | "assert_fail"
            | "cxa_throw"
            | "cxa_rethrow"
            | "cxa_bad_cast"
            | "cxa_bad_typeid"
            | "Unwind_Resume"
            | "longjmp"
            | "siglongjmp"
            | "pthread_exit"
            | "thrd_exit"
            | "quick_exit"
            | "stack_chk_fail"
            | "fortify_fail"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, BlockTerminator, Condition};

    // --- Helper functions to create test CFGs ---

    fn make_diamond_cfg() -> ControlFlowGraph {
        //     bb0
        //    /   \
        //  bb1   bb2
        //    \   /
        //     bb3
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        cfg
    }

    fn make_while_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (loop header with condition)
        //        bb1 -> bb2 (loop body) -> bb1 (back edge)
        //        bb1 -> bb3 (exit)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1));

        cfg
    }

    fn make_dowhile_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (loop body)
        //        bb1 -> bb2 (condition at bottom)
        //        bb2 -> bb1 (back edge if true)
        //        bb2 -> bb3 (exit if false)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        cfg
    }

    fn make_infinite_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (loop header)
        //        bb1 -> bb1 (unconditional back edge)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(1));

        cfg
    }

    fn make_nested_if_cfg() -> ControlFlowGraph {
        // bb0 (if cond1)
        //   -> bb1 (then: if cond2)
        //        -> bb2 (then-then)
        //        -> bb3 (then-else)
        //        both -> bb4
        //   -> bb5 (else)
        //   bb4 -> bb6, bb5 -> bb6 (exit)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(5),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Less,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x1040);
        bb4.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(6),
        };
        cfg.add_block(bb4);

        let mut bb5 = BasicBlock::new(BasicBlockId::new(5), 0x1050);
        bb5.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(6),
        };
        cfg.add_block(bb5);

        let mut bb6 = BasicBlock::new(BasicBlockId::new(6), 0x1060);
        bb6.terminator = BlockTerminator::Return;
        cfg.add_block(bb6);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(5));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(6));
        cfg.add_edge(BasicBlockId::new(5), BasicBlockId::new(6));

        cfg
    }

    fn make_simple_return_cfg() -> ControlFlowGraph {
        // bb0 -> return
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Return;
        cfg.add_block(bb0);
        cfg
    }

    fn make_nested_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (outer header) -> bb2 (inner header) -> bb3 (inner body)
        //                                                      -> bb2 (inner back)
        //                              bb2 -> bb4 (between loops) -> bb1 (outer back)
        //        bb1 -> bb5 (exit)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(5),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(3),
            false_target: BasicBlockId::new(4),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x1040);
        bb4.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb4);

        let mut bb5 = BasicBlock::new(BasicBlockId::new(5), 0x1050);
        bb5.terminator = BlockTerminator::Return;
        cfg.add_block(bb5);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(5));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(1));

        cfg
    }

    // --- LoopKind Tests ---

    #[test]
    fn test_loop_kind_equality() {
        assert_eq!(LoopKind::While, LoopKind::While);
        assert_eq!(LoopKind::DoWhile, LoopKind::DoWhile);
        assert_eq!(LoopKind::Infinite, LoopKind::Infinite);
        assert_eq!(LoopKind::For, LoopKind::For);
        assert_ne!(LoopKind::While, LoopKind::DoWhile);
    }

    #[test]
    fn test_loop_kind_debug() {
        assert_eq!(format!("{:?}", LoopKind::While), "While");
        assert_eq!(format!("{:?}", LoopKind::DoWhile), "DoWhile");
        assert_eq!(format!("{:?}", LoopKind::Infinite), "Infinite");
        assert_eq!(format!("{:?}", LoopKind::For), "For");
    }

    #[test]
    fn test_loop_kind_copy() {
        let kind = LoopKind::While;
        let kind_copy = kind;
        assert_eq!(kind, kind_copy);
    }

    // --- LoopInfo Tests ---

    #[test]
    fn test_loop_info_creation() {
        let info = LoopInfo {
            header: BasicBlockId::new(1),
            back_edges: vec![BasicBlockId::new(2)],
            body: [BasicBlockId::new(1), BasicBlockId::new(2)]
                .into_iter()
                .collect(),
            kind: LoopKind::While,
            exit_blocks: vec![BasicBlockId::new(3)],
        };

        assert_eq!(info.header, BasicBlockId::new(1));
        assert_eq!(info.back_edges.len(), 1);
        assert_eq!(info.body.len(), 2);
        assert_eq!(info.kind, LoopKind::While);
        assert_eq!(info.exit_blocks.len(), 1);
    }

    #[test]
    fn test_loop_info_debug() {
        let info = LoopInfo {
            header: BasicBlockId::new(0),
            back_edges: vec![],
            body: HashSet::new(),
            kind: LoopKind::Infinite,
            exit_blocks: vec![],
        };
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("LoopInfo"));
        assert!(debug_str.contains("Infinite"));
    }

    // --- StructuredNode Tests ---

    #[test]
    fn test_structured_node_block() {
        let node = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![],
            address_range: (0x1000, 0x1010),
        };

        if let StructuredNode::Block {
            id,
            statements,
            address_range,
        } = node
        {
            assert_eq!(id, BasicBlockId::new(0));
            assert!(statements.is_empty());
            assert_eq!(address_range, (0x1000, 0x1010));
        } else {
            panic!("Expected Block node");
        }
    }

    #[test]
    fn test_structured_node_if() {
        let node = StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Break],
            else_body: Some(vec![StructuredNode::Continue]),
        };

        if let StructuredNode::If {
            then_body,
            else_body,
            ..
        } = node
        {
            assert_eq!(then_body.len(), 1);
            assert!(else_body.is_some());
            assert_eq!(else_body.unwrap().len(), 1);
        } else {
            panic!("Expected If node");
        }
    }

    #[test]
    fn test_structured_node_while() {
        let node = StructuredNode::While {
            condition: Expr::int(1),
            body: vec![],
            header: Some(BasicBlockId::new(1)),
            exit_block: None,
        };

        if let StructuredNode::While {
            condition, header, ..
        } = node
        {
            assert!(matches!(
                condition.kind,
                super::super::expression::ExprKind::IntLit(1)
            ));
            assert_eq!(header, Some(BasicBlockId::new(1)));
        } else {
            panic!("Expected While node");
        }
    }

    #[test]
    fn test_structured_node_dowhile() {
        let node = StructuredNode::DoWhile {
            body: vec![StructuredNode::Break],
            condition: Expr::int(0),
            header: Some(BasicBlockId::new(2)),
            exit_block: None,
        };

        if let StructuredNode::DoWhile { body, header, .. } = node {
            assert_eq!(body.len(), 1);
            assert_eq!(header, Some(BasicBlockId::new(2)));
        } else {
            panic!("Expected DoWhile node");
        }
    }

    #[test]
    fn test_structured_node_for() {
        let node = StructuredNode::For {
            init: Some(Expr::int(0)),
            condition: Expr::int(1),
            update: Some(Expr::int(1)),
            body: vec![],
            header: None,
            exit_block: None,
        };

        if let StructuredNode::For { init, update, .. } = node {
            assert!(init.is_some());
            assert!(update.is_some());
        } else {
            panic!("Expected For node");
        }
    }

    #[test]
    fn test_structured_node_loop() {
        let node = StructuredNode::Loop {
            body: vec![StructuredNode::Continue],
            header: Some(BasicBlockId::new(0)),
            exit_block: None,
        };

        if let StructuredNode::Loop { body, header, .. } = node {
            assert_eq!(body.len(), 1);
            assert!(header.is_some());
        } else {
            panic!("Expected Loop node");
        }
    }

    #[test]
    fn test_structured_node_break_continue() {
        assert!(matches!(StructuredNode::Break, StructuredNode::Break));
        assert!(matches!(StructuredNode::Continue, StructuredNode::Continue));
    }

    #[test]
    fn test_structured_node_return() {
        let ret_none = StructuredNode::Return(None);
        let ret_some = StructuredNode::Return(Some(Expr::int(42)));

        if let StructuredNode::Return(val) = ret_none {
            assert!(val.is_none());
        }

        if let StructuredNode::Return(val) = ret_some {
            assert!(val.is_some());
        }
    }

    #[test]
    fn test_structured_node_goto_label() {
        let goto = StructuredNode::Goto(BasicBlockId::new(5));
        let label = StructuredNode::Label(BasicBlockId::new(5));

        if let StructuredNode::Goto(target) = goto {
            assert_eq!(target, BasicBlockId::new(5));
        }

        if let StructuredNode::Label(target) = label {
            assert_eq!(target, BasicBlockId::new(5));
        }
    }

    #[test]
    fn test_structured_node_switch() {
        let node = StructuredNode::Switch {
            value: Expr::int(0),
            cases: vec![
                (vec![1], vec![StructuredNode::Break]),
                (vec![2, 3], vec![StructuredNode::Continue]),
            ],
            default: Some(vec![StructuredNode::Return(None)]),
        };

        if let StructuredNode::Switch { cases, default, .. } = node {
            assert_eq!(cases.len(), 2);
            assert_eq!(cases[0].0, vec![1]);
            assert_eq!(cases[1].0, vec![2, 3]);
            assert!(default.is_some());
        } else {
            panic!("Expected Switch node");
        }
    }

    // --- Range-based switch case tests ---

    fn make_test_var(name: &str) -> Expr {
        use super::super::expression::{VarKind, Variable};
        Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: name.to_string(),
            size: 4,
        })
    }

    #[test]
    fn test_extract_switch_range_info() {
        use super::super::expression::BinOpKind;

        // Test x >= 1 && x <= 10
        let var_x = make_test_var("x");
        let cond = Expr::binop(
            BinOpKind::LogicalAnd,
            Expr::binop(BinOpKind::Ge, var_x.clone(), Expr::int(1)),
            Expr::binop(BinOpKind::Le, var_x.clone(), Expr::int(10)),
        );

        let range_info = extract_switch_range_info(&cond);
        assert!(range_info.is_some());
        let info = range_info.unwrap();
        assert_eq!(info.start, 1);
        assert_eq!(info.end, 10);
    }

    #[test]
    fn test_extract_switch_range_reversed() {
        use super::super::expression::BinOpKind;

        // Test x <= 10 && x >= 1 (reversed order)
        let var_x = make_test_var("x");
        let cond = Expr::binop(
            BinOpKind::LogicalAnd,
            Expr::binop(BinOpKind::Le, var_x.clone(), Expr::int(10)),
            Expr::binop(BinOpKind::Ge, var_x.clone(), Expr::int(1)),
        );

        let range_info = extract_switch_range_info(&cond);
        assert!(range_info.is_some());
        let info = range_info.unwrap();
        assert_eq!(info.start, 1);
        assert_eq!(info.end, 10);
    }

    #[test]
    fn test_extract_switch_range_gt_lt() {
        use super::super::expression::BinOpKind;

        // Test x > 0 && x < 11 (should become [1, 10])
        let var_x = make_test_var("x");
        let cond = Expr::binop(
            BinOpKind::LogicalAnd,
            Expr::binop(BinOpKind::Gt, var_x.clone(), Expr::int(0)),
            Expr::binop(BinOpKind::Lt, var_x.clone(), Expr::int(11)),
        );

        let range_info = extract_switch_range_info(&cond);
        assert!(range_info.is_some());
        let info = range_info.unwrap();
        assert_eq!(info.start, 1);
        assert_eq!(info.end, 10);
    }

    #[test]
    fn test_extract_switch_range_too_large() {
        use super::super::expression::BinOpKind;

        // Test x >= 0 && x <= 1000 (should fail - range too large)
        let var_x = make_test_var("x");
        let cond = Expr::binop(
            BinOpKind::LogicalAnd,
            Expr::binop(BinOpKind::Ge, var_x.clone(), Expr::int(0)),
            Expr::binop(BinOpKind::Le, var_x.clone(), Expr::int(1000)),
        );

        let range_info = extract_switch_range_info(&cond);
        assert!(range_info.is_none()); // Too large, should fail
    }

    #[test]
    fn test_extract_switch_case_or_range_equality() {
        use super::super::expression::BinOpKind;

        // Test x == 5 (should return single value)
        let var_x = make_test_var("x");
        let cond = Expr::binop(BinOpKind::Eq, var_x.clone(), Expr::int(5));

        let result = extract_switch_case_or_range(&cond);
        assert!(result.is_some());
        let (_, _, values) = result.unwrap();
        assert_eq!(values, vec![5]);
    }

    #[test]
    fn test_extract_switch_case_or_range_range() {
        use super::super::expression::BinOpKind;

        // Test x >= 1 && x <= 3 (should return [1, 2, 3])
        let var_x = make_test_var("x");
        let cond = Expr::binop(
            BinOpKind::LogicalAnd,
            Expr::binop(BinOpKind::Ge, var_x.clone(), Expr::int(1)),
            Expr::binop(BinOpKind::Le, var_x.clone(), Expr::int(3)),
        );

        let result = extract_switch_case_or_range(&cond);
        assert!(result.is_some());
        let (_, _, values) = result.unwrap();
        assert_eq!(values, vec![1, 2, 3]);
    }

    #[test]
    fn test_structured_node_sequence() {
        let node = StructuredNode::Sequence(vec![
            StructuredNode::Break,
            StructuredNode::Continue,
            StructuredNode::Return(None),
        ]);

        if let StructuredNode::Sequence(nodes) = node {
            assert_eq!(nodes.len(), 3);
        } else {
            panic!("Expected Sequence node");
        }
    }

    #[test]
    fn test_structured_node_expr() {
        let node = StructuredNode::Expr(Expr::int(123));

        if let StructuredNode::Expr(expr) = node {
            assert!(matches!(
                expr.kind,
                super::super::expression::ExprKind::IntLit(123)
            ));
        } else {
            panic!("Expected Expr node");
        }
    }

    #[test]
    fn test_structured_node_try_catch() {
        let handler = CatchHandler {
            exception_type: Some("std::exception".to_string()),
            variable_name: Some("e".to_string()),
            body: vec![StructuredNode::Return(None)],
            landing_pad: 0x2000,
        };

        let node = StructuredNode::TryCatch {
            try_body: vec![StructuredNode::Break],
            catch_handlers: vec![handler],
        };

        if let StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } = node
        {
            assert_eq!(try_body.len(), 1);
            assert_eq!(catch_handlers.len(), 1);
            assert_eq!(
                catch_handlers[0].exception_type,
                Some("std::exception".to_string())
            );
        } else {
            panic!("Expected TryCatch node");
        }
    }

    // --- CatchHandler Tests ---

    #[test]
    fn test_catch_handler_creation() {
        let handler = CatchHandler {
            exception_type: None,
            variable_name: None,
            body: vec![],
            landing_pad: 0x3000,
        };

        assert!(handler.exception_type.is_none());
        assert!(handler.variable_name.is_none());
        assert!(handler.body.is_empty());
        assert_eq!(handler.landing_pad, 0x3000);
    }

    #[test]
    fn test_catch_handler_with_type() {
        let handler = CatchHandler {
            exception_type: Some("int".to_string()),
            variable_name: Some("x".to_string()),
            body: vec![StructuredNode::Break],
            landing_pad: 0x4000,
        };

        assert_eq!(handler.exception_type, Some("int".to_string()));
        assert_eq!(handler.variable_name, Some("x".to_string()));
    }

    // --- body_terminates Tests ---

    #[test]
    fn test_body_terminates_empty() {
        assert!(!body_terminates(&[]));
    }

    #[test]
    fn test_body_terminates_return() {
        assert!(body_terminates(&[StructuredNode::Return(None)]));
        assert!(body_terminates(&[StructuredNode::Return(Some(Expr::int(
            0
        )))]));
    }

    #[test]
    fn test_body_terminates_break_continue() {
        assert!(body_terminates(&[StructuredNode::Break]));
        assert!(body_terminates(&[StructuredNode::Continue]));
    }

    #[test]
    fn test_body_terminates_goto() {
        assert!(body_terminates(&[StructuredNode::Goto(BasicBlockId::new(
            0
        ))]));
    }

    #[test]
    fn test_body_terminates_if_both_branches() {
        // If both branches terminate, the if terminates
        let if_node = StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Return(None)],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        assert!(body_terminates(&[if_node]));
    }

    #[test]
    fn test_body_terminates_if_one_branch() {
        // If only one branch terminates, the if does not terminate
        let if_node = StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Return(None)],
            else_body: Some(vec![]), // else doesn't terminate
        };
        assert!(!body_terminates(&[if_node]));
    }

    #[test]
    fn test_body_terminates_if_no_else() {
        // If without else does not terminate
        let if_node = StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Return(None)],
            else_body: None,
        };
        assert!(!body_terminates(&[if_node]));
    }

    #[test]
    fn test_body_terminates_sequence() {
        let seq = StructuredNode::Sequence(vec![
            StructuredNode::Expr(Expr::int(1)),
            StructuredNode::Return(None),
        ]);
        assert!(body_terminates(&[seq]));
    }

    #[test]
    fn test_body_terminates_non_terminating() {
        // Block with just expressions doesn't terminate
        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::int(1)],
            address_range: (0, 0),
        };
        assert!(!body_terminates(&[block]));
    }

    // --- is_noreturn_function Tests ---

    #[test]
    fn test_is_noreturn_function_exit() {
        assert!(is_noreturn_function("exit"));
        assert!(is_noreturn_function("_exit"));
        assert!(is_noreturn_function("__exit"));
        assert!(is_noreturn_function("Exit"));
    }

    #[test]
    fn test_is_noreturn_function_abort() {
        assert!(is_noreturn_function("abort"));
        assert!(is_noreturn_function("_abort"));
    }

    #[test]
    fn test_is_noreturn_function_err_family() {
        assert!(is_noreturn_function("err"));
        assert!(is_noreturn_function("errx"));
        assert!(is_noreturn_function("verr"));
        assert!(is_noreturn_function("verrx"));
    }

    #[test]
    fn test_is_noreturn_function_cxx() {
        assert!(is_noreturn_function("__cxa_throw"));
        assert!(is_noreturn_function("__cxa_rethrow"));
        assert!(is_noreturn_function("__cxa_bad_cast"));
        assert!(is_noreturn_function("__cxa_bad_typeid"));
    }

    #[test]
    fn test_is_noreturn_function_longjmp() {
        assert!(is_noreturn_function("longjmp"));
        assert!(is_noreturn_function("siglongjmp"));
    }

    #[test]
    fn test_is_noreturn_function_thread() {
        assert!(is_noreturn_function("pthread_exit"));
        assert!(is_noreturn_function("thrd_exit"));
    }

    #[test]
    fn test_is_noreturn_function_security() {
        assert!(is_noreturn_function("__stack_chk_fail"));
        assert!(is_noreturn_function("__fortify_fail"));
    }

    #[test]
    fn test_is_noreturn_function_false() {
        assert!(!is_noreturn_function("printf"));
        assert!(!is_noreturn_function("malloc"));
        assert!(!is_noreturn_function("main"));
        assert!(!is_noreturn_function(""));
    }

    // --- Structurer Integration Tests ---

    #[test]
    fn test_structurer_simple_return() {
        let cfg = make_simple_return_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        assert_eq!(structured.cfg_entry, BasicBlockId::new(0));
        // Should produce at least a return node
        let has_return = structured
            .body()
            .iter()
            .any(|n| matches!(n, StructuredNode::Return(_)));
        assert!(has_return, "Should contain a return node");
    }

    #[test]
    fn test_structurer_diamond_if_else() {
        let cfg = make_diamond_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should produce an if-else structure
        let has_if = structured
            .body()
            .iter()
            .any(|n| matches!(n, StructuredNode::If { .. }));
        assert!(has_if, "Diamond CFG should produce if-else structure");
    }

    #[test]
    fn test_structurer_while_loop() {
        let cfg = make_while_loop_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should produce a while loop
        let has_while = structured
            .body()
            .iter()
            .any(|n| matches!(n, StructuredNode::While { .. } | StructuredNode::For { .. }));
        assert!(
            has_while,
            "While loop CFG should produce while/for structure"
        );
    }

    #[test]
    fn test_structurer_dowhile_loop() {
        let cfg = make_dowhile_loop_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should produce a do-while loop
        let has_dowhile = structured.body().iter().any(|n| {
            matches!(
                n,
                StructuredNode::DoWhile { .. }
                    | StructuredNode::While { .. }
                    | StructuredNode::Loop { .. }
            )
        });
        assert!(
            has_dowhile,
            "Do-while loop CFG should produce loop structure"
        );
    }

    #[test]
    fn test_structurer_infinite_loop() {
        let cfg = make_infinite_loop_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should produce an infinite loop or while(1)
        let has_loop = structured.body().iter().any(|n| {
            matches!(
                n,
                StructuredNode::Loop { .. } | StructuredNode::While { .. }
            )
        });
        assert!(
            has_loop,
            "Infinite loop CFG should produce loop/while structure"
        );
    }

    #[test]
    fn test_structurer_nested_if() {
        let cfg = make_nested_if_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should contain at least one if structure
        let has_if = structured
            .body()
            .iter()
            .any(|n| matches!(n, StructuredNode::If { .. }));
        assert!(has_if, "Nested if CFG should produce if structure");
    }

    #[test]
    fn test_structurer_nested_loop() {
        let cfg = make_nested_loop_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        // Should produce nested loops - count loop structures
        fn count_loops(nodes: &[StructuredNode]) -> usize {
            let mut count = 0;
            for node in nodes {
                match node {
                    StructuredNode::While { body, .. }
                    | StructuredNode::DoWhile { body, .. }
                    | StructuredNode::For { body, .. }
                    | StructuredNode::Loop { body, .. } => {
                        count += 1;
                        count += count_loops(body);
                    }
                    StructuredNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        count += count_loops(then_body);
                        if let Some(eb) = else_body {
                            count += count_loops(eb);
                        }
                    }
                    StructuredNode::Sequence(nodes) => {
                        count += count_loops(nodes);
                    }
                    _ => {}
                }
            }
            count
        }

        let loop_count = count_loops(structured.body());
        assert!(
            loop_count >= 1,
            "Nested loop CFG should produce at least 1 loop structure, got {}",
            loop_count
        );
    }

    // --- flatten_guard_clauses Tests ---

    #[test]
    fn test_flatten_guard_clauses_simple_return() {
        let nodes = vec![StructuredNode::Return(None)];
        let flattened = flatten_guard_clauses(nodes);
        assert_eq!(flattened.len(), 1);
        assert!(matches!(flattened[0], StructuredNode::Return(_)));
    }

    #[test]
    fn test_flatten_guard_clauses_if_with_return() {
        // if (cond) { work } else { return }
        // Should become: if (!cond) { return }; work
        let nodes = vec![StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Expr(Expr::int(42))],
            else_body: Some(vec![StructuredNode::Return(None)]),
        }];

        let flattened = flatten_guard_clauses(nodes);
        // The flattening transforms this pattern
        assert!(!flattened.is_empty());
    }

    #[test]
    fn test_flatten_guard_clauses_nested_sequence() {
        let nodes = vec![StructuredNode::Sequence(vec![
            StructuredNode::Expr(Expr::int(1)),
            StructuredNode::Sequence(vec![StructuredNode::Return(None)]),
        ])];

        let flattened = flatten_guard_clauses(nodes);
        // Sequences should be flattened
        assert!(!flattened.is_empty());
    }

    #[test]
    fn test_flatten_guard_clauses_preserves_loops() {
        let nodes = vec![StructuredNode::While {
            condition: Expr::int(1),
            body: vec![StructuredNode::Break],
            header: None,
            exit_block: None,
        }];

        let flattened = flatten_guard_clauses(nodes);
        assert_eq!(flattened.len(), 1);
        assert!(matches!(flattened[0], StructuredNode::While { .. }));
    }

    // --- Loop Classification Tests ---

    #[test]
    fn test_classify_loop_while() {
        let cfg = make_while_loop_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty(), "Should detect a loop");

        // The loop should be classified as While (condition at header)
        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let kind = Structurer::classify_loop(&cfg, &loops[0], &body_set);
        assert_eq!(kind, LoopKind::While);
    }

    #[test]
    fn test_classify_loop_dowhile() {
        let cfg = make_dowhile_loop_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty(), "Should detect a loop");

        // Find the actual back edge block for do-while classification
        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let kind = Structurer::classify_loop(&cfg, &loops[0], &body_set);
        // Do-while has condition at the back edge block
        assert!(
            kind == LoopKind::DoWhile || kind == LoopKind::While,
            "Should be DoWhile or While, got {:?}",
            kind
        );
    }

    // --- Find Loop Exits Tests ---

    #[test]
    fn test_find_loop_exits_while() {
        let cfg = make_while_loop_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty());

        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let exits = Structurer::find_loop_exits(&cfg, &body_set);

        assert!(
            exits.contains(&BasicBlockId::new(3)),
            "Loop exit should be bb3"
        );
    }

    #[test]
    fn test_find_loop_exits_infinite() {
        let cfg = make_infinite_loop_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty());

        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let exits = Structurer::find_loop_exits(&cfg, &body_set);

        // Infinite loop has no exits
        assert!(exits.is_empty(), "Infinite loop should have no exits");
    }

    // --- StructuredCfg body() Tests ---

    #[test]
    fn test_structured_cfg_body() {
        let cfg = make_simple_return_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        let body = structured.body();
        assert!(!body.is_empty());
    }

    // --- simplify_expressions Tests ---

    #[test]
    fn test_simplify_expressions_block() {
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::int(1)],
            address_range: (0, 0),
        }];

        let simplified = simplify_expressions(nodes);
        assert_eq!(simplified.len(), 1);
    }

    #[test]
    fn test_simplify_expressions_nested_if() {
        let nodes = vec![StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Expr(Expr::int(2))],
            else_body: Some(vec![StructuredNode::Expr(Expr::int(3))]),
        }];

        let simplified = simplify_expressions(nodes);
        assert_eq!(simplified.len(), 1);
    }

    #[test]
    fn test_simplify_expressions_for_loop() {
        let nodes = vec![StructuredNode::For {
            init: Some(Expr::int(0)),
            condition: Expr::int(1),
            update: Some(Expr::int(1)),
            body: vec![],
            header: None,
            exit_block: None,
        }];

        let simplified = simplify_expressions(nodes);
        assert_eq!(simplified.len(), 1);
    }

    // --- convert_gotos_to_break_continue Tests ---

    #[test]
    fn test_convert_gotos_no_loop_context() {
        let nodes = vec![StructuredNode::Goto(BasicBlockId::new(5))];
        let converted = convert_gotos_to_break_continue(nodes, None);

        // Without loop context, goto remains a goto
        assert_eq!(converted.len(), 1);
        assert!(matches!(converted[0], StructuredNode::Goto(_)));
    }

    #[test]
    fn test_convert_gotos_to_continue() {
        let ctx = LoopContext {
            header: BasicBlockId::new(1),
            exit_block: None,
        };

        let nodes = vec![StructuredNode::Goto(BasicBlockId::new(1))];
        let converted = convert_gotos_to_break_continue(nodes, Some(&ctx));

        // Goto to header becomes continue
        assert_eq!(converted.len(), 1);
        assert!(matches!(converted[0], StructuredNode::Continue));
    }

    #[test]
    fn test_convert_gotos_preserves_other() {
        let nodes = vec![StructuredNode::Return(None), StructuredNode::Break];
        let converted = convert_gotos_to_break_continue(nodes, None);

        assert_eq!(converted.len(), 2);
        assert!(matches!(converted[0], StructuredNode::Return(_)));
        assert!(matches!(converted[1], StructuredNode::Break));
    }

    #[test]
    fn test_convert_gotos_to_break() {
        // Goto to exit block should become break
        let ctx = LoopContext {
            header: BasicBlockId::new(1),
            exit_block: Some(BasicBlockId::new(5)),
        };

        let nodes = vec![StructuredNode::Goto(BasicBlockId::new(5))];
        let converted = convert_gotos_to_break_continue(nodes, Some(&ctx));

        // Goto to exit block becomes break
        assert_eq!(converted.len(), 1);
        assert!(matches!(converted[0], StructuredNode::Break));
    }

    #[test]
    fn test_convert_gotos_in_loop_with_exit() {
        // Test that gotos inside a while loop get converted to breaks
        let loop_header = BasicBlockId::new(10);
        let loop_exit = BasicBlockId::new(20);

        let while_node = StructuredNode::While {
            condition: Expr::int(1),
            body: vec![
                StructuredNode::If {
                    condition: Expr::int(0),
                    then_body: vec![StructuredNode::Goto(loop_exit)], // should become break
                    else_body: None,
                },
                StructuredNode::Goto(loop_header), // should become continue
            ],
            header: Some(loop_header),
            exit_block: Some(loop_exit),
        };

        let converted = convert_gotos_to_break_continue(vec![while_node], None);

        // Check that the while loop body has break and continue
        assert_eq!(converted.len(), 1);
        if let StructuredNode::While { body, .. } = &converted[0] {
            // Should have an If and Continue
            assert_eq!(body.len(), 2);

            // Check the If has a break in its then_body
            if let StructuredNode::If { then_body, .. } = &body[0] {
                assert_eq!(then_body.len(), 1);
                assert!(matches!(then_body[0], StructuredNode::Break));
            } else {
                panic!("Expected If node");
            }

            // Check the second node is continue
            assert!(matches!(body[1], StructuredNode::Continue));
        } else {
            panic!("Expected While node");
        }
    }

    #[test]
    fn test_capture_return_register_uses_after_call_arg0() {
        use crate::decompiler::expression::{CallTarget, ExprKind, VarKind, Variable};

        let call = Expr::call(CallTarget::Named("___error".to_string()), vec![]);
        let arg0 = Expr::var(Variable {
            kind: VarKind::Arg(0),
            name: "arg0".to_string(),
            size: 8,
        });
        let use_stmt = Expr::assign(Expr::var(Variable::reg("tmp0", 8)), Expr::deref(arg0, 4));

        let mut counter = 0u32;
        let out = capture_return_register_uses_in_block(vec![call, use_stmt], &mut counter);

        assert_eq!(out.len(), 3);
        // Inserted capture: ret_0 = arg0
        if let ExprKind::Assign { lhs, rhs } = &out[1].kind {
            match (&lhs.kind, &rhs.kind) {
                (ExprKind::Var(lv), ExprKind::Var(rv)) => {
                    assert_eq!(lv.name, "ret_0");
                    assert_eq!(rv.name, "arg0");
                }
                _ => panic!("expected var-to-var capture assignment"),
            }
        } else {
            panic!("expected inserted assignment");
        }
        // Original use rewritten to ret_0
        if let ExprKind::Assign { rhs, .. } = &out[2].kind {
            if let ExprKind::Deref { addr, .. } = &rhs.kind {
                if let ExprKind::Var(v) = &addr.kind {
                    assert_eq!(v.name, "ret_0");
                } else {
                    panic!("expected deref of ret_0");
                }
            } else {
                panic!("expected deref RHS");
            }
        } else {
            panic!("expected rewritten use assignment");
        }
    }

    #[test]
    fn test_rewrite_strcmp_switch_to_if() {
        use crate::decompiler::expression::{CallTarget, VarKind, Variable};

        let cmp_var = Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: "cmp_result".to_string(),
            size: 4,
        });
        let assign = Expr::assign(
            cmp_var.clone(),
            Expr::call(
                CallTarget::Named("strcmp".to_string()),
                vec![Expr::unknown("opt"), Expr::unknown("\"-separator\"")],
            ),
        );

        let nodes = vec![
            StructuredNode::Expr(assign),
            StructuredNode::Switch {
                value: cmp_var.clone(),
                cases: vec![(vec![0], vec![StructuredNode::Return(Some(Expr::int(1)))])],
                default: Some(vec![StructuredNode::Return(Some(Expr::int(0)))]),
            },
        ];

        let out = simplify_strcmp_switch_patterns(nodes);
        assert_eq!(out.len(), 1);
        match &out[0] {
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                assert_eq!(then_body.len(), 1);
                assert!(else_body.is_some());
                if let super::super::expression::ExprKind::BinOp { op, .. } = condition.kind {
                    assert_eq!(op, BinOpKind::Eq);
                } else {
                    panic!("expected equality condition");
                }
            }
            _ => panic!("expected If after rewrite"),
        }
    }
}
