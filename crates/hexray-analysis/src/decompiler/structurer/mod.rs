//! Control flow structuring.
//!
//! Transforms a CFG into structured control flow (if/else, while, for, etc.).

#![allow(dead_code)]

use hexray_core::{
    cfg::Loop, BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlow, ControlFlowGraph,
    Instruction, Operand, Operation,
};
use std::collections::{HashMap, HashSet};

use crate::dataflow::infer_cfg_arch;

use super::abi;
use super::expression::{
    resolve_adrp_patterns, BinOpKind, CallTarget as ExprCallTarget, Expr, ExprKind, UnaryOpKind,
    Variable,
};
use super::for_loop_detection::detect_for_loops;
use super::short_circuit::detect_short_circuit;
use super::switch_recovery::SwitchRecovery;
use super::{BinaryDataContext, ExceptionInfo};

mod cleanup;
mod condition;
mod gotos;
mod simplify;
mod switch;
pub use cleanup::{
    convert_cleanup_gotos, convert_gotos_to_early_returns, convert_multilevel_breaks,
    remove_orphan_gotos, remove_orphan_labels, structure_shared_exits,
};
#[cfg(test)]
use condition::try_extract_arm64_branch_condition;
use condition::{
    condition_to_expr_with_block, condition_to_expr_with_block_no_alu_updates,
    generate_writeback_expr, lift_cmovcc_with_context, lift_setcc_with_context, negate_condition,
};
#[cfg(test)]
use gotos::LoopContext;
use gotos::{
    collect_loop_headers, convert_global_gotos_to_continue, convert_gotos_to_break_continue,
    convert_switch_gotos_to_break,
};
#[cfg(test)]
use simplify::capture_return_register_uses_in_block;
use simplify::{
    extract_return_value, merge_return_value_captures, propagate_args_in_block,
    propagate_call_args_with_binary_data_and_arch, simplify_statements,
    statement_contains_real_call, substitute_return_register_uses,
};
use switch::{detect_switch_statements, simplify_strcmp_switch_patterns};
#[cfg(test)]
use switch::{extract_switch_case_or_range, extract_switch_range_info};

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

/// Pre-structuring annotations that adjust how the CFG is consumed
/// without mutating the underlying graph.
#[derive(Debug, Clone, Default)]
pub(crate) struct StructuringAnnotations {
    folded_conditions: HashMap<BasicBlockId, FoldedConditionCall>,
    folded_predecessor_calls: HashSet<BasicBlockId>,
    suppressed_side_blocks: HashSet<BasicBlockId>,
}

#[derive(Debug, Clone)]
struct FoldedConditionCall {
    predecessor: BasicBlockId,
    call_expr: Expr,
}

impl StructuringAnnotations {
    pub(crate) fn from_cfg_and_exception_info(
        cfg: &ControlFlowGraph,
        exception_info: Option<&ExceptionInfo>,
    ) -> Self {
        let mut annotations = Self::default();
        annotations.detect_folded_call_conditions(cfg);

        if let Some(info) = exception_info {
            annotations.detect_cleanup_side_blocks(cfg, info);
        }

        annotations
    }

    fn detect_folded_call_conditions(&mut self, cfg: &ControlFlowGraph) {
        for block_id in cfg.block_ids() {
            let Some(block) = cfg.block(block_id) else {
                continue;
            };
            if !is_foldable_condition_micro_block(block) {
                continue;
            }

            let preds = cfg.predecessors(block_id);
            let unique_preds: HashSet<_> = preds.iter().copied().collect();
            if unique_preds.len() != 1 {
                continue;
            }

            let pred_id = *unique_preds.iter().next().expect("single predecessor");
            let Some(pred_block) = cfg.block(pred_id) else {
                continue;
            };
            let succs = cfg.successors(pred_id);
            if succs.is_empty() || succs.iter().any(|succ| *succ != block_id) {
                continue;
            }

            let Some(call_inst) = pred_block.instructions.last() else {
                continue;
            };
            if !matches!(&call_inst.control_flow, ControlFlow::Call { .. }) {
                continue;
            }
            let Some(call_expr) = extract_folded_predecessor_call_expr(pred_block) else {
                continue;
            };

            self.folded_conditions.insert(
                block_id,
                FoldedConditionCall {
                    predecessor: pred_id,
                    call_expr,
                },
            );
            self.folded_predecessor_calls.insert(pred_id);
        }
    }

    fn detect_cleanup_side_blocks(
        &mut self,
        cfg: &ControlFlowGraph,
        exception_info: &ExceptionInfo,
    ) {
        let mut landing_pad_blocks = HashSet::new();

        for cleanup in &exception_info.cleanup_handlers {
            if let Some(block) = cfg.block_containing(cleanup.landing_pad) {
                landing_pad_blocks.insert(block.id);
                continue;
            }

            if let Some(block_id) = cfg.block_ids().find(|&block_id| {
                cfg.block(block_id)
                    .map(|block| {
                        block.start >= cleanup.landing_pad && block.start < cleanup.landing_pad + 32
                    })
                    .unwrap_or(false)
            }) {
                landing_pad_blocks.insert(block_id);
            }
        }

        self.suppressed_side_blocks.extend(&landing_pad_blocks);

        let mut changed = true;
        while changed {
            changed = false;
            let current_side_blocks: Vec<_> = self.suppressed_side_blocks.iter().copied().collect();

            for block_id in current_side_blocks {
                for &succ in cfg.successors(block_id) {
                    if self.suppressed_side_blocks.contains(&succ) {
                        continue;
                    }

                    let preds = cfg.predecessors(succ);
                    if !preds.is_empty()
                        && preds
                            .iter()
                            .all(|pred| self.suppressed_side_blocks.contains(pred))
                    {
                        changed |= self.suppressed_side_blocks.insert(succ);
                    }
                }
            }
        }
    }

    fn folded_condition(&self, block_id: BasicBlockId) -> Option<&FoldedConditionCall> {
        self.folded_conditions.get(&block_id)
    }

    fn suppresses_predecessor_call(&self, block_id: BasicBlockId) -> bool {
        self.folded_predecessor_calls.contains(&block_id)
    }

    fn folded_condition_successor(&self, block_id: BasicBlockId) -> Option<BasicBlockId> {
        self.folded_conditions
            .iter()
            .find_map(|(&cond_block, folded)| {
                (folded.predecessor == block_id).then_some(cond_block)
            })
    }

    fn suppresses_side_block(&self, block_id: BasicBlockId) -> bool {
        self.suppressed_side_blocks.contains(&block_id)
    }
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
        let known_noreturn_targets = HashMap::new();
        Self::from_cfg_with_config_and_binary_data_and_exception_info_and_noreturn_targets(
            cfg,
            config,
            None,
            None,
            &known_noreturn_targets,
        )
    }

    pub(crate) fn from_cfg_with_config_and_binary_data_and_exception_info(
        cfg: &ControlFlowGraph,
        config: &super::config::DecompilerConfig,
        binary_data: Option<&BinaryDataContext>,
        exception_info: Option<&ExceptionInfo>,
    ) -> Self {
        let known_noreturn_targets = HashMap::new();
        let known_ubsan_targets = HashMap::new();
        Self::from_cfg_with_config_and_binary_data_and_exception_info_and_known_targets(
            cfg,
            config,
            binary_data,
            exception_info,
            &known_noreturn_targets,
            &known_ubsan_targets,
        )
    }

    pub(crate) fn from_cfg_with_config_and_binary_data_and_exception_info_and_noreturn_targets(
        cfg: &ControlFlowGraph,
        config: &super::config::DecompilerConfig,
        binary_data: Option<&BinaryDataContext>,
        exception_info: Option<&ExceptionInfo>,
        known_noreturn_targets: &HashMap<u64, String>,
    ) -> Self {
        let known_ubsan_targets = HashMap::new();
        Self::from_cfg_with_config_and_binary_data_and_exception_info_and_known_targets(
            cfg,
            config,
            binary_data,
            exception_info,
            known_noreturn_targets,
            &known_ubsan_targets,
        )
    }

    pub(crate) fn from_cfg_with_config_and_binary_data_and_exception_info_and_known_targets(
        cfg: &ControlFlowGraph,
        config: &super::config::DecompilerConfig,
        binary_data: Option<&BinaryDataContext>,
        exception_info: Option<&ExceptionInfo>,
        known_noreturn_targets: &HashMap<u64, String>,
        known_ubsan_targets: &HashMap<u64, String>,
    ) -> Self {
        use super::config::OptimizationPass;

        let annotations = StructuringAnnotations::from_cfg_and_exception_info(cfg, exception_info);
        let mut structurer = Structurer::new_with_binary_data_annotations_and_known_targets(
            cfg,
            binary_data,
            annotations,
            known_noreturn_targets.clone(),
            known_ubsan_targets.clone(),
        );
        let mut body = structurer.structure();
        if !structurer.known_noreturn_targets.is_empty() {
            body = rewrite_known_noreturn_calls(body, &structurer.known_noreturn_targets);
        }

        // Post-process to propagate arguments into function calls (before copy propagation)
        if config.is_pass_enabled(OptimizationPass::CallArgPropagation) {
            body = propagate_call_args_with_binary_data_and_arch(
                body,
                structurer.binary_data,
                infer_cfg_arch(cfg),
            );
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

        // Post-process to eliminate common subexpressions
        if config.is_pass_enabled(OptimizationPass::CommonSubexpressionElimination) {
            body = super::cse::eliminate_common_subexpressions(body);
        }

        // Post-process to infer better variable names
        if config.is_pass_enabled(OptimizationPass::VariableNaming) {
            body = super::variable_naming::suggest_variable_names(body);
        }

        // Run dead store elimination again after variable naming
        // This catches duplicates that arise from variables being renamed to the same name
        if config.is_pass_enabled(OptimizationPass::DeadStoreElimination) {
            body = super::dead_store::eliminate_dead_stores(body);
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
        Self::from_cfg_with_config_and_binary_data_and_exception_info(
            cfg,
            config,
            binary_data,
            None,
        )
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
    /// Pre-structuring annotations for folded condition blocks and EH side blocks.
    annotations: StructuringAnnotations,
    /// Binary data context for jump table reconstruction.
    binary_data: Option<&'a BinaryDataContext>,
    /// Known noreturn call targets resolved from the enclosing decompiler context.
    known_noreturn_targets: HashMap<u64, String>,
    /// Known recoverable UBSan helper targets resolved from the enclosing decompiler context.
    known_ubsan_targets: HashMap<u64, String>,
}

impl<'a> Structurer<'a> {
    fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self::new_with_binary_data_annotations_and_noreturn_targets(
            cfg,
            None,
            StructuringAnnotations::default(),
            HashMap::new(),
        )
    }

    fn new_with_annotations(
        cfg: &'a ControlFlowGraph,
        annotations: StructuringAnnotations,
    ) -> Self {
        Self::new_with_binary_data_annotations_and_noreturn_targets(
            cfg,
            None,
            annotations,
            HashMap::new(),
        )
    }

    fn new_with_binary_data_and_annotations(
        cfg: &'a ControlFlowGraph,
        binary_data: Option<&'a BinaryDataContext>,
        annotations: StructuringAnnotations,
    ) -> Self {
        Self::new_with_binary_data_annotations_and_noreturn_targets(
            cfg,
            binary_data,
            annotations,
            HashMap::new(),
        )
    }

    fn new_with_binary_data_annotations_and_noreturn_targets(
        cfg: &'a ControlFlowGraph,
        binary_data: Option<&'a BinaryDataContext>,
        annotations: StructuringAnnotations,
        known_noreturn_targets: HashMap<u64, String>,
    ) -> Self {
        Self::new_with_binary_data_annotations_and_known_targets(
            cfg,
            binary_data,
            annotations,
            known_noreturn_targets,
            HashMap::new(),
        )
    }

    fn new_with_binary_data_annotations_and_known_targets(
        cfg: &'a ControlFlowGraph,
        binary_data: Option<&'a BinaryDataContext>,
        annotations: StructuringAnnotations,
        known_noreturn_targets: HashMap<u64, String>,
        known_ubsan_targets: HashMap<u64, String>,
    ) -> Self {
        let loops = cfg.find_loops();
        let mut loop_headers = HashSet::new();
        let mut loop_info = HashMap::new();

        for lp in &loops {
            loop_headers.insert(lp.header);

            let body_set: HashSet<_> = lp.body.iter().copied().collect();
            let exit_blocks = Self::find_loop_exits(cfg, &body_set);
            let kind = Self::classify_loop(cfg, lp, &body_set, &annotations);

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
            annotations,
            binary_data,
            known_noreturn_targets,
            known_ubsan_targets,
        }
    }

    fn is_noreturn_call(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call {
                target: ExprCallTarget::Named(name),
                ..
            } => crate::is_noreturn_function_name(name),
            ExprKind::Call {
                target: ExprCallTarget::Direct { target, .. },
                ..
            } => self.known_noreturn_targets.contains_key(target),
            ExprKind::Assign { rhs, .. } => self.is_noreturn_call(rhs),
            _ => false,
        }
    }

    fn body_terminates(&self, body: &[StructuredNode]) -> bool {
        if body.is_empty() {
            return false;
        }

        match body.last() {
            Some(StructuredNode::Return(_)) => true,
            Some(StructuredNode::Break) => true,
            Some(StructuredNode::Continue) => true,
            Some(StructuredNode::Goto(_)) => true,
            Some(StructuredNode::If {
                then_body,
                else_body: Some(else_body),
                ..
            }) => self.body_terminates(then_body) && self.body_terminates(else_body),
            Some(StructuredNode::Sequence(nodes)) => self.body_terminates(nodes),
            Some(StructuredNode::Expr(expr)) => self.is_noreturn_call(expr),
            Some(StructuredNode::Block { statements, .. }) => statements
                .last()
                .is_some_and(|expr| self.is_noreturn_call(expr)),
            _ => false,
        }
    }

    fn attach_shared_return_to_branch(
        &self,
        mut body: Vec<StructuredNode>,
        shared_return: Option<Expr>,
    ) -> Vec<StructuredNode> {
        let stripped_terminal_bare_return =
            matches!(body.last(), Some(StructuredNode::Return(None)));
        if stripped_terminal_bare_return {
            body.pop();
        } else if self.body_terminates(&body) {
            return body;
        }

        let mut return_value = shared_return;

        if let Some(StructuredNode::Block { statements, .. }) = body.last_mut() {
            let original_statements = std::mem::take(statements);
            let (filtered_statements, branch_return) =
                extract_return_value(original_statements.clone());
            let branch_return_is_safe = branch_return.is_some()
                && filtered_statements
                    .last()
                    .map_or(true, |stmt| !statement_contains_real_call(stmt));
            if branch_return_is_safe {
                *statements = filtered_statements;
                return_value = branch_return;
            } else {
                *statements = original_statements;
            }
        }

        if matches!(
            body.last(),
            Some(StructuredNode::Block { statements, .. }) if statements.is_empty()
        ) {
            body.pop();
        }

        if self.body_terminates(&body) {
            return body;
        }

        body.push(StructuredNode::Return(return_value));
        body
    }

    fn new_with_binary_data(
        cfg: &'a ControlFlowGraph,
        binary_data: Option<&'a BinaryDataContext>,
    ) -> Self {
        Self::new_with_binary_data_and_annotations(
            cfg,
            binary_data,
            StructuringAnnotations::default(),
        )
    }

    /// Checks if a block (and its successors) eventually return with just cleanup calls.
    ///
    /// Returns:
    /// - `Some(Some(expr))` for pure return chains with an explicit return value
    /// - `Some(None)` for pure return chains with a void return
    /// - `None` when the chain is not a pure return
    fn get_return_expr_if_pure_return(&self, block_id: BasicBlockId) -> Option<Option<Expr>> {
        self.get_return_expr_following_chain(block_id, &mut HashSet::new())
    }

    fn mark_pure_return_chain_processed(&mut self, block_id: BasicBlockId) {
        self.mark_pure_return_chain_processed_inner(block_id, &mut HashSet::new());
    }

    /// Helper that follows the chain of blocks to find the return expression.
    fn get_return_expr_following_chain(
        &self,
        block_id: BasicBlockId,
        visited: &mut HashSet<BasicBlockId>,
    ) -> Option<Option<Expr>> {
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
                Some(self.extract_return_value(block))
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
                let target_return = self.get_return_expr_following_chain(*target, visited)?;
                let (remaining_statements, block_return) =
                    extract_return_value(self.block_to_statements(block_id));
                if remaining_statements.is_empty() {
                    if block_return.is_some() {
                        return Some(block_return);
                    }
                    return Some(target_return);
                }
                None
            }
            BlockTerminator::Fallthrough { target } => {
                let target_return = self.get_return_expr_following_chain(*target, visited)?;
                let (remaining_statements, block_return) =
                    extract_return_value(self.block_to_statements(block_id));
                if remaining_statements.is_empty() {
                    if block_return.is_some() {
                        return Some(block_return);
                    }
                    return Some(target_return);
                }
                None
            }
            _ => None,
        }
    }

    fn mark_pure_return_chain_processed_inner(
        &mut self,
        block_id: BasicBlockId,
        visited: &mut HashSet<BasicBlockId>,
    ) {
        if !visited.insert(block_id) {
            return;
        }

        let Some(block) = self.cfg.block(block_id) else {
            return;
        };

        self.processed.insert(block_id);

        match &block.terminator {
            BlockTerminator::Return => {}
            BlockTerminator::Call { return_block, .. } => {
                if self.is_cleanup_block(block) {
                    self.mark_pure_return_chain_processed_inner(*return_block, visited);
                }
            }
            BlockTerminator::Jump { target } | BlockTerminator::Fallthrough { target } => {
                self.mark_pure_return_chain_processed_inner(*target, visited);
            }
            _ => {}
        }
    }

    /// Extracts the return value from a pure return block.
    ///
    /// Returns `None` when the block is a pure `return;` without an explicit
    /// return-register assignment.
    fn extract_return_value(&self, block: &BasicBlock) -> Option<Expr> {
        let mut return_value: Option<Expr> = None;

        for inst in &block.instructions {
            // Check for return value setup in the architecture return register.
            if matches!(inst.operation, Operation::Move | Operation::Load)
                && inst.operands.len() >= 2
            {
                if let hexray_core::Operand::Register(dst) = &inst.operands[0] {
                    let dst_name = dst.name().to_lowercase();
                    if abi::is_return_register(&dst_name) {
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

        // Only return an expression when we saw an explicit return-register assignment.
        return_value.or_else(|| self.implicit_return_register_expr_for_block(block.id))
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

    fn is_pure_asan_report_block(&self, block_id: BasicBlockId) -> bool {
        let Some(block) = self.cfg.block(block_id) else {
            return false;
        };
        let Some(call_inst) = block.instructions.last() else {
            return false;
        };
        let ControlFlow::Call { target, .. } = &call_inst.control_flow else {
            return false;
        };
        let Some(name) = self.known_noreturn_targets.get(target) else {
            return false;
        };
        let stripped = name.trim_start_matches('_');
        if !stripped.starts_with("asan_report_") || stripped.ends_with("_noabort") {
            return false;
        }

        for inst in &block.instructions[..block.instructions.len().saturating_sub(1)] {
            if inst.mnemonic.starts_with("nop") || inst.mnemonic.starts_with("endbr") {
                continue;
            }
            if !inst
                .writes
                .iter()
                .all(|reg| abi::is_argument_register(reg.name()))
            {
                return false;
            }
        }

        true
    }

    fn asan_probe_normal_target(
        &self,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
    ) -> Option<(BasicBlockId, BasicBlockId)> {
        if self.is_pure_asan_report_block(true_target) {
            return Some((true_target, false_target));
        }
        if self.is_pure_asan_report_block(false_target) {
            return Some((false_target, true_target));
        }
        None
    }

    fn is_recoverable_ubsan_handler_block(
        &self,
        block_id: BasicBlockId,
        normal_target: BasicBlockId,
    ) -> bool {
        let Some(block) = self.cfg.block(block_id) else {
            return false;
        };
        let Some(call_inst) = block.instructions.last() else {
            return false;
        };
        let ControlFlow::Call { target, .. } = &call_inst.control_flow else {
            return false;
        };
        let Some(name) = self.known_ubsan_targets.get(target) else {
            return false;
        };
        if !crate::is_ubsan_handler_function_name(name) {
            return false;
        }
        if !matches!(
            block.terminator,
            BlockTerminator::Call { return_block, .. } if return_block == normal_target
        ) && !matches!(
            block.terminator,
            BlockTerminator::Jump { target } | BlockTerminator::Fallthrough { target }
                if target == normal_target
        ) {
            return false;
        }

        block.instructions[..block.instructions.len().saturating_sub(1)]
            .iter()
            .all(|inst| !inst.is_branch() && inst.operation != Operation::Syscall)
    }

    fn ubsan_probe_normal_target(
        &self,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
    ) -> Option<(BasicBlockId, BasicBlockId)> {
        if self.is_recoverable_ubsan_handler_block(true_target, false_target) {
            return Some((true_target, false_target));
        }
        if self.is_recoverable_ubsan_handler_block(false_target, true_target) {
            return Some((false_target, true_target));
        }
        None
    }

    fn is_stack_canary_fail_block(
        &self,
        block_id: BasicBlockId,
        normal_target: BasicBlockId,
    ) -> bool {
        let Some(block) = self.cfg.block(block_id) else {
            return false;
        };
        let Some(call_inst) = block.instructions.last() else {
            return false;
        };
        let ControlFlow::Call { target, .. } = &call_inst.control_flow else {
            return false;
        };
        let Some(name) = self.known_noreturn_targets.get(target) else {
            return false;
        };
        if !name.contains("stack_chk_fail") {
            return false;
        }
        if !matches!(
            block.terminator,
            BlockTerminator::Call { return_block, .. } if return_block == normal_target
        ) && !matches!(
            block.terminator,
            BlockTerminator::Jump { target } | BlockTerminator::Fallthrough { target }
                if target == normal_target
        ) {
            return false;
        }

        block.instructions[..block.instructions.len().saturating_sub(1)]
            .iter()
            .all(|inst| !inst.is_branch() && inst.operation != Operation::Syscall)
    }

    fn stack_canary_probe_normal_target(
        &self,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
    ) -> Option<(BasicBlockId, BasicBlockId)> {
        if self.is_stack_canary_fail_block(true_target, false_target) {
            return Some((true_target, false_target));
        }
        if self.is_stack_canary_fail_block(false_target, true_target) {
            return Some((false_target, true_target));
        }
        None
    }

    fn asan_probe_setup_end_index(
        &self,
        block: &BasicBlock,
        normal_target: BasicBlockId,
    ) -> Option<usize> {
        let normal_block = self.cfg.block(normal_target)?;
        let access_regs: HashSet<u16> = normal_block.instructions.iter().find_map(|inst| {
            let regs: HashSet<u16> = inst
                .operands
                .iter()
                .filter_map(|operand| match operand {
                    Operand::Memory(mem) => mem.base.as_ref().map(|reg| reg.id),
                    _ => None,
                })
                .collect();
            (!regs.is_empty()).then_some(regs)
        })?;

        block
            .instructions
            .iter()
            .enumerate()
            .rfind(|(_, inst)| {
                matches!(
                    inst.operands.first(),
                    Some(Operand::Register(reg)) if access_regs.contains(&reg.id)
                ) || instruction_transfers_from_any_reg(inst, &access_regs)
            })
            .map(|(idx, _)| idx)
    }

    fn recoverable_ubsan_setup_end_index(
        &self,
        block: &BasicBlock,
        normal_target: BasicBlockId,
    ) -> Option<usize> {
        let has_explicit_guard_setup = block.instructions.iter().any(|inst| {
            matches!(inst.operation, Operation::Compare | Operation::Test)
                || matches!(inst.operation, Operation::Sub if inst.operands.len() < 3)
        });
        if !has_explicit_guard_setup {
            return block.instructions.len().checked_sub(1);
        }

        let live_in_regs = self.block_live_in_registers(normal_target)?;
        // Architectures whose disassemblers don't populate inst.reads /
        // inst.writes (notably x86_64) leave live_in_regs empty even when
        // there is a real continuation user value. Falling back to keeping
        // every prior instruction is safer than dropping the user
        // computation along with the helper-arg setup.
        if live_in_regs.is_empty() {
            return block.instructions.len().checked_sub(1);
        }

        block
            .instructions
            .iter()
            .enumerate()
            .rfind(|(_, inst)| {
                inst.writes
                    .iter()
                    .map(canonical_register_key)
                    .any(|reg| live_in_regs.contains(&reg))
            })
            .map(|(idx, _)| idx)
            .or_else(|| block.instructions.len().checked_sub(1))
    }

    fn block_live_in_registers(&self, block_id: BasicBlockId) -> Option<HashSet<String>> {
        let block = self.cfg.block(block_id)?;
        let mut defined = HashSet::new();
        let mut live_in = HashSet::new();

        for inst in &block.instructions {
            for reg in &inst.reads {
                let reg = canonical_register_key(reg);
                if !defined.contains(&reg) {
                    live_in.insert(reg);
                }
            }
            for reg in &inst.writes {
                defined.insert(canonical_register_key(reg));
            }
        }

        Some(live_in)
    }

    fn can_inline_ubsan_continuation(
        &self,
        block_id: BasicBlockId,
        handler_target: BasicBlockId,
        normal_target: BasicBlockId,
    ) -> bool {
        let preds = self.cfg.predecessors(normal_target);
        !preds.is_empty()
            && preds
                .iter()
                .all(|pred| *pred == block_id || *pred == handler_target)
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

    fn classify_loop(
        cfg: &ControlFlowGraph,
        lp: &Loop,
        body: &HashSet<BasicBlockId>,
        annotations: &StructuringAnnotations,
    ) -> LoopKind {
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
                    // A conditional self-loop executes the block body before evaluating
                    // the terminating branch, so it is structurally a do-while.
                    if lp.back_edge == lp.header {
                        return LoopKind::DoWhile;
                    }
                    return LoopKind::While;
                }
            }
        }

        // Folded call->test headers keep the condition in the successor block.
        if let Some(cond_block_id) = annotations.folded_condition_successor(lp.header) {
            if let Some(cond_block) = cfg.block(cond_block_id) {
                if let BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                    ..
                } = &cond_block.terminator
                {
                    let true_in_loop = body.contains(true_target);
                    let false_in_loop = body.contains(false_target);
                    if true_in_loop != false_in_loop {
                        return LoopKind::While;
                    }
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

        if let Some(cond_block_id) = annotations.folded_condition_successor(lp.back_edge) {
            if let Some(cond_block) = cfg.block(cond_block_id) {
                if let BlockTerminator::ConditionalBranch {
                    true_target,
                    false_target,
                    ..
                } = &cond_block.terminator
                {
                    if *true_target == lp.header || *false_target == lp.header {
                        return LoopKind::DoWhile;
                    }
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
            .filter(|b| !self.processed.contains(b) && !self.annotations.suppresses_side_block(**b))
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

            if self.annotations.suppresses_side_block(block_id) {
                self.processed.insert(block_id);
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
                    self.mark_pure_return_chain_processed(block_id);
                    result.push(StructuredNode::Return(ret_expr));
                } else {
                    result.push(StructuredNode::Goto(block_id));
                }
                break;
            }

            // Prevent infinite loops in structuring
            if self.processed.contains(&block_id) {
                // Check if target is a pure return block - if so, emit return instead of goto
                if let Some(ret_expr) = self.get_return_expr_if_pure_return(block_id) {
                    self.mark_pure_return_chain_processed(block_id);
                    result.push(StructuredNode::Return(ret_expr));
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
            let mut statements = self.block_to_statements(block_id);
            let address_range = (block.start, block.end);

            // Handle based on terminator
            match &block.terminator {
                BlockTerminator::Return => {
                    // Check if last statement is an assignment to return register (eax/rax)
                    // If so, extract it as the return value
                    // Note: extract_return_value applies copy propagation internally
                    let (mut filtered_stmts, return_value) = extract_return_value(statements);
                    let implicit_return = return_value
                        .is_none()
                        .then(|| self.implicit_return_register_expr_for_block(block_id))
                        .flatten();
                    if matches!(
                        implicit_return,
                        Some(Expr {
                            kind: ExprKind::Call { .. }
                        })
                    ) && matches!(
                        filtered_stmts.last(),
                        Some(Expr {
                            kind: ExprKind::Call { .. },
                        })
                    ) {
                        filtered_stmts.pop();
                    }
                    let return_value = return_value.or(implicit_return);

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

                BlockTerminator::Jump { target }
                    if self.is_empty_placeholder_block(*target)
                        && Self::tail_jump_call_expr(block).is_some() =>
                {
                    if let Some(expr) = Self::tail_jump_call_expr(block) {
                        statements.push(expr);
                        statements = propagate_args_in_block(statements);
                    }
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

                BlockTerminator::ExternalJump { target } => {
                    let call = Expr::call(
                        ExprCallTarget::Direct {
                            target: *target,
                            call_site: block.start,
                        },
                        vec![],
                    );
                    if !statements.is_empty() {
                        statements = propagate_args_in_block(statements);
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    result.push(StructuredNode::Return(Some(call)));
                    break;
                }

                BlockTerminator::ConditionalBranch {
                    condition,
                    true_target,
                    false_target,
                } => {
                    if let Some((report_target, normal_target)) =
                        self.asan_probe_normal_target(*true_target, *false_target)
                    {
                        if !statements.is_empty() {
                            result.push(StructuredNode::Block {
                                id: block_id,
                                statements,
                                address_range,
                            });
                        }
                        self.processed.insert(report_target);
                        current = Some(normal_target);
                        continue;
                    }
                    if let Some((handler_target, normal_target)) =
                        self.stack_canary_probe_normal_target(*true_target, *false_target)
                    {
                        let Some(normal_block) = self.cfg.block(normal_target) else {
                            break;
                        };
                        self.processed.insert(handler_target);
                        self.processed.insert(normal_target);

                        let mut merged_statements = statements.clone();
                        let mut normal_statements = self.block_to_statements(normal_target);
                        trim_trailing_epilogue_statements(&mut normal_statements);
                        merged_statements.append(&mut normal_statements);
                        let merged_range = (block.start, normal_block.end);

                        match &normal_block.terminator {
                            BlockTerminator::Return => {
                                let (mut filtered_stmts, return_value) =
                                    extract_return_value(merged_statements);
                                let implicit_return = return_value
                                    .is_none()
                                    .then(|| {
                                        self.implicit_return_register_expr_for_block(normal_target)
                                    })
                                    .flatten();
                                if matches!(
                                    implicit_return,
                                    Some(Expr {
                                        kind: ExprKind::Call { .. }
                                    })
                                ) && matches!(
                                    filtered_stmts.last(),
                                    Some(Expr {
                                        kind: ExprKind::Call { .. },
                                    })
                                ) {
                                    filtered_stmts.pop();
                                }
                                let return_value = return_value.or(implicit_return);

                                if !filtered_stmts.is_empty() {
                                    result.push(StructuredNode::Block {
                                        id: block_id,
                                        statements: filtered_stmts,
                                        address_range: merged_range,
                                    });
                                }
                                result.push(StructuredNode::Return(return_value));
                                break;
                            }
                            BlockTerminator::Jump { target }
                            | BlockTerminator::Fallthrough { target } => {
                                if self.can_inline_ubsan_continuation(
                                    block_id,
                                    handler_target,
                                    normal_target,
                                ) {
                                    if !merged_statements.is_empty() {
                                        result.push(StructuredNode::Block {
                                            id: block_id,
                                            statements: merged_statements,
                                            address_range: merged_range,
                                        });
                                    }
                                    current = Some(*target);
                                    continue;
                                }
                            }
                            _ => {}
                        }
                    }
                    if let Some((handler_target, normal_target)) =
                        self.ubsan_probe_normal_target(*true_target, *false_target)
                    {
                        self.processed.insert(handler_target);

                        let mut trimmed_normal = self.block_to_statements(normal_target);
                        trim_trailing_epilogue_statements(&mut trimmed_normal);
                        let (filtered_normal, normal_return) =
                            extract_return_value(trimmed_normal.clone());
                        if filtered_normal.is_empty() && normal_return.is_some() {
                            self.processed.insert(normal_target);

                            let mut merged_statements = statements.clone();
                            merged_statements.extend(trimmed_normal);
                            let (filtered_stmts, return_value) =
                                extract_return_value(merged_statements);

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

                        if self.can_inline_ubsan_continuation(
                            block_id,
                            handler_target,
                            normal_target,
                        ) {
                            let Some(normal_block) = self.cfg.block(normal_target) else {
                                break;
                            };

                            self.processed.insert(normal_target);
                            let mut merged_statements = statements.clone();
                            let mut normal_statements = self.block_to_statements(normal_target);
                            trim_trailing_epilogue_statements(&mut normal_statements);
                            merged_statements.append(&mut normal_statements);
                            let merged_range = (block.start, normal_block.end);

                            match &normal_block.terminator {
                                BlockTerminator::Return => {
                                    let (mut filtered_stmts, return_value) =
                                        extract_return_value(merged_statements);
                                    let implicit_return = return_value
                                        .is_none()
                                        .then(|| {
                                            self.implicit_return_register_expr_for_block(
                                                normal_target,
                                            )
                                        })
                                        .flatten();
                                    if matches!(
                                        implicit_return,
                                        Some(Expr {
                                            kind: ExprKind::Call { .. }
                                        })
                                    ) && matches!(
                                        filtered_stmts.last(),
                                        Some(Expr {
                                            kind: ExprKind::Call { .. },
                                        })
                                    ) {
                                        filtered_stmts.pop();
                                    }
                                    let return_value = return_value.or(implicit_return);

                                    if !filtered_stmts.is_empty() {
                                        result.push(StructuredNode::Block {
                                            id: block_id,
                                            statements: filtered_stmts,
                                            address_range: merged_range,
                                        });
                                    }
                                    result.push(StructuredNode::Return(return_value));
                                    break;
                                }
                                BlockTerminator::Jump { target }
                                | BlockTerminator::Fallthrough { target } => {
                                    if !merged_statements.is_empty() {
                                        result.push(StructuredNode::Block {
                                            id: block_id,
                                            statements: merged_statements,
                                            address_range: merged_range,
                                        });
                                    }
                                    current = Some(*target);
                                    continue;
                                }
                                BlockTerminator::Call { return_block, .. } => {
                                    if !merged_statements.is_empty() {
                                        result.push(StructuredNode::Block {
                                            id: block_id,
                                            statements: merged_statements,
                                            address_range: merged_range,
                                        });
                                    }
                                    current = Some(*return_block);
                                    continue;
                                }
                                _ => {}
                            }
                        }

                        if !statements.is_empty() {
                            result.push(StructuredNode::Block {
                                id: block_id,
                                statements,
                                address_range,
                            });
                        }
                        current = Some(normal_target);
                        continue;
                    }

                    // Add block statements first
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }

                    let join = self.find_join_point(*true_target, *false_target, end);

                    // Structure the if/else
                    let (if_node, consumes_join) = self.structure_if_else(
                        *condition,
                        *true_target,
                        *false_target,
                        join,
                        block_id,
                        block,
                    );
                    result.push(if_node);

                    if consumes_join {
                        break;
                    }

                    // Find join point and continue
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
                    if let Some(expr) = Self::tail_jump_call_expr(block) {
                        statements.push(expr);
                        statements = propagate_args_in_block(statements);
                    }
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
                    if let Some(expr) = Self::tail_jump_call_expr(block) {
                        statements.push(expr);
                        statements = propagate_args_in_block(statements);
                    }
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

    fn implicit_return_register_expr_for_block(&self, block_id: BasicBlockId) -> Option<Expr> {
        let block = self.cfg.block(block_id)?;
        if !matches!(block.terminator, BlockTerminator::Return) {
            return None;
        }
        if !self.cfg.successors(block_id).is_empty() {
            return None;
        }
        self.implicit_return_register_expr_for_block_inner(block_id, &mut HashSet::new())
    }

    fn implicit_return_register_expr_for_block_inner(
        &self,
        block_id: BasicBlockId,
        visited: &mut HashSet<BasicBlockId>,
    ) -> Option<Expr> {
        if !visited.insert(block_id) {
            return None;
        }

        let statements = self.block_to_statements(block_id);
        if let Some(expr) = Self::last_safe_return_register_expr_in_statements(&statements) {
            return Some(expr);
        }

        let mut candidate: Option<Variable> = None;
        for &pred in self.cfg.predecessors(block_id) {
            let pred_statements = self.block_to_statements(pred);
            if let Some(expr) = Self::last_safe_return_register_expr_in_statements(&pred_statements)
            {
                let ExprKind::Var(var) = expr.kind else {
                    continue;
                };
                match &candidate {
                    Some(existing) if existing != &var => return None,
                    Some(_) => {}
                    None => candidate = Some(var),
                }
                continue;
            }

            let Some(pred_block) = self.cfg.block(pred) else {
                continue;
            };
            let is_passthrough = pred_statements.is_empty()
                && matches!(
                    pred_block.terminator,
                    BlockTerminator::Jump { target } | BlockTerminator::Fallthrough { target }
                        if target == block_id
                );
            if !is_passthrough {
                continue;
            }

            let Some(expr) = self.implicit_return_register_expr_for_block_inner(pred, visited)
            else {
                continue;
            };
            let ExprKind::Var(var) = expr.kind else {
                continue;
            };
            match &candidate {
                Some(existing) if existing != &var => return None,
                Some(_) => {}
                None => candidate = Some(var),
            }
        }

        candidate.map(Expr::var)
    }

    fn last_safe_return_register_expr_in_statements(statements: &[Expr]) -> Option<Expr> {
        let mut saw_call_after = false;

        for stmt in statements.iter().rev() {
            match &stmt.kind {
                ExprKind::Call { .. } => {
                    saw_call_after = true;
                }
                ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
                    let ExprKind::Var(var) = &lhs.kind else {
                        continue;
                    };
                    if abi::is_return_register(&var.name) {
                        if saw_call_after {
                            return None;
                        }
                        return Some(Expr::var(var.clone()));
                    }
                }
                _ => {}
            }
        }

        None
    }

    fn is_empty_placeholder_block(&self, block_id: BasicBlockId) -> bool {
        self.cfg
            .block(block_id)
            .is_some_and(|block| block.instructions.is_empty())
    }

    fn tail_jump_call_expr(block: &BasicBlock) -> Option<Expr> {
        let inst = block.instructions.last()?;

        match (&block.terminator, &inst.control_flow) {
            (BlockTerminator::Unknown, ControlFlow::UnconditionalBranch { target }) => {
                Some(Expr::call(
                    ExprCallTarget::Direct {
                        target: *target,
                        call_site: inst.address,
                    },
                    Self::direct_tail_passthrough_args(block),
                ))
            }
            (BlockTerminator::Jump { .. }, ControlFlow::UnconditionalBranch { target }) => {
                Some(Expr::call(
                    ExprCallTarget::Direct {
                        target: *target,
                        call_site: inst.address,
                    },
                    Self::direct_tail_passthrough_args(block),
                ))
            }
            (
                BlockTerminator::IndirectJump {
                    possible_targets, ..
                },
                ControlFlow::IndirectBranch { .. },
            ) if possible_targets.is_empty() => {
                Some(Expr::call(Self::tail_jump_indirect_target(inst), vec![]))
            }
            _ => None,
        }
    }

    fn direct_tail_passthrough_args(block: &BasicBlock) -> Vec<Expr> {
        let is_pure_jump_wrapper = block.instructions.iter().all(|inst| {
            inst.operation == Operation::Jump
                || inst.operation == Operation::Nop
                || inst.mnemonic.starts_with("endbr")
        });

        if is_pure_jump_wrapper {
            vec![Expr::var(Variable::reg("edi", 4))]
        } else {
            vec![]
        }
    }

    fn tail_jump_indirect_target(inst: &hexray_core::Instruction) -> ExprCallTarget {
        let Some(target_op) = inst.operands.first() else {
            return ExprCallTarget::Named("unknown".to_string());
        };

        match target_op {
            Operand::PcRelative { target, .. } => ExprCallTarget::Direct {
                target: *target,
                call_site: inst.address,
            },
            Operand::Immediate(imm) => ExprCallTarget::Direct {
                target: imm.as_u64(),
                call_site: inst.address,
            },
            Operand::Memory(mem) => {
                if mem.base.as_ref().map(|r| r.name()).unwrap_or("") == "rip" && mem.index.is_none()
                {
                    let got_address =
                        (inst.address as i64 + inst.size as i64 + mem.displacement) as u64;
                    ExprCallTarget::IndirectGot {
                        got_address,
                        expr: Box::new(Expr::from_operand(target_op)),
                    }
                } else {
                    ExprCallTarget::Indirect(Box::new(Expr::from_operand(target_op)))
                }
            }
            _ => ExprCallTarget::Indirect(Box::new(Expr::from_operand(target_op))),
        }
    }

    fn structure_loop(&mut self, header: BasicBlockId) -> StructuredNode {
        let info = match self.loop_info.get(&header).cloned() {
            Some(i) => i,
            None => return StructuredNode::Goto(header),
        };

        // Get the primary exit block (first one, if any)
        let exit_block = info.exit_blocks.first().copied();

        if matches!(info.kind, LoopKind::While) && self.external_loop_guard(header, &info).is_some()
        {
            let (condition, _) = self.get_dowhile_condition(&info);
            let body = self.structure_loop_body(header, &info);

            return StructuredNode::While {
                condition,
                body,
                header: Some(header),
                exit_block,
            };
        }

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

        if let Some((condition, external_target, loop_target)) =
            self.external_loop_guard(header, info)
        {
            let then_body = self.structure_region(external_target, None);
            result.push(StructuredNode::If {
                condition,
                then_body,
                else_body: None,
            });

            let mut rest = self.structure_region(loop_target, Some(header));
            result.append(&mut rest);
            return result;
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

    fn external_loop_guard(
        &self,
        header: BasicBlockId,
        info: &LoopInfo,
    ) -> Option<(Expr, BasicBlockId, BasicBlockId)> {
        let block = self.cfg.block(header)?;
        let BlockTerminator::ConditionalBranch {
            condition,
            true_target,
            false_target,
        } = &block.terminator
        else {
            return None;
        };

        let true_in_loop = info.body.contains(true_target);
        let false_in_loop = info.body.contains(false_target);
        if true_in_loop == false_in_loop {
            return None;
        }

        let lifted = self.rewrite_condition_call_return_alias(
            header,
            condition_to_expr_with_block(*condition, block),
        );

        let (loop_target, external_target, external_condition) = if true_in_loop {
            (*true_target, *false_target, negate_condition(lifted))
        } else {
            (*false_target, *true_target, lifted)
        };

        if !matches!(
            self.cfg
                .block(external_target)
                .map(|block| &block.terminator),
            Some(BlockTerminator::ExternalJump { .. })
        ) {
            return None;
        }

        Some((external_condition, external_target, loop_target))
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
        } else if let Some(cond_block_id) = self.annotations.folded_condition_successor(header) {
            let Some(cond_block) = self.cfg.block(cond_block_id) else {
                return (Expr::int(1), self.cfg.successors(header).first().copied());
            };
            if let BlockTerminator::ConditionalBranch {
                condition,
                true_target,
                false_target,
                ..
            } = &cond_block.terminator
            {
                let true_in_loop = info.body.contains(true_target);
                let false_in_loop = info.body.contains(false_target);

                let cond_expr = self.rewrite_condition_call_return_alias(
                    cond_block_id,
                    condition_to_expr_with_block(*condition, cond_block),
                );

                if true_in_loop && !false_in_loop {
                    (cond_expr, Some(*true_target))
                } else if !true_in_loop && false_in_loop {
                    (negate_condition(cond_expr), Some(*false_target))
                } else {
                    (cond_expr, Some(*true_target))
                }
            } else {
                (Expr::int(1), self.cfg.successors(header).first().copied())
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
                let lifted = if back_edge == info.header {
                    condition_to_expr_with_block_no_alu_updates(*condition, block)
                } else {
                    condition_to_expr_with_block(*condition, block)
                };
                let cond_expr = self.rewrite_condition_call_return_alias(back_edge, lifted);
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
        join: Option<BasicBlockId>,
        block_id: BasicBlockId,
        block: &BasicBlock,
    ) -> (StructuredNode, bool) {
        let cond_expr = self.rewrite_condition_call_return_alias(
            block_id,
            condition_to_expr_with_block(condition, block),
        );

        let shared_return = join.and_then(|join_id| self.get_return_expr_if_pure_return(join_id));

        let mut then_body = if join == Some(true_target) {
            shared_return
                .clone()
                .map(|ret_expr| vec![StructuredNode::Return(ret_expr)])
                .unwrap_or_default()
        } else {
            self.structure_region(true_target, join)
        };

        let mut else_body = if join == Some(false_target) {
            shared_return
                .clone()
                .map(|ret_expr| vec![StructuredNode::Return(ret_expr)])
        } else {
            let body = self.structure_region(false_target, join);
            if body.is_empty() {
                None
            } else {
                Some(body)
            }
        };

        if let Some(ret_expr) = shared_return.clone() {
            then_body = self.attach_shared_return_to_branch(then_body, ret_expr.clone());
            else_body =
                else_body.map(|body| self.attach_shared_return_to_branch(body, ret_expr.clone()));
        }

        let consumes_join = shared_return.is_some()
            && self.body_terminates(&then_body)
            && else_body
                .as_ref()
                .is_some_and(|body| self.body_terminates(body));

        if consumes_join {
            if let Some(join_id) = join {
                self.mark_pure_return_chain_processed(join_id);
            }
        }

        (
            StructuredNode::If {
                condition: cond_expr,
                then_body,
                else_body,
            },
            consumes_join,
        )
    }

    /// In blocks entered from a call-terminated predecessor, treat arg0/x0/w0
    /// as a call return value alias in condition expressions.
    fn rewrite_condition_call_return_alias(&self, block_id: BasicBlockId, expr: Expr) -> Expr {
        use super::expression::{VarKind, Variable};

        if let Some(folded) = self.annotations.folded_condition(block_id) {
            let rewritten = substitute_return_register_uses(
                expr,
                &return_register_condition_aliases(),
                &folded.call_expr,
            );
            return simplify_folded_call_condition(rewritten);
        }

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
            "al".to_string(),
            "ax".to_string(),
            "eax".to_string(),
            "rax".to_string(),
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
        let suppress_terminating_call = self.annotations.suppresses_predecessor_call(block_id);

        // Check if block ends with conditional branch
        let has_conditional_branch =
            matches!(block.terminator, BlockTerminator::ConditionalBranch { .. });

        // Find the index of the compare instruction if the block ends with a conditional
        let compare_idx = if has_conditional_branch {
            block.instructions.iter().rposition(|inst| {
                match inst.operation {
                    Operation::Compare | Operation::Test => true,
                    // Only treat Sub as pure comparison if it has < 3 operands
                    // SUBS with 3 operands (dst, src1, src2) writes to dst, so keep it
                    Operation::Sub => inst.operands.len() < 3,
                    _ => false,
                }
            })
        } else {
            None
        };

        let probe_setup_end = match block.terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
                ..
            } => self
                .asan_probe_normal_target(true_target, false_target)
                .and_then(|(_, normal_target)| {
                    self.asan_probe_setup_end_index(block, normal_target)
                }),
            _ => None,
        };
        let recoverable_ubsan_setup_end = match block.terminator {
            BlockTerminator::ConditionalBranch {
                true_target,
                false_target,
                ..
            } => self
                .ubsan_probe_normal_target(true_target, false_target)
                .map(|(_, normal_target)| {
                    self.recoverable_ubsan_setup_end_index(block, normal_target)
                }),
            _ => None,
        };

        let exprs: Vec<Expr> = block
            .instructions
            .iter()
            .enumerate()
            .filter(|(idx, inst)| {
                if let Some(last_keep_idx) = recoverable_ubsan_setup_end {
                    match last_keep_idx {
                        Some(last_keep_idx) => {
                            if *idx > last_keep_idx {
                                return false;
                            }
                        }
                        None => return false,
                    }
                }
                if let Some(last_keep_idx) = probe_setup_end {
                    if *idx > last_keep_idx {
                        return false;
                    }
                }
                // Skip branch instructions, but keep calls
                if inst.is_branch() && !inst.is_call() && inst.operation != Operation::Syscall {
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

                let mut exprs = vec![main_expr];
                if let Some(wb) = writeback {
                    exprs.push(wb);
                }
                exprs
            })
            .collect();

        // Resolve ADRP + ADD patterns (ARM64 PC-relative addressing)
        let exprs = resolve_adrp_patterns(exprs);

        if suppress_terminating_call {
            let mut propagated = propagate_args_in_block(exprs);
            if matches!(
                propagated.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ) {
                propagated.pop();
            }
            propagated
        } else {
            exprs
        }
    }
}

fn instruction_transfers_from_any_reg(inst: &Instruction, regs: &HashSet<u16>) -> bool {
    matches!(inst.operands.first(), Some(Operand::Register(_)))
        && inst
            .operands
            .iter()
            .skip(1)
            .any(|operand| operand_uses_any_reg(operand, regs))
}

fn operand_uses_any_reg(operand: &Operand, regs: &HashSet<u16>) -> bool {
    match operand {
        Operand::Register(reg) => regs.contains(&reg.id),
        Operand::Memory(mem) => {
            mem.base.as_ref().is_some_and(|reg| regs.contains(&reg.id))
                || mem.index.as_ref().is_some_and(|reg| regs.contains(&reg.id))
        }
        _ => false,
    }
}

fn canonical_register_key(reg: &hexray_core::Register) -> String {
    let name = reg.name().to_ascii_lowercase();
    abi::normalize_x86_64_register(&name, (reg.size / 8) as u8)
        .map(|(normalized, _)| normalized.to_string())
        .unwrap_or(name)
}

fn trim_trailing_epilogue_statements(statements: &mut Vec<Expr>) {
    while statements
        .last()
        .is_some_and(is_trailing_epilogue_statement)
    {
        statements.pop();
    }
}

fn is_trailing_epilogue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, .. } => match &lhs.kind {
            ExprKind::Var(var) => {
                abi::is_callee_saved_or_renamed(&var.name)
                    || matches!(
                        var.name.as_str(),
                        "sp" | "rsp" | "esp" | "fp" | "rbp" | "ebp"
                    )
            }
            _ => false,
        },
        ExprKind::CompoundAssign { lhs, .. } => match &lhs.kind {
            ExprKind::Var(var) => matches!(var.name.as_str(), "sp" | "rsp" | "esp"),
            _ => false,
        },
        _ => false,
    }
}

fn return_register_condition_aliases() -> Vec<String> {
    vec![
        "al".to_string(),
        "ax".to_string(),
        "eax".to_string(),
        "rax".to_string(),
        "ret_0".to_string(),
        "arg0".to_string(),
        "x0".to_string(),
        "w0".to_string(),
        "a0".to_string(),
    ]
}

fn direct_call_expr(inst: &hexray_core::Instruction) -> Option<Expr> {
    match &inst.control_flow {
        ControlFlow::Call { target, .. } => Some(Expr::call(
            ExprCallTarget::Direct {
                target: *target,
                call_site: inst.address,
            },
            vec![],
        )),
        _ => None,
    }
}

fn extract_folded_predecessor_call_expr(block: &BasicBlock) -> Option<Expr> {
    let exprs: Vec<Expr> = block
        .instructions
        .iter()
        .filter(|inst| !inst.is_branch() || inst.is_call())
        .flat_map(|inst| {
            let main_expr = match inst.operation {
                Operation::SetConditional => lift_setcc_with_context(inst, block),
                Operation::ConditionalMove => lift_cmovcc_with_context(inst, block),
                _ => Expr::from_instruction(inst),
            };
            let writeback = generate_writeback_expr(inst);
            let mut exprs = vec![main_expr];
            if let Some(wb) = writeback {
                exprs.push(wb);
            }
            exprs
        })
        .collect();
    let propagated = propagate_args_in_block(resolve_adrp_patterns(exprs));

    propagated
        .last()
        .filter(|expr| matches!(expr.kind, ExprKind::Call { .. }))
        .cloned()
        .or_else(|| block.instructions.last().and_then(direct_call_expr))
}

fn simplify_folded_call_condition(expr: Expr) -> Expr {
    match expr.kind {
        ExprKind::BinOp { op, left, right } => match (&op, &left.kind, &right.kind) {
            (BinOpKind::Ne, _, ExprKind::IntLit(0)) | (BinOpKind::Ne, ExprKind::IntLit(0), _) => {
                if matches!(&right.kind, ExprKind::IntLit(0)) {
                    (*left).simplify()
                } else {
                    (*right).simplify()
                }
            }
            (BinOpKind::Eq, _, ExprKind::IntLit(0)) | (BinOpKind::Eq, ExprKind::IntLit(0), _) => {
                let operand = if matches!(&right.kind, ExprKind::IntLit(0)) {
                    *left
                } else {
                    *right
                };
                Expr::unary(UnaryOpKind::LogicalNot, operand).simplify()
            }
            _ => Expr::binop(op, *left, *right).simplify(),
        },
        _ => expr.simplify(),
    }
}

fn is_foldable_condition_micro_block(block: &BasicBlock) -> bool {
    if !matches!(block.terminator, BlockTerminator::ConditionalBranch { .. }) {
        return false;
    }

    let meaningful: Vec<_> = block
        .instructions
        .iter()
        .filter(|inst| !inst.mnemonic.starts_with("nop") && !inst.mnemonic.starts_with("endbr"))
        .collect();
    let non_branch: Vec<_> = meaningful
        .into_iter()
        .filter(|inst| !inst.is_branch())
        .collect();
    if non_branch.len() != 1 {
        return false;
    }

    let inst = non_branch[0];
    match inst.operation {
        Operation::Test if inst.operands.len() >= 2 => {
            matches!(
                (&inst.operands[0], &inst.operands[1]),
                (Operand::Register(left), Operand::Register(right))
                    if left == right && abi::is_return_register(&left.name().to_lowercase())
            )
        }
        Operation::Compare if inst.operands.len() >= 2 => {
            is_return_register_operand(&inst.operands[0])
                && is_zero_immediate_operand(&inst.operands[1])
                || is_zero_immediate_operand(&inst.operands[0])
                    && is_return_register_operand(&inst.operands[1])
        }
        _ => false,
    }
}

fn is_return_register_operand(op: &Operand) -> bool {
    match op {
        Operand::Register(reg) => abi::is_return_register(&reg.name().to_lowercase()),
        _ => false,
    }
}

fn is_zero_immediate_operand(op: &Operand) -> bool {
    matches!(op, Operand::Immediate(imm) if imm.value == 0)
}

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

fn rewrite_known_noreturn_calls(
    nodes: Vec<StructuredNode>,
    known_noreturn_targets: &HashMap<u64, String>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(|node| rewrite_known_noreturn_calls_in_node(node, known_noreturn_targets))
        .collect()
}

fn rewrite_known_noreturn_calls_in_node(
    node: StructuredNode,
    known_noreturn_targets: &HashMap<u64, String>,
) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: statements
                .into_iter()
                .map(|expr| rewrite_known_noreturn_calls_in_expr(expr, known_noreturn_targets))
                .collect(),
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: rewrite_known_noreturn_calls_in_expr(condition, known_noreturn_targets),
            then_body: rewrite_known_noreturn_calls(then_body, known_noreturn_targets),
            else_body: else_body
                .map(|body| rewrite_known_noreturn_calls(body, known_noreturn_targets)),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: rewrite_known_noreturn_calls_in_expr(condition, known_noreturn_targets),
            body: rewrite_known_noreturn_calls(body, known_noreturn_targets),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: rewrite_known_noreturn_calls(body, known_noreturn_targets),
            condition: rewrite_known_noreturn_calls_in_expr(condition, known_noreturn_targets),
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
            init: init
                .map(|expr| rewrite_known_noreturn_calls_in_expr(expr, known_noreturn_targets)),
            condition: rewrite_known_noreturn_calls_in_expr(condition, known_noreturn_targets),
            update: update
                .map(|expr| rewrite_known_noreturn_calls_in_expr(expr, known_noreturn_targets)),
            body: rewrite_known_noreturn_calls(body, known_noreturn_targets),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: rewrite_known_noreturn_calls(body, known_noreturn_targets),
            header,
            exit_block,
        },
        StructuredNode::Return(expr) => StructuredNode::Return(
            expr.map(|value| rewrite_known_noreturn_calls_in_expr(value, known_noreturn_targets)),
        ),
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: rewrite_known_noreturn_calls_in_expr(value, known_noreturn_targets),
            cases: cases
                .into_iter()
                .map(|(values, body)| {
                    (
                        values,
                        rewrite_known_noreturn_calls(body, known_noreturn_targets),
                    )
                })
                .collect(),
            default: default.map(|body| rewrite_known_noreturn_calls(body, known_noreturn_targets)),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(rewrite_known_noreturn_calls(nodes, known_noreturn_targets))
        }
        StructuredNode::Expr(expr) => StructuredNode::Expr(rewrite_known_noreturn_calls_in_expr(
            expr,
            known_noreturn_targets,
        )),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: rewrite_known_noreturn_calls(try_body, known_noreturn_targets),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: rewrite_known_noreturn_calls(handler.body, known_noreturn_targets),
                    ..handler
                })
                .collect(),
        },
        other => other,
    }
}

fn rewrite_known_noreturn_calls_in_expr(
    expr: Expr,
    known_noreturn_targets: &HashMap<u64, String>,
) -> Expr {
    let kind = match expr.kind {
        ExprKind::Var(var) => ExprKind::Var(var),
        ExprKind::IntLit(value) => ExprKind::IntLit(value),
        ExprKind::BinOp { op, left, right } => ExprKind::BinOp {
            op,
            left: Box::new(rewrite_known_noreturn_calls_in_expr(
                *left,
                known_noreturn_targets,
            )),
            right: Box::new(rewrite_known_noreturn_calls_in_expr(
                *right,
                known_noreturn_targets,
            )),
        },
        ExprKind::UnaryOp { op, operand } => ExprKind::UnaryOp {
            op,
            operand: Box::new(rewrite_known_noreturn_calls_in_expr(
                *operand,
                known_noreturn_targets,
            )),
        },
        ExprKind::Deref { addr, size } => ExprKind::Deref {
            addr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *addr,
                known_noreturn_targets,
            )),
            size,
        },
        ExprKind::GotRef {
            address,
            instruction_address,
            size,
            display_expr,
            is_deref,
        } => ExprKind::GotRef {
            address,
            instruction_address,
            size,
            display_expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *display_expr,
                known_noreturn_targets,
            )),
            is_deref,
        },
        ExprKind::AddressOf(inner) => ExprKind::AddressOf(Box::new(
            rewrite_known_noreturn_calls_in_expr(*inner, known_noreturn_targets),
        )),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => ExprKind::ArrayAccess {
            base: Box::new(rewrite_known_noreturn_calls_in_expr(
                *base,
                known_noreturn_targets,
            )),
            index: Box::new(rewrite_known_noreturn_calls_in_expr(
                *index,
                known_noreturn_targets,
            )),
            element_size,
        },
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => ExprKind::FieldAccess {
            base: Box::new(rewrite_known_noreturn_calls_in_expr(
                *base,
                known_noreturn_targets,
            )),
            field_name,
            offset,
        },
        ExprKind::Call { target, args } => {
            let target = match target {
                ExprCallTarget::Direct { target, call_site } => known_noreturn_targets
                    .get(&target)
                    .cloned()
                    .map(ExprCallTarget::Named)
                    .unwrap_or(ExprCallTarget::Direct { target, call_site }),
                ExprCallTarget::Named(name) => ExprCallTarget::Named(name),
                ExprCallTarget::Indirect(inner) => ExprCallTarget::Indirect(Box::new(
                    rewrite_known_noreturn_calls_in_expr(*inner, known_noreturn_targets),
                )),
                ExprCallTarget::IndirectGot { got_address, expr } => ExprCallTarget::IndirectGot {
                    got_address,
                    expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                        *expr,
                        known_noreturn_targets,
                    )),
                },
            };
            ExprKind::Call {
                target,
                args: args
                    .into_iter()
                    .map(|arg| rewrite_known_noreturn_calls_in_expr(arg, known_noreturn_targets))
                    .collect(),
            }
        }
        ExprKind::Assign { lhs, rhs } => ExprKind::Assign {
            lhs: Box::new(rewrite_known_noreturn_calls_in_expr(
                *lhs,
                known_noreturn_targets,
            )),
            rhs: Box::new(rewrite_known_noreturn_calls_in_expr(
                *rhs,
                known_noreturn_targets,
            )),
        },
        ExprKind::CompoundAssign { op, lhs, rhs } => ExprKind::CompoundAssign {
            op,
            lhs: Box::new(rewrite_known_noreturn_calls_in_expr(
                *lhs,
                known_noreturn_targets,
            )),
            rhs: Box::new(rewrite_known_noreturn_calls_in_expr(
                *rhs,
                known_noreturn_targets,
            )),
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => ExprKind::Conditional {
            cond: Box::new(rewrite_known_noreturn_calls_in_expr(
                *cond,
                known_noreturn_targets,
            )),
            then_expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *then_expr,
                known_noreturn_targets,
            )),
            else_expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *else_expr,
                known_noreturn_targets,
            )),
        },
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => ExprKind::Cast {
            expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *inner,
                known_noreturn_targets,
            )),
            to_size,
            signed,
        },
        ExprKind::BitField {
            expr: inner,
            start,
            width,
        } => ExprKind::BitField {
            expr: Box::new(rewrite_known_noreturn_calls_in_expr(
                *inner,
                known_noreturn_targets,
            )),
            start,
            width,
        },
        ExprKind::Phi(values) => ExprKind::Phi(
            values
                .into_iter()
                .map(|value| rewrite_known_noreturn_calls_in_expr(value, known_noreturn_targets))
                .collect(),
        ),
        ExprKind::Unknown(name) => ExprKind::Unknown(name),
    };

    Expr { kind }
}

fn attach_shared_return_to_branch(
    mut body: Vec<StructuredNode>,
    shared_return: Option<Expr>,
) -> Vec<StructuredNode> {
    let stripped_terminal_bare_return = matches!(body.last(), Some(StructuredNode::Return(None)));
    if stripped_terminal_bare_return {
        body.pop();
    } else if body_terminates(&body) {
        return body;
    }

    let mut return_value = shared_return;

    if let Some(StructuredNode::Block { statements, .. }) = body.last_mut() {
        let original_statements = std::mem::take(statements);
        let (filtered_statements, branch_return) =
            extract_return_value(original_statements.clone());
        let branch_return_is_safe = branch_return.is_some()
            && filtered_statements
                .last()
                .map_or(true, |stmt| !statement_contains_real_call(stmt));
        if branch_return_is_safe {
            *statements = filtered_statements;
            return_value = branch_return;
        } else {
            *statements = original_statements;
        }
    }

    if matches!(
        body.last(),
        Some(StructuredNode::Block { statements, .. }) if statements.is_empty()
    ) {
        body.pop();
    }

    if body_terminates(&body) {
        return body;
    }

    body.push(StructuredNode::Return(return_value));
    body
}

/// Checks if a body of statements terminates (ends with return/break/continue/goto/noreturn call).
pub(super) fn body_terminates(body: &[StructuredNode]) -> bool {
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
pub(super) fn is_noreturn_call(expr: &Expr) -> bool {
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
    crate::is_noreturn_function_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BlockTerminator, Condition, ControlFlow, Operand, Operation,
        Register, RegisterClass,
    };

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

    fn make_shared_return_diamond_cfg() -> ControlFlowGraph {
        //     bb0
        //    /   \
        //  bb1   bb2
        //    \   /
        //     bb3 (ret)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.instructions.push(
            Instruction::new(0x1010, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(1, 32)]),
        );
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.instructions.push(
            Instruction::new(0x1020, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(0, 32)]),
        );
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

    fn make_shared_return_arithmetic_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x2000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x2010);
        bb1.instructions.push(
            Instruction::new(0x2010, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(5, 32)]),
        );
        bb1.instructions.push(
            Instruction::new(0x2015, 3, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(20, 32)]),
        );
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x2020);
        bb2.instructions.push(
            Instruction::new(0x2020, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(7, 32)]),
        );
        bb2.instructions.push(
            Instruction::new(0x2025, 2, vec![], "neg")
                .with_operation(Operation::Neg)
                .with_operands(vec![Operand::Register(eax)]),
        );
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x2030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        cfg
    }

    fn make_shared_return_intermediary_jump_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x2100);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x2110);
        bb1.instructions.push(
            Instruction::new(0x2110, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(7, 32)]),
        );
        bb1.instructions.push(
            Instruction::new(0x2115, 2, vec![], "neg")
                .with_operation(Operation::Neg)
                .with_operands(vec![Operand::Register(eax)]),
        );
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(5),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x2120);
        bb2.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x2130);
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x2140);
        bb4.instructions.push(
            Instruction::new(0x2140, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm_unsigned(20, 32)]),
        );
        bb4.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(5),
        };
        cfg.add_block(bb4);

        let mut bb5 = BasicBlock::new(BasicBlockId::new(5), 0x2150);
        bb5.terminator = BlockTerminator::Return;
        cfg.add_block(bb5);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(5));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(5));

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

    fn make_self_loop_conditional_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (single-block loop body + condition)
        //        bb1 -> bb1 (back edge if true)
        //        bb1 -> bb2 (exit if false)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::Return;
        cfg.add_block(bb2);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

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

    #[test]
    fn test_extract_tbz_sign_bit_as_signed_ge_zero() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let reg_w8 = Register::new(Architecture::Arm64, RegisterClass::General, 8, 32);
        let inst = Instruction::new(0x1000, 4, vec![], "tbz")
            .with_operation(Operation::ConditionalJump)
            .with_operands(vec![
                Operand::Register(reg_w8),
                Operand::imm_unsigned(31, 8),
                Operand::pc_rel(16, 0x1010),
            ]);
        block.instructions.push(inst);

        let cond = try_extract_arm64_branch_condition(&block, BinOpKind::Eq, &HashMap::new())
            .expect("tbz sign-bit condition should be extracted");
        assert!(matches!(
            cond.kind,
            super::super::expression::ExprKind::BinOp {
                op: BinOpKind::Ge,
                ..
            }
        ));
    }

    #[test]
    fn test_extract_tbnz_sign_bit_as_signed_lt_zero() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let reg_w8 = Register::new(Architecture::Arm64, RegisterClass::General, 8, 32);
        let inst = Instruction::new(0x1000, 4, vec![], "tbnz")
            .with_operation(Operation::ConditionalJump)
            .with_operands(vec![
                Operand::Register(reg_w8),
                Operand::imm_unsigned(31, 8),
                Operand::pc_rel(16, 0x1010),
            ]);
        block.instructions.push(inst);

        let cond = try_extract_arm64_branch_condition(&block, BinOpKind::Ne, &HashMap::new())
            .expect("tbnz sign-bit condition should be extracted");
        assert!(matches!(
            cond.kind,
            super::super::expression::ExprKind::BinOp {
                op: BinOpKind::Lt,
                ..
            }
        ));
    }

    #[test]
    fn test_extract_tbz_non_sign_bit_keeps_bit_test() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let reg_w8 = Register::new(Architecture::Arm64, RegisterClass::General, 8, 32);
        let inst = Instruction::new(0x1000, 4, vec![], "tbz")
            .with_operation(Operation::ConditionalJump)
            .with_operands(vec![
                Operand::Register(reg_w8),
                Operand::imm_unsigned(5, 8),
                Operand::pc_rel(16, 0x1010),
            ]);
        block.instructions.push(inst);

        let cond = try_extract_arm64_branch_condition(&block, BinOpKind::Eq, &HashMap::new())
            .expect("tbz bit-test condition should be extracted");
        if let super::super::expression::ExprKind::BinOp { op, left, right } = &cond.kind {
            assert_eq!(*op, BinOpKind::Eq);
            assert!(matches!(
                right.kind,
                super::super::expression::ExprKind::IntLit(0)
            ));
            assert!(matches!(
                left.kind,
                super::super::expression::ExprKind::BinOp {
                    op: BinOpKind::And,
                    ..
                }
            ));
        } else {
            panic!("expected eq(bit-test, 0), got {:?}", cond.kind);
        }
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

    fn expr_contains_int_lit(expr: &Expr, target: i128) -> bool {
        use crate::decompiler::expression::ExprKind;

        match &expr.kind {
            ExprKind::IntLit(value) => *value == target,
            ExprKind::Var(_) | ExprKind::GotRef { .. } | ExprKind::Unknown(_) => false,
            ExprKind::BinOp { left, right, .. } => {
                expr_contains_int_lit(left, target) || expr_contains_int_lit(right, target)
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => expr_contains_int_lit(operand, target),
            ExprKind::Deref { addr, .. } => expr_contains_int_lit(addr, target),
            ExprKind::ArrayAccess { base, index, .. } => {
                expr_contains_int_lit(base, target) || expr_contains_int_lit(index, target)
            }
            ExprKind::FieldAccess { base, .. } => expr_contains_int_lit(base, target),
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
                args.iter().any(|arg| expr_contains_int_lit(arg, target))
            }
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                expr_contains_int_lit(lhs, target) || expr_contains_int_lit(rhs, target)
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                expr_contains_int_lit(cond, target)
                    || expr_contains_int_lit(then_expr, target)
                    || expr_contains_int_lit(else_expr, target)
            }
        }
    }

    fn contains_return_literal(nodes: &[StructuredNode], target: i128) -> bool {
        for node in nodes {
            match node {
                StructuredNode::Return(Some(expr)) if expr_contains_int_lit(expr, target) => {
                    return true;
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    if contains_return_literal(then_body, target)
                        || else_body
                            .as_ref()
                            .is_some_and(|body| contains_return_literal(body, target))
                    {
                        return true;
                    }
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. }
                | StructuredNode::Loop { body, .. }
                | StructuredNode::Sequence(body) => {
                    if contains_return_literal(body, target) {
                        return true;
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    if cases
                        .iter()
                        .any(|(_, body)| contains_return_literal(body, target))
                        || default
                            .as_ref()
                            .is_some_and(|body| contains_return_literal(body, target))
                    {
                        return true;
                    }
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    if contains_return_literal(try_body, target)
                        || catch_handlers
                            .iter()
                            .any(|handler| contains_return_literal(&handler.body, target))
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    fn contains_void_return(nodes: &[StructuredNode]) -> bool {
        for node in nodes {
            match node {
                StructuredNode::Return(None) => return true,
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    if contains_void_return(then_body)
                        || else_body
                            .as_ref()
                            .is_some_and(|body| contains_void_return(body))
                    {
                        return true;
                    }
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. }
                | StructuredNode::Loop { body, .. }
                | StructuredNode::Sequence(body) => {
                    if contains_void_return(body) {
                        return true;
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    if cases.iter().any(|(_, body)| contains_void_return(body))
                        || default
                            .as_ref()
                            .is_some_and(|body| contains_void_return(body))
                    {
                        return true;
                    }
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    if contains_void_return(try_body)
                        || catch_handlers
                            .iter()
                            .any(|handler| contains_void_return(&handler.body))
                    {
                        return true;
                    }
                }
                _ => {}
            }
        }

        false
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
    fn test_is_noreturn_function_asan_reports() {
        assert!(is_noreturn_function("__asan_report_load4"));
        assert!(is_noreturn_function("__asan_report_store1"));
        assert!(!is_noreturn_function("__asan_report_load4_noabort"));
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
    fn test_structurer_preserves_shared_return_branch_values() {
        let cfg = make_shared_return_diamond_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        assert!(
            contains_return_literal(structured.body(), 1),
            "Expected a branch-specific return value of 1 in {:?}",
            structured.body()
        );
        assert!(
            contains_return_literal(structured.body(), 0),
            "Expected a branch-specific return value of 0 in {:?}",
            structured.body()
        );
        assert!(
            !contains_void_return(structured.body()),
            "Shared return join should not leave behind a void return: {:?}",
            structured.body()
        );
    }

    #[test]
    fn test_structurer_preserves_arithmetic_shared_return_branch_values() {
        let cfg = make_shared_return_arithmetic_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        assert!(
            contains_return_literal(structured.body(), 25),
            "Expected arithmetic branch to preserve the computed return value: {:?}",
            structured.body()
        );
        assert!(
            contains_return_literal(structured.body(), -7),
            "Expected negated branch to preserve its computed return value: {:?}",
            structured.body()
        );
        assert!(
            !contains_void_return(structured.body()),
            "Arithmetic shared return join should not degrade to bare returns: {:?}",
            structured.body()
        );
    }

    #[test]
    fn test_structurer_preserves_shared_return_through_intermediary_jump() {
        let cfg = make_shared_return_intermediary_jump_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        assert!(
            contains_return_literal(structured.body(), 20),
            "Expected intermediary jump branch to preserve the computed return value: {:?}",
            structured.body()
        );
        assert!(
            contains_return_literal(structured.body(), -7),
            "Expected shared join branch to preserve its computed return value: {:?}",
            structured.body()
        );
        assert!(
            !contains_void_return(structured.body()),
            "Intermediary jump shared return should not degrade to bare returns: {:?}",
            structured.body()
        );
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
    fn test_structurer_self_loop_conditional_uses_dowhile() {
        let cfg = make_self_loop_conditional_cfg();
        let structured = StructuredCfg::from_cfg(&cfg);

        assert!(
            structured
                .body()
                .iter()
                .any(|n| matches!(n, StructuredNode::DoWhile { .. })),
            "Conditional self-loop should structure as do-while"
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
        let kind = Structurer::classify_loop(
            &cfg,
            &loops[0],
            &body_set,
            &StructuringAnnotations::default(),
        );
        assert_eq!(kind, LoopKind::While);
    }

    #[test]
    fn test_classify_loop_dowhile() {
        let cfg = make_dowhile_loop_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty(), "Should detect a loop");

        // Find the actual back edge block for do-while classification
        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let kind = Structurer::classify_loop(
            &cfg,
            &loops[0],
            &body_set,
            &StructuringAnnotations::default(),
        );
        // Do-while has condition at the back edge block
        assert!(
            kind == LoopKind::DoWhile || kind == LoopKind::While,
            "Should be DoWhile or While, got {:?}",
            kind
        );
    }

    #[test]
    fn test_classify_self_loop_header_as_dowhile() {
        let cfg = make_self_loop_conditional_cfg();
        let loops = cfg.find_loops();

        assert!(!loops.is_empty(), "Should detect a self-loop");

        let body_set: HashSet<_> = loops[0].body.iter().copied().collect();
        let kind = Structurer::classify_loop(
            &cfg,
            &loops[0],
            &body_set,
            &StructuringAnnotations::default(),
        );
        assert_eq!(kind, LoopKind::DoWhile);
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
    fn test_rewrite_condition_call_return_alias_handles_x86_low_byte_return() {
        let al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x1005,
                }),
        );
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1005);
        bb1.instructions.push(
            Instruction::new(0x1005, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(al), Operand::Register(al)]),
        );
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1010);
        bb2.terminator = BlockTerminator::Return;
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1020);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));

        let structurer = Structurer::new(&cfg);
        let block = cfg.block(BasicBlockId::new(1)).expect("condition block");
        let raw = condition_to_expr_with_block(Condition::NotEqual, block);
        let rewritten = structurer.rewrite_condition_call_return_alias(BasicBlockId::new(1), raw);

        assert!(
            format!("{rewritten}").contains("ret_0"),
            "expected x86 low-byte return alias to rewrite through predecessor call"
        );
    }

    #[test]
    fn test_folded_condition_annotation_rewrites_to_call_expr_and_suppresses_pred_call() {
        use crate::decompiler::expression::{ExprKind, Variable};
        use hexray_core::basic_block::CallTarget as BlockCallTarget;

        let al = Register::new(Architecture::X86_64, RegisterClass::General, 0, 8);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x1005,
                }),
        );
        bb0.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x2000),
            return_block: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1005);
        bb1.instructions.push(
            Instruction::new(0x1005, 2, vec![], "test")
                .with_operation(Operation::Test)
                .with_operands(vec![Operand::Register(al), Operand::Register(al)]),
        );
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1010);
        bb2.terminator = BlockTerminator::Return;
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1020);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));

        let annotations = StructuringAnnotations::from_cfg_and_exception_info(&cfg, None);
        let structurer = Structurer::new_with_annotations(&cfg, annotations);

        let pred_statements = structurer.block_to_statements(BasicBlockId::new(0));
        assert!(
            pred_statements.is_empty(),
            "expected folded predecessor call to be suppressed"
        );

        let raw = Expr::binop(
            BinOpKind::Ne,
            Expr::var(Variable::reg("al", 1)),
            Expr::int(0),
        );
        let rewritten = structurer.rewrite_condition_call_return_alias(BasicBlockId::new(1), raw);

        assert!(
            matches!(rewritten.kind, ExprKind::Call { .. }),
            "expected folded condition to become a direct call expression, got {rewritten}"
        );
    }

    #[test]
    fn test_cleanup_side_block_annotation_stops_before_shared_block() {
        use crate::decompiler::CleanupInfo;

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1200);
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1210);
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x1220);
        bb4.terminator = BlockTerminator::Return;
        cfg.add_block(bb4);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(4));

        let info = ExceptionInfo {
            try_blocks: Vec::new(),
            cleanup_handlers: vec![CleanupInfo {
                start: 0x1000,
                end: 0x1010,
                landing_pad: 0x1200,
            }],
        };

        let annotations = StructuringAnnotations::from_cfg_and_exception_info(&cfg, Some(&info));

        assert!(annotations
            .suppressed_side_blocks
            .contains(&BasicBlockId::new(2)));
        assert!(annotations
            .suppressed_side_blocks
            .contains(&BasicBlockId::new(3)));
        assert!(
            !annotations
                .suppressed_side_blocks
                .contains(&BasicBlockId::new(4)),
            "shared block should remain emittable"
        );
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

    #[test]
    fn test_structure_unknown_direct_tail_jump_as_call() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 5, vec![0xe9, 0, 0, 0, 0], "jmp")
                .with_operation(Operation::Jump)
                .with_operands(vec![Operand::pc_rel(0, 0x2000), Operand::Register(edi)])
                .with_control_flow(ControlFlow::UnconditionalBranch { target: 0x2000 }),
        );
        bb0.terminator = BlockTerminator::Unknown;
        cfg.add_block(bb0);

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();
        let Some(StructuredNode::Block { statements, .. }) = structured.first() else {
            panic!("expected single block body");
        };
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = statements.last()
        else {
            panic!("expected synthesized tail call");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["edi"]
        );
    }

    #[test]
    fn test_structure_indirect_tail_jump_propagates_target_and_args() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let rdi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 64);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1270);
        bb0.instructions.push(
            Instruction::new(0x1274, 3, vec![0x48, 0x89, 0xf8], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(rax), Operand::Register(rdi)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1277, 2, vec![0x89, 0xf7], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(esi)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1279, 2, vec![0xff, 0xe0], "jmp")
                .with_operation(Operation::Jump)
                .with_operands(vec![Operand::Register(rax)])
                .with_control_flow(ControlFlow::IndirectBranch {
                    possible_targets: vec![],
                }),
        );
        bb0.terminator = BlockTerminator::IndirectJump {
            target: Operand::Register(rax),
            possible_targets: vec![],
        };
        cfg.add_block(bb0);

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();
        let Some(StructuredNode::Block { statements, .. }) = structured.first() else {
            panic!("expected single block body");
        };
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = statements.last()
        else {
            panic!("expected synthesized indirect tail call");
        };

        match target {
            ExprCallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "rdi"),
            other => panic!("expected indirect target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rsi"]
        );
    }

    #[test]
    fn test_asan_probe_setup_end_index_tracks_access_register_bridge_copy() {
        use hexray_core::{Architecture, MemoryRef, Register, RegisterClass};

        let rax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let rcx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 64);
        let rdx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 64);
        let sil = Register::new(Architecture::X86_64, RegisterClass::General, 6, 8);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut probe = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        probe.instructions.push(
            Instruction::new(0x1000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(rax), Operand::Register(rcx)]),
        );
        probe.instructions.push(
            Instruction::new(0x1003, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(rdx), Operand::Register(rax)]),
        );
        probe.instructions.push(
            Instruction::new(0x1006, 4, vec![], "shr")
                .with_operation(Operation::Shr)
                .with_operands(vec![Operand::Register(rdx), Operand::imm_unsigned(3, 8)]),
        );
        cfg.add_block(probe.clone());

        let mut normal = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        normal.instructions.push(
            Instruction::new(0x1010, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base(rcx, 1)),
                    Operand::Register(sil),
                ]),
        );
        cfg.add_block(normal);

        let structurer = Structurer::new(&cfg);
        assert_eq!(
            structurer.asan_probe_setup_end_index(&probe, BasicBlockId::new(1)),
            Some(0)
        );
    }

    #[test]
    fn test_recoverable_ubsan_setup_end_index_falls_back_when_no_arch_liveness() {
        // x86_64 disassembler doesn't populate inst.reads/inst.writes, so
        // block_live_in_registers returns an empty set even when the
        // continuation has live values. Falling back to keeping every
        // pre-terminator instruction is required so user computation
        // (e.g. ebx = a + b) survives UBSan trimming.
        use hexray_core::{Architecture, Operand, Register, RegisterClass};

        let rsp = Register::new(Architecture::X86_64, RegisterClass::General, 4, 64);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let ebx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut probe = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        // sub rsp, 0x18 sets the explicit guard predicate but the disasm
        // here intentionally omits inst.reads/writes to mimic the x86_64
        // case.
        probe.instructions.push(
            Instruction::new(0x1000, 4, vec![], "sub")
                .with_operation(Operation::Sub)
                .with_operands(vec![Operand::Register(rsp), Operand::imm(0x18, 8)]),
        );
        probe.instructions.push(
            Instruction::new(0x1004, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(ebx), Operand::Register(edi)]),
        );
        probe.instructions.push(
            Instruction::new(0x1007, 2, vec![], "add")
                .with_operation(Operation::Add)
                .with_operands(vec![Operand::Register(ebx), Operand::Register(esi)]),
        );
        cfg.add_block(probe.clone());

        let mut normal = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        normal.instructions.push(
            Instruction::new(0x1010, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::Register(ebx)]),
        );
        cfg.add_block(normal);

        let structurer = Structurer::new(&cfg);
        // Without the fallback this would return None and block_to_statements
        // would drop every prior instruction, including ebx = ebx + esi.
        assert_eq!(
            structurer.recoverable_ubsan_setup_end_index(&probe, BasicBlockId::new(1)),
            Some(2)
        );
    }

    #[test]
    fn test_recoverable_ubsan_setup_end_index_tracks_continuation_live_ins() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let ebx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 32);
        let r12d = Register::new(Architecture::X86_64, RegisterClass::General, 12, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let dl = Register::new(Architecture::X86_64, RegisterClass::General, 2, 8);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut probe = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut load_rhs = Instruction::new(0x1000, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(esi)]);
        load_rhs.reads = vec![esi];
        load_rhs.writes = vec![ebx];
        probe.instructions.push(load_rhs);

        let mut load_lhs = Instruction::new(0x1003, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(r12d), Operand::Register(edi)]);
        load_lhs.reads = vec![edi];
        load_lhs.writes = vec![r12d];
        probe.instructions.push(load_lhs);

        let mut guard_test = Instruction::new(0x1006, 2, vec![], "test")
            .with_operation(Operation::Test)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(ebx)]);
        guard_test.reads = vec![ebx, ebx];
        probe.instructions.push(guard_test);

        let mut guard_set = Instruction::new(0x1008, 2, vec![], "sete")
            .with_operation(Operation::SetConditional)
            .with_operands(vec![Operand::Register(dl)]);
        guard_set.writes = vec![dl];
        probe.instructions.push(guard_set);
        cfg.add_block(probe.clone());

        let mut normal = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        let mut move_result = Instruction::new(0x1010, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(eax), Operand::Register(r12d)]);
        move_result.reads = vec![r12d];
        move_result.writes = vec![eax];
        normal.instructions.push(move_result);

        let mut use_divisor = Instruction::new(0x1013, 2, vec![], "cmp")
            .with_operation(Operation::Compare)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(eax)]);
        use_divisor.reads = vec![ebx, eax];
        normal.instructions.push(use_divisor);
        cfg.add_block(normal);

        let structurer = Structurer::new(&cfg);
        assert_eq!(
            structurer.recoverable_ubsan_setup_end_index(&probe, BasicBlockId::new(1)),
            Some(1)
        );
    }

    #[test]
    fn test_structure_elides_recoverable_ubsan_handler_branch() {
        use hexray_core::basic_block::CallTarget as BlockCallTarget;
        use hexray_core::{Architecture, Register, RegisterClass};

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let ebx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut load_lhs = Instruction::new(0x1000, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(edi)]);
        load_lhs.reads = vec![edi];
        load_lhs.writes = vec![ebx];
        bb0.instructions.push(load_lhs);

        let mut add = Instruction::new(0x1003, 2, vec![], "add")
            .with_operation(Operation::Add)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(esi)]);
        add.reads = vec![ebx, esi];
        add.writes = vec![ebx];
        bb0.instructions.push(add);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotOverflow,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut handler = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        handler.instructions.push(
            Instruction::new(0x1010, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x5000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x5000,
                    return_addr: 0x1015,
                }),
        );
        handler.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x5000),
            return_block: BasicBlockId::new(2),
        };
        cfg.add_block(handler);

        let mut cont = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        let mut move_ret = Instruction::new(0x1020, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(eax), Operand::Register(ebx)]);
        move_ret.reads = vec![ebx];
        move_ret.writes = vec![eax];
        cont.instructions.push(move_ret);
        cont.instructions.push(
            Instruction::new(0x1023, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        cont.terminator = BlockTerminator::Return;
        cfg.add_block(cont);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let mut structurer = Structurer::new_with_binary_data_annotations_and_known_targets(
            &cfg,
            None,
            StructuringAnnotations::default(),
            HashMap::new(),
            HashMap::from([(0x5000, "__ubsan_handle_add_overflow@plt".to_string())]),
        );
        let structured = structurer.structure();

        assert!(
            structured
                .iter()
                .all(|node| !matches!(node, StructuredNode::If { .. })),
            "recoverable UBSan branch should be elided, got {structured:?}"
        );
        assert!(
            structurer.processed.contains(&BasicBlockId::new(1)),
            "UBSan handler block should be marked processed"
        );
    }

    #[test]
    fn test_structure_elides_stack_canary_fail_branch_and_keeps_return_value() {
        use hexray_core::basic_block::CallTarget as BlockCallTarget;
        use hexray_core::{Architecture, Register, RegisterClass};

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let ebx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x2000);
        let mut save_value = Instruction::new(0x2000, 2, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(edi)]);
        save_value.reads = vec![edi];
        save_value.writes = vec![ebx];
        bb0.instructions.push(save_value);

        let mut move_ret = Instruction::new(0x2002, 2, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(eax), Operand::Register(ebx)]);
        move_ret.reads = vec![ebx];
        move_ret.writes = vec![eax];
        bb0.instructions.push(move_ret);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut handler = BasicBlock::new(BasicBlockId::new(1), 0x2010);
        handler.instructions.push(
            Instruction::new(0x2010, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x5000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x5000,
                    return_addr: 0x2015,
                }),
        );
        handler.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x5000),
            return_block: BasicBlockId::new(2),
        };
        cfg.add_block(handler);

        let mut cont = BasicBlock::new(BasicBlockId::new(2), 0x2020);
        cont.instructions.push(
            Instruction::new(0x2020, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        cont.terminator = BlockTerminator::Return;
        cfg.add_block(cont);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let mut structurer = Structurer::new_with_binary_data_annotations_and_known_targets(
            &cfg,
            None,
            StructuringAnnotations::default(),
            HashMap::from([(0x5000, "__stack_chk_fail@plt".to_string())]),
            HashMap::new(),
        );
        let structured = structurer.structure();

        assert!(
            structured
                .iter()
                .all(|node| !matches!(node, StructuredNode::If { .. })),
            "stack canary branch should be elided, got {structured:?}"
        );
        assert!(
            structured.iter().any(|node| matches!(
                node,
                StructuredNode::Return(Some(Expr {
                    kind: ExprKind::Var(var)
                })) if var.name == "eax" || var.name == "rbx"
            )),
            "expected return value to be preserved, got {structured:?}"
        );
        assert!(
            structurer.processed.contains(&BasicBlockId::new(1)),
            "stack canary fail block should be marked processed"
        );
    }

    #[test]
    fn test_recoverable_ubsan_block_to_statements_keeps_signed_add_prefix() {
        use hexray_core::basic_block::CallTarget as BlockCallTarget;
        use hexray_core::{Architecture, MemoryRef, Register, RegisterClass};

        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let esi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 32);
        let edx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let ebx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 32);
        let rbx = Register::new(Architecture::X86_64, RegisterClass::General, 3, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut store_a = Instruction::new(0x1000, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Memory(MemoryRef::base_disp(rbp, -0x14, 4)),
                Operand::Register(edi),
            ]);
        store_a.reads = vec![rbp, edi];
        bb0.instructions.push(store_a);

        let mut store_b = Instruction::new(0x1003, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Memory(MemoryRef::base_disp(rbp, -0x18, 4)),
                Operand::Register(esi),
            ]);
        store_b.reads = vec![rbp, esi];
        bb0.instructions.push(store_b);

        let mut load_a = Instruction::new(0x1006, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Register(edx),
                Operand::Memory(MemoryRef::base_disp(rbp, -0x14, 4)),
            ]);
        load_a.reads = vec![rbp];
        load_a.writes = vec![edx];
        bb0.instructions.push(load_a);

        let mut load_b = Instruction::new(0x1009, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Register(eax),
                Operand::Memory(MemoryRef::base_disp(rbp, -0x18, 4)),
            ]);
        load_b.reads = vec![rbp];
        load_b.writes = vec![eax];
        bb0.instructions.push(load_b);

        let mut copy = Instruction::new(0x100c, 2, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(edx)]);
        copy.reads = vec![edx];
        copy.writes = vec![ebx];
        bb0.instructions.push(copy);

        let mut add = Instruction::new(0x100e, 2, vec![], "add")
            .with_operation(Operation::Add)
            .with_operands(vec![Operand::Register(ebx), Operand::Register(eax)]);
        add.reads = vec![ebx, eax];
        add.writes = vec![ebx];
        bb0.instructions.push(add);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotOverflow,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut handler = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        handler.instructions.push(
            Instruction::new(0x1010, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x5000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x5000,
                    return_addr: 0x1015,
                }),
        );
        handler.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x5000),
            return_block: BasicBlockId::new(2),
        };
        cfg.add_block(handler);

        let mut cont = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        let mut move_ret = Instruction::new(0x1020, 3, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![Operand::Register(eax), Operand::Register(ebx)]);
        move_ret.reads = vec![ebx];
        move_ret.writes = vec![eax];
        cont.instructions.push(move_ret);

        let mut restore_rbx = Instruction::new(0x1023, 4, vec![], "mov")
            .with_operation(Operation::Move)
            .with_operands(vec![
                Operand::Register(rbx),
                Operand::Memory(MemoryRef::base_disp(rbp, -0x8, 8)),
            ]);
        restore_rbx.reads = vec![rbp];
        restore_rbx.writes = vec![rbx];
        cont.instructions.push(restore_rbx);
        cont.instructions.push(
            Instruction::new(0x1027, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        cont.terminator = BlockTerminator::Return;
        cfg.add_block(cont);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let structurer = Structurer::new_with_binary_data_annotations_and_known_targets(
            &cfg,
            None,
            StructuringAnnotations::default(),
            HashMap::new(),
            HashMap::from([(0x5000, "__ubsan_handle_add_overflow@plt".to_string())]),
        );
        let statements = structurer.block_to_statements(BasicBlockId::new(0));
        let rendered: Vec<_> = statements.iter().map(|expr| format!("{expr}")).collect();

        assert!(
            rendered
                .iter()
                .any(|expr| expr.contains("+=") || expr.contains(" + ")),
            "expected signed-add user op to survive UBSan trimming, got {rendered:?}"
        );
    }

    #[test]
    fn test_structure_split_tail_call_leaves_bare_return_for_emitter_fold() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::Register(edi)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1003, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1005, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x100a,
                }),
        );
        bb0.terminator = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x100a);
        bb1.instructions.push(
            Instruction::new(0x100a, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();

        assert!(matches!(
            structured.last(),
            Some(StructuredNode::Return(None))
        ));
        let Some(StructuredNode::Block { statements, .. }) = structured.first() else {
            panic!("expected call block");
        };
        assert!(
            matches!(
                statements.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ),
            "expected split tail call to remain a bare call for emitter folding"
        );
    }

    #[test]
    fn test_structure_same_block_tail_call_leaves_bare_return_for_emitter_fold() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::Register(edi)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1003, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1005, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x100a,
                }),
        );
        bb0.instructions.push(
            Instruction::new(0x100a, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb0.terminator = BlockTerminator::Return;
        cfg.add_block(bb0);

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();

        assert!(matches!(
            structured.last(),
            Some(StructuredNode::Return(None))
        ));
        let Some(StructuredNode::Block { statements, .. }) = structured.first() else {
            panic!("expected setup block");
        };
        assert!(
            matches!(
                statements.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ),
            "same-block tail call should remain available for emitter folding"
        );
    }

    #[test]
    fn test_structure_stack_backed_tail_call_leaves_bare_return_for_emitter_fold() {
        use hexray_core::{Architecture, MemoryRef, Register, RegisterClass};

        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let rsi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x4, 4)),
                    Operand::Register(edi),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x1003, 4, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x10, 8)),
                    Operand::Register(rsi),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x1007, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x4, 4)),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x100a, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb0.instructions.push(
            Instruction::new(0x100c, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x1011,
                }),
        );
        bb0.terminator = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1011);
        bb1.instructions.push(
            Instruction::new(0x1011, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();

        assert!(
            matches!(structured.last(), Some(StructuredNode::Return(None))),
            "expected bare return for stack-backed tail call, got {structured:?}"
        );
        let Some(StructuredNode::Block { statements, .. }) = structured.first() else {
            panic!("expected setup block");
        };
        assert!(
            matches!(
                statements.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ),
            "stack-backed tail call should remain available for emitter folding"
        );
    }

    #[test]
    fn test_structured_cfg_stack_backed_tail_call_keeps_bare_return_for_emitter_fold() {
        use hexray_core::{Architecture, MemoryRef, Register, RegisterClass};

        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let rsi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1100);
        bb0.instructions.push(
            Instruction::new(0x1100, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x4, 4)),
                    Operand::Register(edi),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x1103, 4, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x10, 8)),
                    Operand::Register(rsi),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x1107, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(eax),
                    Operand::Memory(MemoryRef::base_disp(rbp, -0x4, 4)),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x110a, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb0.instructions.push(
            Instruction::new(0x110c, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x1111,
                }),
        );
        bb0.terminator = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1111);
        bb1.instructions.push(
            Instruction::new(0x1111, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let structured = StructuredCfg::from_cfg(&cfg);

        assert!(
            matches!(structured.body().last(), Some(StructuredNode::Return(None))),
            "post-processed structured cfg should keep a bare return, got {:?}",
            structured.body()
        );
        let Some(StructuredNode::Block { statements, .. }) = structured.body().first() else {
            panic!("expected leading block");
        };
        assert!(
            matches!(
                statements.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ),
            "post-processed tail call should remain available for emitter folding"
        );
    }

    #[test]
    fn test_get_return_expr_if_pure_return_rejects_mid_function_call_chain() {
        use hexray_core::{Architecture, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.instructions.push(
            Instruction::new(0x1010, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm(1, 4)]),
        );
        bb1.instructions.push(
            Instruction::new(0x1013, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb1.instructions.push(
            Instruction::new(0x1015, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x101a,
                }),
        );
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.instructions.push(
            Instruction::new(0x1020, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(hexray_core::Register::new(
                        hexray_core::Architecture::X86_64,
                        hexray_core::RegisterClass::General,
                        2,
                        32,
                    )),
                    Operand::imm(1, 4),
                ]),
        );
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.instructions.push(
            Instruction::new(0x1030, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Register(hexray_core::Register::new(
                        hexray_core::Architecture::X86_64,
                        hexray_core::RegisterClass::General,
                        0,
                        32,
                    )),
                    Operand::imm(0, 4),
                ]),
        );
        bb3.instructions.push(
            Instruction::new(0x1035, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let structurer = Structurer::new(&cfg);
        assert!(
            structurer
                .get_return_expr_if_pure_return(BasicBlockId::new(1))
                .is_none(),
            "mid-function call chain should not be treated as a pure return"
        );
    }

    #[test]
    fn test_last_safe_return_register_expr_in_statements_accepts_xmm0() {
        use crate::decompiler::expression::Variable;

        let statements = vec![
            Expr::assign(
                Expr::var(Variable::reg("xmm1", 16)),
                Expr::var(Variable::reg("xmm0", 16)),
            ),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(Expr::var(Variable::reg("xmm0", 16))),
                    rhs: Box::new(Expr::var(Variable::reg("xmm1", 16))),
                },
            },
        ];

        let expr = Structurer::last_safe_return_register_expr_in_statements(&statements)
            .expect("xmm0 should be treated as an implicit return register");
        assert_eq!(format!("{}", expr), "xmm0");
    }

    #[test]
    fn test_attach_shared_return_to_branch_ignores_call_arg_setup_capture() {
        use crate::decompiler::expression::{CallTarget, Variable};

        let body = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::var(Variable::reg("eax", 4)), Expr::int(1)),
                Expr::assign(
                    Expr::var(Variable::reg("edi", 4)),
                    Expr::var(Variable::reg("eax", 4)),
                ),
                Expr::call(
                    CallTarget::Named("atoi".to_string()),
                    vec![Expr::var(Variable::reg("edi", 4))],
                ),
            ],
            address_range: (0x1000, 0x1010),
        }];

        let attached = attach_shared_return_to_branch(body, Some(Expr::int(7)));

        let Some(StructuredNode::Return(Some(Expr {
            kind: ExprKind::IntLit(7),
        }))) = attached.last()
        else {
            panic!("shared return should not be overridden by pre-call eax setup");
        };
        let Some(StructuredNode::Block { statements, .. }) = attached.first() else {
            panic!("expected branch body block");
        };
        assert!(
            matches!(
                statements.last(),
                Some(Expr {
                    kind: ExprKind::Call { .. },
                })
            ),
            "call should remain in the branch body"
        );
    }

    #[test]
    fn test_attach_shared_return_to_branch_keeps_nontrivial_branch_return_capture() {
        use crate::decompiler::expression::{CallTarget, VarKind, Variable};

        let ret_0 = Expr::var(Variable {
            kind: VarKind::Temp(1),
            name: "ret_0".to_string(),
            size: 4,
        });
        let body = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    ret_0.clone(),
                    Expr::call(
                        CallTarget::Named("recursive_sum".to_string()),
                        vec![Expr::unknown("n - 1")],
                    ),
                ),
                Expr::assign(Expr::var(Variable::reg("edx", 4)), Expr::unknown("n")),
                Expr::assign(
                    Expr::var(Variable::reg("eax", 4)),
                    Expr::binop(
                        BinOpKind::Add,
                        ret_0.clone(),
                        Expr::var(Variable::reg("edx", 4)),
                    ),
                ),
            ],
            address_range: (0x1000, 0x1010),
        }];

        let attached =
            attach_shared_return_to_branch(body, Some(Expr::var(Variable::reg("eax", 4))));

        let Some(StructuredNode::Block { statements, .. }) = attached.first() else {
            panic!("expected branch body block");
        };
        let Some(StructuredNode::Return(Some(expr))) = attached.last() else {
            panic!("expected attached return");
        };

        assert_eq!(statements.len(), 2);
        assert_eq!(format!("{}", statements[0]), "ret_0 = recursive_sum(n - 1)");
        assert_eq!(format!("{}", statements[1]), "edx = n");
        assert_eq!(format!("{}", expr), "ret_0 + n");
    }

    #[test]
    fn test_structure_if_else_call_then_continue_does_not_terminate_else_branch() {
        use hexray_core::basic_block::CallTarget as BlockCallTarget;
        use hexray_core::{Architecture, Register, RegisterClass};

        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.instructions.push(
            Instruction::new(0x1000, 2, vec![], "cmp")
                .with_operation(Operation::Compare)
                .with_operands(vec![Operand::Register(eax), Operand::imm(1, 4)]),
        );
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::LessOrEqual,
            true_target: BasicBlockId::new(3),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.instructions.push(
            Instruction::new(0x1010, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm(1, 4)]),
        );
        bb1.instructions.push(
            Instruction::new(0x1013, 2, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(eax)]),
        );
        bb1.instructions.push(
            Instruction::new(0x1015, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x2000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x2000,
                    return_addr: 0x101a,
                }),
        );
        bb1.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x2000),
            return_block: BasicBlockId::new(2),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x101a);
        bb2.instructions.push(
            Instruction::new(0x101a, 2, vec![], "jmp")
                .with_operation(Operation::Jump)
                .with_operands(vec![Operand::pc_rel(0, 0x1030)])
                .with_control_flow(ControlFlow::UnconditionalBranch { target: 0x1030 }),
        );
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1020);
        bb3.instructions.push(
            Instruction::new(0x1020, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm(2, 4)]),
        );
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x1030);
        bb4.instructions.push(
            Instruction::new(0x1030, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(eax), Operand::imm(0, 4)]),
        );
        bb4.instructions.push(
            Instruction::new(0x1033, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x3000)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x3000,
                    return_addr: 0x1038,
                }),
        );
        bb4.terminator = BlockTerminator::Call {
            target: BlockCallTarget::Direct(0x3000),
            return_block: BasicBlockId::new(5),
        };
        cfg.add_block(bb4);

        let mut bb5 = BasicBlock::new(BasicBlockId::new(5), 0x1038);
        bb5.instructions.push(
            Instruction::new(0x1038, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb5.terminator = BlockTerminator::Return;
        cfg.add_block(bb5);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(5));

        let mut structurer = Structurer::new(&cfg);
        let structured = structurer.structure();

        let Some(StructuredNode::If { else_body, .. }) = structured.first() else {
            panic!("expected if node at top level, got {structured:?}");
        };
        let else_body = else_body.as_ref().expect("expected else body");
        assert!(
            !body_terminates(else_body),
            "else branch should continue into the join block, got {else_body:?}"
        );
    }
}
