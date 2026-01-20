//! Control flow structuring.
//!
//! Transforms a CFG into structured control flow (if/else, while, for, etc.).

#![allow(dead_code)]

use hexray_core::{
    cfg::Loop, BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph, Operation,
};
use std::collections::{HashMap, HashSet};

use super::expression::{resolve_adrp_patterns, BinOpKind, Expr};
use super::switch_recovery::SwitchRecovery;

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
    },

    /// Do-while loop.
    DoWhile {
        body: Vec<StructuredNode>,
        condition: Expr,
    },

    /// For loop (recognized from while with init/update).
    For {
        init: Option<Expr>,
        condition: Expr,
        update: Option<Expr>,
        body: Vec<StructuredNode>,
    },

    /// Infinite loop.
    Loop { body: Vec<StructuredNode> },

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
    /// Creates a structured CFG from an unstructured one.
    pub fn from_cfg(cfg: &ControlFlowGraph) -> Self {
        let mut structurer = Structurer::new(cfg);
        let body = structurer.structure();

        // Post-process to propagate arguments into function calls (before copy propagation)
        let body = propagate_call_args(body);

        // Post-process to merge return value captures across block boundaries
        let body = merge_return_value_captures(body);

        // Post-process to eliminate temporary register patterns
        let body = simplify_statements(body);

        // Post-process to detect for loops from while loops with init/update
        let body = detect_for_loops(body);

        // Post-process to detect switch statements from if-else chains
        let body = detect_switch_statements(body);

        // Post-process to detect short-circuit boolean patterns (a && b, a || b)
        let body = detect_short_circuit(body);

        // Post-process to convert gotos to break/continue where applicable
        let body = convert_gotos_to_break_continue(body, None);

        // Post-process to simplify expressions (constant folding, algebraic simplifications)
        let body = simplify_expressions(body);

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

        Self {
            cfg,
            loops,
            loop_headers,
            loop_info,
            visited: HashSet::new(),
            processed: HashSet::new(),
            multi_pred_blocks,
        }
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
            // Check for return value setup: eax/rax = something
            if matches!(inst.operation, Operation::Move) && inst.operands.len() >= 2 {
                if let hexray_core::Operand::Register(dst) = &inst.operands[0] {
                    let dst_name = dst.name().to_lowercase();
                    if matches!(dst_name.as_str(), "eax" | "rax" | "x0" | "w0" | "a0") {
                        return_value = Some(Expr::from_operand(&inst.operands[1]));
                    }
                }
            }
            // Skip epilogue instructions and jump/ret
            else if !matches!(
                inst.operation,
                Operation::Pop | Operation::Push | Operation::Jump | Operation::Return
            ) && !inst.mnemonic.starts_with("nop")
                && !inst.mnemonic.starts_with("endbr")
            {
                return None;
            }
        }

        // Return the captured value, or default to ebx (common for kernel error paths)
        Some(return_value.unwrap_or_else(|| {
            Expr::var(super::expression::Variable {
                name: "ebx".to_string(),
                kind: super::expression::VarKind::Register(3),
                size: 4,
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

        // Emit any unprocessed multi-predecessor blocks as labeled sections
        // Sort by address for consistent output
        let mut unprocessed: Vec<_> = self
            .multi_pred_blocks
            .iter()
            .filter(|b| !self.processed.contains(b))
            .copied()
            .collect();
        unprocessed.sort_by_key(|b| self.cfg.block(*b).map(|blk| blk.start).unwrap_or(0));

        for block_id in unprocessed {
            // Add label
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
            // emit a goto and let it be handled as a labeled block later
            if self.multi_pred_blocks.contains(&block_id) && block_id != start {
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
                    let if_node =
                        self.structure_if_else(*condition, *true_target, *false_target, end, block);
                    result.push(if_node);

                    // Find join point and continue
                    let join = self.find_join_point(*true_target, *false_target, end);
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
                    let switch_recovery = SwitchRecovery::new(self.cfg);
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

        match info.kind {
            LoopKind::While => {
                // Get condition from header's conditional branch
                let (condition, body_start) = self.get_while_condition(header, &info);
                let body = if let Some(start) = body_start {
                    self.structure_region(start, Some(header))
                } else {
                    vec![]
                };

                StructuredNode::While { condition, body }
            }

            LoopKind::DoWhile => {
                // Body is the loop content, condition at the end
                let (condition, _) = self.get_dowhile_condition(&info);
                let body = self.structure_loop_body(header, &info);

                StructuredNode::DoWhile { body, condition }
            }

            LoopKind::Infinite => {
                let body = self.structure_loop_body(header, &info);
                StructuredNode::Loop { body }
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
                StructuredNode::While { condition, body }
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

            let cond_expr = condition_to_expr_with_block(*condition, block);

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
                let cond_expr = condition_to_expr_with_block(*condition, block);
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
        block: &BasicBlock,
    ) -> StructuredNode {
        let cond_expr = condition_to_expr_with_block(condition, block);

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

    /// Structures a switch statement from recovered switch information.
    fn structure_switch_from_recovery(
        &mut self,
        switch_info: super::switch_recovery::SwitchInfo,
    ) -> StructuredNode {
        // Structure each case body
        let cases: Vec<(Vec<i128>, Vec<StructuredNode>)> = switch_info
            .cases
            .into_iter()
            .map(|(values, target)| {
                let body = self.structure_region(target, None);
                (values, body)
            })
            .collect();

        // Structure the default case if present
        let default = switch_info
            .default
            .map(|target| self.structure_region(target, None));

        StructuredNode::Switch {
            value: switch_info.switch_value,
            cases,
            default,
        }
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
            .map(|(_, inst)| Expr::from_instruction(inst))
            .collect();

        // Resolve ADRP + ADD patterns (ARM64 PC-relative addressing)
        resolve_adrp_patterns(exprs)
    }
}

/// Converts a Condition to an Expr, extracting operands from the block's compare instruction.
/// Also substitutes register names with their values from preceding MOV instructions.
fn condition_to_expr_with_block(cond: Condition, block: &BasicBlock) -> Expr {
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
        _ => BinOpKind::Ne, // Default for flag-based conditions
    };

    // Build a map of register values from MOV instructions before the compare
    let reg_values = build_register_value_map(block);

    // Find the last compare instruction in the block
    let compare_inst = block.instructions.iter().rev().find(|inst| {
        matches!(
            inst.operation,
            Operation::Compare | Operation::Test | Operation::Sub
        )
    });

    if let Some(inst) = compare_inst {
        // For SUB/SUBS instructions (ARM64), operands are [dst, src1, src2]
        // The comparison is between src1 and src2
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Sub) {
            let left =
                substitute_register_in_expr(Expr::from_operand(&inst.operands[1]), &reg_values);
            let right =
                substitute_register_in_expr(Expr::from_operand(&inst.operands[2]), &reg_values);
            return Expr::binop(op, left, right);
        } else if inst.operands.len() >= 2 {
            // For CMP/TEST instructions, operands are [src1, src2]
            let left =
                substitute_register_in_expr(Expr::from_operand(&inst.operands[0]), &reg_values);
            let right =
                substitute_register_in_expr(Expr::from_operand(&inst.operands[1]), &reg_values);

            // Special case: TEST reg, reg (same register) is a zero check
            // test eax, eax; je → jump if eax == 0
            // test eax, eax; jne → jump if eax != 0
            if matches!(inst.operation, Operation::Test) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, left, Expr::int(0));
            }

            return Expr::binop(op, left, right);
        } else if inst.operands.len() == 1 {
            // Compare against zero (common for test/cmp with single operand)
            let left =
                substitute_register_in_expr(Expr::from_operand(&inst.operands[0]), &reg_values);
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
    use hexray_core::Operand;

    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut at_block_start = true;
    let mut saw_call = false;

    for inst in &block.instructions {
        // Track if we've seen a call instruction
        if inst.is_call() {
            saw_call = true;
            at_block_start = false;
            continue;
        }

        // Look for MOV instructions (x86-64)
        if matches!(inst.operation, Operation::Move) && inst.operands.len() >= 2 {
            // First operand is destination (register), second is source
            if let Operand::Register(dst_reg) = &inst.operands[0] {
                let dst_name = dst_reg.name().to_lowercase();

                // Check if source is a memory operand (stack variable)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand(&inst.operands[1]);
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
                // Track if source is a memory operand (stack variable)
                if let Operand::Memory { .. } = &inst.operands[1] {
                    let value = Expr::from_operand(&inst.operands[1]);
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

    // Second pass: copy propagation per-block
    let nodes: Vec<_> = nodes.into_iter().map(simplify_node_copies).collect();

    // Third pass: substitute global refs everywhere (including conditions)
    nodes
        .into_iter()
        .map(|node| substitute_globals_in_node(node, &global_refs))
        .collect()
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
                            global_refs.insert(lhs_var.name.clone(), (**rhs).clone());
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
        | StructuredNode::Loop { body } => {
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
            // Substitute in statements and remove GotRef assignments
            let statements: Vec<_> = statements
                .into_iter()
                .map(|stmt| substitute_global_refs(&stmt, global_refs))
                .filter(|stmt| {
                    // Remove GotRef assignments (they've been propagated)
                    if let ExprKind::Assign { rhs, .. } = &stmt.kind {
                        if let ExprKind::GotRef { .. } = &rhs.kind {
                            return false;
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
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition: substitute_global_refs(&condition, global_refs),
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
            condition: substitute_global_refs(&condition, global_refs),
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init: init.map(|e| substitute_global_refs(&e, global_refs)),
            condition: substitute_global_refs(&condition, global_refs),
            update: update.map(|e| substitute_global_refs(&e, global_refs)),
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: body
                .into_iter()
                .map(|n| substitute_globals_in_node(n, global_refs))
                .collect(),
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
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition,
            body: body.into_iter().map(simplify_node_copies).collect(),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: body.into_iter().map(simplify_node_copies).collect(),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: body.into_iter().map(simplify_node_copies).collect(),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: body.into_iter().map(simplify_node_copies).collect(),
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
/// Transforms patterns like `eax = x; y = eax;` into `y = x;` and removes the temp assignment.
fn propagate_copies(statements: Vec<Expr>) -> Vec<Expr> {
    use super::expression::ExprKind;

    // Track the last value assigned to each temp register
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    // Track which temp register assignments can be removed
    let mut can_remove: HashSet<String> = HashSet::new();
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
                    can_remove.insert(lhs_var.name.clone());
                    // Emit with substituted RHS
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

    // Second pass: remove temp register assignments that were fully propagated
    result
        .into_iter()
        .filter(|stmt| {
            if let ExprKind::Assign { lhs, .. } = &stmt.kind {
                if let ExprKind::Var(v) = &lhs.kind {
                    if is_temp_register(&v.name) && can_remove.contains(&v.name) {
                        return false; // Remove this temp assignment
                    }
                }
            }
            true
        })
        .collect()
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
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_global_refs(lhs, global_refs),
            substitute_global_refs(rhs, global_refs),
        ),
        _ => expr.clone(),
    }
}

/// Check if a register name is a temporary (likely to be eliminated)
/// Note: Only caller-saved registers should be temps; callee-saved are preserved
fn is_temp_register(name: &str) -> bool {
    matches!(
        name,
        // x86-64 caller-saved registers (SysV ABI)
        // Note: rbx, rbp, r12-r15 are callee-saved and should NOT be temps
        "eax" | "rax" | "ecx" | "rcx" | "edx" | "rdx" |
        "esi" | "rsi" | "edi" | "rdi" | "r8" | "r8d" | "r9" | "r9d" |
        "r10" | "r10d" | "r11" | "r11d" |
        // ARM64 registers (x0-x18 and w0-w18 are caller-saved/temp)
        // Note: x19-x28 are callee-saved
        "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7" |
        "x8" | "x9" | "x10" | "x11" | "x12" | "x13" | "x14" | "x15" |
        "x16" | "x17" | "x18" |
        "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" | "w7" |
        "w8" | "w9" | "w10" | "w11" | "w12" | "w13" | "w14" | "w15" |
        "w16" | "w17" | "w18" |
        // RISC-V registers (a0-a7 are argument/caller-saved)
        "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7" |
        "t0" | "t1" | "t2" | "t3" | "t4" | "t5" | "t6"
    )
}

/// Check if a register is callee-saved (preserved across function calls)
/// These registers are used to save return values that need to survive subsequent calls
fn is_callee_saved_register(name: &str) -> bool {
    matches!(
        name,
        // x86-64 callee-saved registers (SysV ABI)
        "ebx" | "rbx" | "ebp" | "rbp" |
        "r12" | "r12d" | "r13" | "r13d" | "r14" | "r14d" | "r15" | "r15d" |
        // ARM64 callee-saved registers (AAPCS64)
        "x19" | "x20" | "x21" | "x22" | "x23" | "x24" | "x25" | "x26" | "x27" | "x28" |
        "w19" | "w20" | "w21" | "w22" | "w23" | "w24" | "w25" | "w26" | "w27" | "w28" |
        // RISC-V callee-saved registers
        "s0" | "s1" | "s2" | "s3" | "s4" | "s5" | "s6" | "s7" | "s8" | "s9" | "s10" | "s11"
    )
}

/// Substitute variable references with their known values
fn substitute_vars(expr: &Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    use super::expression::ExprKind;

    match &expr.kind {
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
    }
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
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition,
            body: propagate_call_args(body),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: propagate_call_args(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: propagate_call_args(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: propagate_call_args(body),
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

    // Track argument register values
    let mut arg_values: HashMap<String, Expr> = HashMap::new();
    let mut to_remove: HashSet<usize> = HashSet::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for (i, stmt) in statements.into_iter().enumerate() {
        // Check if this is an assignment to an argument register
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if get_arg_register_index(&v.name).is_some() {
                    // Track this argument value
                    arg_values.insert(v.name.clone(), (**rhs).clone());
                    to_remove.insert(i);
                    result.push(stmt);
                    continue;
                }
            }
        }

        // Check if this is a function call (not push/pop/syscall/etc.)
        if let ExprKind::Call { target, args } = &stmt.kind {
            if is_real_function_call(target) && args.is_empty() {
                // Try to extract arguments from tracked registers
                let new_args = extract_call_arguments(&arg_values);
                if !new_args.is_empty() {
                    // Create a new call with arguments
                    let new_call = Expr::call(target.clone(), new_args);
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

    // Filter out argument register assignments that were propagated
    result
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| !to_remove.contains(idx))
        .map(|(_, stmt)| stmt)
        .collect()
}

/// Returns the argument index (0-based) for an argument register, or None if not an arg register.
fn get_arg_register_index(name: &str) -> Option<usize> {
    match name {
        // x86-64 System V ABI
        "edi" | "rdi" => Some(0),
        "esi" | "rsi" => Some(1),
        "edx" | "rdx" => Some(2),
        "ecx" | "rcx" => Some(3),
        "r8d" | "r8" => Some(4),
        "r9d" | "r9" => Some(5),
        // ARM64 AAPCS64
        "x0" | "w0" => Some(0),
        "x1" | "w1" => Some(1),
        "x2" | "w2" => Some(2),
        "x3" | "w3" => Some(3),
        "x4" | "w4" => Some(4),
        "x5" | "w5" => Some(5),
        "x6" | "w6" => Some(6),
        "x7" | "w7" => Some(7),
        // RISC-V
        "a0" => Some(0),
        "a1" => Some(1),
        "a2" => Some(2),
        "a3" => Some(3),
        "a4" => Some(4),
        "a5" => Some(5),
        "a6" => Some(6),
        "a7" => Some(7),
        _ => None,
    }
}

/// Checks if a register is a return value register.
fn is_return_register(name: &str) -> bool {
    matches!(name, "eax" | "rax" | "x0" | "w0" | "a0")
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

/// Merges return value captures across basic block boundaries.
/// Transforms patterns where:
///   Block1: ...; func();
///   Block2: var = eax; ...
/// Into:
///   Block1: ...
///   Block2: var = func(); ...
fn merge_return_value_captures(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    use super::expression::ExprKind;

    let mut result: Vec<StructuredNode> = Vec::with_capacity(nodes.len());

    for node in nodes {
        // First, recursively process nested structures
        let node = merge_return_value_captures_node(node);

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
fn merge_return_value_captures_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: merge_return_value_captures(then_body),
            else_body: else_body.map(merge_return_value_captures),
        },
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition,
            body: merge_return_value_captures(body),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: merge_return_value_captures(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: merge_return_value_captures(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: merge_return_value_captures(body),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, merge_return_value_captures(body)))
                .collect(),
            default: default.map(merge_return_value_captures),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(merge_return_value_captures(nodes))
        }
        other => other,
    }
}

/// Detect and convert while loops with init/update patterns to for loops.
fn detect_for_loops(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < nodes.len() {
        // Check for Block followed by While pattern
        if i + 1 < nodes.len() {
            if let (
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                },
                StructuredNode::While { condition, body },
            ) = (&nodes[i], &nodes[i + 1])
            {
                // Try to extract a for loop
                if let Some((init, updated_condition, update, new_body, remaining_stmts)) =
                    try_extract_for_loop(statements, condition, body)
                {
                    // Add remaining statements from the block (if any) as a separate block
                    if !remaining_stmts.is_empty() {
                        result.push(StructuredNode::Block {
                            id: *id,
                            statements: remaining_stmts,
                            address_range: *address_range,
                        });
                    }

                    // Add the for loop
                    result.push(StructuredNode::For {
                        init: Some(init),
                        condition: updated_condition,
                        update: Some(update),
                        body: detect_for_loops(new_body),
                    });

                    i += 2;
                    continue;
                }
            }
        }

        // Recursively process the node
        result.push(detect_for_loops_in_node(nodes[i].clone()));
        i += 1;
    }

    result
}

/// Recursively detect for loops within a single node.
fn detect_for_loops_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: detect_for_loops(then_body),
            else_body: else_body.map(detect_for_loops),
        },
        StructuredNode::While { condition, body } => {
            // Check if the while body itself has init/update pattern (rare but possible)
            StructuredNode::While {
                condition,
                body: detect_for_loops(body),
            }
        }
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: detect_for_loops(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_for_loops(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: detect_for_loops(body),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_for_loops(body)))
                .collect(),
            default: default.map(detect_for_loops),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(detect_for_loops(nodes)),
        other => other,
    }
}

/// Try to extract a for loop from a block followed by a while loop.
/// Returns (init_expr, condition, update_expr, new_body, remaining_block_stmts) if successful.
#[allow(clippy::type_complexity)]
fn try_extract_for_loop(
    block_stmts: &[Expr],
    condition: &Expr,
    body: &[StructuredNode],
) -> Option<(Expr, Expr, Expr, Vec<StructuredNode>, Vec<Expr>)> {
    // Extract the loop variable from the condition
    let loop_var = extract_loop_variable(condition)?;

    // Find init: last statement in the block that assigns to the loop variable
    let init_idx = block_stmts
        .iter()
        .rposition(|stmt| is_init_assignment(stmt, &loop_var))?;
    let init = block_stmts[init_idx].clone();

    // Find update: look for increment/decrement of the loop variable in the body
    let (update, new_body) = extract_update_from_body(body, &loop_var)?;

    // Remaining statements from the block (everything before the init)
    let remaining_stmts: Vec<_> = block_stmts[..init_idx].to_vec();

    Some((init, condition.clone(), update, new_body, remaining_stmts))
}

/// Extract the loop variable name from a comparison condition.
/// Looks for patterns like: var < n, var <= n, var > n, var >= n, var != n
fn extract_loop_variable(condition: &Expr) -> Option<String> {
    use super::expression::ExprKind;

    if let ExprKind::BinOp {
        op:
            BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
            | BinOpKind::ULt
            | BinOpKind::ULe
            | BinOpKind::UGt
            | BinOpKind::UGe
            | BinOpKind::Ne
            | BinOpKind::Eq,
        left,
        right,
    } = &condition.kind
    {
        // Try to get variable from left side first
        if let Some(var) = get_expr_var_key(left) {
            return Some(var);
        }
        // Try right side (for reversed comparisons like `n > i`)
        if let Some(var) = get_expr_var_key(right) {
            return Some(var);
        }
    }
    None
}

/// Get a unique key for a variable expression.
/// Handles both simple variables (Var) and stack slots (Deref of rbp/sp + offset).
fn get_expr_var_key(expr: &Expr) -> Option<String> {
    use super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        ExprKind::Deref { addr, .. } => {
            // Extract stack variable pattern like [rbp - 4] or [sp + 8]
            get_stack_slot_key(addr)
        }
        _ => None,
    }
}

/// Extract a key for a stack slot address expression.
/// Handles patterns like: rbp, rbp + offset, rbp - offset, sp + offset
fn get_stack_slot_key(addr: &Expr) -> Option<String> {
    use super::expression::ExprKind;

    match &addr.kind {
        // Just base register (offset 0)
        ExprKind::Var(var) => {
            if is_frame_register(&var.name) {
                Some("stack_0".to_string())
            } else {
                None
            }
        }
        // base + offset or base - offset
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

/// Check if a register name is a frame/stack pointer.
fn is_frame_register(name: &str) -> bool {
    matches!(
        name,
        "rbp" | "ebp" | "bp" | "sp" | "rsp" | "esp" | "x29" | "fp"
    )
}

/// Check if an expression is an initialization assignment to the given variable.
/// Matches patterns like: var = 0, var = 1, var = expr
fn is_init_assignment(stmt: &Expr, var_key: &str) -> bool {
    use super::expression::ExprKind;

    if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
        if let Some(lhs_key) = get_expr_var_key(lhs) {
            if lhs_key == var_key {
                // Check that RHS is a constant or simple expression (not another loop variable)
                return is_simple_init_value(rhs);
            }
        }
    }
    false
}

/// Check if an expression is a valid initialization value (constant or simple expression).
fn is_simple_init_value(expr: &Expr) -> bool {
    use super::expression::ExprKind;

    match &expr.kind {
        ExprKind::IntLit(_) => true,
        ExprKind::Var(_) => true,
        ExprKind::BinOp { left, right, .. } => {
            is_simple_init_value(left) && is_simple_init_value(right)
        }
        _ => false,
    }
}

/// Extract the update statement from the loop body.
/// Returns (update_expr, modified_body) if found.
fn extract_update_from_body(
    body: &[StructuredNode],
    var_name: &str,
) -> Option<(Expr, Vec<StructuredNode>)> {
    if body.is_empty() {
        return None;
    }

    let last_node = body.last()?;

    // Check if the last node is a Block with an update statement
    if let StructuredNode::Block {
        id,
        statements,
        address_range,
    } = last_node
    {
        if let Some(last_stmt) = statements.last() {
            if is_update_statement(last_stmt, var_name) {
                let update = last_stmt.clone();

                // Create new body with the update removed
                let mut new_body: Vec<_> = body[..body.len() - 1].to_vec();

                // Add the block back without the last statement (if there are remaining statements)
                let remaining_stmts: Vec<_> = statements[..statements.len() - 1].to_vec();
                if !remaining_stmts.is_empty() {
                    new_body.push(StructuredNode::Block {
                        id: *id,
                        statements: remaining_stmts,
                        address_range: *address_range,
                    });
                }

                return Some((update, new_body));
            }
        }
    }

    // Also check for a Sequence ending with a Block
    if let StructuredNode::Sequence(inner_nodes) = last_node {
        if let Some((update, new_inner)) = extract_update_from_body(inner_nodes, var_name) {
            let mut new_body: Vec<_> = body[..body.len() - 1].to_vec();
            if !new_inner.is_empty() {
                new_body.push(StructuredNode::Sequence(new_inner));
            }
            return Some((update, new_body));
        }
    }

    None
}

/// Check if an expression is an update statement for the given variable.
/// Matches patterns like: var++, var--, var += n, var -= n, var = var + n
fn is_update_statement(stmt: &Expr, var_key: &str) -> bool {
    use super::expression::{ExprKind, UnaryOpKind};

    match &stmt.kind {
        // var++ or var--
        ExprKind::UnaryOp { op, operand } => {
            matches!(op, UnaryOpKind::Inc | UnaryOpKind::Dec)
                && get_expr_var_key(operand).is_some_and(|k| k == var_key)
        }

        // var += n or var -= n
        ExprKind::CompoundAssign { op, lhs, rhs: _ } => {
            matches!(op, BinOpKind::Add | BinOpKind::Sub)
                && get_expr_var_key(lhs).is_some_and(|k| k == var_key)
        }

        // var = var + n or var = var - n
        ExprKind::Assign { lhs, rhs } => {
            if let Some(lhs_key) = get_expr_var_key(lhs) {
                if lhs_key == var_key {
                    if let ExprKind::BinOp { op, left, right: _ } = &rhs.kind {
                        if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                            if let Some(rhs_key) = get_expr_var_key(left) {
                                return rhs_key == var_key;
                            }
                        }
                    }
                }
            }
            false
        }

        _ => false,
    }
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
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition,
            body: detect_switch_statements(body),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: detect_switch_statements(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_switch_statements(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: detect_switch_statements(body),
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
fn try_extract_switch(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<StructuredNode> {
    // Check if condition is a comparison against a literal: var == N
    let (first_var_key, first_var_expr, first_value) = extract_switch_case(condition)?;

    // Start collecting cases
    let mut cases: Vec<(Vec<i128>, Vec<StructuredNode>)> =
        vec![(vec![first_value], then_body.to_vec())];
    let mut current_else = else_body.clone();
    let mut switch_var_key = first_var_key.clone();
    let mut switch_var_expr = first_var_expr.clone();
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
                if let Some((var_key, var_expr, value)) = extract_switch_case(else_cond) {
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
                        cases.push((vec![value], else_then.to_vec()));
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

/// Extract switch case from a condition: var == N
/// Returns (variable_key, variable_expr, value) if it matches the pattern.
fn extract_switch_case(condition: &Expr) -> Option<(String, Expr, i128)> {
    use super::expression::BinOpKind;
    use super::expression::ExprKind;

    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        left,
        right,
    } = &condition.kind
    {
        // var == N
        if let Some(key) = get_expr_var_key(left) {
            if let ExprKind::IntLit(n) = right.kind {
                return Some((key, (**left).clone(), n));
            }
        }
        // N == var (reversed)
        if let Some(key) = get_expr_var_key(right) {
            if let ExprKind::IntLit(n) = left.kind {
                return Some((key, (**right).clone(), n));
            }
        }
    }

    None
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
        // For loops, create a new loop context for the body
        StructuredNode::While { condition, body } => {
            // For while loops, we can detect the loop header from the structured form
            // The condition block is implicitly the header, but we don't have the block ID here
            // So we pass the current context through
            StructuredNode::While {
                condition,
                body: convert_gotos_in_loop_body(body, current_loop),
            }
        }
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: convert_gotos_in_loop_body(body, current_loop),
            condition,
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: convert_gotos_in_loop_body(body, current_loop),
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: convert_gotos_in_loop_body(body, current_loop),
        },
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
                // Note: We could check if target is outside the loop body
                // but that requires more context. For now, keep as goto.
            }
            StructuredNode::Goto(target)
        }
        // Other nodes pass through unchanged
        other => other,
    }
}

/// Converts gotos in a loop body, creating a new loop context.
fn convert_gotos_in_loop_body(
    body: Vec<StructuredNode>,
    _outer_loop: Option<&LoopContext>,
) -> Vec<StructuredNode> {
    // For now, we don't have the block ID available from the structured form,
    // so we process the body without a specific loop context.
    // The break/continue detection happens at the CFG level during initial structuring.
    // This pass catches any remaining opportunities.
    convert_gotos_to_break_continue(body, None)
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
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition: condition.simplify(),
            body: simplify_expressions(body),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: simplify_expressions(body),
            condition: condition.simplify(),
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init: init.map(|e| e.simplify()),
            condition: condition.simplify(),
            update: update.map(|e| e.simplify()),
            body: simplify_expressions(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: simplify_expressions(body),
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

// ==================== Short-Circuit Boolean Detection ====================

/// Detects short-circuit boolean patterns and converts nested ifs to && / ||.
///
/// Patterns detected:
/// 1. `if (a) { if (b) { body }}` → `if (a && b) { body }`
/// 2. `if (a) { body } else { if (b) { same_body }}` → `if (a || b) { body }`
/// 3. Chains: `if (a) { if (b) { if (c) { body }}}` → `if (a && b && c) { body }`
fn detect_short_circuit(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(detect_short_circuit_in_node)
        .collect()
}

/// Recursively detect short-circuit patterns in a single node.
fn detect_short_circuit_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            // First, recursively process children
            let then_body = detect_short_circuit(then_body);
            let else_body = else_body.map(detect_short_circuit);

            // Try to detect short-circuit AND: if (a) { if (b) { body } }
            if else_body.is_none() {
                if let Some((combined_cond, inner_body, inner_else)) =
                    try_extract_and_chain(&condition, &then_body)
                {
                    return StructuredNode::If {
                        condition: combined_cond,
                        then_body: inner_body,
                        else_body: inner_else,
                    };
                }
            }

            // Try to detect short-circuit OR: if (a) { body } else { if (b) { same_body } }
            if let Some(ref else_nodes) = else_body {
                if let Some((combined_cond, body)) =
                    try_extract_or_chain(&condition, &then_body, else_nodes)
                {
                    return StructuredNode::If {
                        condition: combined_cond,
                        then_body: body,
                        else_body: None,
                    };
                }
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            }
        }
        StructuredNode::While { condition, body } => StructuredNode::While {
            condition,
            body: detect_short_circuit(body),
        },
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: detect_short_circuit(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_short_circuit(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: detect_short_circuit(body),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_short_circuit(body)))
                .collect(),
            default: default.map(detect_short_circuit),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(detect_short_circuit(nodes)),
        other => other,
    }
}

/// Try to extract a short-circuit AND chain from nested ifs.
/// Pattern: `if (a) { if (b) { body } }` → Some((a && b, body, None))
/// Pattern: `if (a) { if (b) { body } else { e } }` → Some((a && b, body, Some(e)))
fn try_extract_and_chain(
    outer_cond: &Expr,
    then_body: &[StructuredNode],
) -> Option<(Expr, Vec<StructuredNode>, Option<Vec<StructuredNode>>)> {
    // The then_body must contain exactly one If node (possibly with surrounding trivial nodes)
    let (inner_if, prefix, suffix) = extract_single_if(then_body)?;

    // Don't combine if there's non-trivial code before/after the inner if
    if !prefix.is_empty() || !suffix.is_empty() {
        return None;
    }

    // Extract the inner if
    let (inner_cond, inner_body, inner_else) = match inner_if {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => (condition, then_body, else_body),
        _ => return None,
    };

    // Recursively try to extract more AND conditions from the inner body
    let (final_cond, final_body, final_else) = if inner_else.is_none() {
        if let Some((nested_cond, nested_body, nested_else)) =
            try_extract_and_chain(&inner_cond, &inner_body)
        {
            (nested_cond, nested_body, nested_else)
        } else {
            (inner_cond.clone(), inner_body.clone(), inner_else.clone())
        }
    } else {
        (inner_cond.clone(), inner_body.clone(), inner_else.clone())
    };

    // Combine: outer_cond && final_cond
    let combined = Expr::binop(BinOpKind::LogicalAnd, outer_cond.clone(), final_cond);

    Some((combined, final_body, final_else))
}

/// Try to extract a short-circuit OR chain from if-else with same body.
/// Pattern: `if (a) { body } else { if (b) { same_body } }` → Some((a || b, body))
fn try_extract_or_chain(
    outer_cond: &Expr,
    then_body: &[StructuredNode],
    else_body: &[StructuredNode],
) -> Option<(Expr, Vec<StructuredNode>)> {
    // The else_body must contain exactly one If node
    let (inner_if, prefix, suffix) = extract_single_if(else_body)?;

    // Don't combine if there's non-trivial code
    if !prefix.is_empty() || !suffix.is_empty() {
        return None;
    }

    let (inner_cond, inner_body, inner_else) = match inner_if {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => (condition, then_body, else_body),
        _ => return None,
    };

    // The inner if must not have an else, and bodies must be structurally equal
    if inner_else.is_some() {
        return None;
    }

    if !bodies_are_equal(then_body, &inner_body) {
        return None;
    }

    // Recursively try to extract more OR conditions
    let (final_cond, _) =
        if let Some((nested_cond, _)) = try_extract_or_chain(&inner_cond, &inner_body, &[]) {
            (nested_cond, inner_body.clone())
        } else {
            (inner_cond.clone(), inner_body.clone())
        };

    // Combine: outer_cond || final_cond
    let combined = Expr::binop(BinOpKind::LogicalOr, outer_cond.clone(), final_cond);

    Some((combined, then_body.to_vec()))
}

/// Extract a single If node from a body, returning (if_node, prefix_nodes, suffix_nodes).
/// Returns None if there's no If or multiple Ifs.
fn extract_single_if(
    body: &[StructuredNode],
) -> Option<(StructuredNode, Vec<StructuredNode>, Vec<StructuredNode>)> {
    let mut if_idx = None;

    for (i, node) in body.iter().enumerate() {
        match node {
            StructuredNode::If { .. } => {
                if if_idx.is_some() {
                    // Multiple ifs, can't combine
                    return None;
                }
                if_idx = Some(i);
            }
            StructuredNode::Block { statements, .. } if statements.is_empty() => {
                // Empty block, ignore
            }
            StructuredNode::Expr(_) => {
                // Expression statement before/after the if prevents combining
                // (side effects matter)
                if if_idx.is_some() {
                    return None; // Side effect after the if
                }
            }
            _ => {
                // Other node types prevent combining
                return None;
            }
        }
    }

    let idx = if_idx?;
    let prefix: Vec<_> = body[..idx]
        .iter()
        .filter(|n| !matches!(n, StructuredNode::Block { statements, .. } if statements.is_empty()))
        .cloned()
        .collect();
    let suffix: Vec<_> = body[idx + 1..]
        .iter()
        .filter(|n| !matches!(n, StructuredNode::Block { statements, .. } if statements.is_empty()))
        .cloned()
        .collect();

    Some((body[idx].clone(), prefix, suffix))
}

/// Check if two structured bodies are structurally equal.
/// This is a simplified check - full equality would require deep comparison.
fn bodies_are_equal(a: &[StructuredNode], b: &[StructuredNode]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for (node_a, node_b) in a.iter().zip(b.iter()) {
        if !nodes_are_equal(node_a, node_b) {
            return false;
        }
    }

    true
}

/// Check if two nodes are structurally equal.
fn nodes_are_equal(a: &StructuredNode, b: &StructuredNode) -> bool {
    match (a, b) {
        (
            StructuredNode::Block { statements: s1, .. },
            StructuredNode::Block { statements: s2, .. },
        ) => {
            s1.len() == s2.len()
                && s1
                    .iter()
                    .zip(s2.iter())
                    .all(|(e1, e2)| exprs_are_equal(e1, e2))
        }
        (StructuredNode::Return(e1), StructuredNode::Return(e2)) => match (e1, e2) {
            (Some(e1), Some(e2)) => exprs_are_equal(e1, e2),
            (None, None) => true,
            _ => false,
        },
        (StructuredNode::Break, StructuredNode::Break) => true,
        (StructuredNode::Continue, StructuredNode::Continue) => true,
        (StructuredNode::Goto(a), StructuredNode::Goto(b)) => a == b,
        (StructuredNode::Expr(e1), StructuredNode::Expr(e2)) => exprs_are_equal(e1, e2),
        // For more complex nodes, we're conservative and say they're not equal
        // This could be expanded for more thorough comparison
        _ => false,
    }
}

/// Check if two expressions are structurally equal.
fn exprs_are_equal(a: &Expr, b: &Expr) -> bool {
    use super::expression::ExprKind;

    match (&a.kind, &b.kind) {
        (ExprKind::Var(v1), ExprKind::Var(v2)) => v1.name == v2.name,
        (ExprKind::IntLit(n1), ExprKind::IntLit(n2)) => n1 == n2,
        (
            ExprKind::BinOp {
                op: op1,
                left: l1,
                right: r1,
            },
            ExprKind::BinOp {
                op: op2,
                left: l2,
                right: r2,
            },
        ) => op1 == op2 && exprs_are_equal(l1, l2) && exprs_are_equal(r1, r2),
        (
            ExprKind::UnaryOp {
                op: op1,
                operand: o1,
            },
            ExprKind::UnaryOp {
                op: op2,
                operand: o2,
            },
        ) => op1 == op2 && exprs_are_equal(o1, o2),
        (
            ExprKind::Call {
                target: t1,
                args: a1,
            },
            ExprKind::Call {
                target: t2,
                args: a2,
            },
        ) => {
            call_targets_equal(t1, t2)
                && a1.len() == a2.len()
                && a1
                    .iter()
                    .zip(a2.iter())
                    .all(|(e1, e2)| exprs_are_equal(e1, e2))
        }
        (ExprKind::Deref { addr: a1, size: s1 }, ExprKind::Deref { addr: a2, size: s2 }) => {
            s1 == s2 && exprs_are_equal(a1, a2)
        }
        (ExprKind::Assign { lhs: l1, rhs: r1 }, ExprKind::Assign { lhs: l2, rhs: r2 }) => {
            exprs_are_equal(l1, l2) && exprs_are_equal(r1, r2)
        }
        _ => false,
    }
}

/// Check if two call targets are equal.
fn call_targets_equal(
    a: &super::expression::CallTarget,
    b: &super::expression::CallTarget,
) -> bool {
    use super::expression::CallTarget;
    match (a, b) {
        (CallTarget::Direct { target: t1, .. }, CallTarget::Direct { target: t2, .. }) => t1 == t2,
        (CallTarget::Named(n1), CallTarget::Named(n2)) => n1 == n2,
        (CallTarget::Indirect(e1), CallTarget::Indirect(e2)) => exprs_are_equal(e1, e2),
        (
            CallTarget::IndirectGot {
                got_address: a1, ..
            },
            CallTarget::IndirectGot {
                got_address: a2, ..
            },
        ) => a1 == a2,
        _ => false,
    }
}
