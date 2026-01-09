//! Control flow structuring.
//!
//! Transforms a CFG into structured control flow (if/else, while, for, etc.).

#![allow(dead_code)]

use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph, Operation, cfg::Loop};
use std::collections::{HashMap, HashSet};

use super::expression::{Expr, BinOpKind, resolve_adrp_patterns};

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
    Loop {
        body: Vec<StructuredNode>,
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

        // Post-process to eliminate temporary register patterns
        let body = simplify_statements(body);

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

            loop_info.insert(lp.header, LoopInfo {
                header: lp.header,
                back_edges: vec![lp.back_edge],
                body: body_set,
                kind,
                exit_blocks,
            });
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
            let backward_jumps = preds.iter()
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
            if let BlockTerminator::ConditionalBranch { true_target, false_target, .. } = &block.terminator {
                let true_in_loop = body.contains(true_target);
                let false_in_loop = body.contains(false_target);
                if true_in_loop != false_in_loop {
                    return LoopKind::While;
                }
            }
        }

        // Check if back edge block has a conditional branch (do-while loop)
        if let Some(block) = back_edge_block {
            if let BlockTerminator::ConditionalBranch { true_target, false_target, .. } = &block.terminator {
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
        let mut unprocessed: Vec<_> = self.multi_pred_blocks
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
                result.push(StructuredNode::Goto(block_id));
                break;
            }

            // Prevent infinite loops in structuring
            if self.processed.contains(&block_id) {
                result.push(StructuredNode::Goto(block_id));
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
                        block,
                    );
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

                BlockTerminator::IndirectJump { .. } => {
                    if !statements.is_empty() {
                        result.push(StructuredNode::Block {
                            id: block_id,
                            statements,
                            address_range,
                        });
                    }
                    // Can't follow indirect jump
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

    fn structure_loop_body(&mut self, header: BasicBlockId, info: &LoopInfo) -> Vec<StructuredNode> {
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
        let succs: Vec<_> = self.cfg.successors(header)
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

    fn get_while_condition(&self, header: BasicBlockId, info: &LoopInfo) -> (Expr, Option<BasicBlockId>) {
        let block = match self.cfg.block(header) {
            Some(b) => b,
            None => return (Expr::int(1), None),
        };

        if let BlockTerminator::ConditionalBranch { condition, true_target, false_target, .. } = &block.terminator {
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

            if let BlockTerminator::ConditionalBranch { condition, true_target, false_target, .. } = &block.terminator {
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
        let common: Vec<_> = true_reachable.intersection(&false_reachable).copied().collect();

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
        let has_conditional_branch = matches!(
            block.terminator,
            BlockTerminator::ConditionalBranch { .. }
        );

        // Find the index of the compare instruction if the block ends with a conditional
        let compare_idx = if has_conditional_branch {
            block.instructions.iter().rposition(|inst| {
                matches!(inst.operation, Operation::Compare | Operation::Test | Operation::Sub)
            })
        } else {
            None
        };

        let exprs: Vec<Expr> = block.instructions
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

    // Find the last compare instruction in the block
    let compare_inst = block.instructions.iter().rev().find(|inst| {
        matches!(inst.operation, Operation::Compare | Operation::Test | Operation::Sub)
    });

    if let Some(inst) = compare_inst {
        // For SUB/SUBS instructions (ARM64), operands are [dst, src1, src2]
        // The comparison is between src1 and src2
        if inst.operands.len() >= 3 && matches!(inst.operation, Operation::Sub) {
            let left = Expr::from_operand(&inst.operands[1]);
            let right = Expr::from_operand(&inst.operands[2]);
            return Expr::binop(op, left, right);
        } else if inst.operands.len() >= 2 {
            // For CMP/TEST instructions, operands are [src1, src2]
            let left = Expr::from_operand(&inst.operands[0]);
            let right = Expr::from_operand(&inst.operands[1]);

            // Special case: TEST reg, reg (same register) is a zero check
            // test eax, eax; je → jump if eax == 0
            // test eax, eax; jne → jump if eax != 0
            if matches!(inst.operation, Operation::Test) && inst.operands[0] == inst.operands[1] {
                return Expr::binop(op, left, Expr::int(0));
            }

            return Expr::binop(op, left, right);
        } else if inst.operands.len() == 1 {
            // Compare against zero (common for test/cmp with single operand)
            let left = Expr::from_operand(&inst.operands[0]);
            return Expr::binop(op, left, Expr::int(0));
        }
    }

    // Fallback: use placeholder if no compare found
    Expr::binop(op, Expr::unknown("cmp_left"), Expr::unknown("cmp_right"))
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
    Expr::binop(op, Expr::unknown("cmp_left"), Expr::unknown("cmp_right"))
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
fn extract_return_value(mut statements: Vec<Expr>) -> (Vec<Expr>, Option<Expr>) {
    // Search backwards for an assignment to a return register
    for i in (0..statements.len()).rev() {
        let stmt = &statements[i];
        if let super::expression::ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let super::expression::ExprKind::Var(v) = &lhs.kind {
                // Check if this is assigning to a return register (eax, rax, x0, a0)
                let is_return_reg = matches!(v.name.as_str(), "eax" | "rax" | "x0" | "a0");
                if is_return_reg {
                    let return_value = (**rhs).clone();
                    statements.remove(i);
                    return (statements, Some(return_value));
                }
            }
        }
        // Skip prologue/epilogue-like statements (push/pop)
        if let super::expression::ExprKind::Call { target, .. } = &stmt.kind {
            if let super::expression::CallTarget::Named(name) = target {
                if name == "push" || name == "pop" {
                    continue;
                }
            }
        }
        // If we hit a non-prologue statement that's not a return reg assignment, stop
        break;
    }
    (statements, None)
}

/// Simplifies statements by performing copy propagation on temporary registers.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
fn simplify_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(simplify_node).collect()
}

fn simplify_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block { id, statements, address_range } => {
            let statements = propagate_copies(statements);
            StructuredNode::Block { id, statements, address_range }
        }
        StructuredNode::If { condition, then_body, else_body } => {
            StructuredNode::If {
                condition,
                then_body: simplify_statements(then_body),
                else_body: else_body.map(simplify_statements),
            }
        }
        StructuredNode::While { condition, body } => {
            StructuredNode::While {
                condition,
                body: simplify_statements(body),
            }
        }
        StructuredNode::DoWhile { body, condition } => {
            StructuredNode::DoWhile {
                body: simplify_statements(body),
                condition,
            }
        }
        StructuredNode::For { init, condition, update, body } => {
            StructuredNode::For {
                init,
                condition,
                update,
                body: simplify_statements(body),
            }
        }
        StructuredNode::Loop { body } => {
            StructuredNode::Loop {
                body: simplify_statements(body),
            }
        }
        StructuredNode::Switch { value, cases, default } => {
            StructuredNode::Switch {
                value,
                cases: cases.into_iter()
                    .map(|(vals, body)| (vals, simplify_statements(body)))
                    .collect(),
                default: default.map(simplify_statements),
            }
        }
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(simplify_statements(nodes))
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
    result.into_iter()
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

/// Check if a register name is a temporary (likely to be eliminated)
fn is_temp_register(name: &str) -> bool {
    matches!(name, "eax" | "rax" | "ebx" | "rbx" | "ecx" | "rcx" | "edx" | "rdx" |
                   "esi" | "rsi" | "edi" | "rdi" | "r8" | "r8d" | "r9" | "r9d" |
                   "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7" |
                   "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7")
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
        ExprKind::BinOp { op, left, right } => {
            Expr::binop(
                *op,
                substitute_vars(left, reg_values),
                substitute_vars(right, reg_values),
            )
        }
        ExprKind::UnaryOp { op, operand } => {
            Expr::unary(*op, substitute_vars(operand, reg_values))
        }
        ExprKind::Assign { lhs, rhs } => {
            Expr::assign(
                substitute_vars(lhs, reg_values),
                substitute_vars(rhs, reg_values),
            )
        }
        ExprKind::Deref { addr, size } => {
            Expr::deref(substitute_vars(addr, reg_values), *size)
        }
        _ => expr.clone(),
    }
}

