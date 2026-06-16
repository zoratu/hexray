//! Short-circuit boolean detection.
//!
//! Detects short-circuit boolean patterns and converts nested ifs to && / ||.
//!
//! Patterns detected:
//! 1. `if (a) { if (b) { body }}` → `if (a && b) { body }`
//! 2. `if (a) { body } else { if (b) { same_body }}` → `if (a || b) { body }`
//! 3. Chains: `if (a) { if (b) { if (c) { body }}}` → `if (a && b && c) { body }`

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind};
use super::structurer::StructuredNode;

/// Entry point: detect short-circuit patterns in a list of nodes.
pub fn detect_short_circuit(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
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
            // Allow combination when else_body is None OR empty
            let else_is_empty = else_body.as_ref().is_none_or(|e| e.is_empty());
            if else_is_empty {
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

            // Collapse a redundant duplicate-condition guard:
            //   if (c) {} else { if (c) {} else { body } }
            //     → if (c) {} else { body }
            // This is the structured manifestation of the x86 float-equality
            // idiom `ucomisd; jne X; jp X` — the compiler emits TWO conditional
            // branches to the same target so NaN is handled per C's `==`
            // semantics, and the structurer turns each into its own empty-then
            // `if` on the same lifted comparison. See
            // `try_collapse_duplicate_empty_then_guard`.
            if let Some(collapsed_else) =
                try_collapse_duplicate_empty_then_guard(&condition, &then_body, &else_body)
            {
                return StructuredNode::If {
                    condition,
                    then_body,
                    else_body: collapsed_else,
                };
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: detect_short_circuit(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: detect_short_circuit(body),
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
            body: detect_short_circuit(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: detect_short_circuit(body),
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
    // Treat empty else as no else for recursion purposes
    let inner_else_is_empty = inner_else.as_ref().is_none_or(|e| e.is_empty());
    let (final_cond, final_body, final_else) = if inner_else_is_empty {
        if let Some((nested_cond, nested_body, nested_else)) =
            try_extract_and_chain(&inner_cond, &inner_body)
        {
            (nested_cond, nested_body, nested_else)
        } else {
            // If inner else is empty, convert to None
            let normalized_else = if inner_else_is_empty {
                None
            } else {
                inner_else.clone()
            };
            (inner_cond.clone(), inner_body.clone(), normalized_else)
        }
    } else {
        (inner_cond.clone(), inner_body.clone(), inner_else.clone())
    };

    // Combine: outer_cond && final_cond. If both sides are
    // identical AND known-boolean / side-effect-free, collapse to
    // a single copy so the recovered code reads `if (c) { ... }`
    // instead of `if (c && c) { ... }`. We DO NOT call the full
    // `Expr::simplify` here — codex review on PR #33 pass 3 noted
    // it would apply other algebraic folds (e.g. `x - x = 0`) that
    // are not side-effect safe in this expression-tree position
    // and could drop calls from conditions like `f() - f()`. The
    // targeted dedup is the only collapse we need.
    let combined = combine_with_dedup(outer_cond.clone(), final_cond);

    Some((combined, final_body, final_else))
}

fn combine_with_dedup(left: Expr, right: Expr) -> Expr {
    if expressions_dedup_safe(&left, &right) {
        return left;
    }
    Expr::binop(BinOpKind::LogicalAnd, left, right)
}

/// Whether `left` and `right` are structurally identical AND it is
/// semantics-preserving to drop one copy (boolean-typed, no
/// side effects, no memory reads).
fn expressions_dedup_safe(left: &Expr, right: &Expr) -> bool {
    if !exprs_are_equal(left, right) {
        return false;
    }
    is_boolean_dedup_safe(left)
}

/// Mirror of `expression::expr_is_safe_to_deduplicate` PLUS the
/// boolean-result requirement, scoped to short-circuit chaining.
fn is_boolean_dedup_safe(expr: &Expr) -> bool {
    use super::expression::UnaryOpKind;

    let bool_typed = matches!(
        &expr.kind,
        ExprKind::BinOp { op, .. } if op.is_comparison()
            || matches!(op, BinOpKind::LogicalAnd | BinOpKind::LogicalOr)
    ) || matches!(
        &expr.kind,
        ExprKind::UnaryOp {
            op: UnaryOpKind::LogicalNot,
            ..
        }
    );
    if !bool_typed {
        return false;
    }

    fn no_side_effects(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call { .. }
            | ExprKind::Assign { .. }
            | ExprKind::CompoundAssign { .. }
            | ExprKind::Deref { .. }
            | ExprKind::ArrayAccess { .. }
            | ExprKind::FieldAccess { .. } => false,
            ExprKind::GotRef { is_deref, .. } => !*is_deref,
            ExprKind::BinOp { left, right, .. } => no_side_effects(left) && no_side_effects(right),
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => no_side_effects(operand),
            ExprKind::AddressOf(inner) => no_side_effects(inner),
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => no_side_effects(cond) && no_side_effects(then_expr) && no_side_effects(else_expr),
            ExprKind::Phi(args) => args.iter().all(no_side_effects),
            ExprKind::IntLit(_) | ExprKind::Var(_) | ExprKind::Unknown(_) => true,
        }
    }
    no_side_effects(expr)
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

/// Collapse a redundant duplicate-condition guard:
///   `if (c) {} else { if (c) {} else { body } }` → `if (c) {} else { body }`
///
/// Returns the new `else_body` (the inner if's else) when the pattern matches,
/// or `None` otherwise. The caller keeps the outer condition and (empty) then.
///
/// ## Why this is sound
///
/// The two conditions are structurally equal, the outer then is empty, and the
/// inner `if` is the SOLE content of the outer else (no statements before it).
/// So there is literally no code between the two evaluations of `c` — control
/// reaches the inner `if (c)` only along the outer's `else` edge (c false), and
/// nothing has run that could change `c`. The inner test is therefore always
/// false and its else body always executes; the inner guard is dead.
///
/// ## Why this fires on the ucomisd parity idiom
///
/// For `if (b == 0.0)` clang at `-O0` emits `ucomisd; jne X; jp X` — two
/// conditional branches to the same target X so NaN follows C's `==` semantics
/// (NaN compares unequal). The structurer lifts each branch into its own
/// empty-then `if` on the same recovered comparison (`b != 0.0`), nesting the
/// second in the first's else. Collapsing yields a single guard, so the emitter
/// renders the clean `if (b == 0.0) { ... } else { ... }`.
///
/// ## Re-evaluation safety
///
/// We require `c` to be free of calls and assignments (`expr_safe_to_reevaluate`).
/// A plain comparison of a (possibly memory-loaded) value against a constant is
/// idempotent given the no-intervening-code guarantee above; a call or
/// assignment in the condition would not be, so those are rejected.
fn try_collapse_duplicate_empty_then_guard(
    condition: &Expr,
    then_body: &[StructuredNode],
    else_body: &Option<Vec<StructuredNode>>,
) -> Option<Option<Vec<StructuredNode>>> {
    // Outer then must carry no statements (only empty blocks allowed).
    if !then_body.iter().all(is_empty_block_node) {
        return None;
    }
    if !expr_safe_to_reevaluate(condition) {
        return None;
    }

    let else_nodes = else_body.as_ref()?;
    let (inner_if, prefix, suffix) = extract_single_if(else_nodes)?;
    // The inner if must be the SOLE content of the outer else — no statements
    // before or after it, or there would be intervening code between the two
    // condition evaluations.
    if !prefix.is_empty() || !suffix.is_empty() {
        return None;
    }

    let StructuredNode::If {
        condition: inner_cond,
        then_body: inner_then,
        else_body: inner_else,
    } = inner_if
    else {
        return None;
    };
    if !inner_then.iter().all(is_empty_block_node) {
        return None;
    }
    if !exprs_are_equal(condition, &inner_cond) {
        return None;
    }

    // Drop the redundant inner guard: keep the outer (empty) then and splice
    // the inner else up to be the outer else.
    Some(inner_else)
}

/// Whether a structured node carries no statements (an empty `Block`).
fn is_empty_block_node(node: &StructuredNode) -> bool {
    matches!(node, StructuredNode::Block { statements, .. } if statements.is_empty())
}

/// Whether `expr` can be evaluated twice with the same result GIVEN no
/// intervening code mutates state. It must contain no function call and no
/// assignment, AND any memory read must be a STACK-FRAME access (rsp/rbp/x29
/// -relative). Heap/global/volatile/MMIO reads are rejected — even with no
/// intervening structured statements, externally-mutable memory could change
/// between the two evaluations, so the rest of this module treats those as
/// unsafe to deduplicate (codex review on PR #39 pass 1). Stack-frame slots
/// (the parity idiom's spilled compare operand) are the function's own frame
/// and provably stable across the two adjacent branch tests.
fn expr_safe_to_reevaluate(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Call { .. } | ExprKind::Assign { .. } | ExprKind::CompoundAssign { .. } => false,
        ExprKind::BinOp { left, right, .. } => {
            expr_safe_to_reevaluate(left) && expr_safe_to_reevaluate(right)
        }
        // `++x` / `--x` mutate their operand, so re-evaluation is not
        // idempotent — reject like assignments. Codex review on PR #39
        // pass 2.
        ExprKind::UnaryOp {
            op: UnaryOpKind::Inc | UnaryOpKind::Dec,
            ..
        } => false,
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_safe_to_reevaluate(operand),
        // Memory reads: only safe when the access is a PROVEN fixed
        // stack-frame slot (`[rbp-16]`, `rsp[-3]`). A variable offset
        // (`rbp + rax`) or variable index could escape the frame or hit
        // externally-mutable memory — reject. Codex review on PR #39
        // pass 3.
        ExprKind::Deref { addr, .. } => expr_is_fixed_stack_frame_address(addr),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_is_fixed_stack_frame_address(base)
                && matches!(index.kind, ExprKind::IntLit(_))
        }
        ExprKind::FieldAccess { base, .. } => expr_is_fixed_stack_frame_address(base),
        ExprKind::AddressOf(inner) => expr_safe_to_reevaluate(inner),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_safe_to_reevaluate(cond)
                && expr_safe_to_reevaluate(then_expr)
                && expr_safe_to_reevaluate(else_expr)
        }
        ExprKind::Phi(args) => args.iter().all(expr_safe_to_reevaluate),
        // A non-dereferencing GotRef is an address constant (safe); a
        // dereferencing one is a global memory load (reject).
        ExprKind::GotRef { is_deref, .. } => !*is_deref,
        ExprKind::IntLit(_) | ExprKind::Var(_) | ExprKind::Unknown(_) => true,
    }
}

/// Whether `addr` is a PROVEN fixed stack-frame slot address — the bare frame
/// register, or `base ± <constant>`. A constant offset keeps the access
/// pinned to the function's own frame (not externally mutable across two
/// adjacent branch tests); a variable offset (`rbp + rax`) could escape the
/// frame or hit volatile/shared memory, so it is rejected. Codex review on
/// PR #39 pass 3.
fn expr_is_fixed_stack_frame_address(addr: &Expr) -> bool {
    match &addr.kind {
        ExprKind::Var(v) => is_stack_base_register_name(&v.name),
        ExprKind::Unknown(name) => is_stack_base_register_name(name),
        ExprKind::Cast { expr: inner, .. } => expr_is_fixed_stack_frame_address(inner),
        // `base ± constant` — exactly one operand is the frame base and the
        // other is an integer literal. For `Sub` the base must be the left
        // operand (`base - k`, never `k - base`).
        ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } => {
            (expr_is_fixed_stack_frame_address(left) && matches!(right.kind, ExprKind::IntLit(_)))
                || (expr_is_fixed_stack_frame_address(right)
                    && matches!(left.kind, ExprKind::IntLit(_)))
        }
        ExprKind::BinOp {
            op: BinOpKind::Sub,
            left,
            right,
        } => {
            expr_is_fixed_stack_frame_address(left) && matches!(right.kind, ExprKind::IntLit(_))
        }
        _ => false,
    }
}

fn is_stack_base_register_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "rsp" | "esp" | "sp" | "rbp" | "ebp" | "bp" | "x29" | "fp" | "x31"
    )
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
        (ExprKind::Unknown(s1), ExprKind::Unknown(s2)) => s1 == s2,
        (
            ExprKind::ArrayAccess {
                base: b1,
                index: i1,
                element_size: e1,
            },
            ExprKind::ArrayAccess {
                base: b2,
                index: i2,
                element_size: e2,
            },
        ) => e1 == e2 && exprs_are_equal(b1, b2) && exprs_are_equal(i1, i2),
        (
            ExprKind::FieldAccess {
                base: b1,
                offset: o1,
                ..
            },
            ExprKind::FieldAccess {
                base: b2,
                offset: o2,
                ..
            },
        ) => o1 == o2 && exprs_are_equal(b1, b2),
        (
            ExprKind::Cast {
                expr: e1,
                to_size: s1,
                signed: sg1,
            },
            ExprKind::Cast {
                expr: e2,
                to_size: s2,
                signed: sg2,
            },
        ) => s1 == s2 && sg1 == sg2 && exprs_are_equal(e1, e2),
        (ExprKind::AddressOf(e1), ExprKind::AddressOf(e2)) => exprs_are_equal(e1, e2),
        (
            ExprKind::GotRef {
                address: a1,
                size: s1,
                is_deref: d1,
                ..
            },
            ExprKind::GotRef {
                address: a2,
                size: s2,
                is_deref: d2,
                ..
            },
        ) => a1 == a2 && s1 == s2 && d1 == d2,
        _ => false,
    }
}

/// Check if two call targets are equal.
fn call_targets_equal(a: &CallTarget, b: &CallTarget) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::Variable;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable::reg(name, 4))
    }

    fn make_condition(name: &str) -> Expr {
        Expr::binop(BinOpKind::Ne, make_var(name), Expr::int(0))
    }

    /// Helper: `mem[off] != 0` — the lifted shape of the ucomisd
    /// parity-idiom condition (a stack-slot float compared to zero).
    fn mem_ne_zero() -> Expr {
        Expr::binop(
            BinOpKind::Ne,
            Expr::array_access(make_var("rsp"), Expr::int(-3), 8),
            Expr::int(0),
        )
    }

    /// gap-2 ucomisd parity coalescer: the structured form of
    /// `ucomisd; jne X; jp X` is
    ///   `if (c) {} else { if (c) {} else { body } }`
    /// with both `c` structurally identical and no intervening code.
    /// Collapses to `if (c) {} else { body }`.
    #[test]
    fn test_collapse_duplicate_empty_then_guard() {
        let body = vec![StructuredNode::Return(Some(Expr::int(0)))];
        let inner = StructuredNode::If {
            condition: mem_ne_zero(),
            then_body: vec![],
            else_body: Some(body.clone()),
        };
        let outer = StructuredNode::If {
            condition: mem_ne_zero(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };

        let result = detect_short_circuit(vec![outer]);
        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                assert!(then_body.is_empty(), "outer then stays empty");
                let else_nodes = else_body.as_ref().expect("else preserved");
                // The inner duplicate guard is gone — the else is the body
                // directly, no nested If.
                assert!(
                    !else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "inner duplicate If must be collapsed, got {else_nodes:?}",
                );
                assert!(
                    else_nodes
                        .iter()
                        .any(|n| matches!(n, StructuredNode::Return(_))),
                    "body must survive in the else",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// A 3-deep duplicate-guard nest collapses fully (bottom-up).
    #[test]
    fn test_collapse_triple_duplicate_empty_then_guard() {
        let body = vec![StructuredNode::Return(Some(Expr::int(0)))];
        let mut node = StructuredNode::If {
            condition: mem_ne_zero(),
            then_body: vec![],
            else_body: Some(body),
        };
        for _ in 0..2 {
            node = StructuredNode::If {
                condition: mem_ne_zero(),
                then_body: vec![],
                else_body: Some(vec![node]),
            };
        }
        let result = detect_short_circuit(vec![node]);
        // Count nested Ifs remaining — should be exactly 1.
        fn count_ifs(nodes: &[StructuredNode]) -> usize {
            nodes
                .iter()
                .map(|n| match n {
                    StructuredNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        1 + count_ifs(then_body)
                            + else_body.as_ref().map_or(0, |e| count_ifs(e))
                    }
                    _ => 0,
                })
                .sum()
        }
        assert_eq!(count_ifs(&result), 1, "all duplicate guards collapse to one");
    }

    /// The collapse must NOT fire when the conditions differ.
    #[test]
    fn test_collapse_skips_distinct_conditions() {
        let inner = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        // Both Ifs remain (different conditions).
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "distinct-condition inner If must be preserved",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// The collapse must NOT fire when the outer then is non-empty
    /// (there's a real branch body, not the empty parity guard).
    #[test]
    fn test_collapse_skips_nonempty_then() {
        let inner = StructuredNode::If {
            condition: mem_ne_zero(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: mem_ne_zero(),
            then_body: vec![StructuredNode::Expr(Expr::unknown("side_effect"))],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                assert!(!then_body.is_empty(), "non-empty then preserved");
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "inner If must be preserved when outer then is non-empty",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// Codex review on PR #39 pass 3: a stack-frame read with a
    /// VARIABLE offset (`rbp[rax]`, `*(rsp + rcx)`) is not a proven
    /// fixed slot — it could escape the frame — so the collapse must
    /// NOT fire. Only fixed-offset slots (`*(rbp-16)`, `rsp[-3]`)
    /// qualify.
    #[test]
    fn test_collapse_skips_variable_offset_stack_read() {
        // *(rbp + rax) != 0 — variable offset.
        let var_off_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::deref(
                    Expr::binop(BinOpKind::Add, make_var("rbp"), make_var("rax")),
                    8,
                ),
                Expr::int(0),
            )
        };
        let inner = StructuredNode::If {
            condition: var_off_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: var_off_cond(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "variable-offset stack read must NOT collapse (not a proven fixed slot)",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }

        // rbp[rax] (variable index ArrayAccess) — also rejected.
        let var_idx_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::array_access(make_var("rbp"), make_var("rax"), 8),
                Expr::int(0),
            )
        };
        let inner2 = StructuredNode::If {
            condition: var_idx_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer2 = StructuredNode::If {
            condition: var_idx_cond(),
            then_body: vec![],
            else_body: Some(vec![inner2]),
        };
        let result2 = detect_short_circuit(vec![outer2]);
        match &result2[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "variable-index stack ArrayAccess must NOT collapse",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// Codex review on PR #39 pass 2: the collapse must NOT fire when
    /// the condition contains a side-effecting `++`/`--` — the first
    /// (false) evaluation mutates the operand, so the inner guard is
    /// NOT redundant.
    #[test]
    fn test_collapse_skips_increment_condition() {
        let inc_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::unary(UnaryOpKind::Inc, make_var("i")),
                Expr::int(0),
            )
        };
        let inner = StructuredNode::If {
            condition: inc_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: inc_cond(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "++i condition must NOT collapse (mutates operand)",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// Codex review on PR #39 pass 1: the collapse must NOT fire when
    /// the condition reads NON-stack memory (heap/global/volatile/MMIO)
    /// — that memory could change between the two evaluations even with
    /// no intervening structured code. Here `*rdi != 0` (a deref of an
    /// arbitrary pointer arg) must be preserved.
    #[test]
    fn test_collapse_skips_non_stack_memory_condition() {
        let heap_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::deref(make_var("rdi"), 8),
                Expr::int(0),
            )
        };
        let inner = StructuredNode::If {
            condition: heap_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: heap_cond(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "non-stack memory deref condition must NOT collapse (could be volatile)",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// The collapse STILL fires for a stack-frame memory read (the
    /// parity idiom's spilled compare operand `[rbp-N]`), since the
    /// frame is not externally mutable.
    #[test]
    fn test_collapse_fires_for_stack_frame_deref_condition() {
        let stack_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::deref(
                    Expr::binop(BinOpKind::Sub, make_var("rbp"), Expr::int(16)),
                    8,
                ),
                Expr::int(0),
            )
        };
        let inner = StructuredNode::If {
            condition: stack_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: stack_cond(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    !else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "stack-frame deref condition SHOULD collapse, got {else_nodes:?}",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// The collapse must NOT fire when the condition contains a call
    /// (re-evaluation could differ).
    #[test]
    fn test_collapse_skips_call_condition() {
        let call_cond = || {
            Expr::binop(
                BinOpKind::Ne,
                Expr::call(CallTarget::Named("f".to_string()), vec![]),
                Expr::int(0),
            )
        };
        let inner = StructuredNode::If {
            condition: call_cond(),
            then_body: vec![],
            else_body: Some(vec![StructuredNode::Return(None)]),
        };
        let outer = StructuredNode::If {
            condition: call_cond(),
            then_body: vec![],
            else_body: Some(vec![inner]),
        };
        let result = detect_short_circuit(vec![outer]);
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                let else_nodes = else_body.as_ref().unwrap();
                assert!(
                    else_nodes.iter().any(|n| matches!(n, StructuredNode::If { .. })),
                    "call-condition inner If must be preserved (re-eval unsafe)",
                );
            }
            other => panic!("expected If, got {other:?}"),
        }
    }

    /// Codex review on PR #33 pass 3: the chain combine must not
    /// run the general-purpose `Expr::simplify`, because algebraic
    /// folds like `x - x = 0` would drop call sub-expressions.
    /// Verify that an effectful condition `f() - f()` survives the
    /// AND-chain combine intact.
    #[test]
    fn test_and_chain_does_not_drop_side_effects_in_conditions() {
        let f_call = || Expr::call(CallTarget::Named("f".to_string()), vec![]);
        let effectful_cond = || Expr::binop(BinOpKind::Sub, f_call(), f_call());

        let inner_if = StructuredNode::If {
            condition: effectful_cond(),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: effectful_cond(),
            then_body: vec![inner_if],
            else_body: None,
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        match &result[0] {
            StructuredNode::If { condition, .. } => match &condition.kind {
                ExprKind::BinOp {
                    op: BinOpKind::LogicalAnd,
                    left,
                    right,
                } => {
                    // Each side must STILL be a `BinOp::Sub` of two
                    // Calls. If `Expr::simplify` had run, the `x - x`
                    // fold would have collapsed each to `IntLit(0)`,
                    // silently dropping the calls.
                    for side in [&**left, &**right] {
                        match &side.kind {
                            ExprKind::BinOp { op: BinOpKind::Sub, .. } => {}
                            _ => panic!(
                                "expected each AND operand to remain `f() - f()`, got {:?}",
                                side.kind
                            ),
                        }
                    }
                }
                other => panic!("expected LogicalAnd, got {:?}", other),
            },
            _ => panic!("expected If node"),
        }
    }

    #[test]
    fn test_and_chain_detection() {
        // Create: if (a) { if (b) { return 1; } }
        // Use distinct comparison-shaped conditions so that the
        // simplify() pass on the combined LogicalAnd does not
        // constant-fold them (which would happen with IntLit
        // operands via fold_binary_constants).
        let inner_if = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![inner_if],
            else_body: None,
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        // Should be transformed to: if (a && b) { return 1; }
        match &result[0] {
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Check condition is AND
                match &condition.kind {
                    ExprKind::BinOp { op, .. } => {
                        assert_eq!(*op, BinOpKind::LogicalAnd);
                    }
                    _ => panic!("Expected AND condition"),
                }
                assert_eq!(then_body.len(), 1);
                assert!(else_body.is_none());
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_triple_and_chain() {
        // Create: if (a) { if (b) { if (c) { return 1; } } }
        // Should become: if (a && b && c) { return 1; }
        let inner_most = StructuredNode::If {
            condition: make_condition("c"),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: None,
        };
        let middle_if = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![inner_most],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![middle_if],
            else_body: None,
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        // Should be transformed - check it's a nested AND
        match &result[0] {
            StructuredNode::If { condition, .. } => {
                // Should be (a && (b && c))
                if let ExprKind::BinOp { op, right, .. } = &condition.kind {
                    assert_eq!(*op, BinOpKind::LogicalAnd);
                    // Right side should also be AND
                    if let ExprKind::BinOp { op: inner_op, .. } = &right.kind {
                        assert_eq!(*inner_op, BinOpKind::LogicalAnd);
                    } else {
                        panic!("Expected nested AND");
                    }
                } else {
                    panic!("Expected AND condition");
                }
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_or_chain_detection() {
        // Create: if (a) { return 1; } else { if (b) { return 1; } }
        // Should become: if (a || b) { return 1; }
        let return_stmt = StructuredNode::Return(Some(Expr::int(1)));

        let inner_if = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![return_stmt.clone()],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![return_stmt],
            else_body: Some(vec![inner_if]),
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        // Should be transformed to: if (a || b) { return 1; }
        match &result[0] {
            StructuredNode::If {
                condition,
                else_body,
                ..
            } => {
                // Check condition is OR
                match &condition.kind {
                    ExprKind::BinOp { op, .. } => {
                        assert_eq!(*op, BinOpKind::LogicalOr);
                    }
                    _ => panic!("Expected OR condition"),
                }
                // Else should be removed
                assert!(else_body.is_none());
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_no_transform_with_side_effects() {
        // Create: if (a) { x = 1; if (b) { return 1; } }
        // Should NOT be transformed because of side effect before inner if
        let inner_if = StructuredNode::If {
            condition: Expr::int(1),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: Expr::int(2),
            then_body: vec![
                StructuredNode::Expr(Expr::int(42)), // side effect
                inner_if,
            ],
            else_body: None,
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        // Should NOT be transformed - inner body should still have 2 elements
        match &result[0] {
            StructuredNode::If { then_body, .. } => {
                assert_eq!(then_body.len(), 2);
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_no_transform_different_bodies() {
        // Create: if (a) { return 1; } else { if (b) { return 2; } }
        // Should NOT be transformed because bodies are different
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: Some(vec![StructuredNode::If {
                condition: make_condition("b"),
                then_body: vec![StructuredNode::Return(Some(Expr::int(2)))], // Different!
                else_body: None,
            }]),
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        // Should NOT be transformed - else body should still exist
        match &result[0] {
            StructuredNode::If { else_body, .. } => {
                assert!(else_body.is_some());
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_nested_in_while_loop() {
        // Create: while (x) { if (a) { if (b) { break; } } }
        let inner_if = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![StructuredNode::Break],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![inner_if],
            else_body: None,
        };
        let while_loop = StructuredNode::While {
            condition: make_condition("x"),
            body: vec![outer_if],
            header: None,
            exit_block: None,
        };

        let result = detect_short_circuit(vec![while_loop]);
        assert_eq!(result.len(), 1);

        // Check the while loop contains a transformed if
        match &result[0] {
            StructuredNode::While { body, .. } => {
                assert_eq!(body.len(), 1);
                match &body[0] {
                    StructuredNode::If { condition, .. } => {
                        // Should be AND condition
                        match &condition.kind {
                            ExprKind::BinOp { op, .. } => {
                                assert_eq!(*op, BinOpKind::LogicalAnd);
                            }
                            _ => panic!("Expected AND condition inside while"),
                        }
                    }
                    _ => panic!("Expected If inside while"),
                }
            }
            _ => panic!("Expected While node"),
        }
    }

    #[test]
    fn test_if_with_else_preserved() {
        // Create: if (a) { if (b) { return 1; } else { return 2; } }
        // Should transform to: if (a && b) { return 1; } else { return 2; }
        let inner_if = StructuredNode::If {
            condition: make_condition("b"),
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: Some(vec![StructuredNode::Return(Some(Expr::int(2)))]),
        };
        let outer_if = StructuredNode::If {
            condition: make_condition("a"),
            then_body: vec![inner_if],
            else_body: None,
        };

        let result = detect_short_circuit(vec![outer_if]);
        assert_eq!(result.len(), 1);

        match &result[0] {
            StructuredNode::If {
                condition,
                else_body,
                ..
            } => {
                // Check condition is AND
                match &condition.kind {
                    ExprKind::BinOp { op, .. } => {
                        assert_eq!(*op, BinOpKind::LogicalAnd);
                    }
                    _ => panic!("Expected AND condition"),
                }
                // Else body should be preserved
                assert!(else_body.is_some());
            }
            _ => panic!("Expected If node"),
        }
    }

    #[test]
    fn test_exprs_are_equal() {
        let a = make_var("x");
        let b = make_var("x");
        let c = make_var("y");

        assert!(exprs_are_equal(&a, &b));
        assert!(!exprs_are_equal(&a, &c));

        // Test binary ops
        let binop1 = Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(1));
        let binop2 = Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(1));
        let binop3 = Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(2));

        assert!(exprs_are_equal(&binop1, &binop2));
        assert!(!exprs_are_equal(&binop1, &binop3));
    }

    #[test]
    fn test_nodes_are_equal() {
        let ret1 = StructuredNode::Return(Some(Expr::int(42)));
        let ret2 = StructuredNode::Return(Some(Expr::int(42)));
        let ret3 = StructuredNode::Return(Some(Expr::int(99)));
        let ret_none = StructuredNode::Return(None);

        assert!(nodes_are_equal(&ret1, &ret2));
        assert!(!nodes_are_equal(&ret1, &ret3));
        assert!(!nodes_are_equal(&ret1, &ret_none));

        assert!(nodes_are_equal(
            &StructuredNode::Break,
            &StructuredNode::Break
        ));
        assert!(!nodes_are_equal(
            &StructuredNode::Break,
            &StructuredNode::Continue
        ));
    }
}
