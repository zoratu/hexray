//! Post-reduction simplification + variable / argument propagation
//! passes.
//!
//! These run after the basic CFG-to-tree reduction but before goto
//! cleanup ([`super::cleanup`]). Each transforms a
//! `Vec<StructuredNode>` in place semantics-preserving ways, with the
//! goal of recovering high-level idioms hidden by the SSA-style
//! intermediate form.
//!
//! Composed in order by the structurer driver in
//! [`super::Structurer::structurize`]:
//!
//! 1. `simplify_statements` — drop unreachable code after a return
//!    in the same block; collapse single-statement blocks.
//! 2. `simplify_conditions_in_node` — fold `!(a == b)` into
//!    `a != b`, `if (cond) { return x; } return y;` into ternary,
//!    etc.
//! 3. `remove_temp_assignments` — drop `tmp = expr;` when `tmp` is
//!    never read.
//! 4. `propagate_temps_to_conditions` — substitute `tmp = expr;
//!    if (tmp) { ... }` into `if (expr) { ... }`.
//! 5. `simplify_node_copies` (called per-node) — propagate
//!    `dst = src;` into subsequent uses of `dst` if `src` isn't
//!    overwritten.
//! 6. `propagate_call_args` — walk `arg_reg = expr; arg_reg = …;
//!    foo(arg_reg, …)` patterns and inline the argument expressions
//!    at the call site.
//! 7. `merge_return_value_captures` — collapse `tmp = call(); use(tmp)`
//!    chains where `tmp` is only consumed once.
//! 8. `substitute_globals_in_node` — replace `*&G` (LEA-then-load
//!    of a global) with `G` directly.
//!
//! Most of the per-pass entry points are `pub(super)`; the helper
//! functions stay private to this module.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use hexray_core::Architecture;
use hexray_types::{
    builtin::{load_libc_functions, load_linux_types, load_posix_types},
    TypeDatabase,
};

use super::super::abi::{
    get_arg_register_index, is_argument_register, is_callee_saved_or_renamed, is_return_register,
    is_temp_register,
};
use super::super::dead_store::collect_all_uses;
use super::super::expression::{BinOpKind, CallTarget, Expr, ExprKind, Variable};
use super::super::BinaryDataContext;
use super::{CatchHandler, StructuredNode};

/// Extracts the return value from a return register assignment near the end of the block.
/// Returns the filtered statements (without the return value assignment) and the return value.
/// Looks backwards through statements to find the last assignment to a return register,
/// skipping over prologue/epilogue statements like pop(rbp).
pub(super) fn extract_return_value(statements: Vec<Expr>) -> (Vec<Expr>, Option<Expr>) {
    use super::super::expression::ExprKind;

    // First pass: build a map of temp register values for substitution
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut substituted_assignments: HashMap<usize, Expr> = HashMap::new();
    for (stmt_idx, stmt) in statements.iter().enumerate() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if is_temp_register(&v.name)
                    || is_return_register(&v.name)
                    || is_argument_register(&v.name)
                {
                    // Substitute known values in RHS before storing
                    let substituted_rhs = substitute_vars(rhs, &reg_values);
                    substituted_assignments.insert(stmt_idx, substituted_rhs.clone());
                    invalidate_clobbered_register_mappings(&mut reg_values, &v.name);
                    if expr_requires_single_evaluation(&substituted_rhs)
                        && !expr_is_pure_stack_slot_expression(&substituted_rhs)
                    {
                        reg_values.remove(&v.name);
                    } else {
                        reg_values.insert(v.name.clone(), substituted_rhs);
                    }
                }
            }
        }
    }

    let mut return_value = None;
    let mut indices_to_remove = Vec::new();
    let mut saw_real_call_after = false;
    let mut saw_stack_canary_after = false;

    // Search backwards for an assignment to a return register, collecting epilogue statements
    for i in (0..statements.len()).rev() {
        let stmt = &statements[i];
        if expr_mentions_stack_canary_guard(stmt) {
            saw_stack_canary_after = true;
        }

        // Check for return register assignment
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                // Check if this is assigning to a return register
                // x86: eax (32-bit), rax (64-bit)
                // ARM64: w0 (32-bit), x0 (64-bit)
                // RISC-V: a0
                let is_return_reg = matches!(
                    v.name.as_str(),
                    "eax" | "rax" | "w0" | "x0" | "a0" | "xmm0" | "ymm0" | "zmm0"
                );
                if is_return_reg {
                    if saw_real_call_after {
                        continue;
                    }
                    // Use the fully substituted value from reg_values if available,
                    // otherwise substitute the RHS directly
                    return_value = Some(
                        substituted_assignments
                            .get(&i)
                            .cloned()
                            .or_else(|| reg_values.get(&v.name).cloned())
                            .unwrap_or_else(|| substitute_vars(rhs, &reg_values)),
                    );
                    indices_to_remove.push(i);
                    break;
                }

                if saw_stack_canary_after {
                    indices_to_remove.push(i);
                    continue;
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

                // Callee-saved register restore near the end of the block.
                if is_callee_saved_or_renamed(&v.name) {
                    indices_to_remove.push(i);
                    continue;
                }

                // Skip other temp register assignments only when they're plain data shuffles.
                // Side-effecting RHS expressions (e.g. lifted atomic ops) must survive.
                if is_temp_register(&v.name) {
                    if !expr_has_side_effects_from_assignment(stmt) {
                        indices_to_remove.push(i);
                        continue;
                    }
                }
            }
        }

        // Compound updates to the return register still leave the final value
        // live in-place, so keep the statement and return the updated register.
        if let ExprKind::CompoundAssign { lhs, .. } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                let is_return_reg = matches!(
                    v.name.as_str(),
                    "eax" | "rax" | "w0" | "x0" | "a0" | "xmm0" | "ymm0" | "zmm0"
                );
                if is_return_reg {
                    if saw_real_call_after {
                        continue;
                    }
                    return_value = Some((**lhs).clone());
                    break;
                }
            }
        }

        if statement_contains_real_call(stmt) {
            saw_real_call_after = true;
            continue;
        }

        // x86 epilogue: push/pop calls
        if let ExprKind::Call {
            target: super::super::expression::CallTarget::Named(name),
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

fn expr_mentions_stack_canary_guard(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(v) => v.name.contains("stack_chk_guard"),
        ExprKind::Unknown(name) => name.contains("stack_chk_guard"),
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_mentions_stack_canary_guard(left) || expr_mentions_stack_canary_guard(right),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_mentions_stack_canary_guard(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_mentions_stack_canary_guard(base) || expr_mentions_stack_canary_guard(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_mentions_stack_canary_guard(base),
        ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
            args.iter().any(expr_mentions_stack_canary_guard)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_mentions_stack_canary_guard(cond)
                || expr_mentions_stack_canary_guard(then_expr)
                || expr_mentions_stack_canary_guard(else_expr)
        }
        ExprKind::GotRef { display_expr, .. } => expr_mentions_stack_canary_guard(display_expr),
        ExprKind::IntLit(_) => false,
    }
}

/// Simplifies statements by performing copy propagation on temporary registers.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
pub(super) fn simplify_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let nodes = merge_adjacent_blocks(nodes);

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

    // Fifth pass: when a condition reconstructs an arithmetic expression that was
    // already saved in the preheader, reuse the saved value so the local stays live.
    let nodes = reuse_saved_condition_values(nodes);

    // Sixth pass: remove temp register assignments that have been propagated.
    let nodes = remove_temp_assignments(nodes);

    // Seventh pass: prune dead register artifacts that only exist to shuttle
    // machine state between adjacent lowered blocks.
    let nodes = prune_dead_register_artifacts(nodes);

    // Eighth pass: simplify all conditions (convert | to ||, & to && for comparisons, etc.)
    nodes.into_iter().map(simplify_conditions_in_node).collect()
}

#[derive(Debug, Clone)]
struct SavedConditionValue {
    var: Variable,
    rhs: Expr,
}

fn prune_dead_register_artifacts(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    prune_dead_register_artifacts_in_list(nodes, HashSet::new()).0
}

fn prune_dead_register_artifacts_in_loop_body(
    body: Vec<StructuredNode>,
    loop_live_after: HashSet<String>,
) -> (Vec<StructuredNode>, HashSet<String>) {
    let original_body = body;
    let mut seed = loop_live_after;

    loop {
        let (pruned_body, body_live_in) =
            prune_dead_register_artifacts_in_list(original_body.clone(), seed.clone());
        let mut next_seed = seed.clone();
        next_seed.extend(body_live_in.iter().cloned());
        if next_seed == seed {
            return (pruned_body, body_live_in);
        }
        seed = next_seed;
    }
}

fn prune_dead_register_artifacts_in_list(
    nodes: Vec<StructuredNode>,
    live_after: HashSet<String>,
) -> (Vec<StructuredNode>, HashSet<String>) {
    let mut live = live_after;
    let mut pruned = Vec::with_capacity(nodes.len());

    for node in nodes.into_iter().rev() {
        let (node, live_before) = prune_dead_register_artifacts_in_node(node, &live);
        live = live_before;
        pruned.push(node);
    }

    pruned.reverse();
    (pruned, live)
}

fn prune_dead_register_artifacts_in_node(
    node: StructuredNode,
    live_after: &HashSet<String>,
) -> (StructuredNode, HashSet<String>) {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let (statements, live_before) =
                prune_dead_register_artifacts_in_block(statements, live_after.clone());
            (
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                },
                live_before,
            )
        }
        StructuredNode::Expr(expr) => {
            let (mut statements, live_before) =
                prune_dead_register_artifacts_in_block(vec![expr], live_after.clone());
            let expr = statements
                .pop()
                .unwrap_or_else(|| Expr::unknown("/* nop */"));
            (StructuredNode::Expr(expr), live_before)
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let (then_body, then_live_in) =
                prune_dead_register_artifacts_in_list(then_body, live_after.clone());
            let (else_body, else_live_in) = if let Some(else_body) = else_body {
                let (else_body, live_in) =
                    prune_dead_register_artifacts_in_list(else_body, live_after.clone());
                (Some(else_body), live_in)
            } else {
                (None, live_after.clone())
            };

            let mut live_before = then_live_in;
            live_before.extend(else_live_in);
            collect_live_uses_in_expr(&condition, &mut live_before);

            (
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                },
                live_before,
            )
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            let mut loop_live_after = live_after.clone();
            collect_live_uses_in_expr(&condition, &mut loop_live_after);
            let (body, body_live_in) =
                prune_dead_register_artifacts_in_loop_body(body, loop_live_after.clone());

            let mut live_before = loop_live_after;
            live_before.extend(body_live_in);

            (
                StructuredNode::While {
                    condition,
                    body,
                    header,
                    exit_block,
                },
                live_before,
            )
        }
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let mut loop_live_after = live_after.clone();
            collect_live_uses_in_expr(&condition, &mut loop_live_after);
            let (body, body_live_in) =
                prune_dead_register_artifacts_in_loop_body(body, loop_live_after.clone());

            let mut live_before = loop_live_after;
            live_before.extend(body_live_in);

            (
                StructuredNode::DoWhile {
                    body,
                    condition,
                    header,
                    exit_block,
                },
                live_before,
            )
        }
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            let mut loop_live_after = live_after.clone();
            collect_live_uses_in_expr(&condition, &mut loop_live_after);
            if let Some(update) = &update {
                collect_live_uses_in_expr(update, &mut loop_live_after);
            }
            let (body, body_live_in) =
                prune_dead_register_artifacts_in_loop_body(body, loop_live_after.clone());

            let mut live_before = loop_live_after;
            live_before.extend(body_live_in);
            if let Some(init) = &init {
                collect_live_uses_in_expr(init, &mut live_before);
            }

            (
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    header,
                    exit_block,
                },
                live_before,
            )
        }
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let (body, body_live_in) =
                prune_dead_register_artifacts_in_loop_body(body, live_after.clone());
            let mut live_before = live_after.clone();
            live_before.extend(body_live_in);
            (
                StructuredNode::Loop {
                    body,
                    header,
                    exit_block,
                },
                live_before,
            )
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            let mut live_before = live_after.clone();
            collect_live_uses_in_expr(&value, &mut live_before);

            let cases = cases
                .into_iter()
                .map(|(values, body)| {
                    let (body, body_live_in) =
                        prune_dead_register_artifacts_in_list(body, live_after.clone());
                    live_before.extend(body_live_in);
                    (values, body)
                })
                .collect();
            let default = default.map(|body| {
                let (body, body_live_in) =
                    prune_dead_register_artifacts_in_list(body, live_after.clone());
                live_before.extend(body_live_in);
                body
            });

            (
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                },
                live_before,
            )
        }
        StructuredNode::Sequence(nodes) => {
            let (nodes, live_before) =
                prune_dead_register_artifacts_in_list(nodes, live_after.clone());
            (StructuredNode::Sequence(nodes), live_before)
        }
        StructuredNode::Return(Some(expr)) => {
            let mut live_before = HashSet::new();
            collect_live_uses_in_expr(&expr, &mut live_before);
            (StructuredNode::Return(Some(expr)), live_before)
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            let (try_body, try_live_in) =
                prune_dead_register_artifacts_in_list(try_body, live_after.clone());
            let mut live_before = try_live_in;
            let catch_handlers = catch_handlers
                .into_iter()
                .map(|handler| {
                    let (body, body_live_in) =
                        prune_dead_register_artifacts_in_list(handler.body, live_after.clone());
                    live_before.extend(body_live_in);
                    CatchHandler { body, ..handler }
                })
                .collect();

            (
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                },
                live_before,
            )
        }
        StructuredNode::Return(None)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_) => (node, HashSet::new()),
        StructuredNode::Label(_) => (node, live_after.clone()),
    }
}

fn prune_dead_register_artifacts_in_block(
    statements: Vec<Expr>,
    live_after: HashSet<String>,
) -> (Vec<Expr>, HashSet<String>) {
    let mut live = live_after;
    let mut pruned = Vec::with_capacity(statements.len());

    for stmt in statements.into_iter().rev() {
        if let Some(affected_aliases) = register_state_pseudo_call_aliases(&stmt) {
            if affected_aliases.iter().all(|alias| !live.contains(alias)) {
                continue;
            }
            live.extend(affected_aliases);
            pruned.push(stmt);
            continue;
        }

        if let Some(defined_aliases) = ephemeral_statement_def_aliases(&stmt) {
            if defined_aliases.iter().all(|alias| !live.contains(alias)) {
                if let Some(rewritten) = rewrite_dead_atomic_result_capture(&stmt) {
                    collect_live_uses_in_expr(&rewritten, &mut live);
                    pruned.push(rewritten);
                    continue;
                }
                if !expr_has_side_effects_from_assignment(&stmt) {
                    continue;
                }
            }
        }

        for defined_name in defined_statement_names(&stmt) {
            live.remove(&defined_name);
        }
        collect_live_uses_in_expr(&stmt, &mut live);
        pruned.push(stmt);
    }

    pruned.reverse();
    (pruned, live)
}

fn defined_statement_names(stmt: &Expr) -> Vec<String> {
    use super::super::expression::ExprKind;

    match &stmt.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
            defined_lhs_names(lhs)
        }
        _ => Vec::new(),
    }
}

fn defined_lhs_names(lhs: &Expr) -> Vec<String> {
    use super::super::expression::ExprKind;

    match &lhs.kind {
        ExprKind::Var(v) => vec![v.name.to_lowercase()],
        ExprKind::Unknown(name) => vec![name.to_lowercase()],
        _ => Vec::new(),
    }
}

fn ephemeral_statement_def_aliases(stmt: &Expr) -> Option<Vec<String>> {
    use super::super::expression::{ExprKind, VarKind};

    let ExprKind::Assign { lhs, .. } = &stmt.kind else {
        return None;
    };
    let ExprKind::Var(var) = &lhs.kind else {
        return None;
    };
    if matches!(var.kind, VarKind::Register(_) | VarKind::Arg(_)) {
        return Some(vec![var.name.to_lowercase()]);
    }
    None
}

fn register_state_pseudo_call_aliases(stmt: &Expr) -> Option<Vec<String>> {
    let ExprKind::Call { target, .. } = &stmt.kind else {
        return None;
    };
    let CallTarget::Named(name) = target else {
        return None;
    };

    let aliases = match name.as_str() {
        "cbw" | "cwde" | "cdqe" | "cbtw" | "cwtl" | "cltq" => {
            vec!["al", "ax", "eax", "rax"]
        }
        "cwd" | "cdq" | "cqo" | "cwtd" | "cltd" | "cqto" => {
            vec!["ax", "eax", "rax", "dx", "edx", "rdx"]
        }
        _ => return None,
    };

    Some(aliases.into_iter().map(str::to_string).collect())
}

fn rewrite_dead_atomic_result_capture(stmt: &Expr) -> Option<Expr> {
    let ExprKind::Assign { rhs, .. } = &stmt.kind else {
        return None;
    };
    let ExprKind::Call { target, args } = &rhs.kind else {
        return None;
    };
    let CallTarget::Named(name) = target else {
        return None;
    };

    let target = match name.as_str() {
        "atomic_exchange" => CallTarget::Named("atomic_store".to_string()),
        "atomic_fetch_add"
        | "atomic_fetch_sub"
        | "atomic_fetch_and"
        | "atomic_fetch_or"
        | "atomic_fetch_xor"
        | "atomic_compare_exchange_strong" => CallTarget::Named(name.clone()),
        _ => return None,
    };

    Some(Expr::call(target, args.clone()))
}

fn collect_live_uses_in_expr(expr: &Expr, live: &mut HashSet<String>) {
    match &expr.kind {
        ExprKind::Var(v) => {
            live.insert(v.name.to_lowercase());
        }
        ExprKind::Unknown(name) => {
            live.insert(name.to_lowercase());
        }
        ExprKind::Assign { lhs, rhs } => {
            collect_live_uses_in_lhs(lhs, live);
            collect_live_uses_in_expr(rhs, live);
        }
        ExprKind::CompoundAssign { lhs, rhs, .. } => {
            collect_live_uses_in_expr(lhs, live);
            collect_live_uses_in_expr(rhs, live);
        }
        ExprKind::BinOp { left, right, .. } => {
            collect_live_uses_in_expr(left, live);
            collect_live_uses_in_expr(right, live);
        }
        ExprKind::UnaryOp { operand, .. } => collect_live_uses_in_expr(operand, live),
        ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
            for arg in args {
                collect_live_uses_in_expr(arg, live);
            }
        }
        ExprKind::Deref { addr, .. } => collect_live_uses_in_expr(addr, live),
        ExprKind::AddressOf(inner) => collect_live_uses_in_expr(inner, live),
        ExprKind::Cast { expr, .. } => collect_live_uses_in_expr(expr, live),
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_live_uses_in_expr(base, live);
            collect_live_uses_in_expr(index, live);
        }
        ExprKind::FieldAccess { base, .. } => collect_live_uses_in_expr(base, live),
        ExprKind::BitField { expr, .. } => collect_live_uses_in_expr(expr, live),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_live_uses_in_expr(cond, live);
            collect_live_uses_in_expr(then_expr, live);
            collect_live_uses_in_expr(else_expr, live);
        }
        ExprKind::IntLit(_) | ExprKind::GotRef { .. } => {}
    }
}

fn collect_live_uses_in_lhs(lhs: &Expr, live: &mut HashSet<String>) {
    use super::super::expression::ExprKind;

    match &lhs.kind {
        ExprKind::Deref { addr, .. } => collect_live_uses_in_expr(addr, live),
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_live_uses_in_expr(base, live);
            collect_live_uses_in_expr(index, live);
        }
        ExprKind::FieldAccess { base, .. } => collect_live_uses_in_expr(base, live),
        ExprKind::BitField { expr, .. } => collect_live_uses_in_expr(expr, live),
        _ => {}
    }
}

fn expr_has_side_effects_from_assignment(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Assign { rhs, .. } => expr_has_side_effects(rhs),
        ExprKind::CompoundAssign { .. } => true,
        _ => expr_has_side_effects(expr),
    }
}

fn expr_has_side_effects(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Call { target, .. } => is_real_function_call(target),
        ExprKind::Assign { .. } | ExprKind::CompoundAssign { .. } => true,
        ExprKind::BinOp { left, right, .. } => {
            expr_has_side_effects(left) || expr_has_side_effects(right)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_has_side_effects(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_has_side_effects(base) || expr_has_side_effects(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_has_side_effects(base),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_has_side_effects(cond)
                || expr_has_side_effects(then_expr)
                || expr_has_side_effects(else_expr)
        }
        ExprKind::Phi(args) => args.iter().any(expr_has_side_effects),
        ExprKind::IntLit(_) | ExprKind::Unknown(_) | ExprKind::Var(_) | ExprKind::GotRef { .. } => {
            false
        }
    }
}

fn expr_requires_single_evaluation(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Call { target, .. } => is_real_function_call(target),
        ExprKind::Assign { .. } | ExprKind::CompoundAssign { .. } => true,
        ExprKind::Deref { .. } | ExprKind::ArrayAccess { .. } | ExprKind::FieldAccess { .. } => {
            true
        }
        ExprKind::GotRef { is_deref, .. } => *is_deref,
        ExprKind::BinOp { left, right, .. } => {
            expr_requires_single_evaluation(left) || expr_requires_single_evaluation(right)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_requires_single_evaluation(operand),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_requires_single_evaluation(cond)
                || expr_requires_single_evaluation(then_expr)
                || expr_requires_single_evaluation(else_expr)
        }
        ExprKind::Phi(args) => args.iter().any(expr_requires_single_evaluation),
        ExprKind::AddressOf(_) | ExprKind::IntLit(_) | ExprKind::Unknown(_) | ExprKind::Var(_) => {
            false
        }
    }
}

fn merge_adjacent_blocks(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut merged = Vec::new();

    for node in nodes {
        let node = match node {
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: merge_adjacent_blocks(then_body),
                else_body: else_body.map(merge_adjacent_blocks),
            },
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition,
                body: merge_adjacent_blocks(body),
                header,
                exit_block,
            },
            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: merge_adjacent_blocks(body),
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
                body: merge_adjacent_blocks(body),
                header,
                exit_block,
            },
            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: merge_adjacent_blocks(body),
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
                    .map(|(values, body)| (values, merge_adjacent_blocks(body)))
                    .collect(),
                default: default.map(merge_adjacent_blocks),
            },
            StructuredNode::Sequence(inner) => {
                StructuredNode::Sequence(merge_adjacent_blocks(inner))
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => StructuredNode::TryCatch {
                try_body: merge_adjacent_blocks(try_body),
                catch_handlers: catch_handlers
                    .into_iter()
                    .map(|handler| CatchHandler {
                        body: merge_adjacent_blocks(handler.body),
                        ..handler
                    })
                    .collect(),
            },
            other => other,
        };

        if let (
            Some(StructuredNode::Block {
                statements: prev_statements,
                address_range: prev_range,
                ..
            }),
            StructuredNode::Block {
                statements,
                address_range,
                ..
            },
        ) = (merged.last_mut(), &node)
        {
            prev_statements.extend(statements.iter().cloned());
            prev_range.1 = address_range.1;
            continue;
        }

        merged.push(node);
    }

    merged
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
pub(super) fn remove_temp_assignments(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
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
pub(super) fn remove_temp_assignments_in_node(
    node: StructuredNode,
    uses: &HashSet<String>,
) -> StructuredNode {
    use super::super::expression::ExprKind;

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
pub(super) fn propagate_temps_to_conditions(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
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
            // Collect temp values from the body, but avoid substituting loop-carried
            // induction updates back into the post-body condition.
            let mut temps = collect_temps_from_nodes(&body);
            let modified = collect_modified_vars_from_nodes(&body);
            temps.retain(|name, _| !modified.contains(name));
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

fn collect_modified_vars_from_nodes(nodes: &[StructuredNode]) -> HashSet<String> {
    let mut modified = HashSet::new();
    for node in nodes {
        collect_modified_vars_from_node(node, &mut modified);
    }
    modified
}

fn collect_modified_vars_from_node(node: &StructuredNode, modified: &mut HashSet<String>) {
    use super::super::expression::ExprKind;

    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                match &stmt.kind {
                    ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
                        if let ExprKind::Var(v) = &lhs.kind {
                            modified.insert(v.name.clone());
                        }
                    }
                    _ => {}
                }
            }
        }
        StructuredNode::Expr(expr) => {
            if let ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } = &expr.kind
            {
                if let ExprKind::Var(v) = &lhs.kind {
                    modified.insert(v.name.clone());
                }
            }
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for node in then_body {
                collect_modified_vars_from_node(node, modified);
            }
            if let Some(else_body) = else_body {
                for node in else_body {
                    collect_modified_vars_from_node(node, modified);
                }
            }
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::Loop { body, .. } => {
            for node in body {
                collect_modified_vars_from_node(node, modified);
            }
        }
        StructuredNode::For { body, .. } => {
            for node in body {
                collect_modified_vars_from_node(node, modified);
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for node in body {
                    collect_modified_vars_from_node(node, modified);
                }
            }
            if let Some(default) = default {
                for node in default {
                    collect_modified_vars_from_node(node, modified);
                }
            }
        }
        StructuredNode::Sequence(nodes) => {
            for node in nodes {
                collect_modified_vars_from_node(node, modified);
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for node in try_body {
                collect_modified_vars_from_node(node, modified);
            }
            for handler in catch_handlers {
                for node in &handler.body {
                    collect_modified_vars_from_node(node, modified);
                }
            }
        }
        _ => {}
    }
}

/// Collects temp register values from a single node.
fn collect_temps_from_node(node: &StructuredNode, temps: &mut HashMap<String, Expr>) {
    use super::super::expression::ExprKind;

    if let StructuredNode::Block { statements, .. } = node {
        for stmt in statements {
            match &stmt.kind {
                ExprKind::Assign { lhs, rhs } => {
                    if let ExprKind::Var(v) = &lhs.kind {
                        if is_temp_register(&v.name) {
                            // Substitute existing temps in the RHS
                            let rhs_substituted = substitute_vars(rhs, temps);
                            let aliases = get_register_aliases(&v.name);
                            for alias in &aliases {
                                temps.remove(alias);
                            }
                            if !expr_requires_single_evaluation(&rhs_substituted) {
                                for alias in aliases {
                                    temps.insert(alias, rhs_substituted.clone());
                                }
                            }
                        }
                    }
                }
                ExprKind::CompoundAssign { op, lhs, rhs } => {
                    // Handle x |= y as x = x | y, etc.
                    if let ExprKind::Var(v) = &lhs.kind {
                        if is_temp_register(&v.name) {
                            let aliases = get_register_aliases(&v.name);
                            let lhs_val =
                                aliases.iter().find_map(|alias| temps.get(alias).cloned());
                            let rhs_substituted = substitute_vars(rhs, temps);
                            if let Some(lhs_val) = lhs_val {
                                if expr_uses_any_alias(&lhs_val, &aliases) {
                                    for alias in aliases {
                                        temps.remove(&alias);
                                    }
                                    continue;
                                }
                                // Build the compound expression from the stabilized pre-update value.
                                let new_val = Expr::binop(*op, lhs_val, rhs_substituted).simplify();
                                if expr_requires_single_evaluation(&new_val) {
                                    for alias in aliases {
                                        temps.remove(&alias);
                                    }
                                } else {
                                    for alias in aliases {
                                        temps.insert(alias, new_val.clone());
                                    }
                                }
                            } else {
                                for alias in aliases {
                                    temps.remove(&alias);
                                }
                            }
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

fn reuse_saved_condition_values(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    reuse_saved_condition_values_in_list(nodes)
}

fn reuse_saved_condition_values_in_list(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::with_capacity(nodes.len());
    let mut saved = Vec::new();

    for node in nodes {
        let node = reuse_saved_condition_values_in_node(node, &saved);
        collect_saved_condition_values_from_node(&node, &mut saved);
        result.push(node);
    }

    result
}

fn reuse_saved_condition_values_in_node(
    node: StructuredNode,
    saved: &[SavedConditionValue],
) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: substitute_saved_condition_values(&condition, saved),
            then_body: reuse_saved_condition_values_in_list(then_body),
            else_body: else_body.map(reuse_saved_condition_values_in_list),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            let body = reuse_saved_condition_values_in_list(body);
            let reusable_saved = filter_saved_condition_values_for_loop(saved, &body);
            StructuredNode::While {
                condition: substitute_saved_condition_values(&condition, &reusable_saved),
                body,
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
            let body = reuse_saved_condition_values_in_list(body);
            let reusable_saved = filter_saved_condition_values_for_loop(saved, &body);
            StructuredNode::DoWhile {
                body,
                condition: substitute_saved_condition_values(&condition, &reusable_saved),
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
            let body = reuse_saved_condition_values_in_list(body);
            let reusable_saved = filter_saved_condition_values_for_loop(saved, &body);
            StructuredNode::For {
                init,
                condition: substitute_saved_condition_values(&condition, &reusable_saved),
                update,
                body,
                header,
                exit_block,
            }
        }
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: reuse_saved_condition_values_in_list(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: substitute_saved_condition_values(&value, saved),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, reuse_saved_condition_values_in_list(body)))
                .collect(),
            default: default.map(reuse_saved_condition_values_in_list),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(reuse_saved_condition_values_in_list(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: reuse_saved_condition_values_in_list(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: reuse_saved_condition_values_in_list(handler.body),
                    ..handler
                })
                .collect(),
        },
        other => other,
    }
}

fn filter_saved_condition_values_for_loop(
    saved: &[SavedConditionValue],
    body: &[StructuredNode],
) -> Vec<SavedConditionValue> {
    let modified = collect_modified_vars_from_nodes(body);
    saved
        .iter()
        .filter(|candidate| !modified.contains(&candidate.var.name))
        .cloned()
        .collect()
}

fn collect_saved_condition_values_from_node(
    node: &StructuredNode,
    saved: &mut Vec<SavedConditionValue>,
) {
    let statements = match node {
        StructuredNode::Block { statements, .. } => Some(statements.as_slice()),
        StructuredNode::Expr(expr) => Some(std::slice::from_ref(expr)),
        _ => None,
    };

    let Some(statements) = statements else {
        return;
    };

    for stmt in statements {
        let Some(candidate) = extract_saved_condition_value(stmt) else {
            continue;
        };
        saved.retain(|existing| existing.var.name != candidate.var.name);
        saved.push(candidate);
    }
}

fn extract_saved_condition_value(stmt: &Expr) -> Option<SavedConditionValue> {
    use super::super::expression::ExprKind;

    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
        return None;
    };
    let ExprKind::Var(var) = &lhs.kind else {
        return None;
    };
    if expr_has_side_effects(rhs) || !is_condition_reuse_candidate(rhs) {
        return None;
    }

    Some(SavedConditionValue {
        var: var.clone(),
        rhs: rhs.clone().simplify(),
    })
}

fn is_condition_reuse_candidate(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::BinOp { op, .. } => {
            !op.is_comparison() && !matches!(op, BinOpKind::LogicalAnd | BinOpKind::LogicalOr)
        }
        ExprKind::UnaryOp { .. }
        | ExprKind::Deref { .. }
        | ExprKind::AddressOf(_)
        | ExprKind::ArrayAccess { .. }
        | ExprKind::FieldAccess { .. }
        | ExprKind::Cast { .. }
        | ExprKind::BitField { .. } => true,
        ExprKind::Var(_)
        | ExprKind::IntLit(_)
        | ExprKind::GotRef { .. }
        | ExprKind::Call { .. }
        | ExprKind::Assign { .. }
        | ExprKind::CompoundAssign { .. }
        | ExprKind::Conditional { .. }
        | ExprKind::Phi(_)
        | ExprKind::Unknown(_) => false,
    }
}

fn substitute_saved_condition_values(expr: &Expr, saved: &[SavedConditionValue]) -> Expr {
    use super::super::expression::{CallTarget, ExprKind};

    if let Some(candidate) = saved
        .iter()
        .rev()
        .find(|candidate| exprs_structurally_equal(expr, &candidate.rhs))
    {
        return Expr::var(candidate.var.clone());
    }

    match &expr.kind {
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_saved_condition_values(left, saved),
            substitute_saved_condition_values(right, saved),
        ),
        ExprKind::UnaryOp { op, operand } => {
            Expr::unary(*op, substitute_saved_condition_values(operand, saved))
        }
        ExprKind::Deref { addr, size } => {
            Expr::deref(substitute_saved_condition_values(addr, saved), *size)
        }
        ExprKind::AddressOf(inner) => {
            Expr::address_of(substitute_saved_condition_values(inner, saved))
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(substitute_saved_condition_values(base, saved)),
                index: Box::new(substitute_saved_condition_values(index, saved)),
                element_size: *element_size,
            },
        },
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr {
            kind: ExprKind::FieldAccess {
                base: Box::new(substitute_saved_condition_values(base, saved)),
                field_name: field_name.clone(),
                offset: *offset,
            },
        },
        ExprKind::Call { target, args } => {
            let target = match target {
                CallTarget::Indirect(expr) => {
                    CallTarget::Indirect(Box::new(substitute_saved_condition_values(expr, saved)))
                }
                CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
                    got_address: *got_address,
                    expr: Box::new(substitute_saved_condition_values(expr, saved)),
                },
                other => other.clone(),
            };
            Expr::call(
                target,
                args.iter()
                    .map(|arg| substitute_saved_condition_values(arg, saved))
                    .collect(),
            )
        }
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_saved_condition_values(lhs, saved),
            substitute_saved_condition_values(rhs, saved),
        ),
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op: *op,
                lhs: Box::new(substitute_saved_condition_values(lhs, saved)),
                rhs: Box::new(substitute_saved_condition_values(rhs, saved)),
            },
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(substitute_saved_condition_values(cond, saved)),
                then_expr: Box::new(substitute_saved_condition_values(then_expr, saved)),
                else_expr: Box::new(substitute_saved_condition_values(else_expr, saved)),
            },
        },
        ExprKind::Cast {
            expr,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(substitute_saved_condition_values(expr, saved)),
                to_size: *to_size,
                signed: *signed,
            },
        },
        ExprKind::BitField { expr, start, width } => Expr {
            kind: ExprKind::BitField {
                expr: Box::new(substitute_saved_condition_values(expr, saved)),
                start: *start,
                width: *width,
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(
                args.iter()
                    .map(|arg| substitute_saved_condition_values(arg, saved))
                    .collect(),
            ),
        },
        ExprKind::Var(_) | ExprKind::IntLit(_) | ExprKind::GotRef { .. } | ExprKind::Unknown(_) => {
            expr.clone()
        }
    }
    .simplify()
}

fn exprs_structurally_equal(a: &Expr, b: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match (&a.kind, &b.kind) {
        (ExprKind::Var(va), ExprKind::Var(vb)) => va == vb,
        (ExprKind::IntLit(ia), ExprKind::IntLit(ib)) => ia == ib,
        (
            ExprKind::BinOp {
                op: opa,
                left: la,
                right: ra,
            },
            ExprKind::BinOp {
                op: opb,
                left: lb,
                right: rb,
            },
        ) => opa == opb && exprs_structurally_equal(la, lb) && exprs_structurally_equal(ra, rb),
        (
            ExprKind::UnaryOp {
                op: opa,
                operand: oa,
            },
            ExprKind::UnaryOp {
                op: opb,
                operand: ob,
            },
        ) => opa == opb && exprs_structurally_equal(oa, ob),
        (ExprKind::Deref { addr: aa, size: sa }, ExprKind::Deref { addr: ab, size: sb }) => {
            sa == sb && exprs_structurally_equal(aa, ab)
        }
        (ExprKind::AddressOf(ia), ExprKind::AddressOf(ib)) => exprs_structurally_equal(ia, ib),
        (
            ExprKind::ArrayAccess {
                base: ba,
                index: ia,
                element_size: ea,
            },
            ExprKind::ArrayAccess {
                base: bb,
                index: ib,
                element_size: eb,
            },
        ) => ea == eb && exprs_structurally_equal(ba, bb) && exprs_structurally_equal(ia, ib),
        (
            ExprKind::FieldAccess {
                base: ba,
                field_name: fa,
                offset: oa,
            },
            ExprKind::FieldAccess {
                base: bb,
                field_name: fb,
                offset: ob,
            },
        ) => oa == ob && fa == fb && exprs_structurally_equal(ba, bb),
        (
            ExprKind::Cast {
                expr: ea,
                to_size: sa,
                signed: siga,
            },
            ExprKind::Cast {
                expr: eb,
                to_size: sb,
                signed: sigb,
            },
        ) => sa == sb && siga == sigb && exprs_structurally_equal(ea, eb),
        (
            ExprKind::BitField {
                expr: ea,
                start: sa,
                width: wa,
            },
            ExprKind::BitField {
                expr: eb,
                start: sb,
                width: wb,
            },
        ) => sa == sb && wa == wb && exprs_structurally_equal(ea, eb),
        (
            ExprKind::GotRef {
                address: aa,
                size: sa,
                ..
            },
            ExprKind::GotRef {
                address: ab,
                size: sb,
                ..
            },
        ) => aa == ab && sa == sb,
        (ExprKind::Unknown(ua), ExprKind::Unknown(ub)) => ua == ub,
        _ => false,
    }
}

/// Collect GotRef assignments from all blocks.
pub(super) fn collect_global_refs(nodes: &[StructuredNode]) -> HashMap<String, Expr> {
    let mut global_refs = HashMap::new();

    for node in nodes {
        collect_global_refs_from_node(node, &mut global_refs);
    }

    global_refs
}

pub(super) fn collect_global_refs_from_node(
    node: &StructuredNode,
    global_refs: &mut HashMap<String, Expr>,
) {
    use super::super::expression::ExprKind;

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
pub(super) fn substitute_globals_in_node(
    node: StructuredNode,
    global_refs: &HashMap<String, Expr>,
) -> StructuredNode {
    use super::super::expression::ExprKind;

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

pub(super) fn simplify_node_copies(node: StructuredNode) -> StructuredNode {
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

/// Normalize register names for aliasing (ARM64 w->x, x86 32->64 bit).
/// Returns all aliases that should be tracked together.
fn get_register_aliases(name: &str) -> Vec<String> {
    match name {
        // ARM64: wN and xN are aliases (w is lower 32 bits of x)
        // Store both so lookups work for either variant
        "w0" => vec!["w0".to_string(), "x0".to_string()],
        "w1" => vec!["w1".to_string(), "x1".to_string()],
        "w2" => vec!["w2".to_string(), "x2".to_string()],
        "w3" => vec!["w3".to_string(), "x3".to_string()],
        "w4" => vec!["w4".to_string(), "x4".to_string()],
        "w5" => vec!["w5".to_string(), "x5".to_string()],
        "w6" => vec!["w6".to_string(), "x6".to_string()],
        "w7" => vec!["w7".to_string(), "x7".to_string()],
        "w8" => vec!["w8".to_string(), "x8".to_string()],
        "w9" => vec!["w9".to_string(), "x9".to_string()],
        "w10" => vec!["w10".to_string(), "x10".to_string()],
        "w11" => vec!["w11".to_string(), "x11".to_string()],
        "w12" => vec!["w12".to_string(), "x12".to_string()],
        "w13" => vec!["w13".to_string(), "x13".to_string()],
        "w14" => vec!["w14".to_string(), "x14".to_string()],
        "w15" => vec!["w15".to_string(), "x15".to_string()],
        "w16" => vec!["w16".to_string(), "x16".to_string()],
        "w17" => vec!["w17".to_string(), "x17".to_string()],
        "w18" => vec!["w18".to_string(), "x18".to_string()],
        "x0" => vec!["w0".to_string(), "x0".to_string()],
        "x1" => vec!["w1".to_string(), "x1".to_string()],
        "x2" => vec!["w2".to_string(), "x2".to_string()],
        "x3" => vec!["w3".to_string(), "x3".to_string()],
        "x4" => vec!["w4".to_string(), "x4".to_string()],
        "x5" => vec!["w5".to_string(), "x5".to_string()],
        "x6" => vec!["w6".to_string(), "x6".to_string()],
        "x7" => vec!["w7".to_string(), "x7".to_string()],
        "x8" => vec!["w8".to_string(), "x8".to_string()],
        "x9" => vec!["w9".to_string(), "x9".to_string()],
        "x10" => vec!["w10".to_string(), "x10".to_string()],
        "x11" => vec!["w11".to_string(), "x11".to_string()],
        "x12" => vec!["w12".to_string(), "x12".to_string()],
        "x13" => vec!["w13".to_string(), "x13".to_string()],
        "x14" => vec!["w14".to_string(), "x14".to_string()],
        "x15" => vec!["w15".to_string(), "x15".to_string()],
        "x16" => vec!["w16".to_string(), "x16".to_string()],
        "x17" => vec!["w17".to_string(), "x17".to_string()],
        "x18" => vec!["w18".to_string(), "x18".to_string()],
        // x86: 32-bit and 64-bit register aliasing
        "al" | "ax" | "eax" | "rax" => vec![
            "al".to_string(),
            "ax".to_string(),
            "eax".to_string(),
            "rax".to_string(),
        ],
        "bl" | "bx" | "ebx" | "rbx" => vec![
            "bl".to_string(),
            "bx".to_string(),
            "ebx".to_string(),
            "rbx".to_string(),
        ],
        "cl" | "cx" | "ecx" | "rcx" => vec![
            "cl".to_string(),
            "cx".to_string(),
            "ecx".to_string(),
            "rcx".to_string(),
        ],
        "dl" | "dx" | "edx" | "rdx" => vec![
            "dl".to_string(),
            "dx".to_string(),
            "edx".to_string(),
            "rdx".to_string(),
        ],
        "sil" | "si" | "esi" | "rsi" => vec![
            "sil".to_string(),
            "si".to_string(),
            "esi".to_string(),
            "rsi".to_string(),
        ],
        "dil" | "di" | "edi" | "rdi" => vec![
            "dil".to_string(),
            "di".to_string(),
            "edi".to_string(),
            "rdi".to_string(),
        ],
        "r8b" | "r8w" | "r8d" | "r8" => vec![
            "r8b".to_string(),
            "r8w".to_string(),
            "r8d".to_string(),
            "r8".to_string(),
        ],
        "r9b" | "r9w" | "r9d" | "r9" => vec![
            "r9b".to_string(),
            "r9w".to_string(),
            "r9d".to_string(),
            "r9".to_string(),
        ],
        "r10b" | "r10w" | "r10d" | "r10" => vec![
            "r10b".to_string(),
            "r10w".to_string(),
            "r10d".to_string(),
            "r10".to_string(),
        ],
        "r11b" | "r11w" | "r11d" | "r11" => vec![
            "r11b".to_string(),
            "r11w".to_string(),
            "r11d".to_string(),
            "r11".to_string(),
        ],
        _ => vec![name.to_string()],
    }
}

/// Performs copy propagation on a list of statements.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
/// Note: Temp register assignments are kept for now so that propagate_temps_to_conditions
/// can use them for substituting into conditions. They will be removed later.
fn propagate_copies(statements: Vec<Expr>) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    // Track the last value assigned to each temp register
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for stmt in statements.into_iter() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            // Always substitute known register values in the RHS
            let new_lhs = substitute_assignment_lhs(lhs, &reg_values);
            let new_rhs = substitute_vars(rhs, &reg_values);

            if let ExprKind::Var(lhs_var) = &lhs.kind {
                invalidate_clobbered_register_mappings(&mut reg_values, &lhs_var.name);

                // Check if LHS is a temp register
                if is_temp_register(&lhs_var.name) {
                    // Track this assignment for all aliased register names
                    // (e.g., w9 and x9 on ARM64, eax and rax on x86)
                    if !expr_requires_single_evaluation(&new_rhs) {
                        for alias in get_register_aliases(&lhs_var.name) {
                            reg_values.insert(alias, new_rhs.clone());
                        }
                    }
                    // Emit with substituted RHS (keep the assignment for now)
                    result.push(Expr::assign((**lhs).clone(), new_rhs));
                    continue;
                }
            }

            // Non-temp LHS (memory location or non-temp register): emit with substitution
            result.push(Expr::assign(new_lhs, new_rhs));
            continue;
        }

        if let ExprKind::CompoundAssign { op, lhs, rhs } = &stmt.kind {
            let new_rhs = substitute_vars(rhs, &reg_values);
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                let aliases = get_register_aliases(&lhs_var.name);
                let prior_value = if is_temp_register(&lhs_var.name) {
                    aliases
                        .iter()
                        .find_map(|alias| reg_values.get(alias).cloned())
                } else {
                    None
                };
                invalidate_clobbered_register_mappings(&mut reg_values, &lhs_var.name);
                if is_temp_register(&lhs_var.name)
                    && compound_update_defines_full_alias_value(&lhs_var.name)
                {
                    if let Some(current) = prior_value {
                        if !expr_uses_any_alias(&current, &aliases) {
                            let new_val = Expr::binop(*op, current, new_rhs.clone()).simplify();
                            if !expr_requires_single_evaluation(&new_val) {
                                for alias in aliases {
                                    reg_values.insert(alias, new_val.clone());
                                }
                            }
                        }
                    }
                }
            }
            result.push(Expr {
                kind: ExprKind::CompoundAssign {
                    op: *op,
                    lhs: lhs.clone(),
                    rhs: Box::new(new_rhs),
                },
            });
            continue;
        }

        if let ExprKind::Call { .. } = &stmt.kind {
            let substituted = substitute_vars(&stmt, &reg_values);
            if let ExprKind::Call { target, .. } = &substituted.kind {
                if is_real_function_call(target) {
                    reg_values.clear();
                } else {
                    invalidate_pseudo_call_output_copies(&mut reg_values, target);
                }
            }
            result.push(substituted);
            continue;
        }
        // Non-assignment statement: pass through
        result.push(stmt);
    }

    result
}

fn invalidate_clobbered_register_mappings(reg_values: &mut HashMap<String, Expr>, written: &str) {
    let aliases = get_register_aliases(written);
    reg_values.retain(|name, value| {
        !aliases.iter().any(|alias| alias == name) && !expr_uses_any_alias(value, &aliases)
    });
}

fn compound_update_defines_full_alias_value(name: &str) -> bool {
    !matches!(
        name,
        "al" | "ah"
            | "ax"
            | "bl"
            | "bh"
            | "bx"
            | "cl"
            | "ch"
            | "cx"
            | "dl"
            | "dh"
            | "dx"
            | "sil"
            | "si"
            | "dil"
            | "di"
            | "r8b"
            | "r8w"
            | "r9b"
            | "r9w"
            | "r10b"
            | "r10w"
            | "r11b"
            | "r11w"
    )
}

fn invalidate_pseudo_call_output_copies(
    reg_values: &mut HashMap<String, Expr>,
    target: &CallTarget,
) {
    let written_aliases: HashSet<String> = call_output_alias_groups(target)
        .into_iter()
        .flatten()
        .collect();
    if written_aliases.is_empty() {
        return;
    }

    invalidate_dependent_register_values(reg_values, &written_aliases);
}

/// Substitute variable references with their GotRef values.
fn substitute_global_refs(expr: &Expr, global_refs: &HashMap<String, Expr>) -> Expr {
    use super::super::expression::{CallTarget, ExprKind};

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
    use super::super::expression::ExprKind;

    fn lookup_named_substitution<'a>(
        reg_values: &'a HashMap<String, Expr>,
        name: &str,
    ) -> Option<&'a Expr> {
        reg_values
            .get(name)
            .or_else(|| reg_values.get(&name.to_lowercase()))
    }

    let result = match &expr.kind {
        ExprKind::Var(v) => {
            if let Some(value) = lookup_named_substitution(reg_values, &v.name) {
                value.clone()
            } else {
                expr.clone()
            }
        }
        ExprKind::Unknown(name) => lookup_named_substitution(reg_values, name)
            .cloned()
            .unwrap_or_else(|| expr.clone()),
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
        ExprKind::AddressOf(inner) => Expr::address_of(substitute_vars(inner, reg_values)),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            substitute_vars(base, reg_values),
            substitute_vars(index, reg_values),
            *element_size,
        ),
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(
            substitute_vars(base, reg_values),
            field_name.clone(),
            *offset,
        ),
        ExprKind::Call { target, args } => Expr::call(
            substitute_call_target_vars(target, reg_values),
            substitute_call_args(target, args, reg_values),
        ),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(substitute_vars(inner, reg_values)),
                to_size: *to_size,
                signed: *signed,
            },
        },
        ExprKind::BitField {
            expr: inner,
            start,
            width,
        } => Expr {
            kind: ExprKind::BitField {
                expr: Box::new(substitute_vars(inner, reg_values)),
                start: *start,
                width: *width,
            },
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(substitute_vars(cond, reg_values)),
                then_expr: Box::new(substitute_vars(then_expr, reg_values)),
                else_expr: Box::new(substitute_vars(else_expr, reg_values)),
            },
        },
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op: *op,
                lhs: Box::new(substitute_vars(lhs, reg_values)),
                rhs: Box::new(substitute_vars(rhs, reg_values)),
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(
                args.iter()
                    .map(|arg| substitute_vars(arg, reg_values))
                    .collect(),
            ),
        },
        _ => expr.clone(),
    };
    // Simplify after substitution to handle boolean patterns like (x == 1) != 1 → x != 1
    result.simplify()
}

fn substitute_call_args(
    target: &CallTarget,
    args: &[Expr],
    reg_values: &HashMap<String, Expr>,
) -> Vec<Expr> {
    match target {
        CallTarget::Named(name) if name == "SET_BITS" => {
            substitute_set_bits_call_args(args, reg_values)
        }
        _ => args
            .iter()
            .map(|arg| substitute_vars(arg, reg_values))
            .collect(),
    }
}

fn substitute_set_bits_call_args(args: &[Expr], reg_values: &HashMap<String, Expr>) -> Vec<Expr> {
    let substituted_start = args.get(2).map(|arg| substitute_vars(arg, reg_values));
    let bit_start = substituted_start.as_ref().and_then(|expr| match expr.kind {
        ExprKind::IntLit(value) if (0..=u8::MAX as i128).contains(&value) => Some(value as u8),
        _ => None,
    });

    args.iter()
        .enumerate()
        .map(|(idx, arg)| match idx {
            1 => bit_start
                .map(|start| substitute_set_bits_value_arg(arg, start, reg_values))
                .unwrap_or_else(|| substitute_vars(arg, reg_values)),
            2 => substituted_start
                .clone()
                .unwrap_or_else(|| substitute_vars(arg, reg_values)),
            _ => substitute_vars(arg, reg_values),
        })
        .collect()
}

fn substitute_set_bits_value_arg(
    arg: &Expr,
    bit_start: u8,
    reg_values: &HashMap<String, Expr>,
) -> Expr {
    if let Some(inner) = strip_matching_left_shift(arg, bit_start) {
        return substitute_set_bits_value_arg(&inner, bit_start, reg_values);
    }

    if let Some(normalized) = lookup_shifted_register_value(arg, bit_start, reg_values) {
        return normalized;
    }

    let substituted = substitute_vars(arg, reg_values);
    strip_matching_left_shift(&substituted, bit_start).unwrap_or(substituted)
}

fn lookup_shifted_register_value(
    expr: &Expr,
    bit_start: u8,
    reg_values: &HashMap<String, Expr>,
) -> Option<Expr> {
    match &expr.kind {
        ExprKind::Var(var) => reg_values
            .get(&var.name)
            .and_then(|value| strip_matching_left_shift(value, bit_start)),
        ExprKind::Unknown(name) => reg_values
            .get(name)
            .and_then(|value| strip_matching_left_shift(value, bit_start)),
        _ => None,
    }
}

fn strip_matching_left_shift(expr: &Expr, bit_start: u8) -> Option<Expr> {
    let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };
    let ExprKind::IntLit(shift_amount) = right.kind else {
        return None;
    };
    if shift_amount != i128::from(bit_start) {
        return None;
    }
    Some(left.as_ref().clone())
}

fn substitute_call_target_vars(
    target: &CallTarget,
    reg_values: &HashMap<String, Expr>,
) -> CallTarget {
    match target {
        CallTarget::Direct { target, call_site } => CallTarget::Direct {
            target: *target,
            call_site: *call_site,
        },
        CallTarget::Named(name) => CallTarget::Named(name.clone()),
        CallTarget::Indirect(expr) => {
            CallTarget::Indirect(Box::new(substitute_vars(expr, reg_values)))
        }
        CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
            got_address: *got_address,
            expr: Box::new(substitute_vars(expr, reg_values)),
        },
    }
}

/// Recursively propagates function call arguments through structured nodes.
pub(super) fn propagate_call_args(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    propagate_call_args_with_binary_data_and_arch(nodes, None, None)
}

pub(super) fn propagate_call_args_with_binary_data(
    nodes: Vec<StructuredNode>,
    binary_data: Option<&BinaryDataContext>,
) -> Vec<StructuredNode> {
    propagate_call_args_with_binary_data_and_arch(nodes, binary_data, None)
}

pub(super) fn propagate_call_args_with_binary_data_and_arch(
    nodes: Vec<StructuredNode>,
    binary_data: Option<&BinaryDataContext>,
    arch: Option<Architecture>,
) -> Vec<StructuredNode> {
    let preferred_family = arch.and_then(argument_abi_family_from_arch);
    propagate_call_args_node_sequence(nodes, binary_data, preferred_family)
}

pub(super) fn propagate_call_args_node(node: StructuredNode) -> StructuredNode {
    propagate_call_args_node_with_binary_data(node, None, None)
}

fn propagate_call_args_node_with_binary_data(
    node: StructuredNode,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> StructuredNode {
    propagate_call_args_node_with_state(
        node,
        binary_data,
        preferred_family,
        CallArgPropagationState::default(),
    )
    .0
}

#[derive(Clone, Default)]
struct CallArgPropagationState {
    arg_values: HashMap<String, (Option<usize>, Expr)>,
    reg_values: HashMap<String, Expr>,
    call_target_values: HashMap<String, Expr>,
    stack_slot_values: HashMap<String, Expr>,
}

impl CallArgPropagationState {
    fn clear_after_real_call(&mut self) {
        self.arg_values.clear();
        self.reg_values.clear();
        self.call_target_values.clear();
    }

    fn clear_arg_statement_indices(&mut self) {
        for (stmt_idx, _) in self.arg_values.values_mut() {
            *stmt_idx = None;
        }
    }
}

fn body_definitely_terminates(nodes: &[StructuredNode]) -> bool {
    let Some(last) = nodes.last() else {
        return false;
    };

    match last {
        StructuredNode::Return(_)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_) => true,
        StructuredNode::Sequence(nodes) => body_definitely_terminates(nodes),
        StructuredNode::If {
            then_body,
            else_body: Some(else_body),
            ..
        } => body_definitely_terminates(then_body) && body_definitely_terminates(else_body),
        _ => false,
    }
}

fn propagate_call_args_node_with_state(
    node: StructuredNode,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
    incoming_state: CallArgPropagationState,
) -> (StructuredNode, CallArgPropagationState) {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let mut state = incoming_state;
            let statements = propagate_args_in_block_with_state(
                statements,
                &mut state,
                binary_data,
                preferred_family,
            );
            state.clear_arg_statement_indices();
            (
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                },
                state,
            )
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let (then_body, then_state) = propagate_call_args_node_sequence_with_state(
                then_body,
                binary_data,
                preferred_family,
                incoming_state.clone(),
            );
            let else_result = else_body.map(|body| {
                propagate_call_args_node_sequence_with_state(
                    body,
                    binary_data,
                    preferred_family,
                    incoming_state.clone(),
                )
            });
            let then_terminates = body_definitely_terminates(&then_body);
            let (else_body, else_state, else_terminates) = match else_result {
                Some((body, state)) => {
                    let terminates = body_definitely_terminates(&body);
                    (Some(body), Some(state), terminates)
                }
                None => (None, None, false),
            };
            let mut outgoing_state = if then_terminates && else_body.is_none() {
                incoming_state
            } else if then_terminates && !else_terminates {
                else_state.unwrap_or_default()
            } else if else_terminates && !then_terminates {
                then_state
            } else {
                CallArgPropagationState::default()
            };
            outgoing_state.clear_arg_statement_indices();
            (
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                },
                outgoing_state,
            )
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                incoming_state,
            );
            (
                StructuredNode::While {
                    condition,
                    body,
                    header,
                    exit_block,
                },
                CallArgPropagationState::default(),
            )
        }
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                incoming_state,
            );
            (
                StructuredNode::DoWhile {
                    body,
                    condition,
                    header,
                    exit_block,
                },
                CallArgPropagationState::default(),
            )
        }
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                incoming_state,
            );
            (
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    header,
                    exit_block,
                },
                CallArgPropagationState::default(),
            )
        }
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                incoming_state,
            );
            (
                StructuredNode::Loop {
                    body,
                    header,
                    exit_block,
                },
                CallArgPropagationState::default(),
            )
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            let cases = cases
                .into_iter()
                .map(|(vals, body)| {
                    (
                        vals,
                        propagate_call_args_node_sequence_with_state(
                            body,
                            binary_data,
                            preferred_family,
                            incoming_state.clone(),
                        )
                        .0,
                    )
                })
                .collect();
            let default = default.map(|body| {
                propagate_call_args_node_sequence_with_state(
                    body,
                    binary_data,
                    preferred_family,
                    incoming_state.clone(),
                )
                .0
            });
            (
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                },
                CallArgPropagationState::default(),
            )
        }
        StructuredNode::Sequence(nodes) => {
            let (nodes, state) = propagate_call_args_node_sequence_with_state(
                nodes,
                binary_data,
                preferred_family,
                incoming_state,
            );
            (StructuredNode::Sequence(nodes), state)
        }
        other => (other, CallArgPropagationState::default()),
    }
}

fn propagate_call_args_node_sequence(
    nodes: Vec<StructuredNode>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Vec<StructuredNode> {
    propagate_call_args_node_sequence_with_state(
        nodes,
        binary_data,
        preferred_family,
        CallArgPropagationState::default(),
    )
    .0
}

fn propagate_call_args_node_sequence_with_state(
    nodes: Vec<StructuredNode>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
    mut state: CallArgPropagationState,
) -> (Vec<StructuredNode>, CallArgPropagationState) {
    let mut propagated = Vec::with_capacity(nodes.len());
    for node in nodes {
        let (node, next_state) =
            propagate_call_args_node_with_state(node, binary_data, preferred_family, state);
        propagated.push(node);
        state = next_state;
    }
    (propagated, state)
}

/// Propagates arguments into function calls within a block.
/// Transforms patterns like:
///   edi = 5;
///   func();
/// Into:
///   func(5);
pub(super) fn propagate_args_in_block(statements: Vec<Expr>) -> Vec<Expr> {
    propagate_args_in_block_with_binary_data(statements, None, None)
}

fn propagate_args_in_block_with_binary_data(
    statements: Vec<Expr>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Vec<Expr> {
    let mut state = CallArgPropagationState::default();
    propagate_args_in_block_with_state(statements, &mut state, binary_data, preferred_family)
}

fn propagate_args_in_block_with_state(
    statements: Vec<Expr>,
    state: &mut CallArgPropagationState,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    let mut to_remove: HashSet<usize> = HashSet::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for (i, stmt) in statements.into_iter().enumerate() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(rhs_var) = &rhs.kind {
                if is_return_register(&rhs_var.name) {
                    if let Some(Expr {
                        kind: ExprKind::Call { target, args },
                    }) = result.last().cloned()
                    {
                        if is_real_function_call(&target) {
                            let merged_assign =
                                Expr::assign((**lhs).clone(), Expr::call(target, args));
                            result.pop();
                            let merged = propagate_args_in_block_with_state(
                                vec![merged_assign],
                                state,
                                binary_data,
                                preferred_family,
                            );
                            result.extend(merged);
                            continue;
                        }
                    }
                }
            }

            let substituted_lhs = substitute_assignment_lhs(lhs, &state.reg_values);
            let tracked_rhs = substitute_stack_slot_values(
                substitute_vars(rhs, &state.reg_values),
                &state.stack_slot_values,
            );

            if let ExprKind::Var(v) = &lhs.kind {
                let written_aliases: HashSet<String> =
                    get_register_aliases(&v.name).into_iter().collect();
                invalidate_dependent_register_values(&mut state.reg_values, &written_aliases);
                invalidate_dependent_arg_values(&mut state.arg_values, &written_aliases);
                invalidate_written_call_target_values(
                    &mut state.call_target_values,
                    &written_aliases,
                );
                invalidate_dependent_stack_slot_values(
                    &mut state.stack_slot_values,
                    &written_aliases,
                );
                if aliases_include_stack_base(&written_aliases) {
                    state.stack_slot_values.clear();
                }

                if is_temp_register(&v.name) {
                    let stabilized_temp_rhs = stabilize_saved_arg_registers(tracked_rhs.clone());
                    if !expr_requires_single_evaluation(&stabilized_temp_rhs) {
                        for alias in &written_aliases {
                            state
                                .reg_values
                                .insert(alias.clone(), stabilized_temp_rhs.clone());
                            state
                                .call_target_values
                                .insert(alias.clone(), stabilized_temp_rhs.clone());
                        }
                    }
                }

                if let Some(tracked_arg_key) = tracked_call_arg_key(v, preferred_family) {
                    let tracks_register_aliases = is_tracked_call_arg_register(&v.name);
                    if tracks_register_aliases && !expr_requires_single_evaluation(&tracked_rhs) {
                        for alias in &written_aliases {
                            state.reg_values.insert(alias.clone(), tracked_rhs.clone());
                            state
                                .call_target_values
                                .insert(alias.clone(), tracked_rhs.clone());
                        }
                    }
                    // If one ABI argument register is only staging a value into another
                    // argument register, keep the destination but drop the staged source.
                    if let ExprKind::Var(src_var) = &rhs.kind {
                        if let Some(src_idx) = get_arg_register_index(&src_var.name) {
                            if get_arg_register_index(&tracked_arg_key) != Some(src_idx) {
                                for alias in get_register_aliases(&src_var.name) {
                                    state.arg_values.remove(&alias);
                                }
                            }
                        }
                    }

                    // Preserve copies of incoming ABI arguments even if the source
                    // registers get reused later in the setup sequence.
                    let tracked_arg_value = match v.kind {
                        super::super::expression::VarKind::Arg(_) => Expr::var(v.clone()),
                        _ => match &tracked_rhs.kind {
                            ExprKind::Call { target, .. } if is_real_function_call(target) => {
                                call_result_placeholder_expr(preferred_family, &v.name, v.size)
                                    .unwrap_or_else(|| {
                                        stabilize_saved_arg_registers(tracked_rhs.clone())
                                    })
                            }
                            _ => stabilize_saved_arg_registers(tracked_rhs.clone()),
                        },
                    };
                    let stmt_idx = match v.kind {
                        super::super::expression::VarKind::Arg(_) => None,
                        _ => Some(i),
                    };
                    state
                        .arg_values
                        .insert(tracked_arg_key, (stmt_idx, tracked_arg_value));
                    result.push(Expr::assign((**lhs).clone(), tracked_rhs));
                    continue;
                }
            }

            if let Some(slot_key) = stack_slot_key(&substituted_lhs) {
                let stabilized_rhs = stabilize_saved_arg_registers(tracked_rhs);
                state.stack_slot_values.remove(&slot_key);
                if !expr_requires_single_evaluation(&stabilized_rhs) {
                    state
                        .stack_slot_values
                        .insert(slot_key, stabilized_rhs.clone());
                }
                forget_pending_arg_values_from_expr(&stmt, &mut state.arg_values);
                result.push(Expr::assign(substituted_lhs, stabilized_rhs));
                continue;
            }

            if let ExprKind::Call { target, args } = &rhs.kind {
                let substituted_target =
                    substitute_call_target(target.clone(), &state.call_target_values);
                if is_real_function_call(target) {
                    let mut rewritten_args: Vec<Expr> =
                        substitute_call_args(target, args, &state.reg_values);
                    let excluded_arg_regs = collect_target_argument_registers(target);
                    if let Some((recovered_args, used_stmt_indices)) =
                        try_recover_format_call_arguments(
                            target,
                            args,
                            &state.arg_values,
                            &excluded_arg_regs,
                            binary_data,
                            preferred_family,
                        )
                    {
                        for idx in used_stmt_indices {
                            to_remove.insert(idx);
                        }
                        rewritten_args = recovered_args;
                    } else {
                        let recovered_args = extract_call_arguments_with_indices(
                            Some(target),
                            args,
                            &state.arg_values,
                            &excluded_arg_regs,
                            binary_data,
                            preferred_family,
                        );
                        if recovered_args.0.len() != args.len() || !recovered_args.1.is_empty() {
                            for idx in recovered_args.1 {
                                to_remove.insert(idx);
                            }
                            rewritten_args = recovered_args.0;
                        } else if args.is_empty() {
                            rewritten_args =
                                synthesize_leading_passthrough_args_from_target(&excluded_arg_regs);
                        }
                    }
                    let rewritten_call = Expr::call(substituted_target, rewritten_args);
                    state.clear_after_real_call();
                    if let ExprKind::Var(_) = &substituted_lhs.kind {
                        track_call_result_aliases(
                            &substituted_lhs,
                            &mut state.reg_values,
                            &mut state.call_target_values,
                        );
                    }
                    result.push(Expr::assign(substituted_lhs, rewritten_call));
                    continue;
                } else {
                    let rewritten_call = Expr::call(
                        substituted_target,
                        substitute_call_args(target, args, &state.reg_values),
                    );
                    if invalidate_pseudo_call_outputs(
                        target,
                        &mut state.reg_values,
                        &mut state.arg_values,
                        &mut state.call_target_values,
                        &mut state.stack_slot_values,
                    ) {
                        result.push(Expr::assign(substituted_lhs, rewritten_call));
                        continue;
                    }
                }
            }

            forget_pending_arg_values_from_expr(&stmt, &mut state.arg_values);
            result.push(Expr::assign(substituted_lhs, tracked_rhs));
            continue;
        }

        if let ExprKind::CompoundAssign { op, lhs, rhs } = &stmt.kind {
            let substituted_lhs = substitute_assignment_lhs(lhs, &state.reg_values);
            let tracked_rhs = substitute_stack_slot_values(
                substitute_vars(rhs, &state.reg_values),
                &state.stack_slot_values,
            );

            if let ExprKind::Var(v) = &lhs.kind {
                let written_aliases: HashSet<String> =
                    get_register_aliases(&v.name).into_iter().collect();
                let prior_aliases: Vec<String> = written_aliases.iter().cloned().collect();
                let prior_value = if is_temp_register(&v.name) {
                    prior_aliases
                        .iter()
                        .find_map(|alias| state.reg_values.get(alias).cloned())
                } else {
                    None
                };
                invalidate_dependent_register_values(&mut state.reg_values, &written_aliases);
                invalidate_dependent_arg_values(&mut state.arg_values, &written_aliases);
                invalidate_written_call_target_values(
                    &mut state.call_target_values,
                    &written_aliases,
                );
                invalidate_dependent_stack_slot_values(
                    &mut state.stack_slot_values,
                    &written_aliases,
                );
                if aliases_include_stack_base(&written_aliases) {
                    state.stack_slot_values.clear();
                }

                if is_temp_register(&v.name) && compound_update_defines_full_alias_value(&v.name) {
                    if let Some(current) = prior_value {
                        if !expr_uses_any_register_alias(&current, &written_aliases) {
                            let new_val = Expr::binop(*op, current, tracked_rhs.clone()).simplify();
                            if !expr_requires_single_evaluation(&new_val) {
                                for alias in &written_aliases {
                                    state.reg_values.insert(alias.clone(), new_val.clone());
                                    state
                                        .call_target_values
                                        .insert(alias.clone(), new_val.clone());
                                }
                            }
                        }
                    }
                }
                if is_tracked_call_arg_register(&v.name) {
                    for alias in &written_aliases {
                        state.reg_values.remove(alias);
                    }
                    state.arg_values.remove(&v.name.to_lowercase());
                }
            }

            forget_pending_arg_values_from_expr(&stmt, &mut state.arg_values);
            result.push(Expr {
                kind: ExprKind::CompoundAssign {
                    op: *op,
                    lhs: Box::new(substituted_lhs),
                    rhs: Box::new(tracked_rhs),
                },
            });
            continue;
        }

        // Check if this is an assignment to an argument register
        // Check if this is a function call (not push/pop/syscall/etc.)
        if let ExprKind::Call { target, args } = &stmt.kind {
            let substituted_target =
                substitute_call_target(target.clone(), &state.call_target_values);
            if is_real_function_call(target) {
                let excluded_arg_regs = collect_target_argument_registers(target);
                if let Some((recovered_args, used_stmt_indices)) = try_recover_format_call_arguments(
                    target,
                    args,
                    &state.arg_values,
                    &excluded_arg_regs,
                    binary_data,
                    preferred_family,
                ) {
                    for idx in used_stmt_indices {
                        to_remove.insert(idx);
                    }
                    result.push(Expr::call(substituted_target, recovered_args));
                    state.clear_after_real_call();
                    track_bare_call_result_aliases(
                        &mut state.reg_values,
                        &mut state.call_target_values,
                        preferred_family,
                    );
                    continue;
                }
                // Try to extract arguments from tracked registers
                let new_args = extract_call_arguments_with_indices(
                    Some(target),
                    args,
                    &state.arg_values,
                    &excluded_arg_regs,
                    binary_data,
                    preferred_family,
                );
                if (new_args.0.len() != args.len() || !new_args.1.is_empty()) && !args.is_empty() {
                    for idx in new_args.1 {
                        to_remove.insert(idx);
                    }
                    result.push(Expr::call(substituted_target, new_args.0));
                    state.clear_after_real_call();
                    track_bare_call_result_aliases(
                        &mut state.reg_values,
                        &mut state.call_target_values,
                        preferred_family,
                    );
                    continue;
                }
                if args.is_empty() && (!new_args.0.is_empty() || !new_args.1.is_empty()) {
                    // Mark the used arg assignments for removal
                    for idx in new_args.1 {
                        to_remove.insert(idx);
                    }
                    // Create a new call with arguments
                    let new_call = Expr::call(substituted_target, new_args.0);
                    result.push(new_call);
                    // Clear argument tracking after the call
                    state.clear_after_real_call();
                    track_bare_call_result_aliases(
                        &mut state.reg_values,
                        &mut state.call_target_values,
                        preferred_family,
                    );
                    continue;
                }
                if args.is_empty() {
                    let passthrough_args =
                        synthesize_leading_passthrough_args_from_target(&excluded_arg_regs);
                    if !passthrough_args.is_empty() {
                        result.push(Expr::call(substituted_target, passthrough_args));
                        state.clear_after_real_call();
                        track_bare_call_result_aliases(
                            &mut state.reg_values,
                            &mut state.call_target_values,
                            preferred_family,
                        );
                        continue;
                    }
                }

                result.push(Expr::call(
                    substituted_target,
                    substitute_call_args(target, args, &state.reg_values),
                ));
                state.clear_after_real_call();
                track_bare_call_result_aliases(
                    &mut state.reg_values,
                    &mut state.call_target_values,
                    preferred_family,
                );
                continue;
            } else {
                let substituted_args: Vec<_> =
                    substitute_call_args(target, args, &state.reg_values);
                if invalidate_pseudo_call_outputs(
                    target,
                    &mut state.reg_values,
                    &mut state.arg_values,
                    &mut state.call_target_values,
                    &mut state.stack_slot_values,
                ) {
                    result.push(Expr::call(substituted_target, substituted_args));
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
        forget_pending_arg_values_from_expr(&stmt, &mut state.arg_values);
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

fn substitute_assignment_lhs(lhs: &Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    use super::super::expression::ExprKind;

    match &lhs.kind {
        ExprKind::Var(_) => lhs.clone(),
        _ => substitute_vars(lhs, reg_values),
    }
}

fn invalidate_written_call_target_values(
    call_target_values: &mut HashMap<String, Expr>,
    written_aliases: &HashSet<String>,
) {
    call_target_values.retain(|alias, _| !written_aliases.contains(alias));
}

fn invalidate_dependent_stack_slot_values(
    stack_slot_values: &mut HashMap<String, Expr>,
    written_aliases: &HashSet<String>,
) {
    stack_slot_values.retain(|_, expr| !expr_uses_any_register_alias(expr, written_aliases));
}

fn aliases_include_stack_base(written_aliases: &HashSet<String>) -> bool {
    written_aliases.iter().any(|alias| {
        matches!(
            alias.as_str(),
            "sp" | "rsp" | "esp" | "rbp" | "ebp" | "bp" | "x29" | "fp"
        )
    })
}

fn track_call_result_aliases(
    result_expr: &Expr,
    reg_values: &mut HashMap<String, Expr>,
    call_target_values: &mut HashMap<String, Expr>,
) {
    for alias in ["rax", "eax", "x0", "w0", "a0"] {
        reg_values.insert(alias.to_string(), result_expr.clone());
        call_target_values.insert(alias.to_string(), result_expr.clone());
    }
}

fn track_bare_call_result_aliases(
    reg_values: &mut HashMap<String, Expr>,
    call_target_values: &mut HashMap<String, Expr>,
    preferred_family: Option<ArgumentAbiFamily>,
) {
    let Some((primary_reg, primary_expr)) = primary_call_result_alias_expr(preferred_family) else {
        return;
    };

    for alias in get_register_aliases(primary_reg)
        .into_iter()
        .chain(std::iter::once("ret".to_string()))
    {
        reg_values.insert(alias.clone(), primary_expr.clone());
        call_target_values.insert(alias, primary_expr.clone());
    }
}

fn primary_call_result_alias_expr(
    preferred_family: Option<ArgumentAbiFamily>,
) -> Option<(&'static str, Expr)> {
    match preferred_family.unwrap_or(ArgumentAbiFamily::X86_64SysV) {
        ArgumentAbiFamily::X86_64SysV => Some(("eax", Expr::var(Variable::reg("eax", 4)))),
        ArgumentAbiFamily::Aarch64 => Some(("w0", Expr::var(Variable::reg("w0", 4)))),
        ArgumentAbiFamily::RiscV => Some(("a0", Expr::var(Variable::reg("a0", 8)))),
    }
}

fn invalidate_pseudo_call_outputs(
    target: &super::super::expression::CallTarget,
    reg_values: &mut HashMap<String, Expr>,
    arg_values: &mut HashMap<String, (Option<usize>, Expr)>,
    call_target_values: &mut HashMap<String, Expr>,
    stack_slot_values: &mut HashMap<String, Expr>,
) -> bool {
    let written_aliases: HashSet<String> = call_output_alias_groups(target)
        .into_iter()
        .flatten()
        .collect();
    if written_aliases.is_empty() {
        return false;
    }

    invalidate_dependent_register_values(reg_values, &written_aliases);
    invalidate_dependent_arg_values(arg_values, &written_aliases);
    invalidate_written_call_target_values(call_target_values, &written_aliases);
    invalidate_dependent_stack_slot_values(stack_slot_values, &written_aliases);
    if aliases_include_stack_base(&written_aliases) {
        stack_slot_values.clear();
    }

    true
}

fn invalidate_dependent_register_values(
    reg_values: &mut HashMap<String, Expr>,
    written_aliases: &HashSet<String>,
) {
    reg_values.retain(|alias, expr| {
        !written_aliases.contains(alias) && !expr_uses_any_register_alias(expr, written_aliases)
    });
}

fn invalidate_dependent_arg_values(
    arg_values: &mut HashMap<String, (Option<usize>, Expr)>,
    written_aliases: &HashSet<String>,
) {
    arg_values.retain(|alias, (_, expr)| {
        !written_aliases.contains(alias) && !expr_uses_any_register_alias(expr, written_aliases)
    });
}

fn substitute_stack_slot_values(expr: Expr, stack_slot_values: &HashMap<String, Expr>) -> Expr {
    use super::super::expression::ExprKind;

    match expr.kind {
        ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => expr,
        ExprKind::Deref { addr, size } => {
            let deref = Expr::deref(substitute_stack_slot_values(*addr, stack_slot_values), size);
            if let Some(key) = stack_slot_key(&deref) {
                if let Some(value) = stack_slot_values.get(&key) {
                    return value.clone();
                }
            }
            deref
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            op,
            substitute_stack_slot_values(*left, stack_slot_values),
            substitute_stack_slot_values(*right, stack_slot_values),
        ),
        ExprKind::UnaryOp { op, operand } => Expr::unary(
            op,
            substitute_stack_slot_values(*operand, stack_slot_values),
        ),
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_stack_slot_values(*lhs, stack_slot_values),
            substitute_stack_slot_values(*rhs, stack_slot_values),
        ),
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(substitute_stack_slot_values(*lhs, stack_slot_values)),
                rhs: Box::new(substitute_stack_slot_values(*rhs, stack_slot_values)),
            },
        },
        ExprKind::AddressOf(inner) => {
            Expr::address_of(substitute_stack_slot_values(*inner, stack_slot_values))
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            substitute_stack_slot_values(*base, stack_slot_values),
            substitute_stack_slot_values(*index, stack_slot_values),
            element_size,
        ),
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(
            substitute_stack_slot_values(*base, stack_slot_values),
            field_name,
            offset,
        ),
        ExprKind::Call { target, args } => Expr::call(
            substitute_call_target_stack_slots(target, stack_slot_values),
            args.into_iter()
                .map(|arg| substitute_stack_slot_values(arg, stack_slot_values))
                .collect(),
        ),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(substitute_stack_slot_values(*inner, stack_slot_values)),
                to_size,
                signed,
            },
        },
        ExprKind::BitField {
            expr: inner,
            start,
            width,
        } => Expr {
            kind: ExprKind::BitField {
                expr: Box::new(substitute_stack_slot_values(*inner, stack_slot_values)),
                start,
                width,
            },
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(substitute_stack_slot_values(*cond, stack_slot_values)),
                then_expr: Box::new(substitute_stack_slot_values(*then_expr, stack_slot_values)),
                else_expr: Box::new(substitute_stack_slot_values(*else_expr, stack_slot_values)),
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(
                args.into_iter()
                    .map(|arg| substitute_stack_slot_values(arg, stack_slot_values))
                    .collect(),
            ),
        },
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
                display_expr: Box::new(substitute_stack_slot_values(
                    *display_expr,
                    stack_slot_values,
                )),
                is_deref,
            },
        },
    }
}

fn substitute_call_target_stack_slots(
    target: CallTarget,
    stack_slot_values: &HashMap<String, Expr>,
) -> CallTarget {
    match target {
        CallTarget::Indirect(expr) => CallTarget::Indirect(Box::new(substitute_stack_slot_values(
            *expr,
            stack_slot_values,
        ))),
        CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
            got_address,
            expr: Box::new(substitute_stack_slot_values(*expr, stack_slot_values)),
        },
        other => other,
    }
}

fn stabilize_saved_arg_registers(expr: Expr) -> Expr {
    use super::super::expression::ExprKind;

    match expr.kind {
        ExprKind::Var(v) => get_arg_register_index(&v.name)
            .map(|index| Expr::unknown(format!("arg{}", index)))
            .unwrap_or_else(|| Expr::var(v)),
        ExprKind::Unknown(_) | ExprKind::IntLit(_) => expr,
        ExprKind::Deref { addr, size } => Expr::deref(stabilize_saved_arg_registers(*addr), size),
        ExprKind::BinOp { op, left, right } => Expr::binop(
            op,
            stabilize_saved_arg_registers(*left),
            stabilize_saved_arg_registers(*right),
        ),
        ExprKind::UnaryOp { op, operand } => {
            Expr::unary(op, stabilize_saved_arg_registers(*operand))
        }
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            stabilize_saved_arg_registers(*lhs),
            stabilize_saved_arg_registers(*rhs),
        ),
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(stabilize_saved_arg_registers(*lhs)),
                rhs: Box::new(stabilize_saved_arg_registers(*rhs)),
            },
        },
        ExprKind::AddressOf(inner) => Expr::address_of(stabilize_saved_arg_registers(*inner)),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            stabilize_saved_arg_registers(*base),
            stabilize_saved_arg_registers(*index),
            element_size,
        ),
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(stabilize_saved_arg_registers(*base), field_name, offset),
        ExprKind::Call { target, args } => Expr::call(
            stabilize_saved_arg_call_target(target),
            args.into_iter()
                .map(stabilize_saved_arg_registers)
                .collect(),
        ),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(stabilize_saved_arg_registers(*inner)),
                to_size,
                signed,
            },
        },
        ExprKind::BitField {
            expr: inner,
            start,
            width,
        } => Expr {
            kind: ExprKind::BitField {
                expr: Box::new(stabilize_saved_arg_registers(*inner)),
                start,
                width,
            },
        },
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(stabilize_saved_arg_registers(*cond)),
                then_expr: Box::new(stabilize_saved_arg_registers(*then_expr)),
                else_expr: Box::new(stabilize_saved_arg_registers(*else_expr)),
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(
                args.into_iter()
                    .map(stabilize_saved_arg_registers)
                    .collect(),
            ),
        },
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
                display_expr: Box::new(stabilize_saved_arg_registers(*display_expr)),
                is_deref,
            },
        },
    }
}

fn stabilize_saved_arg_call_target(target: CallTarget) -> CallTarget {
    match target {
        CallTarget::Indirect(expr) => {
            CallTarget::Indirect(Box::new(stabilize_saved_arg_registers(*expr)))
        }
        CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
            got_address,
            expr: Box::new(stabilize_saved_arg_registers(*expr)),
        },
        other => other,
    }
}

fn stack_slot_key(expr: &Expr) -> Option<String> {
    let super::super::expression::ExprKind::Deref { addr, .. } = &expr.kind else {
        return None;
    };
    stack_slot_address_key(addr)
}

fn stack_slot_address_key(addr: &Expr) -> Option<String> {
    use super::super::expression::ExprKind;

    match &addr.kind {
        ExprKind::Var(var) if is_stack_slot_base_register(&var.name) => {
            Some(format!("{}:{:+}", var.name.to_lowercase(), 0))
        }
        ExprKind::BinOp { op, left, right } => {
            let ExprKind::Var(base) = &left.kind else {
                return None;
            };
            if !is_stack_slot_base_register(&base.name) {
                return None;
            }
            let ExprKind::IntLit(offset) = &right.kind else {
                return None;
            };
            let actual_offset = match op {
                BinOpKind::Add => *offset,
                BinOpKind::Sub => -*offset,
                _ => return None,
            };
            Some(format!("{}:{:+}", base.name.to_lowercase(), actual_offset))
        }
        _ => None,
    }
}

fn is_stack_slot_base_register(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "sp" | "rsp" | "esp" | "rbp" | "ebp" | "bp" | "x29" | "fp"
    )
}

fn expr_is_pure_stack_slot_expression(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Deref { .. } => stack_slot_key(expr).is_some(),
        ExprKind::IntLit(_) | ExprKind::Var(_) | ExprKind::Unknown(_) => true,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_is_pure_stack_slot_expression(left) && expr_is_pure_stack_slot_expression(right),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_is_pure_stack_slot_expression(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_is_pure_stack_slot_expression(base) && expr_is_pure_stack_slot_expression(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_is_pure_stack_slot_expression(base),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_is_pure_stack_slot_expression(cond)
                && expr_is_pure_stack_slot_expression(then_expr)
                && expr_is_pure_stack_slot_expression(else_expr)
        }
        ExprKind::Phi(values) => values.iter().all(expr_is_pure_stack_slot_expression),
        ExprKind::Call { .. } | ExprKind::GotRef { .. } => false,
    }
}

fn expr_uses_any_register_alias(expr: &Expr, aliases: &HashSet<String>) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(v) => get_register_aliases(&v.name)
            .into_iter()
            .any(|alias| aliases.contains(&alias)),
        ExprKind::Unknown(name) => get_register_aliases(&name.to_lowercase())
            .into_iter()
            .any(|alias| aliases.contains(&alias)),
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => {
            expr_uses_any_register_alias(left, aliases)
                || expr_uses_any_register_alias(right, aliases)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => {
            expr_uses_any_register_alias(operand, aliases)
        }
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_uses_any_register_alias(base, aliases)
                || expr_uses_any_register_alias(index, aliases)
        }
        ExprKind::FieldAccess { base, .. } => expr_uses_any_register_alias(base, aliases),
        ExprKind::Call { args, .. } | ExprKind::Phi(args) => args
            .iter()
            .any(|arg| expr_uses_any_register_alias(arg, aliases)),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_uses_any_register_alias(cond, aliases)
                || expr_uses_any_register_alias(then_expr, aliases)
                || expr_uses_any_register_alias(else_expr, aliases)
        }
        ExprKind::GotRef { display_expr, .. } => {
            expr_uses_any_register_alias(display_expr, aliases)
        }
        ExprKind::IntLit(_) => false,
    }
}

fn forget_pending_arg_values_from_expr(
    expr: &Expr,
    arg_values: &mut HashMap<String, (Option<usize>, Expr)>,
) {
    use super::super::expression::ExprKind;

    fn walk(expr: &Expr, consumed: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                if is_tracked_call_arg_register(&v.name) {
                    consumed.insert(v.name.to_lowercase());
                }
            }
            ExprKind::BinOp { left, right, .. }
            | ExprKind::Assign {
                lhs: left,
                rhs: right,
            }
            | ExprKind::CompoundAssign {
                lhs: left,
                rhs: right,
                ..
            } => {
                walk(left, consumed);
                walk(right, consumed);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => walk(operand, consumed),
            ExprKind::ArrayAccess { base, index, .. } => {
                walk(base, consumed);
                walk(index, consumed);
            }
            ExprKind::FieldAccess { base, .. } => walk(base, consumed),
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
                for arg in args {
                    walk(arg, consumed);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                walk(cond, consumed);
                walk(then_expr, consumed);
                walk(else_expr, consumed);
            }
            ExprKind::GotRef { display_expr, .. } => walk(display_expr, consumed),
            ExprKind::Unknown(_) | ExprKind::IntLit(_) => {}
        }
    }

    let mut consumed = HashSet::new();
    walk(expr, &mut consumed);
    for reg in consumed {
        arg_values.remove(&reg);
    }
}

fn substitute_call_target(
    target: super::super::expression::CallTarget,
    reg_values: &HashMap<String, Expr>,
) -> super::super::expression::CallTarget {
    use super::super::expression::CallTarget;

    match target {
        CallTarget::Indirect(expr) => {
            CallTarget::Indirect(Box::new(substitute_vars(&expr, reg_values)))
        }
        CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
            got_address,
            expr: Box::new(substitute_vars(&expr, reg_values)),
        },
        other => other,
    }
}

fn collect_target_argument_registers(
    target: &super::super::expression::CallTarget,
) -> HashSet<String> {
    fn collect_expr_arg_regs(expr: &Expr, out: &mut HashSet<String>) {
        use super::super::expression::ExprKind;

        match &expr.kind {
            ExprKind::Var(v) => {
                if is_tracked_call_arg_register(&v.name) {
                    out.insert(v.name.to_lowercase());
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                collect_expr_arg_regs(left, out);
                collect_expr_arg_regs(right, out);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => collect_expr_arg_regs(operand, out),
            ExprKind::ArrayAccess { base, index, .. } => {
                collect_expr_arg_regs(base, out);
                collect_expr_arg_regs(index, out);
            }
            ExprKind::FieldAccess { base, .. } => collect_expr_arg_regs(base, out),
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
                for arg in args {
                    collect_expr_arg_regs(arg, out);
                }
            }
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                collect_expr_arg_regs(lhs, out);
                collect_expr_arg_regs(rhs, out);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                collect_expr_arg_regs(cond, out);
                collect_expr_arg_regs(then_expr, out);
                collect_expr_arg_regs(else_expr, out);
            }
            ExprKind::IntLit(_) | ExprKind::Unknown(_) | ExprKind::GotRef { .. } => {}
        }
    }

    let mut regs = HashSet::new();
    match target {
        super::super::expression::CallTarget::Indirect(expr)
        | super::super::expression::CallTarget::IndirectGot { expr, .. } => {
            collect_expr_arg_regs(expr, &mut regs);
        }
        _ => {}
    }
    regs
}

pub(super) fn statement_contains_real_call(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Call { target, .. } => is_real_function_call(target),
        ExprKind::Assign { rhs, .. } | ExprKind::CompoundAssign { rhs, .. } => {
            statement_contains_real_call(rhs)
        }
        _ => false,
    }
}

/// Checks if a call target is a "real" function call (not push/pop/syscall etc.)
fn is_real_function_call(target: &super::super::expression::CallTarget) -> bool {
    use super::super::expression::CallTarget;
    match target {
        CallTarget::Named(name) => {
            !matches!(
                name.as_str(),
                "push"
                    | "pop"
                    | "__linux_syscall"
                    | "__raw_syscall"
                    | "int"
                    | "halt"
                    | "swap"
                    | "rol"
                    | "ror"
            ) && !is_register_state_pseudo_call(name)
        }
        CallTarget::Direct { .. } | CallTarget::Indirect(_) | CallTarget::IndirectGot { .. } => {
            true
        }
    }
}

fn is_register_state_pseudo_call(name: &str) -> bool {
    matches!(
        name,
        "cbw"
            | "cwde"
            | "cdqe"
            | "cwd"
            | "cdq"
            | "cqo"
            | "cbtw"
            | "cwtl"
            | "cltq"
            | "cwtd"
            | "cltd"
            | "cqto"
            | "cpuid"
            | "rdtsc"
            | "rdtscp"
    )
}

fn should_capture_call_result_directly(target: &super::super::expression::CallTarget) -> bool {
    matches!(
        target,
        super::super::expression::CallTarget::Named(name)
            if matches!(name.as_str(), "cpuid" | "rdtsc" | "rdtscp")
    )
}

fn is_call_capture_boundary(target: &super::super::expression::CallTarget) -> bool {
    is_real_function_call(target) || should_capture_call_result_directly(target)
}

fn direct_capture_primary_register(
    target: &super::super::expression::CallTarget,
) -> Option<&'static str> {
    match target {
        super::super::expression::CallTarget::Named(name)
            if matches!(name.as_str(), "cpuid" | "rdtsc" | "rdtscp") =>
        {
            Some("eax")
        }
        _ => None,
    }
}

fn call_output_alias_groups(target: &super::super::expression::CallTarget) -> Vec<Vec<String>> {
    use super::super::expression::CallTarget;

    match target {
        CallTarget::Named(name) if name == "cpuid" => vec![
            vec!["eax".to_string(), "rax".to_string()],
            vec!["ebx".to_string(), "rbx".to_string()],
            vec!["ecx".to_string(), "rcx".to_string()],
            vec!["edx".to_string(), "rdx".to_string()],
        ],
        CallTarget::Named(name) if name == "rdtsc" => vec![
            vec!["eax".to_string(), "rax".to_string()],
            vec!["edx".to_string(), "rdx".to_string()],
        ],
        CallTarget::Named(name) if name == "rdtscp" => vec![
            vec!["eax".to_string(), "rax".to_string()],
            vec!["edx".to_string(), "rdx".to_string()],
            vec!["ecx".to_string(), "rcx".to_string()],
        ],
        _ => Vec::new(),
    }
}

fn secondary_call_result_replacements(
    target: &super::super::expression::CallTarget,
    capture_counter: u32,
) -> Vec<(Vec<String>, Expr)> {
    use super::super::expression::CallTarget;

    match target {
        CallTarget::Named(name) if name == "cpuid" => vec![
            (
                vec!["ebx".to_string(), "rbx".to_string()],
                Expr::unknown(format!("cpuid_ebx_{capture_counter}")),
            ),
            (
                vec!["ecx".to_string(), "rcx".to_string()],
                Expr::unknown(format!("cpuid_ecx_{capture_counter}")),
            ),
            (
                vec!["edx".to_string(), "rdx".to_string()],
                Expr::unknown(format!("cpuid_edx_{capture_counter}")),
            ),
        ],
        CallTarget::Named(name) if name == "rdtsc" => vec![(
            vec!["edx".to_string(), "rdx".to_string()],
            Expr::unknown(format!("rdtsc_high_{capture_counter}")),
        )],
        CallTarget::Named(name) if name == "rdtscp" => vec![
            (
                vec!["edx".to_string(), "rdx".to_string()],
                Expr::unknown(format!("rdtscp_high_{capture_counter}")),
            ),
            (
                vec!["ecx".to_string(), "rcx".to_string()],
                Expr::unknown(format!("rdtscp_aux_{capture_counter}")),
            ),
        ],
        _ => Vec::new(),
    }
}

fn call_has_output_use_before_clobber(
    statements: &[Expr],
    target: &super::super::expression::CallTarget,
) -> bool {
    let output_aliases = call_output_alias_groups(target);
    if output_aliases.is_empty() {
        return false;
    }
    let flat_aliases: Vec<String> = output_aliases.iter().flatten().cloned().collect();

    for stmt in statements {
        if let super::super::expression::ExprKind::Call { target, .. } = &stmt.kind {
            if is_call_capture_boundary(target) {
                break;
            }
        }

        if output_aliases
            .iter()
            .any(|aliases| expr_uses_any_alias(stmt, aliases))
        {
            return true;
        }

        if statement_clobbers_aliases(stmt, &flat_aliases) {
            break;
        }
    }

    false
}

/// Extracts call arguments and returns (arguments, statement_indices_used).
/// The statement indices are used to track which arg assignments should be removed.
#[derive(Debug, Clone, Copy)]
struct KnownCallSignature {
    fixed_arg_count: usize,
    variadic: bool,
}

fn normalize_known_call_name(name: &str) -> &str {
    let trimmed = name.trim_start_matches('_');
    trimmed.split('@').next().unwrap_or(trimmed)
}

fn resolved_known_call_name(
    target: &super::super::expression::CallTarget,
    binary_data: Option<&BinaryDataContext>,
) -> Option<String> {
    match target {
        super::super::expression::CallTarget::Named(name) => Some(name.clone()),
        super::super::expression::CallTarget::Direct { target, call_site } => binary_data
            .and_then(|ctx| {
                ctx.call_target_name_by_call_site(*call_site)
                    .or_else(|| ctx.call_target_name_by_address(*target))
            })
            .map(str::to_string),
        super::super::expression::CallTarget::Indirect(_)
        | super::super::expression::CallTarget::IndirectGot { .. } => None,
    }
}

fn builtin_call_type_database() -> &'static TypeDatabase {
    static DB: OnceLock<TypeDatabase> = OnceLock::new();
    DB.get_or_init(|| {
        let mut db = TypeDatabase::new();
        load_posix_types(&mut db);
        load_linux_types(&mut db);
        load_libc_functions(&mut db);
        db
    })
}

fn known_call_signature(
    target: &super::super::expression::CallTarget,
    binary_data: Option<&BinaryDataContext>,
) -> Option<KnownCallSignature> {
    if let Some(name) = resolved_known_call_name(target, binary_data) {
        if let Some(proto) =
            builtin_call_type_database().get_function(normalize_known_call_name(&name))
        {
            return Some(KnownCallSignature {
                fixed_arg_count: proto.parameters.len(),
                variadic: proto.variadic,
            });
        }
        if let Some(hinted_arg_count) = binary_data.and_then(|ctx| {
            ctx.call_signature_hint_by_name(&name)
                .or_else(|| ctx.call_signature_hint_by_name(normalize_known_call_name(&name)))
        }) {
            return Some(KnownCallSignature {
                fixed_arg_count: hinted_arg_count,
                variadic: false,
            });
        }
    }

    let hinted_arg_count = match target {
        super::super::expression::CallTarget::Direct { target, .. } => {
            binary_data?.call_signature_hint_by_address(*target)
        }
        super::super::expression::CallTarget::Named(_)
        | super::super::expression::CallTarget::Indirect(_)
        | super::super::expression::CallTarget::IndirectGot { .. } => None,
    }?;
    Some(KnownCallSignature {
        fixed_arg_count: hinted_arg_count,
        variadic: false,
    })
}

fn extract_call_arguments_with_indices(
    target: Option<&super::super::expression::CallTarget>,
    existing_args: &[Expr],
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    excluded_regs: &HashSet<String>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> (Vec<Expr>, Vec<usize>) {
    let signature = target.and_then(|target| known_call_signature(target, binary_data));
    let mut args: Vec<(usize, Option<usize>, Expr)> = Vec::new(); // (arg_idx, stmt_idx, value)
    let mut removable_indices = Vec::new();

    for (reg_name, (stmt_idx, value)) in arg_values {
        if excluded_regs.contains(&reg_name.to_lowercase()) {
            continue;
        }
        if let Some(arg_idx) = get_arg_register_index(reg_name) {
            if signature.is_some_and(|sig| !sig.variadic && arg_idx >= sig.fixed_arg_count) {
                if let Some(stmt_idx) = stmt_idx {
                    removable_indices.push(*stmt_idx);
                }
                continue;
            }
            args.push((arg_idx, *stmt_idx, value.clone()));
        }
    }

    // Sort by argument index
    args.sort_by_key(|(arg_idx, _, _)| *arg_idx);

    let family = infer_argument_abi_family(
        arg_values
            .keys()
            .map(String::as_str)
            .chain(excluded_regs.iter().map(String::as_str)),
    )
    .or(preferred_family);
    let explicit_by_index: HashMap<usize, (Option<usize>, Expr)> = args
        .into_iter()
        .map(|(arg_idx, stmt_idx, value)| (arg_idx, (stmt_idx, value)))
        .collect();
    let Some(max_idx) = explicit_by_index.keys().copied().max() else {
        if let Some(sig) = signature {
            if sig.fixed_arg_count == 0 {
                return (existing_args.to_vec(), removable_indices);
            }
            let Some(family) = infer_argument_abi_family(
                excluded_regs
                    .iter()
                    .map(String::as_str)
                    .chain(arg_values.keys().map(String::as_str)),
            )
            .or(preferred_family) else {
                return (existing_args.to_vec(), removable_indices);
            };
            let start_idx = existing_args.len();
            let end_idx = sig.fixed_arg_count.saturating_sub(1);
            let mut result = existing_args.to_vec();
            for expected_idx in start_idx..=end_idx {
                let Some(reg_name) = pass_through_arg_register_name(family, expected_idx) else {
                    break;
                };
                if excluded_regs.contains(reg_name) {
                    continue;
                }
                result.push(pass_through_arg_expr(reg_name));
            }
            return (result, removable_indices);
        }
        return (existing_args.to_vec(), removable_indices);
    };

    if !existing_args.is_empty() {
        if target.is_some_and(|target| {
            matches!(
                target,
                super::super::expression::CallTarget::Indirect(_)
                    | super::super::expression::CallTarget::IndirectGot { .. }
            )
        }) && signature.is_none()
        {
            return (existing_args.to_vec(), removable_indices);
        }
    }

    if signature.is_some_and(|sig| !sig.variadic && sig.fixed_arg_count == 0) {
        return (existing_args.to_vec(), removable_indices);
    }

    let max_idx = if let Some(sig) = signature {
        if sig.variadic {
            max_idx
        } else {
            max_idx.min(sig.fixed_arg_count.saturating_sub(1))
        }
    } else {
        max_idx
    };

    // Include contiguous arguments starting from 0. If a thin wrapper only
    // materializes later ABI registers (e.g. edx = 64; jmp memcmp), synthesize
    // untouched leading entry registers as pass-through arguments.
    let start_idx = existing_args.len();
    let mut result = existing_args.to_vec();
    let mut used_indices = removable_indices;
    for expected_idx in start_idx..=max_idx {
        if let Some((stmt_idx, value)) = explicit_by_index.get(&expected_idx) {
            result.push(value.clone());
            if let Some(stmt_idx) = stmt_idx {
                used_indices.push(*stmt_idx);
            }
            continue;
        }

        let Some(family) = family else {
            break;
        };
        let Some(reg_name) = pass_through_arg_register_name(family, expected_idx) else {
            break;
        };
        if excluded_regs.contains(reg_name) {
            continue;
        }
        result.push(pass_through_arg_expr(reg_name));
    }

    (result, used_indices)
}

fn synthesize_leading_passthrough_args_from_target(excluded_regs: &HashSet<String>) -> Vec<Expr> {
    let Some(family) = infer_argument_abi_family(excluded_regs.iter().map(String::as_str)) else {
        return Vec::new();
    };
    let Some(highest_target_idx) = excluded_regs
        .iter()
        .filter_map(|reg| get_arg_register_index(reg))
        .max()
    else {
        return Vec::new();
    };

    let mut args = Vec::new();
    for idx in 0..highest_target_idx {
        let Some(reg_name) = pass_through_arg_register_name(family, idx) else {
            break;
        };
        if excluded_regs.contains(reg_name) {
            continue;
        }
        args.push(pass_through_arg_expr(reg_name));
    }
    args
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatArgClass {
    Integer,
    Float,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArgumentAbiFamily {
    X86_64SysV,
    Aarch64,
    RiscV,
}

fn infer_argument_abi_family<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Option<ArgumentAbiFamily> {
    for name in names {
        let lower = name.to_lowercase();
        if get_arg_register_index(&lower).is_none()
            && get_float_arg_register_index(&lower).is_none()
        {
            continue;
        }
        if matches!(
            lower.as_str(),
            "rdi"
                | "edi"
                | "rsi"
                | "esi"
                | "rdx"
                | "edx"
                | "rcx"
                | "ecx"
                | "r8"
                | "r8d"
                | "r9"
                | "r9d"
                | "xmm0"
                | "xmm1"
                | "xmm2"
                | "xmm3"
                | "xmm4"
                | "xmm5"
                | "xmm6"
                | "xmm7"
        ) {
            return Some(ArgumentAbiFamily::X86_64SysV);
        }
        if lower.starts_with('x')
            || lower.starts_with('w')
            || matches!(
                lower.as_str(),
                "d0" | "d1" | "d2" | "d3" | "d4" | "d5" | "d6" | "d7"
            )
        {
            return Some(ArgumentAbiFamily::Aarch64);
        }
        if lower.starts_with('a') {
            return Some(ArgumentAbiFamily::RiscV);
        }
    }

    None
}

fn argument_abi_family_from_arch(arch: Architecture) -> Option<ArgumentAbiFamily> {
    match arch {
        Architecture::X86_64 => Some(ArgumentAbiFamily::X86_64SysV),
        Architecture::Arm64 => Some(ArgumentAbiFamily::Aarch64),
        Architecture::RiscV64 => Some(ArgumentAbiFamily::RiscV),
        _ => None,
    }
}

fn pass_through_arg_register_name(family: ArgumentAbiFamily, index: usize) -> Option<&'static str> {
    match family {
        ArgumentAbiFamily::X86_64SysV => {
            ["rdi", "rsi", "rdx", "rcx", "r8", "r9"].get(index).copied()
        }
        ArgumentAbiFamily::Aarch64 => ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
            .get(index)
            .copied(),
        ArgumentAbiFamily::RiscV => ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
            .get(index)
            .copied(),
    }
}

fn pass_through_arg_expr(reg_name: &str) -> Expr {
    Expr::var(super::super::expression::Variable::reg(reg_name, 8))
}

fn tracked_call_arg_key(
    var: &Variable,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Option<String> {
    if is_tracked_call_arg_register(&var.name) {
        return Some(var.name.to_lowercase());
    }

    match var.kind {
        super::super::expression::VarKind::Arg(index) => preferred_family
            .and_then(|family| pass_through_arg_register_name(family, index as usize))
            .map(str::to_string)
            .or_else(|| Some(format!("arg{}", index))),
        _ => None,
    }
}

fn call_result_placeholder_expr(
    preferred_family: Option<ArgumentAbiFamily>,
    dest_reg_name: &str,
    dest_reg_size: u8,
) -> Option<Expr> {
    let family = preferred_family.or_else(|| infer_argument_abi_family([dest_reg_name]))?;
    let reg_name = match family {
        ArgumentAbiFamily::X86_64SysV => {
            if dest_reg_size <= 4 {
                "eax"
            } else {
                "rax"
            }
        }
        ArgumentAbiFamily::Aarch64 => {
            if dest_reg_size <= 4 {
                "w0"
            } else {
                "x0"
            }
        }
        ArgumentAbiFamily::RiscV => "a0",
    };
    let reg_size = if matches!(reg_name, "eax" | "w0") {
        4
    } else {
        8
    };
    Some(Expr::var(super::super::expression::Variable::reg(
        reg_name, reg_size,
    )))
}

fn pass_through_float_arg_register_name(
    family: ArgumentAbiFamily,
    index: usize,
) -> Option<&'static str> {
    match family {
        ArgumentAbiFamily::X86_64SysV => [
            "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
        ]
        .get(index)
        .copied(),
        ArgumentAbiFamily::Aarch64 => ["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"]
            .get(index)
            .copied(),
        ArgumentAbiFamily::RiscV => None,
    }
}

fn pass_through_float_arg_expr(reg_name: &str) -> Expr {
    let size = if reg_name.starts_with("xmm") { 16 } else { 8 };
    Expr::var(super::super::expression::Variable::reg(reg_name, size))
}

fn is_tracked_call_arg_register(name: &str) -> bool {
    get_arg_register_index(name).is_some() || get_float_arg_register_index(name).is_some()
}

fn get_float_arg_register_index(name: &str) -> Option<usize> {
    match name.to_lowercase().as_str() {
        "xmm0" | "d0" => Some(0),
        "xmm1" | "d1" => Some(1),
        "xmm2" | "d2" => Some(2),
        "xmm3" | "d3" => Some(3),
        "xmm4" | "d4" => Some(4),
        "xmm5" | "d5" => Some(5),
        "xmm6" | "d6" => Some(6),
        "xmm7" | "d7" => Some(7),
        _ => None,
    }
}

fn try_recover_format_call_arguments(
    target: &super::super::expression::CallTarget,
    args: &[Expr],
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    excluded_regs: &HashSet<String>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Option<(Vec<Expr>, Vec<usize>)> {
    let target_name = match target {
        super::super::expression::CallTarget::Named(name) => Some(name.as_str()),
        _ => None,
    };
    let spec = detect_format_call(target_name, args, binary_data)?;
    if args.len() < spec.fixed_arg_count
        || args.len() > spec.fixed_arg_count + spec.arg_classes.len()
    {
        return None;
    }

    let family =
        infer_argument_abi_family(arg_values.keys().map(String::as_str)).or(preferred_family)?;
    let mut recovered_args = args[..spec.fixed_arg_count].to_vec();
    let existing_variadic_args = &args[spec.fixed_arg_count..];
    let mut existing_variadic_index = 0usize;
    let mut used_stmt_indices = Vec::new();
    let mut int_slot = spec.fixed_arg_count;
    let mut float_slot = 0usize;

    for class in spec.arg_classes {
        match class {
            FormatArgClass::Integer => {
                if let Some((stmt_idx, value)) = lookup_slot_value_or_passthrough(
                    arg_values,
                    existing_variadic_args,
                    &mut existing_variadic_index,
                    family,
                    int_slot,
                    excluded_regs,
                ) {
                    if let Some(stmt_idx) = stmt_idx {
                        used_stmt_indices.push(stmt_idx);
                    }
                    recovered_args.push(value);
                } else if let Some(value) = reuse_existing_integer_variadic_arg(
                    existing_variadic_args,
                    &mut existing_variadic_index,
                ) {
                    recovered_args.push(value);
                } else {
                    let reg_name = pass_through_arg_register_name(family, int_slot)?;
                    if excluded_regs.contains(reg_name) {
                        return None;
                    }
                    recovered_args.push(pass_through_arg_expr(reg_name));
                }
                int_slot += 1;
            }
            FormatArgClass::Float => {
                if let Some((stmt_idx, value)) = lookup_float_slot_value_or_passthrough(
                    arg_values,
                    existing_variadic_args,
                    &mut existing_variadic_index,
                    family,
                    float_slot,
                    excluded_regs,
                ) {
                    if let Some(stmt_idx) = stmt_idx {
                        used_stmt_indices.push(stmt_idx);
                    }
                    recovered_args.push(value);
                } else if let Some(value) = reuse_existing_float_variadic_arg(
                    existing_variadic_args,
                    &mut existing_variadic_index,
                ) {
                    recovered_args.push(value);
                } else {
                    let reg_name = pass_through_float_arg_register_name(family, float_slot)?;
                    if excluded_regs.contains(reg_name) {
                        return None;
                    }
                    recovered_args.push(pass_through_float_arg_expr(reg_name));
                }
                float_slot += 1;
            }
        }
    }

    Some((recovered_args, used_stmt_indices))
}

fn lookup_slot_value_or_passthrough(
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    existing_variadic_args: &[Expr],
    existing_variadic_index: &mut usize,
    family: ArgumentAbiFamily,
    int_slot: usize,
    excluded_regs: &HashSet<String>,
) -> Option<(Option<usize>, Expr)> {
    let reg_name = pass_through_arg_register_name(family, int_slot)?;
    if excluded_regs.contains(reg_name) {
        return None;
    }
    if let Some((stmt_idx, value)) = lookup_tracked_register_value(arg_values, reg_name) {
        return Some((stmt_idx, value));
    }

    if existing_variadic_args
        .get(*existing_variadic_index)
        .is_some_and(expr_looks_float_like)
    {
        return None;
    }

    None
}

fn lookup_float_slot_value_or_passthrough(
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    existing_variadic_args: &[Expr],
    existing_variadic_index: &mut usize,
    family: ArgumentAbiFamily,
    float_slot: usize,
    excluded_regs: &HashSet<String>,
) -> Option<(Option<usize>, Expr)> {
    let reg_name = pass_through_float_arg_register_name(family, float_slot)?;
    if excluded_regs.contains(reg_name) {
        return None;
    }
    if let Some((stmt_idx, value)) = lookup_tracked_register_value(arg_values, reg_name) {
        return Some((stmt_idx, value));
    }

    if existing_variadic_args
        .get(*existing_variadic_index)
        .is_some_and(expr_looks_float_like)
    {
        return None;
    }

    None
}

fn reuse_existing_integer_variadic_arg(
    existing_variadic_args: &[Expr],
    existing_variadic_index: &mut usize,
) -> Option<Expr> {
    let candidate = existing_variadic_args.get(*existing_variadic_index)?;
    if expr_looks_float_like(candidate) {
        return None;
    }
    *existing_variadic_index += 1;
    Some(candidate.clone())
}

fn reuse_existing_float_variadic_arg(
    existing_variadic_args: &[Expr],
    existing_variadic_index: &mut usize,
) -> Option<Expr> {
    let candidate = existing_variadic_args.get(*existing_variadic_index)?;
    if !expr_looks_float_like(candidate) {
        return None;
    }
    *existing_variadic_index += 1;
    Some(candidate.clone())
}

fn expr_looks_float_like(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(var) => {
            let lower = var.name.to_lowercase();
            lower.starts_with("xmm") || lower.starts_with('d') || lower.starts_with("farg")
        }
        ExprKind::Unknown(name) => {
            let lower = name.to_lowercase();
            lower.starts_with("farg") || lower.starts_with("xmm")
        }
        ExprKind::Cast { expr, .. } => expr_looks_float_like(expr),
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct FormatCallRecovery {
    fixed_arg_count: usize,
    arg_classes: Vec<FormatArgClass>,
}

fn detect_format_call(
    target_name: Option<&str>,
    args: &[Expr],
    binary_data: Option<&BinaryDataContext>,
) -> Option<FormatCallRecovery> {
    let named_fixed_arg_count = target_name.and_then(|name| {
        let normalized = name
            .split_once('@')
            .map_or(name, |(base, _)| base)
            .trim_start_matches('_');
        match normalized {
            "printf" => Some(1),
            "fprintf" | "dprintf" | "syslog" => Some(2),
            "sprintf" | "asprintf" => Some(2),
            "snprintf" => Some(3),
            "printf_chk" => Some(2),
            "fprintf_chk" | "dprintf_chk" => Some(3),
            "sprintf_chk" | "asprintf_chk" => Some(4),
            "snprintf_chk" => Some(5),
            _ => None,
        }
    });

    let candidate_counts: Vec<usize> = if let Some(count) = named_fixed_arg_count {
        vec![count]
    } else {
        (1..=args.len().min(5)).collect()
    };

    for fixed_arg_count in candidate_counts {
        if !is_plausible_format_call_prefix(args, fixed_arg_count) {
            continue;
        }
        let Some(format_arg) = args.get(fixed_arg_count.saturating_sub(1)) else {
            continue;
        };
        let Some(format) = resolve_string_literal(format_arg, binary_data) else {
            continue;
        };
        let arg_classes = parse_printf_format_arg_classes(&format);
        if arg_classes.is_empty() {
            continue;
        }

        return Some(FormatCallRecovery {
            fixed_arg_count,
            arg_classes,
        });
    }

    None
}

fn is_plausible_format_call_prefix(args: &[Expr], fixed_arg_count: usize) -> bool {
    use super::super::expression::ExprKind;

    if args.len() < fixed_arg_count {
        return false;
    }

    match fixed_arg_count {
        1 => true,
        2 => matches!(
            args.first().map(|expr| &expr.kind),
            Some(ExprKind::IntLit(_))
        ),
        3 | 4 => matches!(
            args.get(1).map(|expr| &expr.kind),
            Some(ExprKind::IntLit(_))
        ),
        5 => matches!(
            args.get(2).map(|expr| &expr.kind),
            Some(ExprKind::IntLit(_))
        ),
        _ => false,
    }
}

fn lookup_tracked_register_value(
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    reg_name: &str,
) -> Option<(Option<usize>, Expr)> {
    if let Some((stmt_idx, value)) = arg_values.get(&reg_name.to_lowercase()) {
        return Some((*stmt_idx, value.clone()));
    }
    for alias in get_register_aliases(reg_name) {
        if let Some((stmt_idx, value)) = arg_values.get(&alias) {
            return Some((*stmt_idx, value.clone()));
        }
    }
    None
}

fn resolve_string_literal(expr: &Expr, binary_data: Option<&BinaryDataContext>) -> Option<String> {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::IntLit(value) if *value >= 0 && *value <= i128::from(u64::MAX) => {
            read_c_string(binary_data?, *value as u64)
        }
        ExprKind::GotRef { address, .. } => read_c_string(binary_data?, *address),
        ExprKind::Unknown(text)
            if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 =>
        {
            Some(text[1..text.len() - 1].to_string())
        }
        _ => None,
    }
}

fn read_c_string(binary_data: &BinaryDataContext, address: u64) -> Option<String> {
    let (section, base) = binary_data.section_containing(address)?;
    let start = usize::try_from(address.checked_sub(base)?).ok()?;
    let suffix = section.get(start..)?;
    let end = suffix.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&suffix[..end]).ok().map(str::to_string)
}

fn parse_printf_format_arg_classes(format: &str) -> Vec<FormatArgClass> {
    let bytes = format.as_bytes();
    let mut i = 0usize;
    let mut classes = Vec::new();

    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            break;
        }
        if bytes[i] == b'%' {
            i += 1;
            continue;
        }

        while i < bytes.len() && matches!(bytes[i], b'#' | b'0' | b'-' | b' ' | b'+' | b'\'') {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'*' {
            classes.push(FormatArgClass::Integer);
            i += 1;
        } else {
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
        }
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'*' {
                classes.push(FormatArgClass::Integer);
                i += 1;
            } else {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
        }

        let mut long_double = false;
        if i + 1 < bytes.len() && (&bytes[i..i + 2] == b"hh" || &bytes[i..i + 2] == b"ll") {
            i += 2;
        } else if i < bytes.len() {
            match bytes[i] {
                b'h' | b'l' | b'j' | b'z' | b't' => i += 1,
                b'L' => {
                    long_double = true;
                    i += 1;
                }
                _ => {}
            }
        }

        if i >= bytes.len() {
            break;
        }
        match bytes[i] as char {
            'd' | 'i' | 'u' | 'o' | 'x' | 'X' | 'c' | 's' | 'p' | 'n' => {
                classes.push(FormatArgClass::Integer);
            }
            'a' | 'A' | 'e' | 'E' | 'f' | 'F' | 'g' | 'G' if !long_double => {
                classes.push(FormatArgClass::Float);
            }
            _ => {}
        }
        i += 1;
    }

    classes
}

fn extract_materializable_condition_call(expr: &Expr) -> Option<(Expr, bool)> {
    match &expr.kind {
        ExprKind::Call { target, .. } if is_real_function_call(target) => {
            Some((expr.clone(), false))
        }
        ExprKind::UnaryOp {
            op: super::super::expression::UnaryOpKind::LogicalNot,
            operand,
        } => match &operand.kind {
            ExprKind::Call { target, .. } if is_real_function_call(target) => {
                Some(((**operand).clone(), true))
            }
            _ => None,
        },
        _ => None,
    }
}

fn first_return_value_alias_use_in_nodes(nodes: &[StructuredNode]) -> Option<String> {
    nodes
        .iter()
        .find_map(first_return_value_alias_use_in_body_node)
}

fn first_return_value_alias_use_in_body_node(node: &StructuredNode) -> Option<String> {
    match node {
        StructuredNode::Block { statements, .. } => statements
            .iter()
            .find_map(first_return_value_alias_use_in_expr),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => first_return_value_alias_use_in_expr(condition)
            .or_else(|| first_return_value_alias_use_in_nodes(then_body))
            .or_else(|| {
                else_body
                    .as_ref()
                    .and_then(|body| first_return_value_alias_use_in_nodes(body))
            }),
        StructuredNode::While {
            condition, body, ..
        }
        | StructuredNode::DoWhile {
            condition, body, ..
        } => first_return_value_alias_use_in_expr(condition)
            .or_else(|| first_return_value_alias_use_in_nodes(body)),
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => init
            .as_ref()
            .and_then(first_return_value_alias_use_in_expr)
            .or_else(|| first_return_value_alias_use_in_expr(condition))
            .or_else(|| {
                update
                    .as_ref()
                    .and_then(first_return_value_alias_use_in_expr)
            })
            .or_else(|| first_return_value_alias_use_in_nodes(body)),
        StructuredNode::Loop { body, .. } | StructuredNode::Sequence(body) => {
            first_return_value_alias_use_in_nodes(body)
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => first_return_value_alias_use_in_expr(value)
            .or_else(|| {
                cases
                    .iter()
                    .find_map(|(_, body)| first_return_value_alias_use_in_nodes(body))
            })
            .or_else(|| {
                default
                    .as_ref()
                    .and_then(|body| first_return_value_alias_use_in_nodes(body))
            }),
        StructuredNode::Return(Some(expr)) | StructuredNode::Expr(expr) => {
            first_return_value_alias_use_in_expr(expr)
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => first_return_value_alias_use_in_nodes(try_body).or_else(|| {
            catch_handlers
                .iter()
                .find_map(|handler| first_return_value_alias_use_in_nodes(&handler.body))
        }),
        StructuredNode::Return(None)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_)
        | StructuredNode::Label(_) => None,
    }
}

fn rewrite_terminal_bare_returns(
    mut body: Vec<StructuredNode>,
    value: &Expr,
) -> Vec<StructuredNode> {
    let Some(last) = body.pop() else {
        return body;
    };
    body.push(rewrite_terminal_bare_return_node(last, value));
    body
}

fn rewrite_terminal_bare_return_node(node: StructuredNode, value: &Expr) -> StructuredNode {
    match node {
        StructuredNode::Return(None) => StructuredNode::Return(Some(value.clone())),
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(rewrite_terminal_bare_returns(nodes, value))
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: rewrite_terminal_bare_returns(then_body, value),
            else_body: else_body.map(|body| rewrite_terminal_bare_returns(body, value)),
        },
        other => other,
    }
}

fn materialize_folded_condition_call_result(
    node: StructuredNode,
    capture_counter: &mut u32,
) -> StructuredNode {
    let (condition, then_body, else_body) = match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => (condition, then_body, else_body),
        other => return other,
    };

    let Some((call_expr, negated)) = extract_materializable_condition_call(&condition) else {
        return StructuredNode::If {
            condition,
            then_body,
            else_body,
        };
    };

    let primary_alias = first_return_value_alias_use_in_nodes(&then_body).or_else(|| {
        else_body
            .as_ref()
            .and_then(|body| first_return_value_alias_use_in_nodes(body))
    });
    let Some(primary_alias) = primary_alias else {
        return StructuredNode::If {
            condition,
            then_body,
            else_body,
        };
    };

    let temp_name = format!("ret_{}", *capture_counter);
    *capture_counter += 1;
    let temp_expr = Expr::var(Variable {
        kind: super::super::expression::VarKind::Temp(*capture_counter),
        name: temp_name,
        size: 8,
    });
    let aliases = broad_return_value_aliases(&primary_alias);
    let then_body = rewrite_terminal_bare_returns(
        then_body
            .into_iter()
            .map(|body_node| {
                substitute_return_value_aliases_in_node(body_node, &aliases, &temp_expr)
            })
            .collect(),
        &temp_expr,
    );
    let else_body = else_body.map(|body| {
        rewrite_terminal_bare_returns(
            body.into_iter()
                .map(|body_node| {
                    substitute_return_value_aliases_in_node(body_node, &aliases, &temp_expr)
                })
                .collect(),
            &temp_expr,
        )
    });
    let condition = if negated {
        Expr::unary(
            super::super::expression::UnaryOpKind::LogicalNot,
            temp_expr.clone(),
        )
        .simplify()
    } else {
        temp_expr.clone()
    };

    StructuredNode::Sequence(vec![
        StructuredNode::Expr(Expr::assign(temp_expr.clone(), call_expr)),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        },
    ])
}

/// Merges return value captures across basic block boundaries.
/// Transforms patterns where:
///   Block1: ...; func();
///   Block2: var = eax; ...
/// Into:
///   Block1: ...
///   Block2: var = func(); ...
pub(super) fn merge_return_value_captures(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut capture_counter = 0u32;
    merge_return_value_captures_with_counter(nodes, &mut capture_counter)
}

pub(super) fn merge_return_value_captures_with_counter(
    nodes: Vec<StructuredNode>,
    capture_counter: &mut u32,
) -> Vec<StructuredNode> {
    use super::super::expression::ExprKind;

    let mut result: Vec<StructuredNode> = Vec::with_capacity(nodes.len());

    for node in nodes {
        // First, recursively process nested structures
        let mut node = merge_return_value_captures_node(node, capture_counter);
        node = materialize_folded_condition_call_result(node, capture_counter);

        if let Some((aliases, primary_alias)) = first_return_value_alias_use_in_node(&node) {
            if let Some(block_index) = find_previous_call_capture_block(&result, &aliases) {
                if let Some(temp_expr) = capture_previous_call_result(
                    &mut result,
                    block_index,
                    capture_counter,
                    &primary_alias,
                ) {
                    node = substitute_return_value_aliases_in_node(node, &aliases, &temp_expr);
                }
            }
        }

        match node {
            StructuredNode::Block {
                id,
                mut statements,
                address_range,
            } => {
                // Check if first statement is `var = eax` (return value capture)
                if !statements.is_empty() {
                    let should_merge = if let ExprKind::Assign { lhs: _, rhs } = &statements[0].kind
                    {
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

                    capture_return_register_uses_from_previous_block(
                        &mut result,
                        &mut statements,
                        capture_counter,
                    );
                }
                let statements = capture_return_register_uses_in_block(statements, capture_counter);
                result.push(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                });
            }
            StructuredNode::Return(Some(mut expr)) => {
                capture_return_register_uses_in_return(&mut result, &mut expr, capture_counter);
                result.push(StructuredNode::Return(Some(expr)));
            }
            other => result.push(other),
        }
    }

    result
}

/// Recursively applies return value capture merging to nested structures.
pub(super) fn merge_return_value_captures_node(
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

fn capture_return_register_uses_from_previous_block(
    result: &mut [StructuredNode],
    statements: &mut Vec<Expr>,
    capture_counter: &mut u32,
) {
    if capture_deref_load_from_previous_block(result, statements, capture_counter) {
        return;
    }

    let Some(primary_reg) = first_return_register_use_before_clobber(statements) else {
        return;
    };

    let aliases = return_register_aliases(&primary_reg);
    let Some(block_index) = find_previous_call_capture_block(result, &aliases) else {
        return;
    };
    let Some(temp_expr) =
        capture_previous_call_result(result, block_index, capture_counter, &primary_reg)
    else {
        return;
    };

    substitute_return_register_uses_until_clobber(statements, &aliases, &temp_expr);
}

#[derive(Debug, Clone)]
struct DerefLoadCapture {
    statement_index: usize,
    pointer_reg: String,
    load_size: u8,
    dest_aliases: Option<Vec<String>>,
    can_elide_load: bool,
    is_self_load: bool,
}

fn capture_deref_load_from_previous_block(
    result: &mut [StructuredNode],
    statements: &mut Vec<Expr>,
    capture_counter: &mut u32,
) -> bool {
    let Some(load) = first_deref_load_from_return_register_before_clobber(statements) else {
        return false;
    };

    let pointer_aliases = return_value_aliases(&load.pointer_reg);
    let Some(block_index) = find_previous_call_capture_block(result, &pointer_aliases) else {
        return false;
    };
    let Some(temp_expr) =
        capture_previous_call_result(result, block_index, capture_counter, &load.pointer_reg)
    else {
        return false;
    };

    let deref_expr = Expr::deref(temp_expr, load.load_size);
    let has_following_local_use = load.dest_aliases.as_ref().is_some_and(|aliases| {
        statements[load.statement_index + 1..]
            .iter()
            .take_while(|stmt| !statement_clobbers_return_register(stmt, aliases))
            .any(|stmt| expr_uses_any_alias(stmt, aliases))
    });

    if load.can_elide_load && has_following_local_use {
        let Some(dest_aliases) = load.dest_aliases.as_ref() else {
            return false;
        };

        statements.remove(load.statement_index);
        if load.statement_index < statements.len() {
            if load.is_self_load {
                substitute_loaded_return_value_uses_until_clobber(
                    &mut statements[load.statement_index..],
                    dest_aliases,
                    load.load_size,
                    &deref_expr,
                );
            } else {
                substitute_return_register_uses_until_clobber(
                    &mut statements[load.statement_index..],
                    dest_aliases,
                    &deref_expr,
                );
            }
        }
        return true;
    }

    let lhs = match &statements[load.statement_index].kind {
        super::super::expression::ExprKind::Assign { lhs, .. } => (**lhs).clone(),
        _ => return false,
    };
    statements[load.statement_index] = Expr::assign(lhs, deref_expr);
    true
}

fn capture_return_register_uses_in_return(
    result: &mut [StructuredNode],
    expr: &mut Expr,
    capture_counter: &mut u32,
) {
    let uses = collect_return_register_uses(expr);
    let Some(primary_reg) = uses.into_iter().next() else {
        return;
    };

    let aliases = return_register_aliases(&primary_reg);
    let Some(block_index) = find_previous_call_capture_block(result, &aliases) else {
        return;
    };
    let Some(temp_expr) =
        capture_previous_call_result(result, block_index, capture_counter, &primary_reg)
    else {
        return;
    };

    *expr = substitute_return_register_uses(expr.clone(), &aliases, &temp_expr);
}

pub(super) fn capture_return_register_uses_in_block(
    statements: Vec<Expr>,
    capture_counter: &mut u32,
) -> Vec<Expr> {
    use super::super::expression::{ExprKind, VarKind, Variable};

    let mut stmts = statements;
    let mut i = 0usize;

    while i + 1 < stmts.len() {
        let call_target = match &stmts[i].kind {
            ExprKind::Call { target, .. } if is_call_capture_boundary(target) => Some(target),
            _ => None,
        };
        if call_target.is_none() {
            i += 1;
            continue;
        }

        if let Some(load) = match_deref_load_from_return_register(&stmts[i + 1], i + 1) {
            let Some(temp_expr) =
                capture_current_call_result(&mut stmts, i, capture_counter, &load.pointer_reg)
            else {
                i += 1;
                continue;
            };

            let deref_expr = Expr::deref(temp_expr, load.load_size);

            if load.can_elide_load {
                let Some(dest_aliases) = load.dest_aliases.as_ref() else {
                    i += 1;
                    continue;
                };

                stmts.remove(load.statement_index);
                if load.statement_index < stmts.len() {
                    substitute_return_register_uses_until_clobber(
                        &mut stmts[load.statement_index..],
                        dest_aliases,
                        &deref_expr,
                    );
                }
                i = load.statement_index;
                continue;
            }

            let lhs = match &stmts[load.statement_index].kind {
                ExprKind::Assign { lhs, .. } => (**lhs).clone(),
                _ => {
                    i += 1;
                    continue;
                }
            };
            stmts[load.statement_index] = Expr::assign(lhs, deref_expr);
            i = load.statement_index + 1;
            continue;
        }

        let next_regs = collect_return_register_uses(&stmts[i + 1]);
        let direct_capture = call_target.is_some_and(should_capture_call_result_directly);
        let primary_reg = if !next_regs.is_empty() {
            next_regs
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| "x0".to_string())
        } else if let Some(reg) = first_return_register_use_before_clobber(&stmts[i + 1..]) {
            reg
        } else if direct_capture {
            let Some(target) = call_target else {
                i += 1;
                continue;
            };
            if !call_has_output_use_before_clobber(&stmts[i + 1..], target) {
                i += 1;
                continue;
            }
            let Some(reg) = direct_capture_primary_register(target)
                .map(str::to_string)
                .or_else(|| first_return_register_use_before_clobber(&stmts[i + 1..]))
            else {
                i += 1;
                continue;
            };
            reg
        } else {
            i += 1;
            continue;
        };
        let aliases = return_register_aliases(&primary_reg);

        if direct_capture {
            let secondary_replacements = call_target
                .map(|target| {
                    secondary_call_result_replacements(target, capture_counter.saturating_add(1))
                })
                .unwrap_or_default();
            let Some(temp_expr) =
                capture_current_call_result(&mut stmts, i, capture_counter, &primary_reg)
            else {
                i += 1;
                continue;
            };

            let mut j = i + 1;
            while j < stmts.len() {
                if j > i + 1 {
                    if let ExprKind::Call { target, .. } = &stmts[j].kind {
                        if is_call_capture_boundary(target) {
                            break;
                        }
                    }
                }
                if statement_clobbers_return_register(&stmts[j], &aliases) {
                    break;
                }
                if secondary_replacements
                    .iter()
                    .any(|(aliases, _)| statement_clobbers_aliases(&stmts[j], aliases))
                {
                    break;
                }
                let mut rewritten =
                    substitute_return_register_uses(stmts[j].clone(), &aliases, &temp_expr);
                for (aliases, replacement) in &secondary_replacements {
                    let substitutions: HashMap<String, Expr> = aliases
                        .iter()
                        .cloned()
                        .map(|alias| (alias, replacement.clone()))
                        .collect();
                    rewritten = substitute_vars(&rewritten, &substitutions);
                }
                stmts[j] = rewritten;
                j += 1;
            }

            i = j;
            continue;
        }

        let reg_size = if matches!(primary_reg.as_str(), "eax" | "w0") {
            4
        } else {
            8
        };
        if primary_reg == "ret" || primary_reg.starts_with("ret_") {
            let aliases = broad_return_value_aliases(&primary_reg);
            let Some(temp_expr) =
                capture_current_call_result(&mut stmts, i, capture_counter, &primary_reg)
            else {
                i += 1;
                continue;
            };

            let mut j = i + 1;
            while j < stmts.len() {
                if j > i + 1 {
                    if let ExprKind::Call { target, .. } = &stmts[j].kind {
                        if is_call_capture_boundary(target) {
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
            continue;
        }

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
                    if is_call_capture_boundary(target) {
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

fn capture_current_call_result(
    statements: &mut [Expr],
    call_index: usize,
    capture_counter: &mut u32,
    primary_reg: &str,
) -> Option<Expr> {
    use super::super::expression::{ExprKind, VarKind, Variable};

    let reg_size = if matches!(primary_reg, "eax" | "w0") {
        4
    } else {
        8
    };
    let temp_name = format!("ret_{}", *capture_counter);
    *capture_counter += 1;
    let temp_expr = Expr::var(Variable {
        kind: VarKind::Temp(*capture_counter),
        name: temp_name,
        size: reg_size,
    });

    let Some(Expr {
        kind: ExprKind::Call { target, args },
    }) = statements.get(call_index).cloned()
    else {
        return None;
    };

    if !is_call_capture_boundary(&target) {
        return None;
    }

    statements[call_index] = Expr::assign(temp_expr.clone(), Expr::call(target, args));
    Some(temp_expr)
}

fn first_return_register_use_before_clobber(statements: &[Expr]) -> Option<String> {
    let all_aliases = return_value_aliases("rax")
        .into_iter()
        .chain(return_value_aliases("x0"))
        .chain(return_value_aliases("a0"))
        .collect::<Vec<_>>();

    for stmt in statements {
        if let super::super::expression::ExprKind::Call { target, .. } = &stmt.kind {
            if is_call_capture_boundary(target) {
                break;
            }
        }

        let uses = collect_return_register_uses(stmt);
        if let Some(reg) = uses.into_iter().next() {
            return Some(reg);
        }

        if statement_clobbers_return_register(stmt, &all_aliases) {
            break;
        }
    }

    None
}

fn first_deref_load_from_return_register_before_clobber(
    statements: &[Expr],
) -> Option<DerefLoadCapture> {
    let all_aliases = [
        "eax".to_string(),
        "rax".to_string(),
        "w0".to_string(),
        "x0".to_string(),
        "arg0".to_string(),
        "a0".to_string(),
    ];

    for (idx, stmt) in statements.iter().enumerate() {
        if let super::super::expression::ExprKind::Call { target, .. } = &stmt.kind {
            if is_call_capture_boundary(target) {
                break;
            }
        }

        if let Some(capture) = match_deref_load_from_return_register(stmt, idx) {
            return Some(capture);
        }

        if !collect_return_register_uses(stmt).is_empty() {
            return None;
        }

        if statement_clobbers_return_register(stmt, &all_aliases) {
            break;
        }
    }

    None
}

fn match_deref_load_from_return_register(
    stmt: &Expr,
    statement_index: usize,
) -> Option<DerefLoadCapture> {
    use super::super::expression::ExprKind;

    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
        return None;
    };
    let ExprKind::Deref { addr, size } = &rhs.kind else {
        return None;
    };
    let ExprKind::Var(pointer_var) = &addr.kind else {
        return None;
    };

    let pointer_reg = pointer_var.name.to_lowercase();
    if pointer_reg == "arg0" {
        return None;
    }
    if !is_return_value_alias(&pointer_reg) {
        return None;
    }

    let (dest_aliases, can_elide_load) = match &lhs.kind {
        ExprKind::Var(dest_var) => {
            let lower = dest_var.name.to_lowercase();
            let aliases = if is_return_value_alias(&lower) {
                return_value_aliases(&lower)
            } else {
                vec![lower.clone()]
            };
            let can_elide = is_return_value_alias(&lower);
            (Some(aliases), can_elide)
        }
        _ => (None, false),
    };
    let is_self_load = match &lhs.kind {
        ExprKind::Var(dest_var) => {
            let lower = dest_var.name.to_lowercase();
            return_value_aliases(&lower).contains(&pointer_reg)
        }
        _ => false,
    };

    Some(DerefLoadCapture {
        statement_index,
        pointer_reg,
        load_size: *size,
        dest_aliases,
        can_elide_load,
        is_self_load,
    })
}

fn is_return_value_alias(name: &str) -> bool {
    is_return_register(name) || name == "arg0" || name == "ret" || name.starts_with("ret_")
}

fn return_value_aliases(name: &str) -> Vec<String> {
    if name == "ret" || name.starts_with("ret_") {
        vec![name.to_string()]
    } else {
        return_register_aliases(name)
    }
}

fn broad_return_value_aliases(name: &str) -> Vec<String> {
    let mut aliases = return_value_aliases(name);
    for alias in [
        "al", "ax", "eax", "rax", "ret", "ret_0", "arg0", "w0", "x0", "a0",
    ] {
        if !aliases.iter().any(|existing| existing == alias) {
            aliases.push(alias.to_string());
        }
    }
    aliases
}

fn first_return_value_alias_use_in_node(node: &StructuredNode) -> Option<(Vec<String>, String)> {
    match node {
        StructuredNode::Block { statements, .. } => statements.first().and_then(|stmt| {
            let super::super::expression::ExprKind::Call { target, .. } = &stmt.kind else {
                return None;
            };
            if !is_call_capture_boundary(target) {
                return None;
            }
            collect_return_register_uses(stmt)
                .into_iter()
                .next()
                .map(|name| (broad_return_value_aliases(&name), name))
        }),
        StructuredNode::If { condition, .. }
        | StructuredNode::While { condition, .. }
        | StructuredNode::DoWhile { condition, .. } => {
            first_return_value_alias_use_in_expr(condition)
                .map(|name| (broad_return_value_aliases(&name), name))
        }
        StructuredNode::For {
            init,
            condition,
            update,
            ..
        } => init
            .as_ref()
            .and_then(first_return_value_alias_use_in_expr)
            .or_else(|| first_return_value_alias_use_in_expr(condition))
            .or_else(|| {
                update
                    .as_ref()
                    .and_then(first_return_value_alias_use_in_expr)
            })
            .map(|name| (broad_return_value_aliases(&name), name)),
        StructuredNode::Switch { value, .. } => first_return_value_alias_use_in_expr(value)
            .map(|name| (broad_return_value_aliases(&name), name)),
        _ => None,
    }
}

fn first_return_value_alias_use_in_expr(expr: &Expr) -> Option<String> {
    fn walk(expr: &Expr) -> Option<String> {
        use super::super::expression::{CallTarget, ExprKind};

        match &expr.kind {
            ExprKind::Var(var) => {
                let lower = var.name.to_lowercase();
                is_return_value_alias(&lower).then_some(lower)
            }
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                is_return_value_alias(&lower).then_some(lower)
            }
            ExprKind::BinOp { left, right, .. } => walk(left).or_else(|| walk(right)),
            ExprKind::UnaryOp { operand, .. } => walk(operand),
            ExprKind::Deref { addr, .. } => walk(addr),
            ExprKind::AddressOf(inner) => walk(inner),
            ExprKind::ArrayAccess { base, index, .. } => walk(base).or_else(|| walk(index)),
            ExprKind::FieldAccess { base, .. } => walk(base),
            ExprKind::Call { target, args } => match target {
                CallTarget::Indirect(inner) | CallTarget::IndirectGot { expr: inner, .. } => {
                    walk(inner)
                }
                CallTarget::Direct { .. } | CallTarget::Named(_) => None,
            }
            .or_else(|| args.iter().find_map(walk)),
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                walk(lhs).or_else(|| walk(rhs))
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => walk(cond)
                .or_else(|| walk(then_expr))
                .or_else(|| walk(else_expr)),
            ExprKind::Cast { expr, .. } | ExprKind::BitField { expr, .. } => walk(expr),
            ExprKind::Phi(values) => values.iter().find_map(walk),
            ExprKind::IntLit(_) | ExprKind::GotRef { .. } => None,
        }
    }

    walk(expr)
}

fn substitute_return_value_aliases_in_node(
    node: StructuredNode,
    aliases: &[String],
    replacement: &Expr,
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
                .map(|stmt| substitute_return_register_uses(stmt, aliases, replacement))
                .collect(),
            address_range,
        },
        StructuredNode::Expr(expr) => {
            StructuredNode::Expr(substitute_return_register_uses(expr, aliases, replacement))
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: substitute_return_register_uses(condition, aliases, replacement),
            then_body: then_body
                .into_iter()
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                .collect(),
            else_body: else_body.map(|body| {
                body.into_iter()
                    .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                    .collect()
            }),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: substitute_return_register_uses(condition, aliases, replacement),
            body: body
                .into_iter()
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
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
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                .collect(),
            condition: substitute_return_register_uses(condition, aliases, replacement),
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
            init: init.map(|expr| substitute_return_register_uses(expr, aliases, replacement)),
            condition: substitute_return_register_uses(condition, aliases, replacement),
            update: update.map(|expr| substitute_return_register_uses(expr, aliases, replacement)),
            body: body
                .into_iter()
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
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
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                .collect(),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: substitute_return_register_uses(value, aliases, replacement),
            cases: cases
                .into_iter()
                .map(|(values, body)| {
                    (
                        values,
                        body.into_iter()
                            .map(|node| {
                                substitute_return_value_aliases_in_node(node, aliases, replacement)
                            })
                            .collect(),
                    )
                })
                .collect(),
            default: default.map(|body| {
                body.into_iter()
                    .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                    .collect()
            }),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
            nodes
                .into_iter()
                .map(|node| substitute_return_value_aliases_in_node(node, aliases, replacement))
                .collect(),
        ),
        StructuredNode::Return(Some(expr)) => StructuredNode::Return(Some(
            substitute_return_register_uses(expr, aliases, replacement),
        )),
        other => other,
    }
}

fn find_previous_call_capture_block(nodes: &[StructuredNode], aliases: &[String]) -> Option<usize> {
    use super::super::expression::ExprKind;

    for idx in (0..nodes.len()).rev() {
        let StructuredNode::Block { statements, .. } = &nodes[idx] else {
            return None;
        };

        if statements.is_empty() {
            continue;
        }

        if let Some(Expr {
            kind: ExprKind::Call { target, .. },
        }) = statements.last()
        {
            if is_call_capture_boundary(target) {
                return Some(idx);
            }
        }

        if statements.iter().any(|stmt| {
            matches!(
                &stmt.kind,
                ExprKind::Call { target, .. } if is_call_capture_boundary(target)
            ) || statement_clobbers_return_register(stmt, aliases)
        }) {
            return None;
        }
    }

    None
}

fn capture_previous_call_result(
    nodes: &mut [StructuredNode],
    block_index: usize,
    capture_counter: &mut u32,
    primary_reg: &str,
) -> Option<Expr> {
    use super::super::expression::{ExprKind, VarKind, Variable};

    let reg_size = if matches!(primary_reg, "eax" | "w0") {
        4
    } else {
        8
    };
    let temp_name = format!("ret_{}", *capture_counter);
    *capture_counter += 1;
    let temp_expr = Expr::var(Variable {
        kind: VarKind::Temp(*capture_counter),
        name: temp_name,
        size: reg_size,
    });

    let StructuredNode::Block {
        statements: prev_stmts,
        ..
    } = &mut nodes[block_index]
    else {
        return None;
    };

    let Some(Expr {
        kind: ExprKind::Call { target, args },
    }) = prev_stmts.last().cloned()
    else {
        return None;
    };

    if !is_call_capture_boundary(&target) {
        return None;
    }

    if let Some(last_stmt) = prev_stmts.last_mut() {
        *last_stmt = Expr::assign(temp_expr.clone(), Expr::call(target, args));
    }

    Some(temp_expr)
}

fn substitute_return_register_uses_until_clobber(
    statements: &mut [Expr],
    aliases: &[String],
    replacement: &Expr,
) {
    for stmt in statements.iter_mut() {
        let original = stmt.clone();
        if let super::super::expression::ExprKind::Call { target, .. } = &original.kind {
            if is_call_capture_boundary(target) {
                break;
            }
        }

        *stmt = substitute_return_register_uses(original.clone(), aliases, replacement);

        if statement_clobbers_return_register(&original, aliases) {
            break;
        }
    }
}

fn return_register_aliases(reg_name: &str) -> Vec<String> {
    match reg_name {
        "al" | "ax" | "eax" | "rax" => vec![
            "al".to_string(),
            "ax".to_string(),
            "eax".to_string(),
            "rax".to_string(),
        ],
        "xmm0" => vec!["xmm0".to_string()],
        "w0" | "x0" | "arg0" => vec!["w0".to_string(), "x0".to_string(), "arg0".to_string()],
        "a0" => vec!["a0".to_string()],
        _ => vec![reg_name.to_string()],
    }
}

fn collect_return_register_uses(stmt: &Expr) -> HashSet<String> {
    use super::super::expression::ExprKind;

    fn walk(expr: &Expr, out: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                let name = v.name.to_lowercase();
                if is_return_value_alias(&name) {
                    out.insert(name);
                }
            }
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                if is_return_value_alias(&lower) {
                    out.insert(lower);
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
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Indirect(expr) | CallTarget::IndirectGot { expr, .. } => {
                        walk(expr, out);
                    }
                    CallTarget::Direct { .. } | CallTarget::Named(_) => {}
                }
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
    statement_clobbers_aliases(stmt, aliases)
}

fn statement_clobbers_aliases(stmt: &Expr, aliases: &[String]) -> bool {
    use super::super::expression::ExprKind;
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

fn expr_uses_any_alias(expr: &Expr, aliases: &[String]) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(v) => aliases.contains(&v.name.to_lowercase()),
        ExprKind::Unknown(name) => aliases.contains(&name.to_lowercase()),
        ExprKind::BinOp { left, right, .. } => {
            expr_uses_any_alias(left, aliases) || expr_uses_any_alias(right, aliases)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_uses_any_alias(operand, aliases),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_uses_any_alias(base, aliases) || expr_uses_any_alias(index, aliases)
        }
        ExprKind::FieldAccess { base, .. } => expr_uses_any_alias(base, aliases),
        ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
            args.iter().any(|arg| expr_uses_any_alias(arg, aliases))
        }
        ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
            expr_uses_any_alias(lhs, aliases) || expr_uses_any_alias(rhs, aliases)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_uses_any_alias(cond, aliases)
                || expr_uses_any_alias(then_expr, aliases)
                || expr_uses_any_alias(else_expr, aliases)
        }
        ExprKind::IntLit(_) | ExprKind::GotRef { .. } => false,
    }
}

fn substitute_loaded_return_value_uses_until_clobber(
    statements: &mut [Expr],
    aliases: &[String],
    load_size: u8,
    replacement: &Expr,
) {
    for stmt in statements.iter_mut() {
        let original = stmt.clone();
        if let super::super::expression::ExprKind::Call { target, .. } = &original.kind {
            if is_call_capture_boundary(target) {
                break;
            }
        }

        *stmt =
            substitute_loaded_return_value_uses(original.clone(), aliases, load_size, replacement);

        if statement_clobbers_return_register(&original, aliases) {
            break;
        }
    }
}

fn substitute_loaded_return_value_uses(
    expr: Expr,
    aliases: &[String],
    load_size: u8,
    replacement: &Expr,
) -> Expr {
    use super::super::expression::ExprKind;

    fn sub(
        expr: Expr,
        aliases: &[String],
        load_size: u8,
        replacement: &Expr,
        in_plain_lhs: bool,
    ) -> Expr {
        match expr.kind {
            ExprKind::Var(v) => {
                let lower = v.name.to_lowercase();
                if !in_plain_lhs && aliases.contains(&lower) {
                    replacement.clone()
                } else {
                    Expr::var(v)
                }
            }
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                if !in_plain_lhs && aliases.contains(&lower) {
                    replacement.clone()
                } else {
                    Expr::unknown(name)
                }
            }
            ExprKind::Deref { addr, size } => {
                if size == load_size {
                    match &addr.kind {
                        ExprKind::Var(v) if aliases.contains(&v.name.to_lowercase()) => {
                            return replacement.clone();
                        }
                        ExprKind::Unknown(name) if aliases.contains(&name.to_lowercase()) => {
                            return replacement.clone();
                        }
                        _ => {}
                    }
                }
                Expr::deref(sub(*addr, aliases, load_size, replacement, false), size)
            }
            ExprKind::BinOp { op, left, right } => Expr::binop(
                op,
                sub(*left, aliases, load_size, replacement, false),
                sub(*right, aliases, load_size, replacement, false),
            ),
            ExprKind::UnaryOp { op, operand } => {
                Expr::unary(op, sub(*operand, aliases, load_size, replacement, false))
            }
            ExprKind::AddressOf(inner) => {
                Expr::address_of(sub(*inner, aliases, load_size, replacement, false))
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => Expr::array_access(
                sub(*base, aliases, load_size, replacement, false),
                sub(*index, aliases, load_size, replacement, false),
                element_size,
            ),
            ExprKind::FieldAccess {
                base,
                field_name,
                offset,
            } => Expr::field_access(
                sub(*base, aliases, load_size, replacement, false),
                field_name,
                offset,
            ),
            ExprKind::Call { target, args } => Expr::call(
                target,
                args.into_iter()
                    .map(|arg| sub(arg, aliases, load_size, replacement, false))
                    .collect(),
            ),
            ExprKind::Assign { lhs, rhs } => {
                let lhs_is_plain_var = matches!(lhs.kind, ExprKind::Var(_));
                Expr::assign(
                    sub(*lhs, aliases, load_size, replacement, lhs_is_plain_var),
                    sub(*rhs, aliases, load_size, replacement, false),
                )
            }
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                let lhs_is_plain_var = matches!(lhs.kind, ExprKind::Var(_));
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op,
                        lhs: Box::new(sub(*lhs, aliases, load_size, replacement, lhs_is_plain_var)),
                        rhs: Box::new(sub(*rhs, aliases, load_size, replacement, false)),
                    },
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => Expr {
                kind: ExprKind::Conditional {
                    cond: Box::new(sub(*cond, aliases, load_size, replacement, false)),
                    then_expr: Box::new(sub(*then_expr, aliases, load_size, replacement, false)),
                    else_expr: Box::new(sub(*else_expr, aliases, load_size, replacement, false)),
                },
            },
            ExprKind::Cast {
                expr,
                to_size,
                signed,
            } => Expr {
                kind: ExprKind::Cast {
                    expr: Box::new(sub(*expr, aliases, load_size, replacement, false)),
                    to_size,
                    signed,
                },
            },
            ExprKind::BitField { expr, start, width } => Expr {
                kind: ExprKind::BitField {
                    expr: Box::new(sub(*expr, aliases, load_size, replacement, false)),
                    start,
                    width,
                },
            },
            ExprKind::Phi(values) => Expr {
                kind: ExprKind::Phi(
                    values
                        .into_iter()
                        .map(|value| sub(value, aliases, load_size, replacement, false))
                        .collect(),
                ),
            },
            ExprKind::IntLit(n) => Expr::int(n),
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
                    display_expr: Box::new(sub(
                        *display_expr,
                        aliases,
                        load_size,
                        replacement,
                        false,
                    )),
                    is_deref,
                },
            },
        }
    }

    sub(expr, aliases, load_size, replacement, false)
}

pub(super) fn substitute_return_register_uses(
    expr: Expr,
    aliases: &[String],
    replacement: &Expr,
) -> Expr {
    use super::super::expression::{CallTarget, ExprKind};

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
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                if !in_plain_lhs && aliases.contains(&lower) {
                    replacement.clone()
                } else {
                    Expr::unknown(name)
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
            ExprKind::Call { target, args } => {
                let target = match target {
                    CallTarget::Direct { target, call_site } => {
                        CallTarget::Direct { target, call_site }
                    }
                    CallTarget::Named(name) => CallTarget::Named(name),
                    CallTarget::Indirect(expr) => {
                        CallTarget::Indirect(Box::new(sub(*expr, aliases, replacement, false)))
                    }
                    CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
                        got_address,
                        expr: Box::new(sub(*expr, aliases, replacement, false)),
                    },
                };
                Expr::call(
                    target,
                    args.into_iter()
                        .map(|a| sub(a, aliases, replacement, false))
                        .collect(),
                )
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{
        BinOpKind, CallTarget, ExprKind, UnaryOpKind, VarKind, Variable,
    };
    use crate::decompiler::BinaryDataContext;
    use hexray_core::BasicBlockId;

    fn reg(name: &str, size: u8) -> Expr {
        Expr::var(Variable::reg(name, size))
    }

    fn local(name: &str, size: u8) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: name.to_string(),
            size,
        })
    }

    fn arg(name: &str, index: u8, size: u8) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Arg(index),
            name: name.to_string(),
            size,
        })
    }

    fn block(id: u32, statements: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(id),
            statements,
            address_range: (0x1000 + (id as u64) * 0x10, 0x1008 + (id as u64) * 0x10),
        }
    }

    fn pseudo_ret(size: u8) -> Expr {
        Expr::var(Variable {
            kind: crate::decompiler::expression::VarKind::Temp(0),
            name: "ret".to_string(),
            size,
        })
    }

    fn binary_data_with_string(address: u64, text: &str) -> BinaryDataContext {
        let mut ctx = BinaryDataContext::new();
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        ctx.add_section(address, bytes);
        ctx
    }

    #[test]
    fn test_extract_return_value_keeps_terminal_compound_update_to_float_return_reg() {
        let statements = vec![
            Expr::assign(reg("xmm1", 16), reg("xmm0", 16)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(reg("xmm0", 16)),
                    rhs: Box::new(reg("xmm1", 16)),
                },
            },
        ];

        let (filtered, return_value) = extract_return_value(statements);

        assert_eq!(filtered.len(), 2);
        assert_eq!(format!("{}", filtered[1]), "xmm0 += xmm1");
        assert_eq!(format!("{}", return_value.expect("return value")), "xmm0");
    }

    #[test]
    fn test_extract_return_value_drops_callee_saved_restore_after_return_copy() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("ebx", 4)),
            Expr::assign(reg("rbx", 8), Expr::unknown("var_8")),
        ];

        let (filtered, return_value) = extract_return_value(statements);

        assert!(filtered.is_empty(), "epilogue restore should be stripped");
        assert_eq!(format!("{}", return_value.expect("return value")), "ebx");
    }

    #[test]
    fn test_extract_return_value_ignores_pre_call_return_reg_setup() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::unknown("argc")),
            Expr::assign(reg("edi", 4), reg("eax", 4)),
            Expr::call(
                CallTarget::Named("helper".to_string()),
                vec![Expr::unknown("argc")],
            ),
        ];

        let (filtered, return_value) = extract_return_value(statements);

        assert!(
            return_value.is_none(),
            "pre-call eax setup should not become the function return"
        );
        assert!(
            !filtered.is_empty(),
            "call should remain in the filtered statement list"
        );
        assert_eq!(format!("{}", filtered.last().unwrap()), "helper(argc)");
    }

    #[test]
    fn test_extract_return_value_skips_stack_canary_compare_setup() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("ebx", 4)),
            Expr::assign(reg("rdx", 8), Expr::unknown("local_18")),
            Expr::assign(
                reg("rdx", 8),
                Expr::binop(
                    BinOpKind::Sub,
                    reg("rdx", 8),
                    Expr::unknown("__stack_chk_guard"),
                ),
            ),
        ];

        let (filtered, return_value) = extract_return_value(statements);

        assert!(filtered.is_empty(), "canary setup should be stripped");
        assert_eq!(format!("{}", return_value.expect("return value")), "ebx");
    }

    #[test]
    fn test_extract_return_value_substitutes_prior_return_reg_value_in_atomic_exchange() {
        let statements = vec![
            Expr::assign(reg("rax", 8), Expr::unknown("arg0")),
            Expr::assign(
                reg("rax", 8),
                Expr::call(
                    CallTarget::Named("atomic_exchange".to_string()),
                    vec![Expr::unknown("&g_counter"), reg("rax", 8)],
                ),
            ),
        ];

        let (_, return_value) = extract_return_value(statements);

        assert_eq!(
            format!("{}", return_value.expect("return value")),
            "atomic_exchange(&g_counter, arg0)"
        );
    }

    #[test]
    fn test_extract_return_value_keeps_side_effecting_temp_assignment() {
        let statements = vec![Expr::assign(
            reg("rdi", 8),
            Expr::call(
                CallTarget::Named("atomic_exchange".to_string()),
                vec![Expr::unknown("&g_counter"), reg("rdi", 8)],
            ),
        )];

        let (filtered, return_value) = extract_return_value(statements);

        assert!(return_value.is_none(), "did not expect a return value");
        assert_eq!(filtered.len(), 1);
        assert_eq!(
            format!("{}", filtered[0]),
            "rdi = atomic_exchange(&g_counter, rdi)"
        );
    }

    #[test]
    fn test_extract_return_value_keeps_secondary_snapshot_when_return_reg_is_overwritten() {
        let statements = vec![
            Expr::assign(reg("rdx", 4), reg("rax", 4)),
            Expr::assign(reg("rax", 4), reg("rbx", 4)),
            Expr::assign(
                reg("rax", 4),
                Expr::binop(BinOpKind::Sub, reg("rax", 4), reg("rdx", 4)),
            ),
        ];

        let (filtered, return_value) = extract_return_value(statements);

        assert_eq!(
            filtered
                .iter()
                .map(|stmt| format!("{stmt}"))
                .collect::<Vec<_>>(),
            vec!["rdx = rax".to_string(), "rax = rbx".to_string()]
        );
        assert_eq!(
            format!("{}", return_value.expect("return value")),
            "rbx - rdx"
        );
    }

    #[test]
    fn test_simplify_statements_keeps_register_value_live_into_following_return() {
        let nodes = vec![
            block(0, vec![Expr::assign(reg("eax", 4), Expr::int(7))]),
            StructuredNode::Return(Some(reg("eax", 4))),
        ];

        let simplified = simplify_statements(nodes);
        let StructuredNode::Block { statements, .. } = &simplified[0] else {
            panic!("expected leading block");
        };

        assert_eq!(statements.len(), 1);
        assert_eq!(format!("{}", statements[0]), "eax = 7");
    }

    #[test]
    fn test_simplify_statements_keeps_loop_carried_register_update_live() {
        let update = Expr::assign(
            reg("rbp", 4),
            Expr::binop(
                BinOpKind::Add,
                reg("rbp", 4),
                Expr::deref(
                    Expr::binop(BinOpKind::Add, reg("rbx", 8), Expr::int(0x10)),
                    4,
                ),
            ),
        );
        let nodes = vec![StructuredNode::While {
            condition: Expr::binop(BinOpKind::Ne, Expr::deref(reg("rbx", 8), 8), Expr::int(0)),
            body: vec![
                block(
                    0,
                    vec![Expr::call(
                        CallTarget::Indirect(Box::new(Expr::deref(reg("rbx", 8), 8))),
                        vec![reg("rbx", 8)],
                    )],
                ),
                StructuredNode::If {
                    condition: Expr::binop(
                        BinOpKind::Eq,
                        Expr::deref(reg("rbx", 8), 8),
                        Expr::int(0),
                    ),
                    then_body: vec![StructuredNode::Return(Some(reg("rbp", 4)))],
                    else_body: None,
                },
                block(1, vec![update]),
            ],
            header: None,
            exit_block: None,
        }];

        let simplified = simplify_statements(nodes);
        let StructuredNode::While { body, .. } = &simplified[0] else {
            panic!("expected while loop");
        };
        let StructuredNode::Block { statements, .. } = &body[2] else {
            panic!("expected trailing loop block");
        };

        assert_eq!(statements.len(), 1);
        assert!(
            format!("{}", statements[0]).contains("rbp = rbp + rbx[4]"),
            "expected loop-carried update to remain present, got {}",
            statements[0]
        );
    }

    #[test]
    fn test_simplify_statements_rewrites_dead_atomic_exchange_capture_to_store() {
        let nodes = vec![block(
            0,
            vec![Expr::assign(
                reg("edi", 4),
                Expr::call(
                    CallTarget::Named("atomic_exchange".to_string()),
                    vec![Expr::unknown("&g_counter"), reg("edi", 4)],
                ),
            )],
        )];

        let simplified = simplify_statements(nodes);
        let StructuredNode::Block { statements, .. } = &simplified[0] else {
            panic!("expected block");
        };

        assert_eq!(statements.len(), 1);
        assert_eq!(
            format!("{}", statements[0]),
            "atomic_store(&g_counter, edi)"
        );
    }

    #[test]
    fn test_simplify_statements_prunes_dead_register_artifacts_across_following_block() {
        let nodes = vec![
            block(
                0,
                vec![
                    Expr::assign(reg("eax", 4), Expr::unknown("i")),
                    Expr::call(CallTarget::Named("cdqe".to_string()), vec![]),
                    Expr::assign(
                        reg("rdx", 8),
                        Expr::binop(BinOpKind::Mul, reg("rax", 8), Expr::int(4)),
                    ),
                    Expr::assign(reg("rax", 8), Expr::unknown("arr")),
                    Expr::assign(
                        reg("rcx", 8),
                        Expr::binop(BinOpKind::Add, reg("rdx", 8), reg("rax", 8)),
                    ),
                    Expr::assign(reg("eax", 4), Expr::deref(reg("rcx", 8), 4)),
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Add,
                            lhs: Box::new(Expr::unknown("total")),
                            rhs: Box::new(Expr::deref(reg("rcx", 8), 4)),
                        },
                    },
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Add,
                            lhs: Box::new(Expr::unknown("i")),
                            rhs: Box::new(Expr::int(1)),
                        },
                    },
                ],
            ),
            block(1, vec![Expr::assign(reg("eax", 4), Expr::unknown("total"))]),
            StructuredNode::Return(Some(reg("eax", 4))),
        ];

        let simplified = simplify_statements(nodes);
        let StructuredNode::Block { statements, .. } = &simplified[0] else {
            panic!("expected first block");
        };
        let rendered: Vec<_> = statements.iter().map(|stmt| format!("{stmt}")).collect();

        assert_eq!(
            rendered,
            vec![
                "total += arr[i]".to_string(),
                "i += 1".to_string(),
                "eax = total".to_string(),
            ]
        );
    }

    #[test]
    fn test_propagate_call_args_substitutes_temp_rhs() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::unknown("n")),
            Expr::assign(
                reg("eax", 4),
                Expr::binop(BinOpKind::Sub, reg("eax", 4), Expr::int(1)),
            ),
            Expr::assign(reg("edi", 4), reg("eax", 4)),
            Expr::call(CallTarget::Named("recursive_sum".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(args.len(), 1);
        assert_eq!(format!("{}", args[0]), "n - 1");
    }

    #[test]
    fn test_propagate_call_args_excludes_indirect_target_and_staging_regs() {
        let statements = vec![
            Expr::assign(reg("edx", 4), Expr::int(6)),
            Expr::assign(reg("eax", 4), Expr::int(4)),
            Expr::assign(reg("rcx", 8), Expr::unknown("fn")),
            Expr::assign(reg("esi", 4), reg("edx", 4)),
            Expr::assign(reg("edi", 4), reg("eax", 4)),
            Expr::call(CallTarget::Indirect(Box::new(reg("rcx", 8))), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing indirect call after propagation");
        };

        match target {
            CallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "fn"),
            other => panic!("expected indirect call target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["4", "6"]
        );
    }

    #[test]
    fn test_propagate_call_args_synthesizes_leading_passthrough_wrapper_args() {
        let statements = vec![
            Expr::assign(reg("edx", 4), Expr::int(64)),
            Expr::call(CallTarget::Named("memcmp".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "memcmp"),
            other => panic!("expected direct memcmp call, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi", "rsi", "0x40"]
        );
    }

    #[test]
    fn test_propagate_call_args_synthesizes_passthrough_args_for_indirect_target_reg() {
        let statements = vec![Expr::call(
            CallTarget::Indirect(Box::new(Expr::array_access(reg("rdx", 8), Expr::int(3), 8))),
            vec![],
        )];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing indirect call after propagation");
        };

        match target {
            CallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "rdx[3]"),
            other => panic!("expected indirect target to stay in rdx, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi", "rsi"]
        );
    }

    #[test]
    fn test_extract_call_arguments_skips_hidden_target_register_slot() {
        let mut arg_values = HashMap::new();
        arg_values.insert(
            "rsi".to_string(),
            (Some(0usize), Expr::address_of(Expr::unknown("arg_local"))),
        );
        let excluded = HashSet::from(["rdi".to_string()]);

        let (args, used_indices) =
            extract_call_arguments_with_indices(None, &[], &arg_values, &excluded, None, None);

        assert_eq!(used_indices, vec![0]);
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["&arg_local"]
        );
    }

    #[test]
    fn test_extract_call_arguments_uses_direct_callee_signature_hint_for_passthrough_arg() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_signature_hint_by_name("helper", 1);

        let (args, used_indices) = extract_call_arguments_with_indices(
            Some(&CallTarget::Named("helper".to_string())),
            &[],
            &HashMap::new(),
            &HashSet::new(),
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );

        assert!(used_indices.is_empty());
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi"]
        );
    }

    #[test]
    fn test_propagate_call_args_uses_resolved_direct_import_name_for_known_prototype() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "strlen@GLIBC_2.2.5");

        let statements = vec![Expr::call(
            CallTarget::Direct {
                target: 0x4010c0,
                call_site: 0x5000,
            },
            vec![],
        )];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected direct import call");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi"]
        );
    }

    #[test]
    fn test_propagate_call_args_preserves_lifted_arg_slot_before_source_update() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010a0, "free@GLIBC_2.2.5");

        let head = arg("head", 0, 8);
        let node = local("node", 8);
        let next = local("next", 8);
        let statements = vec![
            Expr::assign(head.clone(), node.clone()),
            Expr::assign(node.clone(), next),
            Expr::call(
                CallTarget::Direct {
                    target: 0x4010a0,
                    call_site: 0x5008,
                },
                vec![],
            ),
        ];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );

        assert_eq!(format!("{}", propagated[0]), "head = node");
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected recovered free call");
        };
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["head"]
        );
    }

    #[test]
    fn test_propagate_call_args_keeps_existing_indirect_arity_on_second_pass() {
        let statements = vec![
            Expr::assign(reg("rdx", 8), Expr::unknown("user")),
            Expr::assign(reg("rcx", 8), Expr::unknown("cb")),
            Expr::call(
                CallTarget::Indirect(Box::new(Expr::unknown("cb"))),
                vec![Expr::unknown("evt"), Expr::unknown("user")],
            ),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing indirect call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["evt", "user"]
        );
    }

    #[test]
    fn test_propagate_call_args_carries_pending_state_into_if_branch_tail_call() {
        let nodes = vec![
            block(
                0,
                vec![
                    Expr::assign(reg("rax", 8), reg("rsi", 8)),
                    Expr::assign(reg("rsi", 8), reg("rdx", 8)),
                ],
            ),
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Eq, reg("rax", 8), Expr::int(0)),
                then_body: vec![StructuredNode::Return(Some(reg("rax", 8)))],
                else_body: Some(vec![block(
                    1,
                    vec![Expr::call(
                        CallTarget::Indirect(Box::new(reg("rax", 8))),
                        vec![],
                    )],
                )]),
            },
        ];

        let propagated = propagate_call_args_node_sequence(nodes, None, None);
        let StructuredNode::If {
            else_body: Some(else_body),
            ..
        } = &propagated[1]
        else {
            panic!("expected trailing if with else branch");
        };
        let StructuredNode::Block { statements, .. } = &else_body[0] else {
            panic!("expected else body block");
        };
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = statements.last()
        else {
            panic!("expected tail-call block expression");
        };

        match target {
            CallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "arg1"),
            other => panic!("expected carried indirect target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi", "arg2"]
        );
    }

    #[test]
    fn test_propagate_call_args_preserves_state_across_guard_if_to_fallthrough_call() {
        let nodes = vec![
            block(
                0,
                vec![
                    Expr::assign(reg("rax", 8), reg("rsi", 8)),
                    Expr::assign(reg("rsi", 8), reg("rdx", 8)),
                ],
            ),
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Eq, reg("rax", 8), Expr::int(0)),
                then_body: vec![StructuredNode::Return(Some(reg("rax", 8)))],
                else_body: None,
            },
            block(
                1,
                vec![Expr::call(
                    CallTarget::Indirect(Box::new(reg("rax", 8))),
                    vec![],
                )],
            ),
        ];

        let propagated = propagate_call_args_node_sequence(nodes, None, None);
        let StructuredNode::Block { statements, .. } = &propagated[2] else {
            panic!("expected trailing call block");
        };
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = statements.last()
        else {
            panic!("expected fallthrough tail-call expression");
        };

        match target {
            CallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "arg1"),
            other => panic!("expected carried indirect target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rdi", "arg2"]
        );
    }

    #[test]
    fn test_propagate_call_args_drops_stale_copy_after_real_call() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::int(0)),
            Expr::call(
                CallTarget::Named("open".to_string()),
                vec![Expr::unknown("path")],
            ),
            Expr::assign(reg("edi", 4), reg("eax", 4)),
            Expr::call(CallTarget::Named("read".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing read call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "read"),
            other => panic!("expected named read target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["eax"]
        );
    }

    #[test]
    fn test_propagate_call_args_treats_ret_alias_as_current_call_result() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_signature_hint_by_name("format_msg", 2);
        let statements = vec![
            Expr::assign(pseudo_ret(4), Expr::int(0)),
            Expr::call(
                CallTarget::Named("strtol".to_string()),
                vec![Expr::unknown("err"), Expr::int(0), Expr::int(10)],
            ),
            Expr::assign(reg("esi", 4), pseudo_ret(4)),
            Expr::call(
                CallTarget::Named("format_msg".to_string()),
                vec![Expr::unknown("rsp")],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing format_msg call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "format_msg"),
            other => panic!("expected named format_msg target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rsp", "eax"]
        );
    }

    #[test]
    fn test_propagate_call_args_substitutes_unknown_ret_alias_to_current_call_result() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_signature_hint_by_name("format_msg", 2);
        let statements = vec![
            Expr::call(
                CallTarget::Named("strtol".to_string()),
                vec![Expr::unknown("err"), Expr::int(0), Expr::int(10)],
            ),
            Expr::assign(reg("esi", 4), Expr::unknown("ret")),
            Expr::call(
                CallTarget::Named("format_msg".to_string()),
                vec![Expr::unknown("rsp")],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing format_msg call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "format_msg"),
            other => panic!("expected named format_msg target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rsp", "eax"]
        );
    }

    #[test]
    fn test_propagate_call_args_recovers_variadic_syscall_suffix() {
        let statements = vec![
            Expr::assign(reg("rcx", 8), reg("rdx", 8)),
            Expr::assign(reg("rdx", 8), reg("rsi", 8)),
            Expr::assign(reg("esi", 4), reg("edi", 4)),
            Expr::call(CallTarget::Named("syscall".to_string()), vec![Expr::int(1)]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing syscall call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "syscall"),
            other => panic!("expected named syscall target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "arg0", "arg1", "arg2"]
        );
    }

    #[test]
    fn test_propagate_call_args_caps_sigaction_to_known_prototype() {
        let statements = vec![
            Expr::assign(reg("r8d", 4), reg("edi", 4)),
            Expr::assign(reg("ecx", 4), Expr::int(18)),
            Expr::assign(reg("edx", 4), Expr::int(0)),
            Expr::assign(reg("rsi", 8), reg("rsp", 8)),
            Expr::assign(reg("edi", 4), reg("r8d", 4)),
            Expr::call(CallTarget::Named("sigaction".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing sigaction call after propagation");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "sigaction"),
            other => panic!("expected named sigaction target, got {other:?}"),
        }
        assert_eq!(args.len(), 3);
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["arg0", "rsp", "0"]
        );
        assert!(
            !propagated
                .iter()
                .any(|expr| format!("{expr}") == "ecx = 18"),
            "truncated fixed-arg setup should be removed: {propagated:#?}"
        );
    }

    #[test]
    fn test_propagate_call_args_drops_pending_arg_after_non_call_use() {
        let statements = vec![
            Expr::assign(reg("edx", 4), Expr::int(0x402070)),
            Expr::assign(Expr::deref(reg("rax", 8), 8), reg("edx", 4)),
            Expr::assign(reg("rdi", 8), reg("rax", 8)),
            Expr::call(CallTarget::Named("Shape::~Shape()".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[1]), "*(uint64_t*)(rax) = 0x402070");

        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["rax"]
        );
    }

    #[test]
    fn test_propagate_call_args_recovers_missing_printf_chk_variadic_float_and_trailing_gpr() {
        let format_addr = 0x5000;
        let binary_data = binary_data_with_string(format_addr, "x=%d y=%.2f s=%s\n");
        let statements = vec![
            Expr::assign(reg("edx", 4), Expr::unknown("x")),
            Expr::assign(reg("rcx", 8), Expr::unknown("s")),
            Expr::call(
                CallTarget::Named("__printf_chk".to_string()),
                vec![Expr::int(1), Expr::int(format_addr as i128)],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "0x5000", "x", "xmm0", "s"]
        );
    }

    #[test]
    fn test_propagate_call_args_rebuilds_partial_printf_chk_variadic_suffix() {
        let format_addr = 0x5100;
        let binary_data = binary_data_with_string(format_addr, "x=%d y=%.2f s=%s\n");
        let statements = vec![
            Expr::assign(reg("ecx", 4), Expr::unknown("s")),
            Expr::assign(reg("edx", 4), Expr::unknown("x")),
            Expr::call(
                CallTarget::Named("__printf_chk".to_string()),
                vec![
                    Expr::int(1),
                    Expr::int(format_addr as i128),
                    Expr::unknown("stale_x"),
                    Expr::unknown("stale_s"),
                ],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "0x5100", "x", "xmm0", "s"]
        );
    }

    #[test]
    fn test_propagate_call_args_rebuilds_partial_printf_chk_suffix_for_direct_imports() {
        let format_addr = 0x5200;
        let binary_data = binary_data_with_string(format_addr, "x=%d y=%.2f s=%s\n");
        let statements = vec![
            Expr::assign(reg("ecx", 4), Expr::unknown("s")),
            Expr::assign(reg("edx", 4), Expr::unknown("x")),
            Expr::call(
                CallTarget::Direct {
                    target: 0x4010a0,
                    call_site: 0x401108,
                },
                vec![
                    Expr::int(1),
                    Expr::int(format_addr as i128),
                    Expr::unknown("stale_x"),
                    Expr::unknown("stale_s"),
                ],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "0x5200", "x", "xmm0", "s"]
        );
    }

    #[test]
    fn test_propagate_call_args_inserts_missing_float_for_direct_import_without_tracked_gprs() {
        let format_addr = 0x5300;
        let binary_data = binary_data_with_string(format_addr, "x=%d y=%.2f s=%s\n");
        let statements = vec![Expr::call(
            CallTarget::Direct {
                target: 0x4010a0,
                call_site: 0x401108,
            },
            vec![
                Expr::int(1),
                Expr::int(format_addr as i128),
                Expr::int(42),
                Expr::unknown("world"),
            ],
        )];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "0x5300", "0x2a", "xmm0", "world"]
        );
    }

    #[test]
    fn test_propagate_call_args_inserts_missing_float_for_assignment_rhs_call() {
        let format_addr = 0x5310;
        let binary_data = binary_data_with_string(format_addr, "x=%d y=%.2f s=%s\n");
        let statements = vec![Expr::assign(
            Expr::unknown("ret_2"),
            Expr::call(
                CallTarget::Direct {
                    target: 0x4010a0,
                    call_site: 0x401108,
                },
                vec![
                    Expr::int(1),
                    Expr::int(format_addr as i128),
                    Expr::int(42),
                    Expr::unknown("world"),
                ],
            ),
        )];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Assign { rhs, .. },
        }) = propagated.last()
        else {
            panic!("expected assignment with recovered call");
        };
        let ExprKind::Call { args, .. } = &rhs.kind else {
            panic!("expected call on assignment rhs");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["1", "0x5310", "0x2a", "xmm0", "world"]
        );
    }

    #[test]
    fn test_propagate_call_args_recovers_user_variadic_format_call_from_first_arg() {
        let format_addr = 0x6000;
        let binary_data = binary_data_with_string(format_addr, "sum=%d, pi=%g\n");
        let statements = vec![
            Expr::assign(reg("esi", 4), Expr::int(5)),
            Expr::assign(reg("xmm0", 16), Expr::unknown("pi")),
            Expr::call(
                CallTarget::Named("my_log".to_string()),
                vec![Expr::int(format_addr as i128)],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["0x6000", "5", "pi"]
        );
    }

    #[test]
    fn test_propagate_call_args_tracks_call_result_aliases_for_following_calls() {
        let handle = local("handle", 8);
        let sym = local("sym", 8);
        let value = local("value", 4);
        let statements = vec![
            Expr::assign(
                handle.clone(),
                Expr::call(
                    CallTarget::Named("dlopen".to_string()),
                    vec![Expr::unknown("\"/tmp/lib_versioned.so\""), Expr::int(2)],
                ),
            ),
            Expr::assign(reg("rsi", 8), Expr::unknown("\"my_func\"")),
            Expr::assign(reg("rdi", 8), reg("rax", 8)),
            Expr::assign(
                sym.clone(),
                Expr::call(CallTarget::Named("dlsym".to_string()), vec![]),
            ),
            Expr::assign(
                value.clone(),
                Expr::call(CallTarget::Indirect(Box::new(reg("rax", 8))), vec![]),
            ),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(propagated.len(), 3);

        let ExprKind::Assign { rhs, .. } = &propagated[1].kind else {
            panic!("expected captured dlsym assignment");
        };
        let ExprKind::Call { target, args } = &rhs.kind else {
            panic!("expected dlsym call on assignment rhs");
        };
        match target {
            CallTarget::Named(name) => assert_eq!(name, "dlsym"),
            other => panic!("expected named dlsym target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["handle", "\"my_func\""]
        );

        let ExprKind::Assign { rhs, .. } = &propagated[2].kind else {
            panic!("expected captured callback assignment");
        };
        let ExprKind::Call { target, args } = &rhs.kind else {
            panic!("expected callback call on assignment rhs");
        };
        match target {
            CallTarget::Indirect(expr) => assert_eq!(format!("{expr}"), "sym"),
            other => panic!("expected indirect callback target, got {other:?}"),
        }
        assert!(args.is_empty(), "callback call should remain nullary");
    }

    #[test]
    fn test_propagate_call_args_reuses_assignment_call_result_for_printf_chk_suffix() {
        let format_addr = 0x6010;
        let binary_data = binary_data_with_string(format_addr, "s=%d v=%d\n");
        let sum = local("sum", 4);
        let value = local("value", 4);
        let statements = vec![
            Expr::assign(
                value.clone(),
                Expr::call(CallTarget::Indirect(Box::new(Expr::unknown("sym"))), vec![]),
            ),
            Expr::assign(reg("ecx", 4), reg("eax", 4)),
            Expr::call(
                CallTarget::Named("__printf_chk".to_string()),
                vec![Expr::int(2), Expr::int(format_addr as i128), sum.clone()],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing printf_chk call");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["2", "0x6010", "sum", "value"]
        );
    }

    #[test]
    fn test_merge_return_value_captures_across_blocks_for_compound_use() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("foo".to_string()),
                    vec![Expr::int(1)],
                )],
            ),
            block(
                1,
                vec![Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Add,
                        lhs: Box::new(Expr::unknown("sum")),
                        rhs: Box::new(reg("eax", 4)),
                    },
                }],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = foo(1)");
        assert_eq!(format!("{}", second_block[0]), "sum += ret_0");
    }

    #[test]
    fn test_merge_return_value_captures_across_blocks_for_call_arg_use() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("strtol".to_string()),
                    vec![Expr::unknown("err"), Expr::int(0), Expr::int(10)],
                )],
            ),
            block(
                1,
                vec![Expr::call(
                    CallTarget::Named("format_msg".to_string()),
                    vec![Expr::unknown("rsp"), Expr::unknown("ret")],
                )],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = strtol(err, 0, 0xa)");
        assert_eq!(format!("{}", second_block[0]), "format_msg(rsp, ret_0)");
    }

    #[test]
    fn test_merge_return_value_captures_rewrites_nested_if_chain_after_call_block() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("getopt_long".to_string()),
                    vec![Expr::unknown("argc"), Expr::unknown("argv")],
                )],
            ),
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Eq, local("ret_0", 4), Expr::int(-1)),
                then_body: vec![StructuredNode::Return(Some(Expr::int(0)))],
                else_body: Some(vec![StructuredNode::If {
                    condition: Expr::binop(BinOpKind::Eq, reg("eax", 4), Expr::int(104)),
                    then_body: vec![block(1, vec![Expr::assign(local("help", 4), Expr::int(1))])],
                    else_body: Some(vec![StructuredNode::If {
                        condition: Expr::binop(BinOpKind::Eq, reg("eax", 4), Expr::int(118)),
                        then_body: vec![block(
                            2,
                            vec![Expr::assign(local("verbose", 4), Expr::int(1))],
                        )],
                        else_body: None,
                    }]),
                }]),
            },
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        assert_eq!(
            format!("{}", first_block[0]),
            "ret_0 = getopt_long(argc, argv)"
        );

        let StructuredNode::If {
            condition,
            else_body: Some(else_body),
            ..
        } = &merged[1]
        else {
            panic!("expected rewritten if chain");
        };
        assert_eq!(format!("{condition}"), "ret_0 == -0x1");

        let StructuredNode::If {
            condition: nested_cond,
            else_body: Some(nested_else),
            ..
        } = &else_body[0]
        else {
            panic!("expected nested if");
        };
        assert_eq!(format!("{nested_cond}"), "ret_0 == 'h'");

        let StructuredNode::If {
            condition: deeper_cond,
            ..
        } = &nested_else[0]
        else {
            panic!("expected deeper if");
        };
        assert_eq!(format!("{deeper_cond}"), "ret_0 == 'v'");
    }

    #[test]
    fn test_merge_return_value_captures_materializes_folded_condition_call_result() {
        let nodes = vec![StructuredNode::If {
            condition: Expr::unary(
                UnaryOpKind::LogicalNot,
                Expr::call(CallTarget::Named("malloc".to_string()), vec![Expr::int(16)]),
            ),
            then_body: vec![StructuredNode::Return(None)],
            else_body: Some(vec![
                block(
                    0,
                    vec![
                        Expr::assign(Expr::deref(reg("rax", 8), 4), Expr::unknown("value")),
                        Expr::assign(
                            Expr::deref(
                                Expr::binop(BinOpKind::Add, reg("rax", 8), Expr::int(8)),
                                8,
                            ),
                            Expr::int(0),
                        ),
                    ],
                ),
                StructuredNode::Return(None),
            ]),
        }];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Sequence(seq) = &merged[0] else {
            panic!("expected folded condition call to materialize into a sequence");
        };
        let StructuredNode::Expr(assign) = &seq[0] else {
            panic!("expected leading call-result assignment");
        };
        assert_eq!(format!("{assign}"), "ret_0 = malloc(0x10)");

        let StructuredNode::If {
            condition,
            then_body,
            else_body: Some(else_body),
        } = &seq[1]
        else {
            panic!("expected rewritten if after call-result assignment");
        };
        assert_eq!(format!("{condition}"), "!ret_0");
        assert!(matches!(
            then_body.last(),
            Some(StructuredNode::Return(Some(expr))) if format!("{expr}") == "ret_0"
        ));

        let StructuredNode::Block { statements, .. } = &else_body[0] else {
            panic!("expected else block with rewritten stores");
        };
        assert_eq!(format!("{}", statements[0]), "*(uint32_t*)(ret_0) = value");
        assert_eq!(format!("{}", statements[1]), "*(uint64_t*)(ret_0 + 8) = 0");
        assert!(matches!(
            else_body.last(),
            Some(StructuredNode::Return(Some(expr))) if format!("{expr}") == "ret_0"
        ));
    }

    #[test]
    fn test_merge_return_value_captures_into_return_across_intervening_block() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("recursive_sum".to_string()),
                    vec![Expr::binop(
                        BinOpKind::Sub,
                        Expr::unknown("n"),
                        Expr::int(1),
                    )],
                )],
            ),
            block(1, vec![Expr::assign(reg("edx", 4), Expr::unknown("n"))]),
            StructuredNode::Return(Some(Expr::binop(
                BinOpKind::Add,
                reg("eax", 4),
                Expr::unknown("n"),
            ))),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Return(Some(ret_expr)) = &merged[2] else {
            panic!("expected trailing return node");
        };

        assert_eq!(
            format!("{}", first_block[0]),
            "ret_0 = recursive_sum(n - 1)"
        );
        assert_eq!(format!("{}", ret_expr), "ret_0 + n");
    }

    #[test]
    fn test_merge_return_value_captures_across_blocks_for_deref_load_into_named_var() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(CallTarget::Named("foo".to_string()), vec![])],
            ),
            block(
                1,
                vec![
                    Expr::assign(Expr::unknown("x"), Expr::deref(reg("rax", 8), 4)),
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Add,
                            lhs: Box::new(Expr::unknown("sum")),
                            rhs: Box::new(Expr::unknown("x")),
                        },
                    },
                ],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = foo()");
        assert_eq!(format!("{}", second_block[0]), "x = *(uint32_t*)(ret_0)");
        assert_eq!(format!("{}", second_block[1]), "sum += x");
    }

    #[test]
    fn test_merge_return_value_captures_across_blocks_for_deref_load_into_return_reg() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(CallTarget::Named("foo".to_string()), vec![])],
            ),
            block(
                1,
                vec![
                    Expr::assign(reg("eax", 4), Expr::deref(reg("rax", 8), 4)),
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Add,
                            lhs: Box::new(Expr::unknown("sum")),
                            rhs: Box::new(reg("eax", 4)),
                        },
                    },
                ],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = foo()");
        assert_eq!(second_block.len(), 1);
        assert_eq!(format!("{}", second_block[0]), "sum += *(uint32_t*)(ret_0)");
    }

    #[test]
    fn test_merge_return_value_captures_keeps_cross_block_deref_load_for_later_use() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(CallTarget::Named("foo".to_string()), vec![])],
            ),
            block(
                1,
                vec![Expr::assign(reg("eax", 4), Expr::deref(reg("rax", 8), 4))],
            ),
            block(
                2,
                vec![Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Add,
                        lhs: Box::new(Expr::unknown("sum")),
                        rhs: Box::new(reg("eax", 4)),
                    },
                }],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };
        let StructuredNode::Block {
            statements: third_block,
            ..
        } = &merged[2]
        else {
            panic!("expected third node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = foo()");
        assert_eq!(format!("{}", second_block[0]), "eax = *(uint32_t*)(ret_0)");
        assert_eq!(format!("{}", third_block[0]), "sum += eax");
    }

    #[test]
    fn test_merge_return_value_captures_rewrites_self_load_followed_by_named_capture() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(CallTarget::Named("foo".to_string()), vec![])],
            ),
            block(
                1,
                vec![
                    Expr::assign(reg("eax", 4), Expr::deref(reg("rax", 8), 4)),
                    Expr::assign(Expr::unknown("x"), Expr::deref(reg("rax", 8), 4)),
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Add,
                            lhs: Box::new(Expr::unknown("sum")),
                            rhs: Box::new(Expr::unknown("x")),
                        },
                    },
                ],
            ),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: first_block,
            ..
        } = &merged[0]
        else {
            panic!("expected first node to remain a block");
        };
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected second node to remain a block");
        };

        assert_eq!(format!("{}", first_block[0]), "ret_0 = foo()");
        assert_eq!(format!("{}", second_block[0]), "x = *(uint32_t*)(ret_0)");
        assert_eq!(format!("{}", second_block[1]), "sum += x");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_for_deref_load_into_return_reg() {
        let statements = vec![
            Expr::call(CallTarget::Named("foo".to_string()), vec![]),
            Expr::assign(reg("eax", 4), Expr::deref(reg("rax", 8), 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(Expr::unknown("sum")),
                    rhs: Box::new(reg("eax", 4)),
                },
            },
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(merged.len(), 2);
        assert_eq!(format!("{}", merged[0]), "ret_0 = foo()");
        assert_eq!(format!("{}", merged[1]), "sum += *(uint32_t*)(ret_0)");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_for_deref_load_via_ret_alias() {
        let statements = vec![
            Expr::call(CallTarget::Named("foo".to_string()), vec![]),
            Expr::assign(Expr::unknown("x"), Expr::deref(pseudo_ret(8), 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(Expr::unknown("sum")),
                    rhs: Box::new(Expr::unknown("x")),
                },
            },
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(merged.len(), 3);
        assert_eq!(format!("{}", merged[0]), "ret_0 = foo()");
        assert_eq!(format!("{}", merged[1]), "x = *(uint32_t*)(ret_0)");
        assert_eq!(format!("{}", merged[2]), "sum += x");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_rewrites_ret_alias_call_arg() {
        let statements = vec![
            Expr::call(CallTarget::Named("strtol".to_string()), vec![]),
            Expr::call(
                CallTarget::Named("format_msg".to_string()),
                vec![Expr::unknown("rsp"), pseudo_ret(4)],
            ),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = strtol()");
        assert_eq!(format!("{}", merged[1]), "format_msg(rsp, ret_0)");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_rewrites_unknown_ret_alias_call_arg() {
        let statements = vec![
            Expr::call(CallTarget::Named("strtol".to_string()), vec![]),
            Expr::call(
                CallTarget::Named("format_msg".to_string()),
                vec![Expr::unknown("rsp"), Expr::unknown("ret")],
            ),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = strtol()");
        assert_eq!(format!("{}", merged[1]), "format_msg(rsp, ret_0)");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_tracks_ret_alias_through_arg_setup() {
        let statements = vec![
            Expr::call(CallTarget::Named("strtol".to_string()), vec![]),
            Expr::assign(reg("rdi", 8), Expr::unknown("rsp")),
            Expr::assign(reg("esi", 4), pseudo_ret(4)),
            Expr::call(CallTarget::Named("format_msg".to_string()), vec![]),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = strtol()");
        assert_eq!(format!("{}", merged[1]), "rdi = rsp");
        assert_eq!(format!("{}", merged[2]), "esi = ret_0");
        assert_eq!(format!("{}", merged[3]), "format_msg()");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_rewrites_indirect_call_target() {
        let statements = vec![
            Expr::call(CallTarget::Named("dlsym".to_string()), vec![]),
            Expr::assign(
                Expr::unknown("value"),
                Expr::call(CallTarget::Indirect(Box::new(reg("rax", 8))), vec![]),
            ),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "dlsym()");
        assert_eq!(format!("{}", merged[1]), "ret_0 = rax");
        assert_eq!(format!("{}", merged[2]), "value = (ret_0)()");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_for_rdtsc_with_secondary_result() {
        let statements = vec![
            Expr::call(CallTarget::Named("rdtsc".to_string()), vec![]),
            Expr::assign(Expr::unknown("lo"), reg("eax", 4)),
            Expr::assign(Expr::unknown("hi"), reg("edx", 4)),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = rdtsc()");
        assert_eq!(format!("{}", merged[1]), "lo = ret_0");
        assert_eq!(format!("{}", merged[2]), "hi = rdtsc_high_1");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_for_cpuid_with_named_outputs() {
        let statements = vec![
            Expr::call(CallTarget::Named("cpuid".to_string()), vec![]),
            Expr::assign(Expr::unknown("a"), reg("eax", 4)),
            Expr::assign(Expr::unknown("b"), reg("ebx", 4)),
            Expr::assign(Expr::unknown("c"), reg("ecx", 4)),
            Expr::assign(Expr::unknown("d"), reg("edx", 4)),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = cpuid()");
        assert_eq!(format!("{}", merged[1]), "a = ret_0");
        assert_eq!(format!("{}", merged[2]), "b = cpuid_ebx_1");
        assert_eq!(format!("{}", merged[3]), "c = cpuid_ecx_1");
        assert_eq!(format!("{}", merged[4]), "d = cpuid_edx_1");
    }

    #[test]
    fn test_capture_return_register_uses_in_block_for_cpuid_secondary_only_use() {
        let statements = vec![
            Expr::call(CallTarget::Named("cpuid".to_string()), vec![]),
            Expr::assign(Expr::unknown("vendor_b"), reg("ebx", 4)),
        ];

        let mut counter = 0u32;
        let merged = capture_return_register_uses_in_block(statements, &mut counter);

        assert_eq!(format!("{}", merged[0]), "ret_0 = cpuid()");
        assert_eq!(format!("{}", merged[1]), "vendor_b = cpuid_ebx_1");
    }

    #[test]
    fn test_propagate_copies_invalidates_cpuid_outputs_but_keeps_other_args() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::unknown("leaf")),
            Expr::assign(reg("rsi", 8), Expr::unknown("eax_out")),
            Expr::call(CallTarget::Named("cpuid".to_string()), vec![]),
            Expr::assign(Expr::deref(reg("rsi", 8), 4), reg("eax", 4)),
        ];

        let propagated = propagate_copies(statements);

        assert_eq!(format!("{}", propagated[0]), "eax = leaf");
        assert_eq!(format!("{}", propagated[1]), "rsi = eax_out");
        assert_eq!(format!("{}", propagated[2]), "cpuid()");
        assert_eq!(format!("{}", propagated[3]), "*(uint32_t*)(eax_out) = eax");
    }

    #[test]
    fn test_propagate_copies_keeps_saved_snapshot_after_induction_update() {
        let statements = vec![
            Expr::assign(reg("edx", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Sub,
                    lhs: Box::new(reg("edi", 4)),
                    rhs: Box::new(Expr::int(1)),
                },
            },
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Mul,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(reg("edx", 4)),
                },
            },
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(format!("{}", propagated[2]), "eax *= edx");
    }

    #[test]
    fn test_propagate_copies_tracks_compound_update_from_prior_value() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(reg("ecx", 4), reg("eax", 4)),
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(format!("{}", propagated[2]), "ecx = edi << 4");
    }

    #[test]
    fn test_propagate_copies_does_not_clone_load_rhs_across_temp_copies() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::deref(reg("rdi", 8), 4)),
            Expr::assign(reg("edx", 4), reg("eax", 4)),
            Expr::assign(reg("ecx", 4), reg("eax", 4)),
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(format!("{}", propagated[1]), "edx = eax");
        assert_eq!(format!("{}", propagated[2]), "ecx = eax");
    }

    #[test]
    fn test_propagate_copies_normalizes_set_bits_value_arg_after_shift_update() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(
                reg("esi", 4),
                Expr::call(
                    CallTarget::Named("SET_BITS".to_string()),
                    vec![
                        Expr::unknown("carrier"),
                        reg("eax", 4),
                        Expr::int(4),
                        Expr::int(8),
                    ],
                ),
            ),
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(
            format!("{}", propagated[2]),
            "esi = SET_BITS(carrier, edi, 4, 8)"
        );
    }

    #[test]
    fn test_propagate_call_args_normalizes_set_bits_value_arg_after_shift_update() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(
                reg("esi", 4),
                Expr::call(
                    CallTarget::Named("SET_BITS".to_string()),
                    vec![
                        Expr::unknown("carrier"),
                        reg("eax", 4),
                        Expr::int(4),
                        Expr::int(8),
                    ],
                ),
            ),
        ];

        let propagated = propagate_args_in_block_with_binary_data(statements, None, None);
        assert_eq!(
            format!("{}", propagated[2]),
            "esi = SET_BITS(carrier, arg0, 4, 8)"
        );
    }

    #[test]
    fn test_propagate_copies_normalizes_nested_set_bits_value_shift_for_store() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(
                Expr::deref(reg("rdi", 8), 2),
                Expr::call(
                    CallTarget::Named("SET_BITS".to_string()),
                    vec![
                        Expr::unknown("carrier"),
                        Expr::binop(BinOpKind::Shl, reg("eax", 4), Expr::int(4)),
                        Expr::int(4),
                        Expr::int(8),
                    ],
                ),
            ),
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(
            format!("{}", propagated[2]),
            "*(uint16_t*)(rdi) = SET_BITS(carrier, edi, 4, 8)"
        );
    }

    #[test]
    fn test_propagate_call_args_normalizes_nested_set_bits_value_shift_for_store() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(
                Expr::deref(reg("rdi", 8), 2),
                Expr::call(
                    CallTarget::Named("SET_BITS".to_string()),
                    vec![
                        Expr::unknown("carrier"),
                        Expr::binop(BinOpKind::Shl, reg("eax", 4), Expr::int(4)),
                        Expr::int(4),
                        Expr::int(8),
                    ],
                ),
            ),
        ];

        let propagated = propagate_args_in_block_with_binary_data(statements, None, None);
        assert_eq!(
            format!("{}", propagated[2]),
            "*(uint16_t*)(rdi) = SET_BITS(carrier, arg0, 4, 8)"
        );
    }

    #[test]
    fn test_propagate_copies_invalidates_partial_x86_alias_updates() {
        let statements = vec![
            Expr::assign(reg("esi", 4), Expr::unknown("loaded")),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::And,
                    lhs: Box::new(reg("si", 2)),
                    rhs: Box::new(Expr::int(0xf00f)),
                },
            },
            Expr::assign(reg("eax", 4), reg("esi", 4)),
        ];

        let propagated = propagate_copies(statements);
        assert_eq!(format!("{}", propagated[2]), "eax = esi");
    }

    #[test]
    fn test_propagate_call_args_keeps_saved_snapshot_after_induction_update() {
        let statements = vec![
            Expr::assign(reg("edx", 4), reg("edi", 4)),
            Expr::assign(
                reg("edi", 4),
                Expr::binop(BinOpKind::Sub, reg("edi", 4), Expr::int(1)),
            ),
            Expr::assign(
                reg("eax", 4),
                Expr::binop(BinOpKind::Mul, reg("eax", 4), reg("edx", 4)),
            ),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[2]), "eax = eax * edx");
    }

    #[test]
    fn test_propagate_call_args_keeps_snapshot_across_cdqe_pseudo_call() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr::call(CallTarget::Named("cdqe".to_string()), vec![]),
            Expr::assign(
                reg("rdx", 8),
                Expr::binop(BinOpKind::Mul, reg("rax", 8), Expr::int(4)),
            ),
            Expr::assign(reg("rax", 8), reg("rsi", 8)),
            Expr::assign(
                reg("rcx", 8),
                Expr::binop(BinOpKind::Add, reg("rdx", 8), reg("rax", 8)),
            ),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[2]), "rdx = arg0 * 4");
        assert_eq!(format!("{}", propagated[4]), "rcx = arg0 * 4 + arg1");
    }

    #[test]
    fn test_propagate_call_args_tracks_compound_update_from_prior_value() {
        let statements = vec![
            Expr::assign(reg("eax", 4), reg("edi", 4)),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Shl,
                    lhs: Box::new(reg("eax", 4)),
                    rhs: Box::new(Expr::int(4)),
                },
            },
            Expr::assign(reg("ecx", 4), reg("eax", 4)),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[2]), "ecx = arg0 << 4");
    }

    #[test]
    fn test_propagate_call_args_does_not_clone_load_rhs_across_temp_copies() {
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::deref(reg("rdi", 8), 4)),
            Expr::assign(reg("edx", 4), reg("eax", 4)),
            Expr::assign(reg("ecx", 4), reg("eax", 4)),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[1]), "edx = eax");
        assert_eq!(format!("{}", propagated[2]), "ecx = eax");
    }

    #[test]
    fn test_propagate_call_args_recovers_saved_arm64_param_from_stack_slot() {
        let sp_slot = Expr::deref(reg("sp", 8), 8);
        let statements = vec![
            Expr::assign(sp_slot.clone(), reg("x0", 8)),
            Expr::assign(reg("x0", 8), Expr::int(0x1b8)),
            Expr::call(CallTarget::Named("helper".to_string()), vec![]),
            Expr::assign(reg("x8", 8), sp_slot),
            Expr::assign(
                reg("w8", 4),
                Expr::deref(
                    Expr::binop(BinOpKind::Add, reg("x8", 8), Expr::int(0x1f0)),
                    1,
                ),
            ),
        ];

        let propagated = propagate_args_in_block(statements);
        let final_read = format!(
            "{}",
            propagated
                .last()
                .expect("expected propagated stack-slot reload to remain present")
        );
        assert!(
            final_read.contains("arg0"),
            "expected saved parameter to flow into reload, got {final_read}"
        );
        assert!(
            !final_read.contains("*(uint64_t*)(sp)"),
            "expected stack slot reload to be substituted, got {final_read}"
        );
        assert!(
            final_read.contains("[0x1f0]"),
            "expected the original page offset to survive propagation, got {final_read}"
        );
    }

    #[test]
    fn test_propagate_temps_to_conditions_skips_self_updated_dowhile_induction_var() {
        let nodes = vec![StructuredNode::DoWhile {
            body: vec![block(
                0,
                vec![
                    Expr::assign(reg("edx", 4), reg("edi", 4)),
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Sub,
                            lhs: Box::new(reg("edi", 4)),
                            rhs: Box::new(Expr::int(1)),
                        },
                    },
                    Expr {
                        kind: ExprKind::CompoundAssign {
                            op: BinOpKind::Mul,
                            lhs: Box::new(reg("eax", 4)),
                            rhs: Box::new(reg("edx", 4)),
                        },
                    },
                ],
            )],
            condition: Expr::binop(BinOpKind::Ne, reg("edi", 4), Expr::int(1)),
            header: Some(BasicBlockId::new(0)),
            exit_block: Some(BasicBlockId::new(1)),
        }];

        let propagated = propagate_temps_to_conditions(nodes);
        let StructuredNode::DoWhile { condition, .. } = &propagated[0] else {
            panic!("expected do-while node");
        };

        assert_eq!(format!("{}", condition), "edi != 1");
    }

    #[test]
    fn test_propagate_temps_to_conditions_keeps_single_load_temp_in_dowhile_condition() {
        let nodes = vec![StructuredNode::DoWhile {
            body: vec![block(
                0,
                vec![Expr::assign(reg("eax", 4), Expr::deref(reg("rdi", 8), 4))],
            )],
            condition: Expr::binop(
                BinOpKind::Eq,
                Expr::binop(BinOpKind::And, reg("eax", 4), Expr::unknown("mask")),
                Expr::int(0),
            ),
            header: Some(BasicBlockId::new(0)),
            exit_block: Some(BasicBlockId::new(1)),
        }];

        let propagated = propagate_temps_to_conditions(nodes);
        let StructuredNode::DoWhile { condition, .. } = &propagated[0] else {
            panic!("expected do-while node");
        };
        let rendered = format!("{condition}");

        assert!(
            rendered.contains("eax") && !rendered.contains("*(uint32_t*)(rdi)"),
            "expected the captured load temp to stay single-evaluation, got {rendered}"
        );
    }

    #[test]
    fn test_reuse_saved_condition_values_keeps_preheader_loop_bound() {
        let bound_expr = Expr::binop(
            BinOpKind::Add,
            reg("rdi", 8),
            Expr::binop(BinOpKind::Mul, reg("rsi", 8), Expr::int(4)),
        );
        let nodes = vec![
            block(0, vec![Expr::assign(reg("rdx", 8), bound_expr.clone())]),
            StructuredNode::DoWhile {
                body: vec![block(
                    1,
                    vec![
                        Expr {
                            kind: ExprKind::CompoundAssign {
                                op: BinOpKind::Add,
                                lhs: Box::new(reg("eax", 4)),
                                rhs: Box::new(Expr::deref(reg("rdi", 8), 4)),
                            },
                        },
                        Expr {
                            kind: ExprKind::CompoundAssign {
                                op: BinOpKind::Add,
                                lhs: Box::new(reg("rdi", 8)),
                                rhs: Box::new(Expr::int(4)),
                            },
                        },
                    ],
                )],
                condition: Expr::binop(BinOpKind::Ne, reg("rdi", 8), bound_expr),
                header: Some(BasicBlockId::new(1)),
                exit_block: Some(BasicBlockId::new(2)),
            },
        ];

        let reused = reuse_saved_condition_values(nodes);
        let StructuredNode::DoWhile { condition, .. } = &reused[1] else {
            panic!("expected do-while node");
        };

        assert_eq!(format!("{}", condition), "rdi != rdx");
    }
}
