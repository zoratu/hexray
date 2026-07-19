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
    builtin::{linux_x86_64_syscall_name, load_libc_functions, load_linux_types, load_posix_types},
    CType, TypeDatabase,
};

use super::super::abi::{
    get_arg_register_index, is_argument_register, is_callee_saved_or_renamed, is_return_register,
    is_temp_register,
};
use super::super::dead_store::collect_all_uses;
use super::super::expression::{BinOpKind, CallTarget, Expr, ExprKind, VarKind, Variable};
use super::super::BinaryDataContext;
use super::{body_terminates, CatchHandler, StructuredNode};

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
                if matches!(v.kind, VarKind::Register(_) | VarKind::Arg(_)) {
                    // Substitute known values in RHS before storing
                    let substituted_rhs = substitute_vars(rhs, &reg_values);
                    substituted_assignments.insert(stmt_idx, substituted_rhs.clone());
                    invalidate_clobbered_register_mappings(&mut reg_values, &v.name);
                    if expr_requires_single_evaluation(&substituted_rhs)
                        && !expr_is_pure_stack_slot_expression(&substituted_rhs)
                    {
                        reg_values.remove(&v.name);
                    } else {
                        record_register_substitution(
                            &mut reg_values,
                            &v.name,
                            v.size,
                            substituted_rhs,
                        );
                    }
                }
            }
        }
    }

    let mut return_value = None;
    let mut indices_to_remove = Vec::new();
    let mut saw_real_call_after = false;
    let mut saw_stack_canary_after = false;
    // Variables that participate in the canary check expression
    // (the registers/slots that hold the reloaded canary on the
    // check path). Used to scope the post-canary assignment-drop
    // to ACTUAL canary scaffolding rather than the body work that
    // precedes the canary check. SSE-5.
    //
    // PRE-COMPUTED by a forward-walking taint propagation pass:
    // multi-register check shapes like
    //   `rdx = local_canary; rcx = __stack_chk_guard; rdx = rdx - rcx`
    // require knowing that `rcx` will become canary-tainted BEFORE
    // we encounter the compare. The backward walk below can't see
    // forward, so we precompute the full taint set here. Codex
    // review on PR #28 pass 5.
    let canary_check_vars = precompute_canary_check_vars(&statements);
    // Working copy that the backward walk can adjust (kill on
    // LHS redefinition per codex pass 3).
    let mut canary_check_vars = canary_check_vars;

    // Search backwards for an assignment to a return register, collecting epilogue statements
    for i in (0..statements.len()).rev() {
        let stmt = &statements[i];
        // Flip saw_stack_canary_after when the precomputed taint
        // says this statement participates in the canary check.
        if !saw_stack_canary_after && stmt_is_canary(stmt, &canary_check_vars) {
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
                    // Restrict drop to ACTUAL canary-pattern
                    // assignments. Three accepted shapes:
                    //  (a) RHS mentions `stack_chk_guard` (the
                    //      canary reload itself).
                    //  (b) LHS is a variable that participated in
                    //      the canary check expression (e.g. the
                    //      reload register used in the compare).
                    //  (c) RHS is a reload of one of the
                    //      already-seen canary check vars (e.g.
                    //      `rcx = [rbp-8]` setting up the compare).
                    // Plain body work happening before the canary
                    // check (the SSE arithmetic and result-slot
                    // store on float-returning stack-protected
                    // functions) MUST survive — without this gate
                    // the body recovery would emit
                    // `return uninit_slot;` having dropped the
                    // computation. SSE-5.
                    let rhs_is_canary = expr_mentions_stack_canary_guard(rhs);
                    let lhs_is_check_var = canary_check_vars.contains(&v.name);
                    let mut rhs_vars: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    collect_var_names(rhs, &mut rhs_vars);
                    // Exclude stack-base registers (rbp/rsp/x29/sp)
                    // from check-var tracking — they appear in every
                    // frame-slot dereference (`rcx = *(rbp - 8)`),
                    // so tainting them would poison every subsequent
                    // `[rbp - N]` body access. Codex review on PR
                    // #28 pass 1.
                    let drop_taint_var = |name: &str| {
                        matches!(name, "rbp" | "ebp" | "rsp" | "esp" | "x29" | "fp" | "sp")
                    };
                    let rhs_uses_check_var = rhs_vars
                        .iter()
                        .filter(|n| !drop_taint_var(n))
                        .any(|n| canary_check_vars.contains(n));
                    if rhs_is_canary || lhs_is_check_var || rhs_uses_check_var {
                        // Walking backward, the redefinition kills
                        // the taint for the LHS register: an
                        // earlier `local_ret = rax` should be
                        // preserved because that rax was the body
                        // result, not the canary value the
                        // overwrite later loaded. Remove the LHS
                        // from the canary-check-vars set first.
                        // Codex review on PR #28 pass 3.
                        canary_check_vars.remove(&v.name);
                        // Then propagate taint from RHS — chains
                        // of canary setup (e.g. the saved-canary
                        // slot reload, the guard memory ref) all
                        // get pulled into the set so their earlier
                        // defs also drop. Stack-base registers
                        // stay out (codex pass 1).
                        for n in rhs_vars {
                            if !drop_taint_var(&n) {
                                canary_check_vars.insert(n);
                            }
                        }
                        indices_to_remove.push(i);
                        continue;
                    }
                    // Otherwise leave the assignment in place —
                    // it's likely real body work happening before
                    // the canary check at the end of the block.
                    // CONTINUE so the backward scan keeps walking
                    // toward the earlier return-register assignment
                    // (eax/xmm0/etc.). Falling through to the
                    // generic break below would leave the block
                    // without a recovered return value. Codex
                    // review on PR #28 pass 2.
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

pub(super) fn substitute_prior_register_assignments(expr: Expr, statements: &[Expr]) -> Expr {
    use super::super::expression::ExprKind;

    let mut reg_values: HashMap<String, Expr> = HashMap::new();

    for stmt in statements {
        match &stmt.kind {
            ExprKind::Assign { lhs, rhs } => {
                let ExprKind::Var(var) = &lhs.kind else {
                    continue;
                };
                if !matches!(var.kind, VarKind::Register(_) | VarKind::Arg(_)) {
                    continue;
                }

                let substituted_rhs = substitute_vars(rhs, &reg_values);
                invalidate_clobbered_register_mappings(&mut reg_values, &var.name);
                if expr_requires_single_evaluation(&substituted_rhs)
                    && !expr_is_pure_stack_slot_expression(&substituted_rhs)
                {
                    reg_values.remove(&var.name);
                    continue;
                }

                record_register_substitution(&mut reg_values, &var.name, var.size, substituted_rhs);
            }
            ExprKind::Call { target, .. } => {
                if statement_contains_real_call(stmt) {
                    reg_values.clear();
                } else {
                    invalidate_pseudo_call_output_copies(&mut reg_values, target);
                }
            }
            _ => {}
        }
    }

    substitute_vars(&expr, &reg_values)
}

/// Forward-walking taint propagation over a block's statement list
/// to identify EVERY variable that holds canary-derived state.
/// Walks once forward through the statements; whenever an Assign's
/// RHS mentions `stack_chk_guard` or uses an already-tainted var,
/// the LHS becomes tainted too. Stack-base registers (rbp/rsp/...)
/// stay out of the set so frame-slot dereferences don't poison
/// every body access.
///
/// The backward walk in `extract_return_value` consults this
/// precomputed set so it can recognize multi-register canary
/// patterns like
///   `rdx = local_canary; rcx = stack_chk_guard; rdx = rdx - rcx`
/// where the compare uses `rcx` before `rcx` is loaded — backward
/// alone can't see that connection. Codex review on PR #28 pass 5.
fn precompute_canary_check_vars(statements: &[Expr]) -> std::collections::HashSet<String> {
    use super::super::expression::ExprKind;
    let mut tainted: std::collections::HashSet<String> = std::collections::HashSet::new();
    let drop_taint_var = |n: &str| matches!(n, "rbp" | "ebp" | "rsp" | "esp" | "x29" | "fp" | "sp");
    for stmt in statements {
        if expr_mentions_stack_canary_guard(stmt) {
            let mut vars: std::collections::HashSet<String> = std::collections::HashSet::new();
            collect_var_names(stmt, &mut vars);
            for n in vars {
                if !drop_taint_var(&n) {
                    tainted.insert(n);
                }
            }
        }
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                let mut rhs_vars: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                collect_var_names(rhs, &mut rhs_vars);
                let rhs_uses_tainted = rhs_vars
                    .iter()
                    .any(|n| !drop_taint_var(n) && tainted.contains(n));
                if rhs_uses_tainted && !drop_taint_var(&v.name) {
                    tainted.insert(v.name.clone());
                }
            }
        }
    }
    tainted
}

/// True when `stmt` is part of the canary check chain: it either
/// mentions `stack_chk_guard` directly, or its lhs/rhs participates
/// in the precomputed taint set.
fn stmt_is_canary(stmt: &Expr, tainted: &std::collections::HashSet<String>) -> bool {
    use super::super::expression::ExprKind;
    if expr_mentions_stack_canary_guard(stmt) {
        return true;
    }
    if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
        if let ExprKind::Var(v) = &lhs.kind {
            if tainted.contains(&v.name) {
                return true;
            }
        }
        let mut rhs_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
        collect_var_names(rhs, &mut rhs_vars);
        let drop_taint_var =
            |n: &str| matches!(n, "rbp" | "ebp" | "rsp" | "esp" | "x29" | "fp" | "sp");
        if rhs_vars
            .iter()
            .any(|n| !drop_taint_var(n) && tainted.contains(n))
        {
            return true;
        }
    }
    false
}

/// Collect every `Var` name referenced inside `expr`. Used by the
/// canary-aware return extraction to track which variables flow
/// through the canary check expression. SSE-5.
fn collect_var_names(expr: &Expr, names: &mut std::collections::HashSet<String>) {
    use super::super::expression::ExprKind;
    match &expr.kind {
        ExprKind::Var(v) => {
            names.insert(v.name.clone());
        }
        ExprKind::BinOp { left, right, .. } => {
            collect_var_names(left, names);
            collect_var_names(right, names);
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. }
        | ExprKind::AddressOf(operand) => {
            collect_var_names(operand, names);
        }
        ExprKind::Deref { addr, .. } => collect_var_names(addr, names),
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_var_names(base, names);
            collect_var_names(index, names);
        }
        ExprKind::FieldAccess { base, .. } => collect_var_names(base, names),
        ExprKind::Call { args, .. } => {
            for arg in args {
                collect_var_names(arg, names);
            }
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_var_names(cond, names);
            collect_var_names(then_expr, names);
            collect_var_names(else_expr, names);
        }
        ExprKind::Assign { lhs, rhs } => {
            collect_var_names(lhs, names);
            collect_var_names(rhs, names);
        }
        ExprKind::CompoundAssign { lhs, rhs, .. } => {
            collect_var_names(lhs, names);
            collect_var_names(rhs, names);
        }
        ExprKind::Phi(values) => {
            for v in values {
                collect_var_names(v, names);
            }
        }
        ExprKind::GotRef { display_expr, .. } => collect_var_names(display_expr, names),
        ExprKind::IntLit(_) | ExprKind::Unknown(_) => {}
    }
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
    let nodes = prune_unreachable_nodes(merge_adjacent_blocks(nodes));

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

    // Seventh pass: suppress ASan frame/shadow scaffolding that has no
    // user-visible semantics.
    let nodes = suppress_asan_scaffolding(nodes);

    // Eighth pass: prune dead register artifacts that only exist to shuttle
    // machine state between adjacent lowered blocks.
    let nodes = prune_dead_register_artifacts(nodes);

    // Ninth pass: simplify all conditions (convert | to ||, & to && for comparisons, etc.)
    let nodes: Vec<_> = nodes.into_iter().map(simplify_conditions_in_node).collect();

    // Tenth pass: collapse SysV `va_arg` register/overflow state machines into
    // `va_arg(ap, T)` assignments. Runs last so the diamond's slot reads have
    // already been folded to concrete frame offsets by copy propagation.
    super::va_arg::recover_va_arg(nodes)
}

pub(super) fn prune_unreachable_nodes(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    prune_unreachable_nodes_in_list(nodes)
}

fn prune_unreachable_nodes_in_list(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut pruned = Vec::with_capacity(nodes.len());
    let mut prior_node_terminates = false;

    for node in nodes {
        let node = prune_unreachable_nodes_in_node(node);
        if prior_node_terminates {
            if matches!(node, StructuredNode::Label(_)) {
                prior_node_terminates = false;
                pruned.push(node);
            }
            continue;
        }

        prior_node_terminates = node_definitely_terminates(&node);
        pruned.push(node);
    }

    pruned
}

fn prune_unreachable_nodes_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: prune_unreachable_nodes_in_list(then_body),
            else_body: else_body.map(prune_unreachable_nodes_in_list),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: prune_unreachable_nodes_in_list(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: prune_unreachable_nodes_in_list(body),
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
            body: prune_unreachable_nodes_in_list(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: prune_unreachable_nodes_in_list(body),
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
                .map(|(values, body)| (values, prune_unreachable_nodes_in_list(body)))
                .collect(),
            default: default.map(prune_unreachable_nodes_in_list),
        },
        StructuredNode::Sequence(nodes) => {
            StructuredNode::Sequence(prune_unreachable_nodes_in_list(nodes))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: prune_unreachable_nodes_in_list(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: prune_unreachable_nodes_in_list(handler.body),
                    ..handler
                })
                .collect(),
        },
        other => other,
    }
}

fn node_definitely_terminates(node: &StructuredNode) -> bool {
    body_terminates(std::slice::from_ref(node))
        || matches!(node, StructuredNode::TryCatch { try_body, catch_handlers }
            if body_terminates(try_body)
                && !catch_handlers.is_empty()
                && catch_handlers
                    .iter()
                    .all(|handler| body_terminates(&handler.body)))
}

/// Recognise the canonical Itanium C++ throw triple inside each block
/// and collapse it to a single `throw VALUE` pseudo-statement. The
/// triple gcc/clang emit for `throw 42` (and analogues for
/// `throw 3.14`, `throw std::runtime_error("x")`, …) is:
///
/// ```ignore
///     buf = __cxa_allocate_exception(sizeof(T));
///     *(T *)buf = value;
///     __cxa_throw(buf, &typeinfo for T, dtor);
/// ```
///
/// `resolve(target_addr, call_site_addr)` is plumbed in from the
/// decompiler so the pass can resolve `CallTarget::Direct{target,
/// call_site}` against the symbol and relocation tables — at simplify
/// time the lifter has only an address for many PLT calls, and the
/// `__cxa_*` names only show up after symbol-table lookup. The caller
/// is expected to mirror the emitter's name lookup chain (relocation
/// table by call_site first, symbol table by target_addr second);
/// codex review on PR #13 flagged that a target-only resolver missed
/// relocation-backed PLT imports.
///
/// After this pass the three statements collapse to `throw value;` —
/// `__cxa_throw` already has noreturn detection wired (see
/// `noreturn.rs`), so the surrounding control-flow exit reasoning
/// stays correct without further changes. The pattern is intentionally
/// strict: any extra intervening side effect, a mismatch between the
/// allocator return name and the throw's first argument, or a
/// store-from-something-other-than-the-buffer all decline the rewrite.
///
/// Constructor-style throws (`throw std::runtime_error("x")`) emit a
/// `__cxa_allocate_exception` + ctor-call + `__cxa_throw` triple
/// instead of `*buf = value`. This pass currently only handles the
/// scalar-value form (int/double/raw pointer); the ctor form needs
/// type recovery beyond what we have here and stays a follow-up.
pub fn recover_cxa_throw_pattern<F>(nodes: Vec<StructuredNode>, resolve: &F) -> Vec<StructuredNode>
where
    F: Fn(u64, u64) -> Option<String>,
{
    nodes
        .into_iter()
        .map(|n| recover_cxa_throw_pattern_in_node(n, resolve))
        .collect()
}

fn recover_cxa_throw_pattern_in_node<F>(node: StructuredNode, resolve: &F) -> StructuredNode
where
    F: Fn(u64, u64) -> Option<String>,
{
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: recover_cxa_throw_in_statements(statements, resolve),
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: recover_cxa_throw_pattern(then_body, resolve),
            else_body: else_body.map(|b| recover_cxa_throw_pattern(b, resolve)),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: recover_cxa_throw_pattern(body, resolve),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            condition,
            body: recover_cxa_throw_pattern(body, resolve),
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
            body: recover_cxa_throw_pattern(body, resolve),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: recover_cxa_throw_pattern(body, resolve),
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
                .map(|(vals, body)| (vals, recover_cxa_throw_pattern(body, resolve)))
                .collect(),
            default: default.map(|d| recover_cxa_throw_pattern(d, resolve)),
        },
        StructuredNode::Sequence(inner) => {
            StructuredNode::Sequence(recover_cxa_throw_pattern(inner, resolve))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: recover_cxa_throw_pattern(try_body, resolve),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::CatchHandler {
                    body: recover_cxa_throw_pattern(h.body, resolve),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

fn recover_cxa_throw_in_statements<F>(statements: Vec<Expr>, resolve: &F) -> Vec<Expr>
where
    F: Fn(u64, u64) -> Option<String>,
{
    use super::super::expression::{CallTarget, ExprKind};

    /// Walk through trivial `Cast` wrappers (the lifter usually wraps
    /// the buffer-pointer reload with `(T *)` casts) so the matcher can
    /// reach the underlying `Var`.
    fn strip_casts(expr: &Expr) -> &Expr {
        let mut cur = expr;
        while let ExprKind::Cast { expr: inner, .. } = &cur.kind {
            cur = inner;
        }
        cur
    }

    fn call_canonical_name<G>(target: &CallTarget, resolve: &G) -> Option<String>
    where
        G: Fn(u64, u64) -> Option<String>,
    {
        match target {
            CallTarget::Named(name) => Some(hexray_core::unversioned_symbol_name(name).to_string()),
            CallTarget::Direct {
                target: addr,
                call_site,
            } => {
                let raw = resolve(*addr, *call_site)?;
                Some(hexray_core::unversioned_symbol_name(&raw).to_string())
            }
            _ => None,
        }
    }

    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for stmt in statements {
        // Match `__cxa_throw(buf, &typeinfo, dtor)` against the trailing
        // pair already in `result`. The pair we expect is, in order:
        //   [N-2] buf = __cxa_allocate_exception(SIZE)
        //   [N-1] *(T *)buf = value
        let throw_args = match &stmt.kind {
            ExprKind::Call { target, args }
                if call_canonical_name(target, resolve).as_deref() == Some("__cxa_throw") =>
            {
                args.clone()
            }
            _ => {
                result.push(stmt);
                continue;
            }
        };

        if result.is_empty() {
            result.push(stmt);
            continue;
        }
        let buf_name = match throw_args.first().map(strip_casts).map(|e| &e.kind) {
            Some(ExprKind::Var(v)) => v.name.clone(),
            _ => {
                result.push(stmt);
                continue;
            }
        };

        // The last statement is either a scalar/POD store into the
        // buffer (`*buf = value`, possibly preceded by more stores for
        // multi-field PODs) OR a single ctor call `Class::Class(buf, …)`
        // which initialises the buffer in place. Decide which shape by
        // peeking at the LAST statement, then walk back accordingly:
        //
        //   store form:  alloc; store_0; …; store_{N-1}; throw   (N >= 1)
        //   ctor  form:  alloc; ctor(buf, args);          throw
        //
        // We deliberately keep the ctor form a single statement — a
        // multi-store run after a ctor would be surprising and is
        // conservatively declined per the PR #13 codex-review guidance.
        fn store_address_root_is(lhs: &Expr) -> Option<&Expr> {
            // Accept `*buf`, `*(buf + K)`, `buf[K]`, and casts wrapping
            // any of those.
            match &lhs.kind {
                ExprKind::Deref { addr, .. } => Some(strip_casts(addr)),
                ExprKind::ArrayAccess { base, .. } => Some(strip_casts(base)),
                _ => None,
            }
        }

        fn is_buf_root(addr: &Expr, buf: &str) -> bool {
            let stripped = strip_casts(addr);
            match &stripped.kind {
                ExprKind::Var(v) => v.name == buf,
                ExprKind::BinOp {
                    op: BinOpKind::Add | BinOpKind::Sub,
                    left,
                    right,
                } => {
                    is_buf_root(left, buf) && matches!(&right.kind, ExprKind::IntLit(_))
                        || is_buf_root(right, buf) && matches!(&left.kind, ExprKind::IntLit(_))
                }
                _ => false,
            }
        }

        fn is_store_into_buf(stmt: &Expr, buf: &str) -> bool {
            let ExprKind::Assign { lhs, .. } = &stmt.kind else {
                return false;
            };
            store_address_root_is(lhs)
                .map(|addr| is_buf_root(addr, buf))
                .unwrap_or(false)
        }

        /// A constructor initialising `buf` in place, returning the ctor call's
        /// target and args. The ctor is either a bare `Class::Class(buf, …)`
        /// call or that call captured into an otherwise-unused temporary
        /// `ret = Class::Class(buf, …)` — at `-O0` the compiler keeps the ctor's
        /// ABI return (the object pointer), which the throw discards. Unwrap the
        /// optional assignment, then require the first argument to be `buf`.
        fn ctor_call_into_buf<'a>(
            stmt: &'a Expr,
            buf: &str,
        ) -> Option<(&'a CallTarget, &'a [Expr])> {
            let call = match &stmt.kind {
                ExprKind::Call { .. } => stmt,
                // Only a captured-return temporary `ret = ctor(buf, …)` (LHS is a
                // plain `Var`), never a store `*buf = f(buf, …)` (LHS is a
                // `Deref`/`ArrayAccess`) — the latter stays the scalar-store form
                // so its argument 0 is preserved.
                ExprKind::Assign { lhs, rhs }
                    if matches!(&strip_casts(lhs).kind, ExprKind::Var(_)) =>
                {
                    strip_casts(rhs)
                }
                _ => return None,
            };
            let ExprKind::Call { target, args } = &call.kind else {
                return None;
            };
            let first_is_buf = args
                .first()
                .map(strip_casts)
                .is_some_and(|e| matches!(&e.kind, ExprKind::Var(v) if v.name == buf));
            first_is_buf.then_some((target, args.as_slice()))
        }

        // Determine the run of buffer-initialisation statements
        // immediately before the throw, and the index where the alloc
        // sits. For the ctor form the run is exactly the single trailing
        // call; for the store form it's one or more consecutive stores
        // walking backwards until the first non-store statement.
        let last_idx = result.len() - 1;
        let last_is_ctor = ctor_call_into_buf(&result[last_idx], &buf_name).is_some();
        let mut store_run_start = if last_is_ctor {
            last_idx
        } else if is_store_into_buf(&result[last_idx], &buf_name) {
            // Walk backward while each statement is a buf store.
            let mut start = result.len();
            while start > 0 && is_store_into_buf(&result[start - 1], &buf_name) {
                start -= 1;
            }
            start
        } else {
            // Last statement is neither a buf store nor a ctor — decline.
            result.push(stmt);
            continue;
        };
        // The alloc must sit immediately before the run.
        if store_run_start == 0 {
            result.push(stmt);
            continue;
        }
        let alloc_idx = store_run_start - 1;
        // Pull the trailing ctor (if any) back into the run start for
        // the per-statement match below.
        if last_is_ctor {
            store_run_start = last_idx;
        }
        let alloc_ok = match &result[alloc_idx].kind {
            ExprKind::Assign { lhs, rhs } => {
                let lhs_matches = matches!(
                    &strip_casts(lhs).kind,
                    ExprKind::Var(v) if v.name == buf_name,
                );
                let rhs_is_alloc = match &strip_casts(rhs).kind {
                    ExprKind::Call { target, .. } => {
                        call_canonical_name(target, resolve).as_deref()
                            == Some("__cxa_allocate_exception")
                    }
                    _ => false,
                };
                lhs_matches && rhs_is_alloc
            }
            _ => false,
        };

        if !alloc_ok {
            result.push(stmt);
            continue;
        }

        // `[N-1]` (= the last statement in the store run) is one of:
        //
        // * **Scalar form** — `*(T *)buf = value;` for `throw 42`,
        //   `throw 3.14`, `throw some_ptr`. A single store at the
        //   buffer base.
        //
        // * **Multi-store POD form** — `*(T *)buf = v0; *((T*)buf+1) =
        //   v1; …;` for `throw Pod{...}` with two or more fields. The
        //   collapsed render is `throw { v0, v1, … }` since the C++
        //   type name lives in `&typeinfo` (the throw's second arg)
        //   and is recovered at emit time alongside the LSDA work —
        //   the compound-literal-style brace form lets the analyst
        //   reconstruct which POD type without us asserting one.
        //
        // * **Constructor form** — `TypeName::TypeName(buf, …args);`
        //   for `throw std::runtime_error("x")` and friends. The
        //   ctor's first argument is `buf`; we render the throw as
        //   `throw TypeName::TypeName(args)` so the call shape stays
        //   intact and the user-facing pseudo-C still reads like
        //   real C++. Constructor form is single-statement (the
        //   ctor itself initialises the buffer in place); a multi-
        //   statement store run after a ctor declines the rewrite.
        let store_count = result.len() - store_run_start;
        let last_store_idx = result.len() - 1;

        // Multi-store POD form: two or more stores into the buffer.
        // Per codex review on this PR, we MUST validate the store
        // offsets we used to identify the run before discarding them
        // — if the compiler reorders fields, repeats an offset, or
        // interleaves something we don't model, rendering the stores
        // in statement order would misrepresent the thrown value while
        // deleting the address evidence the analyst needs.
        //
        // Conservative rule: extract each store's offset relative to
        // `buf` (`*buf` = 0, `*(buf + K)` / `buf[K]` = K). All offsets
        // must be present, strictly increasing, and distinct. Anything
        // else declines the rewrite and falls back to the single-store
        // / ctor-form path below — which itself handles only the
        // last statement and won't fire for a multi-store run, so the
        // raw alloc + stores + throw sequence is left intact.
        fn store_offset_relative_to_buf(stmt: &Expr, buf: &str) -> Option<i128> {
            let ExprKind::Assign { lhs, .. } = &stmt.kind else {
                return None;
            };
            // For `*buf = v` the offset is 0; for `*(buf ± K) = v`
            // it's ±K; for `buf[K] = v` it's K * element_size. The
            // element-size form mirrors what `store_address_root_is`
            // already accepts, so failures here decline the rewrite.
            match &lhs.kind {
                ExprKind::Deref { addr, .. } => {
                    let stripped = strip_casts(addr);
                    match &stripped.kind {
                        ExprKind::Var(v) if v.name == buf => Some(0),
                        ExprKind::BinOp {
                            op: BinOpKind::Add,
                            left,
                            right,
                        } => match (strip_casts(left), strip_casts(right)) {
                            (
                                Expr {
                                    kind: ExprKind::Var(v),
                                },
                                Expr {
                                    kind: ExprKind::IntLit(off),
                                },
                            ) if v.name == buf => Some(*off),
                            (
                                Expr {
                                    kind: ExprKind::IntLit(off),
                                },
                                Expr {
                                    kind: ExprKind::Var(v),
                                },
                            ) if v.name == buf => Some(*off),
                            _ => None,
                        },
                        ExprKind::BinOp {
                            op: BinOpKind::Sub,
                            left,
                            right,
                        } => match (strip_casts(left), strip_casts(right)) {
                            (
                                Expr {
                                    kind: ExprKind::Var(v),
                                },
                                Expr {
                                    kind: ExprKind::IntLit(off),
                                },
                            ) if v.name == buf => Some(-off),
                            _ => None,
                        },
                        _ => None,
                    }
                }
                ExprKind::ArrayAccess {
                    base,
                    index,
                    element_size,
                } => {
                    let stripped_base = strip_casts(base);
                    let ExprKind::Var(v) = &stripped_base.kind else {
                        return None;
                    };
                    if v.name != buf {
                        return None;
                    }
                    let ExprKind::IntLit(idx) = &strip_casts(index).kind else {
                        return None;
                    };
                    Some(idx.saturating_mul(*element_size as i128))
                }
                _ => None,
            }
        }

        let multi_store_value: Option<String> = if store_count >= 2 {
            let mut field_offsets: Vec<i128> = Vec::with_capacity(store_count);
            let mut fields: Vec<String> = Vec::with_capacity(store_count);
            let mut offsets_ok = true;
            for stmt in &result[store_run_start..] {
                let Some(off) = store_offset_relative_to_buf(stmt, &buf_name) else {
                    offsets_ok = false;
                    break;
                };
                let ExprKind::Assign { rhs, .. } = &stmt.kind else {
                    offsets_ok = false;
                    break;
                };
                field_offsets.push(off);
                fields.push(format!("{}", **rhs));
            }
            if offsets_ok && field_offsets.windows(2).all(|w| w[0] < w[1]) {
                Some(format!("{{ {} }}", fields.join(", ")))
            } else {
                None
            }
        } else {
            None
        };

        let stored_value = if let Some(brace_literal) = multi_store_value {
            Some(brace_literal)
        } else if let Some((target, args)) =
            ctor_call_into_buf(&result[last_store_idx], &buf_name)
        {
            // Constructor form — bare `Class::Class(buf, …)` or the temp-captured
            // `ret = Class::Class(buf, …)`. Render `throw TypeName(remaining_args)`,
            // dropping the implicit buf slot so the throw reads like the source
            // expression. Falls back to the resolved call name when `Direct`.
            fn canonicalise_ctor_name(raw: &str) -> String {
                // Strip glibc/PLT decorations, demangle a raw Itanium symbol
                // (a `Direct` relocation resolves to the mangled ctor name, e.g.
                // `_ZNSt13runtime_errorC1EPKc`), then strip the
                // `[base]`/`[complete]`/`[clone …]` disambiguator labels and the
                // trailing `(args)` signature — in that order, because each step
                // exposes the next one's tail. Mirrors the chain in
                // `PseudoCodeEmitter::format_call_target_name` from deferral #5.
                let unversioned = hexray_core::unversioned_symbol_name(raw);
                let demangled =
                    hexray_demangle::demangle(unversioned).unwrap_or_else(|| unversioned.to_string());
                let labels_stripped =
                    crate::symbol_names::strip_demangler_disambiguator_labels(&demangled);
                crate::symbol_names::strip_demangled_signature(labels_stripped).to_string()
            }
            let target_name = match target {
                CallTarget::Named(name) => Some(canonicalise_ctor_name(name)),
                CallTarget::Direct {
                    target: addr,
                    call_site,
                } => resolve(*addr, *call_site).map(|raw| canonicalise_ctor_name(&raw)),
                _ => None,
            };
            // Require the callee to actually be a constructor (its last two
            // `::`-segments name the same class) so a captured helper return
            // (`ret = memcpy(buf, …)`) is not mistaken for the ctor. Then trim
            // the doubled `TypeName::TypeName` to `TypeName(args)`.
            target_name.filter(|name| looks_like_constructor(name)).map(|name| {
                let prettified = collapse_ctor_pretty_name(&name);
                let rest_args: Vec<String> =
                    args.iter().skip(1).map(|a| format!("{}", a)).collect();
                format!("{}({})", prettified, rest_args.join(", "))
            })
        } else {
            // Scalar store form: `*(T *)buf = value`.
            match &result[last_store_idx].kind {
                ExprKind::Assign { lhs, rhs } => {
                    let target_matches = match &lhs.kind {
                        ExprKind::Deref { addr, .. } => matches!(
                            &strip_casts(addr).kind,
                            ExprKind::Var(v) if v.name == buf_name,
                        ),
                        _ => false,
                    };
                    if target_matches {
                        Some(format!("{}", (**rhs).clone()))
                    } else {
                        None
                    }
                }
                _ => None,
            }
        };
        let Some(value) = stored_value else {
            result.push(stmt);
            continue;
        };

        // All three matched — collapse to `throw <value>;`. The Unknown
        // marker mirrors the cold-clone throw rendering shape from
        // deferral #4 so downstream `body_ends_with_*` heuristics stay
        // consistent.
        let throw_text = format!("throw {}", value);
        // Drop the allocate + all stores; replace with the throw pseudo-stmt.
        result.truncate(alloc_idx);
        result.push(Expr::unknown(throw_text));
    }

    result
}

/// Collapse `Namespace::Class::Class` ctor-symbol patterns down to
/// `Namespace::Class` so a recovered `throw Class(args)` reads like
/// source rather than the doubled-segment Itanium-ABI form. Leaves any
/// non-matching name untouched.
/// The base identifier of a `::`-segment: the part before any template-argument
/// list (`vector<int, std::allocator<int> >` → `vector`) or GNU ABI tag
/// (`failure[abi:cxx11]` → `failure`).
fn ctor_segment_base(segment: &str) -> &str {
    segment
        .split(|c| c == '<' || c == '[')
        .next()
        .unwrap_or(segment)
        .trim()
}

/// The last two `::`-separated segments of a qualified name, split at angle
/// depth 0 so a `::` inside template arguments (`std::allocator<int>`) is not
/// mistaken for a segment boundary. Returns `(prev, tail)`, or `None` when the
/// name has no top-level `::`.
fn last_two_top_level_segments(name: &str) -> Option<(&str, &str)> {
    let bytes = name.as_bytes();
    let mut depth = 0i32;
    let mut seps: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b':' if depth == 0 && i + 1 < bytes.len() && bytes[i + 1] == b':' => {
                seps.push(i);
                i += 1; // skip the second ':'
            }
            _ => {}
        }
        i += 1;
    }
    let last = *seps.last()?;
    let prev_start = if seps.len() >= 2 {
        seps[seps.len() - 2] + 2
    } else {
        0
    };
    Some((&name[prev_start..last], &name[last + 2..]))
}

fn collapse_ctor_pretty_name(name: &str) -> String {
    // Drop the trailing ctor segment when the last two top-level segments name
    // the same class (`A::B::B` → `A::B`, `std::vector<…>::vector` →
    // `std::vector<…>`), comparing the base before any template arguments.
    if let Some((prev, tail)) = last_two_top_level_segments(name) {
        if !ctor_segment_base(tail).is_empty()
            && ctor_segment_base(prev) == ctor_segment_base(tail)
        {
            if let Some(head) = name.strip_suffix(tail).and_then(|s| s.strip_suffix("::")) {
                return head.to_string();
            }
        }
    }
    name.to_string()
}

/// Whether a demangled name is a C++ constructor: its last two top-level
/// `::`-segments name the same class (`ns::Class::Class`, `Class<T>::Class`,
/// `std::vector<int, std::allocator<int> >::vector`). This gates the throw
/// recogniser's ctor form so an ordinary helper that returns its first argument
/// and is captured into a temp — `ret = memcpy(buf, src, n)` — is not mistaken
/// for the discarded constructor return and rewritten into a `throw`.
fn looks_like_constructor(name: &str) -> bool {
    let Some((prev, tail)) = last_two_top_level_segments(name) else {
        return false;
    };
    !ctor_segment_base(tail).is_empty() && ctor_segment_base(prev) == ctor_segment_base(tail)
}

fn suppress_asan_scaffolding(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .filter_map(suppress_asan_scaffolding_in_node)
        .collect()
}

fn suppress_asan_scaffolding_in_node(node: StructuredNode) -> Option<StructuredNode> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = suppress_asan_scaffolding_in_statements(statements);
            Some(StructuredNode::Block {
                id,
                statements,
                address_range,
            })
        }
        StructuredNode::Expr(expr) => {
            (!is_asan_scaffolding_statement(&expr)).then_some(StructuredNode::Expr(expr))
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let then_body = suppress_asan_scaffolding(then_body);
            let else_body = else_body.map(suppress_asan_scaffolding);
            if then_body.is_empty() && else_body.as_ref().is_none_or(Vec::is_empty) {
                None
            } else {
                Some(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                })
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: suppress_asan_scaffolding(body),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: suppress_asan_scaffolding(body),
            condition,
            header,
            exit_block,
        }),
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::For {
            init,
            condition,
            update,
            body: suppress_asan_scaffolding(body),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: suppress_asan_scaffolding(body),
            header,
            exit_block,
        }),
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => Some(StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(values, body)| (values, suppress_asan_scaffolding(body)))
                .collect(),
            default: default.map(suppress_asan_scaffolding),
        }),
        StructuredNode::Sequence(nodes) => {
            Some(StructuredNode::Sequence(suppress_asan_scaffolding(nodes)))
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => Some(StructuredNode::TryCatch {
            try_body: suppress_asan_scaffolding(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: suppress_asan_scaffolding(handler.body),
                    ..handler
                })
                .collect(),
        }),
        StructuredNode::Return(_)
        | StructuredNode::Break
        | StructuredNode::Continue
        | StructuredNode::Goto(_)
        | StructuredNode::Label(_) => Some(node),
    }
}

fn suppress_asan_scaffolding_in_statements(statements: Vec<Expr>) -> Vec<Expr> {
    let mut filtered = Vec::with_capacity(statements.len());
    for stmt in statements {
        if is_asan_scaffolding_statement(&stmt) {
            continue;
        }
        filtered.push(stmt);
    }
    filtered
}

fn is_asan_scaffolding_statement(stmt: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &stmt.kind {
        ExprKind::Assign { lhs, rhs } => {
            is_asan_helper_call_expr(rhs)
                || (expr_contains_asan_shadow_marker(lhs)
                    && matches!(rhs.kind, ExprKind::IntLit(_)))
                || expr_is_asan_magic_constant(rhs)
                || expr_is_asan_stack_metadata(rhs)
        }
        ExprKind::CompoundAssign { lhs, .. } => expr_contains_asan_shadow_marker(lhs),
        ExprKind::Call { .. } => is_asan_helper_call_expr(stmt),
        _ => false,
    }
}

pub(super) fn elide_stack_clash_probe_scaffolding(
    nodes: Vec<StructuredNode>,
) -> Vec<StructuredNode> {
    let nodes = elide_stack_clash_probe_scaffolding_in_list(nodes);
    prune_dead_stack_clash_target_assignments(nodes)
}

pub(super) fn elide_profiling_probe_calls(
    nodes: Vec<StructuredNode>,
    binary_data: Option<&BinaryDataContext>,
) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .filter_map(|node| elide_profiling_probe_calls_in_node(node, binary_data))
        .collect()
}

fn elide_profiling_probe_calls_in_node(
    node: StructuredNode,
    binary_data: Option<&BinaryDataContext>,
) -> Option<StructuredNode> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements: Vec<_> = statements
                .into_iter()
                .filter(|stmt| !is_profiling_probe_statement(stmt, binary_data))
                .collect();
            if statements.is_empty() {
                None
            } else {
                Some(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                })
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let then_body = elide_profiling_probe_calls(then_body, binary_data);
            let else_body = else_body
                .map(|body| elide_profiling_probe_calls(body, binary_data))
                .filter(|body| !body.is_empty());
            if then_body.is_empty() && else_body.is_none() {
                None
            } else {
                Some(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                })
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: elide_profiling_probe_calls(body, binary_data),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: elide_profiling_probe_calls(body, binary_data),
            condition,
            header,
            exit_block,
        }),
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::For {
            init,
            condition,
            update,
            body: elide_profiling_probe_calls(body, binary_data),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: elide_profiling_probe_calls(body, binary_data),
            header,
            exit_block,
        }),
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => Some(StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(values, body)| (values, elide_profiling_probe_calls(body, binary_data)))
                .collect(),
            default: default.map(|body| elide_profiling_probe_calls(body, binary_data)),
        }),
        StructuredNode::Sequence(nodes) => Some(StructuredNode::Sequence(
            elide_profiling_probe_calls(nodes, binary_data),
        )),
        StructuredNode::Expr(expr) => (!is_profiling_probe_statement(&expr, binary_data))
            .then_some(StructuredNode::Expr(expr)),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => Some(StructuredNode::TryCatch {
            try_body: elide_profiling_probe_calls(try_body, binary_data),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: elide_profiling_probe_calls(handler.body, binary_data),
                    ..handler
                })
                .collect(),
        }),
        other => Some(other),
    }
}

fn elide_stack_clash_probe_scaffolding_in_list(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let nodes: Vec<_> = nodes
        .into_iter()
        .filter_map(elide_stack_clash_probe_scaffolding_in_node)
        .collect();

    let mut result = Vec::with_capacity(nodes.len());
    let mut idx = 0;
    while idx < nodes.len() {
        if let Some((consumed, replacements)) = try_elide_stack_clash_probe_sequence(&nodes[idx..])
        {
            result.extend(replacements);
            idx += consumed;
            continue;
        }

        result.push(nodes[idx].clone());
        idx += 1;
    }

    result
}

fn elide_stack_clash_probe_scaffolding_in_node(node: StructuredNode) -> Option<StructuredNode> {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let then_body = elide_stack_clash_probe_scaffolding_in_list(then_body);
            let else_body = else_body
                .map(elide_stack_clash_probe_scaffolding_in_list)
                .filter(|body| !body.is_empty());
            if then_body.is_empty() && else_body.is_none() {
                None
            } else {
                Some(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                })
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: elide_stack_clash_probe_scaffolding_in_list(body),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: elide_stack_clash_probe_scaffolding_in_list(body),
            condition,
            header,
            exit_block,
        }),
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::For {
            init,
            condition,
            update,
            body: elide_stack_clash_probe_scaffolding_in_list(body),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: elide_stack_clash_probe_scaffolding_in_list(body),
            header,
            exit_block,
        }),
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => Some(StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(values, body)| (values, elide_stack_clash_probe_scaffolding_in_list(body)))
                .collect(),
            default: default.map(elide_stack_clash_probe_scaffolding_in_list),
        }),
        StructuredNode::Sequence(nodes) => Some(StructuredNode::Sequence(
            elide_stack_clash_probe_scaffolding_in_list(nodes),
        )),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => Some(StructuredNode::TryCatch {
            try_body: elide_stack_clash_probe_scaffolding_in_list(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: elide_stack_clash_probe_scaffolding_in_list(handler.body),
                    ..handler
                })
                .collect(),
        }),
        other => Some(other),
    }
}

fn prune_dead_stack_clash_target_assignments(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut uses = HashSet::new();
    collect_all_uses(&nodes, &mut uses);
    nodes
        .into_iter()
        .filter_map(|node| prune_dead_stack_clash_target_assignments_in_node(node, &uses))
        .collect()
}

fn prune_dead_stack_clash_target_assignments_in_node(
    node: StructuredNode,
    uses: &HashSet<String>,
) -> Option<StructuredNode> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements: Vec<_> = statements
                .into_iter()
                .filter(|stmt| {
                    stack_clash_probe_target_assignment_name(stmt)
                        .is_none_or(|name| uses.contains(&name))
                })
                .collect();
            if statements.is_empty() {
                None
            } else {
                Some(StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                })
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            let then_body = prune_dead_stack_clash_target_assignments(then_body);
            let else_body = else_body
                .map(prune_dead_stack_clash_target_assignments)
                .filter(|body| !body.is_empty());
            if then_body.is_empty() && else_body.is_none() {
                None
            } else {
                Some(StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                })
            }
        }
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: prune_dead_stack_clash_target_assignments(body),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: prune_dead_stack_clash_target_assignments(body),
            condition,
            header,
            exit_block,
        }),
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::For {
            init,
            condition,
            update,
            body: prune_dead_stack_clash_target_assignments(body),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: prune_dead_stack_clash_target_assignments(body),
            header,
            exit_block,
        }),
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => Some(StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(values, body)| (values, prune_dead_stack_clash_target_assignments(body)))
                .collect(),
            default: default.map(prune_dead_stack_clash_target_assignments),
        }),
        StructuredNode::Sequence(nodes) => Some(StructuredNode::Sequence(
            prune_dead_stack_clash_target_assignments(nodes),
        )),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => Some(StructuredNode::TryCatch {
            try_body: prune_dead_stack_clash_target_assignments(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|handler| CatchHandler {
                    body: prune_dead_stack_clash_target_assignments(handler.body),
                    ..handler
                })
                .collect(),
        }),
        other => Some(other),
    }
}

fn try_elide_stack_clash_probe_sequence(
    nodes: &[StructuredNode],
) -> Option<(usize, Vec<StructuredNode>)> {
    if let Some((prefix, target_name)) = nodes
        .first()
        .and_then(split_trailing_stack_clash_target_assignment)
    {
        if nodes.len() >= 4
            && node_is_runtime_stack_clash_probe_guard(&nodes[1], &target_name)
            && node_is_single_stack_pointer_adjustment(&nodes[2])
            && node_is_single_probe_tail_touch_if(&nodes[3])
        {
            let mut replacements = Vec::new();
            if let Some(prefix) = prefix {
                replacements.push(prefix);
            }
            return Some((4, replacements));
        }

        if nodes.len() >= 3
            && node_is_runtime_stack_clash_probe_guard(&nodes[1], &target_name)
            && node_is_single_stack_pointer_adjustment(&nodes[2])
        {
            let mut replacements = Vec::new();
            if let Some(prefix) = prefix {
                replacements.push(prefix);
            }
            return Some((3, replacements));
        }

        if nodes.len() >= 2 && node_is_runtime_stack_clash_probe_guard(&nodes[1], &target_name) {
            let mut replacements = Vec::new();
            if let Some(prefix) = prefix {
                replacements.push(prefix);
            }
            return Some((2, replacements));
        }

        if nodes.len() >= 2 && node_is_stack_clash_probe_loop(&nodes[1], &target_name) {
            let mut replacements = Vec::new();
            if let Some(prefix) = prefix {
                replacements.push(prefix);
            }
            return Some((2, replacements));
        }
    }

    if runtime_stack_clash_probe_guard_target(nodes.first()?).is_some() {
        if nodes.len() >= 3
            && node_is_single_stack_pointer_adjustment(&nodes[1])
            && node_is_single_probe_tail_touch_if(&nodes[2])
        {
            return Some((3, Vec::new()));
        }
        if nodes.len() >= 2 && node_is_single_stack_pointer_adjustment(&nodes[1]) {
            return Some((2, Vec::new()));
        }
        return Some((1, Vec::new()));
    }

    if nodes.len() >= 2
        && node_is_single_stack_pointer_adjustment(nodes.first()?)
        && node_is_single_probe_tail_touch_if(&nodes[1])
    {
        return Some((2, Vec::new()));
    }

    if stack_clash_probe_loop_target(nodes.first()?).is_some() {
        return Some((1, Vec::new()));
    }

    None
}

fn split_trailing_stack_clash_target_assignment(
    node: &StructuredNode,
) -> Option<(Option<StructuredNode>, String)> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let (last, prefix) = statements.split_last()?;
            let target_name = stack_clash_probe_target_assignment_name(last)?;
            let prefix = (!prefix.is_empty()).then(|| StructuredNode::Block {
                id: *id,
                statements: prefix.to_vec(),
                address_range: *address_range,
            });
            Some((prefix, target_name))
        }
        StructuredNode::Expr(expr) => {
            let target_name = stack_clash_probe_target_assignment_name(expr)?;
            Some((None, target_name))
        }
        _ => None,
    }
}

fn stack_clash_probe_target_assignment_name(expr: &Expr) -> Option<String> {
    let ExprKind::Assign { lhs, rhs } = &expr.kind else {
        return None;
    };
    let target_name = expr_simple_identifier(lhs)?;
    if matches!(target_name, "sp" | "rsp" | "esp") {
        return None;
    }
    if expr_has_side_effects(rhs)
        || !expr_mentions_stack_pointer(rhs)
        || expr_mentions_identifier(rhs, target_name)
    {
        return None;
    }
    Some(target_name.to_string())
}

fn node_is_runtime_stack_clash_probe_guard(node: &StructuredNode, target_name: &str) -> bool {
    runtime_stack_clash_probe_guard_target(node).as_deref() == Some(target_name)
}

fn runtime_stack_clash_probe_guard_target(node: &StructuredNode) -> Option<String> {
    let StructuredNode::If {
        condition,
        then_body,
        else_body,
    } = node
    else {
        return None;
    };
    if else_body.is_some() {
        return None;
    }
    let target_name = body_is_single_stack_clash_probe_loop_target(then_body)?;
    if stack_pointer_compare_matches_target(condition, &target_name)
        || stack_pointer_self_compare(condition)
    {
        Some(target_name)
    } else {
        None
    }
}

fn body_is_single_stack_clash_probe_loop(body: &[StructuredNode], target_name: &str) -> bool {
    body_is_single_stack_clash_probe_loop_target(body).as_deref() == Some(target_name)
}

fn body_is_single_stack_clash_probe_loop_target(body: &[StructuredNode]) -> Option<String> {
    stack_clash_probe_loop_target(extract_single_node(body)?)
}

fn node_is_stack_clash_probe_loop(node: &StructuredNode, target_name: &str) -> bool {
    stack_clash_probe_loop_target(node).as_deref() == Some(target_name)
}

fn stack_clash_probe_loop_target(node: &StructuredNode) -> Option<String> {
    match node {
        StructuredNode::While {
            condition, body, ..
        }
        | StructuredNode::DoWhile {
            body, condition, ..
        } => {
            let target_name = stack_pointer_compare_target_name(condition)?;
            ((structured_nodes_are_empty(body) || stack_clash_probe_loop_body_matches(body))
                && !target_name.is_empty())
            .then_some(target_name)
        }
        StructuredNode::Sequence(nodes) => body_is_single_stack_clash_probe_loop_target(nodes),
        _ => None,
    }
}

fn node_is_single_stack_pointer_adjustment(node: &StructuredNode) -> bool {
    single_statement_from_node(node).is_some_and(expr_is_stack_pointer_adjustment)
}

fn node_is_single_probe_tail_touch_if(node: &StructuredNode) -> bool {
    let StructuredNode::If {
        then_body,
        else_body,
        ..
    } = node
    else {
        return false;
    };
    else_body.is_none()
        && extract_single_node(then_body)
            .and_then(single_statement_from_node)
            .is_some_and(expr_is_probe_tail_touch_assignment)
}

fn stack_clash_probe_loop_body_matches(body: &[StructuredNode]) -> bool {
    let mut statements = Vec::new();
    if !collect_flat_statements(body, &mut statements) {
        return false;
    }

    matches!(
        statements.as_slice(),
        [sub, touch]
            if expr_is_page_probe_subtraction(sub) && expr_is_stack_probe_touch_assignment(touch)
    )
}

fn extract_single_node(nodes: &[StructuredNode]) -> Option<&StructuredNode> {
    match nodes {
        [node] => match node {
            StructuredNode::Sequence(inner) => extract_single_node(inner),
            other => Some(other),
        },
        _ => None,
    }
}

fn single_statement_from_node(node: &StructuredNode) -> Option<&Expr> {
    match node {
        StructuredNode::Block { statements, .. } => match statements.as_slice() {
            [stmt] => Some(stmt),
            _ => None,
        },
        StructuredNode::Expr(expr) => Some(expr),
        StructuredNode::Sequence(nodes) => {
            extract_single_node(nodes).and_then(single_statement_from_node)
        }
        _ => None,
    }
}

fn expr_is_stack_pointer_adjustment(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, rhs } if expr_is_stack_pointer(lhs) => match &rhs.kind {
            ExprKind::BinOp {
                op: BinOpKind::Sub,
                left,
                ..
            } => expr_is_stack_pointer(left),
            _ => false,
        },
        ExprKind::CompoundAssign {
            op: BinOpKind::Sub,
            lhs,
            ..
        } => expr_is_stack_pointer(lhs),
        _ => false,
    }
}

fn expr_is_page_probe_subtraction(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, rhs } if expr_is_stack_pointer(lhs) => match &rhs.kind {
            ExprKind::BinOp {
                op: BinOpKind::Sub,
                left,
                right,
            } => expr_is_stack_pointer(left) && matches!(right.kind, ExprKind::IntLit(0x1000)),
            _ => false,
        },
        ExprKind::CompoundAssign {
            op: BinOpKind::Sub,
            lhs,
            rhs,
        } => expr_is_stack_pointer(lhs) && matches!(rhs.kind, ExprKind::IntLit(0x1000)),
        _ => false,
    }
}

fn expr_is_probe_tail_touch_assignment(expr: &Expr) -> bool {
    let ExprKind::Assign { lhs, rhs } = &expr.kind else {
        return false;
    };
    expr_is_memory_lvalue(lhs) && exprs_structurally_equal(lhs, rhs)
}

fn expr_is_stack_probe_touch_assignment(expr: &Expr) -> bool {
    let ExprKind::Assign { lhs, rhs } = &expr.kind else {
        return false;
    };
    expr_is_memory_lvalue(lhs)
        && exprs_structurally_equal(lhs, rhs)
        && expr_mentions_stack_pointer(lhs)
        && expr_mentions_stack_pointer(rhs)
}

fn expr_is_memory_lvalue(expr: &Expr) -> bool {
    matches!(
        expr.kind,
        ExprKind::Deref { .. }
            | ExprKind::ArrayAccess { .. }
            | ExprKind::FieldAccess { .. }
            | ExprKind::BitField { .. }
    )
}

fn stack_pointer_compare_matches_target(expr: &Expr, target_name: &str) -> bool {
    stack_pointer_compare_target_name(expr).as_deref() == Some(target_name)
}

fn stack_pointer_compare_target_name(expr: &Expr) -> Option<String> {
    let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &expr.kind
    else {
        return None;
    };

    if expr_is_stack_pointer(left) {
        return expr_simple_identifier(right).map(str::to_string);
    }
    if expr_is_stack_pointer(right) {
        return expr_simple_identifier(left).map(str::to_string);
    }
    None
}

fn stack_pointer_self_compare(expr: &Expr) -> bool {
    let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &expr.kind
    else {
        return false;
    };
    expr_is_stack_pointer(left) && expr_is_stack_pointer(right)
}

fn expr_mentions_stack_pointer(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Var(var) => matches!(var.name.as_str(), "sp" | "rsp" | "esp"),
        ExprKind::Unknown(_) | ExprKind::IntLit(_) => false,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_mentions_stack_pointer(left) || expr_mentions_stack_pointer(right),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_mentions_stack_pointer(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_mentions_stack_pointer(base) || expr_mentions_stack_pointer(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_mentions_stack_pointer(base),
        ExprKind::Call { target, args } => {
            let target_mentions = match target {
                CallTarget::Indirect(expr) | CallTarget::IndirectGot { expr, .. } => {
                    expr_mentions_stack_pointer(expr)
                }
                CallTarget::Direct { .. } | CallTarget::Named(_) => false,
            };
            target_mentions || args.iter().any(expr_mentions_stack_pointer)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_mentions_stack_pointer(cond)
                || expr_mentions_stack_pointer(then_expr)
                || expr_mentions_stack_pointer(else_expr)
        }
        ExprKind::Phi(values) => values.iter().any(expr_mentions_stack_pointer),
        ExprKind::GotRef { display_expr, .. } => expr_mentions_stack_pointer(display_expr),
    }
}

fn expr_is_stack_pointer(expr: &Expr) -> bool {
    matches!(
        expr_simple_identifier(expr),
        Some("sp") | Some("rsp") | Some("esp")
    )
}

fn structured_nodes_are_empty(nodes: &[StructuredNode]) -> bool {
    nodes.iter().all(structured_node_is_empty)
}

fn structured_node_is_empty(node: &StructuredNode) -> bool {
    match node {
        StructuredNode::Block { statements, .. } => statements.is_empty(),
        StructuredNode::Sequence(nodes) => structured_nodes_are_empty(nodes),
        _ => false,
    }
}

fn collect_flat_statements<'a>(nodes: &'a [StructuredNode], out: &mut Vec<&'a Expr>) -> bool {
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => out.extend(statements.iter()),
            StructuredNode::Expr(expr) => out.push(expr),
            StructuredNode::Sequence(inner) => {
                if !collect_flat_statements(inner, out) {
                    return false;
                }
            }
            _ => return false,
        }
    }
    true
}

fn is_asan_helper_call_expr(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    matches!(
        &expr.kind,
        ExprKind::Call {
            target: CallTarget::Named(name),
            ..
        } if normalize_known_call_name(name).starts_with("asan_")
    )
}

fn is_profiling_probe_statement(expr: &Expr, binary_data: Option<&BinaryDataContext>) -> bool {
    match &expr.kind {
        ExprKind::Call { target, .. } => call_target_is_profiling_probe(target, binary_data),
        ExprKind::Assign { rhs, .. } => match &rhs.kind {
            ExprKind::Call { target, .. } => call_target_is_profiling_probe(target, binary_data),
            _ => false,
        },
        _ => false,
    }
}

fn call_target_is_profiling_probe(
    target: &CallTarget,
    binary_data: Option<&BinaryDataContext>,
) -> bool {
    resolved_known_call_name(target, binary_data)
        .and_then(|name| {
            let base = name.split('@').next().unwrap_or(name.as_str());
            matches!(
                base,
                "mcount"
                    | "_mcount"
                    | "__gnu_mcount_nc"
                    | "__fentry__"
                    | "__cyg_profile_func_enter"
                    | "__cyg_profile_func_exit"
            )
            .then_some(())
        })
        .is_some()
}

fn expr_contains_asan_shadow_marker(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::IntLit(value) => matches!(
            *value as i64 as u64,
            0x7fff8000 | 0x1fffe000 | 0x1fffe001 | 0x1fffe002 | 0x1fffe003
        ),
        ExprKind::Var(_) | ExprKind::Unknown(_) => false,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_contains_asan_shadow_marker(left) || expr_contains_asan_shadow_marker(right),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_contains_asan_shadow_marker(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_contains_asan_shadow_marker(base) || expr_contains_asan_shadow_marker(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_contains_asan_shadow_marker(base),
        ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
            args.iter().any(expr_contains_asan_shadow_marker)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_contains_asan_shadow_marker(cond)
                || expr_contains_asan_shadow_marker(then_expr)
                || expr_contains_asan_shadow_marker(else_expr)
        }
        ExprKind::GotRef { display_expr, .. } => expr_contains_asan_shadow_marker(display_expr),
    }
}

fn expr_is_asan_magic_constant(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    let ExprKind::IntLit(value) = expr.kind else {
        return false;
    };
    matches!(
        value as i64 as u32,
        0x41b58ab3 | 0x45e0360e | 0xf1f1f1f1 | 0xf3f3f3f3
    )
}

fn expr_is_asan_stack_metadata(expr: &Expr) -> bool {
    match resolve_string_literal(expr, None) {
        Some(text) => {
            text.chars()
                .next()
                .is_some_and(|first| first.is_ascii_digit())
                && text.contains("buf:")
        }
        None => false,
    }
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
                                if expr_has_side_effects_from_assignment(stmt) {
                                    return true; // Keep side-effecting temp captures (e.g. atomics)
                                }
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
                                record_register_substitution(
                                    temps,
                                    &v.name,
                                    v.size,
                                    rhs_substituted,
                                );
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
                                    record_register_substitution(temps, &v.name, v.size, new_val);
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
            StructuredNode::Sequence(simplify_sequence_node_copies(nodes))
        }
        // Pass through other nodes unchanged
        other => other,
    }
}

fn simplify_sequence_node_copies(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    fn flush_expr_run(run: &mut Vec<Expr>, out: &mut Vec<StructuredNode>) {
        if run.is_empty() {
            return;
        }
        for expr in propagate_copies(std::mem::take(run)) {
            out.push(StructuredNode::Expr(expr));
        }
    }

    let mut simplified = Vec::with_capacity(nodes.len());
    let mut expr_run = Vec::new();

    for node in nodes {
        match node {
            StructuredNode::Expr(expr) => expr_run.push(expr),
            other => {
                flush_expr_run(&mut expr_run, &mut simplified);
                simplified.push(simplify_node_copies(other));
            }
        }
    }

    flush_expr_run(&mut expr_run, &mut simplified);
    simplified
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
    let mut compound_updated_aliases: HashSet<String> = HashSet::new();
    let mut stack_slot_values: HashMap<String, Expr> = HashMap::new();
    // Registers written earlier in this block hold local temporaries, not the
    // incoming argument, so a later spill of one must not be canonicalized back
    // to `argN` (mirrors the def-aware exclusion in the propagate_call_args path).
    let mut clobbered_regs: HashSet<String> = HashSet::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for stmt in statements.into_iter() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            // Always substitute known register values in the RHS
            let new_lhs = substitute_assignment_lhs(lhs, &reg_values);
            let new_rhs = if should_preserve_materialized_compound_temp_rhs(
                lhs,
                rhs,
                &compound_updated_aliases,
            ) {
                (**rhs).clone()
            } else {
                substitute_stack_slot_values(substitute_vars(rhs, &reg_values), &stack_slot_values)
            };

            if let ExprKind::Var(lhs_var) = &lhs.kind {
                let written_aliases: HashSet<String> =
                    get_register_aliases(&lhs_var.name).into_iter().collect();
                // Once written, this register is a local temporary for the rest
                // of the block, not the incoming argument.
                for alias in &written_aliases {
                    clobbered_regs.insert(alias.to_lowercase());
                }
                invalidate_clobbered_register_mappings(&mut reg_values, &lhs_var.name);
                invalidate_tracked_compound_updated_aliases(
                    &mut compound_updated_aliases,
                    &written_aliases,
                );
                invalidate_dependent_stack_slot_values(&mut stack_slot_values, &written_aliases);
                if aliases_include_stack_base(&written_aliases) {
                    stack_slot_values.clear();
                }

                // Check if LHS is a temp register
                if is_temp_register(&lhs_var.name) {
                    // Track this assignment for all aliased register names
                    // (e.g., w9 and x9 on ARM64, eax and rax on x86)
                    if !expr_requires_single_evaluation(&new_rhs) {
                        record_register_substitution(
                            &mut reg_values,
                            &lhs_var.name,
                            lhs_var.size,
                            new_rhs.clone(),
                        );
                    }
                    if expr_uses_any_register_alias(&new_rhs, &written_aliases) {
                        compound_updated_aliases.extend(written_aliases.iter().cloned());
                    }
                    // Emit with substituted RHS (keep the assignment for now)
                    result.push(Expr::assign((**lhs).clone(), new_rhs));
                    continue;
                }
            }

            if let Some(slot_key) = stack_slot_key(&new_lhs) {
                let stabilized_rhs =
                    stabilize_saved_arg_registers_excluding(new_rhs, &clobbered_regs);
                stack_slot_values.remove(&slot_key);
                if !expr_requires_single_evaluation(&stabilized_rhs) {
                    stack_slot_values.insert(slot_key, stabilized_rhs.clone());
                }
                result.push(Expr::assign(new_lhs, stabilized_rhs));
                continue;
            }

            // Non-temp LHS (memory location or non-temp register): emit with substitution
            result.push(Expr::assign(new_lhs, new_rhs));
            continue;
        }

        if let ExprKind::CompoundAssign { op, lhs, rhs } = &stmt.kind {
            let new_rhs =
                substitute_stack_slot_values(substitute_vars(rhs, &reg_values), &stack_slot_values);
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                let aliases = get_register_aliases(&lhs_var.name);
                let alias_set: HashSet<String> = aliases.iter().cloned().collect();
                let prior_value = if is_temp_register(&lhs_var.name) {
                    aliases
                        .iter()
                        .find_map(|alias| reg_values.get(alias).cloned())
                } else {
                    None
                };
                invalidate_clobbered_register_mappings(&mut reg_values, &lhs_var.name);
                invalidate_tracked_compound_updated_aliases(
                    &mut compound_updated_aliases,
                    &alias_set,
                );
                if is_temp_register(&lhs_var.name)
                    && compound_update_defines_full_alias_value(&lhs_var.name)
                    && lifted_var_size_defines_full_alias(&lhs_var.name, lhs_var.size)
                {
                    if let Some(current) = prior_value {
                        if !expr_uses_any_alias(&current, &aliases) {
                            let new_val = Expr::binop(*op, current, new_rhs.clone()).simplify();
                            if !expr_requires_single_evaluation(&new_val) {
                                for alias in aliases {
                                    reg_values.insert(alias, new_val.clone());
                                }
                                compound_updated_aliases.extend(alias_set);
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
            let substituted = substitute_stack_slot_values(
                substitute_vars(&stmt, &reg_values),
                &stack_slot_values,
            );
            if let ExprKind::Call { target, .. } = &substituted.kind {
                if is_real_function_call(target) {
                    reg_values.clear();
                    compound_updated_aliases.clear();
                    stack_slot_values.clear();
                } else {
                    invalidate_pseudo_call_output_copies(&mut reg_values, target);
                    let written_aliases: HashSet<String> = call_output_alias_groups(target)
                        .into_iter()
                        .flatten()
                        .collect();
                    if !written_aliases.is_empty() {
                        invalidate_tracked_compound_updated_aliases(
                            &mut compound_updated_aliases,
                            &written_aliases,
                        );
                        invalidate_dependent_stack_slot_values(
                            &mut stack_slot_values,
                            &written_aliases,
                        );
                        if aliases_include_stack_base(&written_aliases) {
                            stack_slot_values.clear();
                        }
                    }
                }
            }
            result.push(substituted);
            continue;
        }
        // Non-assignment statement: pass through
        result.push(stmt);
    }

    let result = collapse_single_use_call_result_copies(result);
    let result = collapse_single_use_named_call_results(result);
    collapse_single_use_temp_loads(result)
}

/// Count how many times `name` occurs as a variable/unknown identifier in
/// `expr`, in any position (read or write).
fn count_identifier_occurrences(expr: &Expr, name: &str) -> usize {
    use super::super::expression::{CallTarget, ExprKind};

    let here = match &expr.kind {
        ExprKind::Var(v) => (v.name == name) as usize,
        ExprKind::Unknown(n) => (n == name) as usize,
        _ => 0,
    };
    let children = match &expr.kind {
        ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => 0,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => count_identifier_occurrences(left, name) + count_identifier_occurrences(right, name),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => count_identifier_occurrences(operand, name),
        ExprKind::ArrayAccess { base, index, .. } => {
            count_identifier_occurrences(base, name) + count_identifier_occurrences(index, name)
        }
        ExprKind::FieldAccess { base, .. } => count_identifier_occurrences(base, name),
        ExprKind::Call { target, args } => {
            let target_count = match target {
                CallTarget::Indirect(e) | CallTarget::IndirectGot { expr: e, .. } => {
                    count_identifier_occurrences(e, name)
                }
                _ => 0,
            };
            target_count
                + args
                    .iter()
                    .map(|a| count_identifier_occurrences(a, name))
                    .sum::<usize>()
        }
        ExprKind::Phi(args) => args
            .iter()
            .map(|a| count_identifier_occurrences(a, name))
            .sum(),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            count_identifier_occurrences(cond, name)
                + count_identifier_occurrences(then_expr, name)
                + count_identifier_occurrences(else_expr, name)
        }
        ExprKind::GotRef { display_expr, .. } => count_identifier_occurrences(display_expr, name),
    };
    here + children
}

/// Collapse a temp register holding a single-evaluation value (e.g. a memory
/// load) into its sole, immediately-following use.
///
/// `propagate_copies` deliberately refuses to substitute
/// `expr_requires_single_evaluation` values (loads, derefs) to avoid
/// duplicating a load, so `ret = arr[i]; s += ret` is left split across two
/// statements. But when the temp is read exactly once, in the *immediately
/// following* statement, there is no duplication and — because the use is
/// adjacent — no intervening clobber, store, or call can change the value's
/// meaning. In that case the load can safely fold into the use:
/// `s += arr[i]`. Anything less constrained (a non-adjacent use, multiple
/// uses) is left alone.
fn collapse_single_use_temp_loads(mut statements: Vec<Expr>) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    let mut i = 0usize;
    while i + 1 < statements.len() {
        let ExprKind::Assign { lhs, rhs } = &statements[i].kind else {
            i += 1;
            continue;
        };
        let Some(temp) = expr_simple_identifier(lhs) else {
            i += 1;
            continue;
        };
        // Only fold temp registers holding a single-evaluation value (the case
        // copy-prop skipped); pure values were already propagated. A real call
        // result is handled by collapse_single_use_call_result_copies. The value
        // must not reference the temp itself (`rax = *(rax + 4)`).
        let is_real_call =
            matches!(&rhs.kind, ExprKind::Call { target, .. } if is_real_function_call(target));
        if !is_temp_register(temp)
            || !expr_requires_single_evaluation(rhs)
            || is_real_call
            || count_identifier_occurrences(rhs, temp) > 0
        {
            i += 1;
            continue;
        }
        let temp = temp.to_string();

        // Exactly one read of the temp across the rest of the block, and it must
        // be in the immediately following statement, which must not also write
        // the temp. Adjacency is what makes the move sound.
        let next_uses = count_identifier_occurrences(&statements[i + 1], &temp);
        let later_uses: usize = statements[i + 2..]
            .iter()
            .map(|s| count_identifier_occurrences(s, &temp))
            .sum();
        if next_uses != 1 || later_uses != 0 || stmt_writes_identifier(&statements[i + 1], &temp) {
            i += 1;
            continue;
        }

        let value = match &statements[i].kind {
            ExprKind::Assign { rhs, .. } => (**rhs).clone(),
            _ => unreachable!(),
        };
        let substitutions = HashMap::from([(temp, value)]);
        statements[i + 1] = substitute_vars(&statements[i + 1], &substitutions);
        statements.remove(i);
        // Stay at i: the folded statement may itself now be foldable, and the
        // loop terminates because the vector shrank.
    }

    statements
}

fn expr_simple_identifier(expr: &Expr) -> Option<&str> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.as_str()),
        ExprKind::Unknown(name) => Some(name.as_str()),
        ExprKind::Cast { expr, .. } => expr_simple_identifier(expr),
        _ => None,
    }
}

fn expr_mentions_identifier(expr: &Expr, name: &str) -> bool {
    match &expr.kind {
        ExprKind::Var(var) => var.name == name,
        ExprKind::Unknown(candidate) => candidate == name,
        ExprKind::BinOp { left, right, .. }
        | ExprKind::Assign {
            lhs: left,
            rhs: right,
        }
        | ExprKind::CompoundAssign {
            lhs: left,
            rhs: right,
            ..
        } => expr_mentions_identifier(left, name) || expr_mentions_identifier(right, name),
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_mentions_identifier(operand, name),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_mentions_identifier(base, name) || expr_mentions_identifier(index, name)
        }
        ExprKind::FieldAccess { base, .. } => expr_mentions_identifier(base, name),
        ExprKind::Call { target, args } => {
            let target_mentions = match target {
                CallTarget::Indirect(expr) | CallTarget::IndirectGot { expr, .. } => {
                    expr_mentions_identifier(expr, name)
                }
                CallTarget::Direct { .. } | CallTarget::Named(_) => false,
            };
            target_mentions || args.iter().any(|arg| expr_mentions_identifier(arg, name))
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_mentions_identifier(cond, name)
                || expr_mentions_identifier(then_expr, name)
                || expr_mentions_identifier(else_expr, name)
        }
        ExprKind::Phi(values) => values
            .iter()
            .any(|value| expr_mentions_identifier(value, name)),
        ExprKind::GotRef { display_expr, .. } => expr_mentions_identifier(display_expr, name),
        ExprKind::IntLit(_) => false,
    }
}

fn stmt_writes_identifier(expr: &Expr, name: &str) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
            expr_simple_identifier(lhs).is_some_and(|lhs_name| lhs_name == name)
        }
        _ => false,
    }
}

fn collapse_single_use_call_result_copies(mut statements: Vec<Expr>) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    let mut i = 0usize;
    while i + 1 < statements.len() {
        let (temp_name, target, args) = match &statements[i].kind {
            ExprKind::Assign { lhs, rhs } => {
                let Some(temp_name) = expr_simple_identifier(lhs) else {
                    i += 1;
                    continue;
                };
                let ExprKind::Call { target, args } = &rhs.kind else {
                    i += 1;
                    continue;
                };
                if !temp_name.starts_with("ret_") || !is_real_function_call(target) {
                    i += 1;
                    continue;
                }
                (temp_name.to_string(), target.clone(), args.clone())
            }
            _ => {
                i += 1;
                continue;
            }
        };

        let (copy_lhs_name, copy_lhs) = match &statements[i + 1].kind {
            ExprKind::Assign { lhs, rhs } => {
                let Some(rhs_name) = expr_simple_identifier(rhs) else {
                    i += 1;
                    continue;
                };
                let Some(lhs_name) = expr_simple_identifier(lhs) else {
                    i += 1;
                    continue;
                };
                if rhs_name != temp_name || lhs_name == temp_name || lhs_name.starts_with("ret_") {
                    i += 1;
                    continue;
                }
                (lhs_name.to_string(), (**lhs).clone())
            }
            _ => {
                i += 1;
                continue;
            }
        };

        if statements[i + 2..].iter().any(|stmt| {
            stmt_writes_identifier(stmt, &temp_name) || stmt_writes_identifier(stmt, &copy_lhs_name)
        }) {
            i += 1;
            continue;
        }

        let substitutions = HashMap::from([(temp_name.clone(), copy_lhs.clone())]);
        for stmt in &mut statements[i + 2..] {
            *stmt = substitute_vars(stmt, &substitutions);
        }
        statements[i] = Expr::assign(copy_lhs, Expr::call(target, args));
        statements.remove(i + 1);
    }

    statements
}

/// Second-stage call-result fold: after `collapse_single_use_call_result_copies`
/// renames the temp register to its slot (turning `ret_X = call(); var_Y =
/// ret_X;` into `var_Y = call();`), the resulting `<named_local> = call();`
/// is itself a candidate for single-use-adjacent folding into the very next
/// statement. The existing `collapse_single_use_temp_loads` pass refuses
/// real calls and only handles register-named temps, so this thread-through
/// step is what turns `var_2c = sub_50(); return var_2c << 1;` into
/// `return sub_50() << 1;`.
///
/// Safety mirrors the other single-use folds: the named local must be read
/// exactly once across the rest of the block AND that single read must be in
/// the immediately-following statement, which must not also write the name.
/// Adjacency is what makes the move sound — no intervening side effect can
/// change semantics. A call result is moved, not duplicated, so even
/// side-effectful calls are preserved. Register-named temps are left to
/// `collapse_single_use_temp_loads` (its existing call-exclusion is now
/// redundant but harmless; this pass picks up the named-local case it
/// declined).
fn collapse_single_use_named_call_results(mut statements: Vec<Expr>) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    let mut i = 0usize;
    while i + 1 < statements.len() {
        let (name, call_expr) = match &statements[i].kind {
            ExprKind::Assign { lhs, rhs } => {
                let Some(name) = expr_simple_identifier(lhs) else {
                    i += 1;
                    continue;
                };
                let ExprKind::Call { target, .. } = &rhs.kind else {
                    i += 1;
                    continue;
                };
                if !is_real_function_call(target) {
                    i += 1;
                    continue;
                }
                // Skip register temps — the existing temp-load pass owns
                // those, and threading them here would mask the
                // call-result-copies rename pattern earlier in the chain.
                if is_temp_register(name) {
                    i += 1;
                    continue;
                }
                // Don't fold into a name that references itself in the call
                // (`local_8 = f(local_8)`); that's a real use, not a
                // throw-away temp.
                if count_identifier_occurrences(rhs, name) > 0 {
                    i += 1;
                    continue;
                }
                (name.to_string(), (**rhs).clone())
            }
            _ => {
                i += 1;
                continue;
            }
        };

        let next_uses = count_identifier_occurrences(&statements[i + 1], &name);
        let later_uses: usize = statements[i + 2..]
            .iter()
            .map(|s| count_identifier_occurrences(s, &name))
            .sum();
        if next_uses != 1 || later_uses != 0 || stmt_writes_identifier(&statements[i + 1], &name) {
            i += 1;
            continue;
        }
        // Don't fold a call into a consumer that itself contains another
        // call: in C/C++, argument and operand evaluation order is
        // unspecified, so substituting `tmp = foo(); out = bar(baz(),
        // tmp);` into `out = bar(baz(), foo());` would change the
        // *apparent* execution order between the two side-effecting
        // calls. Keep the spill in that case.
        if expr_contains_call(&statements[i + 1]) {
            i += 1;
            continue;
        }

        let substitutions = HashMap::from([(name, call_expr)]);
        statements[i + 1] = substitute_vars(&statements[i + 1], &substitutions);
        statements.remove(i);
        // Stay at i: the folded statement may itself now be foldable, and the
        // loop terminates because the vector shrank.
    }

    statements
}

/// Deep walk for any real-function `Call` node anywhere inside `expr`
/// (operand of a `BinOp`, argument of another `Call`, condition of a
/// `Conditional`, etc.). Used to guard the
/// `collapse_single_use_named_call_results` fold from re-sequencing two
/// side-effecting calls into one C expression where their order would
/// become unspecified.
fn expr_contains_call(expr: &Expr) -> bool {
    use super::super::expression::{CallTarget, ExprKind};

    match &expr.kind {
        ExprKind::Call { target, args } => {
            is_real_function_call(target)
                || args.iter().any(expr_contains_call)
                || matches!(target, CallTarget::Indirect(e) | CallTarget::IndirectGot { expr: e, .. } if expr_contains_call(e))
        }
        ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
            expr_contains_call(lhs) || expr_contains_call(rhs)
        }
        ExprKind::BinOp { left, right, .. } => {
            expr_contains_call(left) || expr_contains_call(right)
        }
        ExprKind::UnaryOp { operand, .. }
        | ExprKind::Deref { addr: operand, .. }
        | ExprKind::AddressOf(operand)
        | ExprKind::Cast { expr: operand, .. }
        | ExprKind::BitField { expr: operand, .. } => expr_contains_call(operand),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_contains_call(base) || expr_contains_call(index)
        }
        ExprKind::FieldAccess { base, .. } => expr_contains_call(base),
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            expr_contains_call(cond)
                || expr_contains_call(then_expr)
                || expr_contains_call(else_expr)
        }
        ExprKind::Phi(values) => values.iter().any(expr_contains_call),
        ExprKind::GotRef { display_expr, .. } => expr_contains_call(display_expr),
        ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => false,
    }
}

fn invalidate_clobbered_register_mappings(reg_values: &mut HashMap<String, Expr>, written: &str) {
    let aliases = get_register_aliases(written);
    reg_values.retain(|name, value| {
        !aliases.iter().any(|alias| alias == name) && !expr_uses_any_alias(value, &aliases)
    });
}

/// Record `substituted_rhs` for the registers that `var_name = ...` actually
/// defines. Full-width writes (rax/eax/edi/etc.) propagate to every alias
/// (rax/eax/ax/al on x86, xN/wN on ARM64) so later reads of any width recover
/// the same value. Sub-register writes (al/ah/ax, bl/bh/bx, ...) only update
/// the same-name slot — the wider aliases hold an untracked partial-merge
/// value (`(rax_prior & ~mask) | (sub & mask)`) and the caller has already
/// invalidated them. Propagating the sub-register expression into the wider
/// alias caused exponential expression growth: when the same sub-register
/// was assigned twice (e.g. `add al, al; add al, al`) and then read through
/// the wider alias (e.g. `or [rax], al`), each subsequent simplification pass
/// re-substituted through the alias map, doubling the expression on every
/// pass. Cf. the 11-byte fuzz repro `64 00 c0 00 0f 00 c0 a3 08 00 5a`.
fn record_register_substitution(
    reg_values: &mut HashMap<String, Expr>,
    var_name: &str,
    var_size_bytes: u8,
    substituted_rhs: Expr,
) {
    if !lifted_var_size_defines_full_alias(var_name, var_size_bytes) {
        // Sub-register write (al/ah/ax/al-class). Wider aliases carry an
        // untracked partial-merge value and must stay invalidated by the
        // caller; propagating the sub-register expression into them caused
        // exponential growth across simplification passes
        // (cf. fuzz/artifacts/decompiler/oom-* repro).
        return;
    }
    if expr_node_count(&substituted_rhs) > SUBSTITUTION_VALUE_NODE_CAP {
        // Defense in depth: refuse to memo any expression that has already
        // grown larger than what a real-world decompile would produce.
        // Specific cascade patterns (sub-register self-update, cmov on the
        // same operand) have targeted fixes above, but the fuzz corpus
        // showed many other adversarial-input shapes that doubled the
        // expression across simplification passes (top sweep result was
        // 127 MB of pseudo-C from an 11-byte input). Refusing to memo and
        // refusing to substitute past this cap (see substitute_vars below)
        // caps the worst case at O(cap) per statement regardless of the
        // pattern.
        return;
    }
    if compound_update_defines_full_alias_value(var_name) {
        for alias in get_register_aliases(var_name) {
            reg_values.insert(alias, substituted_rhs.clone());
        }
    } else {
        reg_values.insert(var_name.to_string(), substituted_rhs);
    }
}

/// Decides whether a register write at this width fully defines the
/// canonical-name slot in the substitution map. Hexray normalizes
/// x86-64 partial registers (`al`, `ax`, `eax`) to their 64-bit canonical
/// name (`rax`) but keeps the original byte size on the `Variable`. The
/// size is what tells us whether a write replaces the wider register's
/// value (`mov eax, ...` zero-extends to rax) or only mutates a slice
/// (`add al, al` leaves the upper 56 bits of rax untouched).
fn lifted_var_size_defines_full_alias(var_name: &str, size_bytes: u8) -> bool {
    if !matches!(
        var_name,
        // x86-64 64-bit canonical names that have sub-register variants.
        "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi"
            | "rbp" | "rsp"
            | "r8" | "r9" | "r10" | "r11" | "r12" | "r13" | "r14" | "r15"
            // ARM64 — `xN` may carry a 4-byte `wN` write.
            | "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6" | "x7"
            | "x8" | "x9" | "x10" | "x11" | "x12" | "x13" | "x14" | "x15"
            | "x16" | "x17" | "x18" | "x29" | "x30"
    ) {
        return true;
    }
    // x86-64: 4-byte writes zero-extend the 64-bit reg; 8-byte writes
    // fully define it. 1/2-byte writes leave upper bits intact.
    // ARM64: 4-byte `wN` writes zero-extend `xN`; 8-byte writes do too.
    matches!(size_bytes, 4 | 8)
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

/// Upper bound on the size of a substitution value we are willing to memo or
/// inline. Real decompiles produce expressions in the low tens of nodes; the
/// fuzz corpus surfaced adversarial-input shapes (chained self-cmov, chained
/// sub-register self-update through partial registers, etc.) that doubled
/// expressions across every simplification pass and reached 127 MB of pseudo-C
/// from an 11-byte input. Refusing to memo or substitute past this cap caps
/// the worst-case per-statement output at O(cap) regardless of the cascade
/// pattern. 256 leaves comfortable headroom over real-world expressions.
const SUBSTITUTION_VALUE_NODE_CAP: usize = 256;

/// Count the AST nodes in `expr`, short-circuiting once we exceed `limit + 1`
/// so very large expressions don't waste time being fully traversed.
fn expr_node_count_bounded(expr: &Expr, limit: usize) -> usize {
    use super::super::expression::ExprKind;

    fn walk(expr: &Expr, budget: &mut usize) {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        match &expr.kind {
            ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => {}
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
                walk(left, budget);
                walk(right, budget);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => walk(operand, budget),
            ExprKind::ArrayAccess { base, index, .. } => {
                walk(base, budget);
                walk(index, budget);
            }
            ExprKind::FieldAccess { base, .. } => walk(base, budget),
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
                for arg in args {
                    walk(arg, budget);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                walk(cond, budget);
                walk(then_expr, budget);
                walk(else_expr, budget);
            }
            ExprKind::GotRef { display_expr, .. } => walk(display_expr, budget),
        }
    }

    let total = limit + 1;
    let mut budget = total;
    walk(expr, &mut budget);
    total - budget
}

#[inline]
fn expr_node_count(expr: &Expr) -> usize {
    expr_node_count_bounded(expr, SUBSTITUTION_VALUE_NODE_CAP)
}

/// Recursive structural equality on Exprs, sufficient for the
/// call-argument replacement guard in
/// [`should_replace_existing_call_args`].
///
/// `Display` cannot serve as a proxy because `Expr`'s formatter
/// omits parentheses around nested BinOps with the same operator —
/// `(a - b) - c` and `a - (b - c)` would print identically. Codex
/// review on PR #34 pass 5 flagged this as defeating the equal-size
/// stale-protection in exactly the case it was meant to protect.
fn exprs_call_arg_structurally_equal(left: &Expr, right: &Expr) -> bool {
    use super::super::expression::ExprKind;
    match (&left.kind, &right.kind) {
        (ExprKind::Var(a), ExprKind::Var(b)) => a == b,
        (ExprKind::IntLit(a), ExprKind::IntLit(b)) => a == b,
        (ExprKind::Unknown(a), ExprKind::Unknown(b)) => a == b,
        (
            ExprKind::BinOp {
                op: op_a,
                left: la,
                right: ra,
            },
            ExprKind::BinOp {
                op: op_b,
                left: lb,
                right: rb,
            },
        ) => {
            op_a == op_b
                && exprs_call_arg_structurally_equal(la, lb)
                && exprs_call_arg_structurally_equal(ra, rb)
        }
        (
            ExprKind::UnaryOp {
                op: op_a,
                operand: a,
            },
            ExprKind::UnaryOp {
                op: op_b,
                operand: b,
            },
        ) => op_a == op_b && exprs_call_arg_structurally_equal(a, b),
        (
            ExprKind::Deref {
                addr: a,
                size: size_a,
            },
            ExprKind::Deref {
                addr: b,
                size: size_b,
            },
        ) => size_a == size_b && exprs_call_arg_structurally_equal(a, b),
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
        ) => {
            ea == eb
                && exprs_call_arg_structurally_equal(ba, bb)
                && exprs_call_arg_structurally_equal(ia, ib)
        }
        (
            ExprKind::FieldAccess {
                base: ba,
                offset: oa,
                field_name: fa,
            },
            ExprKind::FieldAccess {
                base: bb,
                offset: ob,
                field_name: fb,
            },
        ) => oa == ob && fa == fb && exprs_call_arg_structurally_equal(ba, bb),
        (ExprKind::AddressOf(a), ExprKind::AddressOf(b)) => {
            exprs_call_arg_structurally_equal(a, b)
        }
        (
            ExprKind::Cast {
                expr: a,
                to_size: sa,
                signed: za,
            },
            ExprKind::Cast {
                expr: b,
                to_size: sb,
                signed: zb,
            },
        ) => sa == sb && za == zb && exprs_call_arg_structurally_equal(a, b),
        (
            ExprKind::BitField {
                expr: a,
                start: sa,
                width: wa,
            },
            ExprKind::BitField {
                expr: b,
                start: sb,
                width: wb,
            },
        ) => sa == sb && wa == wb && exprs_call_arg_structurally_equal(a, b),
        (
            ExprKind::Assign { lhs: la, rhs: ra },
            ExprKind::Assign { lhs: lb, rhs: rb },
        ) => {
            exprs_call_arg_structurally_equal(la, lb)
                && exprs_call_arg_structurally_equal(ra, rb)
        }
        (
            ExprKind::CompoundAssign {
                op: op_a,
                lhs: la,
                rhs: ra,
            },
            ExprKind::CompoundAssign {
                op: op_b,
                lhs: lb,
                rhs: rb,
            },
        ) => {
            op_a == op_b
                && exprs_call_arg_structurally_equal(la, lb)
                && exprs_call_arg_structurally_equal(ra, rb)
        }
        (
            ExprKind::Call {
                target: ta,
                args: aa,
            },
            ExprKind::Call {
                target: tb,
                args: ab,
            },
        ) => {
            format!("{ta:?}") == format!("{tb:?}")
                && aa.len() == ab.len()
                && aa
                    .iter()
                    .zip(ab.iter())
                    .all(|(a, b)| exprs_call_arg_structurally_equal(a, b))
        }
        (
            ExprKind::Conditional {
                cond: ca,
                then_expr: ta,
                else_expr: ea,
            },
            ExprKind::Conditional {
                cond: cb,
                then_expr: tb,
                else_expr: eb,
            },
        ) => {
            exprs_call_arg_structurally_equal(ca, cb)
                && exprs_call_arg_structurally_equal(ta, tb)
                && exprs_call_arg_structurally_equal(ea, eb)
        }
        (
            ExprKind::GotRef {
                address: aa,
                size: sa,
                is_deref: da,
                ..
            },
            ExprKind::GotRef {
                address: ab,
                size: sb,
                is_deref: db,
                ..
            },
        ) => aa == ab && sa == sb && da == db,
        (ExprKind::Phi(a), ExprKind::Phi(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b.iter())
                    .all(|(x, y)| exprs_call_arg_structurally_equal(x, y))
        }
        _ => false,
    }
}

/// Substitute variable references with their known values and simplify.
///
/// Two phases: a simplify-free recursive substitution ([`substitute_vars_rec`])
/// over the whole tree, then a single result-cap check plus one
/// [`Expr::simplify`] pass. `Expr::simplify` already recurses bottom-up, so
/// simplifying once at the top is equivalent to simplifying at every recursion
/// level — but doing it per level (as this used to) also re-ran the result-cap
/// node count at every level, making substitution O(N²) in expression size.
/// A self-referential `idiv`/`xor` chain builds degenerate left-leaning trees,
/// so an 11-byte fuzz input took 8–17 s and ballooned memory past the RSS
/// limit. Substituting first and simplifying/capping once keeps it O(N).
///
/// The recursion also threads a shared node *budget* so it stops expanding once
/// the output would exceed [`SUBSTITUTION_RESULT_NODE_CAP`], instead of building
/// a giant intermediate only to discard it below — that build-then-discard was
/// the residual cost (and peak RSS) after the per-level simplify was removed.
/// Exhausting the budget backs out to the original input, so the observable
/// result is identical to the post-build result-cap check, minus the wasted
/// allocation.
fn substitute_vars(expr: &Expr, reg_values: &HashMap<String, Expr>) -> Expr {
    // One past the cap, so the budget reaches 0 only when the output strictly
    // exceeds the cap — matching the `> SUBSTITUTION_RESULT_NODE_CAP` check.
    let mut budget = SUBSTITUTION_RESULT_NODE_CAP + 1;
    let result = substitute_vars_rec(expr, reg_values, &mut budget);
    // Defense in depth: if the substitution result is much larger than the
    // input, back out to the input. Several adversarial fuzz inputs put many
    // refs to the same register inside one expression (e.g. a `Conditional`
    // whose condition, then-branch, and else-branch each mention `rax`),
    // where each leaf gets replaced with a near-cap-sized subtree and the
    // result is N × cap nodes. The budget normally trips first; the explicit
    // count still guards paths it under-counts (call arguments).
    if budget == 0
        || expr_node_count_bounded(&result, SUBSTITUTION_RESULT_NODE_CAP)
            > SUBSTITUTION_RESULT_NODE_CAP
    {
        return expr.clone();
    }
    // Simplify after substitution to handle boolean patterns like (x == 1) != 1 → x != 1
    result.simplify()
}

/// Recursive substitution core for [`substitute_vars`]: replace variable
/// references with their known values WITHOUT simplifying or size-capping at
/// each level (the wrapper does both once over the final tree). Keeping the
/// recursion simplify-free is what bounds the cost to O(N) rather than O(N²).
///
/// `budget` tracks how many more output nodes may be produced; each emitted
/// node decrements it and a substituted value consumes its whole node count.
/// When it reaches zero the recursion stops expanding (returning the original
/// subtree) and the caller backs out — this bounds both time and peak memory
/// to O(cap) regardless of how self-referential the input is.
fn substitute_vars_rec(
    expr: &Expr,
    reg_values: &HashMap<String, Expr>,
    budget: &mut usize,
) -> Expr {
    use super::super::expression::ExprKind;

    fn lookup_named_substitution<'a>(
        reg_values: &'a HashMap<String, Expr>,
        name: &str,
    ) -> Option<&'a Expr> {
        reg_values
            .get(name)
            .or_else(|| reg_values.get(&name.to_lowercase()))
    }

    if *budget == 0 {
        return expr.clone();
    }
    // Account for this node; a substituted value charges its extra nodes below.
    *budget -= 1;

    match &expr.kind {
        ExprKind::Var(v) => {
            if let Some(value) = lookup_named_substitution(reg_values, &v.name) {
                let value_nodes = expr_node_count(value);
                if value_nodes > SUBSTITUTION_VALUE_NODE_CAP {
                    expr.clone()
                } else {
                    *budget = budget.saturating_sub(value_nodes.saturating_sub(1));
                    value.clone()
                }
            } else {
                expr.clone()
            }
        }
        ExprKind::Unknown(name) => {
            if let Some(value) = lookup_named_substitution(reg_values, name) {
                let value_nodes = expr_node_count(value);
                if value_nodes > SUBSTITUTION_VALUE_NODE_CAP {
                    expr.clone()
                } else {
                    *budget = budget.saturating_sub(value_nodes.saturating_sub(1));
                    value.clone()
                }
            } else {
                expr.clone()
            }
        }
        ExprKind::BinOp { op, left, right } => Expr::binop(
            *op,
            substitute_vars_rec(left, reg_values, budget),
            substitute_vars_rec(right, reg_values, budget),
        ),
        ExprKind::UnaryOp { op, operand } => {
            Expr::unary(*op, substitute_vars_rec(operand, reg_values, budget))
        }
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_vars_rec(lhs, reg_values, budget),
            substitute_vars_rec(rhs, reg_values, budget),
        ),
        ExprKind::Deref { addr, size } => {
            Expr::deref(substitute_vars_rec(addr, reg_values, budget), *size)
        }
        ExprKind::AddressOf(inner) => {
            Expr::address_of(substitute_vars_rec(inner, reg_values, budget))
        }
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(
            substitute_vars_rec(base, reg_values, budget),
            substitute_vars_rec(index, reg_values, budget),
            *element_size,
        ),
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(
            substitute_vars_rec(base, reg_values, budget),
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
                expr: Box::new(substitute_vars_rec(inner, reg_values, budget)),
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
                expr: Box::new(substitute_vars_rec(inner, reg_values, budget)),
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
                cond: Box::new(substitute_vars_rec(cond, reg_values, budget)),
                then_expr: Box::new(substitute_vars_rec(then_expr, reg_values, budget)),
                else_expr: Box::new(substitute_vars_rec(else_expr, reg_values, budget)),
            },
        },
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op: *op,
                lhs: Box::new(substitute_vars_rec(lhs, reg_values, budget)),
                rhs: Box::new(substitute_vars_rec(rhs, reg_values, budget)),
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(
                args.iter()
                    .map(|arg| substitute_vars_rec(arg, reg_values, budget))
                    .collect(),
            ),
        },
        _ => expr.clone(),
    }
}

/// Upper bound on the size of the *result* of [`substitute_vars`]. Even with
/// the per-value cap, an input expression with N references to the same
/// register can still produce roughly `N × SUBSTITUTION_VALUE_NODE_CAP` nodes.
/// This caps the result regardless. Set generously: real-world post-
/// substitution expressions stay in the low hundreds of nodes.
const SUBSTITUTION_RESULT_NODE_CAP: usize = 1024;

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
    compound_updated_aliases: HashSet<String>,
    saved_temp_values: HashMap<String, Expr>,
    call_target_values: HashMap<String, Expr>,
    stack_slot_values: HashMap<String, Expr>,
}

impl CallArgPropagationState {
    fn clear_after_real_call(&mut self) {
        self.arg_values.clear();
        self.reg_values.clear();
        self.compound_updated_aliases.clear();
        self.saved_temp_values.clear();
        self.call_target_values.clear();
    }

    fn clear_arg_statement_indices(&mut self) {
        for (stmt_idx, _) in self.arg_values.values_mut() {
            *stmt_idx = None;
        }
    }

    /// Drop tracked values for any variable assigned inside `body` before
    /// propagating into a loop. These variables are loop-carried — their value
    /// at loop entry is not valid across iterations — so propagating a pre-loop
    /// value (e.g. `i = 0`) into the body would corrupt the update
    /// (`i = i + 1` folding to `i = 1`). Loop-invariant values survive and can
    /// still propagate into calls inside the loop.
    fn invalidate_loop_carried(&mut self, body: &[StructuredNode]) {
        let mut regs: HashSet<String> = HashSet::new();
        let mut slots: HashSet<String> = HashSet::new();
        collect_loop_body_modifications(body, &mut regs, &mut slots);

        for reg in &regs {
            for alias in get_register_aliases(reg) {
                let alias = alias.to_lowercase();
                self.arg_values.remove(&alias);
                self.reg_values.remove(&alias);
                self.saved_temp_values.remove(&alias);
                self.call_target_values.remove(&alias);
                self.compound_updated_aliases.remove(&alias);
            }
            self.arg_values.remove(reg);
            self.reg_values.remove(reg);
            self.saved_temp_values.remove(reg);
            self.call_target_values.remove(reg);
            self.compound_updated_aliases.remove(reg);
        }
        for slot in &slots {
            self.stack_slot_values.remove(slot);
        }
    }
}

/// Collect the register names and stack-slot keys assigned anywhere within a
/// (loop) body, recursing into nested control flow.
fn collect_loop_body_modifications(
    nodes: &[StructuredNode],
    regs: &mut HashSet<String>,
    slots: &mut HashSet<String>,
) {
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    collect_modified_lvalue(stmt, regs, slots);
                }
            }
            StructuredNode::Expr(e) => collect_modified_lvalue(e, regs, slots),
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                collect_loop_body_modifications(then_body, regs, slots);
                if let Some(else_body) = else_body {
                    collect_loop_body_modifications(else_body, regs, slots);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. } => {
                collect_loop_body_modifications(body, regs, slots)
            }
            StructuredNode::For {
                init, update, body, ..
            } => {
                if let Some(init) = init {
                    collect_modified_lvalue(init, regs, slots);
                }
                if let Some(update) = update {
                    collect_modified_lvalue(update, regs, slots);
                }
                collect_loop_body_modifications(body, regs, slots);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    collect_loop_body_modifications(body, regs, slots);
                }
                if let Some(default) = default {
                    collect_loop_body_modifications(default, regs, slots);
                }
            }
            StructuredNode::Sequence(body) => collect_loop_body_modifications(body, regs, slots),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                collect_loop_body_modifications(try_body, regs, slots);
                for handler in catch_handlers {
                    collect_loop_body_modifications(&handler.body, regs, slots);
                }
            }
            _ => {}
        }
    }
}

fn collect_modified_lvalue(stmt: &Expr, regs: &mut HashSet<String>, slots: &mut HashSet<String>) {
    use super::super::expression::ExprKind;
    let lhs = match &stmt.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => lhs,
        _ => return,
    };
    // A frame slot (Var(Stack)/Deref/ArrayAccess off the frame) is keyed the
    // same way the propagation state tracks it; everything else with a Var lhs
    // is a register.
    if let Some(key) = stack_slot_key(lhs) {
        slots.insert(key);
    } else if let ExprKind::Var(v) = &lhs.kind {
        regs.insert(v.name.to_lowercase());
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
            let mut state = incoming_state;
            state.invalidate_loop_carried(&body);
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                state,
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
            let mut state = incoming_state;
            state.invalidate_loop_carried(&body);
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                state,
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
            let mut state = incoming_state;
            state.invalidate_loop_carried(&body);
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                state,
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
            let mut state = incoming_state;
            state.invalidate_loop_carried(&body);
            let (body, _) = propagate_call_args_node_sequence_with_state(
                body,
                binary_data,
                preferred_family,
                state,
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
    // Registers written earlier in this block — they hold local temporaries, not
    // the incoming argument, so they must not be canonicalized back to `argN`.
    let mut clobbered_regs: HashSet<String> = HashSet::new();

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
            let tracked_rhs = if should_preserve_materialized_compound_temp_rhs(
                lhs,
                rhs,
                &state.compound_updated_aliases,
            ) {
                (**rhs).clone()
            } else {
                substitute_stack_slot_values(
                    substitute_vars(rhs, &state.reg_values),
                    &state.stack_slot_values,
                )
            };

            if let ExprKind::Var(v) = &lhs.kind {
                let written_aliases: HashSet<String> =
                    get_register_aliases(&v.name).into_iter().collect();
                // Snapshot the clobbered set BEFORE we mark the
                // current LHS as written. A read of the LHS in this
                // same statement's RHS (the canonical self-modify
                // `rdi = rdi + 1`) refers to the INCOMING value, so
                // stabilization needs to canonicalize it back to
                // `arg0`. Using the post-insert set would block that
                // canonicalization. Codex review on PR #36 pass 1.
                let prior_clobbered_regs = clobbered_regs.clone();
                // Once written, this register is a local temporary for the rest
                // of the block, not the incoming argument.
                for alias in &written_aliases {
                    clobbered_regs.insert(alias.to_lowercase());
                }
                invalidate_dependent_stabilized_register_values(
                    &mut state.reg_values,
                    &written_aliases,
                );
                invalidate_tracked_compound_updated_aliases(
                    &mut state.compound_updated_aliases,
                    &written_aliases,
                );
                invalidate_dependent_register_values(
                    &mut state.saved_temp_values,
                    &written_aliases,
                );
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
                    let stabilized_temp_rhs = stabilize_saved_arg_registers_excluding(
                        tracked_rhs.clone(),
                        &prior_clobbered_regs,
                    );
                    // Sub-register writes (al, ah, ax, ...) must not propagate
                    // the substituted RHS at all under the canonical-name slot
                    // — `v.name` for `al` is `rax`, so storing here would let
                    // later size=4/8 reads of rax pick up an al-only expression
                    // and cascade-substitute on every pass (exponential growth,
                    // cf. fuzz/artifacts/decompiler/oom-* repros).
                    let propagate_aliases = lifted_var_size_defines_full_alias(&v.name, v.size)
                        && compound_update_defines_full_alias_value(&v.name);
                    if propagate_aliases && !expr_requires_single_evaluation(&stabilized_temp_rhs) {
                        for alias in &written_aliases {
                            state
                                .reg_values
                                .insert(alias.clone(), stabilized_temp_rhs.clone());
                            state
                                .call_target_values
                                .insert(alias.clone(), stabilized_temp_rhs.clone());
                        }
                    }
                    if propagate_aliases && expr_is_saved_temp_arg_source(&stabilized_temp_rhs) {
                        for alias in &written_aliases {
                            state
                                .saved_temp_values
                                .insert(alias.clone(), stabilized_temp_rhs.clone());
                        }
                    }
                    if expr_uses_any_register_alias(&stabilized_temp_rhs, &written_aliases) {
                        state
                            .compound_updated_aliases
                            .extend(written_aliases.iter().cloned());
                    }
                }

                if let Some(tracked_arg_key) = tracked_call_arg_key(v, preferred_family) {
                    let tracks_register_aliases = is_tracked_call_arg_register(&v.name);
                    let preserved_tracked_arg_value = resolve_tracked_arg_snapshot_value(
                        rhs,
                        &tracked_rhs,
                        &state.arg_values,
                        Some(&state.saved_temp_values),
                        &prior_clobbered_regs,
                    );
                    if tracks_register_aliases && !expr_requires_single_evaluation(&tracked_rhs) {
                        let tracked_reg_value = preserved_tracked_arg_value.clone();
                        for alias in &written_aliases {
                            state
                                .reg_values
                                .insert(alias.clone(), tracked_reg_value.clone());
                            state
                                .call_target_values
                                .insert(alias.clone(), tracked_reg_value.clone());
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
                                    .unwrap_or_else(|| preserved_tracked_arg_value.clone())
                            }
                            _ => preserved_tracked_arg_value.clone(),
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
                let stabilized_rhs =
                    stabilize_saved_arg_registers_excluding(tracked_rhs, &clobbered_regs);
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
                            Some(&state.saved_temp_values),
                            &excluded_arg_regs,
                            binary_data,
                            preferred_family,
                        );
                        if should_replace_existing_call_args(
                            args,
                            &recovered_args.0,
                            &recovered_args.1,
                        ) {
                            for idx in recovered_args.1 {
                                to_remove.insert(idx);
                            }
                            rewritten_args = recovered_args.0;
                        } else if args.is_empty() {
                            let fallback_args = recover_call_arguments_from_recent_statements(
                                Some(target),
                                args,
                                &result,
                                &excluded_arg_regs,
                                binary_data,
                                preferred_family,
                            );
                            if should_replace_existing_call_args(
                                args,
                                &fallback_args.0,
                                &fallback_args.1,
                            ) {
                                for idx in fallback_args.1 {
                                    to_remove.insert(idx);
                                }
                                rewritten_args = fallback_args.0;
                            } else {
                                rewritten_args = synthesize_leading_passthrough_args_from_target(
                                    &excluded_arg_regs,
                                );
                            }
                        }
                    }
                    let rewritten_call = rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        rewritten_args,
                        binary_data,
                    );
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
                    let rewritten_call = rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        substitute_call_args(target, args, &state.reg_values),
                        binary_data,
                    );
                    if invalidate_pseudo_call_outputs(
                        target,
                        &mut state.reg_values,
                        &mut state.saved_temp_values,
                        &mut state.arg_values,
                        &mut state.call_target_values,
                        &mut state.stack_slot_values,
                    ) {
                        let written_aliases: HashSet<String> = call_output_alias_groups(target)
                            .into_iter()
                            .flatten()
                            .collect();
                        invalidate_tracked_compound_updated_aliases(
                            &mut state.compound_updated_aliases,
                            &written_aliases,
                        );
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
                invalidate_dependent_stabilized_register_values(
                    &mut state.reg_values,
                    &written_aliases,
                );
                invalidate_tracked_compound_updated_aliases(
                    &mut state.compound_updated_aliases,
                    &written_aliases,
                );
                invalidate_dependent_register_values(
                    &mut state.saved_temp_values,
                    &written_aliases,
                );
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

                if is_temp_register(&v.name)
                    && compound_update_defines_full_alias_value(&v.name)
                    && lifted_var_size_defines_full_alias(&v.name, v.size)
                {
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
                                state
                                    .compound_updated_aliases
                                    .extend(written_aliases.iter().cloned());
                            }
                        }
                    }
                }
                if is_tracked_call_arg_register(&v.name) {
                    for alias in &written_aliases {
                        state.reg_values.remove(alias);
                        state.saved_temp_values.remove(alias);
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
                    result.push(rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        recovered_args,
                        binary_data,
                    ));
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
                    Some(&state.saved_temp_values),
                    &excluded_arg_regs,
                    binary_data,
                    preferred_family,
                );
                if should_replace_existing_call_args(args, &new_args.0, &new_args.1) {
                    for idx in new_args.1 {
                        to_remove.insert(idx);
                    }
                    result.push(rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        new_args.0,
                        binary_data,
                    ));
                    state.clear_after_real_call();
                    track_bare_call_result_aliases(
                        &mut state.reg_values,
                        &mut state.call_target_values,
                        preferred_family,
                    );
                    continue;
                }
                let fallback_args = recover_call_arguments_from_recent_statements(
                    Some(target),
                    args,
                    &result,
                    &excluded_arg_regs,
                    binary_data,
                    preferred_family,
                );
                if should_replace_existing_call_args(args, &fallback_args.0, &fallback_args.1) {
                    for idx in fallback_args.1 {
                        to_remove.insert(idx);
                    }
                    result.push(rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        fallback_args.0,
                        binary_data,
                    ));
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
                    let new_call = rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        new_args.0,
                        binary_data,
                    );
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
                        result.push(rewrite_known_runtime_wrapper_call(
                            substituted_target,
                            passthrough_args,
                            binary_data,
                        ));
                        state.clear_after_real_call();
                        track_bare_call_result_aliases(
                            &mut state.reg_values,
                            &mut state.call_target_values,
                            preferred_family,
                        );
                        continue;
                    }
                }

                result.push(rewrite_known_runtime_wrapper_call(
                    substituted_target,
                    substitute_call_args(target, args, &state.reg_values),
                    binary_data,
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
                    &mut state.saved_temp_values,
                    &mut state.arg_values,
                    &mut state.call_target_values,
                    &mut state.stack_slot_values,
                ) {
                    let written_aliases: HashSet<String> = call_output_alias_groups(target)
                        .into_iter()
                        .flatten()
                        .collect();
                    invalidate_tracked_compound_updated_aliases(
                        &mut state.compound_updated_aliases,
                        &written_aliases,
                    );
                    result.push(rewrite_known_runtime_wrapper_call(
                        substituted_target,
                        substituted_args,
                        binary_data,
                    ));
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

fn invalidate_tracked_compound_updated_aliases(
    compound_updated_aliases: &mut HashSet<String>,
    written_aliases: &HashSet<String>,
) {
    compound_updated_aliases.retain(|alias| !written_aliases.contains(alias));
}

fn should_preserve_materialized_compound_temp_rhs(
    lhs: &Expr,
    rhs: &Expr,
    compound_updated_aliases: &HashSet<String>,
) -> bool {
    use super::super::expression::ExprKind;

    if matches!(lhs.kind, ExprKind::Var(_)) {
        return false;
    }

    let rhs_name = match &rhs.kind {
        ExprKind::Var(var) => var.name.as_str(),
        ExprKind::Unknown(name) => name.as_str(),
        _ => return false,
    };

    get_register_aliases(rhs_name)
        .into_iter()
        .any(|alias| compound_updated_aliases.contains(&alias))
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
    let Some((primary_reg, _)) = primary_call_result_alias_expr(preferred_family) else {
        return;
    };
    let primary_expr = Expr::unknown("ret");

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
    saved_temp_values: &mut HashMap<String, Expr>,
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

    invalidate_dependent_stabilized_register_values(reg_values, &written_aliases);
    invalidate_dependent_register_values(saved_temp_values, &written_aliases);
    invalidate_dependent_arg_values(arg_values, &written_aliases);
    invalidate_written_call_target_values(call_target_values, &written_aliases);
    invalidate_dependent_stack_slot_values(stack_slot_values, &written_aliases);
    if aliases_include_stack_base(&written_aliases) {
        stack_slot_values.clear();
    }

    true
}

fn expand_written_aliases_with_arg_placeholders(
    written_aliases: &HashSet<String>,
) -> HashSet<String> {
    let mut expanded = written_aliases.clone();
    for alias in written_aliases {
        if let Some(index) = get_arg_register_index(alias) {
            expanded.insert(format!("arg{index}"));
        }
        if let Some(index) = get_float_arg_register_index(alias) {
            expanded.insert(format!("farg{index}"));
        }
    }
    expanded
}

fn invalidate_dependent_register_values(
    reg_values: &mut HashMap<String, Expr>,
    written_aliases: &HashSet<String>,
) {
    reg_values.retain(|alias, expr| {
        !written_aliases.contains(alias) && !expr_uses_any_register_alias(expr, written_aliases)
    });
}

fn invalidate_dependent_stabilized_register_values(
    reg_values: &mut HashMap<String, Expr>,
    written_aliases: &HashSet<String>,
) {
    let expanded = expand_written_aliases_with_arg_placeholders(written_aliases);
    reg_values.retain(|alias, expr| {
        !expanded.contains(alias) && !expr_uses_any_register_alias(expr, &expanded)
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
        ExprKind::Var(var) => {
            let expr = Expr::var(var);
            if let Some(key) = stack_slot_key(&expr) {
                if let Some(value) = stack_slot_values.get(&key) {
                    return value.clone();
                }
            }
            expr
        }
        ExprKind::Unknown(name) => {
            let expr = Expr::unknown(name);
            if let Some(key) = stack_slot_key(&expr) {
                if let Some(value) = stack_slot_values.get(&key) {
                    return value.clone();
                }
            }
            expr
        }
        ExprKind::IntLit(_) => expr,
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
        } => {
            let array = Expr::array_access(
                substitute_stack_slot_values(*base, stack_slot_values),
                substitute_stack_slot_values(*index, stack_slot_values),
                element_size,
            );
            if let Some(key) = stack_slot_key(&array) {
                if let Some(value) = stack_slot_values.get(&key) {
                    return value.clone();
                }
            }
            array
        }
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
            is_float_context,
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
                is_float_context,
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
    stabilize_saved_arg_registers_excluding(expr, &HashSet::new())
}

/// Canonicalize incoming argument registers to `argN`/`fargN`, but never rename
/// a register listed in `excluded` — those have been written (clobbered) earlier
/// in the block and so are local temporaries, not the incoming argument. (For
/// example a loop index materialized as `rdx = i * 4` must stay `rdx`, not be
/// rewritten to `arg2`, which would fabricate a parameter and a bogus
/// `arr[arg2]` index.)
fn stabilize_saved_arg_registers_excluding(expr: Expr, excluded: &HashSet<String>) -> Expr {
    use super::super::expression::ExprKind;

    let rec = |e: Expr| stabilize_saved_arg_registers_excluding(e, excluded);
    match expr.kind {
        ExprKind::Var(v) => {
            if excluded.contains(&v.name.to_lowercase()) {
                Expr::var(v)
            } else if let Some(index) = get_arg_register_index(&v.name) {
                Expr::unknown(format!("arg{}", index))
            } else if let Some(index) = get_float_arg_register_index(&v.name) {
                Expr::unknown(format!("farg{}", index))
            } else {
                Expr::var(v)
            }
        }
        ExprKind::Unknown(name) => {
            if excluded.contains(&name.to_lowercase()) {
                Expr::unknown(name)
            } else if let Some(index) = get_arg_register_index(&name) {
                Expr::unknown(format!("arg{}", index))
            } else if let Some(index) = get_float_arg_register_index(&name) {
                Expr::unknown(format!("farg{}", index))
            } else {
                Expr::unknown(name)
            }
        }
        ExprKind::IntLit(_) => expr,
        ExprKind::Deref { addr, size } => Expr::deref(rec(*addr), size),
        ExprKind::BinOp { op, left, right } => Expr::binop(op, rec(*left), rec(*right)),
        ExprKind::UnaryOp { op, operand } => Expr::unary(op, rec(*operand)),
        ExprKind::Assign { lhs, rhs } => Expr::assign(rec(*lhs), rec(*rhs)),
        ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(rec(*lhs)),
                rhs: Box::new(rec(*rhs)),
            },
        },
        ExprKind::AddressOf(inner) => Expr::address_of(rec(*inner)),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr::array_access(rec(*base), rec(*index), element_size),
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => Expr::field_access(rec(*base), field_name, offset),
        ExprKind::Call { target, args } => Expr::call(
            stabilize_saved_arg_call_target(target),
            args.into_iter().map(rec).collect(),
        ),
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => Expr {
            kind: ExprKind::Cast {
                expr: Box::new(rec(*inner)),
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
                expr: Box::new(rec(*inner)),
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
                cond: Box::new(rec(*cond)),
                then_expr: Box::new(rec(*then_expr)),
                else_expr: Box::new(rec(*else_expr)),
            },
        },
        ExprKind::Phi(args) => Expr {
            kind: ExprKind::Phi(args.into_iter().map(rec).collect()),
        },
        ExprKind::GotRef {
            address,
            instruction_address,
            size,
            display_expr,
            is_deref,
            is_float_context,
        } => Expr {
            kind: ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr: Box::new(rec(*display_expr)),
                is_deref,
                is_float_context,
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
    use super::super::expression::{ExprKind, VarKind};

    match &expr.kind {
        ExprKind::Deref { addr, .. } => stack_slot_address_key(addr),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => stack_slot_array_key(base, index, *element_size),
        ExprKind::Var(var) => match var.kind {
            VarKind::Stack(offset) => Some(format!("stack:{:+}", offset)),
            _ => stack_slot_name_key(&var.name),
        },
        ExprKind::Unknown(name) => stack_slot_name_key(name),
        _ => None,
    }
}

fn stack_slot_name_key(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();

    if let Some(hex) = lower
        .strip_prefix("var_")
        .or_else(|| lower.strip_prefix("local_"))
    {
        let offset = i64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()?;
        return Some(format!("stack:{:+}", -offset));
    }
    if let Some(hex) = lower.strip_prefix("arg_") {
        let offset = i64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()?;
        return Some(format!("stack:{:+}", offset));
    }
    if let Some(offset) = lower.strip_prefix("stack_") {
        let offset = offset.parse::<i64>().ok()?;
        return Some(format!("stack:{:+}", offset));
    }

    None
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

fn stack_slot_array_key(base: &Expr, index: &Expr, element_size: usize) -> Option<String> {
    use super::super::expression::ExprKind;

    let ExprKind::Var(base_var) = &base.kind else {
        return None;
    };
    if !is_stack_slot_base_register(&base_var.name) {
        return None;
    }
    let ExprKind::IntLit(slot_index) = &index.kind else {
        return None;
    };
    let actual_offset = slot_index.checked_mul(element_size as i128)?;
    let actual_offset = i64::try_from(actual_offset).ok()?;
    Some(format!(
        "{}:{:+}",
        base_var.name.to_lowercase(),
        actual_offset
    ))
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

fn expr_is_pure_data_load_expression(expr: &Expr) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::GotRef { is_deref, .. } => *is_deref,
        ExprKind::Cast { expr: inner, .. } | ExprKind::BitField { expr: inner, .. } => {
            expr_is_pure_data_load_expression(inner)
        }
        _ => false,
    }
}

fn expr_is_saved_temp_arg_source(expr: &Expr) -> bool {
    expr_is_pure_stack_slot_expression(expr) || expr_is_pure_data_load_expression(expr)
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

fn recover_call_arguments_from_recent_statements(
    target: Option<&super::super::expression::CallTarget>,
    existing_args: &[Expr],
    prior_statements: &[Expr],
    excluded_regs: &HashSet<String>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> (Vec<Expr>, Vec<usize>) {
    let mut recent_arg_values: HashMap<String, (Option<usize>, Expr)> = HashMap::new();

    for (idx, stmt) in prior_statements.iter().enumerate().rev() {
        if statement_contains_real_call(stmt) {
            break;
        }

        let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
            continue;
        };
        let ExprKind::Var(var) = &lhs.kind else {
            continue;
        };
        let Some(arg_key) = tracked_call_arg_key(var, preferred_family) else {
            continue;
        };
        if recent_arg_values.contains_key(&arg_key) {
            continue;
        }

        recent_arg_values.insert(
            arg_key,
            (
                Some(idx),
                substitute_prior_register_assignments((**rhs).clone(), &prior_statements[..idx]),
            ),
        );
    }

    extract_call_arguments_with_indices(
        target,
        existing_args,
        &recent_arg_values,
        None,
        excluded_regs,
        binary_data,
        preferred_family,
    )
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
#[derive(Debug, Clone)]
struct KnownCallSignature {
    fixed_arg_count: usize,
    variadic: bool,
    param_classes: Option<Vec<CallParamClass>>,
    source: KnownCallSignatureSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallParamClass {
    Integer,
    Float,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KnownCallSignatureSource {
    Builtin,
    Recovered,
    Hint,
}

fn normalize_known_call_name(name: &str) -> &str {
    let trimmed = name.trim_start_matches('_');
    trimmed.split('@').next().unwrap_or(trimmed)
}

fn rewrite_known_runtime_wrapper_call(
    target: CallTarget,
    args: Vec<Expr>,
    binary_data: Option<&BinaryDataContext>,
) -> Expr {
    let (target, args) = rewrite_known_glibc_fortify_call(target, args, binary_data);
    rewrite_known_linux_syscall_call(target, args, binary_data)
}

fn rewrite_known_glibc_fortify_call(
    target: CallTarget,
    args: Vec<Expr>,
    binary_data: Option<&BinaryDataContext>,
) -> (CallTarget, Vec<Expr>) {
    let Some(name) = resolved_known_call_name(&target, binary_data) else {
        return (target, args);
    };

    let (rewritten_name, rewritten_args) =
        match rewrite_glibc_fortify_name_and_args(normalize_known_call_name(&name), args) {
            Ok(rewritten) => rewritten,
            Err(args) => return (target, args),
        };

    (
        CallTarget::Named(rewritten_name.to_string()),
        rewritten_args,
    )
}

fn rewrite_glibc_fortify_name_and_args(
    name: &str,
    args: Vec<Expr>,
) -> Result<(&'static str, Vec<Expr>), Vec<Expr>> {
    match name {
        "printf_chk" if args.len() >= 2 => Ok(("printf", args.into_iter().skip(1).collect())),
        "fprintf_chk" if args.len() >= 3 => {
            let mut iter = args.into_iter();
            let stream = iter.next().expect("len checked");
            iter.next();
            let mut rewritten_args = vec![stream];
            rewritten_args.extend(iter);
            Ok(("fprintf", rewritten_args))
        }
        "vprintf_chk" if args.len() >= 2 => Ok(("vprintf", args.into_iter().skip(1).collect())),
        "vfprintf_chk" if args.len() >= 3 => {
            let mut iter = args.into_iter();
            let stream = iter.next().expect("len checked");
            iter.next();
            let mut rewritten_args = vec![stream];
            rewritten_args.extend(iter);
            Ok(("vfprintf", rewritten_args))
        }
        "sprintf_chk" if args.len() >= 4 => {
            let mut iter = args.into_iter();
            let dst = iter.next().expect("len checked");
            iter.next();
            iter.next();
            let mut rewritten_args = vec![dst];
            rewritten_args.extend(iter);
            Ok(("sprintf", rewritten_args))
        }
        "snprintf_chk" if args.len() >= 5 => {
            let mut iter = args.into_iter();
            let dst = iter.next().expect("len checked");
            let len = iter.next().expect("len checked");
            iter.next();
            iter.next();
            let mut rewritten_args = vec![dst, len];
            rewritten_args.extend(iter);
            Ok(("snprintf", rewritten_args))
        }
        "vsprintf_chk" if args.len() >= 4 => {
            let mut iter = args.into_iter();
            let dst = iter.next().expect("len checked");
            iter.next();
            iter.next();
            let mut rewritten_args = vec![dst];
            rewritten_args.extend(iter);
            Ok(("vsprintf", rewritten_args))
        }
        "vsnprintf_chk" if args.len() >= 5 => {
            let mut iter = args.into_iter();
            let dst = iter.next().expect("len checked");
            let len = iter.next().expect("len checked");
            iter.next();
            iter.next();
            let mut rewritten_args = vec![dst, len];
            rewritten_args.extend(iter);
            Ok(("vsnprintf", rewritten_args))
        }
        "memcpy_chk" if args.len() >= 4 => Ok(("memcpy", args.into_iter().take(3).collect())),
        "memmove_chk" if args.len() >= 4 => Ok(("memmove", args.into_iter().take(3).collect())),
        "memset_chk" if args.len() >= 4 => Ok(("memset", args.into_iter().take(3).collect())),
        "strcpy_chk" if args.len() >= 3 => Ok(("strcpy", args.into_iter().take(2).collect())),
        "strncpy_chk" if args.len() >= 4 => Ok(("strncpy", args.into_iter().take(3).collect())),
        "strcat_chk" if args.len() >= 3 => Ok(("strcat", args.into_iter().take(2).collect())),
        "strncat_chk" if args.len() >= 4 => Ok(("strncat", args.into_iter().take(3).collect())),
        "stpcpy_chk" if args.len() >= 3 => Ok(("stpcpy", args.into_iter().take(2).collect())),
        "stpncpy_chk" if args.len() >= 4 => Ok(("stpncpy", args.into_iter().take(3).collect())),
        _ => Err(args),
    }
}

fn rewrite_known_linux_syscall_call(
    target: CallTarget,
    args: Vec<Expr>,
    binary_data: Option<&BinaryDataContext>,
) -> Expr {
    let Some(number) = args.first().and_then(extract_linux_syscall_number) else {
        return Expr::call(target, args);
    };

    let is_linux_syscall = matches!(&target, CallTarget::Named(name) if name == "__linux_syscall")
        || resolved_known_call_name(&target, binary_data)
            .is_some_and(|name| normalize_known_call_name(&name) == "syscall");
    if !is_linux_syscall {
        return Expr::call(target, args);
    }

    let Some(name) = linux_x86_64_syscall_name(number) else {
        return Expr::call(target, args);
    };

    Expr::call(
        CallTarget::Named(name.to_string()),
        args.into_iter().skip(1).collect(),
    )
}

fn extract_linux_syscall_number(expr: &Expr) -> Option<u64> {
    let ExprKind::IntLit(value) = &expr.kind else {
        return None;
    };
    u64::try_from(*value).ok()
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
                param_classes: Some(
                    proto
                        .parameters
                        .iter()
                        .map(|(_, ty)| call_param_class_from_ctype(ty))
                        .collect(),
                ),
                source: KnownCallSignatureSource::Builtin,
            });
        }
        if let Some(signature) = binary_data.and_then(|ctx| {
            ctx.call_signature_by_name(&name)
                .or_else(|| ctx.call_signature_by_name(normalize_known_call_name(&name)))
        }) {
            return Some(KnownCallSignature {
                fixed_arg_count: signature.parameters.len(),
                variadic: signature.is_variadic,
                param_classes: Some(
                    signature
                        .parameters
                        .iter()
                        .map(call_param_class_from_signature_parameter)
                        .collect(),
                ),
                source: KnownCallSignatureSource::Recovered,
            });
        }
        if let Some(hinted_arg_count) = binary_data.and_then(|ctx| {
            ctx.call_signature_hint_by_name(&name)
                .or_else(|| ctx.call_signature_hint_by_name(normalize_known_call_name(&name)))
        }) {
            return Some(KnownCallSignature {
                fixed_arg_count: hinted_arg_count,
                variadic: false,
                param_classes: None,
                source: KnownCallSignatureSource::Hint,
            });
        }
    }

    match target {
        super::super::expression::CallTarget::Direct { target, .. } => {
            if let Some(signature) = binary_data?.call_signature_by_address(*target) {
                return Some(KnownCallSignature {
                    fixed_arg_count: signature.parameters.len(),
                    variadic: signature.is_variadic,
                    param_classes: Some(
                        signature
                            .parameters
                            .iter()
                            .map(call_param_class_from_signature_parameter)
                            .collect(),
                    ),
                    source: KnownCallSignatureSource::Recovered,
                });
            }
            let hinted_arg_count = binary_data?.call_signature_hint_by_address(*target)?;
            Some(KnownCallSignature {
                fixed_arg_count: hinted_arg_count,
                variadic: false,
                param_classes: None,
                source: KnownCallSignatureSource::Hint,
            })
        }
        super::super::expression::CallTarget::Named(_)
        | super::super::expression::CallTarget::Indirect(_)
        | super::super::expression::CallTarget::IndirectGot { .. } => None,
    }
}

fn call_param_class_from_ctype(ty: &CType) -> CallParamClass {
    if ty.is_float() {
        CallParamClass::Float
    } else {
        CallParamClass::Integer
    }
}

fn call_param_class_from_signature_parameter(
    parameter: &super::super::signature::Parameter,
) -> CallParamClass {
    match (&parameter.location, &parameter.param_type) {
        (super::super::signature::ParameterLocation::FloatRegister { .. }, _)
        | (_, super::super::signature::ParamType::Float(_))
        | (_, super::super::signature::ParamType::SimdFloat(_)) => CallParamClass::Float,
        _ => CallParamClass::Integer,
    }
}

fn extract_call_arguments_with_indices(
    target: Option<&super::super::expression::CallTarget>,
    existing_args: &[Expr],
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    excluded_regs: &HashSet<String>,
    binary_data: Option<&BinaryDataContext>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> (Vec<Expr>, Vec<usize>) {
    let signature = target.and_then(|target| known_call_signature(target, binary_data));
    if let Some(signature) = signature.as_ref() {
        if !signature.variadic
            && signature.param_classes.is_some()
            && existing_args.len() <= signature.fixed_arg_count
        {
            if let Some(recovered) = recover_typed_call_arguments(
                signature,
                existing_args,
                arg_values,
                saved_temp_values,
                excluded_regs,
                preferred_family,
            ) {
                return recovered;
            }
        }
    }
    let mut removable_indices = Vec::new();
    let mut explicit_by_index: HashMap<usize, (Option<usize>, String, Expr)> = HashMap::new();

    for (reg_name, (stmt_idx, value)) in arg_values {
        if excluded_regs.contains(&reg_name.to_lowercase()) {
            continue;
        }
        if let Some(arg_idx) = get_arg_register_index(reg_name) {
            if signature
                .as_ref()
                .is_some_and(|sig| !sig.variadic && arg_idx >= sig.fixed_arg_count)
            {
                if let Some(stmt_idx) = stmt_idx {
                    removable_indices.push(*stmt_idx);
                }
                continue;
            }
            let candidate = (*stmt_idx, reg_name.to_lowercase(), value.clone());
            match explicit_by_index.get_mut(&arg_idx) {
                Some(existing) => {
                    if tracked_arg_candidate_priority(candidate.0, &candidate.1)
                        > tracked_arg_candidate_priority(existing.0, &existing.1)
                    {
                        *existing = candidate;
                    }
                }
                None => {
                    explicit_by_index.insert(arg_idx, candidate);
                }
            }
        }
    }

    let family = infer_argument_abi_family(
        arg_values
            .keys()
            .map(String::as_str)
            .chain(excluded_regs.iter().map(String::as_str)),
    )
    .or(preferred_family);
    let Some(max_idx) = explicit_by_index.keys().copied().max() else {
        if let Some(sig) = signature.as_ref() {
            if sig.fixed_arg_count == 0 {
                return (existing_args.to_vec(), removable_indices);
            }
            let start_idx = existing_args.len();
            let end_idx = sig.fixed_arg_count.saturating_sub(1);
            let mut result = existing_args.to_vec();
            for expected_idx in start_idx..=end_idx {
                if family
                    .and_then(|family| pass_through_arg_register_name(family, expected_idx))
                    .is_some_and(|reg_name| excluded_regs.contains(reg_name))
                {
                    continue;
                }
                if let Some(arg_expr) = fallback_pass_through_integer_arg(expected_idx, family) {
                    result.push(arg_expr);
                }
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

    if signature
        .as_ref()
        .is_some_and(|sig| !sig.variadic && sig.fixed_arg_count == 0)
    {
        return (existing_args.to_vec(), removable_indices);
    }

    let max_idx = if let Some(sig) = signature.as_ref() {
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
        if let Some((stmt_idx, _, value)) = explicit_by_index.get(&expected_idx) {
            result.push(value.clone());
            if let Some(stmt_idx) = stmt_idx {
                used_indices.push(*stmt_idx);
            }
            continue;
        }

        if family
            .and_then(|family| pass_through_arg_register_name(family, expected_idx))
            .is_some_and(|reg_name| excluded_regs.contains(reg_name))
        {
            continue;
        }
        let Some(arg_expr) = fallback_pass_through_integer_arg(expected_idx, family) else {
            break;
        };
        result.push(arg_expr);
    }

    (result, used_indices)
}

fn fallback_pass_through_integer_arg(
    index: usize,
    family: Option<ArgumentAbiFamily>,
) -> Option<Expr> {
    if let Some(family) = family {
        return pass_through_arg_register_name(family, index).map(pass_through_arg_expr);
    }
    u8::try_from(index).ok().map(|index| {
        Expr::var(Variable {
            kind: VarKind::Arg(index),
            name: format!("arg{index}"),
            size: 8,
        })
    })
}

fn tracked_arg_candidate_priority(
    stmt_idx: Option<usize>,
    reg_name: &str,
) -> (usize, usize, usize, String) {
    (
        usize::from(stmt_idx.is_some()),
        stmt_idx.unwrap_or(0),
        tracked_arg_register_priority(reg_name),
        reg_name.to_lowercase(),
    )
}

fn should_replace_existing_call_args(
    existing_args: &[Expr],
    recovered_args: &[Expr],
    used_indices: &[usize],
) -> bool {
    if !used_indices.is_empty()
        || (existing_args.is_empty() && !recovered_args.is_empty())
        || recovered_args.len() > existing_args.len()
    {
        // Guard against truncating a previously-recovered complex
        // argument back to a partial one. A later pass that walks
        // `result` may see only the most recent xmm-register
        // assignment (e.g. `xmm0 = x*x` after the `xmm0 = x*x + y*y`
        // statement was consumed by an earlier pass) and would
        // happily replace the good `[x*x + y*y]` with the partial
        // `[x*x]`. Refuse the replacement when EVERY existing arg
        // has structure worth protecting (> 2 nodes — a minimal
        // BinOp with two operands) AND every recovered arg is no
        // LARGER than the corresponding existing arg.
        //
        // Refuse only when SOMETHING is actually at risk:
        //   - Truncation: complex existing has strictly more nodes
        //     than recovered (hypot2 case).
        //   - Equal-size stale: complex existing has the same node
        //     count as recovered BUT structurally different (pass 1
        //     concern — a same-size stale could overwrite a good
        //     recovery).
        //
        // Two-part gate so legitimate pass-through cleanup still
        // runs (pass 2): replacing a synthesized `Var(rdi)` with a
        // tracked concrete value like `0` is a 1→1 node swap that
        // SHOULD happen.
        //
        // Use `any` (not `all`) so a thin pass-through arg coexisting
        // with a complex arg doesn't disable protection for the
        // complex one (pass 3).
        //
        // Equal-size structurally-IDENTICAL existing args don't
        // block the replacement (pass 4) — when typed recovery
        // re-presents the same arg unchanged alongside a pass-
        // through sibling that needs concretization, there's
        // nothing to protect at that position.
        if existing_args.len() == recovered_args.len()
            && !existing_args.is_empty()
            && existing_args
                .iter()
                .zip(recovered_args.iter())
                .any(|(existing, recovered)| {
                    let existing_nodes = expr_node_count(existing);
                    if existing_nodes <= 2 {
                        return false;
                    }
                    let recovered_nodes = expr_node_count(recovered);
                    if existing_nodes > recovered_nodes {
                        return true;
                    }
                    // Same node count: only veto when structurally
                    // different (potential stale-replaces-good).
                    // Use a proper recursive comparison — `Display`
                    // omits parentheses for nested BinOps so
                    // `(a-b)-c` and `a-(b-c)` would compare equal
                    // (codex review on PR #34 pass 5).
                    existing_nodes == recovered_nodes
                        && !exprs_call_arg_structurally_equal(existing, recovered)
                })
        {
            return false;
        }
        return true;
    }
    false
}

fn tracked_arg_register_priority(reg_name: &str) -> usize {
    match reg_name.to_lowercase().as_str() {
        "rdi" | "rsi" | "rdx" | "rcx" | "r8" | "r9" | "xmm0" | "xmm1" | "xmm2" | "xmm3"
        | "xmm4" | "xmm5" | "xmm6" | "xmm7" | "x0" | "x1" | "x2" | "x3" | "x4" | "x5" | "x6"
        | "x7" | "a0" | "a1" | "a2" | "a3" | "a4" | "a5" | "a6" | "a7" => 2,
        "edi" | "esi" | "edx" | "ecx" | "r8d" | "r9d" | "d0" | "d1" | "d2" | "d3" | "d4" | "d5"
        | "d6" | "d7" | "w0" | "w1" | "w2" | "w3" | "w4" | "w5" | "w6" | "w7" => 1,
        _ => 0,
    }
}

fn recover_typed_call_arguments(
    signature: &KnownCallSignature,
    existing_args: &[Expr],
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    excluded_regs: &HashSet<String>,
    preferred_family: Option<ArgumentAbiFamily>,
) -> Option<(Vec<Expr>, Vec<usize>)> {
    let param_classes = signature.param_classes.as_ref()?;
    if existing_args.len() > param_classes.len() {
        return None;
    }

    let family = infer_argument_abi_family(
        arg_values
            .keys()
            .map(String::as_str)
            .chain(excluded_regs.iter().map(String::as_str)),
    )
    .or(preferred_family);
    let mut recovered_args = Vec::with_capacity(param_classes.len());
    let mut used_stmt_indices = Vec::new();
    let mut int_slot = 0usize;
    let mut float_slot = 0usize;
    let saved_temp_values = (signature.source == KnownCallSignatureSource::Recovered)
        .then_some(saved_temp_values)
        .flatten();

    for (param_index, class) in param_classes.iter().enumerate() {
        match class {
            CallParamClass::Integer => {
                if let Some(family) = family {
                    let tracked = lookup_fixed_integer_slot_value(
                        arg_values,
                        saved_temp_values,
                        family,
                        int_slot,
                        excluded_regs,
                    );
                    if let Some(existing) =
                        reuse_existing_positional_integer_arg(existing_args, param_index)
                    {
                        if let Some((stmt_idx, tracked_value)) = tracked {
                            if should_prefer_tracked_fixed_integer_arg(
                                &existing,
                                &tracked_value,
                                family,
                                int_slot,
                            ) {
                                if let Some(stmt_idx) = stmt_idx {
                                    used_stmt_indices.push(stmt_idx);
                                }
                                recovered_args.push(tracked_value);
                            } else {
                                recovered_args.push(existing);
                            }
                        } else {
                            recovered_args.push(existing);
                        }
                    } else if let Some((stmt_idx, value)) = tracked {
                        if let Some(stmt_idx) = stmt_idx {
                            used_stmt_indices.push(stmt_idx);
                        }
                        recovered_args.push(value);
                    } else if signature.source != KnownCallSignatureSource::Recovered {
                        if !recovered_args.is_empty()
                            && !has_remaining_typed_materialized_arg(
                                param_classes,
                                param_index + 1,
                                arg_values,
                                saved_temp_values,
                                existing_args,
                                Some(family),
                                int_slot + 1,
                                float_slot,
                                excluded_regs,
                            )
                        {
                            break;
                        }
                        let reg_name = pass_through_arg_register_name(family, int_slot)?;
                        if excluded_regs.contains(reg_name) {
                            return None;
                        }
                        recovered_args.push(pass_through_arg_expr(reg_name));
                    } else {
                        let reg_name = pass_through_arg_register_name(family, int_slot)?;
                        if excluded_regs.contains(reg_name) {
                            return None;
                        }
                        recovered_args.push(pass_through_arg_expr(reg_name));
                    }
                } else if let Some(value) =
                    reuse_existing_positional_integer_arg(existing_args, param_index)
                {
                    recovered_args.push(value);
                } else {
                    return None;
                }
                int_slot += 1;
            }
            CallParamClass::Float => {
                if let Some(family) = family {
                    let tracked = lookup_fixed_float_slot_value(
                        arg_values,
                        saved_temp_values,
                        family,
                        float_slot,
                        excluded_regs,
                    );
                    if let Some(existing) =
                        reuse_existing_positional_float_arg(existing_args, param_index)
                    {
                        if let Some((stmt_idx, tracked_value)) = tracked {
                            if should_prefer_tracked_fixed_float_arg(
                                &existing,
                                &tracked_value,
                                family,
                                float_slot,
                            ) {
                                if let Some(stmt_idx) = stmt_idx {
                                    used_stmt_indices.push(stmt_idx);
                                }
                                recovered_args.push(tracked_value);
                            } else {
                                recovered_args.push(existing);
                            }
                        } else {
                            recovered_args.push(existing);
                        }
                    } else if let Some((stmt_idx, value)) = tracked {
                        if let Some(stmt_idx) = stmt_idx {
                            used_stmt_indices.push(stmt_idx);
                        }
                        recovered_args.push(value);
                    } else if signature.source != KnownCallSignatureSource::Recovered {
                        if !recovered_args.is_empty()
                            && !has_remaining_typed_materialized_arg(
                                param_classes,
                                param_index + 1,
                                arg_values,
                                saved_temp_values,
                                existing_args,
                                Some(family),
                                int_slot,
                                float_slot + 1,
                                excluded_regs,
                            )
                        {
                            break;
                        }
                        let reg_name = pass_through_float_arg_register_name(family, float_slot)?;
                        if excluded_regs.contains(reg_name) {
                            return None;
                        }
                        recovered_args.push(pass_through_float_arg_expr(reg_name));
                    } else {
                        let reg_name = pass_through_float_arg_register_name(family, float_slot)?;
                        if excluded_regs.contains(reg_name) {
                            return None;
                        }
                        recovered_args.push(pass_through_float_arg_expr(reg_name));
                    }
                } else if let Some(value) =
                    reuse_existing_positional_float_arg(existing_args, param_index)
                {
                    recovered_args.push(value);
                } else {
                    return None;
                }
                float_slot += 1;
            }
        }
    }

    Some((recovered_args, used_stmt_indices))
}

#[allow(clippy::too_many_arguments)]
fn has_remaining_typed_materialized_arg(
    param_classes: &[CallParamClass],
    start_index: usize,
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    existing_args: &[Expr],
    family: Option<ArgumentAbiFamily>,
    int_slot: usize,
    float_slot: usize,
    excluded_regs: &HashSet<String>,
) -> bool {
    let mut int_slot = int_slot;
    let mut float_slot = float_slot;

    for (offset, class) in param_classes[start_index..].iter().enumerate() {
        let param_index = start_index + offset;
        match class {
            CallParamClass::Integer => {
                if let Some(family) = family {
                    if lookup_fixed_integer_slot_value(
                        arg_values,
                        saved_temp_values,
                        family,
                        int_slot,
                        excluded_regs,
                    )
                    .is_some()
                    {
                        return true;
                    }
                }
                if reuse_existing_positional_integer_arg(existing_args, param_index).is_some() {
                    return true;
                }
                int_slot += 1;
            }
            CallParamClass::Float => {
                if let Some(family) = family {
                    if lookup_fixed_float_slot_value(
                        arg_values,
                        saved_temp_values,
                        family,
                        float_slot,
                        excluded_regs,
                    )
                    .is_some()
                    {
                        return true;
                    }
                }
                if reuse_existing_positional_float_arg(existing_args, param_index).is_some() {
                    return true;
                }
                float_slot += 1;
            }
        }
    }

    false
}

fn lookup_fixed_integer_slot_value(
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    family: ArgumentAbiFamily,
    int_slot: usize,
    excluded_regs: &HashSet<String>,
) -> Option<(Option<usize>, Expr)> {
    let reg_name = pass_through_arg_register_name(family, int_slot)?;
    if excluded_regs.contains(reg_name) {
        return None;
    }
    lookup_tracked_register_value(arg_values, reg_name, saved_temp_values)
}

fn lookup_fixed_float_slot_value(
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    family: ArgumentAbiFamily,
    float_slot: usize,
    excluded_regs: &HashSet<String>,
) -> Option<(Option<usize>, Expr)> {
    let reg_name = pass_through_float_arg_register_name(family, float_slot)?;
    if excluded_regs.contains(reg_name) {
        return None;
    }
    lookup_tracked_register_value(arg_values, reg_name, saved_temp_values)
}

fn reuse_existing_positional_integer_arg(
    existing_args: &[Expr],
    param_index: usize,
) -> Option<Expr> {
    let candidate = existing_args.get(param_index)?;
    (!expr_looks_float_like(candidate)).then(|| candidate.clone())
}

fn reuse_existing_positional_float_arg(existing_args: &[Expr], param_index: usize) -> Option<Expr> {
    let candidate = existing_args.get(param_index)?;
    expr_looks_float_like(candidate).then(|| candidate.clone())
}

fn should_prefer_tracked_fixed_integer_arg(
    existing: &Expr,
    tracked: &Expr,
    family: ArgumentAbiFamily,
    int_slot: usize,
) -> bool {
    let _ = tracked;
    let Some(reg_name) = pass_through_arg_register_name(family, int_slot) else {
        return false;
    };
    expr_is_exact_passthrough_register(existing, reg_name)
}

fn should_prefer_tracked_fixed_float_arg(
    existing: &Expr,
    tracked: &Expr,
    family: ArgumentAbiFamily,
    float_slot: usize,
) -> bool {
    let _ = tracked;
    let Some(reg_name) = pass_through_float_arg_register_name(family, float_slot) else {
        return false;
    };
    expr_is_exact_passthrough_register(existing, reg_name)
}

fn expr_is_exact_passthrough_register(expr: &Expr, reg_name: &str) -> bool {
    use super::super::expression::ExprKind;

    match &expr.kind {
        ExprKind::Var(var) => get_register_aliases(&var.name)
            .into_iter()
            .any(|alias| alias == reg_name),
        ExprKind::Unknown(name) => get_register_aliases(name)
            .into_iter()
            .any(|alias| alias == reg_name),
        _ => false,
    }
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
        if lower.starts_with("arg") || lower.starts_with("farg") {
            continue;
        }
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
    let _ = dest_reg_size;
    preferred_family
        .or_else(|| infer_argument_abi_family([dest_reg_name]))
        .map(|_| Expr::unknown("ret"))
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
                    None,
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
                    None,
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
    saved_temp_values: Option<&HashMap<String, Expr>>,
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
    if let Some((stmt_idx, value)) =
        lookup_tracked_register_value(arg_values, reg_name, saved_temp_values)
    {
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
    saved_temp_values: Option<&HashMap<String, Expr>>,
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
    if let Some((stmt_idx, value)) =
        lookup_tracked_register_value(arg_values, reg_name, saved_temp_values)
    {
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
    saved_temp_values: Option<&HashMap<String, Expr>>,
) -> Option<(Option<usize>, Expr)> {
    let resolve = |expr: &Expr| {
        saved_temp_values
            .map(|saved| substitute_vars(expr, saved))
            .unwrap_or_else(|| expr.clone())
    };
    if let Some((stmt_idx, value)) = arg_values.get(&reg_name.to_lowercase()) {
        return Some((*stmt_idx, resolve(value)));
    }
    for alias in get_register_aliases(reg_name) {
        if let Some((stmt_idx, value)) = arg_values.get(&alias) {
            return Some((*stmt_idx, resolve(value)));
        }
    }
    None
}

fn resolve_tracked_arg_snapshot_value(
    original_rhs: &Expr,
    tracked_rhs: &Expr,
    arg_values: &HashMap<String, (Option<usize>, Expr)>,
    saved_temp_values: Option<&HashMap<String, Expr>>,
    clobbered_regs: &HashSet<String>,
) -> Expr {
    use super::super::expression::ExprKind;

    if let ExprKind::Var(src_var) = &original_rhs.kind {
        if is_tracked_call_arg_register(&src_var.name) {
            if let Some((_, value)) =
                lookup_tracked_register_value(arg_values, &src_var.name, saved_temp_values)
            {
                return value;
            }
        }
    }

    // Pass `clobbered_regs` so a scratch xmm read (e.g. saxpy_dot's
    // `xmm0 = xmm0 * xmm2` where xmm2 was just loaded from memory)
    // does NOT get renamed to `farg2`. Without this, the
    // stabilized form propagates through state.reg_values into every
    // later use, and the original `xmm2 = ys[i]` def becomes an
    // orphan because nobody references the original register name
    // anymore.
    stabilize_saved_arg_registers_excluding(tracked_rhs.clone(), clobbered_regs)
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

enum MaterializableConditionCall {
    Direct {
        call_expr: Expr,
        negated: bool,
    },
    Compare {
        call_expr: Expr,
        op: BinOpKind,
        other: Expr,
        call_on_left: bool,
    },
}

fn extract_materializable_condition_call(expr: &Expr) -> Option<MaterializableConditionCall> {
    match &expr.kind {
        ExprKind::Call { target, .. } if is_real_function_call(target) => {
            Some(MaterializableConditionCall::Direct {
                call_expr: expr.clone(),
                negated: false,
            })
        }
        ExprKind::UnaryOp {
            op: super::super::expression::UnaryOpKind::LogicalNot,
            operand,
        } => match &operand.kind {
            ExprKind::Call { target, .. } if is_real_function_call(target) => {
                Some(MaterializableConditionCall::Direct {
                    call_expr: (**operand).clone(),
                    negated: true,
                })
            }
            _ => None,
        },
        ExprKind::BinOp { op, left, right } if op.is_comparison() => {
            match (&left.kind, &right.kind) {
                (ExprKind::Call { target, .. }, _) if is_real_function_call(target) => {
                    Some(MaterializableConditionCall::Compare {
                        call_expr: (**left).clone(),
                        op: *op,
                        other: (**right).clone(),
                        call_on_left: true,
                    })
                }
                (_, ExprKind::Call { target, .. }) if is_real_function_call(target) => {
                    Some(MaterializableConditionCall::Compare {
                        call_expr: (**right).clone(),
                        op: *op,
                        other: (**left).clone(),
                        call_on_left: false,
                    })
                }
                _ => None,
            }
        }
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

    let Some(materialized_call) = extract_materializable_condition_call(&condition) else {
        return StructuredNode::If {
            condition,
            then_body,
            else_body,
        };
    };
    let call_expr = match &materialized_call {
        MaterializableConditionCall::Direct { call_expr, .. }
        | MaterializableConditionCall::Compare { call_expr, .. } => call_expr.clone(),
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
    let condition = match materialized_call {
        MaterializableConditionCall::Direct { negated, .. } => {
            if negated {
                Expr::unary(
                    super::super::expression::UnaryOpKind::LogicalNot,
                    temp_expr.clone(),
                )
                .simplify()
            } else {
                temp_expr.clone()
            }
        }
        MaterializableConditionCall::Compare {
            op,
            other,
            call_on_left,
            ..
        } => {
            if call_on_left {
                Expr::binop(op, temp_expr.clone(), other).simplify()
            } else {
                Expr::binop(op, other, temp_expr.clone()).simplify()
            }
        }
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
                if !statements.is_empty() {
                    merge_previous_block_call_capture(&mut result, &mut statements);
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

fn merge_previous_block_call_capture(result: &mut Vec<StructuredNode>, statements: &mut [Expr]) {
    use super::super::expression::ExprKind;

    let Some(ExprKind::Assign { lhs, rhs }) = statements.first().map(|stmt| &stmt.kind) else {
        return;
    };

    let merge_kind = match &rhs.kind {
        ExprKind::Var(var) if is_return_register(&var.name) => Some(None),
        _ => expr_simple_identifier(rhs)
            .filter(|name| name.starts_with("ret_"))
            .map(|name| Some(name.to_string())),
    };
    let Some(expected_capture_name) = merge_kind else {
        return;
    };

    let Some(StructuredNode::Block {
        id: prev_id,
        statements: prev_stmts,
        address_range: prev_range,
    }) = result.last().cloned()
    else {
        return;
    };
    result.pop();

    let Some(last_stmt) = prev_stmts.last().cloned() else {
        result.push(StructuredNode::Block {
            id: prev_id,
            statements: prev_stmts,
            address_range: prev_range,
        });
        return;
    };

    let call = match (&expected_capture_name, &last_stmt.kind) {
        (None, ExprKind::Call { target, args }) if is_real_function_call(target) => {
            let excluded_arg_regs = collect_target_argument_registers(target);
            let recovered = recover_call_arguments_from_recent_statements(
                Some(target),
                args,
                &prev_stmts[..prev_stmts.len().saturating_sub(1)],
                &excluded_arg_regs,
                None,
                None,
            );
            let args = if should_replace_existing_call_args(args, &recovered.0, &recovered.1) {
                recovered.0
            } else {
                args.clone()
            };
            Some(Expr::call(target.clone(), args))
        }
        (Some(expected_name), ExprKind::Assign { lhs, rhs }) => match &rhs.kind {
            ExprKind::Call { target, args } if is_real_function_call(target) => {
                if let Some(actual_name) = expr_simple_identifier(lhs) {
                    (actual_name == expected_name).then(|| {
                        let excluded_arg_regs = collect_target_argument_registers(target);
                        let recovered = recover_call_arguments_from_recent_statements(
                            Some(target),
                            args,
                            &prev_stmts[..prev_stmts.len().saturating_sub(1)],
                            &excluded_arg_regs,
                            None,
                            None,
                        );
                        let args = if should_replace_existing_call_args(
                            args,
                            &recovered.0,
                            &recovered.1,
                        ) {
                            recovered.0
                        } else {
                            args.clone()
                        };
                        Expr::call(target.clone(), args)
                    })
                } else {
                    None
                }
            }
            _ => None,
        },
        _ => None,
    };
    let Some(call) = call else {
        result.push(StructuredNode::Block {
            id: prev_id,
            statements: prev_stmts,
            address_range: prev_range,
        });
        return;
    };

    let mut prev_stmts = prev_stmts;
    prev_stmts.pop();
    if !prev_stmts.is_empty() {
        result.push(StructuredNode::Block {
            id: prev_id,
            statements: prev_stmts,
            address_range: prev_range,
        });
    }

    statements[0] = Expr::assign((**lhs).clone(), call);
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
    let temp_expr = if let Some(block_index) = find_previous_call_capture_block(result, &aliases) {
        capture_previous_call_result(result, block_index, capture_counter, &primary_reg)
    } else {
        capture_previous_if_result(result, capture_counter, &primary_reg)
    };
    let Some(temp_expr) = temp_expr else {
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
                .first()
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
            statements: {
                let mut statements = statements;
                substitute_return_register_uses_until_clobber(
                    &mut statements,
                    aliases,
                    replacement,
                );
                statements
            },
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
            then_body: substitute_return_value_aliases_in_nodes(then_body, aliases, replacement),
            else_body: else_body
                .map(|body| substitute_return_value_aliases_in_nodes(body, aliases, replacement)),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: substitute_return_register_uses(condition, aliases, replacement),
            body: substitute_return_value_aliases_in_nodes(body, aliases, replacement),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: substitute_return_value_aliases_in_nodes(body, aliases, replacement),
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
            body: substitute_return_value_aliases_in_nodes(body, aliases, replacement),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: substitute_return_value_aliases_in_nodes(body, aliases, replacement),
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
                        substitute_return_value_aliases_in_nodes(body, aliases, replacement),
                    )
                })
                .collect(),
            default: default
                .map(|body| substitute_return_value_aliases_in_nodes(body, aliases, replacement)),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
            substitute_return_value_aliases_in_nodes(nodes, aliases, replacement),
        ),
        StructuredNode::Return(Some(expr)) => StructuredNode::Return(Some(
            substitute_return_register_uses(expr, aliases, replacement),
        )),
        other => other,
    }
}

fn substitute_return_value_aliases_in_nodes(
    nodes: Vec<StructuredNode>,
    aliases: &[String],
    replacement: &Expr,
) -> Vec<StructuredNode> {
    let mut rewritten = Vec::with_capacity(nodes.len());
    let mut propagation_live = true;

    for node in nodes {
        if !propagation_live {
            rewritten.push(node);
            continue;
        }

        let node = substitute_return_value_aliases_in_node(node, aliases, replacement);
        propagation_live = !node_stops_return_value_alias_propagation(&node, aliases);
        rewritten.push(node);
    }

    rewritten
}

fn node_stops_return_value_alias_propagation(node: &StructuredNode, aliases: &[String]) -> bool {
    use super::super::expression::ExprKind;

    match node {
        StructuredNode::Block { statements, .. } => statements.iter().any(|stmt| {
            matches!(
                &stmt.kind,
                ExprKind::Call { target, .. } if is_call_capture_boundary(target)
            ) || matches!(
                &stmt.kind,
                ExprKind::Assign { rhs, .. }
                    if matches!(
                        &rhs.kind,
                        ExprKind::Call { target, .. } if is_call_capture_boundary(target)
                    )
            ) || statement_clobbers_return_register(stmt, aliases)
        }),
        StructuredNode::Expr(expr) => match &expr.kind {
            ExprKind::Call { target, .. } if is_call_capture_boundary(target) => true,
            _ => statement_clobbers_return_register(expr, aliases),
        },
        StructuredNode::Return(Some(expr)) => statement_clobbers_return_register(expr, aliases),
        _ => false,
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

fn capture_previous_if_result(
    nodes: &mut [StructuredNode],
    capture_counter: &mut u32,
    primary_reg: &str,
) -> Option<Expr> {
    use super::super::expression::{VarKind, Variable};

    let StructuredNode::If {
        then_body,
        else_body: Some(else_body),
        ..
    } = nodes.last()?.clone()
    else {
        return None;
    };
    if body_definitely_terminates(&then_body) || body_definitely_terminates(&else_body) {
        return None;
    }

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

    let aliases = return_register_aliases(primary_reg);
    let mut then_body = then_body;
    let mut else_body = else_body;
    if !capture_branch_tail_result(&mut then_body, &temp_expr, &aliases)
        || !capture_branch_tail_result(&mut else_body, &temp_expr, &aliases)
    {
        return None;
    }

    let StructuredNode::If {
        then_body: actual_then,
        else_body: Some(actual_else),
        ..
    } = nodes.last_mut()?
    else {
        return None;
    };
    *actual_then = then_body;
    *actual_else = else_body;

    Some(temp_expr)
}

fn capture_branch_tail_result(
    body: &mut [StructuredNode],
    temp_expr: &Expr,
    return_aliases: &[String],
) -> bool {
    use super::super::expression::ExprKind;

    let Some(last) = body.last_mut() else {
        return false;
    };

    match last {
        StructuredNode::Block { statements, .. } => {
            let Some(stmt) = statements.last_mut() else {
                return false;
            };
            match &stmt.kind {
                ExprKind::Call { target, args } if is_call_capture_boundary(target) => {
                    *stmt =
                        Expr::assign(temp_expr.clone(), Expr::call(target.clone(), args.clone()));
                    true
                }
                ExprKind::Assign { lhs, rhs } => {
                    let Some(lhs_name) = expr_simple_identifier(lhs) else {
                        return false;
                    };
                    let lower = lhs_name.to_lowercase();
                    if !return_aliases.iter().any(|alias| alias == &lower) {
                        return false;
                    }
                    *stmt = Expr::assign(temp_expr.clone(), (**rhs).clone());
                    true
                }
                _ => false,
            }
        }
        StructuredNode::Expr(expr) => match &expr.kind {
            ExprKind::Call { target, args } if is_call_capture_boundary(target) => {
                *expr = Expr::assign(temp_expr.clone(), Expr::call(target.clone(), args.clone()));
                true
            }
            _ => false,
        },
        StructuredNode::Sequence(nodes) => {
            capture_branch_tail_result(nodes.as_mut_slice(), temp_expr, return_aliases)
        }
        _ => false,
    }
}

fn substitute_return_register_uses_until_clobber(
    statements: &mut [Expr],
    aliases: &[String],
    replacement: &Expr,
) {
    for stmt in statements.iter_mut() {
        let original = stmt.clone();
        *stmt = substitute_return_register_uses(original.clone(), aliases, replacement);

        if matches!(
            &original.kind,
            super::super::expression::ExprKind::Call { target, .. }
                if is_call_capture_boundary(target)
        ) {
            break;
        }

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

fn push_unique_return_register_use(out: &mut Vec<String>, name: String) {
    if !out.iter().any(|existing| existing == &name) {
        out.push(name);
    }
}

fn collect_return_register_uses(stmt: &Expr) -> Vec<String> {
    use super::super::expression::ExprKind;

    fn walk(expr: &Expr, out: &mut Vec<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                let name = v.name.to_lowercase();
                if is_return_value_alias(&name) {
                    push_unique_return_register_use(out, name);
                }
            }
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                if is_return_value_alias(&lower) {
                    push_unique_return_register_use(out, lower);
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

    let mut out = Vec::new();
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
                is_float_context,
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
                    is_float_context,
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
                is_float_context,
            } => Expr {
                kind: ExprKind::GotRef {
                    address,
                    instruction_address,
                    size,
                    display_expr: Box::new(sub(*display_expr, aliases, replacement, false)),
                    is_deref,
                    is_float_context,
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
    use crate::decompiler::{
        CallingConvention, FunctionSignature, ParamType, Parameter, ParameterLocation,
        SignatureRecovery, StructuredCfg,
    };
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
    fn test_suppress_asan_scaffolding_drops_shadow_and_magic_statements() {
        let nodes = vec![block(
            0,
            vec![
                Expr::assign(
                    Expr::array_access(local("shadow", 8), Expr::int(0x1fffe000), 4),
                    Expr::int(0xf1f1f1f1u32 as i128),
                ),
                Expr::assign(Expr::deref(local("err", 8), 8), Expr::int(0x41b58ab3)),
                Expr::assign(local("meta", 8), Expr::unknown("\"1 32 64 6 buf:12\"")),
                Expr::assign(local("live", 4), Expr::int(1)),
            ],
        )];

        let suppressed = suppress_asan_scaffolding(nodes);
        let StructuredNode::Block { statements, .. } = &suppressed[0] else {
            panic!("expected surviving block");
        };

        assert_eq!(statements.len(), 1);
        assert_eq!(format!("{}", statements[0]), "live = 1");
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
    fn test_extract_return_value_substitutes_cross_width_x86_aliases_for_idiv() {
        let statements = vec![
            Expr::assign(reg("rax", 8), reg("rdi", 8)),
            Expr::assign(reg("rbx", 8), reg("rsi", 8)),
            Expr::call(CallTarget::Named("cdq".to_string()), vec![]),
            Expr::assign(
                reg("eax", 4),
                Expr::binop(BinOpKind::Div, reg("eax", 4), reg("rbx", 8)),
            ),
        ];

        let (_, return_value) = extract_return_value(statements);

        assert_eq!(
            format!("{}", return_value.expect("return value")),
            "rdi / rsi"
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
    fn test_simplify_statements_keeps_dead_atomic_fetch_sub_capture_side_effect() {
        let nodes = vec![block(
            0,
            vec![Expr::assign(
                reg("eax", 4),
                Expr::call(
                    CallTarget::Named("atomic_fetch_sub".to_string()),
                    vec![reg("rdi", 8), Expr::int(1)],
                ),
            )],
        )];

        let simplified = simplify_statements(nodes);
        let StructuredNode::Block { statements, .. } = &simplified[0] else {
            panic!("expected block");
        };

        assert_eq!(statements.len(), 1);
        assert_eq!(format!("{}", statements[0]), "atomic_fetch_sub(rdi, 1)");
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
    fn test_simplify_statements_drops_dead_tail_after_return() {
        let nodes = vec![
            StructuredNode::Return(Some(Expr::int(-1))),
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("sub_0".to_string()),
                    vec![arg("arg0", 0, 4)],
                )],
            ),
            StructuredNode::Return(Some(Expr::int(-1))),
        ];

        let simplified = simplify_statements(nodes);

        assert!(
            matches!(
                simplified.as_slice(),
                [StructuredNode::Return(Some(Expr {
                    kind: ExprKind::IntLit(value),
                }))] if *value == -1
            ),
            "expected dead tail after return to be pruned, got {simplified:#?}"
        );
    }

    #[test]
    fn test_prune_unreachable_nodes_keeps_labeled_tail() {
        let nodes = vec![
            StructuredNode::Return(None),
            block(0, vec![Expr::unknown("dead_before_label")]),
            StructuredNode::Label(BasicBlockId::new(7)),
            block(1, vec![Expr::unknown("live_after_label")]),
        ];

        let pruned = prune_unreachable_nodes(nodes);

        assert_eq!(
            pruned.len(),
            3,
            "expected only unlabeled dead node to be removed"
        );
        assert!(matches!(pruned[0], StructuredNode::Return(None)));
        assert!(matches!(pruned[1], StructuredNode::Label(id) if id == BasicBlockId::new(7)));
        let StructuredNode::Block { statements, .. } = &pruned[2] else {
            panic!("expected labeled tail block");
        };
        assert_eq!(statements.len(), 1);
        assert_eq!(format!("{}", statements[0]), "live_after_label");
    }

    #[test]
    fn test_prune_unreachable_nodes_drops_tail_after_noreturn_call() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(CallTarget::Named("abort".to_string()), vec![])],
            ),
            block(1, vec![Expr::assign(local("dead", 4), Expr::int(1))]),
        ];

        let pruned = prune_unreachable_nodes(nodes);

        assert_eq!(
            pruned.len(),
            1,
            "expected dead tail after abort() to be pruned"
        );
        let StructuredNode::Block { statements, .. } = &pruned[0] else {
            panic!("expected noreturn block to remain");
        };
        assert_eq!(statements.len(), 1);
        assert_eq!(format!("{}", statements[0]), "abort()");
    }

    #[test]
    fn test_propagate_call_args_does_not_fold_loop_carried_slot() {
        // A loop counter initialized to 0 before the loop must not have that 0
        // propagated into the loop body, which would corrupt `i = i + 1` into
        // `i = 0 + 1`.
        let slot = || Expr::deref(Expr::binop(BinOpKind::Add, reg("rbp", 8), Expr::int(-8)), 8);
        let nodes = vec![
            block(0, vec![Expr::assign(slot(), Expr::int(0))]),
            StructuredNode::While {
                condition: Expr::binop(BinOpKind::Lt, slot(), Expr::int(10)),
                body: vec![block(
                    1,
                    vec![Expr::assign(
                        slot(),
                        Expr::binop(BinOpKind::Add, slot(), Expr::int(1)),
                    )],
                )],
                header: None,
                exit_block: None,
            },
        ];

        let out = propagate_call_args(nodes);
        let StructuredNode::While { body, .. } = &out[1] else {
            panic!("expected while");
        };
        let StructuredNode::Block { statements, .. } = &body[0] else {
            panic!("expected block");
        };
        let ExprKind::Assign { rhs, .. } = &statements[0].kind else {
            panic!("expected assignment");
        };
        // The increment must still read the slot (`*(rbp-8) + 1`), not the
        // pre-loop constant (`0 + 1`).
        assert!(
            rhs.to_string().contains("rbp"),
            "loop-carried slot folded into the loop body: {}",
            rhs
        );
    }

    /// Saxpy-style scratch-register usage: `xmm2 = ys[i];
    /// xmm0 = xmm0 * xmm2`. The xmm2 use is a SCRATCH read of the
    /// value just loaded, not the third float argument. Without
    /// passing `clobbered_regs` through `resolve_tracked_arg_snapshot_value`,
    /// the tracked value for xmm0 had xmm2 renamed to `farg2`, the
    /// rename propagated through `state.reg_values` into every later
    /// use, and the `xmm2 = ys[i]` def became orphaned.
    ///
    /// After the fix, propagate_args_in_block preserves the xmm2
    /// references so the original load survives as a real
    /// statement.
    #[test]
    fn test_propagate_args_preserves_scratch_xmm_assignment() {
        // Mimic the saxpy_dot loop body:
        //   xmm2 = ys[i]
        //   xmm0 = xmm0 * xmm2
        let scratch_load = Expr::assign(
            reg("xmm2", 8),
            Expr::array_access(reg("rsi", 8), reg("rcx", 8), 8),
        );
        let scratch_use = Expr::assign(
            reg("xmm0", 8),
            Expr::binop(BinOpKind::Mul, reg("xmm0", 8), reg("xmm2", 8)),
        );

        let propagated = propagate_args_in_block(vec![scratch_load, scratch_use]);
        let rendered: String = propagated
            .iter()
            .map(|s| format!("{s}"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(
            !rendered.contains("farg2"),
            "scratch xmm2 must NOT be renamed to farg2 (renders:\n{rendered})",
        );
        // The scratch load must survive — it's referenced by the
        // multiplication on the next line.
        assert!(
            rendered.contains("xmm2"),
            "scratch xmm2 def must survive (renders:\n{rendered})",
        );
    }

    /// Codex review on PR #36 pass 1: a self-referential first
    /// assignment `rdi = rdi + 1` reads the INCOMING `rdi` value
    /// (which is the function's arg0). The clobber set must be
    /// snapshotted BEFORE the LHS is added, otherwise the
    /// self-read fails to canonicalize back to `arg0` and a later
    /// call uses the raw register name.
    #[test]
    fn test_propagate_args_canonicalizes_self_read_to_incoming_arg() {
        // rdi = rdi + 1
        // call recurse
        // The call's arg0 should be canonicalized to `arg0 + 1`,
        // NOT left as `rdi + 1`.
        let statements = vec![
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(BinOpKind::Add, reg("rdi", 8), Expr::int(1)),
            ),
            Expr::call(CallTarget::Named("recurse".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing call after propagation");
        };
        assert_eq!(args.len(), 1);
        let arg_str = format!("{}", args[0]);
        assert!(
            arg_str.contains("arg0"),
            "self-read of rdi must canonicalize to arg0, got `{arg_str}`",
        );
    }

    #[test]
    fn test_stabilize_excludes_clobbered_arg_register() {
        // `rdx` (the arg2 register) reused as a temp must not be canonicalized
        // back to `arg2` — that would fabricate a parameter and a bogus index.
        let expr = || {
            Expr::deref(
                Expr::binop(BinOpKind::Add, reg("arg0", 8), reg("rdx", 8)),
                4,
            )
        };

        let mut excluded = HashSet::new();
        excluded.insert("rdx".to_string());
        let kept = stabilize_saved_arg_registers_excluding(expr(), &excluded);
        assert!(
            kept.to_string().contains("rdx") && !kept.to_string().contains("arg2"),
            "clobbered rdx must stay rdx: {kept}"
        );

        // Without exclusion an unwritten arg register is still canonicalized.
        let canon = stabilize_saved_arg_registers_excluding(expr(), &HashSet::new());
        assert!(
            canon.to_string().contains("arg2"),
            "an unclobbered arg register should canonicalize: {canon}"
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
    fn test_propagate_copies_does_not_explode_on_sub_register_self_update() {
        // Regression for the 11-byte fuzz repro
        // `64 00 c0 00 0f 00 c0 a3 08 00 5a` which disassembles to
        //   add al, al
        //   add [rdi], cl
        //   add al, al
        //   or  [rax], al
        //   pop rdx
        // The lifter normalizes `al` to the canonical name `"rax"` while
        // preserving the original 1-byte size. Before the fix, each sub-
        // register self-update was being propagated into every alias of
        // `rax` (incl. the full 8-byte slot), so the next pass would
        // substitute the wider read with the prior expression and the
        // expression doubled on every simplification pass. This produced
        // 600+ Add terms and a 2GB+ allocation churn that ASAN flagged as
        // an OOM. We now refuse to broadcast sub-register expressions into
        // the wider alias.
        let al = || Expr::var(Variable::reg("rax", 1));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let cl = || Expr::var(Variable::reg("rcx", 1));
        let rdi = || Expr::var(Variable::reg("rdi", 8));
        let rdx = || Expr::var(Variable::reg("rdx", 8));

        let statements = vec![
            // add al, al
            Expr::assign(al(), Expr::binop(BinOpKind::Add, al(), al())),
            // add [rdi], cl
            Expr::assign(
                Expr::deref(rdi(), 1),
                Expr::binop(BinOpKind::Add, Expr::deref(rdi(), 1), cl()),
            ),
            // add al, al
            Expr::assign(al(), Expr::binop(BinOpKind::Add, al(), al())),
            // or [rax], al  -> [rax] = [rax] | al
            Expr::assign(
                Expr::deref(rax(), 1),
                Expr::binop(BinOpKind::Or, Expr::deref(rax(), 1), al()),
            ),
            // pop rdx
            Expr::assign(
                rdx(),
                Expr::call(CallTarget::Named("pop".to_string()), vec![rdx()]),
            ),
        ];

        let propagated = propagate_copies(statements);

        // Sanity bound: the rendered output of any statement must stay
        // O(N) in the input size, not exponential. A 4 KiB ceiling on
        // per-statement text catches future regressions long before they
        // can reach the libfuzzer 2 GiB RSS budget.
        for (i, stmt) in propagated.iter().enumerate() {
            let rendered = format!("{}", stmt);
            assert!(
                rendered.len() < 4096,
                "stmt {} ballooned to {} bytes:\n{}",
                i,
                rendered.len(),
                &rendered[..rendered.len().min(512)]
            );
        }
    }

    #[test]
    fn test_propagate_copies_does_not_explode_on_long_sub_register_chain() {
        // Regression for the second OOM repro
        // `2f 00 c0 00 c0 00 c0 00 c0 00 08` (4 consecutive `add al, al`s
        // before the memory-add through rax). The original 11-byte fix
        // only blocked alias broadcast in `record_register_substitution`,
        // but `propagate_copies` and `propagate_args_in_block` also
        // broadcast/insert in their CompoundAssign and sub-register fall-
        // back branches under the *canonical* `var.name` ("rax"). Because
        // the lifter normalizes `al`/`ax`/`eax` to the canonical name and
        // keeps the original byte size on `Variable`, those branches were
        // still polluting `reg_values["rax"]` with the sub-register
        // expression — and subsequent reads of `rax` (size=8) picked it
        // up. With four chained `add al, al`s, the expression doubled
        // four times: 98 KB of rendered output. We now gate every alias
        // insert on `lifted_var_size_defines_full_alias`.
        let al = || Expr::var(Variable::reg("rax", 1));
        let rax = || Expr::var(Variable::reg("rax", 8));
        let cl = || Expr::var(Variable::reg("rcx", 1));

        let mut statements = Vec::new();
        // 4 × `add al, al`
        for _ in 0..4 {
            statements.push(Expr::assign(al(), Expr::binop(BinOpKind::Add, al(), al())));
        }
        // `add [rax], cl` — reads rax as memory base
        statements.push(Expr::assign(
            Expr::deref(rax(), 1),
            Expr::binop(BinOpKind::Add, Expr::deref(rax(), 1), cl()),
        ));

        let propagated = propagate_copies(statements);

        for (i, stmt) in propagated.iter().enumerate() {
            let rendered = format!("{}", stmt);
            assert!(
                rendered.len() < 4096,
                "stmt {} ballooned to {} bytes:\n{}",
                i,
                rendered.len(),
                &rendered[..rendered.len().min(512)]
            );
        }
    }

    #[test]
    fn test_substitution_node_cap_blocks_runaway_expression_growth() {
        // Belt-and-suspenders for the broader class of expression-self-
        // substitution cascades the fuzzer surfaced (top sweep result was
        // 127 MB of pseudo-C from an 11-byte input). Synthesizes a value
        // that exceeds SUBSTITUTION_VALUE_NODE_CAP, stores it in
        // reg_values, and asserts substitute_vars refuses to inline it so
        // downstream passes can't expand it further.
        let mut reg_values: HashMap<String, Expr> = HashMap::new();

        // Build a balanced Add tree until we cross the cap. Each leaf is a
        // distinct unknown ("x") so the tree has SUBSTITUTION_VALUE_NODE_CAP
        // + 1 nodes total.
        fn balanced_add(leaves: usize) -> Expr {
            if leaves <= 1 {
                Expr::unknown("x")
            } else {
                Expr::binop(
                    BinOpKind::Add,
                    balanced_add(leaves / 2),
                    balanced_add(leaves - leaves / 2),
                )
            }
        }
        let huge = balanced_add(SUBSTITUTION_VALUE_NODE_CAP * 2);
        assert!(expr_node_count(&huge) > SUBSTITUTION_VALUE_NODE_CAP);
        reg_values.insert("rax".to_string(), huge);

        // A read of rax must not inline the cached huge expression — the
        // result should still be a bare Var, not the huge BinOp tree.
        let read = Expr::var(Variable::reg("rax", 8));
        let substituted = substitute_vars(&read, &reg_values);
        assert!(
            matches!(substituted.kind, ExprKind::Var(_)),
            "expected bare Var after cap-blocked substitute, got {:?}",
            substituted.kind
        );
        assert!(expr_node_count(&substituted) <= 2);

        // Walking a larger input that contains many rax references must also
        // refuse to expand to N × cap nodes.
        let big_input = Expr::binop(
            BinOpKind::Add,
            Expr::binop(BinOpKind::Add, read.clone(), read.clone()),
            Expr::binop(BinOpKind::Add, read.clone(), read.clone()),
        );
        let big_substituted = substitute_vars(&big_input, &reg_values);
        assert!(
            expr_node_count(&big_substituted) <= SUBSTITUTION_RESULT_NODE_CAP,
            "result must respect SUBSTITUTION_RESULT_NODE_CAP, got {}",
            expr_node_count(&big_substituted)
        );
    }

    #[test]
    fn test_substitute_vars_still_folds_after_single_top_level_simplify() {
        // substitute_vars was split into a simplify-free recursive core plus a
        // single top-level Expr::simplify (the per-level simplify made it
        // O(N²)). Expr::simplify recurses bottom-up, so the folding that used
        // to happen at every level must still happen once at the top: a Mul-by-
        // zero sub-expression produced *beneath* an Add by substitution still
        // has to collapse.  (rax * 0) + rbx  with rax=2, rbx=3  ->  3.
        let mut reg_values: HashMap<String, Expr> = HashMap::new();
        reg_values.insert("rax".to_string(), Expr::int(2));
        reg_values.insert("rbx".to_string(), Expr::int(3));

        let input = Expr::binop(
            BinOpKind::Add,
            Expr::binop(
                BinOpKind::Mul,
                Expr::var(Variable::reg("rax", 8)),
                Expr::int(0),
            ),
            Expr::var(Variable::reg("rbx", 8)),
        );
        let out = substitute_vars(&input, &reg_values);
        assert!(
            matches!(out.kind, ExprKind::IntLit(3)),
            "expected folded IntLit(3) after substitute + simplify, got {:?}",
            out.kind
        );
    }

    #[test]
    fn test_substitute_vars_bounded_on_deep_self_referential_chain() {
        // Regression for the O(N²) substitution cost a fuzz soak surfaced via a
        // self-referential idiv/xor chain (8–17 s and >4 GB RSS from 11 bytes).
        // A deep left-leaning chain that references the same register at every
        // level must terminate and stay within the result cap rather than
        // re-counting + re-simplifying a growing tree at every recursion level.
        let mut reg_values: HashMap<String, Expr> = HashMap::new();
        // A moderately large cached value (under the per-value cap of 256).
        let mut value = Expr::unknown("y");
        for _ in 0..120 {
            value = Expr::binop(BinOpKind::Add, value, Expr::unknown("y"));
        }
        reg_values.insert("rax".to_string(), value);

        let read = Expr::var(Variable::reg("rax", 8));
        let mut input = read.clone();
        for _ in 0..300 {
            input = Expr::binop(BinOpKind::Add, input, read.clone());
        }
        let out = substitute_vars(&input, &reg_values);
        assert!(
            expr_node_count(&out) <= SUBSTITUTION_RESULT_NODE_CAP,
            "deep self-referential substitution must stay within the result cap, got {}",
            expr_node_count(&out)
        );
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

    /// `hypot2(x, y) = sqrt(x*x + y*y)` — the addsd-chain recovery
    /// puts `farg0 * farg0 + farg1 * farg1` as sqrt's existing arg
    /// after the first simplifier pass. A subsequent basic-block
    /// consolidation pass walks the rewritten statement list (which
    /// no longer contains the addsd, because pass 1 consumed it),
    /// recovers a TRUNCATED `farg0 * farg0` from the surviving
    /// mulsd, and previously would replace the good arg with the
    /// bad one because `should_replace_existing_call_args` only
    /// gated on `!used_indices.is_empty()`. The guard added in this
    /// PR rejects the replacement when every recovered arg is
    /// strictly smaller than its corresponding existing arg.
    #[test]
    fn should_replace_existing_call_args_keeps_richer_existing_when_recovered_is_subset() {
        // existing = [farg0 * farg0 + farg1 * farg1]  (the good
        // result from the prior pass).
        let big_arg = Expr::binop(
            BinOpKind::Add,
            Expr::binop(
                BinOpKind::Mul,
                Expr::unknown("farg0"),
                Expr::unknown("farg0"),
            ),
            Expr::binop(
                BinOpKind::Mul,
                Expr::unknown("farg1"),
                Expr::unknown("farg1"),
            ),
        );
        // recovered = [farg0 * farg0]  (the truncation a later pass
        // produces when the addsd statement has already been
        // consumed). used_indices is non-empty (the surviving
        // mulsd statement was reachable).
        let small_arg = Expr::binop(
            BinOpKind::Mul,
            Expr::unknown("farg0"),
            Expr::unknown("farg0"),
        );
        let used_indices = vec![9usize];

        assert!(
            !should_replace_existing_call_args(&[big_arg], &[small_arg], &used_indices),
            "must NOT replace a richer existing arg with a smaller recovered arg",
        );
    }

    /// Codex review on PR #34 pass 1: an equal-size stale recovered
    /// arg must NOT replace an existing rich arg of the same size.
    /// Both binary expressions of identical node count could be one
    /// good (existing) and one stale (recovered) — without a deeper
    /// equivalence check we can't distinguish, so we default to
    /// keeping existing.
    #[test]
    fn should_replace_existing_call_args_keeps_equal_size_existing() {
        // existing = farg0 + farg1  (3 nodes — the prior good pass)
        let good = Expr::binop(
            BinOpKind::Add,
            Expr::unknown("farg0"),
            Expr::unknown("farg1"),
        );
        // recovered = farg0 - farg1  (3 nodes — a same-size stale)
        let stale = Expr::binop(
            BinOpKind::Sub,
            Expr::unknown("farg0"),
            Expr::unknown("farg1"),
        );
        let used_indices = vec![7usize];

        assert!(
            !should_replace_existing_call_args(&[good], &[stale], &used_indices),
            "equal-size existing must NOT be replaced by an equal-size recovered arg",
        );
    }

    /// Codex review on PR #34 pass 2: the equal-size gate must not
    /// block legitimate pass-through replacements. When an earlier
    /// pass synthesized `Var(rdi)` as a placeholder, the later
    /// recovery that maps it to a tracked constant `0` (or a
    /// register-typed local) is a beneficial 1→1 node swap that
    /// must be allowed.
    #[test]
    fn should_replace_existing_call_args_replaces_passthrough_with_concrete() {
        // existing = Var(rdi)  (1 node — passthrough placeholder)
        let placeholder = Expr::unknown("rdi");
        // recovered = IntLit(0)  (1 node — tracked concrete value)
        let concrete = Expr::int(0);
        let used_indices = vec![3usize];

        assert!(
            should_replace_existing_call_args(&[placeholder], &[concrete], &used_indices),
            "pass-through Var(rdi) → IntLit(0) replacement must be allowed",
        );
    }

    /// Companion: a 2-node UnaryOp(Var) wrapper is also passthrough-
    /// ish and should be replaced when a recovery surfaces. The
    /// gate only protects > 2-node existing args.
    #[test]
    fn should_replace_existing_call_args_replaces_thin_unary_with_constant() {
        // -rdi (UnaryOp Neg over Var) is 2 nodes.
        let placeholder = Expr::unary(UnaryOpKind::Neg, Expr::unknown("rdi"));
        let concrete = Expr::int(42);
        let used_indices = vec![3usize];

        assert!(
            should_replace_existing_call_args(&[placeholder], &[concrete], &used_indices),
            "thin UnaryOp(Var) (2 nodes) should not block 1-node concrete replacement",
        );
    }

    /// Codex review on PR #34 pass 3: a thin/passthrough arg in a
    /// multi-arg call must NOT disable protection for a coexisting
    /// complex arg. If ANY position is a complex existing vs
    /// smaller-or-equal recovered, the whole replacement is refused.
    #[test]
    fn should_replace_existing_call_args_keeps_complex_when_thin_sibling_exists() {
        // existing = [farg0*farg0 + farg1*farg1, rsi]
        let complex = Expr::binop(
            BinOpKind::Add,
            Expr::binop(
                BinOpKind::Mul,
                Expr::unknown("farg0"),
                Expr::unknown("farg0"),
            ),
            Expr::binop(
                BinOpKind::Mul,
                Expr::unknown("farg1"),
                Expr::unknown("farg1"),
            ),
        );
        let thin_existing = Expr::unknown("rsi");
        // recovered = [farg0*farg0, 0]
        let truncated = Expr::binop(
            BinOpKind::Mul,
            Expr::unknown("farg0"),
            Expr::unknown("farg0"),
        );
        let thin_recovered = Expr::int(0);
        let used_indices = vec![5usize, 3usize];

        assert!(
            !should_replace_existing_call_args(
                &[complex, thin_existing],
                &[truncated, thin_recovered],
                &used_indices,
            ),
            "thin sibling must NOT enable complex-arg truncation"
        );
    }

    /// Codex review on PR #34 pass 4: when typed recovery
    /// re-presents an UNCHANGED complex arg alongside a thin
    /// pass-through sibling that needs cleanup, the unchanged arg
    /// must NOT veto the sibling cleanup. Structural equality at a
    /// position means there's nothing to protect there.
    #[test]
    fn should_replace_existing_call_args_allows_sibling_cleanup_when_complex_unchanged() {
        let complex = || {
            Expr::binop(
                BinOpKind::Add,
                Expr::binop(
                    BinOpKind::Mul,
                    Expr::unknown("farg0"),
                    Expr::unknown("farg0"),
                ),
                Expr::binop(
                    BinOpKind::Mul,
                    Expr::unknown("farg1"),
                    Expr::unknown("farg1"),
                ),
            )
        };
        // existing = [complex, rsi]  recovered = [SAME complex, 0]
        let used_indices = vec![3usize];
        assert!(
            should_replace_existing_call_args(
                &[complex(), Expr::unknown("rsi")],
                &[complex(), Expr::int(0)],
                &used_indices,
            ),
            "unchanged complex arg must NOT block sibling pass-through cleanup",
        );
    }

    /// Codex review on PR #34 pass 5: `Display` is lossy because
    /// the formatter omits parens for same-operator nested BinOps.
    /// `(a - b) - c` and `a - (b - c)` print identically but are
    /// structurally different and produce different results. The
    /// guard now uses recursive structural equality so this case
    /// is correctly recognized as "different" and the replacement
    /// is refused.
    #[test]
    fn should_replace_existing_call_args_uses_structural_equality_not_display() {
        // (a - b) - c
        let left_assoc = Expr::binop(
            BinOpKind::Sub,
            Expr::binop(BinOpKind::Sub, Expr::unknown("a"), Expr::unknown("b")),
            Expr::unknown("c"),
        );
        // a - (b - c) — same nodes, different structure.
        let right_assoc = Expr::binop(
            BinOpKind::Sub,
            Expr::unknown("a"),
            Expr::binop(BinOpKind::Sub, Expr::unknown("b"), Expr::unknown("c")),
        );
        assert_eq!(
            format!("{left_assoc}"),
            format!("{right_assoc}"),
            "Display is lossy (this is the bug codex flagged)",
        );
        let used_indices = vec![5usize];
        assert!(
            !should_replace_existing_call_args(
                &[left_assoc],
                &[right_assoc],
                &used_indices,
            ),
            "structurally different same-size args must NOT trigger replacement",
        );
    }

    #[test]
    fn should_replace_existing_call_args_replaces_when_recovered_is_richer() {
        // The opposite direction: when the recovery has more
        // information than what's already there, we DO want to
        // replace. (Common case for the first arg-recovery pass.)
        let existing = Expr::unknown("xmm0");
        let recovered = Expr::binop(
            BinOpKind::Mul,
            Expr::unknown("farg0"),
            Expr::unknown("farg0"),
        );
        let used_indices = vec![5usize];

        assert!(
            should_replace_existing_call_args(&[existing], &[recovered], &used_indices),
            "must replace a thin passthrough arg with a recovered expression",
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

        let (args, used_indices) = extract_call_arguments_with_indices(
            None,
            &[],
            &arg_values,
            None,
            &excluded,
            None,
            None,
        );

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
            None,
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
            ["ret"]
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
            ["rsp", "ret"]
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
            ["rsp", "ret"]
        );
    }

    #[test]
    fn test_propagate_call_args_preserves_fd_from_bare_call_after_return_reg_clobber() {
        let statements = vec![
            Expr::call(
                CallTarget::Named("open".to_string()),
                vec![Expr::unknown("path")],
            ),
            Expr::assign(Expr::unknown("marker"), Expr::int(1)),
            Expr::assign(reg("ebp", 4), reg("eax", 4)),
            Expr::assign(reg("edi", 4), reg("ebp", 4)),
            Expr::assign(reg("eax", 4), Expr::int(0)),
            Expr::assign(reg("rsi", 8), Expr::unknown("buf")),
            Expr::assign(reg("edx", 4), Expr::unknown("len")),
            Expr::call(CallTarget::Named("read".to_string()), vec![]),
        ];

        let propagated = propagate_args_in_block(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing read call after propagation, got {rendered:?}");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "read"),
            other => panic!("expected named read target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["ebp", "buf", "len"]
        );
    }

    #[test]
    fn test_propagate_call_args_keeps_explicit_args_on_captured_calls() {
        let statements = vec![
            Expr::assign(
                Expr::unknown("ret_0"),
                Expr::call(
                    CallTarget::Named("_factorial".to_string()),
                    vec![Expr::int(5)],
                ),
            ),
            Expr::assign(Expr::unknown("var_8"), Expr::unknown("ret_0")),
            Expr::assign(
                Expr::unknown("ret_1"),
                Expr::call(
                    CallTarget::Named("_sum_while".to_string()),
                    vec![Expr::int(10)],
                ),
            ),
            Expr::assign(Expr::unknown("local_4"), Expr::unknown("ret_1")),
            Expr::assign(
                Expr::unknown("ret_2"),
                Expr::call(
                    CallTarget::Named("_conditional".to_string()),
                    vec![Expr::int(7)],
                ),
            ),
            Expr::assign(Expr::unknown("var_0"), Expr::unknown("ret_2")),
        ];

        let propagated = propagate_args_in_block(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(rendered[0], "ret_0 = _factorial(5)");
        assert_eq!(rendered[2], "ret_1 = _sum_while(0xa)");
        assert_eq!(rendered[4], "ret_2 = _conditional(7)");
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
    fn test_propagate_call_args_names_direct_syscall_imports_from_modern_numbers() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "syscall@GLIBC_2.2.5");

        let statements = vec![Expr::call(
            CallTarget::Direct {
                target: 0x4010c0,
                call_site: 0x5000,
            },
            vec![
                Expr::int(425),
                Expr::unknown("entries"),
                Expr::unknown("params"),
            ],
        )];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Call { target, args },
        }) = propagated.last()
        else {
            panic!("expected trailing syscall import call");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "io_uring_setup"),
            other => panic!("expected io_uring_setup target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["entries", "params"]
        );
    }

    #[test]
    fn test_rewrite_known_runtime_wrapper_call_normalizes_direct_fprintf_chk_import() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "__fprintf_chk@GLIBC_2.3.4");

        let rewritten = rewrite_known_runtime_wrapper_call(
            CallTarget::Direct {
                target: 0x4010c0,
                call_site: 0x5000,
            },
            vec![
                Expr::unknown("stderr"),
                Expr::int(2),
                Expr::unknown("fmt"),
                Expr::unknown("arg0"),
                Expr::unknown("arg1"),
            ],
            Some(&binary_data),
        );

        let ExprKind::Call { target, args } = &rewritten.kind else {
            panic!("expected call expression");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "fprintf"),
            other => panic!("expected fprintf target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["stderr", "fmt", "arg0", "arg1"]
        );
    }

    #[test]
    fn test_rewrite_known_runtime_wrapper_call_normalizes_snprintf_chk() {
        let rewritten = rewrite_known_runtime_wrapper_call(
            CallTarget::Named("__snprintf_chk".to_string()),
            vec![
                Expr::unknown("dst"),
                Expr::unknown("maxlen"),
                Expr::int(2),
                Expr::int(-1),
                Expr::unknown("fmt"),
                Expr::unknown("value"),
            ],
            None,
        );

        let ExprKind::Call { target, args } = &rewritten.kind else {
            panic!("expected call expression");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "snprintf"),
            other => panic!("expected snprintf target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["dst", "maxlen", "fmt", "value"]
        );
    }

    #[test]
    fn test_rewrite_known_runtime_wrapper_call_normalizes_memcpy_chk() {
        let rewritten = rewrite_known_runtime_wrapper_call(
            CallTarget::Named("__memcpy_chk".to_string()),
            vec![
                Expr::unknown("dst"),
                Expr::unknown("src"),
                Expr::unknown("n"),
                Expr::unknown("dst_len"),
            ],
            None,
        );

        let ExprKind::Call { target, args } = &rewritten.kind else {
            panic!("expected call expression");
        };

        match target {
            CallTarget::Named(name) => assert_eq!(name, "memcpy"),
            other => panic!("expected memcpy target, got {other:?}"),
        }
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["dst", "src", "n"]
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
    fn test_propagate_call_args_recovers_sigaction_after_hidden_rep_stos_clobber() {
        let statements = vec![
            Expr::assign(reg("r8d", 4), reg("edi", 4)),
            Expr::assign(reg("ecx", 4), Expr::int(18)),
            Expr::assign(reg("edx", 4), Expr::int(0)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(8)),
            ),
            Expr::assign(reg("rsi", 8), reg("rsp", 8)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(
                    BinOpKind::Add,
                    reg("rdi", 8),
                    Expr::binop(BinOpKind::Mul, reg("rcx", 8), Expr::int(8)),
                ),
            ),
            Expr::assign(reg("rcx", 8), Expr::int(0)),
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
        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["arg0", "rsp", "0"]
        );
    }

    #[test]
    fn test_recover_recent_call_args_fills_missing_leading_slot_without_abi_family() {
        let mut binary_data = BinaryDataContext::new();
        let mut signature = FunctionSignature::new(CallingConvention::SystemV);
        signature.parameters.push(Parameter::new(
            "arg0",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        signature.parameters.push(Parameter::new(
            "arg1",
            ParamType::SignedInt(32),
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));
        binary_data.add_call_signature_by_name("sum_array", signature);

        let prior_statements = vec![
            Expr::assign(
                reg("rax", 8),
                Expr::binop(BinOpKind::Add, reg("rbp", 8), Expr::int(-80)),
            ),
            Expr::assign(arg("arg1", 1, 4), Expr::int(16)),
            Expr::assign(arg("arg0", 0, 8), reg("rax", 8)),
        ];
        let recovered = recover_call_arguments_from_recent_statements(
            Some(&CallTarget::Named("sum_array".to_string())),
            &[],
            &prior_statements,
            &HashSet::new(),
            Some(&binary_data),
            None,
        );

        assert_eq!(recovered.0.len(), 2);
        assert!(format!("{}", recovered.0[0]).contains("rbp + -"));
        assert!(matches!(recovered.0[1].kind, ExprKind::IntLit(16)));
    }

    #[test]
    fn test_propagate_call_args_recovers_direct_sigaction_after_hidden_rep_stos_clobber() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "sigaction@GLIBC_2.2.5");

        let statements = vec![
            Expr::assign(reg("r8d", 4), reg("edi", 4)),
            Expr::assign(reg("ecx", 4), Expr::int(18)),
            Expr::assign(reg("edx", 4), Expr::int(0)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(8)),
            ),
            Expr::assign(reg("rsi", 8), reg("rsp", 8)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(
                    BinOpKind::Add,
                    reg("rdi", 8),
                    Expr::binop(BinOpKind::Mul, reg("rcx", 8), Expr::int(8)),
                ),
            ),
            Expr::assign(reg("rcx", 8), Expr::int(0)),
            Expr::assign(reg("edi", 4), reg("r8d", 4)),
            Expr::call(
                CallTarget::Direct {
                    target: 0x4010c0,
                    call_site: 0x40140e,
                },
                vec![],
            ),
        ];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing sigaction call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["arg0", "rsp", "0"]
        );
    }

    #[test]
    fn test_propagate_call_args_recovers_normalized_sigaction_after_hidden_rep_stos_clobber() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "sigaction@GLIBC_2.2.5");

        let statements = vec![
            Expr::assign(reg("r8", 4), reg("rdi", 4)),
            Expr::assign(reg("rcx", 4), Expr::int(18)),
            Expr::assign(reg("rdx", 4), Expr::int(0)),
            Expr::assign(reg("rax", 4), Expr::int(0)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(8)),
            ),
            Expr::assign(reg("rsi", 8), reg("rsp", 8)),
            Expr::assign(Expr::deref(reg("rsp", 8), 8), Expr::int(0x401300)),
            Expr::assign(
                reg("rdi", 8),
                Expr::binop(
                    BinOpKind::Add,
                    reg("rdi", 8),
                    Expr::binop(BinOpKind::Mul, reg("rcx", 8), Expr::int(8)),
                ),
            ),
            Expr::assign(reg("rcx", 8), Expr::int(0)),
            Expr::assign(reg("rdi", 4), reg("r8", 4)),
            Expr::call(
                CallTarget::Direct {
                    target: 0x4010c0,
                    call_site: 0x40140e,
                },
                vec![],
            ),
        ];

        let propagated = propagate_args_in_block_with_binary_data(
            statements,
            Some(&binary_data),
            Some(ArgumentAbiFamily::X86_64SysV),
        );
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing sigaction call after propagation");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["arg0", "rsp", "0"]
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
            ["0x5000", "x", "xmm0", "s"]
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
            ["0x5100", "x", "xmm0", "s"]
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
    fn test_propagate_call_args_recovers_saved_x86_float_param_from_stack_slot_reload() {
        let spill_slot = Expr::deref(Expr::binop(BinOpKind::Add, reg("rbp", 8), Expr::int(-8)), 8);
        let statements = vec![
            Expr::assign(spill_slot.clone(), reg("xmm0", 16)),
            Expr::assign(reg("rax", 8), spill_slot),
            Expr::assign(reg("rcx", 8), reg("rax", 8)),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[1]), "rax = farg0");
        assert_eq!(format!("{}", propagated[2]), "rcx = farg0");
    }

    #[test]
    fn test_propagate_call_args_recovers_saved_x86_float_param_from_named_stack_slot() {
        let spill_slot = Expr::var(Variable::stack(-8, 8));
        let statements = vec![
            Expr::assign(spill_slot.clone(), reg("xmm0", 16)),
            Expr::assign(reg("rax", 8), spill_slot),
            Expr::assign(reg("rcx", 8), reg("rax", 8)),
        ];

        let propagated = propagate_args_in_block(statements);
        assert_eq!(format!("{}", propagated[1]), "rax = farg0");
        assert_eq!(format!("{}", propagated[2]), "rcx = farg0");
    }

    #[test]
    fn test_propagate_call_args_recovers_mixed_float_arg_from_recovered_signature() {
        let mut binary_data = BinaryDataContext::new();
        let mut signature = FunctionSignature::new(CallingConvention::SystemV);
        signature.parameters.push(Parameter::new(
            "arg0",
            ParamType::SignedInt(32),
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        signature.parameters.push(Parameter::new(
            "farg0",
            ParamType::Float(64),
            ParameterLocation::FloatRegister {
                name: "xmm0".to_string(),
                index: 0,
            },
        ));
        signature.parameters.push(Parameter::new(
            "arg1",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));
        binary_data.add_call_signature_by_name("mixed", signature);

        let statements = vec![
            Expr::assign(reg("edi", 4), Expr::int(7)),
            Expr::assign(reg("xmm0", 16), Expr::unknown("pi")),
            Expr::assign(reg("rsi", 8), Expr::unknown("label")),
            Expr::call(
                CallTarget::Named("mixed".to_string()),
                vec![Expr::int(7), Expr::unknown("label")],
            ),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing mixed call");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["7", "pi", "label"]
        );
    }

    #[test]
    fn test_propagate_call_args_recovers_loaded_x86_float_arg_for_user_wrapper() {
        let mut binary_data = BinaryDataContext::new();
        let mut signature = FunctionSignature::new(CallingConvention::SystemV);
        signature.parameters.push(Parameter::new(
            "farg0",
            ParamType::Float(64),
            ParameterLocation::FloatRegister {
                name: "xmm0".to_string(),
                index: 0,
            },
        ));
        binary_data.add_call_signature_by_name("hex_float", signature);

        let statements = vec![
            Expr::assign(
                reg("rax", 8),
                Expr::got_ref(0x5000, 0x4000, 8, Expr::int(0x5000)),
            ),
            Expr::assign(reg("xmm0", 16), reg("rax", 8)),
            Expr::call(CallTarget::Named("hex_float".to_string()), vec![]),
        ];

        let propagated =
            propagate_args_in_block_with_binary_data(statements, Some(&binary_data), None);
        let Some(Expr {
            kind: ExprKind::Call { args, .. },
        }) = propagated.last()
        else {
            panic!("expected trailing hex_float call");
        };

        assert_eq!(
            args.iter().map(|arg| format!("{arg}")).collect::<Vec<_>>(),
            ["*(uint64_t*)(&data_5000)"]
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
            ["0x6010", "sum", "value"]
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
    fn test_merge_return_value_captures_recovers_args_from_previous_block_setup() {
        let nodes = vec![
            block(
                0,
                vec![
                    Expr::assign(
                        reg("rax", 8),
                        Expr::binop(BinOpKind::Add, reg("rbp", 8), Expr::int(-80)),
                    ),
                    Expr::assign(reg("esi", 4), Expr::int(16)),
                    Expr::assign(reg("rdi", 8), reg("rax", 8)),
                    Expr::call(CallTarget::Named("sum_array".to_string()), vec![]),
                ],
            ),
            block(1, vec![Expr::assign(local("out", 4), reg("eax", 4))]),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Block {
            statements: second_block,
            ..
        } = &merged[1]
        else {
            panic!("expected captured call block");
        };
        let ExprKind::Assign { rhs, .. } = &second_block[0].kind else {
            panic!("expected merged assignment");
        };
        let ExprKind::Call { args, .. } = &rhs.kind else {
            panic!("expected merged call rhs");
        };

        assert_eq!(args.len(), 2);
        assert!(format!("{}", args[0]).contains("rbp + -"));
        assert!(matches!(args[1].kind, ExprKind::IntLit(16)));
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
    fn test_merge_return_value_captures_stops_outer_alias_rewrite_at_inner_call_boundary() {
        let nodes = vec![
            block(
                0,
                vec![Expr::call(
                    CallTarget::Named("strncmp".to_string()),
                    vec![Expr::unknown("lhs1"), Expr::unknown("rhs1"), Expr::int(7)],
                )],
            ),
            StructuredNode::If {
                condition: Expr::unary(UnaryOpKind::LogicalNot, reg("eax", 4)),
                then_body: vec![
                    block(
                        1,
                        vec![Expr::call(
                            CallTarget::Named("strncmp".to_string()),
                            vec![Expr::unknown("lhs2"), Expr::unknown("rhs2"), Expr::int(3)],
                        )],
                    ),
                    StructuredNode::If {
                        condition: Expr::unary(UnaryOpKind::LogicalNot, reg("eax", 4)),
                        then_body: vec![block(
                            2,
                            vec![Expr::assign(
                                Expr::deref(reg("rax", 8), 8),
                                Expr::unknown("err"),
                            )],
                        )],
                        else_body: None,
                    },
                ],
                else_body: None,
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
            "ret_1 = strncmp(lhs1, rhs1, 7)"
        );

        let StructuredNode::If {
            condition,
            then_body,
            ..
        } = &merged[1]
        else {
            panic!("expected outer if");
        };
        assert_eq!(format!("{condition}"), "!ret_1");

        let StructuredNode::Block {
            statements: inner_call_block,
            ..
        } = &then_body[0]
        else {
            panic!("expected nested call block");
        };
        assert_eq!(
            format!("{}", inner_call_block[0]),
            "ret_0 = strncmp(lhs2, rhs2, 3)"
        );

        let StructuredNode::If {
            condition: inner_cond,
            then_body: inner_then,
            ..
        } = &then_body[1]
        else {
            panic!("expected nested if after inner call");
        };
        assert_eq!(format!("{inner_cond}"), "!ret_0");

        let StructuredNode::Block {
            statements: inner_store,
            ..
        } = &inner_then[0]
        else {
            panic!("expected nested store block");
        };
        assert_eq!(format!("{}", inner_store[0]), "*(uint64_t*)(ret_0) = err");
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
    fn test_merge_return_value_captures_materializes_compared_condition_call_result() {
        let nodes = vec![StructuredNode::If {
            condition: Expr::binop(
                BinOpKind::Lt,
                Expr::call(
                    CallTarget::Named("open".to_string()),
                    vec![Expr::unknown("path"), Expr::int(0)],
                ),
                Expr::int(0),
            ),
            then_body: vec![StructuredNode::Return(Some(Expr::unknown("cold")))],
            else_body: Some(vec![block(
                0,
                vec![Expr::assign(reg("edi", 4), reg("eax", 4))],
            )]),
        }];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::Sequence(seq) = &merged[0] else {
            panic!("expected compared condition call to materialize into a sequence");
        };
        let StructuredNode::Expr(assign) = &seq[0] else {
            panic!("expected leading call-result assignment");
        };
        assert_eq!(format!("{assign}"), "ret_0 = open(path, 0)");

        let StructuredNode::If {
            condition,
            else_body: Some(else_body),
            ..
        } = &seq[1]
        else {
            panic!("expected rewritten if after call-result assignment");
        };
        assert!(
            format!("{condition}").starts_with("ret_0 <"),
            "expected rewritten condition to compare the materialized call result, got {condition}"
        );

        let StructuredNode::Block { statements, .. } = &else_body[0] else {
            panic!("expected else block with rewritten register copy");
        };
        assert_eq!(format!("{}", statements[0]), "edi = ret_0");
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
    fn test_merge_return_value_captures_materializes_joined_if_call_result() {
        let nodes = vec![
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Eq, arg("arg0", 0, 8), Expr::int(0)),
                then_body: vec![block(0, vec![Expr::assign(reg("eax", 4), Expr::int(0))])],
                else_body: Some(vec![block(
                    1,
                    vec![Expr::call(
                        CallTarget::Named("__dynamic_cast".to_string()),
                        vec![
                            arg("arg0", 0, 8),
                            Expr::unknown("typeinfo_animal"),
                            Expr::unknown("typeinfo_dog"),
                            Expr::int(0),
                        ],
                    )],
                )]),
            },
            block(2, vec![Expr::assign(local("local_8", 8), reg("rax", 8))]),
        ];

        let merged = merge_return_value_captures(nodes);
        let StructuredNode::If {
            then_body,
            else_body: Some(else_body),
            ..
        } = &merged[0]
        else {
            panic!("expected leading if node, got {merged:?}");
        };
        let StructuredNode::Block {
            statements: then_stmts,
            ..
        } = &then_body[0]
        else {
            panic!("expected then block");
        };
        let StructuredNode::Block {
            statements: else_stmts,
            ..
        } = &else_body[0]
        else {
            panic!("expected else block");
        };
        let StructuredNode::Block {
            statements: join_stmts,
            ..
        } = &merged[1]
        else {
            panic!("expected join block, got {merged:?}");
        };

        assert_eq!(format!("{}", then_stmts[0]), "ret_0 = 0");
        assert_eq!(
            format!("{}", else_stmts[0]),
            "ret_0 = __dynamic_cast(arg0, typeinfo_animal, typeinfo_dog, 0)"
        );
        assert_eq!(format!("{}", join_stmts[0]), "local_8 = ret_0");
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
    fn test_collect_return_register_uses_preserves_first_seen_order() {
        let stmt = Expr::binop(BinOpKind::Add, reg("eax", 4), reg("rax", 8));

        let uses = collect_return_register_uses(&stmt);

        assert_eq!(uses, vec!["eax".to_string(), "rax".to_string()]);
    }

    #[test]
    fn test_extract_call_arguments_prefers_latest_alias_for_same_slot() {
        let mut arg_values = HashMap::new();
        arg_values.insert("edi".to_string(), (Some(0), Expr::int(1)));
        arg_values.insert("rdi".to_string(), (Some(1), Expr::int(2)));

        let (args, used_indices) = extract_call_arguments_with_indices(
            None,
            &[],
            &arg_values,
            None,
            &HashSet::new(),
            None,
            Some(ArgumentAbiFamily::X86_64SysV),
        );

        assert_eq!(args.len(), 1);
        assert_eq!(format!("{}", args[0]), "2");
        assert_eq!(used_indices, vec![1]);
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
    fn test_propagate_copies_collapses_single_use_call_result_copy() {
        // Two-stage thread-through:
        //   ret_0 = foo();           [stage 1 input]
        //   var_8 = ret_0;
        //   sum   = var_8 + 1;
        // → var_8 = foo();           [stage 1: collapse_single_use_call_result_copies]
        //   sum   = var_8 + 1;
        // → sum   = foo() + 1;       [stage 2: collapse_single_use_named_call_results]
        // The single-use-adjacent fold is the second stage that turns a
        // helper call's return-value spill into an inline expression at
        // the consuming use site (deferral #4, helper-call return-value
        // threading). The named-local spill `var_8` is single-use,
        // adjacent, with no later writes — safe to inline.
        let statements = vec![
            Expr::assign(
                local("ret_0", 4),
                Expr::call(CallTarget::Named("foo".to_string()), vec![]),
            ),
            Expr::assign(local("var_8", 4), local("ret_0", 4)),
            Expr::assign(
                local("sum", 4),
                Expr::binop(BinOpKind::Add, local("var_8", 4), Expr::int(1)),
            ),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(propagated.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0], "sum = foo() + 1", "{rendered:?}");
    }

    #[test]
    fn test_propagate_copies_keeps_call_result_with_multiple_uses() {
        // Two downstream uses of the named-local spill MUST NOT trigger the
        // single-use-adjacent fold — folding would duplicate the call,
        // changing semantics for any side-effecting helper.
        let statements = vec![
            Expr::assign(
                local("ret_0", 4),
                Expr::call(CallTarget::Named("foo".to_string()), vec![]),
            ),
            Expr::assign(local("var_8", 4), local("ret_0", 4)),
            Expr::assign(
                local("a", 4),
                Expr::binop(BinOpKind::Add, local("var_8", 4), Expr::int(1)),
            ),
            Expr::assign(
                local("b", 4),
                Expr::binop(BinOpKind::Mul, local("var_8", 4), Expr::int(2)),
            ),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        // Stage 1 still collapses ret_0 → var_8; stage 2 must decline
        // because var_8 has two later uses (a and b).
        assert_eq!(propagated.len(), 3, "{rendered:?}");
        assert_eq!(rendered[0], "var_8 = foo()", "{rendered:?}");
        assert_eq!(rendered[1], "a = var_8 + 1", "{rendered:?}");
        assert_eq!(rendered[2], "b = var_8 * 2", "{rendered:?}");
    }

    #[test]
    fn test_propagate_copies_keeps_call_result_when_consumer_has_another_call() {
        // Codex review on PR #10 flagged this: argument evaluation order in
        // C/C++ is unspecified, so folding `tmp = foo(); out = bar(baz(),
        // tmp);` into `out = bar(baz(), foo());` would change the *apparent*
        // execution order between two side-effecting calls. The fold must
        // decline when the consumer already contains another call.
        let statements = vec![
            Expr::assign(
                local("tmp", 4),
                Expr::call(CallTarget::Named("foo".to_string()), vec![]),
            ),
            Expr::assign(
                local("out", 4),
                Expr::call(
                    CallTarget::Named("bar".to_string()),
                    vec![
                        Expr::call(CallTarget::Named("baz".to_string()), vec![]),
                        local("tmp", 4),
                    ],
                ),
            ),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(propagated.len(), 2, "{rendered:?}");
        assert_eq!(rendered[0], "tmp = foo()", "{rendered:?}");
        assert!(
            rendered[1].contains("tmp") && rendered[1].contains("baz()"),
            "consumer must keep tmp + baz() spelt out: {rendered:?}"
        );
    }

    #[test]
    fn test_propagate_copies_keeps_call_with_self_referencing_args() {
        // A named local that the call itself reads (`local_8 = f(local_8)`)
        // is a genuine in-place update, not a throw-away temp — the fold
        // must decline so we don't silently rewrite the value.
        let statements = vec![
            Expr::assign(
                local("var_8", 4),
                Expr::call(
                    CallTarget::Named("update".to_string()),
                    vec![local("var_8", 4)],
                ),
            ),
            Expr::assign(
                local("out", 4),
                Expr::binop(BinOpKind::Add, local("var_8", 4), Expr::int(1)),
            ),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(propagated.len(), 2, "{rendered:?}");
        assert_eq!(rendered[0], "var_8 = update(var_8)", "{rendered:?}");
        assert_eq!(rendered[1], "out = var_8 + 1", "{rendered:?}");
    }

    #[test]
    fn test_propagate_copies_folds_single_use_load_temp_into_next_use() {
        // `s += arr[i]` is compiled as `eax = arr[i]; s += eax`. Copy-prop won't
        // substitute the load (it must not be duplicated), but since the temp is
        // read exactly once in the immediately following statement the load can
        // fold into that use. (Index/param recovery polish, feature/float-abi.)
        let statements = vec![
            Expr::assign(
                reg("eax", 4),
                Expr::array_access(local("arr", 8), local("i", 4), 4),
            ),
            Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(local("s", 4)),
                    rhs: Box::new(reg("eax", 4)),
                },
            },
            Expr::assign(
                local("i", 4),
                Expr::binop(BinOpKind::Add, local("i", 4), Expr::int(1)),
            ),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(propagated.len(), 2, "{rendered:?}");
        assert!(
            !rendered.iter().any(|s| s.starts_with("eax =")),
            "the temp load assignment should be gone: {rendered:?}"
        );
        assert_eq!(rendered[0], "s += arr[i]", "{rendered:?}");
    }

    #[test]
    fn test_propagate_copies_keeps_multi_use_load_temp() {
        // A load temp read more than once must NOT fold (that would duplicate
        // the load); the assignment is kept.
        let statements = vec![
            Expr::assign(reg("eax", 4), Expr::deref(local("p", 8), 4)),
            Expr::assign(local("x", 4), reg("eax", 4)),
            Expr::assign(local("y", 4), reg("eax", 4)),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert_eq!(propagated.len(), 3, "{rendered:?}");
        assert!(
            rendered.iter().any(|s| s.starts_with("eax =")),
            "multi-use load temp must be preserved: {rendered:?}"
        );
    }

    #[test]
    fn test_propagate_copies_excludes_clobbered_arg_register_from_spill() {
        // esi is the 2nd integer arg, but here it is overwritten with a local
        // load before being spilled (with an intervening statement so the load
        // is not adjacent-foldable). The spill must keep `esi`, not be
        // canonicalized back to `arg1`.
        let slot = Expr::deref(
            Expr::binop(BinOpKind::Add, reg("rbp", 8), Expr::int(-0x10)),
            4,
        );
        let statements = vec![
            Expr::assign(reg("esi", 4), Expr::deref(reg("rdi", 8), 4)),
            Expr::assign(reg("eax", 4), Expr::int(5)),
            Expr::assign(slot, reg("esi", 4)),
        ];

        let propagated = propagate_copies(statements);
        let rendered: Vec<String> = propagated.iter().map(ToString::to_string).collect();

        assert!(
            rendered.iter().any(|s| s.contains("= esi")),
            "clobbered esi spill must stay esi: {rendered:?}"
        );
        assert!(
            !rendered.iter().any(|s| s.contains("arg1")),
            "clobbered esi must not be canonicalized to arg1: {rendered:?}"
        );
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
    fn test_propagate_copies_preserves_compound_update_temp_for_store_back() {
        let cases = vec![
            vec![
                Expr::assign(local("ret", 4), Expr::deref(reg("rdi", 8), 4)),
                Expr::assign(reg("eax", 4), local("ret", 4)),
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Sub,
                        lhs: Box::new(reg("eax", 4)),
                        rhs: Box::new(Expr::int(1)),
                    },
                },
                Expr::assign(Expr::deref(reg("rdi", 8), 4), reg("eax", 4)),
            ],
            vec![
                Expr::assign(local("ret", 4), Expr::deref(reg("rdi", 8), 4)),
                Expr::assign(reg("eax", 4), local("ret", 4)),
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Sub,
                        lhs: Box::new(reg("eax", 4)),
                        rhs: Box::new(Expr::int(1)),
                    },
                },
                Expr::assign(local("ret", 4), reg("eax", 4)),
                Expr::assign(Expr::deref(reg("rdi", 8), 4), local("ret", 4)),
            ],
        ];

        for statements in cases {
            let propagated = propagate_copies(statements);
            let rendered = propagated
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            assert!(
                !rendered.contains("- 1 - 1"),
                "expected store-back to avoid duplicating the decrement, got: {rendered}"
            );
        }
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

    #[test]
    fn test_elide_stack_clash_probe_scaffolding_removes_static_probe_loop() {
        let nodes = vec![
            block(
                0,
                vec![Expr::assign(
                    reg("r11", 8),
                    Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(-0x4000)),
                )],
            ),
            StructuredNode::DoWhile {
                body: vec![block(
                    9,
                    vec![
                        Expr {
                            kind: ExprKind::CompoundAssign {
                                op: BinOpKind::Sub,
                                lhs: Box::new(reg("rsp", 8)),
                                rhs: Box::new(Expr::int(0x1000)),
                            },
                        },
                        Expr::assign(Expr::deref(reg("rsp", 8), 8), Expr::deref(reg("rsp", 8), 8)),
                    ],
                )],
                condition: Expr::binop(BinOpKind::Ne, reg("rsp", 8), reg("r11", 8)),
                header: Some(BasicBlockId::new(0)),
                exit_block: Some(BasicBlockId::new(1)),
            },
            block(
                1,
                vec![Expr::call(
                    CallTarget::Named("work".to_string()),
                    vec![reg("rsp", 8)],
                )],
            ),
        ];

        let cleaned = elide_stack_clash_probe_scaffolding(nodes);

        assert_eq!(cleaned.len(), 1, "expected probe scaffolding to be removed");
        assert!(matches!(
            &cleaned[0],
            StructuredNode::Block { statements, .. }
                if matches!(
                    statements.as_slice(),
                    [Expr {
                        kind: ExprKind::Call {
                            target: CallTarget::Named(name),
                            ..
                        }
                    }] if name == "work"
                )
        ));
    }

    #[test]
    fn test_elide_profiling_probe_calls_removes_named_probe_statements_and_assignments() {
        let cleaned = elide_profiling_probe_calls(
            vec![block(
                0,
                vec![
                    Expr::call(
                        CallTarget::Named("__cyg_profile_func_enter".to_string()),
                        vec![Expr::unknown("&hot_func"), local("var_8", 8)],
                    ),
                    Expr::assign(
                        local("ret_0", 4),
                        Expr::call(CallTarget::Named("mcount@GLIBC_2.2.5".to_string()), vec![]),
                    ),
                    Expr::call(
                        CallTarget::Named("work".to_string()),
                        vec![arg("arg0", 0, 4)],
                    ),
                ],
            )],
            None,
        );

        assert!(matches!(
            cleaned.as_slice(),
            [StructuredNode::Block { statements, .. }]
                if matches!(
                    statements.as_slice(),
                    [Expr {
                        kind: ExprKind::Call {
                            target: CallTarget::Named(name),
                            ..
                        }
                    }] if name == "work"
                )
        ));
    }

    #[test]
    fn test_elide_profiling_probe_calls_removes_resolved_direct_probe_calls() {
        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "mcount@GLIBC_2.2.5");

        let cleaned = elide_profiling_probe_calls(
            vec![block(
                0,
                vec![
                    Expr::call(
                        CallTarget::Direct {
                            target: 0x4010c0,
                            call_site: 0x5000,
                        },
                        vec![],
                    ),
                    Expr::call(CallTarget::Named("work".to_string()), vec![]),
                ],
            )],
            Some(&binary_data),
        );

        assert!(matches!(
            cleaned.as_slice(),
            [StructuredNode::Block { statements, .. }]
                if matches!(
                    statements.as_slice(),
                    [Expr {
                        kind: ExprKind::Call {
                            target: CallTarget::Named(name),
                            ..
                        }
                    }] if name == "work"
                )
        ));
    }

    #[test]
    fn test_elide_stack_clash_probe_scaffolding_removes_runtime_probe_and_fixes_signature() {
        let touch = Expr::array_access(local("local_8", 8), reg("rdx", 8), 1);
        let cleaned = elide_stack_clash_probe_scaffolding(vec![
            block(
                0,
                vec![
                    Expr::assign(reg("rsi", 8), reg("rdi", 8)),
                    Expr::assign(
                        reg("rcx", 8),
                        Expr::binop(BinOpKind::Sub, reg("rsp", 8), reg("rax", 8)),
                    ),
                ],
            ),
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Ne, reg("rsp", 8), reg("rsp", 8)),
                then_body: vec![StructuredNode::DoWhile {
                    body: vec![block(
                        10,
                        vec![
                            Expr {
                                kind: ExprKind::CompoundAssign {
                                    op: BinOpKind::Sub,
                                    lhs: Box::new(reg("rsp", 8)),
                                    rhs: Box::new(Expr::int(0x1000)),
                                },
                            },
                            Expr::assign(
                                Expr::deref(
                                    Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(0xff8)),
                                    8,
                                ),
                                Expr::deref(
                                    Expr::binop(BinOpKind::Add, reg("rsp", 8), Expr::int(0xff8)),
                                    8,
                                ),
                            ),
                        ],
                    )],
                    condition: Expr::binop(BinOpKind::Ne, reg("rsp", 8), reg("rcx", 8)),
                    header: Some(BasicBlockId::new(1)),
                    exit_block: Some(BasicBlockId::new(2)),
                }],
                else_body: None,
            },
            block(
                2,
                vec![Expr {
                    kind: ExprKind::CompoundAssign {
                        op: BinOpKind::Sub,
                        lhs: Box::new(reg("rsp", 8)),
                        rhs: Box::new(reg("rdx", 8)),
                    },
                }],
            ),
            StructuredNode::If {
                condition: Expr::binop(BinOpKind::Ne, reg("rdx", 8), Expr::int(0)),
                then_body: vec![StructuredNode::Expr(Expr::assign(touch.clone(), touch))],
                else_body: None,
            },
            block(
                3,
                vec![
                    Expr::call(
                        CallTarget::Named("__snprintf_chk".to_string()),
                        vec![
                            reg("rsp", 8),
                            reg("rsi", 8),
                            Expr::int(2),
                            reg("rsi", 8),
                            Expr::unknown("fmt"),
                            reg("rdi", 8),
                        ],
                    ),
                    Expr::call(CallTarget::Named("strlen".to_string()), vec![reg("rsp", 8)]),
                ],
            ),
            StructuredNode::Return(None),
        ]);

        assert_eq!(
            cleaned
                .iter()
                .filter(|node| matches!(node, StructuredNode::If { .. }))
                .count(),
            0,
            "expected runtime stack-clash probe conditionals to be removed: {cleaned:#?}"
        );

        let cfg = StructuredCfg {
            body: cleaned,
            cfg_entry: BasicBlockId::new(0),
        };
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let signature = recovery.analyze(&cfg);

        assert_eq!(
            signature.parameters.len(),
            1,
            "expected probe scaffolding to stop inventing extra parameters: {signature:?}"
        );
    }

    fn cxa_throw_named(buf: &str, type_arg: &str) -> Expr {
        Expr::call(
            CallTarget::Named("__cxa_throw@CXXABI_1.3@plt".to_string()),
            vec![local(buf, 8), Expr::unknown(type_arg), Expr::int(0)],
        )
    }

    #[test]
    fn recover_cxa_throw_collapses_scalar_throw_triple() {
        // gcc/clang lower `throw 42` to a three-statement triple. The
        // recogniser must collapse it to a single `throw 42`
        // pseudo-statement; downstream control-flow tracking already
        // treats `__cxa_throw` as noreturn so no synthetic fallback
        // return is appended.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(4)],
                    ),
                ),
                Expr::assign(Expr::deref(local("ret_0", 8), 4), Expr::int(42)),
                cxa_throw_named("ret_0", "&typeinfo for int"),
            ],
        )];

        // No symbol-table needed — the calls here are already Named.
        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        assert!(
            matches!(
                &statements[0].kind,
                ExprKind::Unknown(text)
                    if text == "throw 42" || text == "throw 0x2a"
            ),
            "expected single `throw 42` pseudo-stmt, got {:?}",
            statements[0].kind
        );
    }

    #[test]
    fn recover_cxa_throw_collapses_ctor_form() {
        // `throw std::runtime_error("boom")` emits the ctor form: a
        // ctor call replaces the value store between
        // `__cxa_allocate_exception` and `__cxa_throw`. The recogniser
        // canonicalises the ctor symbol (strips disambiguator labels +
        // collapses the doubled `Class::Class` segment) and renders
        // `throw Class(args)`.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(16)],
                    ),
                ),
                Expr::call(
                    CallTarget::Named(
                        "std::runtime_error::runtime_error(char const*) [complete]".to_string(),
                    ),
                    vec![local("ret_0", 8), Expr::unknown("\"boom\"")],
                ),
                cxa_throw_named("ret_0", "&typeinfo for std::runtime_error"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        let text = match &statements[0].kind {
            ExprKind::Unknown(t) => t.as_str(),
            other => panic!("expected Unknown, got {:?}", other),
        };
        assert!(
            text.starts_with("throw std::runtime_error("),
            "expected `throw std::runtime_error(...)`, got {text:?}"
        );
        assert!(
            text.contains("\"boom\""),
            "expected the boom argument preserved, got {text:?}"
        );
    }

    #[test]
    fn recover_cxa_throw_collapses_captured_ctor_via_direct_call() {
        // At -O0 the constructor's ABI return (the object pointer) is captured
        // into an otherwise-unused temporary: `ret_1 = Class::Class(buf, args)`.
        // The ctor is reached by a `Direct` relocation resolving to the mangled
        // Itanium symbol, so the recogniser must unwrap the assignment AND
        // demangle the ctor name — the real-binary shape for `throw
        // std::runtime_error("boom")`.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(16)],
                    ),
                ),
                // Captured ctor call via a Direct relocation.
                Expr::assign(
                    local("ret_1", 8),
                    Expr::call(
                        CallTarget::Direct {
                            target: 0x1000,
                            call_site: 0x2000,
                        },
                        vec![local("ret_0", 8), Expr::unknown("\"boom\"")],
                    ),
                ),
                cxa_throw_named("ret_0", "&typeinfo for std::runtime_error"),
            ],
        )];

        // Resolve the ctor's Direct target to its mangled Itanium symbol.
        let resolve = |addr: u64, _: u64| -> Option<String> {
            (addr == 0x1000).then(|| "_ZNSt13runtime_errorC1EPKc".to_string())
        };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        let text = match &statements[0].kind {
            ExprKind::Unknown(t) => t.as_str(),
            other => panic!("expected Unknown, got {:?}", other),
        };
        assert!(
            text.starts_with("throw std::runtime_error("),
            "expected demangled `throw std::runtime_error(...)`, got {text:?}"
        );
        assert!(
            text.contains("\"boom\""),
            "expected the boom argument preserved, got {text:?}"
        );
    }

    #[test]
    fn recover_cxa_throw_preserves_scalar_store_whose_value_is_a_call() {
        // A scalar store whose value is a call taking the buffer as its first
        // argument — `*buf = f(buf, x)` — is NOT the captured-ctor shape (its
        // LHS is a store, not a temporary), so the whole call is preserved as
        // the thrown value; argument 0 must not be dropped.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(8)],
                    ),
                ),
                Expr::assign(
                    Expr::deref(local("ret_0", 8), 8),
                    Expr::call(
                        CallTarget::Named("compute_exception".to_string()),
                        vec![local("ret_0", 8), Expr::int(5)],
                    ),
                ),
                cxa_throw_named("ret_0", "&typeinfo for int"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        let text = match &statements[0].kind {
            ExprKind::Unknown(t) => t.as_str(),
            other => panic!("expected Unknown, got {:?}", other),
        };
        assert!(
            text.starts_with("throw compute_exception(") && text.contains("ret_0"),
            "expected the store's call preserved with argument 0, got {text:?}"
        );
    }

    #[test]
    fn looks_like_constructor_distinguishes_ctors_from_helpers() {
        assert!(looks_like_constructor("std::runtime_error::runtime_error"));
        assert!(looks_like_constructor("ns::Widget::Widget"));
        assert!(looks_like_constructor("Foo<int>::Foo")); // template class ctor
        // Template arguments containing `::` must not confuse the segment split.
        assert!(looks_like_constructor(
            "std::vector<int, std::allocator<int> >::vector"
        ));
        assert!(looks_like_constructor("Foo<ns::Bar>::Foo"));
        // GNU ABI tag on the class segment (libstdc++ cxx11 types).
        assert!(looks_like_constructor(
            "std::ios_base::failure[abi:cxx11]::failure"
        ));
        assert!(!looks_like_constructor("memcpy"));
        assert!(!looks_like_constructor("ns::make_error"));
        assert!(!looks_like_constructor("Foo::~Foo")); // destructor, not ctor

        // The collapse must likewise ignore `::` inside template arguments.
        assert_eq!(
            collapse_ctor_pretty_name("std::vector<int, std::allocator<int> >::vector"),
            "std::vector<int, std::allocator<int> >"
        );
        assert_eq!(
            collapse_ctor_pretty_name("std::runtime_error::runtime_error"),
            "std::runtime_error"
        );
    }

    #[test]
    fn recover_cxa_throw_declines_captured_non_ctor_helper() {
        // `ret_1 = memcpy(buf, src, 8)` between the alloc and the throw returns
        // its first argument and is captured into a temp, but it is NOT a
        // constructor — the recogniser must leave the raw sequence intact rather
        // than emit `throw memcpy(src, 8)`.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(8)],
                    ),
                ),
                Expr::assign(
                    local("ret_1", 8),
                    Expr::call(
                        CallTarget::Named("memcpy".to_string()),
                        vec![local("ret_0", 8), local("src", 8), Expr::int(8)],
                    ),
                ),
                cxa_throw_named("ret_0", "&typeinfo for int"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        // Nothing collapsed: alloc + memcpy + throw all remain, and no `throw`
        // marker was synthesised.
        assert_eq!(statements.len(), 3, "{statements:#?}");
        assert!(
            !statements
                .iter()
                .any(|s| matches!(&s.kind, ExprKind::Unknown(t) if t.starts_with("throw"))),
            "must not synthesise a throw for a non-ctor helper: {statements:#?}"
        );
    }

    /// `throw Pod{a, b, c}` for a plain-old-data type lowers to:
    /// `alloc; *buf = a; *(buf + 4) = b; *(buf + 8) = c; __cxa_throw(...);`
    /// — a `K`-store run between the alloc and the throw, where `K` is
    /// the number of POD fields. Collapse all `K + 2` statements into a
    /// single `throw { a, b, c }` pseudo-statement in store order.
    #[test]
    fn recover_cxa_throw_collapses_multi_store_pod_throw() {
        let buf = || local("ret_0", 8);
        let buf_plus = |off: i128| -> Expr {
            Expr::deref(Expr::binop(BinOpKind::Add, buf(), Expr::int(off)), 4)
        };
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    buf(),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(12)],
                    ),
                ),
                Expr::assign(Expr::deref(buf(), 4), Expr::int(1)),
                Expr::assign(buf_plus(4), Expr::int(2)),
                Expr::assign(buf_plus(8), Expr::int(3)),
                cxa_throw_named("ret_0", "&typeinfo for Pod"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        let text = match &statements[0].kind {
            ExprKind::Unknown(t) => t.as_str(),
            other => panic!("expected Unknown, got {:?}", other),
        };
        assert!(
            text.starts_with("throw {"),
            "expected brace-literal multi-store throw, got {text:?}"
        );
        // All three field values preserved in store order.
        for v in ["1", "2", "3"] {
            assert!(
                text.contains(v),
                "expected field value {v} preserved in {text:?}"
            );
        }
    }

    /// Codex review on this PR flagged that the multi-store collapse
    /// silently rendered out-of-order field stores in statement order
    /// while deleting the address evidence (which is what tells the
    /// analyst the true layout). Verify that a store run that walks
    /// offsets non-monotonically (e.g. compiler-reordered field stores
    /// or a duplicate offset before `__cxa_throw`) declines the
    /// rewrite and leaves the raw alloc + stores + throw intact.
    #[test]
    fn recover_cxa_throw_declines_when_store_offsets_are_not_increasing() {
        let buf = || local("ret_0", 8);
        let store_at = |off: i128, value: i128| -> Expr {
            Expr::assign(
                Expr::deref(Expr::binop(BinOpKind::Add, buf(), Expr::int(off)), 4),
                Expr::int(value),
            )
        };
        // Out-of-order: writes to offset 8 before offset 0. A
        // brace-literal-in-statement-order would render
        // `{ value@8, value@0 }` and mislead the analyst.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    buf(),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(12)],
                    ),
                ),
                store_at(8, 3),
                store_at(0, 1),
                cxa_throw_named("ret_0", "&typeinfo for Pod"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        // No collapse: all 4 statements survive (alloc, two stores in
        // original order, throw call).
        assert_eq!(
            statements.len(),
            4,
            "expected non-monotonic offsets to decline rewrite: {statements:#?}"
        );
        assert!(matches!(
            &statements.last().unwrap().kind,
            ExprKind::Call { .. }
        ));
    }

    /// Same concern, duplicate-offset variant: two writes to the same
    /// field offset before the throw also decline the rewrite.
    #[test]
    fn recover_cxa_throw_declines_on_duplicate_store_offset() {
        let buf = || local("ret_0", 8);
        let store_at = |off: i128, value: i128| -> Expr {
            Expr::assign(
                Expr::deref(Expr::binop(BinOpKind::Add, buf(), Expr::int(off)), 4),
                Expr::int(value),
            )
        };
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    buf(),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(8)],
                    ),
                ),
                store_at(0, 1),
                store_at(0, 99), // duplicate offset 0
                store_at(4, 2),
                cxa_throw_named("ret_0", "&typeinfo for Pod"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        assert_eq!(
            statements.len(),
            5,
            "expected duplicate offsets to decline rewrite: {statements:#?}"
        );
    }

    /// A multi-store run interrupted by an unrelated store (one that is
    /// not rooted at the alloc buffer) must DECLINE the rewrite — the
    /// interruption could be any side effect we don't model, and a
    /// brace-literal that silently drops it would mislead the reader.
    #[test]
    fn recover_cxa_throw_declines_when_store_run_is_interrupted() {
        let buf = || local("ret_0", 8);
        let other = || local("other", 8);
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    buf(),
                    Expr::call(
                        CallTarget::Named("__cxa_allocate_exception".to_string()),
                        vec![Expr::int(8)],
                    ),
                ),
                Expr::assign(Expr::deref(buf(), 4), Expr::int(1)),
                Expr::assign(Expr::deref(other(), 4), Expr::int(99)),
                Expr::assign(
                    Expr::deref(Expr::binop(BinOpKind::Add, buf(), Expr::int(4)), 4),
                    Expr::int(2),
                ),
                cxa_throw_named("ret_0", "&typeinfo for Pod"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block, got {:?}", rewritten[0]);
        };
        // No collapse — original 5 statements survive (alloc, store0,
        // unrelated store, store1, __cxa_throw call).
        assert_eq!(
            statements.len(),
            5,
            "expected interrupted store run to decline rewrite: {statements:#?}"
        );
        assert!(matches!(
            &statements.last().unwrap().kind,
            ExprKind::Call { .. }
        ));
    }

    #[test]
    fn recover_cxa_throw_leaves_unrelated_calls_alone() {
        // The recogniser must decline when the three trailing
        // statements don't match the canonical throw shape — e.g. a
        // store to an unrelated buffer, or no preceding allocate.
        let body = vec![block(
            0,
            vec![
                Expr::assign(local("v", 4), Expr::int(7)),
                Expr::call(
                    CallTarget::Named("side_effect".to_string()),
                    vec![Expr::int(1)],
                ),
                cxa_throw_named("v", "&typeinfo for int"),
            ],
        )];

        let resolve = |_: u64, _: u64| -> Option<String> { None };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block");
        };
        assert_eq!(statements.len(), 3, "must not rewrite unrelated sequences");
    }

    #[test]
    fn recover_cxa_throw_resolves_direct_call_via_symbol_table() {
        // The lifter often emits PLT calls with `CallTarget::Direct`
        // — only the address is known at simplify time. The
        // recogniser must consult the `resolve` callback (symbol
        // table) to recognise the allocator. Mirrors the
        // dynamically-linked PR repro where
        // `__cxa_allocate_exception` is at a stub address.
        let body = vec![block(
            0,
            vec![
                Expr::assign(
                    local("ret_0", 8),
                    Expr::call(
                        CallTarget::Direct {
                            target: 0x4304,
                            call_site: 0x4392,
                        },
                        vec![Expr::int(4)],
                    ),
                ),
                Expr::assign(Expr::deref(local("ret_0", 8), 4), Expr::int(42)),
                cxa_throw_named("ret_0", "&typeinfo for int"),
            ],
        )];

        let resolve = |target_addr: u64, _call_site: u64| -> Option<String> {
            (target_addr == 0x4304).then_some("__cxa_allocate_exception@CXXABI_1.3@plt".to_string())
        };
        let rewritten = recover_cxa_throw_pattern(body, &resolve);
        let StructuredNode::Block { statements, .. } = &rewritten[0] else {
            panic!("expected Block");
        };
        assert_eq!(statements.len(), 1, "{statements:#?}");
        assert!(
            matches!(
                &statements[0].kind,
                ExprKind::Unknown(text)
                    if text == "throw 42" || text == "throw 0x2a"
            ),
            "expected resolved-Direct throw fold, got {:?}",
            statements[0].kind
        );
    }
}
