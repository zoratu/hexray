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

use super::super::abi::{
    get_arg_register_index, is_argument_register, is_return_register, is_temp_register,
};
use super::super::dead_store::collect_all_uses;
use super::super::expression::Expr;
use super::{CatchHandler, StructuredNode};

/// Extracts the return value from a return register assignment near the end of the block.
/// Returns the filtered statements (without the return value assignment) and the return value.
/// Looks backwards through statements to find the last assignment to a return register,
/// skipping over prologue/epilogue statements like pop(rbp).
pub(super) fn extract_return_value(statements: Vec<Expr>) -> (Vec<Expr>, Option<Expr>) {
    use super::super::expression::ExprKind;

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

/// Simplifies statements by performing copy propagation on temporary registers.
/// Transforms patterns like `eax = x; y = eax;` into `y = x;`.
pub(super) fn simplify_statements(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
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
    use super::super::expression::ExprKind;

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
        "ebx" => vec!["ebx".to_string(), "rbx".to_string()],
        "rbx" => vec!["ebx".to_string(), "rbx".to_string()],
        "ecx" => vec!["ecx".to_string(), "rcx".to_string()],
        "rcx" => vec!["ecx".to_string(), "rcx".to_string()],
        "edx" => vec!["edx".to_string(), "rdx".to_string()],
        "rdx" => vec!["edx".to_string(), "rdx".to_string()],
        "esi" => vec!["esi".to_string(), "rsi".to_string()],
        "rsi" => vec!["esi".to_string(), "rsi".to_string()],
        "edi" => vec!["edi".to_string(), "rdi".to_string()],
        "rdi" => vec!["edi".to_string(), "rdi".to_string()],
        "r8d" => vec!["r8d".to_string(), "r8".to_string()],
        "r8" => vec!["r8d".to_string(), "r8".to_string()],
        "r9d" => vec!["r9d".to_string(), "r9".to_string()],
        "r9" => vec!["r9d".to_string(), "r9".to_string()],
        "r10d" => vec!["r10d".to_string(), "r10".to_string()],
        "r10" => vec!["r10d".to_string(), "r10".to_string()],
        "r11d" => vec!["r11d".to_string(), "r11".to_string()],
        "r11" => vec!["r11d".to_string(), "r11".to_string()],
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
            let new_rhs = substitute_vars(rhs, &reg_values);

            // Check if LHS is a temp register
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if is_temp_register(&lhs_var.name) {
                    // Track this assignment for all aliased register names
                    // (e.g., w9 and x9 on ARM64, eax and rax on x86)
                    for alias in get_register_aliases(&lhs_var.name) {
                        reg_values.insert(alias, new_rhs.clone());
                    }
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
pub(super) fn propagate_call_args(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(propagate_call_args_node).collect()
}

pub(super) fn propagate_call_args_node(node: StructuredNode) -> StructuredNode {
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
pub(super) fn propagate_args_in_block(statements: Vec<Expr>) -> Vec<Expr> {
    use super::super::expression::ExprKind;

    // Track argument register values and their statement indices
    let mut arg_values: HashMap<String, (usize, Expr)> = HashMap::new();
    let mut reg_values: HashMap<String, Expr> = HashMap::new();
    let mut to_remove: HashSet<usize> = HashSet::new();
    let mut result: Vec<Expr> = Vec::with_capacity(statements.len());

    for (i, stmt) in statements.into_iter().enumerate() {
        if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
            let new_rhs = substitute_vars(rhs, &reg_values);

            if let ExprKind::Var(v) = &lhs.kind {
                if is_temp_register(&v.name) {
                    for alias in get_register_aliases(&v.name) {
                        reg_values.insert(alias, new_rhs.clone());
                    }
                }

                if get_arg_register_index(&v.name).is_some() {
                    // If one ABI argument register is only staging a value into another
                    // argument register, keep the destination but drop the staged source.
                    if let ExprKind::Var(src_var) = &rhs.kind {
                        if let Some(src_idx) = get_arg_register_index(&src_var.name) {
                            if get_arg_register_index(&v.name) != Some(src_idx) {
                                for alias in get_register_aliases(&src_var.name) {
                                    arg_values.remove(&alias);
                                }
                            }
                        }
                    }

                    // Track this argument value along with its statement index.
                    arg_values.insert(v.name.clone(), (i, new_rhs.clone()));
                    result.push(Expr::assign((**lhs).clone(), new_rhs));
                    continue;
                }
            }

            result.push(Expr::assign((**lhs).clone(), new_rhs));
            continue;
        }

        // Check if this is an assignment to an argument register
        // Check if this is a function call (not push/pop/syscall/etc.)
        if let ExprKind::Call { target, args } = &stmt.kind {
            let substituted_target = substitute_call_target(target.clone(), &reg_values);
            if is_real_function_call(target) {
                let excluded_arg_regs = collect_target_argument_registers(target);
                // Try to extract arguments from tracked registers
                let new_args = extract_call_arguments_with_indices(&arg_values, &excluded_arg_regs);
                if args.is_empty() && !new_args.0.is_empty() {
                    // Mark the used arg assignments for removal
                    for idx in new_args.1 {
                        to_remove.insert(idx);
                    }
                    // Create a new call with arguments
                    let new_call = Expr::call(substituted_target, new_args.0);
                    result.push(new_call);
                    // Clear argument tracking after the call
                    arg_values.clear();
                    reg_values.clear();
                    continue;
                }

                let substituted_args = args.iter().map(|arg| substitute_vars(arg, &reg_values));
                result.push(Expr::call(substituted_target, substituted_args.collect()));
                arg_values.clear();
                reg_values.clear();
                continue;
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
                if get_arg_register_index(&v.name).is_some() {
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

/// Checks if a call target is a "real" function call (not push/pop/syscall etc.)
fn is_real_function_call(target: &super::super::expression::CallTarget) -> bool {
    use super::super::expression::CallTarget;
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

/// Extracts call arguments and returns (arguments, statement_indices_used).
/// The statement indices are used to track which arg assignments should be removed.
fn extract_call_arguments_with_indices(
    arg_values: &HashMap<String, (usize, Expr)>,
    excluded_regs: &HashSet<String>,
) -> (Vec<Expr>, Vec<usize>) {
    let mut args: Vec<(usize, usize, Expr)> = Vec::new(); // (arg_idx, stmt_idx, value)

    for (reg_name, (stmt_idx, value)) in arg_values {
        if excluded_regs.contains(&reg_name.to_lowercase()) {
            continue;
        }
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
        let node = merge_return_value_captures_node(node, capture_counter);

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
    statements: &mut [Expr],
    capture_counter: &mut u32,
) {
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

fn first_return_register_use_before_clobber(statements: &[Expr]) -> Option<String> {
    let all_aliases = [
        "eax".to_string(),
        "rax".to_string(),
        "w0".to_string(),
        "x0".to_string(),
        "arg0".to_string(),
        "a0".to_string(),
    ];

    for stmt in statements {
        if let super::super::expression::ExprKind::Call { target, .. } = &stmt.kind {
            if is_real_function_call(target) {
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
            if is_real_function_call(target) {
                return Some(idx);
            }
        }

        if statements.iter().any(|stmt| {
            matches!(&stmt.kind, ExprKind::Call { target, .. } if is_real_function_call(target))
                || statement_clobbers_return_register(stmt, aliases)
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

    if !is_real_function_call(&target) {
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
            if is_real_function_call(target) {
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

pub(super) fn substitute_return_register_uses(
    expr: Expr,
    aliases: &[String],
    replacement: &Expr,
) -> Expr {
    use super::super::expression::ExprKind;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{BinOpKind, CallTarget, ExprKind, Variable};
    use hexray_core::BasicBlockId;

    fn reg(name: &str, size: u8) -> Expr {
        Expr::var(Variable::reg(name, size))
    }

    fn block(id: u32, statements: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(id),
            statements,
            address_range: (0x1000 + (id as u64) * 0x10, 0x1008 + (id as u64) * 0x10),
        }
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
}
