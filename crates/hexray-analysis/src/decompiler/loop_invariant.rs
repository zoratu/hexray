//! Loop-invariant code motion for the decompiler.
//!
//! This module detects loop-invariant computations and hoists them out of loops
//! for cleaner pseudo-code output. The goal is presentation clarity rather than
//! execution optimization.
//!
//! Examples of transformations:
//! ```text
//! // Before:
//! for (i = 0; i < n; i++) {
//!     dst[i] = src[i] + (x * y);  // x * y computed each iteration
//! }
//!
//! // After:
//! tmp = x * y;
//! for (i = 0; i < n; i++) {
//!     dst[i] = src[i] + tmp;
//! }
//! ```

use super::expression::{BinOpKind, Expr, ExprKind, VarKind, Variable};
use super::structurer::StructuredNode;
use std::collections::HashSet;

/// Counter for generating unique temporary variable names.
static LICM_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Generates a unique name for a hoisted loop-invariant expression.
fn make_invariant_temp_name() -> String {
    let id = LICM_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("loop_inv_{}", id)
}

/// Creates a temporary variable expression for a hoisted value.
fn make_temp_var(name: &str) -> Expr {
    Expr::var(Variable {
        kind: VarKind::Temp(0),
        name: name.to_string(),
        size: 8, // Default size
    })
}

/// Apply loop-invariant code motion to a list of structured nodes.
pub fn hoist_loop_invariants(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().flat_map(hoist_in_node).collect()
}

/// Apply LICM to a single node, potentially returning multiple nodes
/// (hoisted assignments followed by the transformed node).
fn hoist_in_node(node: StructuredNode) -> Vec<StructuredNode> {
    match node {
        // Handle while loops
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            // Collect loop variables (any variable assigned in the loop)
            let loop_vars = collect_assigned_vars(&body);

            // Find invariant expressions that could be hoisted
            let (hoisted, transformed_body) = hoist_from_body(body, &loop_vars);

            // Build result: hoisted assignments + transformed loop
            let mut result = hoisted;
            result.push(StructuredNode::While {
                condition,
                body: transformed_body,
                header,
                exit_block,
            });
            result
        }

        // Handle for loops
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            // Collect loop variables
            let mut loop_vars = collect_assigned_vars(&body);
            // The loop variable itself is also considered assigned
            if let Some(init_expr) = &init {
                if let Some(var) = extract_assigned_var(init_expr) {
                    loop_vars.insert(var);
                }
            }

            // Find invariant expressions
            let (hoisted, transformed_body) = hoist_from_body(body, &loop_vars);

            // Build result
            let mut result = hoisted;
            result.push(StructuredNode::For {
                init,
                condition,
                update,
                body: transformed_body,
                header,
                exit_block,
            });
            result
        }

        // Handle do-while loops
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let loop_vars = collect_assigned_vars(&body);
            let (hoisted, transformed_body) = hoist_from_body(body, &loop_vars);

            let mut result = hoisted;
            result.push(StructuredNode::DoWhile {
                body: transformed_body,
                condition,
                header,
                exit_block,
            });
            result
        }

        // Handle infinite loops
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let loop_vars = collect_assigned_vars(&body);
            let (hoisted, transformed_body) = hoist_from_body(body, &loop_vars);

            let mut result = hoisted;
            result.push(StructuredNode::Loop {
                body: transformed_body,
                header,
                exit_block,
            });
            result
        }

        // Recurse into other compound structures
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => vec![StructuredNode::If {
            condition,
            then_body: hoist_loop_invariants(then_body),
            else_body: else_body.map(hoist_loop_invariants),
        }],

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => vec![StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, hoist_loop_invariants(body)))
                .collect(),
            default: default.map(hoist_loop_invariants),
        }],

        StructuredNode::Sequence(nodes) => {
            vec![StructuredNode::Sequence(hoist_loop_invariants(nodes))]
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => vec![StructuredNode::TryCatch {
            try_body: hoist_loop_invariants(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|mut h| {
                    h.body = hoist_loop_invariants(h.body);
                    h
                })
                .collect(),
        }],

        // Pass through unchanged
        other => vec![other],
    }
}

/// Collect all variables that are assigned in the given nodes.
fn collect_assigned_vars(nodes: &[StructuredNode]) -> HashSet<String> {
    let mut vars = HashSet::new();
    for node in nodes {
        collect_assigned_vars_in_node(node, &mut vars);
    }
    vars
}

/// Recursively collect assigned variables from a node.
fn collect_assigned_vars_in_node(node: &StructuredNode, vars: &mut HashSet<String>) {
    match node {
        StructuredNode::Expr(expr) => {
            if let Some(var) = extract_assigned_var(expr) {
                vars.insert(var);
            }
        }
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                if let Some(var) = extract_assigned_var(stmt) {
                    vars.insert(var);
                }
            }
        }
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for n in then_body {
                collect_assigned_vars_in_node(n, vars);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_assigned_vars_in_node(n, vars);
                }
            }
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::For { body, .. }
        | StructuredNode::Loop { body, .. } => {
            for n in body {
                collect_assigned_vars_in_node(n, vars);
            }
        }
        StructuredNode::Switch { cases, default, .. } => {
            for (_, body) in cases {
                for n in body {
                    collect_assigned_vars_in_node(n, vars);
                }
            }
            if let Some(def) = default {
                for n in def {
                    collect_assigned_vars_in_node(n, vars);
                }
            }
        }
        StructuredNode::Sequence(nodes) => {
            for n in nodes {
                collect_assigned_vars_in_node(n, vars);
            }
        }
        _ => {}
    }
}

/// Extract the variable name being assigned, if any.
fn extract_assigned_var(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => get_var_name(lhs),
        _ => None,
    }
}

/// Get variable name from expression.
fn get_var_name(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        _ => None,
    }
}

/// Hoist loop-invariant expressions from a loop body.
/// Returns (hoisted_assignments, transformed_body).
fn hoist_from_body(
    body: Vec<StructuredNode>,
    loop_vars: &HashSet<String>,
) -> (Vec<StructuredNode>, Vec<StructuredNode>) {
    // For now, we implement a simple version that looks for common invariant patterns:
    // - Arithmetic operations on loop-invariant operands that appear multiple times

    // Collect candidate invariant sub-expressions
    let candidates = find_invariant_candidates(&body, loop_vars);

    // If we have candidates that appear multiple times, hoist them
    let (hoisted, substitutions) = select_and_hoist(candidates);

    // Apply substitutions to the body
    let transformed_body = if substitutions.is_empty() {
        // Just recurse into nested structures
        hoist_loop_invariants(body)
    } else {
        // Apply substitutions then recurse
        let subst_body = apply_substitutions(body, &substitutions);
        hoist_loop_invariants(subst_body)
    };

    (hoisted, transformed_body)
}

/// Information about a candidate invariant expression.
#[derive(Debug, Clone)]
struct InvariantCandidate {
    /// The expression to potentially hoist.
    expr: Expr,
    /// How many times this expression appears.
    #[allow(dead_code)]
    count: usize,
}

/// Find expressions that are loop-invariant and appear multiple times.
fn find_invariant_candidates(
    body: &[StructuredNode],
    loop_vars: &HashSet<String>,
) -> Vec<InvariantCandidate> {
    let mut expr_counts: std::collections::HashMap<String, (Expr, usize)> =
        std::collections::HashMap::new();

    for node in body {
        collect_invariant_subexprs(node, loop_vars, &mut expr_counts);
    }

    // Return expressions that appear multiple times and are "worth" hoisting
    expr_counts
        .into_values()
        .filter(|(expr, count)| *count >= 2 && is_worth_hoisting(expr))
        .map(|(expr, count)| InvariantCandidate { expr, count })
        .collect()
}

/// Recursively collect loop-invariant sub-expressions.
fn collect_invariant_subexprs(
    node: &StructuredNode,
    loop_vars: &HashSet<String>,
    counts: &mut std::collections::HashMap<String, (Expr, usize)>,
) {
    match node {
        StructuredNode::Expr(expr) => {
            collect_invariant_exprs(expr, loop_vars, counts);
        }
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                collect_invariant_exprs(stmt, loop_vars, counts);
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_invariant_exprs(condition, loop_vars, counts);
            for n in then_body {
                collect_invariant_subexprs(n, loop_vars, counts);
            }
            if let Some(eb) = else_body {
                for n in eb {
                    collect_invariant_subexprs(n, loop_vars, counts);
                }
            }
        }
        // Don't descend into nested loops (their invariants are separate)
        StructuredNode::While { .. }
        | StructuredNode::DoWhile { .. }
        | StructuredNode::For { .. }
        | StructuredNode::Loop { .. } => {}
        StructuredNode::Sequence(nodes) => {
            for n in nodes {
                collect_invariant_subexprs(n, loop_vars, counts);
            }
        }
        _ => {}
    }
}

/// Collect invariant sub-expressions from an expression.
fn collect_invariant_exprs(
    expr: &Expr,
    loop_vars: &HashSet<String>,
    counts: &mut std::collections::HashMap<String, (Expr, usize)>,
) {
    // Check if this expression is invariant and non-trivial
    if is_loop_invariant(expr, loop_vars) && is_compound_expr(expr) {
        let key = expr_to_key(expr);
        counts
            .entry(key)
            .and_modify(|(_, c)| *c += 1)
            .or_insert((expr.clone(), 1));
    }

    // Recurse into sub-expressions
    match &expr.kind {
        ExprKind::BinOp { left, right, .. } => {
            collect_invariant_exprs(left, loop_vars, counts);
            collect_invariant_exprs(right, loop_vars, counts);
        }
        ExprKind::UnaryOp { operand, .. } => {
            collect_invariant_exprs(operand, loop_vars, counts);
        }
        ExprKind::Assign { lhs, rhs } => {
            // Don't count LHS (it's not a value)
            collect_invariant_exprs(rhs, loop_vars, counts);
            // But recurse into array indices in LHS
            if let ExprKind::ArrayAccess { index, .. } = &lhs.kind {
                collect_invariant_exprs(index, loop_vars, counts);
            }
        }
        ExprKind::Call { args, .. } => {
            for arg in args {
                collect_invariant_exprs(arg, loop_vars, counts);
            }
        }
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_invariant_exprs(base, loop_vars, counts);
            collect_invariant_exprs(index, loop_vars, counts);
        }
        ExprKind::Cast { expr: inner, .. } => {
            collect_invariant_exprs(inner, loop_vars, counts);
        }
        _ => {}
    }
}

/// Check if expression is loop-invariant.
fn is_loop_invariant(expr: &Expr, loop_vars: &HashSet<String>) -> bool {
    match &expr.kind {
        ExprKind::Var(var) => !loop_vars.contains(&var.name),
        ExprKind::IntLit(_) => true,
        ExprKind::BinOp { left, right, .. } => {
            is_loop_invariant(left, loop_vars) && is_loop_invariant(right, loop_vars)
        }
        ExprKind::UnaryOp { operand, .. } => is_loop_invariant(operand, loop_vars),
        ExprKind::Cast { expr: inner, .. } => is_loop_invariant(inner, loop_vars),
        // Be conservative for other expressions
        _ => false,
    }
}

/// Check if expression is compound (worth hoisting, not just a simple var or literal).
fn is_compound_expr(expr: &Expr) -> bool {
    matches!(
        expr.kind,
        ExprKind::BinOp { .. } | ExprKind::UnaryOp { .. } | ExprKind::Call { .. }
    )
}

/// Check if expression is "worth" hoisting (complex enough).
fn is_worth_hoisting(expr: &Expr) -> bool {
    // Hoist arithmetic operations with both operands being non-trivial
    // or the operation being complex (mul, div, etc.)
    match &expr.kind {
        ExprKind::BinOp { op, left, right } => {
            // Multiplication and division are always worth hoisting
            if matches!(op, BinOpKind::Mul | BinOpKind::Div | BinOpKind::Mod) {
                return true;
            }
            // Other operations are worth it if both sides are non-trivial
            !is_trivial(left) && !is_trivial(right)
        }
        ExprKind::Call { .. } => {
            // Function calls with side effects shouldn't be hoisted
            // For now, be conservative and don't hoist calls
            false
        }
        _ => false,
    }
}

/// Check if expression is trivial (just a var or literal).
fn is_trivial(expr: &Expr) -> bool {
    matches!(expr.kind, ExprKind::Var(_) | ExprKind::IntLit(_))
}

/// Generate a key for expression deduplication.
fn expr_to_key(expr: &Expr) -> String {
    // Simple string representation for comparison
    format!("{:?}", expr.kind)
}

/// Select candidates for hoisting and create substitution map.
fn select_and_hoist(
    candidates: Vec<InvariantCandidate>,
) -> (Vec<StructuredNode>, Vec<(String, String)>) {
    let mut hoisted = Vec::new();
    let mut substitutions = Vec::new();

    for candidate in candidates {
        let temp_name = make_invariant_temp_name();

        // Create assignment: temp = invariant_expr
        let assignment = Expr::assign(make_temp_var(&temp_name), candidate.expr.clone());
        hoisted.push(StructuredNode::Expr(assignment));

        // Record substitution
        let key = expr_to_key(&candidate.expr);
        substitutions.push((key, temp_name));
    }

    (hoisted, substitutions)
}

/// Apply expression substitutions to the body.
fn apply_substitutions(
    body: Vec<StructuredNode>,
    substitutions: &[(String, String)],
) -> Vec<StructuredNode> {
    body.into_iter()
        .map(|node| apply_substitutions_to_node(node, substitutions))
        .collect()
}

/// Apply substitutions to a single node.
fn apply_substitutions_to_node(
    node: StructuredNode,
    substitutions: &[(String, String)],
) -> StructuredNode {
    match node {
        StructuredNode::Expr(expr) => StructuredNode::Expr(substitute_in_expr(expr, substitutions)),
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements: statements
                .into_iter()
                .map(|s| substitute_in_expr(s, substitutions))
                .collect(),
            address_range,
        },
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: substitute_in_expr(condition, substitutions),
            then_body: apply_substitutions(then_body, substitutions),
            else_body: else_body.map(|e| apply_substitutions(e, substitutions)),
        },
        // Don't apply to nested loops (they have their own invariants)
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: substitute_in_expr(condition, substitutions),
            body, // Don't substitute inside
            header,
            exit_block,
        },
        // Pass through other nodes
        other => other,
    }
}

/// Substitute invariant expressions with temp vars.
fn substitute_in_expr(expr: Expr, substitutions: &[(String, String)]) -> Expr {
    // First check if this entire expression should be substituted
    let key = expr_to_key(&expr);
    for (subst_key, temp_name) in substitutions {
        if &key == subst_key {
            return make_temp_var(temp_name);
        }
    }

    // Otherwise, recurse into sub-expressions
    match expr.kind {
        ExprKind::BinOp { op, left, right } => Expr {
            kind: ExprKind::BinOp {
                op,
                left: Box::new(substitute_in_expr(*left, substitutions)),
                right: Box::new(substitute_in_expr(*right, substitutions)),
            },
        },
        ExprKind::UnaryOp { op, operand } => Expr {
            kind: ExprKind::UnaryOp {
                op,
                operand: Box::new(substitute_in_expr(*operand, substitutions)),
            },
        },
        ExprKind::Assign { lhs, rhs } => Expr::assign(
            substitute_in_expr(*lhs, substitutions),
            substitute_in_expr(*rhs, substitutions),
        ),
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(substitute_in_expr(*base, substitutions)),
                index: Box::new(substitute_in_expr(*index, substitutions)),
                element_size,
            },
        },
        // Pass through other expressions unchanged
        other => Expr { kind: other },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: name.to_string(),
            size: 8,
        })
    }

    #[test]
    fn test_is_loop_invariant() {
        let loop_vars: HashSet<String> = ["i".to_string()].into_iter().collect();

        // Invariant: x (not a loop var)
        assert!(is_loop_invariant(&make_var("x"), &loop_vars));

        // Not invariant: i (is a loop var)
        assert!(!is_loop_invariant(&make_var("i"), &loop_vars));

        // Invariant: literal
        assert!(is_loop_invariant(&Expr::int(5), &loop_vars));

        // Invariant: x * y (neither is loop var)
        let x_times_y = Expr::binop(BinOpKind::Mul, make_var("x"), make_var("y"));
        assert!(is_loop_invariant(&x_times_y, &loop_vars));

        // Not invariant: i * y (i is loop var)
        let i_times_y = Expr::binop(BinOpKind::Mul, make_var("i"), make_var("y"));
        assert!(!is_loop_invariant(&i_times_y, &loop_vars));
    }

    #[test]
    fn test_is_worth_hoisting() {
        // Multiplication is worth hoisting
        let mul = Expr::binop(BinOpKind::Mul, make_var("x"), make_var("y"));
        assert!(is_worth_hoisting(&mul));

        // Simple addition of literals is not worth hoisting
        let add_lit = Expr::binop(BinOpKind::Add, Expr::int(1), Expr::int(2));
        assert!(!is_worth_hoisting(&add_lit));
    }

    #[test]
    fn test_collect_assigned_vars() {
        // for (i = 0; i < n; i++) { x = i + 1; }
        let body = vec![StructuredNode::Expr(Expr::assign(
            make_var("x"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        ))];

        let vars = collect_assigned_vars(&body);
        assert!(vars.contains("x"));
        assert!(!vars.contains("i")); // i is read, not assigned in body
    }
}
