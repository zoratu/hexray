//! Loop canonicalization pass.
//!
//! Transforms loops into canonical forms for better readability:
//! - Convert do-while loops to while loops when the first iteration is always executed
//! - Normalize infinite loops with conditional breaks

use super::expression::{BinOpKind, Expr, ExprKind};
use super::structurer::StructuredNode;

/// Canonicalizes loop structures for better readability.
pub fn canonicalize_loops(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(canonicalize_node).collect()
}

fn canonicalize_node(node: StructuredNode) -> StructuredNode {
    match node {
        // Try to convert do-while to while if possible
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            let canonicalized_body: Vec<_> = body.into_iter().map(canonicalize_node).collect();

            // Check if we can convert to while:
            // 1. Body doesn't modify condition variables before testing
            // 2. Condition is a simple comparison (not too complex)
            if can_convert_to_while(&canonicalized_body, &condition) {
                StructuredNode::While {
                    condition,
                    body: canonicalized_body,
                    header,
                    exit_block,
                }
            } else {
                StructuredNode::DoWhile {
                    body: canonicalized_body,
                    condition,
                    header,
                    exit_block,
                }
            }
        }

        // Handle infinite loops with conditional breaks at the start
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => {
            let canonicalized_body: Vec<_> = body.into_iter().map(canonicalize_node).collect();

            // Check if the loop starts with `if (!cond) break`
            if let Some((condition, remaining)) =
                extract_leading_break_condition(&canonicalized_body)
            {
                // Convert to while (condition) { remaining }
                StructuredNode::While {
                    condition,
                    body: remaining,
                    header,
                    exit_block,
                }
            } else {
                StructuredNode::Loop {
                    body: canonicalized_body,
                    header,
                    exit_block,
                }
            }
        }

        // Recursively process while loops
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: canonicalize_loops(body),
            header,
            exit_block,
        },

        // Recursively process for loops
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
            body: canonicalize_loops(body),
            header,
            exit_block,
        },

        // Recursively process if statements
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: canonicalize_loops(then_body),
            else_body: else_body.map(canonicalize_loops),
        },

        // Recursively process switch
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(values, body)| (values, canonicalize_loops(body)))
                .collect(),
            default: default.map(canonicalize_loops),
        },

        // Recursively process sequences
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(canonicalize_loops(nodes)),

        // Recursively process try-catch
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: canonicalize_loops(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: canonicalize_loops(h.body),
                    ..h
                })
                .collect(),
        },

        // Other nodes pass through unchanged
        other => other,
    }
}

/// Checks if a do-while loop can be safely converted to a while loop.
///
/// This is safe when the condition doesn't depend on variables that are
/// modified in the loop body before being tested.
fn can_convert_to_while(body: &[StructuredNode], condition: &Expr) -> bool {
    // For now, use a conservative heuristic:
    // Only convert if the condition is a simple variable or comparison,
    // and doesn't involve function calls or complex expressions.
    if condition_is_simple(condition) {
        // Check that the condition doesn't reference variables that could
        // be modified at the start of the loop body
        !modifies_condition_vars(body, condition)
    } else {
        false
    }
}

/// Checks if a condition is simple enough for safe transformation.
fn condition_is_simple(condition: &Expr) -> bool {
    match &condition.kind {
        ExprKind::Var(_) => true,
        ExprKind::IntLit(_) => true,
        ExprKind::BinOp { op, left, right } => {
            matches!(
                op,
                BinOpKind::Eq
                    | BinOpKind::Ne
                    | BinOpKind::Lt
                    | BinOpKind::Le
                    | BinOpKind::Gt
                    | BinOpKind::Ge
            ) && condition_is_simple(left)
                && condition_is_simple(right)
        }
        ExprKind::UnaryOp { operand, .. } => condition_is_simple(operand),
        _ => false,
    }
}

/// Checks if the body might modify variables used in the condition.
fn modifies_condition_vars(body: &[StructuredNode], condition: &Expr) -> bool {
    let condition_vars = collect_vars(condition);

    if condition_vars.is_empty() {
        return false;
    }

    // Check if any of the first statements modify these variables
    for node in body.iter().take(3) {
        // Check first few statements
        if node_modifies_any(node, &condition_vars) {
            return true;
        }
    }

    false
}

/// Collects variable names from an expression.
fn collect_vars(expr: &Expr) -> Vec<String> {
    let mut vars = Vec::new();
    collect_vars_recursive(expr, &mut vars);
    vars
}

fn collect_vars_recursive(expr: &Expr, vars: &mut Vec<String>) {
    match &expr.kind {
        ExprKind::Var(v) => {
            vars.push(v.name.clone());
        }
        ExprKind::BinOp { left, right, .. } => {
            collect_vars_recursive(left, vars);
            collect_vars_recursive(right, vars);
        }
        ExprKind::UnaryOp { operand, .. } => {
            collect_vars_recursive(operand, vars);
        }
        ExprKind::Deref { addr, .. } => {
            collect_vars_recursive(addr, vars);
        }
        _ => {}
    }
}

/// Checks if a node modifies any of the given variables.
fn node_modifies_any(node: &StructuredNode, vars: &[String]) -> bool {
    match node {
        StructuredNode::Block { statements, .. } => {
            statements.iter().any(|s| expr_modifies_any(s, vars))
        }
        StructuredNode::Expr(e) => expr_modifies_any(e, vars),
        _ => false,
    }
}

/// Checks if an expression modifies any of the given variables.
fn expr_modifies_any(expr: &Expr, vars: &[String]) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
            if let ExprKind::Var(v) = &lhs.kind {
                vars.contains(&v.name)
            } else {
                false
            }
        }
        ExprKind::UnaryOp { operand, .. } => {
            // Increment/decrement modifies the variable
            if let ExprKind::Var(v) = &operand.kind {
                vars.contains(&v.name)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Extracts a break condition from the start of a loop body.
///
/// Looks for patterns like:
/// ```text
/// if (!condition) break;
/// ```
///
/// Returns the positive condition and the remaining body.
fn extract_leading_break_condition(body: &[StructuredNode]) -> Option<(Expr, Vec<StructuredNode>)> {
    if body.is_empty() {
        return None;
    }

    if let StructuredNode::If {
        condition,
        then_body,
        else_body: None,
    } = &body[0]
    {
        // Check if then_body is just a break
        if then_body.len() == 1 && matches!(then_body[0], StructuredNode::Break) {
            // The break condition is !condition, so the loop condition is condition
            // But we need to negate if the condition is a negation
            let loop_condition = negate_condition(condition.clone());
            let remaining = body[1..].to_vec();
            return Some((loop_condition, remaining));
        }
    }

    None
}

/// Negates a condition expression.
fn negate_condition(condition: Expr) -> Expr {
    match &condition.kind {
        // Double negation: !!x -> x
        ExprKind::UnaryOp {
            op: super::expression::UnaryOpKind::Not,
            operand,
        } => (**operand).clone(),

        // Negate comparisons
        ExprKind::BinOp { op, left, right } => {
            let negated_op = match op {
                BinOpKind::Eq => Some(BinOpKind::Ne),
                BinOpKind::Ne => Some(BinOpKind::Eq),
                BinOpKind::Lt => Some(BinOpKind::Ge),
                BinOpKind::Le => Some(BinOpKind::Gt),
                BinOpKind::Gt => Some(BinOpKind::Le),
                BinOpKind::Ge => Some(BinOpKind::Lt),
                _ => None,
            };

            if let Some(new_op) = negated_op {
                Expr::binop(new_op, (**left).clone(), (**right).clone())
            } else {
                Expr::unary(super::expression::UnaryOpKind::Not, condition)
            }
        }

        // For other expressions, wrap in logical not
        _ => Expr::unary(super::expression::UnaryOpKind::Not, condition),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};
    use hexray_core::BasicBlockId;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            name: name.to_string(),
            kind: VarKind::Register(0),
            size: 8,
        })
    }

    #[test]
    fn test_loop_with_break_to_while() {
        // loop { if (!cond) break; body; }
        // -> while (cond) { body; }
        let body_stmt = StructuredNode::Expr(Expr::assign(make_var("x"), Expr::int(1)));
        let break_cond = Expr::unary(
            super::super::expression::UnaryOpKind::Not,
            make_var("running"),
        );

        let input = StructuredNode::Loop {
            body: vec![
                StructuredNode::If {
                    condition: break_cond,
                    then_body: vec![StructuredNode::Break],
                    else_body: None,
                },
                body_stmt.clone(),
            ],
            header: Some(BasicBlockId::new(0)),
            exit_block: None,
        };

        let result = canonicalize_node(input);

        // Should be converted to a while loop
        match result {
            StructuredNode::While {
                condition, body, ..
            } => {
                // Condition should be "running" (negation of !running)
                assert!(matches!(condition.kind, ExprKind::Var(_)));
                assert_eq!(body.len(), 1);
            }
            _ => panic!("Expected While loop"),
        }
    }

    #[test]
    fn test_negate_comparison() {
        let cond = Expr::binop(BinOpKind::Eq, make_var("x"), Expr::int(0));
        let negated = negate_condition(cond);

        match negated.kind {
            ExprKind::BinOp { op, .. } => assert_eq!(op, BinOpKind::Ne),
            _ => panic!("Expected BinOp"),
        }
    }

    #[test]
    fn test_double_negation() {
        let cond = Expr::unary(super::super::expression::UnaryOpKind::Not, make_var("x"));
        let negated = negate_condition(cond);

        // !!x -> x
        assert!(matches!(negated.kind, ExprKind::Var(_)));
    }
}
