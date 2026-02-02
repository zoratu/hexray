//! Short-circuit boolean detection.
//!
//! Detects short-circuit boolean patterns and converts nested ifs to && / ||.
//!
//! Patterns detected:
//! 1. `if (a) { if (b) { body }}` → `if (a && b) { body }`
//! 2. `if (a) { body } else { if (b) { same_body }}` → `if (a || b) { body }`
//! 3. Chains: `if (a) { if (b) { if (c) { body }}}` → `if (a && b && c) { body }`

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
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
            let else_is_empty = else_body.as_ref().map_or(true, |e| e.is_empty());
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
        } => StructuredNode::While {
            condition,
            body: detect_short_circuit(body),
            header,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
        } => StructuredNode::DoWhile {
            body: detect_short_circuit(body),
            condition,
            header,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_short_circuit(body),
            header,
        },
        StructuredNode::Loop { body, header } => StructuredNode::Loop {
            body: detect_short_circuit(body),
            header,
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
    let inner_else_is_empty = inner_else.as_ref().map_or(true, |e| e.is_empty());
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

    #[test]
    fn test_and_chain_detection() {
        // Create: if (a) { if (b) { return 1; } }
        let inner_if = StructuredNode::If {
            condition: Expr::int(1), // represents condition b
            then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
            else_body: None,
        };
        let outer_if = StructuredNode::If {
            condition: Expr::int(2), // represents condition a
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
