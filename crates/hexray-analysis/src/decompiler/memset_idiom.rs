//! Memset and array initialization idiom detection.
//!
//! Detects patterns that represent memset, array initialization, or
//! buffer zeroing and transforms them into clearer idioms.

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind, VarKind, Variable};
use super::structurer::StructuredNode;

/// Detected memset/initialization pattern.
#[derive(Debug, Clone)]
pub enum InitPattern {
    /// memset(dst, value, size) pattern
    Memset {
        dst: Expr,
        value: i128,
        size: Option<usize>,
    },
    /// Array initialization: arr[i] = value in a loop
    ArrayInit {
        array: Expr,
        value: Expr,
        count: Option<usize>,
    },
    /// Buffer zeroing pattern
    ZeroBuffer { buffer: Expr, size: Option<usize> },
}

/// Detects and transforms memset/initialization patterns.
pub fn detect_init_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(transform_node).collect()
}

fn transform_node(node: StructuredNode) -> StructuredNode {
    match node {
        // Check for loops that represent initialization patterns
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            // Check if this is an array initialization loop
            if let Some(pattern) = detect_for_init_pattern(&init, &condition, &update, &body) {
                return create_init_call(pattern);
            }

            // Otherwise, recursively process
            StructuredNode::For {
                init,
                condition,
                update,
                body: detect_init_patterns(body),
                header,
                exit_block,
            }
        }

        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            // Check for while-based initialization
            if let Some(pattern) = detect_while_init_pattern(&condition, &body) {
                return create_init_call(pattern);
            }

            StructuredNode::While {
                condition,
                body: detect_init_patterns(body),
                header,
                exit_block,
            }
        }

        // Recursively process other structures
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: detect_init_patterns(then_body),
            else_body: else_body.map(detect_init_patterns),
        },

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: detect_init_patterns(body),
            condition,
            header,
            exit_block,
        },

        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: detect_init_patterns(body),
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
                .map(|(vals, body)| (vals, detect_init_patterns(body)))
                .collect(),
            default: default.map(detect_init_patterns),
        },

        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(detect_init_patterns(nodes)),

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: detect_init_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: detect_init_patterns(h.body),
                    ..h
                })
                .collect(),
        },

        other => other,
    }
}

/// Detects initialization patterns in a for loop.
fn detect_for_init_pattern(
    init: &Option<Expr>,
    condition: &Expr,
    update: &Option<Expr>,
    body: &[StructuredNode],
) -> Option<InitPattern> {
    // Pattern: for (i = 0; i < n; i++) { arr[i] = value; }
    let init = init.as_ref()?;

    // Check init is i = 0
    let (loop_var, start_val) = extract_assignment(init)?;
    if start_val != 0 {
        return None;
    }

    // Check condition is i < n
    let limit = extract_loop_limit(condition, &loop_var)?;

    // Check update is i++ or i += 1
    let update = update.as_ref()?;
    if !is_increment(&loop_var, update) {
        return None;
    }

    // Check body is a single indexed store
    if body.len() != 1 {
        return None;
    }

    let (array, value) = extract_indexed_store(&body[0], &loop_var)?;

    // Determine if it's zeroing
    if is_zero_value(&value) {
        Some(InitPattern::ZeroBuffer {
            buffer: array,
            size: limit.map(|l| l as usize),
        })
    } else if let Some(const_val) = extract_constant(&value) {
        Some(InitPattern::Memset {
            dst: array,
            value: const_val,
            size: limit.map(|l| l as usize),
        })
    } else {
        Some(InitPattern::ArrayInit {
            array,
            value,
            count: limit.map(|l| l as usize),
        })
    }
}

/// Detects initialization patterns in a while loop.
fn detect_while_init_pattern(condition: &Expr, body: &[StructuredNode]) -> Option<InitPattern> {
    // Pattern: while (ptr < end) { *ptr++ = value; }
    // This is more complex, defer for now
    let _ = (condition, body);
    None
}

/// Extracts variable and value from an assignment.
fn extract_assignment(expr: &Expr) -> Option<(String, i128)> {
    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        if let ExprKind::Var(v) = &lhs.kind {
            if let ExprKind::IntLit(val) = &rhs.kind {
                return Some((v.name.clone(), *val));
            }
        }
    }
    None
}

/// Extracts the loop limit from a condition like i < n.
fn extract_loop_limit(condition: &Expr, loop_var: &str) -> Option<Option<i128>> {
    if let ExprKind::BinOp { op, left, right } = &condition.kind {
        match op {
            BinOpKind::Lt | BinOpKind::Le => {
                if let ExprKind::Var(v) = &left.kind {
                    if v.name == loop_var {
                        if let ExprKind::IntLit(limit) = &right.kind {
                            return Some(Some(*limit));
                        }
                        // Variable limit
                        return Some(None);
                    }
                }
            }
            BinOpKind::Ne => {
                // i != n form
                if let ExprKind::Var(v) = &left.kind {
                    if v.name == loop_var {
                        if let ExprKind::IntLit(limit) = &right.kind {
                            return Some(Some(*limit));
                        }
                        return Some(None);
                    }
                }
            }
            _ => {}
        }
    }
    None
}

/// Checks if an expression is an increment of the loop variable.
fn is_increment(loop_var: &str, expr: &Expr) -> bool {
    match &expr.kind {
        // i++
        ExprKind::UnaryOp {
            op: UnaryOpKind::Inc,
            operand,
        } => {
            if let ExprKind::Var(v) = &operand.kind {
                v.name == loop_var
            } else {
                false
            }
        }
        // i = i + 1
        ExprKind::Assign { lhs, rhs } => {
            if let ExprKind::Var(v) = &lhs.kind {
                if v.name != loop_var {
                    return false;
                }
                if let ExprKind::BinOp {
                    op: BinOpKind::Add,
                    left,
                    right,
                } = &rhs.kind
                {
                    let left_is_var = matches!(&left.kind, ExprKind::Var(v) if v.name == loop_var);
                    let right_is_one = matches!(&right.kind, ExprKind::IntLit(1));
                    return left_is_var && right_is_one;
                }
            }
            false
        }
        // i += 1
        ExprKind::CompoundAssign {
            op: BinOpKind::Add,
            lhs,
            rhs,
        } => {
            if let ExprKind::Var(v) = &lhs.kind {
                v.name == loop_var && matches!(&rhs.kind, ExprKind::IntLit(1))
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Extracts array and value from an indexed store: arr[i] = value
fn extract_indexed_store(node: &StructuredNode, loop_var: &str) -> Option<(Expr, Expr)> {
    let expr = match node {
        StructuredNode::Expr(e) => e,
        StructuredNode::Block { statements, .. } if statements.len() == 1 => &statements[0],
        _ => return None,
    };

    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        // Check for arr[i] = value
        if let ExprKind::ArrayAccess { base, index, .. } = &lhs.kind {
            if let ExprKind::Var(v) = &index.kind {
                if v.name == loop_var {
                    return Some(((**base).clone(), (**rhs).clone()));
                }
            }
        }

        // Check for *(ptr + i) = value
        if let ExprKind::Deref { addr, .. } = &lhs.kind {
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } = &addr.kind
            {
                if let ExprKind::Var(v) = &right.kind {
                    if v.name == loop_var {
                        return Some(((**left).clone(), (**rhs).clone()));
                    }
                }
                if let ExprKind::Var(v) = &left.kind {
                    if v.name == loop_var {
                        return Some(((**right).clone(), (**rhs).clone()));
                    }
                }
            }
        }
    }

    None
}

/// Checks if a value is zero.
fn is_zero_value(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::IntLit(0))
}

/// Extracts a constant value from an expression.
fn extract_constant(expr: &Expr) -> Option<i128> {
    if let ExprKind::IntLit(val) = &expr.kind {
        Some(*val)
    } else {
        None
    }
}

/// Creates a function call or comment representing the initialization pattern.
fn create_init_call(pattern: InitPattern) -> StructuredNode {
    match pattern {
        InitPattern::ZeroBuffer { buffer, size } => {
            // Generate: memset(buffer, 0, size)
            let size_expr = size.map(|s| Expr::int(s as i128)).unwrap_or_else(|| {
                Expr::var(Variable {
                    name: "count".to_string(),
                    kind: VarKind::Temp(0),
                    size: 8,
                })
            });

            StructuredNode::Expr(Expr::call(
                CallTarget::Named("memset".to_string()),
                vec![buffer, Expr::int(0), size_expr],
            ))
        }
        InitPattern::Memset { dst, value, size } => {
            let size_expr = size.map(|s| Expr::int(s as i128)).unwrap_or_else(|| {
                Expr::var(Variable {
                    name: "count".to_string(),
                    kind: VarKind::Temp(0),
                    size: 8,
                })
            });

            StructuredNode::Expr(Expr::call(
                CallTarget::Named("memset".to_string()),
                vec![dst, Expr::int(value), size_expr],
            ))
        }
        InitPattern::ArrayInit {
            array,
            value,
            count,
        } => {
            // Generate a comment-style representation
            // In the future, could keep as a cleaner for loop
            let count_str = count
                .map(|c| c.to_string())
                .unwrap_or_else(|| "n".to_string());

            // For now, return as a for loop with a comment
            // This could be enhanced to emit as: initialize_array(array, value, count)
            StructuredNode::Expr(Expr::call(
                CallTarget::Named(format!("/* init {} elements */", count_str)),
                vec![array, value],
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::BasicBlockId;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            name: name.to_string(),
            kind: VarKind::Register(0),
            size: 8,
        })
    }

    #[test]
    fn test_detect_zeroing_loop() {
        // for (i = 0; i < 10; i++) { arr[i] = 0; }
        let init = Some(Expr::assign(make_var("i"), Expr::int(0)));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        let update = Some(Expr::unary(UnaryOpKind::Inc, make_var("i")));
        let body = vec![StructuredNode::Expr(Expr::assign(
            Expr::array_access(make_var("arr"), make_var("i"), 4),
            Expr::int(0),
        ))];

        let input = StructuredNode::For {
            init,
            condition,
            update,
            body,
            header: Some(BasicBlockId::new(0)),
            exit_block: None,
        };

        let result = transform_node(input);

        // Should be transformed to memset call
        match result {
            StructuredNode::Expr(e) => {
                if let ExprKind::Call { target, .. } = &e.kind {
                    assert!(matches!(target, CallTarget::Named(name) if name == "memset"));
                } else {
                    panic!("Expected call expression");
                }
            }
            _ => panic!("Expected Expr node with memset call"),
        }
    }

    #[test]
    fn test_is_increment() {
        // i++
        let inc = Expr::unary(UnaryOpKind::Inc, make_var("i"));
        assert!(is_increment("i", &inc));

        // i = i + 1
        let add = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );
        assert!(is_increment("i", &add));

        // j++ should not match
        let wrong_var = Expr::unary(UnaryOpKind::Inc, make_var("j"));
        assert!(!is_increment("i", &wrong_var));
    }
}
