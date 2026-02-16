//! Filter out inline assembly and profiling infrastructure.
//!
//! Removes:
//! - Stack pointer manipulation (rsp/sp += const, rsp/sp -= const)
//! - Profiling calls (__fentry__, mcount, etc.)
//!
//! These are implementation details that should not appear in decompiled output.

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::structurer::{CatchHandler, StructuredNode};

/// Filters out inline assembly and profiling infrastructure from statements.
pub fn filter_inline_asm(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .filter_map(|node| filter_node(node))
        .collect()
}

/// Filter a single structured node.
fn filter_node(node: StructuredNode) -> Option<StructuredNode> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements: Vec<_> = statements
                .into_iter()
                .filter(|stmt| !should_filter_expr(stmt))
                .collect();

            // Don't emit empty blocks
            if statements.is_empty() {
                return None;
            }

            Some(StructuredNode::Block {
                id,
                statements,
                address_range,
            })
        }
        StructuredNode::Expr(expr) => {
            if should_filter_expr(&expr) {
                None
            } else {
                Some(StructuredNode::Expr(expr))
            }
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => Some(StructuredNode::If {
            condition,
            then_body: filter_nodes(then_body),
            else_body: else_body.map(filter_nodes),
        }),
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: filter_nodes(body),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: filter_nodes(body),
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
            body: filter_nodes(body),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: filter_nodes(body),
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
                .map(|(vals, body)| (vals, filter_nodes(body)))
                .collect(),
            default: default.map(filter_nodes),
        }),
        StructuredNode::Sequence(nodes) => {
            let nodes = filter_nodes(nodes);
            if nodes.is_empty() {
                None
            } else {
                Some(StructuredNode::Sequence(nodes))
            }
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => Some(StructuredNode::TryCatch {
            try_body: filter_nodes(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: filter_nodes(h.body),
                    ..h
                })
                .collect(),
        }),
        other => Some(other),
    }
}

/// Filter a list of structured nodes.
fn filter_nodes(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().filter_map(filter_node).collect()
}

/// Check if an expression should be filtered out.
fn should_filter_expr(expr: &Expr) -> bool {
    match &expr.kind {
        // Filter: rsp += const or rsp -= const (and similar for sp, esp, rsp, etc.)
        ExprKind::CompoundAssign { lhs, rhs, op } => {
            if is_stack_pointer_var(lhs) && is_simple_constant(rhs) {
                // Only filter add/sub operations
                return matches!(op, BinOpKind::Add | BinOpKind::Sub);
            }
            false
        }
        // Filter: rsp = rsp + const or rsp = rsp - const (and similar)
        ExprKind::Assign { lhs, rhs } => {
            if is_stack_pointer_var(lhs) {
                // Check if rhs is a simple add/sub with constant
                return is_stack_pointer_arithmetic(rhs);
            }
            false
        }
        // Filter: __fentry__() and similar profiling calls
        ExprKind::Call { target, args } => is_profiling_call(target) && args.is_empty(),
        _ => false,
    }
}

/// Check if the expression is a stack pointer variable.
fn is_stack_pointer_var(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Var(v) => {
            let name = v.name.to_lowercase();
            matches!(
                name.as_str(),
                "rsp" | "sp" | "esp" | "r13" | "x29" | "fp" | "rbp" | "ebp"
            )
        }
        _ => false,
    }
}

/// Check if the expression is a simple constant.
fn is_simple_constant(expr: &Expr) -> bool {
    matches!(&expr.kind, ExprKind::IntLit(_))
}

/// Check if the expression is stack pointer arithmetic (rsp +/- const).
fn is_stack_pointer_arithmetic(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::BinOp { op, left, right } => {
            if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                // Check if it's sp +/- const or const +/- sp
                return (is_stack_pointer_var(left) && is_simple_constant(right))
                    || (is_simple_constant(left) && is_stack_pointer_var(right));
            }
            false
        }
        _ => false,
    }
}

/// Check if the call target is a profiling/infrastructure function.
fn is_profiling_call(target: &CallTarget) -> bool {
    match target {
        CallTarget::Named(name) => {
            let lower = name.to_lowercase();
            matches!(
                lower.as_str(),
                "__fentry__" | "__fentry___" | "mcount" | "_mcount" | "fentry"
            )
        }
        _ => false,
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

    fn make_assign(lhs: &str, rhs: Expr) -> Expr {
        Expr::assign(make_var(lhs), rhs)
    }

    fn make_compound_assign(lhs: &str, op: BinOpKind, rhs: i128) -> Expr {
        Expr {
            kind: ExprKind::CompoundAssign {
                op,
                lhs: Box::new(make_var(lhs)),
                rhs: Box::new(Expr::int(rhs)),
            },
        }
    }

    #[test]
    fn test_filter_rsp_add_constant() {
        let expr = make_compound_assign("rsp", BinOpKind::Add, 8);
        assert!(should_filter_expr(&expr));
    }

    #[test]
    fn test_filter_rsp_sub_constant() {
        let expr = make_compound_assign("rsp", BinOpKind::Sub, 8);
        assert!(should_filter_expr(&expr));
    }

    #[test]
    fn test_filter_sp_assignment() {
        let expr = make_assign(
            "sp",
            Expr::binop(BinOpKind::Add, make_var("sp"), Expr::int(16)),
        );
        assert!(should_filter_expr(&expr));
    }

    #[test]
    fn test_filter_fentry_call() {
        let expr = Expr::call(CallTarget::Named("__fentry__".to_string()), vec![]);
        assert!(should_filter_expr(&expr));
    }

    #[test]
    fn test_filter_mcount_call() {
        let expr = Expr::call(CallTarget::Named("_mcount".to_string()), vec![]);
        assert!(should_filter_expr(&expr));
    }

    #[test]
    fn test_keep_normal_call() {
        let expr = Expr::call(CallTarget::Named("printf".to_string()), vec![]);
        assert!(!should_filter_expr(&expr));
    }

    #[test]
    fn test_filter_block_with_mixed_statements() {
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_assign("x", Expr::int(5)),
                make_compound_assign("rsp", BinOpKind::Add, 8),
                make_assign("y", make_var("x")),
            ],
            address_range: (0, 0),
        }];

        let result = filter_inline_asm(nodes);
        assert_eq!(result.len(), 1);
        if let StructuredNode::Block { statements, .. } = &result[0] {
            assert_eq!(statements.len(), 2); // rsp += 8 should be filtered
        }
    }
}
