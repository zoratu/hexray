//! Linked list traversal detection.
//!
//! Detects patterns that indicate linked list traversal and annotates
//! them for better readability.

#![allow(dead_code)] // Module not yet integrated into pipeline

use super::expression::{BinOpKind, Expr, ExprKind};
use super::structurer::StructuredNode;

/// Information about detected linked list traversal.
#[derive(Debug, Clone)]
pub struct LinkedListTraversal {
    /// The pointer variable being traversed.
    pub ptr_var: String,
    /// The field being used for the next pointer (if detected).
    pub next_field: Option<String>,
    /// The offset used to access the next pointer.
    pub next_offset: Option<usize>,
}

/// Analyzes nodes for linked list traversal patterns.
pub fn detect_linked_list_patterns(nodes: &[StructuredNode]) -> Vec<LinkedListTraversal> {
    let mut detected = Vec::new();

    for node in nodes {
        if let Some(traversal) = detect_traversal_in_node(node) {
            detected.push(traversal);
        }
    }

    detected
}

/// Detect linked list traversal in a single node.
fn detect_traversal_in_node(node: &StructuredNode) -> Option<LinkedListTraversal> {
    match node {
        // Pattern: while (ptr != NULL) { ... ptr = ptr->next; }
        StructuredNode::While {
            condition, body, ..
        } => detect_while_traversal(condition, body),

        // Pattern: for (ptr = head; ptr != NULL; ptr = ptr->next) { ... }
        StructuredNode::For {
            init,
            condition,
            update,
            ..
        } => detect_for_traversal(init.as_ref(), condition, update.as_ref()),

        // Recurse into nested structures
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            if let Some(traversal) = detect_linked_list_patterns(then_body).into_iter().next() {
                return Some(traversal);
            }
            if let Some(else_body) = else_body {
                if let Some(traversal) = detect_linked_list_patterns(else_body).into_iter().next() {
                    return Some(traversal);
                }
            }
            None
        }

        StructuredNode::Sequence(nodes) => detect_linked_list_patterns(nodes).into_iter().next(),

        _ => None,
    }
}

/// Detect linked list traversal in a while loop.
fn detect_while_traversal(
    condition: &Expr,
    body: &[StructuredNode],
) -> Option<LinkedListTraversal> {
    // Check condition: ptr != NULL or ptr != 0
    let ptr_var = extract_ptr_null_check(condition)?;

    // Check body for: ptr = ptr->next (or similar)
    let (next_field, next_offset) = find_next_assignment(body, &ptr_var)?;

    Some(LinkedListTraversal {
        ptr_var,
        next_field,
        next_offset,
    })
}

/// Detect linked list traversal in a for loop.
fn detect_for_traversal(
    _init: Option<&Expr>,
    condition: &Expr,
    update: Option<&Expr>,
) -> Option<LinkedListTraversal> {
    // Check condition: ptr != NULL
    let ptr_var = extract_ptr_null_check(condition)?;

    // Check update: ptr = ptr->next
    let update = update?;
    let (next_field, next_offset) = extract_next_assignment(update, &ptr_var)?;

    Some(LinkedListTraversal {
        ptr_var,
        next_field,
        next_offset,
    })
}

/// Extract pointer variable from `ptr != NULL` or `ptr != 0` check.
fn extract_ptr_null_check(condition: &Expr) -> Option<String> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        // Check for != 0 or != NULL
        if is_null_or_zero(right) {
            return extract_var_name(left);
        }
        if is_null_or_zero(left) {
            return extract_var_name(right);
        }
    }

    // Also check for just the variable (implicit != 0)
    extract_var_name(condition)
}

/// Check if expression is NULL or 0.
fn is_null_or_zero(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::IntLit(0) => true,
        ExprKind::Var(v) if v.name.to_uppercase() == "NULL" => true,
        _ => false,
    }
}

/// Extract variable name from expression.
fn extract_var_name(expr: &Expr) -> Option<String> {
    if let ExprKind::Var(v) = &expr.kind {
        return Some(v.name.clone());
    }
    None
}

/// Find next pointer assignment in loop body.
fn find_next_assignment(
    body: &[StructuredNode],
    ptr_var: &str,
) -> Option<(Option<String>, Option<usize>)> {
    for node in body {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if let Some(result) = extract_next_assignment(stmt, ptr_var) {
                        return Some(result);
                    }
                }
            }
            StructuredNode::Expr(expr) => {
                if let Some(result) = extract_next_assignment(expr, ptr_var) {
                    return Some(result);
                }
            }
            StructuredNode::Sequence(nodes) => {
                if let Some(result) = find_next_assignment(nodes, ptr_var) {
                    return Some(result);
                }
            }
            _ => {}
        }
    }
    None
}

/// Extract next pointer assignment info from `ptr = ptr->next` or `ptr = *(ptr + offset)`.
fn extract_next_assignment(expr: &Expr, ptr_var: &str) -> Option<(Option<String>, Option<usize>)> {
    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        // Check if lhs is the pointer variable
        if let ExprKind::Var(v) = &lhs.kind {
            if v.name != ptr_var {
                return None;
            }
        } else {
            return None;
        }

        // Check rhs for ptr->next pattern
        return extract_next_from_rhs(rhs, ptr_var);
    }
    None
}

/// Extract next pointer info from right-hand side of assignment.
fn extract_next_from_rhs(rhs: &Expr, ptr_var: &str) -> Option<(Option<String>, Option<usize>)> {
    match &rhs.kind {
        // Pattern: ptr->next (field access)
        ExprKind::FieldAccess {
            base,
            field_name,
            offset,
        } => {
            if extract_var_name(base).as_deref() == Some(ptr_var) {
                return Some((Some(field_name.clone()), Some(*offset)));
            }
        }

        // Pattern: *(ptr + offset) (pointer arithmetic)
        ExprKind::Deref { addr, .. } => {
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } = &addr.kind
            {
                // Check if base is our pointer
                if extract_var_name(left).as_deref() == Some(ptr_var) {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        return Some((None, Some(*offset as usize)));
                    }
                }
                if extract_var_name(right).as_deref() == Some(ptr_var) {
                    if let ExprKind::IntLit(offset) = &left.kind {
                        return Some((None, Some(*offset as usize)));
                    }
                }
            }

            // Pattern: *ptr (next at offset 0)
            if extract_var_name(addr).as_deref() == Some(ptr_var) {
                return Some((None, Some(0)));
            }
        }

        // Pattern: ptr[0] (array-style access to next)
        ExprKind::ArrayAccess { base, index, .. } => {
            if extract_var_name(base).as_deref() == Some(ptr_var)
                && matches!(&index.kind, ExprKind::IntLit(0))
            {
                return Some((None, Some(0)));
            }
        }

        _ => {}
    }

    None
}

/// Annotate a while loop as a linked list traversal.
pub fn annotate_traversal_loop(
    traversal: &LinkedListTraversal,
    node: StructuredNode,
) -> StructuredNode {
    // For now, just return the node unchanged.
    // In a more complete implementation, we would add a comment or annotation.
    // This could be extended to modify variable names or add synthetic loop constructs.
    let _ = traversal; // Acknowledge the parameter
    node
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

    fn make_field_access(base: Expr, field: &str, offset: usize) -> Expr {
        Expr::field_access(base, field, offset)
    }

    #[test]
    fn test_extract_ptr_null_check() {
        // ptr != 0
        let cond = Expr::binop(BinOpKind::Ne, make_var("ptr"), Expr::int(0));
        assert_eq!(extract_ptr_null_check(&cond), Some("ptr".to_string()));

        // 0 != ptr
        let cond = Expr::binop(BinOpKind::Ne, Expr::int(0), make_var("node"));
        assert_eq!(extract_ptr_null_check(&cond), Some("node".to_string()));

        // Just the variable (implicit test)
        assert_eq!(
            extract_ptr_null_check(&make_var("current")),
            Some("current".to_string())
        );
    }

    #[test]
    fn test_detect_while_traversal() {
        // while (ptr != NULL) { ... ptr = ptr->next; }
        let condition = Expr::binop(BinOpKind::Ne, make_var("ptr"), Expr::int(0));

        let next_assign = Expr::assign(
            make_var("ptr"),
            make_field_access(make_var("ptr"), "next", 8),
        );

        let body = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![next_assign],
            address_range: (0, 0),
        }];

        let result = detect_while_traversal(&condition, &body);
        assert!(result.is_some());

        let traversal = result.unwrap();
        assert_eq!(traversal.ptr_var, "ptr");
        assert_eq!(traversal.next_field, Some("next".to_string()));
        assert_eq!(traversal.next_offset, Some(8));
    }

    #[test]
    fn test_detect_for_traversal() {
        // for (ptr = head; ptr != NULL; ptr = ptr->next)
        let init = Expr::assign(make_var("ptr"), make_var("head"));
        let condition = Expr::binop(BinOpKind::Ne, make_var("ptr"), Expr::int(0));
        let update = Expr::assign(
            make_var("ptr"),
            make_field_access(make_var("ptr"), "next", 8),
        );

        let result = detect_for_traversal(Some(&init), &condition, Some(&update));
        assert!(result.is_some());

        let traversal = result.unwrap();
        assert_eq!(traversal.ptr_var, "ptr");
        assert_eq!(traversal.next_field, Some("next".to_string()));
    }
}
