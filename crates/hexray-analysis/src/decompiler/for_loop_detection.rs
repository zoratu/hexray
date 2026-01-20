//! For-loop detection from while loops.
//!
//! Detects and converts while loops with init/update patterns to for loops.
//!
//! Patterns detected:
//! - `i = 0; while (i < n) { ... i++; }` → `for (i = 0; i < n; i++) { ... }`

use super::expression::{BinOpKind, Expr, ExprKind, UnaryOpKind};
use super::structurer::StructuredNode;

/// Detect and convert while loops with init/update patterns to for loops.
pub fn detect_for_loops(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < nodes.len() {
        // Check for Block followed by While pattern
        if i + 1 < nodes.len() {
            if let (
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                },
                StructuredNode::While { condition, body },
            ) = (&nodes[i], &nodes[i + 1])
            {
                // Try to extract a for loop
                if let Some((init, updated_condition, update, new_body, remaining_stmts)) =
                    try_extract_for_loop(statements, condition, body)
                {
                    // Add remaining statements from the block (if any) as a separate block
                    if !remaining_stmts.is_empty() {
                        result.push(StructuredNode::Block {
                            id: *id,
                            statements: remaining_stmts,
                            address_range: *address_range,
                        });
                    }

                    // Add the for loop
                    result.push(StructuredNode::For {
                        init: Some(init),
                        condition: updated_condition,
                        update: Some(update),
                        body: detect_for_loops(new_body),
                    });

                    i += 2;
                    continue;
                }
            }
        }

        // Recursively process the node
        result.push(detect_for_loops_in_node(nodes[i].clone()));
        i += 1;
    }

    result
}

/// Recursively detect for loops within a single node.
fn detect_for_loops_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: detect_for_loops(then_body),
            else_body: else_body.map(detect_for_loops),
        },
        StructuredNode::While { condition, body } => {
            // Check if the while body itself has init/update pattern (rare but possible)
            StructuredNode::While {
                condition,
                body: detect_for_loops(body),
            }
        }
        StructuredNode::DoWhile { body, condition } => StructuredNode::DoWhile {
            body: detect_for_loops(body),
            condition,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
        } => StructuredNode::For {
            init,
            condition,
            update,
            body: detect_for_loops(body),
        },
        StructuredNode::Loop { body } => StructuredNode::Loop {
            body: detect_for_loops(body),
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_for_loops(body)))
                .collect(),
            default: default.map(detect_for_loops),
        },
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(detect_for_loops(nodes)),
        other => other,
    }
}

/// Try to extract a for loop from a block followed by a while loop.
/// Returns (init_expr, condition, update_expr, new_body, remaining_block_stmts) if successful.
#[allow(clippy::type_complexity)]
fn try_extract_for_loop(
    block_stmts: &[Expr],
    condition: &Expr,
    body: &[StructuredNode],
) -> Option<(Expr, Expr, Expr, Vec<StructuredNode>, Vec<Expr>)> {
    // Extract the loop variable from the condition
    let loop_var = extract_loop_variable(condition)?;

    // Find init: last statement in the block that assigns to the loop variable
    let init_idx = block_stmts
        .iter()
        .rposition(|stmt| is_init_assignment(stmt, &loop_var))?;
    let init = block_stmts[init_idx].clone();

    // Find update: look for increment/decrement of the loop variable in the body
    let (update, new_body) = extract_update_from_body(body, &loop_var)?;

    // Remaining statements from the block (everything before the init)
    let remaining_stmts: Vec<_> = block_stmts[..init_idx].to_vec();

    Some((init, condition.clone(), update, new_body, remaining_stmts))
}

/// Extract the loop variable name from a comparison condition.
/// Looks for patterns like: var < n, var <= n, var > n, var >= n, var != n
fn extract_loop_variable(condition: &Expr) -> Option<String> {
    if let ExprKind::BinOp {
        op:
            BinOpKind::Lt
            | BinOpKind::Le
            | BinOpKind::Gt
            | BinOpKind::Ge
            | BinOpKind::ULt
            | BinOpKind::ULe
            | BinOpKind::UGt
            | BinOpKind::UGe
            | BinOpKind::Ne
            | BinOpKind::Eq,
        left,
        right,
    } = &condition.kind
    {
        // Try to get variable from left side first
        if let Some(var) = get_expr_var_key(left) {
            return Some(var);
        }
        // Try right side (for reversed comparisons like `n > i`)
        if let Some(var) = get_expr_var_key(right) {
            return Some(var);
        }
    }
    None
}

/// Get a unique key for a variable expression.
/// Handles both simple variables (Var) and stack slots (Deref of rbp/sp + offset).
pub fn get_expr_var_key(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        ExprKind::Deref { addr, .. } => {
            // Extract stack variable pattern like [rbp - 4] or [sp + 8]
            get_stack_slot_key(addr)
        }
        _ => None,
    }
}

/// Extract a key for a stack slot address expression.
/// Handles patterns like: rbp, rbp + offset, rbp - offset, sp + offset
fn get_stack_slot_key(addr: &Expr) -> Option<String> {
    match &addr.kind {
        // Just base register (offset 0)
        ExprKind::Var(var) => {
            if is_frame_register(&var.name) {
                Some("stack_0".to_string())
            } else {
                None
            }
        }
        // base + offset or base - offset
        ExprKind::BinOp { op, left, right } => {
            if let ExprKind::Var(base) = &left.kind {
                if is_frame_register(&base.name) {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        let actual_offset = match op {
                            BinOpKind::Add => *offset,
                            BinOpKind::Sub => -*offset,
                            _ => return None,
                        };
                        return Some(format!("stack_{}", actual_offset));
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Check if a register name is a frame/stack pointer.
fn is_frame_register(name: &str) -> bool {
    matches!(
        name,
        "rbp" | "ebp" | "bp" | "sp" | "rsp" | "esp" | "x29" | "fp"
    )
}

/// Check if an expression is an initialization assignment to the given variable.
/// Matches patterns like: var = 0, var = 1, var = expr
fn is_init_assignment(stmt: &Expr, var_key: &str) -> bool {
    if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
        if let Some(lhs_key) = get_expr_var_key(lhs) {
            if lhs_key == var_key {
                // Check that RHS is a constant or simple expression (not another loop variable)
                return is_simple_init_value(rhs);
            }
        }
    }
    false
}

/// Check if an expression is a valid initialization value (constant or simple expression).
fn is_simple_init_value(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::IntLit(_) => true,
        ExprKind::Var(_) => true,
        ExprKind::BinOp { left, right, .. } => {
            is_simple_init_value(left) && is_simple_init_value(right)
        }
        _ => false,
    }
}

/// Extract the update statement from the loop body.
/// Returns (update_expr, modified_body) if found.
fn extract_update_from_body(
    body: &[StructuredNode],
    var_name: &str,
) -> Option<(Expr, Vec<StructuredNode>)> {
    if body.is_empty() {
        return None;
    }

    let last_node = body.last()?;

    // Check if the last node is a Block with an update statement
    if let StructuredNode::Block {
        id,
        statements,
        address_range,
    } = last_node
    {
        if let Some(last_stmt) = statements.last() {
            if is_update_statement(last_stmt, var_name) {
                let update = last_stmt.clone();

                // Create new body with the update removed
                let mut new_body: Vec<_> = body[..body.len() - 1].to_vec();

                // Add the block back without the last statement (if there are remaining statements)
                let remaining_stmts: Vec<_> = statements[..statements.len() - 1].to_vec();
                if !remaining_stmts.is_empty() {
                    new_body.push(StructuredNode::Block {
                        id: *id,
                        statements: remaining_stmts,
                        address_range: *address_range,
                    });
                }

                return Some((update, new_body));
            }
        }
    }

    // Also check for a Sequence ending with a Block
    if let StructuredNode::Sequence(inner_nodes) = last_node {
        if let Some((update, new_inner)) = extract_update_from_body(inner_nodes, var_name) {
            let mut new_body: Vec<_> = body[..body.len() - 1].to_vec();
            if !new_inner.is_empty() {
                new_body.push(StructuredNode::Sequence(new_inner));
            }
            return Some((update, new_body));
        }
    }

    None
}

/// Check if an expression is an update statement for the given variable.
/// Matches patterns like: var++, var--, var += n, var -= n, var = var + n
fn is_update_statement(stmt: &Expr, var_key: &str) -> bool {
    match &stmt.kind {
        // var++ or var--
        ExprKind::UnaryOp { op, operand } => {
            matches!(op, UnaryOpKind::Inc | UnaryOpKind::Dec)
                && get_expr_var_key(operand).is_some_and(|k| k == var_key)
        }

        // var += n or var -= n
        ExprKind::CompoundAssign { op, lhs, rhs: _ } => {
            matches!(op, BinOpKind::Add | BinOpKind::Sub)
                && get_expr_var_key(lhs).is_some_and(|k| k == var_key)
        }

        // var = var + n or var = var - n
        ExprKind::Assign { lhs, rhs } => {
            if let Some(lhs_key) = get_expr_var_key(lhs) {
                if lhs_key == var_key {
                    if let ExprKind::BinOp { op, left, right: _ } = &rhs.kind {
                        if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                            if let Some(rhs_key) = get_expr_var_key(left) {
                                return rhs_key == var_key;
                            }
                        }
                    }
                }
            }
            false
        }

        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::Variable;
    use hexray_core::BasicBlockId;

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable::reg(name, 4))
    }

    fn make_inc(name: &str) -> Expr {
        Expr {
            kind: ExprKind::UnaryOp {
                op: UnaryOpKind::Inc,
                operand: Box::new(make_var(name)),
            },
        }
    }

    fn make_dec(name: &str) -> Expr {
        Expr {
            kind: ExprKind::UnaryOp {
                op: UnaryOpKind::Dec,
                operand: Box::new(make_var(name)),
            },
        }
    }

    fn make_block(id: u32, stmts: Vec<Expr>) -> StructuredNode {
        StructuredNode::Block {
            id: BasicBlockId::new(id),
            statements: stmts,
            address_range: (0x1000, 0x1010),
        }
    }

    #[test]
    fn test_detect_for_loop_pattern() {
        // Create: i = 0; while (i < 10) { body; i++; }
        let init_stmt = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        let update_stmt = make_inc("i");

        let body_block = make_block(1, vec![Expr::int(42), update_stmt]);
        let init_block = make_block(0, vec![init_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![init_block, while_loop]);

        // Should produce a For loop
        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::For {
                init,
                condition: _,
                update,
                body: _,
            } => {
                assert!(init.is_some());
                assert!(update.is_some());
            }
            _ => panic!("Expected For loop"),
        }
    }

    #[test]
    fn test_for_loop_with_decrement() {
        // Create: i = 10; while (i > 0) { body; i--; }
        let init_stmt = Expr::assign(make_var("i"), Expr::int(10));
        let condition = Expr::binop(BinOpKind::Gt, make_var("i"), Expr::int(0));
        let update_stmt = make_dec("i");

        let body_block = make_block(1, vec![Expr::int(42), update_stmt]);
        let init_block = make_block(0, vec![init_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![init_block, while_loop]);

        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::For { init, update, .. } => {
                assert!(init.is_some());
                assert!(update.is_some());
            }
            _ => panic!("Expected For loop"),
        }
    }

    #[test]
    fn test_no_for_loop_without_init() {
        // Create: while (i < 10) { body; i++; } - no init block before
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        let update_stmt = make_inc("i");

        let body_block = make_block(1, vec![Expr::int(42), update_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![while_loop]);

        // Should remain a while loop (no init block)
        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::While { .. } => {}
            _ => panic!("Expected While loop to remain"),
        }
    }

    #[test]
    fn test_no_for_loop_without_update() {
        // Create: i = 0; while (i < 10) { body; } - no update in body
        let init_stmt = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));

        let body_block = make_block(1, vec![Expr::int(42)]); // No update!
        let init_block = make_block(0, vec![init_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![init_block, while_loop]);

        // Should remain as block + while (can't form for loop)
        assert_eq!(result.len(), 2);
        match &result[1] {
            StructuredNode::While { .. } => {}
            _ => panic!("Expected While loop to remain"),
        }
    }

    #[test]
    fn test_for_loop_with_compound_update() {
        // Create: i = 0; while (i < 100) { body; i += 2; }
        let init_stmt = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(100));
        let update_stmt = Expr {
            kind: ExprKind::CompoundAssign {
                op: BinOpKind::Add,
                lhs: Box::new(make_var("i")),
                rhs: Box::new(Expr::int(2)),
            },
        };

        let body_block = make_block(1, vec![Expr::int(42), update_stmt]);
        let init_block = make_block(0, vec![init_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![init_block, while_loop]);

        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::For { init, update, .. } => {
                assert!(init.is_some());
                assert!(update.is_some());
            }
            _ => panic!("Expected For loop"),
        }
    }

    #[test]
    fn test_for_loop_preserves_remaining_statements() {
        // Create: x = 1; y = 2; i = 0; while (i < 10) { i++; }
        // x = 1 and y = 2 should remain in a separate block
        let stmt1 = Expr::assign(make_var("x"), Expr::int(1));
        let stmt2 = Expr::assign(make_var("y"), Expr::int(2));
        let init_stmt = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        let update_stmt = make_inc("i");

        let body_block = make_block(1, vec![update_stmt]);
        let init_block = make_block(0, vec![stmt1, stmt2, init_stmt]);
        let while_loop = StructuredNode::While {
            condition,
            body: vec![body_block],
        };

        let result = detect_for_loops(vec![init_block, while_loop]);

        // Should produce a block (with x, y) + a for loop
        assert_eq!(result.len(), 2);

        // First should be block with remaining statements
        match &result[0] {
            StructuredNode::Block { statements, .. } => {
                assert_eq!(statements.len(), 2); // x = 1 and y = 2
            }
            _ => panic!("Expected Block with remaining statements"),
        }

        // Second should be for loop
        match &result[1] {
            StructuredNode::For { .. } => {}
            _ => panic!("Expected For loop"),
        }
    }

    #[test]
    fn test_nested_for_loop_detection() {
        // Create: i = 0; while (i < 10) { j = 0; while (j < 10) { j++; } i++; }
        let inner_init = Expr::assign(make_var("j"), Expr::int(0));
        let inner_cond = Expr::binop(BinOpKind::Lt, make_var("j"), Expr::int(10));
        let inner_update = make_inc("j");

        let inner_body = make_block(2, vec![inner_update]);
        let inner_init_block = make_block(1, vec![inner_init]);
        let inner_while = StructuredNode::While {
            condition: inner_cond,
            body: vec![inner_body],
        };

        let outer_init = Expr::assign(make_var("i"), Expr::int(0));
        let outer_cond = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        let outer_update = make_inc("i");

        let outer_body = vec![
            inner_init_block,
            inner_while,
            make_block(3, vec![outer_update]),
        ];
        let outer_init_block = make_block(0, vec![outer_init]);
        let outer_while = StructuredNode::While {
            condition: outer_cond,
            body: outer_body,
        };

        let result = detect_for_loops(vec![outer_init_block, outer_while]);

        // Should produce an outer for loop
        assert_eq!(result.len(), 1);
        match &result[0] {
            StructuredNode::For { body, .. } => {
                // Inner should also be a for loop
                assert!(!body.is_empty());
                let has_inner_for = body.iter().any(|n| matches!(n, StructuredNode::For { .. }));
                assert!(has_inner_for, "Expected inner for loop");
            }
            _ => panic!("Expected outer For loop"),
        }
    }

    #[test]
    fn test_extract_loop_variable() {
        // i < 10
        let cond = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        assert_eq!(extract_loop_variable(&cond), Some("i".to_string()));

        // 10 > i (reversed)
        let cond_rev = Expr::binop(BinOpKind::Gt, Expr::int(10), make_var("j"));
        assert_eq!(extract_loop_variable(&cond_rev), Some("j".to_string()));

        // Different comparison operators
        let cond_le = Expr::binop(BinOpKind::Le, make_var("k"), Expr::int(5));
        assert_eq!(extract_loop_variable(&cond_le), Some("k".to_string()));

        let cond_ne = Expr::binop(BinOpKind::Ne, make_var("x"), Expr::int(0));
        assert_eq!(extract_loop_variable(&cond_ne), Some("x".to_string()));
    }

    #[test]
    fn test_get_expr_var_key() {
        // Simple variable
        let var = make_var("rax");
        assert_eq!(get_expr_var_key(&var), Some("rax".to_string()));

        // Integer literal - not a variable
        let lit = Expr::int(42);
        assert_eq!(get_expr_var_key(&lit), None);

        // Binary op - not a simple variable
        let binop = Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(1));
        assert_eq!(get_expr_var_key(&binop), None);
    }

    #[test]
    fn test_is_frame_register() {
        assert!(is_frame_register("rbp"));
        assert!(is_frame_register("ebp"));
        assert!(is_frame_register("rsp"));
        assert!(is_frame_register("esp"));
        assert!(is_frame_register("x29")); // ARM64 frame pointer
        assert!(is_frame_register("fp"));

        assert!(!is_frame_register("rax"));
        assert!(!is_frame_register("r12"));
        assert!(!is_frame_register("x0"));
    }
}
