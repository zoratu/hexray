//! Dead store elimination.
//!
//! Removes assignments to variables that are never read afterward.
//! This improves readability by eliminating unnecessary temporaries.

use std::collections::HashSet;

use super::expression::{Expr, ExprKind};
use super::structurer::{CatchHandler, StructuredNode};

/// Eliminates dead stores (assignments to variables that are never read).
pub fn eliminate_dead_stores(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    // First pass: collect all variable uses
    let mut uses = HashSet::new();
    collect_all_uses(&nodes, &mut uses);

    // Second pass: remove assignments to variables that are never used
    eliminate_in_nodes(nodes, &uses)
}

/// Collect all variable uses (reads) in the nodes.
pub fn collect_all_uses(nodes: &[StructuredNode], uses: &mut HashSet<String>) {
    for node in nodes {
        collect_uses_in_node(node, uses);
    }
}

/// Collect uses in a single node.
fn collect_uses_in_node(node: &StructuredNode, uses: &mut HashSet<String>) {
    match node {
        StructuredNode::Block { statements, .. } => {
            for stmt in statements {
                collect_uses_in_expr(stmt, uses);
            }
        }
        StructuredNode::Expr(expr) => {
            collect_uses_in_expr(expr, uses);
        }
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => {
            collect_uses_in_expr(condition, uses);
            collect_all_uses(then_body, uses);
            if let Some(else_body) = else_body {
                collect_all_uses(else_body, uses);
            }
        }
        StructuredNode::While {
            condition, body, ..
        } => {
            collect_uses_in_expr(condition, uses);
            collect_all_uses(body, uses);
        }
        StructuredNode::DoWhile {
            body, condition, ..
        } => {
            collect_all_uses(body, uses);
            collect_uses_in_expr(condition, uses);
        }
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            if let Some(init) = init {
                collect_uses_in_expr(init, uses);
            }
            collect_uses_in_expr(condition, uses);
            if let Some(update) = update {
                collect_uses_in_expr(update, uses);
            }
            collect_all_uses(body, uses);
        }
        StructuredNode::Loop { body, .. } => {
            collect_all_uses(body, uses);
        }
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => {
            collect_uses_in_expr(value, uses);
            for (_, body) in cases {
                collect_all_uses(body, uses);
            }
            if let Some(default) = default {
                collect_all_uses(default, uses);
            }
        }
        StructuredNode::Return(Some(expr)) => {
            collect_uses_in_expr(expr, uses);
        }
        StructuredNode::Sequence(nodes) => {
            collect_all_uses(nodes, uses);
        }
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            collect_all_uses(try_body, uses);
            for handler in catch_handlers {
                collect_all_uses(&handler.body, uses);
            }
        }
        _ => {}
    }
}

/// Collect variable uses in an expression.
fn collect_uses_in_expr(expr: &Expr, uses: &mut HashSet<String>) {
    match &expr.kind {
        ExprKind::Var(v) => {
            uses.insert(v.name.clone());
        }
        ExprKind::Unknown(name) => {
            uses.insert(name.clone());
        }
        ExprKind::Assign { lhs, rhs } => {
            // Don't count the lhs as a use (it's a def)
            // But do count any uses within the lhs (e.g., array index)
            collect_uses_in_lhs(lhs, uses);
            collect_uses_in_expr(rhs, uses);
        }
        ExprKind::CompoundAssign { lhs, rhs, .. } => {
            // Compound assignments read the lhs too
            collect_uses_in_expr(lhs, uses);
            collect_uses_in_expr(rhs, uses);
        }
        ExprKind::BinOp { left, right, .. } => {
            collect_uses_in_expr(left, uses);
            collect_uses_in_expr(right, uses);
        }
        ExprKind::UnaryOp { operand, .. } => {
            collect_uses_in_expr(operand, uses);
        }
        ExprKind::Call { target, args } => {
            if let super::expression::CallTarget::Indirect(expr) = target {
                collect_uses_in_expr(expr, uses);
            }
            for arg in args {
                collect_uses_in_expr(arg, uses);
            }
        }
        ExprKind::Deref { addr, .. } => {
            collect_uses_in_expr(addr, uses);
        }
        ExprKind::AddressOf(inner) => {
            collect_uses_in_expr(inner, uses);
        }
        ExprKind::Cast { expr, .. } => {
            collect_uses_in_expr(expr, uses);
        }
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_uses_in_expr(base, uses);
            collect_uses_in_expr(index, uses);
        }
        ExprKind::FieldAccess { base, .. } => {
            collect_uses_in_expr(base, uses);
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            collect_uses_in_expr(cond, uses);
            collect_uses_in_expr(then_expr, uses);
            collect_uses_in_expr(else_expr, uses);
        }
        _ => {}
    }
}

/// Collect uses within an lhs expression (but not the variable being assigned).
fn collect_uses_in_lhs(expr: &Expr, uses: &mut HashSet<String>) {
    match &expr.kind {
        ExprKind::Var(_) | ExprKind::Unknown(_) => {
            // Don't add - this is the target of assignment
        }
        ExprKind::Deref { addr, .. } => {
            collect_uses_in_expr(addr, uses);
        }
        ExprKind::ArrayAccess { base, index, .. } => {
            collect_uses_in_expr(base, uses);
            collect_uses_in_expr(index, uses);
        }
        ExprKind::FieldAccess { base, .. } => {
            collect_uses_in_expr(base, uses);
        }
        _ => {
            collect_uses_in_expr(expr, uses);
        }
    }
}

/// Check if a variable assignment can be eliminated.
fn is_eliminable_var(name: &str, uses: &HashSet<String>) -> bool {
    // Don't eliminate if the variable is used somewhere
    if uses.contains(name) {
        return false;
    }

    // Don't eliminate stack variables (could be used by called functions)
    if name.starts_with("var_") || name.starts_with("local_") {
        return false;
    }

    // Don't eliminate return registers
    if matches!(
        name.to_lowercase().as_str(),
        "eax" | "rax" | "x0" | "w0" | "a0"
    ) {
        return false;
    }

    // Don't eliminate calling convention argument registers
    // These may be set up for tail calls that appear as indirect jumps
    // x86_64 System V ABI: rdi, rsi, rdx, rcx, r8, r9 (and 32-bit variants)
    // ARM64: x0-x7 / w0-w7
    if matches!(
        name.to_lowercase().as_str(),
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
            | "x0"
            | "x1"
            | "x2"
            | "x3"
            | "x4"
            | "x5"
            | "x6"
            | "x7"
            | "w0"
            | "w1"
            | "w2"
            | "w3"
            | "w4"
            | "w5"
            | "w6"
            | "w7"
            | "a0"
            | "a1"
            | "a2"
            | "a3"
            | "a4"
            | "a5"
            | "a6"
            | "a7"
    ) {
        return false;
    }

    // Don't eliminate arguments
    if name.starts_with("arg_") {
        return false;
    }

    // Eliminate temporaries and registers that aren't used
    true
}

/// Eliminate dead stores in a list of nodes.
fn eliminate_in_nodes(nodes: Vec<StructuredNode>, uses: &HashSet<String>) -> Vec<StructuredNode> {
    let nodes: Vec<_> = nodes
        .into_iter()
        .filter_map(|node| eliminate_in_node(node, uses))
        .collect();

    // Also eliminate consecutive overwrite patterns at the StructuredNode level
    eliminate_consecutive_expr_overwrites(nodes)
}

/// Eliminate consecutive StructuredNode::Expr assignments that overwrite the same variable.
/// `Expr(x = 1); Expr(x = 2);` -> `Expr(x = 2);`
fn eliminate_consecutive_expr_overwrites(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    if nodes.len() < 2 {
        return nodes;
    }

    let mut out: Vec<StructuredNode> = Vec::with_capacity(nodes.len());
    let mut i = 0usize;
    while i < nodes.len() {
        if i + 1 < nodes.len() {
            if let (StructuredNode::Expr(cur), StructuredNode::Expr(next)) =
                (&nodes[i], &nodes[i + 1])
            {
                if let (
                    ExprKind::Assign {
                        lhs: lhs_a,
                        rhs: rhs_a,
                    },
                    ExprKind::Assign { lhs: lhs_b, .. },
                ) = (&cur.kind, &next.kind)
                {
                    if exprs_equivalent_lvalue(lhs_a, lhs_b) && !has_side_effects(rhs_a) {
                        // Skip current assignment; it's immediately overwritten.
                        i += 1;
                        continue;
                    }
                }
            }
        }
        out.push(nodes[i].clone());
        i += 1;
    }
    out
}

/// Eliminate dead stores in a single node.
fn eliminate_in_node(node: StructuredNode, uses: &HashSet<String>) -> Option<StructuredNode> {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements: Vec<_> = statements
                .into_iter()
                .filter(|stmt| !is_dead_store(stmt, uses))
                .collect();
            let statements = eliminate_consecutive_overwrites(statements);

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
            if is_dead_store(&expr, uses) {
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
            then_body: eliminate_in_nodes(then_body, uses),
            else_body: else_body.map(|e| eliminate_in_nodes(e, uses)),
        }),
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => Some(StructuredNode::While {
            condition,
            body: eliminate_in_nodes(body, uses),
            header,
            exit_block,
        }),
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => Some(StructuredNode::DoWhile {
            body: eliminate_in_nodes(body, uses),
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
            body: eliminate_in_nodes(body, uses),
            header,
            exit_block,
        }),
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => Some(StructuredNode::Loop {
            body: eliminate_in_nodes(body, uses),
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
                .map(|(vals, body)| (vals, eliminate_in_nodes(body, uses)))
                .collect(),
            default: default.map(|d| eliminate_in_nodes(d, uses)),
        }),
        StructuredNode::Sequence(nodes) => {
            let nodes = eliminate_in_nodes(nodes, uses);
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
            try_body: eliminate_in_nodes(try_body, uses),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: eliminate_in_nodes(h.body, uses),
                    ..h
                })
                .collect(),
        }),
        other => Some(other),
    }
}

/// Check if an expression is a dead store.
fn is_dead_store(expr: &Expr, uses: &HashSet<String>) -> bool {
    match &expr.kind {
        ExprKind::Assign { lhs, rhs } => {
            // Check if the lhs is a simple variable or unknown
            let var_name = match &lhs.kind {
                ExprKind::Var(v) => Some(&v.name),
                ExprKind::Unknown(name) => Some(name),
                _ => None,
            };

            if let Some(name) = var_name {
                // Check if this is an eliminable dead store
                if is_eliminable_var(name, uses) {
                    // But don't eliminate if rhs has side effects
                    return !has_side_effects(rhs);
                }
            }
            false
        }
        _ => false,
    }
}

/// Check if an expression has side effects.
fn has_side_effects(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Call { .. } => true,
        ExprKind::Assign { .. } => true,
        ExprKind::CompoundAssign { .. } => true,
        ExprKind::BinOp { left, right, .. } => has_side_effects(left) || has_side_effects(right),
        ExprKind::UnaryOp { operand, .. } => has_side_effects(operand),
        ExprKind::Deref { addr, .. } => has_side_effects(addr),
        ExprKind::Cast { expr, .. } => has_side_effects(expr),
        ExprKind::ArrayAccess { base, index, .. } => {
            has_side_effects(base) || has_side_effects(index)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => has_side_effects(cond) || has_side_effects(then_expr) || has_side_effects(else_expr),
        _ => false,
    }
}

/// Removes immediately consecutive overwrites to the same lvalue.
///
/// Example:
/// `x = 1; x = 2;` -> `x = 2;`
/// `*p = a; *p = b;` -> `*p = b;`
///
/// This is conservative: we only remove the earlier store when the two writes
/// are adjacent and the earlier RHS has no side effects.
fn eliminate_consecutive_overwrites(statements: Vec<Expr>) -> Vec<Expr> {
    if statements.len() < 2 {
        return statements;
    }

    let mut out: Vec<Expr> = Vec::with_capacity(statements.len());
    let mut i = 0usize;
    while i < statements.len() {
        if i + 1 < statements.len() {
            let cur = &statements[i];
            let next = &statements[i + 1];
            if let (
                ExprKind::Assign {
                    lhs: lhs_a,
                    rhs: rhs_a,
                },
                ExprKind::Assign { lhs: lhs_b, .. },
            ) = (&cur.kind, &next.kind)
            {
                if exprs_equivalent_lvalue(lhs_a, lhs_b) && !has_side_effects(rhs_a) {
                    // Skip current write; it's immediately overwritten.
                    i += 1;
                    continue;
                }
            }
        }
        out.push(statements[i].clone());
        i += 1;
    }
    out
}

/// Structural lvalue equivalence for store overwrite checks.
fn exprs_equivalent_lvalue(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(va), ExprKind::Var(vb)) => va.name == vb.name,
        // Unknown expressions are treated as variables with the given name
        (ExprKind::Unknown(na), ExprKind::Unknown(nb)) => na == nb,
        // Cross-comparison between Var and Unknown (they can represent the same lvalue)
        (ExprKind::Var(v), ExprKind::Unknown(n)) | (ExprKind::Unknown(n), ExprKind::Var(v)) => {
            v.name == *n
        }
        (ExprKind::Deref { addr: aa, size: sa }, ExprKind::Deref { addr: ab, size: sb }) => {
            sa == sb && exprs_equivalent_lvalue(aa, ab)
        }
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
        ) => ea == eb && exprs_equivalent_lvalue(ba, bb) && exprs_equivalent_lvalue(ia, ib),
        (
            ExprKind::FieldAccess {
                base: ba,
                offset: oa,
                ..
            },
            ExprKind::FieldAccess {
                base: bb,
                offset: ob,
                ..
            },
        ) => oa == ob && exprs_equivalent_lvalue(ba, bb),
        (ExprKind::IntLit(na), ExprKind::IntLit(nb)) => na == nb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{BinOpKind, VarKind, Variable};
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

    #[test]
    fn test_dead_store_elimination_basic() {
        // x = 5; y = x; return y; (both x and y are used, keep both assignments)
        let nodes = vec![
            StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![
                    make_assign("x", Expr::int(5)),
                    make_assign("y", make_var("x")),
                ],
                address_range: (0, 0),
            },
            StructuredNode::Return(Some(make_var("y"))),
        ];

        let result = eliminate_dead_stores(nodes);
        assert_eq!(result.len(), 2);
        if let StructuredNode::Block { statements, .. } = &result[0] {
            assert_eq!(statements.len(), 2);
        }
    }

    #[test]
    fn test_dead_store_elimination_removes_unused() {
        // temp = 5; y = 10; (temp is never used, remove it)
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_assign("temp", Expr::int(5)),
                make_assign("y", Expr::int(10)),
            ],
            address_range: (0, 0),
        }];

        let mut uses = HashSet::new();
        // Only y is used somewhere
        uses.insert("y".to_string());

        let result = eliminate_in_nodes(nodes, &uses);
        assert_eq!(result.len(), 1);
        if let StructuredNode::Block { statements, .. } = &result[0] {
            // temp assignment should be removed
            assert_eq!(statements.len(), 1);
        }
    }

    #[test]
    fn test_dead_store_preserves_calls() {
        // temp = func(); (has side effects, keep it)
        let call_expr = Expr::call(
            super::super::expression::CallTarget::Named("func".to_string()),
            vec![],
        );
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![make_assign("temp", call_expr)],
            address_range: (0, 0),
        }];

        let uses = HashSet::new(); // temp is not used

        let result = eliminate_in_nodes(nodes, &uses);
        assert_eq!(result.len(), 1);
        if let StructuredNode::Block { statements, .. } = &result[0] {
            // Should keep the call even though temp is unused
            assert_eq!(statements.len(), 1);
        }
    }

    #[test]
    fn test_collect_uses() {
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_assign("x", Expr::int(5)),
                make_assign(
                    "y",
                    Expr::binop(BinOpKind::Add, make_var("x"), make_var("z")),
                ),
            ],
            address_range: (0, 0),
        }];

        let mut uses = HashSet::new();
        collect_all_uses(&nodes, &mut uses);

        assert!(uses.contains("x")); // Used in rhs of y assignment
        assert!(uses.contains("z")); // Used in rhs of y assignment
        assert!(!uses.contains("y")); // Only assigned, not used
    }

    fn make_unknown_assign(lhs: &str, rhs: Expr) -> Expr {
        Expr::assign(Expr::unknown(lhs), rhs)
    }

    #[test]
    fn test_eliminate_consecutive_overwrites_unknown() {
        // Test that Unknown expressions work for consecutive overwrite detection
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_unknown_assign("idx", Expr::int(2)),
                make_unknown_assign("idx", Expr::int(4)),
                make_unknown_assign("result", Expr::unknown("idx")),
            ],
            address_range: (0, 0),
        }];

        let mut uses = HashSet::new();
        uses.insert("idx".to_string());
        uses.insert("result".to_string());
        let out = eliminate_in_nodes(nodes, &uses);
        if let StructuredNode::Block { statements, .. } = &out[0] {
            assert_eq!(
                statements.len(),
                2,
                "Should eliminate idx=2, keep idx=4 and result=idx"
            );
            // First remaining should be idx = 4
            if let ExprKind::Assign { rhs, .. } = &statements[0].kind {
                assert!(
                    matches!(rhs.kind, ExprKind::IntLit(4)),
                    "First assignment should be idx=4"
                );
            } else {
                panic!("expected assignment");
            }
        } else {
            panic!("expected block");
        }
    }

    #[test]
    fn test_eliminate_consecutive_overwrites_simple_var() {
        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_assign("x", Expr::int(1)),
                make_assign("x", Expr::int(2)),
                make_assign("y", make_var("x")),
            ],
            address_range: (0, 0),
        }];

        let mut uses = HashSet::new();
        uses.insert("x".to_string());
        uses.insert("y".to_string());
        let out = eliminate_in_nodes(nodes, &uses);
        if let StructuredNode::Block { statements, .. } = &out[0] {
            assert_eq!(statements.len(), 2);
            if let ExprKind::Assign { rhs, .. } = &statements[0].kind {
                assert!(matches!(rhs.kind, ExprKind::IntLit(2)));
            } else {
                panic!("expected assignment");
            }
        } else {
            panic!("expected block");
        }
    }
}
