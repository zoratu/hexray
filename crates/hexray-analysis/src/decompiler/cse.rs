//! Common Subexpression Elimination (CSE).
//!
//! Identifies and eliminates redundant computations by replacing duplicate
//! expressions with references to previously computed values.
//!
//! Example transformation:
//! ```text
//! arg3 = a | b | c;
//! arg1 = a | b | c;
//! ```
//! Becomes:
//! ```text
//! arg3 = a | b | c;
//! arg1 = arg3;
//! ```

use std::collections::HashMap;

use super::expression::{BinOpKind, Expr, ExprKind, UnaryOpKind, VarKind, Variable};
use super::structurer::{CatchHandler, StructuredNode};

/// Performs common subexpression elimination on structured nodes.
pub fn eliminate_common_subexpressions(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut cse = CsePass::new();
    cse.process_nodes(nodes)
}

/// CSE pass state.
struct CsePass {
    /// Maps expression hashes to the variable that holds the computed value.
    /// We only cache expressions that were assigned to a named variable.
    expr_cache: HashMap<ExprKey, String>,
}

/// A key for identifying equivalent expressions.
/// Uses a structural hash that captures the expression tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ExprKey {
    Var(String),
    Int(i128),
    BinOp {
        op: BinOpKind,
        left: Box<ExprKey>,
        right: Box<ExprKey>,
    },
    UnaryOp {
        op: UnaryOpKind,
        operand: Box<ExprKey>,
    },
    Deref {
        addr: Box<ExprKey>,
        size: u8,
    },
    ArrayAccess {
        base: Box<ExprKey>,
        index: Box<ExprKey>,
        element_size: usize,
    },
    FieldAccess {
        base: Box<ExprKey>,
        offset: usize,
    },
    GotRef {
        address: u64,
        size: u8,
    },
    Cast {
        expr: Box<ExprKey>,
        to_size: u8,
        signed: bool,
    },
    Unknown(String),
    /// Expression that cannot be cached (calls, phi nodes, etc.)
    NonCacheable,
}

impl CsePass {
    fn new() -> Self {
        Self {
            expr_cache: HashMap::new(),
        }
    }

    /// Process a list of nodes, applying CSE.
    fn process_nodes(&mut self, nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
        // First pass: apply CSE within blocks
        let nodes: Vec<_> = nodes
            .into_iter()
            .map(|node| self.process_node(node))
            .collect();

        // Second pass: eliminate consecutive expression nodes with same RHS
        eliminate_consecutive_duplicate_exprs(nodes)
    }

    /// Process a single node.
    fn process_node(&mut self, node: StructuredNode) -> StructuredNode {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                let statements = self.process_statements(statements);
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                }
            }
            StructuredNode::Expr(expr) => {
                let expr = self.process_expr(expr);
                StructuredNode::Expr(expr)
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Process condition but don't cache across branches
                // (branches may not both execute)
                let condition = self.try_replace_with_cached(condition);

                // Process branches with separate caches
                let saved_cache = self.expr_cache.clone();
                let then_body = self.process_nodes(then_body);

                self.expr_cache = saved_cache.clone();
                let else_body = else_body.map(|e| self.process_nodes(e));

                // After if-else, only keep expressions that are available in both branches
                // For simplicity, clear the cache after conditionals
                self.expr_cache = saved_cache;

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
                exit_block,
            } => {
                // Don't cache across loop iterations
                let saved_cache = self.expr_cache.clone();
                let condition = self.try_replace_with_cached(condition);
                let body = self.process_nodes(body);
                self.expr_cache = saved_cache;

                StructuredNode::While {
                    condition,
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
                let saved_cache = self.expr_cache.clone();
                let body = self.process_nodes(body);
                let condition = self.try_replace_with_cached(condition);
                self.expr_cache = saved_cache;

                StructuredNode::DoWhile {
                    body,
                    condition,
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
                let init = init.map(|e| self.process_expr(e));
                let saved_cache = self.expr_cache.clone();
                let condition = self.try_replace_with_cached(condition);
                let body = self.process_nodes(body);
                let update = update.map(|e| self.process_expr(e));
                self.expr_cache = saved_cache;

                StructuredNode::For {
                    init,
                    condition,
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
            } => {
                let saved_cache = self.expr_cache.clone();
                let body = self.process_nodes(body);
                self.expr_cache = saved_cache;

                StructuredNode::Loop {
                    body,
                    header,
                    exit_block,
                }
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                let value = self.try_replace_with_cached(value);
                let saved_cache = self.expr_cache.clone();

                let cases: Vec<_> = cases
                    .into_iter()
                    .map(|(vals, body)| {
                        self.expr_cache = saved_cache.clone();
                        (vals, self.process_nodes(body))
                    })
                    .collect();

                self.expr_cache = saved_cache.clone();
                let default = default.map(|d| self.process_nodes(d));

                self.expr_cache = saved_cache;

                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                }
            }
            StructuredNode::Sequence(nodes) => StructuredNode::Sequence(self.process_nodes(nodes)),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                let saved_cache = self.expr_cache.clone();
                let try_body = self.process_nodes(try_body);

                let catch_handlers: Vec<_> = catch_handlers
                    .into_iter()
                    .map(|h| {
                        self.expr_cache = saved_cache.clone();
                        CatchHandler {
                            body: self.process_nodes(h.body),
                            ..h
                        }
                    })
                    .collect();

                self.expr_cache = saved_cache;

                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                }
            }
            // Pass through nodes that don't contain expressions to process
            other => other,
        }
    }

    /// Process statements within a block.
    fn process_statements(&mut self, statements: Vec<Expr>) -> Vec<Expr> {
        statements
            .into_iter()
            .map(|stmt| self.process_expr(stmt))
            .collect()
    }

    /// Process an expression, potentially replacing it with a cached value.
    fn process_expr(&mut self, expr: Expr) -> Expr {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                // Try to replace RHS with cached value
                let new_rhs = self.try_replace_with_cached((**rhs).clone());

                // If LHS is a simple variable, cache this expression
                if let ExprKind::Var(v) = &lhs.kind {
                    if is_cacheable_lhs(&v.name) {
                        let key = expr_to_key(&new_rhs);
                        if !matches!(key, ExprKey::NonCacheable) {
                            // Only cache non-trivial expressions
                            if is_worth_caching(&key) {
                                self.expr_cache.insert(key, v.name.clone());
                            }
                        }
                    }
                }

                Expr::assign((**lhs).clone(), new_rhs)
            }
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                let new_rhs = self.try_replace_with_cached((**rhs).clone());
                // Compound assignments invalidate cached value of lhs
                if let ExprKind::Var(v) = &lhs.kind {
                    self.invalidate_var(&v.name);
                }
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op: *op,
                        lhs: lhs.clone(),
                        rhs: Box::new(new_rhs),
                    },
                }
            }
            _ => {
                // For other expressions (calls, etc.), just return as-is
                // We don't try to replace subexpressions within calls
                expr
            }
        }
    }

    /// Try to replace an expression with a cached variable reference.
    fn try_replace_with_cached(&self, expr: Expr) -> Expr {
        let key = expr_to_key(&expr);
        if matches!(key, ExprKey::NonCacheable) {
            return expr;
        }

        // Don't replace trivial expressions (single variables, literals)
        if !is_worth_caching(&key) {
            return expr;
        }

        if let Some(var_name) = self.expr_cache.get(&key) {
            // Return a reference to the cached variable
            Expr::var(Variable {
                name: var_name.clone(),
                kind: VarKind::Register(0),
                size: 8, // Default size
            })
        } else {
            expr
        }
    }

    /// Invalidate any cached expressions that depend on a variable.
    fn invalidate_var(&mut self, var_name: &str) {
        // Remove any cached expression that was stored in this variable
        self.expr_cache.retain(|_, v| v != var_name);
    }
}

/// Convert an expression to a hashable key.
fn expr_to_key(expr: &Expr) -> ExprKey {
    match &expr.kind {
        ExprKind::Var(v) => ExprKey::Var(v.name.clone()),
        ExprKind::IntLit(n) => ExprKey::Int(*n),
        ExprKind::BinOp { op, left, right } => ExprKey::BinOp {
            op: *op,
            left: Box::new(expr_to_key(left)),
            right: Box::new(expr_to_key(right)),
        },
        ExprKind::UnaryOp { op, operand } => ExprKey::UnaryOp {
            op: *op,
            operand: Box::new(expr_to_key(operand)),
        },
        ExprKind::Deref { addr, size } => ExprKey::Deref {
            addr: Box::new(expr_to_key(addr)),
            size: *size,
        },
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => ExprKey::ArrayAccess {
            base: Box::new(expr_to_key(base)),
            index: Box::new(expr_to_key(index)),
            element_size: *element_size,
        },
        ExprKind::FieldAccess { base, offset, .. } => ExprKey::FieldAccess {
            base: Box::new(expr_to_key(base)),
            offset: *offset,
        },
        ExprKind::GotRef {
            address,
            size,
            is_deref,
            ..
        } => {
            if *is_deref {
                ExprKey::GotRef {
                    address: *address,
                    size: *size,
                }
            } else {
                // LEA - address itself
                ExprKey::GotRef {
                    address: *address,
                    size: 0,
                }
            }
        }
        ExprKind::Cast {
            expr,
            to_size,
            signed,
        } => ExprKey::Cast {
            expr: Box::new(expr_to_key(expr)),
            to_size: *to_size,
            signed: *signed,
        },
        ExprKind::Unknown(s) => ExprKey::Unknown(s.clone()),
        // Don't cache calls, assignments, conditionals, phi nodes, etc.
        ExprKind::Call { .. }
        | ExprKind::Assign { .. }
        | ExprKind::CompoundAssign { .. }
        | ExprKind::Conditional { .. }
        | ExprKind::BitField { .. }
        | ExprKind::Phi(_)
        | ExprKind::AddressOf(_) => ExprKey::NonCacheable,
    }
}

/// Check if an expression is worth caching (non-trivial).
fn is_worth_caching(key: &ExprKey) -> bool {
    match key {
        // Don't cache simple values
        ExprKey::Var(_) | ExprKey::Int(_) | ExprKey::Unknown(_) => false,
        // Cache binary operations (especially useful for long OR/AND chains)
        ExprKey::BinOp { .. } => true,
        // Cache unary operations
        ExprKey::UnaryOp { .. } => true,
        // Cache memory accesses
        ExprKey::Deref { .. } | ExprKey::ArrayAccess { .. } | ExprKey::FieldAccess { .. } => true,
        // Cache GOT references
        ExprKey::GotRef { .. } => true,
        // Cache casts of non-trivial expressions
        ExprKey::Cast { expr, .. } => is_worth_caching(expr),
        // Never cache non-cacheable
        ExprKey::NonCacheable => false,
    }
}

/// Check if a variable name is suitable for caching.
fn is_cacheable_lhs(name: &str) -> bool {
    // Cache results stored in argument registers and named variables
    // Don't cache to result/return registers (they may be overwritten)
    !matches!(
        name.to_lowercase().as_str(),
        "rax" | "eax" | "ax" | "al" | "result" | "ret"
    )
}

/// Eliminate consecutive Expr nodes that assign the same RHS to different variables.
fn eliminate_consecutive_duplicate_exprs(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    if nodes.len() < 2 {
        return nodes;
    }

    let mut result = Vec::with_capacity(nodes.len());
    let mut i = 0;

    while i < nodes.len() {
        // Look for consecutive Expr nodes with the same RHS
        if let StructuredNode::Expr(first_expr) = &nodes[i] {
            if let ExprKind::Assign {
                lhs: first_lhs,
                rhs: first_rhs,
            } = &first_expr.kind
            {
                // Check if the first assignment is to a variable we can reference
                if let ExprKind::Var(first_var) = &first_lhs.kind {
                    let first_key = expr_to_key(first_rhs);
                    if is_worth_caching(&first_key) {
                        // Look ahead for consecutive assignments with the same RHS
                        let mut j = i + 1;
                        let mut modified_nodes = vec![nodes[i].clone()];

                        while j < nodes.len() {
                            if let StructuredNode::Expr(next_expr) = &nodes[j] {
                                if let ExprKind::Assign {
                                    lhs: next_lhs,
                                    rhs: next_rhs,
                                } = &next_expr.kind
                                {
                                    let next_key = expr_to_key(next_rhs);
                                    if first_key == next_key {
                                        // Replace RHS with reference to first variable
                                        let new_rhs = Expr::var(Variable {
                                            name: first_var.name.clone(),
                                            kind: first_var.kind.clone(),
                                            size: first_var.size,
                                        });
                                        let new_assign =
                                            Expr::assign((**next_lhs).clone(), new_rhs);
                                        modified_nodes.push(StructuredNode::Expr(new_assign));
                                        j += 1;
                                        continue;
                                    }
                                }
                            }
                            break;
                        }

                        if modified_nodes.len() > 1 {
                            // We found and replaced some duplicates
                            result.extend(modified_nodes);
                            i = j;
                            continue;
                        }
                    }
                }
            }
        }

        // No optimization applied, keep the original node
        result.push(nodes[i].clone());
        i += 1;
    }

    result
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

    fn make_assign(lhs: &str, rhs: Expr) -> Expr {
        Expr::assign(make_var(lhs), rhs)
    }

    #[test]
    fn test_cse_consecutive_identical_rhs() {
        // arg3 = a | b; arg1 = a | b; -> arg3 = a | b; arg1 = arg3;
        let or_expr = Expr::binop(BinOpKind::Or, make_var("a"), make_var("b"));

        let nodes = vec![
            StructuredNode::Expr(make_assign("arg3", or_expr.clone())),
            StructuredNode::Expr(make_assign("arg1", or_expr)),
        ];

        let result = eliminate_common_subexpressions(nodes);

        assert_eq!(result.len(), 2);

        // Second assignment should now reference arg3
        if let StructuredNode::Expr(expr) = &result[1] {
            if let ExprKind::Assign { rhs, .. } = &expr.kind {
                if let ExprKind::Var(v) = &rhs.kind {
                    assert_eq!(v.name, "arg3");
                } else {
                    panic!("Expected variable reference, got: {:?}", rhs);
                }
            } else {
                panic!("Expected assignment");
            }
        } else {
            panic!("Expected Expr node");
        }
    }

    #[test]
    fn test_cse_no_change_for_different_rhs() {
        // arg3 = a | b; arg1 = c | d; -> no change
        let nodes = vec![
            StructuredNode::Expr(make_assign(
                "arg3",
                Expr::binop(BinOpKind::Or, make_var("a"), make_var("b")),
            )),
            StructuredNode::Expr(make_assign(
                "arg1",
                Expr::binop(BinOpKind::Or, make_var("c"), make_var("d")),
            )),
        ];

        let result = eliminate_common_subexpressions(nodes.clone());

        // Should be unchanged
        assert_eq!(result.len(), 2);
        if let StructuredNode::Expr(expr) = &result[1] {
            if let ExprKind::Assign { rhs, .. } = &expr.kind {
                // RHS should still be c | d, not a variable reference
                assert!(matches!(rhs.kind, ExprKind::BinOp { .. }));
            }
        }
    }

    #[test]
    fn test_cse_trivial_not_cached() {
        // x = a; y = a; -> no change (simple variable assignment not worth caching)
        let nodes = vec![
            StructuredNode::Expr(make_assign("x", make_var("a"))),
            StructuredNode::Expr(make_assign("y", make_var("a"))),
        ];

        let result = eliminate_common_subexpressions(nodes);

        // Should be unchanged - trivial assignments shouldn't be CSE'd
        assert_eq!(result.len(), 2);
        if let StructuredNode::Expr(expr) = &result[1] {
            if let ExprKind::Assign { rhs, .. } = &expr.kind {
                if let ExprKind::Var(v) = &rhs.kind {
                    assert_eq!(v.name, "a"); // Still references 'a', not 'x'
                }
            }
        }
    }

    #[test]
    fn test_cse_in_block() {
        // Block with multiple statements
        let or_expr = Expr::binop(BinOpKind::Or, make_var("a"), make_var("b"));

        let nodes = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                make_assign("arg3", or_expr.clone()),
                make_assign("arg1", or_expr),
            ],
            address_range: (0, 0),
        }];

        let result = eliminate_common_subexpressions(nodes);

        assert_eq!(result.len(), 1);
        if let StructuredNode::Block { statements, .. } = &result[0] {
            assert_eq!(statements.len(), 2);
            // Second statement should reference arg3
            if let ExprKind::Assign { rhs, .. } = &statements[1].kind {
                if let ExprKind::Var(v) = &rhs.kind {
                    assert_eq!(v.name, "arg3");
                } else {
                    panic!("Expected variable reference");
                }
            }
        }
    }

    #[test]
    fn test_cse_complex_or_chain() {
        // Test the exact pattern from the cat binary
        // arg3 = a | b | c | d | e | f;
        // arg1 = a | b | c | d | e | f;
        let chain = Expr::binop(
            BinOpKind::Or,
            Expr::binop(
                BinOpKind::Or,
                Expr::binop(
                    BinOpKind::Or,
                    Expr::binop(
                        BinOpKind::Or,
                        Expr::binop(BinOpKind::Or, make_var("a"), make_var("b")),
                        make_var("c"),
                    ),
                    make_var("d"),
                ),
                make_var("e"),
            ),
            make_var("f"),
        );

        let nodes = vec![
            StructuredNode::Expr(make_assign("arg3", chain.clone())),
            StructuredNode::Expr(make_assign("arg1", chain)),
        ];

        let result = eliminate_common_subexpressions(nodes);

        assert_eq!(result.len(), 2);

        // First should be the full expression
        if let StructuredNode::Expr(expr) = &result[0] {
            if let ExprKind::Assign { rhs, .. } = &expr.kind {
                assert!(matches!(rhs.kind, ExprKind::BinOp { .. }));
            }
        }

        // Second should reference arg3
        if let StructuredNode::Expr(expr) = &result[1] {
            if let ExprKind::Assign { rhs, .. } = &expr.kind {
                if let ExprKind::Var(v) = &rhs.kind {
                    assert_eq!(v.name, "arg3");
                } else {
                    panic!("Expected variable reference, got: {:?}", rhs);
                }
            }
        }
    }

    #[test]
    fn test_expr_key_equality() {
        let expr1 = Expr::binop(BinOpKind::Or, make_var("a"), make_var("b"));
        let expr2 = Expr::binop(BinOpKind::Or, make_var("a"), make_var("b"));
        let expr3 = Expr::binop(BinOpKind::Or, make_var("a"), make_var("c"));

        let key1 = expr_to_key(&expr1);
        let key2 = expr_to_key(&expr2);
        let key3 = expr_to_key(&expr3);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
