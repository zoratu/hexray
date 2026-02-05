//! Constant folding and propagation.
//!
//! Evaluates constant expressions at compile time and propagates
//! known constant values through the code.

use std::collections::HashMap;

use super::expression::{BinOpKind, Expr, ExprKind, UnaryOpKind};
use super::structurer::StructuredNode;

/// Performs constant folding and propagation on structured nodes.
pub fn propagate_constants(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    let mut propagator = ConstantPropagator::new();
    propagator.propagate(nodes)
}

/// Constant propagator state.
struct ConstantPropagator {
    /// Known constant values for variables.
    constants: HashMap<String, i128>,
}

impl ConstantPropagator {
    fn new() -> Self {
        Self {
            constants: HashMap::new(),
        }
    }

    fn propagate(&mut self, nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
        nodes.into_iter().map(|n| self.propagate_node(n)).collect()
    }

    fn propagate_node(&mut self, node: StructuredNode) -> StructuredNode {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                let statements = statements
                    .into_iter()
                    .map(|e| self.propagate_expr(e))
                    .collect();
                StructuredNode::Block {
                    id,
                    statements,
                    address_range,
                }
            }

            StructuredNode::Expr(e) => StructuredNode::Expr(self.propagate_expr(e)),

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                let condition = self.propagate_expr(condition);

                // Check if condition is a constant
                if let Some(val) = self.try_eval(&condition) {
                    if val != 0 {
                        // Condition is always true, keep only then branch
                        return StructuredNode::Sequence(self.propagate(then_body));
                    } else if let Some(else_body) = else_body {
                        // Condition is always false, keep only else branch
                        return StructuredNode::Sequence(self.propagate(else_body));
                    } else {
                        // Condition is always false and no else, remove entirely
                        return StructuredNode::Sequence(vec![]);
                    }
                }

                // Save and restore constants around branches
                let saved = self.constants.clone();
                let then_body = self.propagate(then_body);
                self.constants = saved.clone();
                let else_body = else_body.map(|b| {
                    let result = self.propagate(b);
                    self.constants = saved.clone();
                    result
                });

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
                // Don't propagate constants into loops (they may change)
                let saved = self.constants.clone();
                self.invalidate_modified_vars(&body);

                let condition = self.propagate_expr(condition);
                let body = self.propagate(body);

                self.constants = saved;

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
                let saved = self.constants.clone();
                self.invalidate_modified_vars(&body);

                let body = self.propagate(body);
                let condition = self.propagate_expr(condition);

                self.constants = saved;

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
                let saved = self.constants.clone();

                let init = init.map(|e| self.propagate_expr(e));
                self.invalidate_modified_vars(&body);

                let condition = self.propagate_expr(condition);
                let update = update.map(|e| self.propagate_expr(e));
                let body = self.propagate(body);

                self.constants = saved;

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
                let saved = self.constants.clone();
                self.invalidate_modified_vars(&body);

                let body = self.propagate(body);

                self.constants = saved;

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
                let value = self.propagate_expr(value);

                // Check if switch value is constant
                if let Some(const_val) = self.try_eval(&value) {
                    // Find matching case
                    for (case_vals, case_body) in &cases {
                        if case_vals.contains(&const_val) {
                            return StructuredNode::Sequence(self.propagate(case_body.clone()));
                        }
                    }
                    // Fall through to default
                    if let Some(default) = default {
                        return StructuredNode::Sequence(self.propagate(default));
                    }
                    return StructuredNode::Sequence(vec![]);
                }

                let saved = self.constants.clone();
                let cases = cases
                    .into_iter()
                    .map(|(vals, body)| {
                        self.constants = saved.clone();
                        (vals, self.propagate(body))
                    })
                    .collect();
                let default = default.map(|d| {
                    self.constants = saved.clone();
                    self.propagate(d)
                });

                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                }
            }

            StructuredNode::Return(expr) => {
                StructuredNode::Return(expr.map(|e| self.propagate_expr(e)))
            }

            StructuredNode::Sequence(nodes) => StructuredNode::Sequence(self.propagate(nodes)),

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                let saved = self.constants.clone();
                let try_body = self.propagate(try_body);
                let catch_handlers = catch_handlers
                    .into_iter()
                    .map(|h| {
                        self.constants = saved.clone();
                        super::structurer::CatchHandler {
                            body: self.propagate(h.body),
                            ..h
                        }
                    })
                    .collect();

                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                }
            }

            // Pass through unchanged
            other => other,
        }
    }

    fn propagate_expr(&mut self, expr: Expr) -> Expr {
        let folded = self.fold_expr(expr);

        // Track constant assignments
        if let ExprKind::Assign { ref lhs, ref rhs } = folded.kind {
            if let ExprKind::Var(v) = &lhs.kind {
                if let Some(val) = self.try_eval(rhs) {
                    self.constants.insert(v.name.clone(), val);
                } else {
                    // Non-constant assignment invalidates the variable
                    self.constants.remove(&v.name);
                }
            }
        }

        folded
    }

    fn fold_expr(&self, expr: Expr) -> Expr {
        match expr.kind {
            ExprKind::Var(ref v) => {
                // Substitute known constants
                if let Some(&val) = self.constants.get(&v.name) {
                    return Expr::int(val);
                }
                expr
            }

            ExprKind::BinOp { op, left, right } => {
                let left = self.fold_expr(*left);
                let right = self.fold_expr(*right);

                // Try to evaluate constant binary operations
                if let (Some(l), Some(r)) = (self.try_eval(&left), self.try_eval(&right)) {
                    if let Some(result) = eval_binop(op, l, r) {
                        return Expr::int(result);
                    }
                }

                // Algebraic simplifications
                if let Some(simplified) = simplify_binop(op, &left, &right) {
                    return simplified;
                }

                Expr::binop(op, left, right)
            }

            ExprKind::UnaryOp { op, operand } => {
                let operand = self.fold_expr(*operand);

                // Try to evaluate constant unary operations
                if let Some(val) = self.try_eval(&operand) {
                    if let Some(result) = eval_unaryop(op, val) {
                        return Expr::int(result);
                    }
                }

                Expr::unary(op, operand)
            }

            ExprKind::Assign { lhs, rhs } => {
                let rhs = self.fold_expr(*rhs);
                Expr::assign(*lhs, rhs)
            }

            ExprKind::CompoundAssign { op, lhs, rhs } => {
                let rhs = self.fold_expr(*rhs);
                Expr {
                    kind: ExprKind::CompoundAssign {
                        op,
                        lhs,
                        rhs: Box::new(rhs),
                    },
                }
            }

            ExprKind::Call { target, args } => {
                let args = args.into_iter().map(|a| self.fold_expr(a)).collect();
                Expr::call(target, args)
            }

            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond = self.fold_expr(*cond);
                let then_expr = self.fold_expr(*then_expr);
                let else_expr = self.fold_expr(*else_expr);

                // Evaluate constant ternary
                if let Some(val) = self.try_eval(&cond) {
                    if val != 0 {
                        return then_expr;
                    } else {
                        return else_expr;
                    }
                }

                Expr {
                    kind: ExprKind::Conditional {
                        cond: Box::new(cond),
                        then_expr: Box::new(then_expr),
                        else_expr: Box::new(else_expr),
                    },
                }
            }

            ExprKind::Cast {
                expr,
                to_size,
                signed,
            } => {
                let expr = self.fold_expr(*expr);
                Expr {
                    kind: ExprKind::Cast {
                        expr: Box::new(expr),
                        to_size,
                        signed,
                    },
                }
            }

            ExprKind::Deref { addr, size } => {
                let addr = self.fold_expr(*addr);
                Expr::deref(addr, size)
            }

            ExprKind::AddressOf(inner) => {
                let inner = self.fold_expr(*inner);
                Expr::address_of(inner)
            }

            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                let base = self.fold_expr(*base);
                let index = self.fold_expr(*index);
                Expr::array_access(base, index, element_size)
            }

            ExprKind::FieldAccess {
                base,
                field_name,
                offset,
            } => {
                let base = self.fold_expr(*base);
                Expr::field_access(base, field_name, offset)
            }

            // Pass through unchanged
            _ => expr,
        }
    }

    fn try_eval(&self, expr: &Expr) -> Option<i128> {
        match &expr.kind {
            ExprKind::IntLit(val) => Some(*val),
            ExprKind::Var(v) => self.constants.get(&v.name).copied(),
            ExprKind::BinOp { op, left, right } => {
                let l = self.try_eval(left)?;
                let r = self.try_eval(right)?;
                eval_binop(*op, l, r)
            }
            ExprKind::UnaryOp { op, operand } => {
                let val = self.try_eval(operand)?;
                eval_unaryop(*op, val)
            }
            _ => None,
        }
    }

    fn invalidate_modified_vars(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            self.invalidate_in_node(node);
        }
    }

    fn invalidate_in_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.invalidate_in_expr(stmt);
                }
            }
            StructuredNode::Expr(e) => self.invalidate_in_expr(e),
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                self.invalidate_modified_vars(then_body);
                if let Some(else_body) = else_body {
                    self.invalidate_modified_vars(else_body);
                }
            }
            StructuredNode::While { body, .. }
            | StructuredNode::DoWhile { body, .. }
            | StructuredNode::Loop { body, .. }
            | StructuredNode::For { body, .. } => {
                self.invalidate_modified_vars(body);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, body) in cases {
                    self.invalidate_modified_vars(body);
                }
                if let Some(default) = default {
                    self.invalidate_modified_vars(default);
                }
            }
            StructuredNode::Sequence(nodes) => {
                self.invalidate_modified_vars(nodes);
            }
            _ => {}
        }
    }

    fn invalidate_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, .. } | ExprKind::CompoundAssign { lhs, .. } => {
                if let ExprKind::Var(v) = &lhs.kind {
                    self.constants.remove(&v.name);
                }
            }
            ExprKind::UnaryOp { operand, .. } => {
                if let ExprKind::Var(v) = &operand.kind {
                    self.constants.remove(&v.name);
                }
            }
            ExprKind::Call { args, .. } => {
                // Function calls may modify variables through pointers
                // Be conservative and invalidate all
                self.constants.clear();
                let _ = args;
            }
            _ => {}
        }
    }
}

/// Evaluates a binary operation on constants.
fn eval_binop(op: BinOpKind, left: i128, right: i128) -> Option<i128> {
    match op {
        BinOpKind::Add => Some(left.wrapping_add(right)),
        BinOpKind::Sub => Some(left.wrapping_sub(right)),
        BinOpKind::Mul => Some(left.wrapping_mul(right)),
        BinOpKind::Div if right != 0 => Some(left / right),
        BinOpKind::Mod if right != 0 => Some(left % right),
        BinOpKind::And => Some(left & right),
        BinOpKind::Or => Some(left | right),
        BinOpKind::Xor => Some(left ^ right),
        BinOpKind::Shl => Some(left << (right as u32)),
        BinOpKind::Shr => Some(left >> (right as u32)),
        BinOpKind::Eq => Some(if left == right { 1 } else { 0 }),
        BinOpKind::Ne => Some(if left != right { 1 } else { 0 }),
        BinOpKind::Lt => Some(if left < right { 1 } else { 0 }),
        BinOpKind::Le => Some(if left <= right { 1 } else { 0 }),
        BinOpKind::Gt => Some(if left > right { 1 } else { 0 }),
        BinOpKind::Ge => Some(if left >= right { 1 } else { 0 }),
        BinOpKind::LogicalAnd => Some(if left != 0 && right != 0 { 1 } else { 0 }),
        BinOpKind::LogicalOr => Some(if left != 0 || right != 0 { 1 } else { 0 }),
        _ => None,
    }
}

/// Evaluates a unary operation on a constant.
fn eval_unaryop(op: UnaryOpKind, val: i128) -> Option<i128> {
    match op {
        UnaryOpKind::Neg => Some(-val),
        UnaryOpKind::LogicalNot => Some(if val == 0 { 1 } else { 0 }),
        UnaryOpKind::Not => Some(!val),
        _ => None,
    }
}

/// Algebraic simplifications for binary operations.
fn simplify_binop(op: BinOpKind, left: &Expr, right: &Expr) -> Option<Expr> {
    let left_zero = matches!(&left.kind, ExprKind::IntLit(0));
    let right_zero = matches!(&right.kind, ExprKind::IntLit(0));
    let left_one = matches!(&left.kind, ExprKind::IntLit(1));
    let right_one = matches!(&right.kind, ExprKind::IntLit(1));

    match op {
        // x + 0 = x, 0 + x = x
        BinOpKind::Add if right_zero => Some(left.clone()),
        BinOpKind::Add if left_zero => Some(right.clone()),

        // x - 0 = x
        BinOpKind::Sub if right_zero => Some(left.clone()),

        // x * 0 = 0, 0 * x = 0
        BinOpKind::Mul if left_zero || right_zero => Some(Expr::int(0)),

        // x * 1 = x, 1 * x = x
        BinOpKind::Mul if right_one => Some(left.clone()),
        BinOpKind::Mul if left_one => Some(right.clone()),

        // x / 1 = x
        BinOpKind::Div if right_one => Some(left.clone()),

        // x & 0 = 0, 0 & x = 0
        BinOpKind::And if left_zero || right_zero => Some(Expr::int(0)),

        // x | 0 = x, 0 | x = x
        BinOpKind::Or if right_zero => Some(left.clone()),
        BinOpKind::Or if left_zero => Some(right.clone()),

        // x ^ 0 = x, 0 ^ x = x
        BinOpKind::Xor if right_zero => Some(left.clone()),
        BinOpKind::Xor if left_zero => Some(right.clone()),

        // x << 0 = x
        BinOpKind::Shl if right_zero => Some(left.clone()),

        // x >> 0 = x
        BinOpKind::Shr if right_zero => Some(left.clone()),

        // x && 0 = 0
        BinOpKind::LogicalAnd if right_zero => Some(Expr::int(0)),
        BinOpKind::LogicalAnd if left_zero => Some(Expr::int(0)),

        // x || 1 = 1
        BinOpKind::LogicalOr if right_one => Some(Expr::int(1)),
        BinOpKind::LogicalOr if left_one => Some(Expr::int(1)),

        // x || 0 = x, 0 || x = x (as boolean)
        BinOpKind::LogicalOr if right_zero => Some(left.clone()),
        BinOpKind::LogicalOr if left_zero => Some(right.clone()),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            name: name.to_string(),
            kind: VarKind::Register(0),
            size: 8,
        })
    }

    #[test]
    fn test_constant_folding() {
        let prop = ConstantPropagator::new();

        // 2 + 3 = 5
        let expr = Expr::binop(BinOpKind::Add, Expr::int(2), Expr::int(3));
        let folded = prop.fold_expr(expr);
        assert!(matches!(folded.kind, ExprKind::IntLit(5)));

        // 10 * 5 = 50
        let expr = Expr::binop(BinOpKind::Mul, Expr::int(10), Expr::int(5));
        let folded = prop.fold_expr(expr);
        assert!(matches!(folded.kind, ExprKind::IntLit(50)));
    }

    #[test]
    fn test_constant_propagation() {
        let mut prop = ConstantPropagator::new();

        // x = 5
        let assign = Expr::assign(make_var("x"), Expr::int(5));
        prop.propagate_expr(assign);

        // x should be known as 5
        assert_eq!(prop.constants.get("x"), Some(&5));

        // x + 3 should fold to 8
        let expr = Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(3));
        let folded = prop.fold_expr(expr);
        assert!(matches!(folded.kind, ExprKind::IntLit(8)));
    }

    #[test]
    fn test_algebraic_simplification() {
        // x + 0 = x
        let result = simplify_binop(BinOpKind::Add, &make_var("x"), &Expr::int(0));
        assert!(result.is_some());

        // x * 1 = x
        let result = simplify_binop(BinOpKind::Mul, &make_var("x"), &Expr::int(1));
        assert!(result.is_some());

        // x * 0 = 0
        let result = simplify_binop(BinOpKind::Mul, &make_var("x"), &Expr::int(0));
        assert!(matches!(result, Some(e) if matches!(e.kind, ExprKind::IntLit(0))));
    }

    #[test]
    fn test_constant_conditional() {
        let prop = ConstantPropagator::new();

        // true ? 10 : 20 = 10
        let cond = Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(Expr::int(1)),
                then_expr: Box::new(Expr::int(10)),
                else_expr: Box::new(Expr::int(20)),
            },
        };
        let folded = prop.fold_expr(cond);
        assert!(matches!(folded.kind, ExprKind::IntLit(10)));

        // false ? 10 : 20 = 20
        let cond = Expr {
            kind: ExprKind::Conditional {
                cond: Box::new(Expr::int(0)),
                then_expr: Box::new(Expr::int(10)),
                else_expr: Box::new(Expr::int(20)),
            },
        };
        let folded = prop.fold_expr(cond);
        assert!(matches!(folded.kind, ExprKind::IntLit(20)));
    }
}
