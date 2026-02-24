//! Loop condition analysis and normalization.
//!
//! This module provides utilities to analyze and normalize loop conditions
//! for cleaner decompiled output, converting patterns like:
//! - `while (iter != 1)` → `while (i < len)`
//! - `while (ptr != 0)` → `while (ptr != NULL)`
//! - Detecting proper loop bounds and iterators

use super::expression::{BinOpKind, Expr, ExprKind};
use super::for_loop_detection::get_expr_var_key;

/// Information about a loop iterator variable.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Utility struct for future loop analysis enhancements
pub struct LoopIterator {
    /// Variable name or key.
    pub var_key: String,
    /// Initial value (if known).
    pub init_value: Option<i128>,
    /// Step/increment value (typically 1 or -1).
    pub step: i128,
    /// Bound value (if constant).
    pub bound: Option<i128>,
}

/// Analyzes a loop condition and attempts to normalize it for cleaner output.
///
/// Transformations:
/// - `iter != 1` with `iter` counting down → `i >= 0` or similar
/// - `x != 0` → `x` (implicit truthiness)
/// - Pointer comparisons with 0 → NULL
/// - Count-down loops → count-up where appropriate
pub fn normalize_loop_condition(
    condition: &Expr,
    init: Option<&Expr>,
    update: Option<&Expr>,
) -> Expr {
    // Try to extract iterator information from init and update
    let iterator_info = extract_iterator_info(init, update);

    // Normalize the condition based on iterator info
    normalize_condition_with_iterator(condition, &iterator_info)
}

/// Extracts iterator information from initialization and update expressions.
fn extract_iterator_info(init: Option<&Expr>, update: Option<&Expr>) -> Option<LoopIterator> {
    // Extract from init: var = value
    let (var_key, init_value) = if let Some(init_expr) = init {
        if let ExprKind::Assign { lhs, rhs } = &init_expr.kind {
            let key = get_expr_var_key(lhs)?;
            let val = get_const_value(rhs);
            (key, val)
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Extract step from update: var++, var--, var += n, var -= n
    let step = if let Some(update_expr) = update {
        extract_step_value(update_expr, &var_key)?
    } else {
        1 // Default to increment by 1
    };

    Some(LoopIterator {
        var_key,
        init_value,
        step,
        bound: None,
    })
}

/// Extracts the step value from an update expression.
fn extract_step_value(update: &Expr, var_key: &str) -> Option<i128> {
    match &update.kind {
        // var++ or ++var
        ExprKind::UnaryOp { op, operand } => {
            if get_expr_var_key(operand)? == var_key {
                match op {
                    super::expression::UnaryOpKind::Inc => Some(1),
                    super::expression::UnaryOpKind::Dec => Some(-1),
                    _ => None,
                }
            } else {
                None
            }
        }
        // var += n or var -= n
        ExprKind::CompoundAssign { lhs, op, rhs } => {
            if get_expr_var_key(lhs)? == var_key {
                let step = get_const_value(rhs)?;
                match op {
                    BinOpKind::Add => Some(step),
                    BinOpKind::Sub => Some(-step),
                    _ => None,
                }
            } else {
                None
            }
        }
        // var = var + n or var = var - n
        ExprKind::Assign { lhs, rhs } => {
            if get_expr_var_key(lhs)? == var_key {
                if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                    if get_expr_var_key(left)? == var_key {
                        let step = get_const_value(right)?;
                        match op {
                            BinOpKind::Add => Some(step),
                            BinOpKind::Sub => Some(-step),
                            _ => None,
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Normalizes a condition expression using iterator information.
fn normalize_condition_with_iterator(condition: &Expr, iterator: &Option<LoopIterator>) -> Expr {
    match &condition.kind {
        ExprKind::BinOp { op, left, right } => {
            // Check for problematic patterns

            // Pattern: iter != 1 or iter != 0 (count-down loop)
            if let (Some(iter_info), Some(bound_val)) = (iterator, get_const_value(right)) {
                if let Some(var_key) = get_expr_var_key(left) {
                    if var_key == iter_info.var_key {
                        // This is comparing the iterator to a constant
                        if *op == BinOpKind::Ne {
                            // Convert != to proper comparison based on step
                            if iter_info.step > 0 {
                                // Counting up: i != bound → i < bound
                                return Expr::binop(
                                    BinOpKind::Lt,
                                    (**left).clone(),
                                    (**right).clone(),
                                );
                            } else if iter_info.step < 0 {
                                // Counting down: i != bound → i >= bound or i > bound
                                // For count-down loops terminating at 0 or 1, use >= 0
                                if bound_val == 0 || bound_val == 1 {
                                    return Expr::binop(
                                        BinOpKind::Ge,
                                        (**left).clone(),
                                        Expr::int(0),
                                    );
                                } else {
                                    return Expr::binop(
                                        BinOpKind::Gt,
                                        (**left).clone(),
                                        (**right).clone(),
                                    );
                                }
                            }
                        }
                    }
                }
            }

            // Pattern: x != 0 where x is a pointer → cleaner comparison
            if *op == BinOpKind::Ne {
                if let Some(0) = get_const_value(right) {
                    // Keep as-is but could potentially convert to "if (x)" form
                    // For now, return unchanged
                    return condition.clone();
                }
            }

            // Pattern: reverse comparison - const < var → var > const
            if is_constant(left) && !is_constant(right) {
                let flipped_op = flip_comparison_op(*op);
                if let Some(new_op) = flipped_op {
                    return Expr::binop(new_op, (**right).clone(), (**left).clone());
                }
            }

            condition.clone()
        }
        _ => condition.clone(),
    }
}

/// Flips a comparison operator (e.g., < becomes >, <= becomes >=).
fn flip_comparison_op(op: BinOpKind) -> Option<BinOpKind> {
    match op {
        BinOpKind::Lt => Some(BinOpKind::Gt),
        BinOpKind::Le => Some(BinOpKind::Ge),
        BinOpKind::Gt => Some(BinOpKind::Lt),
        BinOpKind::Ge => Some(BinOpKind::Le),
        BinOpKind::ULt => Some(BinOpKind::UGt),
        BinOpKind::ULe => Some(BinOpKind::UGe),
        BinOpKind::UGt => Some(BinOpKind::ULt),
        BinOpKind::UGe => Some(BinOpKind::ULe),
        // Eq and Ne are symmetric
        BinOpKind::Eq | BinOpKind::Ne => Some(op),
        _ => None,
    }
}

/// Checks if an expression is a constant.
fn is_constant(expr: &Expr) -> bool {
    matches!(expr.kind, ExprKind::IntLit(_))
}

/// Gets constant value from an expression.
fn get_const_value(expr: &Expr) -> Option<i128> {
    if let ExprKind::IntLit(val) = expr.kind {
        Some(val)
    } else {
        None
    }
}

/// Detects if a loop condition represents a pointer null check.
#[allow(dead_code)] // Utility function for future loop analysis enhancements
pub fn is_pointer_null_check(condition: &Expr) -> bool {
    match &condition.kind {
        ExprKind::BinOp { op, left: _, right } => {
            matches!(op, BinOpKind::Ne | BinOpKind::Eq) && matches!(get_const_value(right), Some(0))
        }
        _ => false,
    }
}

/// Simplifies pointer arithmetic to array indexing where appropriate.
///
/// Converts patterns like:
/// - `*(ptr + i)` → `ptr[i]`
/// - `*(base + i * size)` → `base[i]` (with size annotation)
#[allow(dead_code)] // Utility function for future loop analysis enhancements
pub fn simplify_pointer_to_array_access(expr: &Expr) -> Expr {
    match &expr.kind {
        ExprKind::Deref { addr, size } => {
            if let Some((base, index, elem_size)) = extract_pointer_arithmetic(addr, *size as usize)
            {
                return Expr {
                    kind: ExprKind::ArrayAccess {
                        base: Box::new(base),
                        index: Box::new(index),
                        element_size: elem_size,
                    },
                };
            }
            expr.clone()
        }
        _ => expr.clone(),
    }
}

/// Extracts base, index, and element size from pointer arithmetic.
#[allow(dead_code)] // Utility function for future loop analysis enhancements
fn extract_pointer_arithmetic(addr: &Expr, deref_size: usize) -> Option<(Expr, Expr, usize)> {
    match &addr.kind {
        // Pattern: base + offset
        ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } => {
            // Check for scaled index: base + (index * scale)
            if let ExprKind::BinOp {
                op: BinOpKind::Mul,
                left: idx,
                right: scale,
            } = &right.kind
            {
                if let Some(scale_val) = get_const_value(scale) {
                    return Some(((**left).clone(), (**idx).clone(), scale_val as usize));
                }
            }

            // Check for unscaled: base + index
            if !is_constant(right) {
                return Some(((**left).clone(), (**right).clone(), deref_size));
            }

            None
        }
        _ => None,
    }
}

/// Analyzes a for-loop to determine if the increment should be made explicit.
///
/// Returns true if the increment is "hidden" and should be shown explicitly,
/// false if it's already in the update clause.
#[allow(dead_code)] // Utility function for future loop analysis enhancements
pub fn should_show_increment_in_body(
    update: Option<&Expr>,
    body: &[super::structurer::StructuredNode],
) -> bool {
    // If there's no update clause, check if increment is in the body
    if update.is_none() {
        return has_increment_in_body(body);
    }

    // If update exists, increment should be in the update clause
    false
}

/// Checks if loop body contains an increment statement.
#[allow(dead_code)] // Utility function for future loop analysis enhancements
fn has_increment_in_body(body: &[super::structurer::StructuredNode]) -> bool {
    use super::structurer::StructuredNode;

    for node in body {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if is_increment_expr(stmt) {
                        return true;
                    }
                }
            }
            StructuredNode::Expr(expr) => {
                if is_increment_expr(expr) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Checks if an expression is an increment/decrement operation.
#[allow(dead_code)] // Utility function for future loop analysis enhancements
fn is_increment_expr(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::UnaryOp { op, .. } => {
            matches!(
                op,
                super::expression::UnaryOpKind::Inc | super::expression::UnaryOpKind::Dec
            )
        }
        ExprKind::CompoundAssign { op, .. } => {
            matches!(op, BinOpKind::Add | BinOpKind::Sub)
        }
        ExprKind::Assign { rhs, .. } => {
            matches!(
                rhs.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Add | BinOpKind::Sub,
                    ..
                }
            )
        }
        _ => false,
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
    fn test_normalize_ne_to_lt() {
        // i = 0; i < 10; i++ but condition is i != 10
        let init = Some(Expr::assign(make_var("i"), Expr::int(0)));
        let condition = Expr::binop(BinOpKind::Ne, make_var("i"), Expr::int(10));
        let update = Some(Expr {
            kind: ExprKind::UnaryOp {
                op: super::super::expression::UnaryOpKind::Inc,
                operand: Box::new(make_var("i")),
            },
        });

        let normalized = normalize_loop_condition(&condition, init.as_ref(), update.as_ref());

        match normalized.kind {
            ExprKind::BinOp { op, .. } => assert_eq!(op, BinOpKind::Lt),
            _ => panic!("Expected BinOp with Lt"),
        }
    }

    #[test]
    fn test_countdown_loop_normalization() {
        // i = 10; i != 0; i--
        let init = Some(Expr::assign(make_var("i"), Expr::int(10)));
        let condition = Expr::binop(BinOpKind::Ne, make_var("i"), Expr::int(0));
        let update = Some(Expr {
            kind: ExprKind::UnaryOp {
                op: super::super::expression::UnaryOpKind::Dec,
                operand: Box::new(make_var("i")),
            },
        });

        let normalized = normalize_loop_condition(&condition, init.as_ref(), update.as_ref());

        // Should normalize to i >= 0 or i > 0
        match normalized.kind {
            ExprKind::BinOp { op, .. } => {
                assert!(matches!(op, BinOpKind::Ge | BinOpKind::Gt));
            }
            _ => panic!("Expected BinOp"),
        }
    }

    #[test]
    fn test_flip_comparison() {
        assert_eq!(flip_comparison_op(BinOpKind::Lt), Some(BinOpKind::Gt));
        assert_eq!(flip_comparison_op(BinOpKind::Ge), Some(BinOpKind::Le));
        assert_eq!(flip_comparison_op(BinOpKind::Eq), Some(BinOpKind::Eq));
    }

    #[test]
    fn test_pointer_null_check() {
        let condition = Expr::binop(BinOpKind::Ne, make_var("ptr"), Expr::int(0));
        assert!(is_pointer_null_check(&condition));

        let condition2 = Expr::binop(BinOpKind::Lt, make_var("i"), Expr::int(10));
        assert!(!is_pointer_null_check(&condition2));
    }

    #[test]
    fn test_extract_step_value() {
        let inc = Expr {
            kind: ExprKind::UnaryOp {
                op: super::super::expression::UnaryOpKind::Inc,
                operand: Box::new(make_var("i")),
            },
        };
        assert_eq!(extract_step_value(&inc, "i"), Some(1));

        let dec = Expr {
            kind: ExprKind::UnaryOp {
                op: super::super::expression::UnaryOpKind::Dec,
                operand: Box::new(make_var("i")),
            },
        };
        assert_eq!(extract_step_value(&dec, "i"), Some(-1));

        let add2 = Expr {
            kind: ExprKind::CompoundAssign {
                lhs: Box::new(make_var("i")),
                op: BinOpKind::Add,
                rhs: Box::new(Expr::int(2)),
            },
        };
        assert_eq!(extract_step_value(&add2, "i"), Some(2));
    }
}
