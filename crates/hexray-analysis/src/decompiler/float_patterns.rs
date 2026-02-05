//! Floating-point pattern detection and simplification.
//!
//! This module detects common floating-point idioms and special value checks,
//! converting low-level bit manipulations into cleaner math function calls.
//!
//! # Supported Patterns
//!
//! - NaN checks: `x != x`, `(bits & 0x7FFFFFFF) > 0x7F800000`
//! - Infinity checks: `(bits & 0x7FFFFFFF) == 0x7F800000`
//! - Finite checks: `(bits & 0x7F800000) != 0x7F800000`
//! - Sign extraction: `bits >> 31`, `bits & 0x80000000`
//! - Absolute value: `bits & 0x7FFFFFFF` (for float)
//! - Negative: `bits ^ 0x80000000`
//! - fpclassify patterns
//! - Fast approximations (reciprocal, sqrt, rsqrt)

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind};
use super::structurer::StructuredNode;

/// IEEE 754 float constants.
pub mod ieee754 {
    /// Float32 exponent mask.
    pub const F32_EXP_MASK: u64 = 0x7F800000;
    /// Float32 mantissa mask.
    pub const F32_MANT_MASK: u64 = 0x007FFFFF;
    /// Float32 sign mask.
    pub const F32_SIGN_MASK: u64 = 0x80000000;
    /// Float32 abs mask (clears sign bit).
    pub const F32_ABS_MASK: u64 = 0x7FFFFFFF;
    /// Float32 infinity bits (without sign).
    pub const F32_INF_BITS: u64 = 0x7F800000;
    /// Float32 quiet NaN bits.
    pub const F32_QNAN_BIT: u64 = 0x00400000;
    /// Float32 exponent bias.
    pub const F32_EXP_BIAS: i32 = 127;

    /// Float64 exponent mask.
    pub const F64_EXP_MASK: u64 = 0x7FF0000000000000;
    /// Float64 mantissa mask.
    pub const F64_MANT_MASK: u64 = 0x000FFFFFFFFFFFFF;
    /// Float64 sign mask.
    pub const F64_SIGN_MASK: u64 = 0x8000000000000000;
    /// Float64 abs mask (clears sign bit).
    pub const F64_ABS_MASK: u64 = 0x7FFFFFFFFFFFFFFF;
    /// Float64 infinity bits (without sign).
    pub const F64_INF_BITS: u64 = 0x7FF0000000000000;
    /// Float64 quiet NaN bit.
    pub const F64_QNAN_BIT: u64 = 0x0008000000000000;
    /// Float64 exponent bias.
    pub const F64_EXP_BIAS: i32 = 1023;

    /// Float32 magic constant for fast inverse square root.
    pub const F32_RSQRT_MAGIC: u64 = 0x5F3759DF;
    /// Float64 magic constant for fast inverse square root.
    pub const F64_RSQRT_MAGIC: u64 = 0x5FE6EB50C7B537A9;
}

/// Floating-point classification result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FpClass {
    /// Positive or negative zero.
    Zero,
    /// Subnormal (denormalized) number.
    Subnormal,
    /// Normal number.
    Normal,
    /// Positive or negative infinity.
    Infinite,
    /// Not a Number.
    Nan,
    /// Quiet NaN specifically.
    QuietNan,
    /// Signaling NaN specifically.
    SignalingNan,
}

/// Simplifies floating-point patterns in structured nodes.
pub fn simplify_float_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(simplify_float_patterns_in_node)
        .collect()
}

fn simplify_float_patterns_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = statements.into_iter().map(simplify_float_expr).collect();
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::Expr(expr) => StructuredNode::Expr(simplify_float_expr(expr)),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: simplify_float_expr(condition),
            then_body: simplify_float_patterns(then_body),
            else_body: else_body.map(simplify_float_patterns),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: simplify_float_expr(condition),
            body: simplify_float_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_float_patterns(body),
            condition: simplify_float_expr(condition),
            header,
            exit_block,
        },
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => StructuredNode::For {
            init: init.map(simplify_float_expr),
            condition: simplify_float_expr(condition),
            update: update.map(simplify_float_expr),
            body: simplify_float_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_float_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: simplify_float_expr(value),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, simplify_float_patterns(body)))
                .collect(),
            default: default.map(simplify_float_patterns),
        },
        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(simplify_float_expr(expr)))
        }
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(simplify_float_patterns(nodes)),
        other => other,
    }
}

/// Simplify floating-point patterns in an expression.
pub fn simplify_float_expr(expr: Expr) -> Expr {
    let simplified = match expr.kind {
        ExprKind::Assign { lhs, rhs } => {
            let rhs = simplify_float_expr(*rhs);
            Expr::assign(*lhs, rhs)
        }
        ExprKind::BinOp { op, left, right } => {
            let left = simplify_float_expr(*left);
            let right = simplify_float_expr(*right);
            Expr::binop(op, left, right)
        }
        ExprKind::UnaryOp { op, operand } => {
            let operand = simplify_float_expr(*operand);
            Expr::unary(op, operand)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let cond = simplify_float_expr(*cond);
            let then_expr = simplify_float_expr(*then_expr);
            let else_expr = simplify_float_expr(*else_expr);
            Expr {
                kind: ExprKind::Conditional {
                    cond: Box::new(cond),
                    then_expr: Box::new(then_expr),
                    else_expr: Box::new(else_expr),
                },
            }
        }
        _ => expr,
    };

    // Apply floating-point pattern simplifications
    apply_float_simplifications(simplified)
}

/// Apply all floating-point simplification patterns.
fn apply_float_simplifications(expr: Expr) -> Expr {
    // Try each pattern in order

    // NaN check: x != x
    if let Some(simplified) = simplify_nan_self_compare(&expr) {
        return simplified;
    }

    // NaN check via bit manipulation
    if let Some(simplified) = simplify_nan_bit_check(&expr) {
        return simplified;
    }

    // Infinity check
    if let Some(simplified) = simplify_inf_check(&expr) {
        return simplified;
    }

    // Finite check
    if let Some(simplified) = simplify_finite_check(&expr) {
        return simplified;
    }

    // Sign bit extraction
    if let Some(simplified) = simplify_signbit(&expr) {
        return simplified;
    }

    // Floating-point absolute value via bit manipulation
    if let Some(simplified) = simplify_fabs_bit(&expr) {
        return simplified;
    }

    // Floating-point negation via bit manipulation
    if let Some(simplified) = simplify_fneg_bit(&expr) {
        return simplified;
    }

    // Fast inverse square root pattern
    if let Some(simplified) = simplify_fast_rsqrt(&expr) {
        return simplified;
    }

    // Copysign pattern
    if let Some(simplified) = simplify_copysign(&expr) {
        return simplified;
    }

    // Floor/ceil/trunc patterns
    if let Some(simplified) = simplify_rounding(&expr) {
        return simplified;
    }

    expr
}

/// Simplify NaN check via self-comparison: `x != x` -> `isnan(x)`.
///
/// In IEEE 754, NaN is the only value that is not equal to itself.
fn simplify_nan_self_compare(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &expr.kind
    {
        if exprs_equal(left, right) {
            // x != x -> isnan(x)
            return Some(Expr::call(
                CallTarget::Named("isnan".to_string()),
                vec![left.as_ref().clone()],
            ));
        }
    }

    // Also handle the negated case: !(x == x) -> isnan(x)
    if let ExprKind::UnaryOp {
        op: UnaryOpKind::LogicalNot,
        operand,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Eq,
            left,
            right,
        } = &operand.kind
        {
            if exprs_equal(left, right) {
                return Some(Expr::call(
                    CallTarget::Named("isnan".to_string()),
                    vec![left.as_ref().clone()],
                ));
            }
        }
    }

    None
}

/// Simplify NaN check via bit manipulation.
///
/// Pattern for float32: `(bits & 0x7FFFFFFF) > 0x7F800000`
/// Pattern for float64: `(bits & 0x7FFFFFFFFFFFFFFF) > 0x7FF0000000000000`
fn simplify_nan_bit_check(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Gt,
        left: masked,
        right: threshold,
    } = &expr.kind
    {
        // Check for (x & ABS_MASK) > INF_BITS
        if let ExprKind::BinOp {
            op: BinOpKind::And,
            left: value,
            right: mask,
        } = &masked.kind
        {
            if let ExprKind::IntLit(mask_val) = &mask.kind {
                if let ExprKind::IntLit(thresh_val) = &threshold.kind {
                    // Float32 pattern
                    if *mask_val == ieee754::F32_ABS_MASK as i128
                        && *thresh_val == ieee754::F32_INF_BITS as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isnan".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "float")],
                        ));
                    }
                    // Float64 pattern
                    if *mask_val == ieee754::F64_ABS_MASK as i128
                        && *thresh_val == ieee754::F64_INF_BITS as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isnan".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "double")],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify infinity check.
///
/// Pattern: `(bits & 0x7FFFFFFF) == 0x7F800000` and mantissa == 0
fn simplify_inf_check(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        left: masked,
        right: inf_bits,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::And,
            left: value,
            right: mask,
        } = &masked.kind
        {
            if let ExprKind::IntLit(mask_val) = &mask.kind {
                if let ExprKind::IntLit(inf_val) = &inf_bits.kind {
                    // Float32 infinity check
                    if *mask_val == ieee754::F32_ABS_MASK as i128
                        && *inf_val == ieee754::F32_INF_BITS as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isinf".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "float")],
                        ));
                    }
                    // Float64 infinity check
                    if *mask_val == ieee754::F64_ABS_MASK as i128
                        && *inf_val == ieee754::F64_INF_BITS as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isinf".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "double")],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify finite check.
///
/// Pattern: `(bits & 0x7F800000) != 0x7F800000`
fn simplify_finite_check(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left: masked,
        right: exp_bits,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::And,
            left: value,
            right: mask,
        } = &masked.kind
        {
            if let ExprKind::IntLit(mask_val) = &mask.kind {
                if let ExprKind::IntLit(exp_val) = &exp_bits.kind {
                    // Float32 finite check (exponent != all 1s)
                    if *mask_val == ieee754::F32_EXP_MASK as i128
                        && *exp_val == ieee754::F32_EXP_MASK as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isfinite".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "float")],
                        ));
                    }
                    // Float64 finite check
                    if *mask_val == ieee754::F64_EXP_MASK as i128
                        && *exp_val == ieee754::F64_EXP_MASK as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("isfinite".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "double")],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify sign bit extraction.
///
/// Patterns:
/// - `bits >> 31` (float32) or `bits >> 63` (float64)
/// - `(bits >> 31) & 1`
/// - `bits & 0x80000000`
fn simplify_signbit(expr: &Expr) -> Option<Expr> {
    // Pattern: bits >> 31
    if let ExprKind::BinOp {
        op: BinOpKind::Shr,
        left: value,
        right: shift,
    } = &expr.kind
    {
        if let ExprKind::IntLit(shift_amt) = &shift.kind {
            if *shift_amt == 31 {
                return Some(Expr::call(
                    CallTarget::Named("signbit".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "float")],
                ));
            }
            if *shift_amt == 63 {
                return Some(Expr::call(
                    CallTarget::Named("signbit".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "double")],
                ));
            }
        }
    }

    // Pattern: bits & SIGN_MASK
    if let ExprKind::BinOp {
        op: BinOpKind::And,
        left: value,
        right: mask,
    } = &expr.kind
    {
        if let ExprKind::IntLit(mask_val) = &mask.kind {
            if *mask_val == ieee754::F32_SIGN_MASK as i128 {
                return Some(Expr::call(
                    CallTarget::Named("signbit".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "float")],
                ));
            }
            if *mask_val == ieee754::F64_SIGN_MASK as i128 {
                return Some(Expr::call(
                    CallTarget::Named("signbit".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "double")],
                ));
            }
        }
    }

    None
}

/// Simplify floating-point absolute value via bit manipulation.
///
/// Pattern: `bits & 0x7FFFFFFF` -> `fabsf(x)`
fn simplify_fabs_bit(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::And,
        left: value,
        right: mask,
    } = &expr.kind
    {
        if let ExprKind::IntLit(mask_val) = &mask.kind {
            // Float32 fabs
            if *mask_val == ieee754::F32_ABS_MASK as i128 {
                return Some(Expr::call(
                    CallTarget::Named("fabsf".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "float")],
                ));
            }
            // Float64 fabs
            if *mask_val == ieee754::F64_ABS_MASK as i128 {
                return Some(Expr::call(
                    CallTarget::Named("fabs".to_string()),
                    vec![make_bitcast(value.as_ref().clone(), "double")],
                ));
            }
        }
    }

    None
}

/// Simplify floating-point negation via bit manipulation.
///
/// Pattern: `bits ^ 0x80000000` -> `-x`
fn simplify_fneg_bit(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Xor,
        left: value,
        right: mask,
    } = &expr.kind
    {
        if let ExprKind::IntLit(mask_val) = &mask.kind {
            // Float32 negation
            if *mask_val == ieee754::F32_SIGN_MASK as i128 {
                return Some(Expr::unary(
                    UnaryOpKind::Neg,
                    make_bitcast(value.as_ref().clone(), "float"),
                ));
            }
            // Float64 negation
            if *mask_val == ieee754::F64_SIGN_MASK as i128 {
                return Some(Expr::unary(
                    UnaryOpKind::Neg,
                    make_bitcast(value.as_ref().clone(), "double"),
                ));
            }
        }
    }

    None
}

/// Simplify fast inverse square root pattern.
///
/// The classic "Quake III" fast inverse square root:
/// ```c
/// float Q_rsqrt(float number) {
///     long i;
///     float x2, y;
///     const float threehalfs = 1.5F;
///     x2 = number * 0.5F;
///     i = *(long*)&number;
///     i = 0x5f3759df - (i >> 1);  // Magic!
///     y = *(float*)&i;
///     y = y * (threehalfs - (x2 * y * y));  // Newton iteration
///     return y;
/// }
/// ```
fn simplify_fast_rsqrt(expr: &Expr) -> Option<Expr> {
    // Look for: MAGIC - (bits >> 1)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left: magic,
        right: shifted,
    } = &expr.kind
    {
        if let ExprKind::IntLit(magic_val) = &magic.kind {
            if let ExprKind::BinOp {
                op: BinOpKind::Shr,
                left: value,
                right: shift,
            } = &shifted.kind
            {
                if let ExprKind::IntLit(1) = &shift.kind {
                    // Float32 magic
                    if *magic_val == ieee754::F32_RSQRT_MAGIC as i128 {
                        return Some(Expr::call(
                            CallTarget::Named("fast_rsqrt".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "float")],
                        ));
                    }
                    // Float64 magic (less common)
                    if *magic_val == ieee754::F64_RSQRT_MAGIC as i128 {
                        return Some(Expr::call(
                            CallTarget::Named("fast_rsqrt".to_string()),
                            vec![make_bitcast(value.as_ref().clone(), "double")],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify copysign pattern.
///
/// Pattern: `(dst_bits & 0x7FFFFFFF) | (src_bits & 0x80000000)`
fn simplify_copysign(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Or,
        left: magnitude,
        right: sign,
    } = &expr.kind
    {
        // Check for magnitude part: x & ABS_MASK
        if let ExprKind::BinOp {
            op: BinOpKind::And,
            left: mag_val,
            right: mag_mask,
        } = &magnitude.kind
        {
            // Check for sign part: y & SIGN_MASK
            if let ExprKind::BinOp {
                op: BinOpKind::And,
                left: sign_val,
                right: sign_mask,
            } = &sign.kind
            {
                if let (ExprKind::IntLit(mm), ExprKind::IntLit(sm)) =
                    (&mag_mask.kind, &sign_mask.kind)
                {
                    // Float32 copysign
                    if *mm == ieee754::F32_ABS_MASK as i128 && *sm == ieee754::F32_SIGN_MASK as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("copysignf".to_string()),
                            vec![
                                make_bitcast(mag_val.as_ref().clone(), "float"),
                                make_bitcast(sign_val.as_ref().clone(), "float"),
                            ],
                        ));
                    }
                    // Float64 copysign
                    if *mm == ieee754::F64_ABS_MASK as i128 && *sm == ieee754::F64_SIGN_MASK as i128
                    {
                        return Some(Expr::call(
                            CallTarget::Named("copysign".to_string()),
                            vec![
                                make_bitcast(mag_val.as_ref().clone(), "double"),
                                make_bitcast(sign_val.as_ref().clone(), "double"),
                            ],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify rounding patterns (floor, ceil, trunc).
///
/// These are typically implemented using:
/// - Addition/subtraction of large constants
/// - Bit manipulation to remove fractional bits
fn simplify_rounding(expr: &Expr) -> Option<Expr> {
    // This is architecture and compiler specific, so we'll look for
    // common patterns but may not catch all cases

    // Pattern: float-to-int-to-float (truncation)
    if let ExprKind::Cast {
        expr: inner,
        to_size: float_size,
        signed: false,
    } = &expr.kind
    {
        if let ExprKind::Cast {
            expr: innermost,
            to_size: int_size,
            signed: true,
        } = &inner.kind
        {
            // (float)(int)x is trunc(x)
            if *float_size == 4 && *int_size == 4 {
                return Some(Expr::call(
                    CallTarget::Named("truncf".to_string()),
                    vec![innermost.as_ref().clone()],
                ));
            }
            if *float_size == 8 && *int_size == 8 {
                return Some(Expr::call(
                    CallTarget::Named("trunc".to_string()),
                    vec![innermost.as_ref().clone()],
                ));
            }
        }
    }

    None
}

/// Create a bitcast expression (type punning).
fn make_bitcast(expr: Expr, to_type: &str) -> Expr {
    Expr::call(
        CallTarget::Named(format!("bitcast<{}>", to_type)),
        vec![expr],
    )
}

/// Check if two expressions are structurally equal.
fn exprs_equal(a: &Expr, b: &Expr) -> bool {
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
        ) => op1 == op2 && exprs_equal(l1, l2) && exprs_equal(r1, r2),
        (
            ExprKind::UnaryOp {
                op: op1,
                operand: o1,
            },
            ExprKind::UnaryOp {
                op: op2,
                operand: o2,
            },
        ) => op1 == op2 && exprs_equal(o1, o2),
        (ExprKind::Deref { addr: a1, .. }, ExprKind::Deref { addr: a2, .. }) => exprs_equal(a1, a2),
        _ => false,
    }
}

/// Detect specific floating-point comparison patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatCompareKind {
    /// Ordered less than.
    OLT,
    /// Ordered less than or equal.
    OLE,
    /// Ordered greater than.
    OGT,
    /// Ordered greater than or equal.
    OGE,
    /// Ordered equal.
    OEQ,
    /// Ordered not equal.
    ONE,
    /// Unordered (either is NaN).
    UNO,
    /// Ordered (neither is NaN).
    ORD,
    /// Unordered or equal.
    UEQ,
    /// Unordered or less than.
    ULT,
    /// Unordered or greater than.
    UGT,
}

/// Analyze a floating-point comparison expression.
pub fn analyze_float_compare(expr: &Expr) -> Option<(FloatCompareKind, Expr, Expr)> {
    if let ExprKind::BinOp { op, left, right } = &expr.kind {
        let kind = match op {
            BinOpKind::Lt => FloatCompareKind::OLT,
            BinOpKind::Le => FloatCompareKind::OLE,
            BinOpKind::Gt => FloatCompareKind::OGT,
            BinOpKind::Ge => FloatCompareKind::OGE,
            BinOpKind::Eq => FloatCompareKind::OEQ,
            BinOpKind::Ne => FloatCompareKind::ONE,
            _ => return None,
        };

        return Some((kind, left.as_ref().clone(), right.as_ref().clone()));
    }

    None
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
    fn test_nan_self_compare() {
        // x != x -> isnan(x)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::Ne, x.clone(), x.clone());

        let result = simplify_nan_self_compare(&expr);
        assert!(result.is_some());

        if let Some(Expr {
            kind:
                ExprKind::Call {
                    target: CallTarget::Named(name),
                    args,
                },
            ..
        }) = result
        {
            assert_eq!(name, "isnan");
            assert_eq!(args.len(), 1);
        } else {
            panic!("Expected named call");
        }
    }

    #[test]
    fn test_nan_bit_check_f32() {
        // (bits & 0x7FFFFFFF) > 0x7F800000 -> isnan
        let bits = make_var("bits");
        let masked = Expr::binop(
            BinOpKind::And,
            bits,
            Expr::int(ieee754::F32_ABS_MASK as i128),
        );
        let expr = Expr::binop(
            BinOpKind::Gt,
            masked,
            Expr::int(ieee754::F32_INF_BITS as i128),
        );

        let result = simplify_nan_bit_check(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_inf_check_f32() {
        // (bits & 0x7FFFFFFF) == 0x7F800000 -> isinf
        let bits = make_var("bits");
        let masked = Expr::binop(
            BinOpKind::And,
            bits,
            Expr::int(ieee754::F32_ABS_MASK as i128),
        );
        let expr = Expr::binop(
            BinOpKind::Eq,
            masked,
            Expr::int(ieee754::F32_INF_BITS as i128),
        );

        let result = simplify_inf_check(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_finite_check_f32() {
        // (bits & 0x7F800000) != 0x7F800000 -> isfinite
        let bits = make_var("bits");
        let masked = Expr::binop(
            BinOpKind::And,
            bits,
            Expr::int(ieee754::F32_EXP_MASK as i128),
        );
        let expr = Expr::binop(
            BinOpKind::Ne,
            masked,
            Expr::int(ieee754::F32_EXP_MASK as i128),
        );

        let result = simplify_finite_check(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_signbit_shift() {
        // bits >> 31 -> signbit
        let bits = make_var("bits");
        let expr = Expr::binop(BinOpKind::Shr, bits, Expr::int(31));

        let result = simplify_signbit(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_fabs_bit_f32() {
        // bits & 0x7FFFFFFF -> fabsf
        let bits = make_var("bits");
        let expr = Expr::binop(
            BinOpKind::And,
            bits,
            Expr::int(ieee754::F32_ABS_MASK as i128),
        );

        let result = simplify_fabs_bit(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_fneg_bit_f32() {
        // bits ^ 0x80000000 -> -x
        let bits = make_var("bits");
        let expr = Expr::binop(
            BinOpKind::Xor,
            bits,
            Expr::int(ieee754::F32_SIGN_MASK as i128),
        );

        let result = simplify_fneg_bit(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_fast_rsqrt() {
        // 0x5f3759df - (bits >> 1) -> fast_rsqrt
        let bits = make_var("bits");
        let shifted = Expr::binop(BinOpKind::Shr, bits, Expr::int(1));
        let expr = Expr::binop(
            BinOpKind::Sub,
            Expr::int(ieee754::F32_RSQRT_MAGIC as i128),
            shifted,
        );

        let result = simplify_fast_rsqrt(&expr);
        assert!(result.is_some());

        if let Some(Expr {
            kind:
                ExprKind::Call {
                    target: CallTarget::Named(name),
                    ..
                },
            ..
        }) = result
        {
            assert_eq!(name, "fast_rsqrt");
        } else {
            panic!("Expected named call");
        }
    }

    #[test]
    fn test_copysign_f32() {
        // (mag & 0x7FFFFFFF) | (sign & 0x80000000) -> copysignf
        let mag = make_var("mag");
        let sign = make_var("sign");

        let mag_part = Expr::binop(
            BinOpKind::And,
            mag,
            Expr::int(ieee754::F32_ABS_MASK as i128),
        );
        let sign_part = Expr::binop(
            BinOpKind::And,
            sign,
            Expr::int(ieee754::F32_SIGN_MASK as i128),
        );
        let expr = Expr::binop(BinOpKind::Or, mag_part, sign_part);

        let result = simplify_copysign(&expr);
        assert!(result.is_some());
    }

    #[test]
    fn test_ieee754_constants() {
        assert_eq!(ieee754::F32_EXP_MASK, 0x7F800000);
        assert_eq!(ieee754::F32_SIGN_MASK, 0x80000000);
        assert_eq!(ieee754::F32_ABS_MASK, 0x7FFFFFFF);
        assert_eq!(ieee754::F64_EXP_MASK, 0x7FF0000000000000);
        assert_eq!(ieee754::F32_RSQRT_MAGIC, 0x5F3759DF);
    }
}
