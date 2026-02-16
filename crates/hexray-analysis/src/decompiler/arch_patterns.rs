//! Architecture-specific pattern detection.
//!
//! Detects and simplifies architecture-specific idioms into cleaner high-level
//! representations.
//!
//! # ARM64-specific patterns
//! - CSEL/CSINC/CSINV/CSNEG: Conditional select instructions
//! - MADD/MSUB: Multiply-accumulate operations (d = a + b*c, d = a - b*c)
//! - CINC/CINV/CNEG: Conditional increment/invert/negate aliases
//!
//! # RISC-V pseudo-instructions
//! - NOP (addi x0, x0, 0)
//! - LI (lui + addi for large constants)
//! - MV (addi rd, rs, 0)
//! - NOT (xori rd, rs, -1)
//! - NEG (sub rd, x0, rs)
//! - SEQZ/SNEZ/SLTZ/SGTZ: Set conditionals
//! - BEQZ/BNEZ/BLEZ/BGEZ/BLTZ/BGTZ: Branch pseudo-instructions

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind};
use super::structurer::{CatchHandler, StructuredNode};

/// Architecture hint for pattern matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchHint {
    /// x86-64 architecture
    X86_64,
    /// ARM64/AArch64 architecture
    Arm64,
    /// RISC-V 64-bit architecture
    RiscV64,
    /// RISC-V 32-bit architecture
    RiscV32,
    /// Unknown/generic architecture
    Unknown,
}

/// Detects and simplifies architecture-specific patterns.
pub fn simplify_arch_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes
        .into_iter()
        .map(simplify_arch_patterns_in_node)
        .collect()
}

fn simplify_arch_patterns_in_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => {
            let statements = simplify_statements_sequence(statements);
            StructuredNode::Block {
                id,
                statements,
                address_range,
            }
        }
        StructuredNode::Expr(expr) => StructuredNode::Expr(simplify_arch_expr(expr)),
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition: simplify_arch_expr(condition),
            then_body: simplify_arch_patterns(then_body),
            else_body: else_body.map(simplify_arch_patterns),
        },
        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition: simplify_arch_expr(condition),
            body: simplify_arch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: simplify_arch_patterns(body),
            condition: simplify_arch_expr(condition),
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
            init: init.map(simplify_arch_expr),
            condition: simplify_arch_expr(condition),
            update: update.map(simplify_arch_expr),
            body: simplify_arch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => StructuredNode::Loop {
            body: simplify_arch_patterns(body),
            header,
            exit_block,
        },
        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value: simplify_arch_expr(value),
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, simplify_arch_patterns(body)))
                .collect(),
            default: default.map(simplify_arch_patterns),
        },
        StructuredNode::Return(Some(expr)) => {
            StructuredNode::Return(Some(simplify_arch_expr(expr)))
        }
        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(simplify_arch_patterns(nodes)),
        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: simplify_arch_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| CatchHandler {
                    body: simplify_arch_patterns(h.body),
                    ..h
                })
                .collect(),
        },
        other => other,
    }
}

/// Simplify a sequence of statements, looking for patterns that span multiple statements.
fn simplify_statements_sequence(mut statements: Vec<Expr>) -> Vec<Expr> {
    // First pass: simplify individual expressions
    statements = statements.into_iter().map(simplify_arch_expr).collect();

    // Second pass: look for multi-statement patterns
    // (e.g., comparison followed by CSEL)
    let mut result = Vec::with_capacity(statements.len());
    let mut i = 0;

    while i < statements.len() {
        // Try to merge cmp + csel patterns
        if i + 1 < statements.len() {
            if let Some(merged) = try_merge_cmp_csel(&statements[i], &statements[i + 1]) {
                result.push(merged);
                i += 2;
                continue;
            }
        }

        result.push(statements[i].clone());
        i += 1;
    }

    result
}

/// Simplify architecture-specific expressions.
fn simplify_arch_expr(expr: Expr) -> Expr {
    let simplified = match expr.kind {
        // Recursively simplify sub-expressions first
        ExprKind::Assign { lhs, rhs } => {
            let rhs = simplify_arch_expr(*rhs);
            Expr::assign(*lhs, rhs)
        }
        ExprKind::BinOp { op, left, right } => {
            let left = simplify_arch_expr(*left);
            let right = simplify_arch_expr(*right);
            Expr::binop(op, left, right)
        }
        ExprKind::UnaryOp { op, operand } => {
            let operand = simplify_arch_expr(*operand);
            Expr::unary(op, operand)
        }
        ExprKind::Conditional {
            cond,
            then_expr,
            else_expr,
        } => {
            let cond = simplify_arch_expr(*cond);
            let then_expr = simplify_arch_expr(*then_expr);
            let else_expr = simplify_arch_expr(*else_expr);
            make_conditional(cond, then_expr, else_expr)
        }
        ExprKind::Cast {
            expr: inner,
            to_size,
            signed,
        } => {
            let inner = simplify_arch_expr(*inner);
            make_cast(inner, to_size, signed)
        }
        _ => expr,
    };

    // Apply architecture-specific simplifications
    apply_arch_simplifications(simplified)
}

/// Create a conditional expression.
fn make_conditional(cond: Expr, then_expr: Expr, else_expr: Expr) -> Expr {
    Expr {
        kind: ExprKind::Conditional {
            cond: Box::new(cond),
            then_expr: Box::new(then_expr),
            else_expr: Box::new(else_expr),
        },
    }
}

/// Create a cast expression.
fn make_cast(expr: Expr, to_size: u8, signed: bool) -> Expr {
    Expr {
        kind: ExprKind::Cast {
            expr: Box::new(expr),
            to_size,
            signed,
        },
    }
}

/// Apply architecture-specific simplifications to an expression.
fn apply_arch_simplifications(expr: Expr) -> Expr {
    // Try each simplification pattern
    if let Some(simplified) = simplify_csel_pattern(&expr) {
        return simplified;
    }

    if let Some(simplified) = simplify_abs_pattern(&expr) {
        return simplified;
    }

    if let Some(simplified) = simplify_min_max_pattern(&expr) {
        return simplified;
    }

    if let Some(simplified) = simplify_sign_extend_pattern(&expr) {
        return simplified;
    }

    // x86 string instruction patterns
    if let Some(simplified) = simplify_x86_rep_pattern(&expr) {
        return simplified;
    }

    if let Some(simplified) = simplify_x86_lea_pattern(&expr) {
        return simplified;
    }

    // Rotate patterns
    if let Some(simplified) = simplify_rotate_pattern(&expr) {
        return simplified;
    }

    // Bit manipulation patterns
    if let Some(simplified) = simplify_bit_manipulation_pattern(&expr) {
        return simplified;
    }

    // Multiply-by-constant patterns
    if let Some(simplified) = simplify_multiply_constant_pattern(&expr) {
        return simplified;
    }

    // Clamp/saturate patterns
    if let Some(simplified) = simplify_clamp_pattern(&expr) {
        return simplified;
    }

    // ARM64-specific patterns
    if let Some(simplified) = simplify_arm64_csinc_pattern(&expr) {
        return simplified;
    }

    if let Some(simplified) = simplify_arm64_madd_pattern(&expr) {
        return simplified;
    }

    // RISC-V pseudo-instruction patterns
    if let Some(simplified) = simplify_riscv_pseudo_pattern(&expr) {
        return simplified;
    }

    expr
}

/// Simplify x86 REP string instruction patterns.
///
/// These patterns are emitted by compilers when optimizing string operations:
/// - REP MOVSB/MOVSD -> memcpy
/// - REP STOSB/STOSD -> memset
/// - REP CMPSB -> memcmp
/// - REPNE SCASB -> strchr/strlen
#[allow(dead_code)]
fn simplify_x86_rep_pattern(expr: &Expr) -> Option<Expr> {
    // Look for patterns that indicate REP instructions:
    // Typically these involve esi/rsi as source, edi/rdi as dest, and ecx/rcx as count

    if let ExprKind::Call {
        target: CallTarget::Named(name),
        args,
    } = &expr.kind
    {
        // Check for intrinsic-like patterns that may have been lowered
        match name.as_str() {
            // REP MOVSB pattern: memcpy(dst, src, n)
            "__builtin_memcpy" | "__movsb" | "__movsd" | "__movsq" => {
                if args.len() == 3 {
                    return Some(Expr::call(
                        CallTarget::Named("memcpy".to_string()),
                        args.clone(),
                    ));
                }
            }

            // REP STOSB pattern: memset(dst, val, n)
            "__builtin_memset" | "__stosb" | "__stosd" | "__stosq" => {
                if args.len() == 3 {
                    return Some(Expr::call(
                        CallTarget::Named("memset".to_string()),
                        args.clone(),
                    ));
                }
            }

            // REP CMPSB pattern: memcmp(s1, s2, n)
            "__builtin_memcmp" | "__cmpsb" | "__cmpsd" | "__cmpsq" => {
                if args.len() == 3 {
                    return Some(Expr::call(
                        CallTarget::Named("memcmp".to_string()),
                        args.clone(),
                    ));
                }
            }

            _ => {}
        }
    }

    None
}

/// Simplify x86 LEA (Load Effective Address) patterns.
///
/// LEA is often used for arithmetic instead of its intended addressing purpose:
/// - lea rax, [rbx + rcx*4] -> rbx + rcx * 4
/// - lea rax, [rbx + rbx*2] -> rbx * 3
/// - lea rax, [rbx + 5] -> rbx + 5
fn simplify_x86_lea_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: base + index * scale
    // This is often represented as a nested structure

    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left: base,
        right: scaled,
    } = &expr.kind
    {
        // Check for index * scale pattern in right operand
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: index,
            right: scale,
        } = &scaled.kind
        {
            // Check if scale is 2, 4, or 8 (common LEA scales)
            if let ExprKind::IntLit(s) = &scale.kind {
                if *s == 2 || *s == 4 || *s == 8 {
                    // Check if base and index are the same (e.g., lea rax, [rbx + rbx*2] = rbx * 3)
                    if exprs_equal(base, index) {
                        let multiplier = 1 + *s;
                        return Some(Expr::binop(
                            BinOpKind::Mul,
                            base.as_ref().clone(),
                            Expr::int(multiplier),
                        ));
                    }
                }
            }
        }

        // Check for left operand being index * scale
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: index,
            right: scale,
        } = &base.kind
        {
            if let ExprKind::IntLit(s) = &scale.kind {
                if (*s == 2 || *s == 4 || *s == 8) && exprs_equal(scaled, index) {
                    let multiplier = 1 + *s;
                    return Some(Expr::binop(
                        BinOpKind::Mul,
                        scaled.as_ref().clone(),
                        Expr::int(multiplier),
                    ));
                }
            }
        }
    }

    // Pattern: x + x -> x * 2 (common LEA optimization)
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    {
        if exprs_equal(left, right) {
            return Some(Expr::binop(
                BinOpKind::Mul,
                left.as_ref().clone(),
                Expr::int(2),
            ));
        }
    }

    None
}

/// Simplify ARM64 CSEL pattern: `cond ? a : b`
///
/// CSEL (Conditional Select) is ARM64's way of doing conditional moves.
/// We convert these to ternary expressions for cleaner output.
fn simplify_csel_pattern(expr: &Expr) -> Option<Expr> {
    // Check for conditional expression
    if let ExprKind::Conditional {
        cond,
        then_expr,
        else_expr,
    } = &expr.kind
    {
        // Simplify: x == 0 ? 0 : x  =>  x
        if is_eq_zero_check(cond) && is_zero(else_expr) {
            let check_var = extract_eq_zero_var(cond)?;
            if exprs_equal(&check_var, then_expr) {
                return Some(then_expr.as_ref().clone());
            }
        }

        // Simplify: x != 0 ? x : 0  =>  x
        if is_neq_zero_check(cond) && is_zero(else_expr) {
            let check_var = extract_neq_zero_var(cond)?;
            if exprs_equal(&check_var, then_expr) {
                return Some(then_expr.as_ref().clone());
            }
        }

        // Simplify: cond ? 1 : 0  =>  (bool)cond
        if is_one(then_expr) && is_zero(else_expr) {
            return Some(make_cast(cond.as_ref().clone(), 1, false));
        }

        // Simplify: cond ? 0 : 1  =>  !(bool)cond
        if is_zero(then_expr) && is_one(else_expr) {
            return Some(Expr::unary(
                UnaryOpKind::LogicalNot,
                make_cast(cond.as_ref().clone(), 1, false),
            ));
        }
    }

    None
}

/// Simplify absolute value pattern: `x < 0 ? -x : x`
fn simplify_abs_pattern(expr: &Expr) -> Option<Expr> {
    if let ExprKind::Conditional {
        cond,
        then_expr,
        else_expr,
    } = &expr.kind
    {
        // Pattern: x < 0 ? -x : x
        if let Some(x) = extract_lt_zero_var(cond) {
            if is_negation_of(&x, then_expr) && exprs_equal(&x, else_expr) {
                return Some(Expr::call(CallTarget::Named("abs".to_string()), vec![x]));
            }
        }

        // Pattern: x >= 0 ? x : -x
        if let Some(x) = extract_ge_zero_var(cond) {
            if exprs_equal(&x, then_expr) && is_negation_of(&x, else_expr) {
                return Some(Expr::call(CallTarget::Named("abs".to_string()), vec![x]));
            }
        }
    }

    None
}

/// Simplify min/max patterns.
fn simplify_min_max_pattern(expr: &Expr) -> Option<Expr> {
    if let ExprKind::Conditional {
        cond,
        then_expr,
        else_expr,
    } = &expr.kind
    {
        // Pattern: a < b ? a : b  =>  min(a, b)
        if let Some((a, b)) = extract_lt_comparison(cond) {
            if exprs_equal(&a, then_expr) && exprs_equal(&b, else_expr) {
                return Some(Expr::call(CallTarget::Named("min".to_string()), vec![a, b]));
            }
            // Pattern: a < b ? b : a  =>  max(a, b)
            if exprs_equal(&b, then_expr) && exprs_equal(&a, else_expr) {
                return Some(Expr::call(CallTarget::Named("max".to_string()), vec![a, b]));
            }
        }

        // Pattern: a > b ? a : b  =>  max(a, b)
        if let Some((a, b)) = extract_gt_comparison(cond) {
            if exprs_equal(&a, then_expr) && exprs_equal(&b, else_expr) {
                return Some(Expr::call(CallTarget::Named("max".to_string()), vec![a, b]));
            }
            // Pattern: a > b ? b : a  =>  min(a, b)
            if exprs_equal(&b, then_expr) && exprs_equal(&a, else_expr) {
                return Some(Expr::call(CallTarget::Named("min".to_string()), vec![a, b]));
            }
        }

        // Pattern: a <= b ? a : b  =>  min(a, b)
        if let Some((a, b)) = extract_le_comparison(cond) {
            if exprs_equal(&a, then_expr) && exprs_equal(&b, else_expr) {
                return Some(Expr::call(CallTarget::Named("min".to_string()), vec![a, b]));
            }
        }

        // Pattern: a >= b ? a : b  =>  max(a, b)
        if let Some((a, b)) = extract_ge_comparison(cond) {
            if exprs_equal(&a, then_expr) && exprs_equal(&b, else_expr) {
                return Some(Expr::call(CallTarget::Named("max".to_string()), vec![a, b]));
            }
        }
    }

    None
}

/// Simplify sign extension patterns.
fn simplify_sign_extend_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: (x << n) >> n  =>  sign_extend(x, 64 - n)
    if let ExprKind::BinOp {
        op: BinOpKind::Sar, // Arithmetic right shift for sign extension
        left,
        right: shift_right,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: inner_val,
            right: shift_left,
        } = &left.kind
        {
            // Check if shifts are equal constants
            if let (ExprKind::IntLit(l), ExprKind::IntLit(r)) =
                (&shift_left.kind, &shift_right.kind)
            {
                if l == r && *l > 0 && *l < 64 {
                    let bit_width = (64 - *l) as u8;
                    // This is sign extension from bit_width bits - emit as signed cast
                    return Some(make_cast(inner_val.as_ref().clone(), bit_width, true));
                }
            }
        }
    }

    None
}

/// Try to merge a comparison with a following CSEL.
fn try_merge_cmp_csel(_cmp: &Expr, _csel: &Expr) -> Option<Expr> {
    // This would require tracking the flags register state
    // For now, just return None and let individual patterns handle it
    None
}

/// Simplify rotate patterns.
///
/// Detects patterns like:
/// - `(x << n) | (x >> (32 - n))` => `rotl(x, n)` (left rotate)
/// - `(x >> n) | (x << (32 - n))` => `rotr(x, n)` (right rotate)
fn simplify_rotate_pattern(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Or,
        left,
        right,
    } = &expr.kind
    {
        // Try both orderings: (shl | shr) and (shr | shl)
        if let Some(result) = try_extract_rotate(left, right) {
            return Some(result);
        }
        if let Some(result) = try_extract_rotate(right, left) {
            return Some(result);
        }
    }
    None
}

fn try_extract_rotate(a: &Expr, b: &Expr) -> Option<Expr> {
    // Pattern: (x << n) | (x >> (width - n)) => rotl(x, n)
    if let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left: x1,
        right: n1,
    } = &a.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Shr,
            left: x2,
            right: n2,
        } = &b.kind
        {
            if exprs_equal(x1, x2) {
                // Check if n2 = width - n1
                if let (
                    ExprKind::IntLit(shift),
                    ExprKind::BinOp {
                        op: BinOpKind::Sub,
                        left: width,
                        right: shift2,
                    },
                ) = (&n1.kind, &n2.kind)
                {
                    if let ExprKind::IntLit(w) = &width.kind {
                        if (*w == 32 || *w == 64) && exprs_equal(n1, shift2) {
                            return Some(Expr::call(
                                CallTarget::Named("rotl".to_string()),
                                vec![x1.as_ref().clone(), Expr::int(*shift)],
                            ));
                        }
                    }
                }
                // Check for constant complement: n1 + n2 = width
                if let (ExprKind::IntLit(s1), ExprKind::IntLit(s2)) = (&n1.kind, &n2.kind) {
                    if *s1 + *s2 == 32 || *s1 + *s2 == 64 {
                        return Some(Expr::call(
                            CallTarget::Named("rotl".to_string()),
                            vec![x1.as_ref().clone(), Expr::int(*s1)],
                        ));
                    }
                }
            }
        }
    }

    // Pattern: (x >> n) | (x << (width - n)) => rotr(x, n)
    if let ExprKind::BinOp {
        op: BinOpKind::Shr,
        left: x1,
        right: n1,
    } = &a.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: x2,
            right: n2,
        } = &b.kind
        {
            if exprs_equal(x1, x2) {
                if let (ExprKind::IntLit(s1), ExprKind::IntLit(s2)) = (&n1.kind, &n2.kind) {
                    if *s1 + *s2 == 32 || *s1 + *s2 == 64 {
                        return Some(Expr::call(
                            CallTarget::Named("rotr".to_string()),
                            vec![x1.as_ref().clone(), Expr::int(*s1)],
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify bit manipulation patterns.
///
/// Detects patterns like:
/// - `(x >> n) & 1` => test bit n
/// - `(x >> n) & mask` => bit field extraction
/// - Byte swap patterns
fn simplify_bit_manipulation_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: (x >> n) & 1 - this is a bit test, keep as is but potentially annotate
    // We'll let this through for now, but could convert to __builtin_bit_test

    // Pattern: byte swap - detect common bswap patterns
    if let Some(result) = try_simplify_bswap(expr) {
        return Some(result);
    }

    // Pattern: popcount loop - detect while((x &= x-1)) count++
    // This is complex to detect in expression form, skip for now

    None
}

fn try_simplify_bswap(expr: &Expr) -> Option<Expr> {
    // 32-bit bswap pattern:
    // ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) | ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000)
    // This is complex - detect simpler patterns first

    // Simple pattern: look for Or chains with shifts and masks
    if let ExprKind::BinOp {
        op: BinOpKind::Or, ..
    } = &expr.kind
    {
        // Count the number of Or operations
        let or_count = count_or_operations(expr);
        if or_count >= 3 {
            // Likely a byte swap pattern - check if all involve the same base variable
            if let Some(base_var) = extract_common_bswap_var(expr) {
                return Some(Expr::call(
                    CallTarget::Named("bswap".to_string()),
                    vec![base_var],
                ));
            }
        }
    }
    None
}

fn count_or_operations(expr: &Expr) -> usize {
    match &expr.kind {
        ExprKind::BinOp {
            op: BinOpKind::Or,
            left,
            right,
        } => 1 + count_or_operations(left) + count_or_operations(right),
        _ => 0,
    }
}

fn extract_common_bswap_var(expr: &Expr) -> Option<Expr> {
    // Extract all leaf variables from the Or chain and check they're the same
    let mut vars = Vec::new();
    collect_shifted_vars(expr, &mut vars);

    if vars.len() >= 4 {
        // Check all vars are the same
        let first = &vars[0];
        if vars.iter().all(|v| exprs_equal(first, v)) {
            return Some(first.clone());
        }
    }
    None
}

fn collect_shifted_vars(expr: &Expr, vars: &mut Vec<Expr>) {
    match &expr.kind {
        ExprKind::BinOp {
            op: BinOpKind::Or,
            left,
            right,
        } => {
            collect_shifted_vars(left, vars);
            collect_shifted_vars(right, vars);
        }
        ExprKind::BinOp {
            op: BinOpKind::And,
            left,
            ..
        } => {
            // Extract the variable from shift & mask
            collect_shifted_vars(left, vars);
        }
        ExprKind::BinOp {
            op: BinOpKind::Shl | BinOpKind::Shr,
            left,
            ..
        } => {
            if let ExprKind::Var(_) = &left.kind {
                vars.push(left.as_ref().clone());
            }
        }
        ExprKind::Var(_) => {
            vars.push(expr.clone());
        }
        _ => {}
    }
}

/// Simplify multiply-by-constant patterns.
///
/// Compilers often use shifts and adds instead of multiply:
/// - `x + (x << 1)` => `x * 3`
/// - `x + (x << 2)` => `x * 5`
/// - `(x << 3) - x` => `x * 7`
fn simplify_multiply_constant_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: x + (x << n) => x * (1 + 2^n)
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    {
        // x + (x << n)
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: shifted,
            right: shift_amt,
        } = &right.kind
        {
            if exprs_equal(left, shifted) {
                if let ExprKind::IntLit(n) = &shift_amt.kind {
                    if *n >= 1 && *n <= 5 {
                        let multiplier = 1 + (1i128 << *n);
                        return Some(Expr::binop(
                            BinOpKind::Mul,
                            left.as_ref().clone(),
                            Expr::int(multiplier),
                        ));
                    }
                }
            }
        }
        // (x << n) + x
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: shifted,
            right: shift_amt,
        } = &left.kind
        {
            if exprs_equal(right, shifted) {
                if let ExprKind::IntLit(n) = &shift_amt.kind {
                    if *n >= 1 && *n <= 5 {
                        let multiplier = 1 + (1i128 << *n);
                        return Some(Expr::binop(
                            BinOpKind::Mul,
                            right.as_ref().clone(),
                            Expr::int(multiplier),
                        ));
                    }
                }
            }
        }
    }

    // Pattern: (x << n) - x => x * (2^n - 1)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left,
        right,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: shifted,
            right: shift_amt,
        } = &left.kind
        {
            if exprs_equal(right, shifted) {
                if let ExprKind::IntLit(n) = &shift_amt.kind {
                    if *n >= 2 && *n <= 5 {
                        let multiplier = (1i128 << *n) - 1;
                        return Some(Expr::binop(
                            BinOpKind::Mul,
                            right.as_ref().clone(),
                            Expr::int(multiplier),
                        ));
                    }
                }
            }
        }
    }

    None
}

/// Simplify clamp/saturate patterns.
///
/// Detects patterns like:
/// - `min(max(x, lo), hi)` => `clamp(x, lo, hi)`
/// - `max(min(x, hi), lo)` => `clamp(x, lo, hi)`
fn simplify_clamp_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: min(max(x, lo), hi)
    if let ExprKind::Call {
        target: CallTarget::Named(outer_name),
        args: outer_args,
    } = &expr.kind
    {
        if outer_name == "min" && outer_args.len() == 2 {
            if let ExprKind::Call {
                target: CallTarget::Named(inner_name),
                args: inner_args,
            } = &outer_args[0].kind
            {
                if inner_name == "max" && inner_args.len() == 2 {
                    // min(max(x, lo), hi) => clamp(x, lo, hi)
                    return Some(Expr::call(
                        CallTarget::Named("clamp".to_string()),
                        vec![
                            inner_args[0].clone(), // x
                            inner_args[1].clone(), // lo
                            outer_args[1].clone(), // hi
                        ],
                    ));
                }
            }
        }

        // Pattern: max(min(x, hi), lo)
        if outer_name == "max" && outer_args.len() == 2 {
            if let ExprKind::Call {
                target: CallTarget::Named(inner_name),
                args: inner_args,
            } = &outer_args[0].kind
            {
                if inner_name == "min" && inner_args.len() == 2 {
                    // max(min(x, hi), lo) => clamp(x, lo, hi)
                    return Some(Expr::call(
                        CallTarget::Named("clamp".to_string()),
                        vec![
                            inner_args[0].clone(), // x
                            outer_args[1].clone(), // lo
                            inner_args[1].clone(), // hi
                        ],
                    ));
                }
            }
        }
    }

    None
}

// === ARM64-specific patterns ===

/// Simplify ARM64 CSINC (Conditional Select Increment) patterns.
///
/// ARM64 has several conditional select instructions:
/// - CSEL: Rd = cond ? Rn : Rm
/// - CSINC: Rd = cond ? Rn : Rm + 1
/// - CSINV: Rd = cond ? Rn : ~Rm
/// - CSNEG: Rd = cond ? Rn : -Rm
///
/// This function recognizes patterns that result from these instructions:
/// - `cond ? x : x + 1` => conditional increment
/// - `cond ? x : ~x` => conditional invert
/// - `cond ? x : -x` => conditional negate
///
/// Aliases detected:
/// - CINC: Rd = cond ? Rn + 1 : Rn (increment if condition true)
/// - CSET: Rd = cond ? 1 : 0 (set to 1 if condition true)
/// - CINV: Rd = cond ? ~Rn : Rn (invert if condition true)
/// - CSETM: Rd = cond ? -1 : 0 (set to all-ones if condition true)
/// - CNEG: Rd = cond ? -Rn : Rn (negate if condition true)
fn simplify_arm64_csinc_pattern(expr: &Expr) -> Option<Expr> {
    if let ExprKind::Conditional {
        cond,
        then_expr,
        else_expr,
    } = &expr.kind
    {
        // Pattern: cond ? x + 1 : x => cinc(x, cond)
        if let ExprKind::BinOp {
            op: BinOpKind::Add,
            left: add_left,
            right: add_right,
        } = &then_expr.kind
        {
            if is_one(add_right) && exprs_equal(add_left, else_expr) {
                return Some(Expr::call(
                    CallTarget::Named("cinc".to_string()),
                    vec![else_expr.as_ref().clone(), cond.as_ref().clone()],
                ));
            }
        }

        // Pattern: cond ? x : x + 1 => cond ? x : cinc(x, !cond)
        // This is the raw CSINC pattern - simplify to cinc with inverted condition
        if let ExprKind::BinOp {
            op: BinOpKind::Add,
            left: add_left,
            right: add_right,
        } = &else_expr.kind
        {
            if is_one(add_right) && exprs_equal(add_left, then_expr) {
                // cond ? x : x + 1 => cinc(x, !cond) simplified to just x + (!cond)
                // For cleaner output, emit as: x + (cond ? 0 : 1)
                return Some(Expr::binop(
                    BinOpKind::Add,
                    then_expr.as_ref().clone(),
                    make_conditional(cond.as_ref().clone(), Expr::int(0), Expr::int(1)),
                ));
            }
        }

        // Pattern: cond ? ~x : x => cinv(x, cond)
        if let ExprKind::UnaryOp {
            op: UnaryOpKind::Not,
            operand,
        } = &then_expr.kind
        {
            if exprs_equal(operand, else_expr) {
                return Some(Expr::call(
                    CallTarget::Named("cinv".to_string()),
                    vec![else_expr.as_ref().clone(), cond.as_ref().clone()],
                ));
            }
        }

        // Pattern: cond ? x : ~x => cinv(x, !cond)
        if let ExprKind::UnaryOp {
            op: UnaryOpKind::Not,
            operand,
        } = &else_expr.kind
        {
            if exprs_equal(operand, then_expr) {
                // x ^ (cond ? 0 : -1) represents conditional inversion
                return Some(Expr::binop(
                    BinOpKind::Xor,
                    then_expr.as_ref().clone(),
                    make_conditional(cond.as_ref().clone(), Expr::int(0), Expr::int(-1)),
                ));
            }
        }

        // Pattern: cond ? -x : x => cneg(x, cond)
        if is_negation_of(else_expr, then_expr) {
            return Some(Expr::call(
                CallTarget::Named("cneg".to_string()),
                vec![else_expr.as_ref().clone(), cond.as_ref().clone()],
            ));
        }

        // Pattern: cond ? x : -x => cneg(x, !cond)
        if is_negation_of(then_expr, else_expr) {
            // x * (cond ? 1 : -1) for conditional negate
            return Some(Expr::binop(
                BinOpKind::Mul,
                then_expr.as_ref().clone(),
                make_conditional(cond.as_ref().clone(), Expr::int(1), Expr::int(-1)),
            ));
        }

        // Pattern: cond ? -1 : 0 => csetm(cond) - conditional set mask
        if is_neg_one(then_expr) && is_zero(else_expr) {
            return Some(Expr::call(
                CallTarget::Named("csetm".to_string()),
                vec![cond.as_ref().clone()],
            ));
        }
    }

    None
}

/// Simplify ARM64 MADD/MSUB (Multiply-Add/Subtract) patterns.
///
/// ARM64 has fused multiply-add/subtract instructions:
/// - MADD: Rd = Ra + Rn * Rm
/// - MSUB: Rd = Ra - Rn * Rm
/// - MUL: Rd = Rn * Rm (MADD with Ra = XZR)
/// - MNEG: Rd = -(Rn * Rm) (MSUB with Ra = XZR)
///
/// This function simplifies:
/// - `a + b * c` => madd(a, b, c) (if not already simplified)
/// - `a - b * c` => msub(a, b, c)
/// - `-(b * c)` => mneg(b, c)
fn simplify_arm64_madd_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: a + b * c => fma(b, c, a) for floating-point or madd(b, c, a) for integer
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left: addend,
        right: product,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: mul_left,
            right: mul_right,
        } = &product.kind
        {
            // a + b * c => madd(b, c, a)
            return Some(Expr::call(
                CallTarget::Named("madd".to_string()),
                vec![
                    mul_left.as_ref().clone(),
                    mul_right.as_ref().clone(),
                    addend.as_ref().clone(),
                ],
            ));
        }

        // Also check left side for multiplication: b * c + a
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: mul_left,
            right: mul_right,
        } = &addend.kind
        {
            return Some(Expr::call(
                CallTarget::Named("madd".to_string()),
                vec![
                    mul_left.as_ref().clone(),
                    mul_right.as_ref().clone(),
                    product.as_ref().clone(),
                ],
            ));
        }
    }

    // Pattern: a - b * c => msub(b, c, a)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left: minuend,
        right: product,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: mul_left,
            right: mul_right,
        } = &product.kind
        {
            return Some(Expr::call(
                CallTarget::Named("msub".to_string()),
                vec![
                    mul_left.as_ref().clone(),
                    mul_right.as_ref().clone(),
                    minuend.as_ref().clone(),
                ],
            ));
        }
    }

    // Pattern: 0 - b * c => mneg(b, c) or -(b * c)
    if let ExprKind::UnaryOp {
        op: UnaryOpKind::Neg,
        operand,
    } = &expr.kind
    {
        if let ExprKind::BinOp {
            op: BinOpKind::Mul,
            left: mul_left,
            right: mul_right,
        } = &operand.kind
        {
            return Some(Expr::call(
                CallTarget::Named("mneg".to_string()),
                vec![mul_left.as_ref().clone(), mul_right.as_ref().clone()],
            ));
        }
    }

    None
}

// === RISC-V pseudo-instruction patterns ===

/// Simplify RISC-V pseudo-instruction patterns.
///
/// RISC-V has many pseudo-instructions that are recognized by assemblers:
/// - NOP: addi x0, x0, 0
/// - LI rd, imm: Load immediate (lui + addi for large values)
/// - MV rd, rs: addi rd, rs, 0
/// - NOT rd, rs: xori rd, rs, -1
/// - NEG rd, rs: sub rd, x0, rs
/// - SEQZ rd, rs: sltiu rd, rs, 1
/// - SNEZ rd, rs: sltu rd, x0, rs
/// - SLTZ rd, rs: slt rd, rs, x0
/// - SGTZ rd, rs: slt rd, x0, rs
fn simplify_riscv_pseudo_pattern(expr: &Expr) -> Option<Expr> {
    // Pattern: x ^ -1 => ~x (NOT pseudo-instruction)
    if let ExprKind::BinOp {
        op: BinOpKind::Xor,
        left,
        right,
    } = &expr.kind
    {
        if is_neg_one(right) {
            return Some(Expr::unary(UnaryOpKind::Not, left.as_ref().clone()));
        }
        if is_neg_one(left) {
            return Some(Expr::unary(UnaryOpKind::Not, right.as_ref().clone()));
        }
    }

    // Pattern: 0 - x => -x (NEG pseudo-instruction)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(left) {
            return Some(Expr::unary(UnaryOpKind::Neg, right.as_ref().clone()));
        }
    }

    // Pattern: x + 0 => x (MV pseudo from addi rd, rs, 0)
    // Pattern: x | 0 => x (ORI identity)
    if let ExprKind::BinOp {
        op: BinOpKind::Add | BinOpKind::Or,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(right) {
            return Some(left.as_ref().clone());
        }
        if is_zero(left) {
            return Some(right.as_ref().clone());
        }
    }

    // Pattern: (x < 1) unsigned => x == 0 (SEQZ: sltiu rd, rs, 1)
    if let ExprKind::BinOp {
        op: BinOpKind::ULt,
        left,
        right,
    } = &expr.kind
    {
        if is_one(right) {
            return Some(Expr::binop(
                BinOpKind::Eq,
                left.as_ref().clone(),
                Expr::int(0),
            ));
        }
    }

    // Pattern: (0 < x) unsigned => x != 0 (SNEZ: sltu rd, x0, rs)
    if let ExprKind::BinOp {
        op: BinOpKind::ULt,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(left) {
            return Some(Expr::binop(
                BinOpKind::Ne,
                right.as_ref().clone(),
                Expr::int(0),
            ));
        }
    }

    // Pattern: lui + addi combination for large constants
    // This is typically handled at a higher level during instruction lifting

    None
}

/// Simplify RISC-V LUI+ADDI pattern for loading large immediates.
///
/// LI pseudo-instruction for values > 12 bits:
/// lui rd, imm[31:12]
/// addi rd, rd, imm[11:0]
///
/// This pattern appears as: (upper << 12) + lower
pub fn simplify_riscv_li_pattern(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    {
        // Pattern: (const << 12) + small_const
        if let ExprKind::BinOp {
            op: BinOpKind::Shl,
            left: upper_val,
            right: shift_amt,
        } = &left.kind
        {
            if let (ExprKind::IntLit(upper), ExprKind::IntLit(12)) =
                (&upper_val.kind, &shift_amt.kind)
            {
                if let ExprKind::IntLit(lower) = &right.kind {
                    // Combine into single immediate
                    let combined = (upper << 12) + lower;
                    return Some(Expr::int(combined));
                }
            }
        }
    }

    None
}

// === Helper functions ===

fn is_zero(expr: &Expr) -> bool {
    matches!(expr.kind, ExprKind::IntLit(0))
}

fn is_one(expr: &Expr) -> bool {
    matches!(expr.kind, ExprKind::IntLit(1))
}

fn is_neg_one(expr: &Expr) -> bool {
    matches!(expr.kind, ExprKind::IntLit(-1))
}

fn is_eq_zero_check(expr: &Expr) -> bool {
    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        right,
        ..
    } = &expr.kind
    {
        return is_zero(right);
    }
    false
}

fn is_neq_zero_check(expr: &Expr) -> bool {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        right,
        ..
    } = &expr.kind
    {
        return is_zero(right);
    }
    false
}

fn extract_eq_zero_var(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(right) {
            return Some(left.as_ref().clone());
        }
        if is_zero(left) {
            return Some(right.as_ref().clone());
        }
    }
    None
}

fn extract_neq_zero_var(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(right) {
            return Some(left.as_ref().clone());
        }
        if is_zero(left) {
            return Some(right.as_ref().clone());
        }
    }
    None
}

fn extract_lt_zero_var(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Lt,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(right) {
            return Some(left.as_ref().clone());
        }
    }
    None
}

fn extract_ge_zero_var(expr: &Expr) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ge,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(right) {
            return Some(left.as_ref().clone());
        }
    }
    None
}

fn extract_lt_comparison(expr: &Expr) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Lt,
        left,
        right,
    } = &expr.kind
    {
        return Some((left.as_ref().clone(), right.as_ref().clone()));
    }
    None
}

fn extract_gt_comparison(expr: &Expr) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Gt,
        left,
        right,
    } = &expr.kind
    {
        return Some((left.as_ref().clone(), right.as_ref().clone()));
    }
    None
}

fn extract_le_comparison(expr: &Expr) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Le,
        left,
        right,
    } = &expr.kind
    {
        return Some((left.as_ref().clone(), right.as_ref().clone()));
    }
    None
}

fn extract_ge_comparison(expr: &Expr) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ge,
        left,
        right,
    } = &expr.kind
    {
        return Some((left.as_ref().clone(), right.as_ref().clone()));
    }
    None
}

fn is_negation_of(x: &Expr, expr: &Expr) -> bool {
    if let ExprKind::UnaryOp {
        op: UnaryOpKind::Neg,
        operand,
    } = &expr.kind
    {
        return exprs_equal(x, operand);
    }
    // Also check for 0 - x
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left,
        right,
    } = &expr.kind
    {
        if is_zero(left) && exprs_equal(x, right) {
            return true;
        }
    }
    false
}

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
        (ExprKind::Deref { addr: i1, .. }, ExprKind::Deref { addr: i2, .. }) => exprs_equal(i1, i2),
        (
            ExprKind::ArrayAccess {
                base: b1,
                index: i1,
                ..
            },
            ExprKind::ArrayAccess {
                base: b2,
                index: i2,
                ..
            },
        ) => exprs_equal(b1, b2) && exprs_equal(i1, i2),
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
    fn test_simplify_csel_bool() {
        // cond ? 1 : 0  =>  (bool)cond
        let cond = Expr::binop(BinOpKind::Lt, make_var("x"), make_var("y"));
        let expr = make_conditional(cond, Expr::int(1), Expr::int(0));

        let simplified = simplify_csel_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            assert!(matches!(s.kind, ExprKind::Cast { .. }));
        }
    }

    #[test]
    fn test_simplify_abs_pattern() {
        // x < 0 ? -x : x  =>  abs(x)
        let x = make_var("x");
        let cond = Expr::binop(BinOpKind::Lt, x.clone(), Expr::int(0));
        let neg_x = Expr::unary(UnaryOpKind::Neg, x.clone());
        let expr = make_conditional(cond, neg_x, x);

        let simplified = simplify_abs_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "abs");
            }
        }
    }

    #[test]
    fn test_simplify_min_pattern() {
        // a < b ? a : b  =>  min(a, b)
        let a = make_var("a");
        let b = make_var("b");
        let cond = Expr::binop(BinOpKind::Lt, a.clone(), b.clone());
        let expr = make_conditional(cond, a, b);

        let simplified = simplify_min_max_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "min");
            }
        }
    }

    #[test]
    fn test_simplify_max_pattern() {
        // a > b ? a : b  =>  max(a, b)
        let a = make_var("a");
        let b = make_var("b");
        let cond = Expr::binop(BinOpKind::Gt, a.clone(), b.clone());
        let expr = make_conditional(cond, a, b);

        let simplified = simplify_min_max_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "max");
            }
        }
    }

    #[test]
    fn test_simplify_rotate_left() {
        // (x << 8) | (x >> 24) => rotl(x, 8) for 32-bit
        let x = make_var("x");
        let shl = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(8));
        let shr = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(24));
        let expr = Expr::binop(BinOpKind::Or, shl, shr);

        let simplified = simplify_rotate_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "rotl");
                assert_eq!(args.len(), 2);
            }
        }
    }

    #[test]
    fn test_simplify_rotate_right() {
        // (x >> 8) | (x << 24) => rotr(x, 8) for 32-bit
        let x = make_var("x");
        let shr = Expr::binop(BinOpKind::Shr, x.clone(), Expr::int(8));
        let shl = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(24));
        let expr = Expr::binop(BinOpKind::Or, shr, shl);

        let simplified = simplify_rotate_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "rotr");
            }
        }
    }

    #[test]
    fn test_simplify_multiply_by_3() {
        // x + (x << 1) => x * 3
        let x = make_var("x");
        let shifted = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(1));
        let expr = Expr::binop(BinOpKind::Add, x.clone(), shifted);

        let simplified = simplify_multiply_constant_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::BinOp {
                op: BinOpKind::Mul,
                right,
                ..
            } = &s.kind
            {
                assert!(matches!(right.kind, ExprKind::IntLit(3)));
            }
        }
    }

    #[test]
    fn test_simplify_multiply_by_7() {
        // (x << 3) - x => x * 7
        let x = make_var("x");
        let shifted = Expr::binop(BinOpKind::Shl, x.clone(), Expr::int(3));
        let expr = Expr::binop(BinOpKind::Sub, shifted, x.clone());

        let simplified = simplify_multiply_constant_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::BinOp {
                op: BinOpKind::Mul,
                right,
                ..
            } = &s.kind
            {
                assert!(matches!(right.kind, ExprKind::IntLit(7)));
            }
        }
    }

    #[test]
    fn test_simplify_clamp() {
        // min(max(x, 0), 255) => clamp(x, 0, 255)
        let x = make_var("x");
        let inner = Expr::call(
            CallTarget::Named("max".to_string()),
            vec![x.clone(), Expr::int(0)],
        );
        let expr = Expr::call(
            CallTarget::Named("min".to_string()),
            vec![inner, Expr::int(255)],
        );

        let simplified = simplify_clamp_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "clamp");
                assert_eq!(args.len(), 3);
            }
        }
    }

    // === ARM64 CSINC/MADD pattern tests ===

    #[test]
    fn test_simplify_arm64_cinc() {
        // cond ? x + 1 : x => cinc(x, cond)
        let x = make_var("x");
        let cond = Expr::binop(BinOpKind::Lt, make_var("a"), make_var("b"));
        let x_plus_1 = Expr::binop(BinOpKind::Add, x.clone(), Expr::int(1));
        let expr = make_conditional(cond.clone(), x_plus_1, x.clone());

        let simplified = simplify_arm64_csinc_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "cinc");
                assert_eq!(args.len(), 2);
            }
        }
    }

    #[test]
    fn test_simplify_arm64_cinv() {
        // cond ? ~x : x => cinv(x, cond)
        let x = make_var("x");
        let cond = Expr::binop(BinOpKind::Eq, make_var("a"), Expr::int(0));
        let not_x = Expr::unary(UnaryOpKind::Not, x.clone());
        let expr = make_conditional(cond.clone(), not_x, x.clone());

        let simplified = simplify_arm64_csinc_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "cinv");
            }
        }
    }

    #[test]
    fn test_simplify_arm64_cneg() {
        // cond ? -x : x => cneg(x, cond)
        let x = make_var("x");
        let cond = Expr::binop(BinOpKind::Lt, make_var("a"), Expr::int(0));
        let neg_x = Expr::unary(UnaryOpKind::Neg, x.clone());
        let expr = make_conditional(cond.clone(), neg_x, x.clone());

        let simplified = simplify_arm64_csinc_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } = &s.kind
            {
                assert_eq!(name, "cneg");
            }
        }
    }

    #[test]
    fn test_simplify_arm64_csetm() {
        // cond ? -1 : 0 => csetm(cond)
        let cond = Expr::binop(BinOpKind::Eq, make_var("x"), Expr::int(0));
        let expr = make_conditional(cond.clone(), Expr::int(-1), Expr::int(0));

        let simplified = simplify_arm64_csinc_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "csetm");
                assert_eq!(args.len(), 1);
            }
        }
    }

    #[test]
    fn test_simplify_arm64_madd() {
        // a + b * c => madd(b, c, a)
        let a = make_var("a");
        let b = make_var("b");
        let c = make_var("c");
        let product = Expr::binop(BinOpKind::Mul, b.clone(), c.clone());
        let expr = Expr::binop(BinOpKind::Add, a.clone(), product);

        let simplified = simplify_arm64_madd_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "madd");
                assert_eq!(args.len(), 3);
            }
        }
    }

    #[test]
    fn test_simplify_arm64_msub() {
        // a - b * c => msub(b, c, a)
        let a = make_var("a");
        let b = make_var("b");
        let c = make_var("c");
        let product = Expr::binop(BinOpKind::Mul, b.clone(), c.clone());
        let expr = Expr::binop(BinOpKind::Sub, a.clone(), product);

        let simplified = simplify_arm64_madd_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "msub");
                assert_eq!(args.len(), 3);
            }
        }
    }

    #[test]
    fn test_simplify_arm64_mneg() {
        // -(b * c) => mneg(b, c)
        let b = make_var("b");
        let c = make_var("c");
        let product = Expr::binop(BinOpKind::Mul, b.clone(), c.clone());
        let expr = Expr::unary(UnaryOpKind::Neg, product);

        let simplified = simplify_arm64_madd_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } = &s.kind
            {
                assert_eq!(name, "mneg");
                assert_eq!(args.len(), 2);
            }
        }
    }

    // === RISC-V pseudo-instruction pattern tests ===

    #[test]
    fn test_simplify_riscv_not() {
        // x ^ -1 => ~x (NOT pseudo-instruction)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::Xor, x.clone(), Expr::int(-1));

        let simplified = simplify_riscv_pseudo_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::UnaryOp {
                op: UnaryOpKind::Not,
                ..
            } = &s.kind
            {
                // Correct!
            } else {
                panic!("Expected NOT unary op");
            }
        }
    }

    #[test]
    fn test_simplify_riscv_neg() {
        // 0 - x => -x (NEG pseudo-instruction)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::Sub, Expr::int(0), x.clone());

        let simplified = simplify_riscv_pseudo_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::UnaryOp {
                op: UnaryOpKind::Neg,
                ..
            } = &s.kind
            {
                // Correct!
            } else {
                panic!("Expected NEG unary op");
            }
        }
    }

    #[test]
    fn test_simplify_riscv_mv() {
        // x + 0 => x (MV pseudo from addi rd, rs, 0)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::Add, x.clone(), Expr::int(0));

        let simplified = simplify_riscv_pseudo_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::Var(v) = &s.kind {
                assert_eq!(v.name, "x");
            } else {
                panic!("Expected variable x");
            }
        }
    }

    #[test]
    fn test_simplify_riscv_seqz() {
        // (x < 1) unsigned => x == 0 (SEQZ: sltiu rd, rs, 1)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::ULt, x.clone(), Expr::int(1));

        let simplified = simplify_riscv_pseudo_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::BinOp {
                op: BinOpKind::Eq,
                left,
                right,
            } = &s.kind
            {
                if let (ExprKind::Var(v), ExprKind::IntLit(0)) = (&left.kind, &right.kind) {
                    assert_eq!(v.name, "x");
                } else {
                    panic!("Expected x == 0");
                }
            } else {
                panic!("Expected equality comparison");
            }
        }
    }

    #[test]
    fn test_simplify_riscv_snez() {
        // (0 < x) unsigned => x != 0 (SNEZ: sltu rd, x0, rs)
        let x = make_var("x");
        let expr = Expr::binop(BinOpKind::ULt, Expr::int(0), x.clone());

        let simplified = simplify_riscv_pseudo_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::BinOp {
                op: BinOpKind::Ne,
                left,
                right,
            } = &s.kind
            {
                if let (ExprKind::Var(v), ExprKind::IntLit(0)) = (&left.kind, &right.kind) {
                    assert_eq!(v.name, "x");
                } else {
                    panic!("Expected x != 0");
                }
            } else {
                panic!("Expected inequality comparison");
            }
        }
    }

    #[test]
    fn test_simplify_riscv_li_pattern() {
        // (upper << 12) + lower => combined constant (LUI+ADDI)
        let expr = Expr::binop(
            BinOpKind::Add,
            Expr::binop(BinOpKind::Shl, Expr::int(0x12345), Expr::int(12)),
            Expr::int(0x678),
        );

        let simplified = simplify_riscv_li_pattern(&expr);
        assert!(simplified.is_some());
        if let Some(s) = simplified {
            if let ExprKind::IntLit(value) = &s.kind {
                // 0x12345 << 12 = 0x12345000, + 0x678 = 0x12345678
                assert_eq!(*value, 0x12345678);
            } else {
                panic!("Expected integer literal");
            }
        }
    }
}
