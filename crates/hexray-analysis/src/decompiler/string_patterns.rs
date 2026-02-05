//! String function pattern detection.
//!
//! Detects common string operation patterns in loops and replaces them with
//! calls to standard library functions like strlen, strcmp, strcpy, etc.

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind, VarKind, Variable};
use super::for_loop_detection::get_expr_var_key;
use super::structurer::StructuredNode;

/// Detected string operation pattern.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some variants are for future use
pub enum StringPattern {
    /// strlen(s): counts characters until null terminator
    Strlen {
        string: Expr,
        result: Option<String>,
    },
    /// strcmp(s1, s2): compares two strings character by character
    Strcmp {
        string1: Expr,
        string2: Expr,
        result: Option<String>,
    },
    /// strcpy(dst, src): copies string from src to dst
    Strcpy { dst: Expr, src: Expr },
    /// strcat(dst, src): appends src to end of dst
    Strcat { dst: Expr, src: Expr },
    /// memchr(s, c, n): finds first occurrence of c in s
    Memchr {
        haystack: Expr,
        needle: Expr,
        size: Expr,
    },
    /// strchr(s, c): finds first occurrence of c in string
    Strchr { string: Expr, char: Expr },
}

/// Detects string patterns in structured nodes.
pub fn detect_string_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().flat_map(detect_in_node).collect()
}

fn detect_in_node(node: StructuredNode) -> Vec<StructuredNode> {
    match node {
        // Check for loops - most string patterns are in loops
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            // Try to detect strlen pattern
            if let Some(pattern) = detect_strlen_pattern(&init, &condition, &update, &body) {
                return vec![pattern_to_node(pattern)];
            }

            // Try to detect strcpy pattern
            if let Some(pattern) = detect_strcpy_pattern(&init, &condition, &update, &body) {
                return vec![pattern_to_node(pattern)];
            }

            // Try to detect strcmp pattern
            if let Some(pattern) = detect_strcmp_pattern(&init, &condition, &update, &body) {
                return vec![pattern_to_node(pattern)];
            }

            // No pattern found, recurse into body
            vec![StructuredNode::For {
                init,
                condition,
                update,
                body: detect_string_patterns(body),
                header,
                exit_block,
            }]
        }

        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => {
            // Try to detect strlen pattern in while loop
            if let Some(pattern) = detect_strlen_while(&condition, &body) {
                return vec![pattern_to_node(pattern)];
            }

            // Try to detect strcpy pattern in while loop
            if let Some(pattern) = detect_strcpy_while(&condition, &body) {
                return vec![pattern_to_node(pattern)];
            }

            vec![StructuredNode::While {
                condition,
                body: detect_string_patterns(body),
                header,
                exit_block,
            }]
        }

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => {
            // Try to detect strcpy in do-while
            if let Some(pattern) = detect_strcpy_dowhile(&body, &condition) {
                return vec![pattern_to_node(pattern)];
            }

            vec![StructuredNode::DoWhile {
                body: detect_string_patterns(body),
                condition,
                header,
                exit_block,
            }]
        }

        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => vec![StructuredNode::If {
            condition,
            then_body: detect_string_patterns(then_body),
            else_body: else_body.map(detect_string_patterns),
        }],

        StructuredNode::Loop {
            body,
            header,
            exit_block,
        } => vec![StructuredNode::Loop {
            body: detect_string_patterns(body),
            header,
            exit_block,
        }],

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => vec![StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_string_patterns(body)))
                .collect(),
            default: default.map(detect_string_patterns),
        }],

        StructuredNode::Sequence(nodes) => {
            vec![StructuredNode::Sequence(detect_string_patterns(nodes))]
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => vec![StructuredNode::TryCatch {
            try_body: detect_string_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|h| super::structurer::CatchHandler {
                    body: detect_string_patterns(h.body),
                    ..h
                })
                .collect(),
        }],

        other => vec![other],
    }
}

/// Detect strlen pattern: for (i = 0; s[i] != 0; i++) {}
fn detect_strlen_pattern(
    init: &Option<Expr>,
    condition: &Expr,
    update: &Option<Expr>,
    body: &[StructuredNode],
) -> Option<StringPattern> {
    // Check init: i = 0
    let init = init.as_ref()?;
    let loop_var = extract_init_var_if_zero(init)?;

    // Check update: i++ or i = i + 1
    let update = update.as_ref()?;
    if !is_increment_of(&loop_var, update) {
        return None;
    }

    // Check condition: s[i] != 0 or *(s + i) != 0
    let string_base = extract_string_nz_check(condition, &loop_var)?;

    // Check body is empty (pure strlen)
    if !body.is_empty() && !is_empty_body(body) {
        return None;
    }

    Some(StringPattern::Strlen {
        string: string_base,
        result: Some(loop_var),
    })
}

/// Detect strlen in while loop: while (s[i] != 0) i++;
fn detect_strlen_while(condition: &Expr, body: &[StructuredNode]) -> Option<StringPattern> {
    // Look for pattern: while (*p != 0) p++;
    // or: while (s[i] != 0) i++;

    // Check if body is just an increment
    if body.len() != 1 {
        return None;
    }

    let (incr_var, is_ptr_incr) = extract_increment_stmt(&body[0])?;

    if is_ptr_incr {
        // Pattern: while (*p != 0) p++;
        let ptr_var = extract_ptr_deref_nz_check(condition)?;
        if ptr_var == incr_var {
            return Some(StringPattern::Strlen {
                string: Expr::var(Variable {
                    name: ptr_var.clone(),
                    kind: VarKind::Register(0),
                    size: 8,
                }),
                result: None,
            });
        }
    } else {
        // Pattern: while (s[i] != 0) i++;
        let string_base = extract_string_nz_check(condition, &incr_var)?;
        return Some(StringPattern::Strlen {
            string: string_base,
            result: Some(incr_var),
        });
    }

    None
}

/// Detect strcpy pattern: for (i = 0; (dst[i] = src[i]) != 0; i++) {}
fn detect_strcpy_pattern(
    init: &Option<Expr>,
    condition: &Expr,
    update: &Option<Expr>,
    body: &[StructuredNode],
) -> Option<StringPattern> {
    // Check init: i = 0
    let init = init.as_ref()?;
    let loop_var = extract_init_var_if_zero(init)?;

    // Check update: i++
    let update = update.as_ref()?;
    if !is_increment_of(&loop_var, update) {
        return None;
    }

    // Check for strcpy in condition or body
    // Pattern 1: condition is (dst[i] = src[i]) != 0
    if let Some((dst, src)) = extract_copy_nz_check(condition, &loop_var) {
        if is_empty_body(body) {
            return Some(StringPattern::Strcpy { dst, src });
        }
    }

    // Pattern 2: body has dst[i] = src[i], condition is src[i] != 0
    if let Some(string_base) = extract_string_nz_check(condition, &loop_var) {
        if let Some(dst) = extract_copy_to_indexed(body, &loop_var) {
            return Some(StringPattern::Strcpy {
                dst,
                src: string_base,
            });
        }
    }

    None
}

/// Detect strcpy in while loop: while ((*dst++ = *src++) != 0) {}
fn detect_strcpy_while(condition: &Expr, body: &[StructuredNode]) -> Option<StringPattern> {
    // Check for: while ((*dst++ = *src++) != 0)
    // or: while ((dst[i] = src[i]) != 0) with i++ in body

    // Simple case: condition contains the copy with post-increment
    if let Some((dst, src)) = extract_ptr_copy_nz_check(condition) {
        if is_empty_body(body) {
            return Some(StringPattern::Strcpy { dst, src });
        }
    }

    None
}

/// Detect strcpy in do-while: do { *dst++ = *src++; } while (c != 0);
fn detect_strcpy_dowhile(body: &[StructuredNode], condition: &Expr) -> Option<StringPattern> {
    // Check body for copy statement
    if body.len() != 1 {
        return None;
    }

    if let Some((dst, src, copied_var)) = extract_copy_stmt(&body[0]) {
        // Check if condition tests the copied character
        if is_var_nz_check(condition, &copied_var) {
            return Some(StringPattern::Strcpy { dst, src });
        }
    }

    None
}

/// Detect strcmp pattern
fn detect_strcmp_pattern(
    init: &Option<Expr>,
    condition: &Expr,
    update: &Option<Expr>,
    _body: &[StructuredNode],
) -> Option<StringPattern> {
    // Check init: i = 0
    let init = init.as_ref()?;
    let loop_var = extract_init_var_if_zero(init)?;

    // Check update: i++
    let update = update.as_ref()?;
    if !is_increment_of(&loop_var, update) {
        return None;
    }

    // Check condition: s1[i] == s2[i] && s1[i] != 0
    // Or just s1[i] == s2[i] with break on s1[i] == 0 in body
    if let Some((s1, s2)) = extract_string_eq_check(condition, &loop_var) {
        return Some(StringPattern::Strcmp {
            string1: s1,
            string2: s2,
            result: None,
        });
    }

    None
}

// === Helper functions ===

/// Extract variable name if init is `var = 0`.
fn extract_init_var_if_zero(init: &Expr) -> Option<String> {
    if let ExprKind::Assign { lhs, rhs } = &init.kind {
        if let ExprKind::IntLit(0) = rhs.kind {
            return get_expr_var_key(lhs);
        }
    }
    None
}

/// Check if expression is `var++` or `var = var + 1`.
fn is_increment_of(var: &str, expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::UnaryOp {
            op: UnaryOpKind::Inc,
            operand,
        } => get_expr_var_key(operand).as_deref() == Some(var),
        ExprKind::Assign { lhs, rhs } => {
            if get_expr_var_key(lhs).as_deref() != Some(var) {
                return false;
            }
            // Check for var + 1
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } = &rhs.kind
            {
                let left_is_var = get_expr_var_key(left).as_deref() == Some(var);
                let right_is_one = matches!(right.kind, ExprKind::IntLit(1));
                let right_is_var = get_expr_var_key(right).as_deref() == Some(var);
                let left_is_one = matches!(left.kind, ExprKind::IntLit(1));
                return (left_is_var && right_is_one) || (right_is_var && left_is_one);
            }
            false
        }
        ExprKind::CompoundAssign {
            op: BinOpKind::Add,
            lhs,
            rhs,
        } => {
            get_expr_var_key(lhs).as_deref() == Some(var) && matches!(rhs.kind, ExprKind::IntLit(1))
        }
        _ => false,
    }
}

/// Extract string base from `s[i] != 0` or `*(s + i) != 0`.
fn extract_string_nz_check(condition: &Expr, loop_var: &str) -> Option<Expr> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        // Check for comparison to 0
        let (access_expr, zero_expr) = if matches!(right.kind, ExprKind::IntLit(0)) {
            (left.as_ref(), right.as_ref())
        } else if matches!(left.kind, ExprKind::IntLit(0)) {
            (right.as_ref(), left.as_ref())
        } else {
            return None;
        };

        let _ = zero_expr; // Silence unused warning

        // Extract base from s[i] or *(s + i)
        return extract_indexed_base(access_expr, loop_var);
    }
    None
}

/// Extract base from array access `s[i]` or pointer arithmetic `*(s + i)`.
fn extract_indexed_base(expr: &Expr, loop_var: &str) -> Option<Expr> {
    match &expr.kind {
        ExprKind::ArrayAccess { base, index, .. } => {
            if get_expr_var_key(index).as_deref() == Some(loop_var) {
                return Some((**base).clone());
            }
        }
        ExprKind::Deref { addr, .. } => {
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } = &addr.kind
            {
                if get_expr_var_key(right).as_deref() == Some(loop_var) {
                    return Some((**left).clone());
                }
                if get_expr_var_key(left).as_deref() == Some(loop_var) {
                    return Some((**right).clone());
                }
            }
        }
        _ => {}
    }
    None
}

/// Extract pointer variable from `*p != 0`.
fn extract_ptr_deref_nz_check(condition: &Expr) -> Option<String> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        let deref_expr = if matches!(right.kind, ExprKind::IntLit(0)) {
            left.as_ref()
        } else if matches!(left.kind, ExprKind::IntLit(0)) {
            right.as_ref()
        } else {
            return None;
        };

        if let ExprKind::Deref { addr, .. } = &deref_expr.kind {
            return get_expr_var_key(addr);
        }
    }
    None
}

/// Extract (dst, src) from `(dst[i] = src[i]) != 0`.
fn extract_copy_nz_check(condition: &Expr, loop_var: &str) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        let assign_expr = if matches!(right.kind, ExprKind::IntLit(0)) {
            left.as_ref()
        } else if matches!(left.kind, ExprKind::IntLit(0)) {
            right.as_ref()
        } else {
            return None;
        };

        if let ExprKind::Assign { lhs, rhs } = &assign_expr.kind {
            let dst = extract_indexed_base(lhs, loop_var)?;
            let src = extract_indexed_base(rhs, loop_var)?;
            return Some((dst, src));
        }
    }
    None
}

/// Extract (dst, src) from pointer copy with nz check.
fn extract_ptr_copy_nz_check(condition: &Expr) -> Option<(Expr, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        let assign_expr = if matches!(right.kind, ExprKind::IntLit(0)) {
            left.as_ref()
        } else if matches!(left.kind, ExprKind::IntLit(0)) {
            right.as_ref()
        } else {
            return None;
        };

        if let ExprKind::Assign { lhs, rhs } = &assign_expr.kind {
            // Check for *dst++ = *src++ pattern
            if let (
                ExprKind::Deref { addr: dst_addr, .. },
                ExprKind::Deref { addr: src_addr, .. },
            ) = (&lhs.kind, &rhs.kind)
            {
                // Extract base pointers (ignoring post-increment for now)
                let dst = extract_post_inc_base(dst_addr).unwrap_or_else(|| (**dst_addr).clone());
                let src = extract_post_inc_base(src_addr).unwrap_or_else(|| (**src_addr).clone());
                return Some((dst, src));
            }
        }
    }
    None
}

/// Extract base from post-increment expression.
fn extract_post_inc_base(expr: &Expr) -> Option<Expr> {
    if let ExprKind::UnaryOp {
        op: UnaryOpKind::Inc,
        operand,
    } = &expr.kind
    {
        return Some((**operand).clone());
    }
    None
}

/// Extract (s1, s2) from `s1[i] == s2[i]`.
fn extract_string_eq_check(condition: &Expr, loop_var: &str) -> Option<(Expr, Expr)> {
    // Handle s1[i] == s2[i] && s1[i] != 0
    if let ExprKind::BinOp {
        op: BinOpKind::LogicalAnd,
        left,
        right,
    } = &condition.kind
    {
        // Try both orders
        if let Some(result) = try_extract_strcmp_parts(left, right, loop_var) {
            return Some(result);
        }
        if let Some(result) = try_extract_strcmp_parts(right, left, loop_var) {
            return Some(result);
        }
    }

    // Handle just s1[i] == s2[i]
    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        left,
        right,
    } = &condition.kind
    {
        let s1 = extract_indexed_base(left, loop_var)?;
        let s2 = extract_indexed_base(right, loop_var)?;
        return Some((s1, s2));
    }

    None
}

fn try_extract_strcmp_parts(
    eq_part: &Expr,
    nz_part: &Expr,
    loop_var: &str,
) -> Option<(Expr, Expr)> {
    // eq_part should be s1[i] == s2[i]
    // nz_part should be s1[i] != 0 (or s2[i] != 0)
    if let ExprKind::BinOp {
        op: BinOpKind::Eq,
        left,
        right,
    } = &eq_part.kind
    {
        let s1 = extract_indexed_base(left, loop_var)?;
        let s2 = extract_indexed_base(right, loop_var)?;

        // Verify nz_part matches one of the strings
        if let Some(nz_base) = extract_string_nz_check(nz_part, loop_var) {
            if exprs_similar(&nz_base, &s1) || exprs_similar(&nz_base, &s2) {
                return Some((s1, s2));
            }
        }
    }
    None
}

/// Check if two expressions are similar (same structure).
fn exprs_similar(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(v1), ExprKind::Var(v2)) => v1.name == v2.name,
        (ExprKind::IntLit(n1), ExprKind::IntLit(n2)) => n1 == n2,
        _ => false,
    }
}

/// Check if body is empty or contains only empty nodes.
fn is_empty_body(body: &[StructuredNode]) -> bool {
    body.is_empty()
        || body.iter().all(|n| match n {
            StructuredNode::Block { statements, .. } => statements.is_empty(),
            StructuredNode::Sequence(nodes) => is_empty_body(nodes),
            _ => false,
        })
}

/// Extract increment statement: returns (var_name, is_pointer_increment).
fn extract_increment_stmt(node: &StructuredNode) -> Option<(String, bool)> {
    let expr = match node {
        StructuredNode::Expr(e) => e,
        StructuredNode::Block { statements, .. } if statements.len() == 1 => &statements[0],
        _ => return None,
    };

    match &expr.kind {
        ExprKind::UnaryOp {
            op: UnaryOpKind::Inc,
            operand,
        } => {
            let var = get_expr_var_key(operand)?;
            // Check if it's a pointer by looking at the type hint or name
            let is_ptr = var.starts_with("p") || var.contains("ptr");
            Some((var, is_ptr))
        }
        ExprKind::CompoundAssign {
            op: BinOpKind::Add,
            lhs,
            rhs,
        } if matches!(rhs.kind, ExprKind::IntLit(1)) => {
            let var = get_expr_var_key(lhs)?;
            Some((var, false))
        }
        _ => None,
    }
}

/// Extract destination from a copy-to-indexed pattern.
fn extract_copy_to_indexed(body: &[StructuredNode], _loop_var: &str) -> Option<Expr> {
    // Look for dst[i] = <something>
    if body.len() != 1 {
        return None;
    }

    let expr = match &body[0] {
        StructuredNode::Expr(e) => e,
        StructuredNode::Block { statements, .. } if statements.len() == 1 => &statements[0],
        _ => return None,
    };

    if let ExprKind::Assign { lhs, .. } = &expr.kind {
        // Just return the base of the destination
        if let ExprKind::ArrayAccess { base, .. } = &lhs.kind {
            return Some((**base).clone());
        }
    }

    None
}

/// Extract copy statement info: (dst_base, src_base, copied_var).
fn extract_copy_stmt(node: &StructuredNode) -> Option<(Expr, Expr, String)> {
    let expr = match node {
        StructuredNode::Expr(e) => e,
        StructuredNode::Block { statements, .. } if statements.len() == 1 => &statements[0],
        _ => return None,
    };

    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
        // Pattern: *dst++ = c = *src++
        // Or: c = *src++; *dst++ = c
        // For now, just extract dst and src from pointer derefs
        if let (ExprKind::Deref { addr: dst_addr, .. }, ExprKind::Deref { addr: src_addr, .. }) =
            (&lhs.kind, &rhs.kind)
        {
            let dst_base = extract_post_inc_base(dst_addr).unwrap_or_else(|| (**dst_addr).clone());
            let src_base = extract_post_inc_base(src_addr).unwrap_or_else(|| (**src_addr).clone());
            // Use a placeholder for the copied variable
            return Some((dst_base, src_base, "_c".to_string()));
        }
    }

    None
}

/// Check if condition is `var != 0`.
fn is_var_nz_check(condition: &Expr, var: &str) -> bool {
    if let ExprKind::BinOp {
        op: BinOpKind::Ne,
        left,
        right,
    } = &condition.kind
    {
        let (var_expr, zero_expr) = if matches!(right.kind, ExprKind::IntLit(0)) {
            (left.as_ref(), right.as_ref())
        } else if matches!(left.kind, ExprKind::IntLit(0)) {
            (right.as_ref(), left.as_ref())
        } else {
            return false;
        };

        let _ = zero_expr;

        return get_expr_var_key(var_expr).as_deref() == Some(var);
    }
    false
}

/// Convert a detected pattern to a StructuredNode.
fn pattern_to_node(pattern: StringPattern) -> StructuredNode {
    match pattern {
        StringPattern::Strlen { string, result } => {
            let call = Expr::call(CallTarget::Named("strlen".to_string()), vec![string]);
            if let Some(result_var) = result {
                StructuredNode::Expr(Expr::assign(
                    Expr::var(Variable {
                        name: result_var,
                        kind: VarKind::Register(0),
                        size: 8,
                    }),
                    call,
                ))
            } else {
                StructuredNode::Expr(call)
            }
        }
        StringPattern::Strcmp {
            string1,
            string2,
            result,
        } => {
            let call = Expr::call(
                CallTarget::Named("strcmp".to_string()),
                vec![string1, string2],
            );
            if let Some(result_var) = result {
                StructuredNode::Expr(Expr::assign(
                    Expr::var(Variable {
                        name: result_var,
                        kind: VarKind::Register(0),
                        size: 4,
                    }),
                    call,
                ))
            } else {
                StructuredNode::Expr(call)
            }
        }
        StringPattern::Strcpy { dst, src } => StructuredNode::Expr(Expr::call(
            CallTarget::Named("strcpy".to_string()),
            vec![dst, src],
        )),
        StringPattern::Strcat { dst, src } => StructuredNode::Expr(Expr::call(
            CallTarget::Named("strcat".to_string()),
            vec![dst, src],
        )),
        StringPattern::Memchr {
            haystack,
            needle,
            size,
        } => StructuredNode::Expr(Expr::call(
            CallTarget::Named("memchr".to_string()),
            vec![haystack, needle, size],
        )),
        StringPattern::Strchr { string, char } => StructuredNode::Expr(Expr::call(
            CallTarget::Named("strchr".to_string()),
            vec![string, char],
        )),
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
    fn test_extract_init_var_if_zero() {
        let init = Expr::assign(make_var("i"), Expr::int(0));
        assert_eq!(extract_init_var_if_zero(&init), Some("i".to_string()));

        let init = Expr::assign(make_var("i"), Expr::int(5));
        assert_eq!(extract_init_var_if_zero(&init), None);
    }

    #[test]
    fn test_is_increment_of() {
        // i++
        let expr = Expr::unary(UnaryOpKind::Inc, make_var("i"));
        assert!(is_increment_of("i", &expr));
        assert!(!is_increment_of("j", &expr));

        // i = i + 1
        let expr = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );
        assert!(is_increment_of("i", &expr));

        // i += 1
        let expr = Expr {
            kind: ExprKind::CompoundAssign {
                op: BinOpKind::Add,
                lhs: Box::new(make_var("i")),
                rhs: Box::new(Expr::int(1)),
            },
        };
        assert!(is_increment_of("i", &expr));
    }

    #[test]
    fn test_is_empty_body() {
        assert!(is_empty_body(&[]));

        let empty_block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![],
            address_range: (0, 0),
        };
        assert!(is_empty_body(&[empty_block]));
    }

    #[test]
    fn test_strlen_pattern_detection() {
        // for (i = 0; s[i] != 0; i++) {}
        let init = Some(Expr::assign(make_var("i"), Expr::int(0)));
        let condition = Expr::binop(
            BinOpKind::Ne,
            Expr::array_access(make_var("s"), make_var("i"), 1),
            Expr::int(0),
        );
        let update = Some(Expr::unary(UnaryOpKind::Inc, make_var("i")));
        let body = vec![];

        let pattern = detect_strlen_pattern(&init, &condition, &update, &body);
        assert!(pattern.is_some());
        if let Some(StringPattern::Strlen { result, .. }) = pattern {
            assert_eq!(result, Some("i".to_string()));
        }
    }
}
