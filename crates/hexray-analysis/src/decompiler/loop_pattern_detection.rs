//! Loop pattern detection for memory operations.
//!
//! Detects common memory operation patterns in for loops and transforms them
//! into standard library function calls:
//!
//! - `for (i=0; i<n; i++) { dst[i] = src[i]; }` → `memcpy(dst, src, n)`
//! - `for (i=0; i<n; i++) { dst[i] = 0; }` → `memset(dst, 0, n)`
//! - `for (i=0; i<n; i++) { dst[i] = val; }` → `memset(dst, val, n)`

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::structurer::StructuredNode;

/// Detected memory operation pattern.
#[derive(Debug, Clone)]
enum LoopPattern {
    /// memcpy(dst, src, size)
    Memcpy { dst: Expr, src: Expr, size: Expr },
    /// memset(dst, value, size)
    Memset { dst: Expr, value: Expr, size: Expr },
    /// 2D memcpy: nested loops copying 2D arrays
    Memcpy2D {
        dst: Expr,
        src: Expr,
        rows: Expr,
        cols: Expr,
        element_size: usize,
    },
    /// 2D memset: nested loops filling 2D arrays
    Memset2D {
        dst: Expr,
        value: Expr,
        rows: Expr,
        cols: Expr,
        element_size: usize,
    },
}

/// Detects and transforms memory operation patterns in structured nodes.
pub fn detect_loop_patterns(nodes: Vec<StructuredNode>) -> Vec<StructuredNode> {
    nodes.into_iter().map(transform_node).collect()
}

/// Recursively transforms a node, detecting patterns in for loops.
fn transform_node(node: StructuredNode) -> StructuredNode {
    match node {
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            header,
            exit_block,
        } => {
            // First, try to detect 2D nested loop pattern (more specific)
            if let Some(pattern) =
                detect_2d_memory_pattern(init.as_ref(), &condition, update.as_ref(), &body)
            {
                // Transform to function call
                let call = pattern_to_call(pattern);
                return StructuredNode::Expr(call);
            }

            // Try to detect 1D memory pattern
            if let Some(pattern) =
                detect_memory_pattern(init.as_ref(), &condition, update.as_ref(), &body)
            {
                // Transform to function call
                let call = pattern_to_call(pattern);
                StructuredNode::Expr(call)
            } else {
                // No pattern found, recurse into body
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body: detect_loop_patterns(body),
                    header,
                    exit_block,
                }
            }
        }

        // Recurse into other node types
        StructuredNode::If {
            condition,
            then_body,
            else_body,
        } => StructuredNode::If {
            condition,
            then_body: detect_loop_patterns(then_body),
            else_body: else_body.map(detect_loop_patterns),
        },

        StructuredNode::While {
            condition,
            body,
            header,
            exit_block,
        } => StructuredNode::While {
            condition,
            body: detect_loop_patterns(body),
            header,
            exit_block,
        },

        StructuredNode::DoWhile {
            body,
            condition,
            header,
            exit_block,
        } => StructuredNode::DoWhile {
            body: detect_loop_patterns(body),
            condition,
            header,
            exit_block,
        },

        StructuredNode::Switch {
            value,
            cases,
            default,
        } => StructuredNode::Switch {
            value,
            cases: cases
                .into_iter()
                .map(|(vals, body)| (vals, detect_loop_patterns(body)))
                .collect(),
            default: default.map(detect_loop_patterns),
        },

        StructuredNode::Sequence(nodes) => StructuredNode::Sequence(detect_loop_patterns(nodes)),

        StructuredNode::Block {
            id,
            statements,
            address_range,
        } => StructuredNode::Block {
            id,
            statements,
            address_range,
        },

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => StructuredNode::TryCatch {
            try_body: detect_loop_patterns(try_body),
            catch_handlers: catch_handlers
                .into_iter()
                .map(|mut h| {
                    h.body = detect_loop_patterns(h.body);
                    h
                })
                .collect(),
        },

        // Pass through unchanged
        other => other,
    }
}

/// Detect 2D nested loop memory pattern.
/// Looks for:
/// ```text
/// for (i = 0; i < rows; i++) {
///     for (j = 0; j < cols; j++) {
///         dst[i * stride + j] = src[i * stride + j];  // or = constant
///     }
/// }
/// ```
fn detect_2d_memory_pattern(
    outer_init: Option<&Expr>,
    outer_condition: &Expr,
    outer_update: Option<&Expr>,
    outer_body: &[StructuredNode],
) -> Option<LoopPattern> {
    // Extract outer loop bounds (row iteration)
    let (outer_var, outer_start, rows) = extract_loop_bounds(outer_init?, outer_condition)?;
    if outer_start != 0 {
        return None;
    }
    if !is_simple_increment(outer_update?, &outer_var) {
        return None;
    }

    // Body should contain a single inner for loop
    let inner_for = extract_inner_for_loop(outer_body)?;
    let (inner_init, inner_condition, inner_update, inner_body) = inner_for;

    // Extract inner loop bounds (column iteration)
    let (inner_var, inner_start, cols) = extract_loop_bounds(inner_init?, inner_condition)?;
    if inner_start != 0 {
        return None;
    }
    if !is_simple_increment(inner_update?, &inner_var) {
        return None;
    }

    // Extract single assignment from inner body
    let assignment = extract_single_assignment(inner_body)?;

    // Analyze the assignment pattern for 2D access
    analyze_2d_assignment_pattern(&assignment, &outer_var, &inner_var, &rows, &cols)
}

/// Extract an inner for loop from a body if it's the only statement.
#[allow(clippy::type_complexity)]
fn extract_inner_for_loop(
    body: &[StructuredNode],
) -> Option<(Option<&Expr>, &Expr, Option<&Expr>, &[StructuredNode])> {
    if body.len() != 1 {
        return None;
    }

    match &body[0] {
        StructuredNode::For {
            init,
            condition,
            update,
            body: inner_body,
            ..
        } => Some((init.as_ref(), condition, update.as_ref(), inner_body)),
        StructuredNode::Sequence(nodes) if nodes.len() == 1 => extract_inner_for_loop(nodes),
        _ => None,
    }
}

/// Analyze 2D array access pattern.
fn analyze_2d_assignment_pattern(
    assignment: &Expr,
    outer_var: &str,
    inner_var: &str,
    rows: &Expr,
    cols: &Expr,
) -> Option<LoopPattern> {
    let (lhs, rhs) = match &assignment.kind {
        ExprKind::Assign { lhs, rhs } => (lhs, rhs),
        _ => return None,
    };

    // LHS must be a 2D array access: dst[i * stride + j] or dst[i][j]
    let (dst_base, dst_element_size) = extract_2d_array_access(lhs, outer_var, inner_var, cols)?;

    // Check RHS pattern
    // Pattern 1: 2D memcpy - src[i * stride + j]
    if let Some((src_base, src_element_size)) =
        extract_2d_array_access(rhs, outer_var, inner_var, cols)
    {
        if dst_element_size == src_element_size {
            return Some(LoopPattern::Memcpy2D {
                dst: dst_base,
                src: src_base,
                rows: rows.clone(),
                cols: cols.clone(),
                element_size: dst_element_size,
            });
        }
    }

    // Pattern 2: 2D memset - constant value
    if let Some(val) = get_const_value(rhs) {
        if (0..=255).contains(&val) {
            return Some(LoopPattern::Memset2D {
                dst: dst_base,
                value: Expr::int(val),
                rows: rows.clone(),
                cols: cols.clone(),
                element_size: dst_element_size,
            });
        }
    }

    // Pattern 3: 2D memset with loop-invariant value
    if is_loop_invariant_2d(rhs, outer_var, inner_var) && dst_element_size == 1 {
        return Some(LoopPattern::Memset2D {
            dst: dst_base,
            value: (**rhs).clone(),
            rows: rows.clone(),
            cols: cols.clone(),
            element_size: dst_element_size,
        });
    }

    None
}

/// Extract 2D array access pattern.
/// Handles patterns like:
/// - base[i * cols + j] (linearized access)
/// - base[i][j] (nested array access, less common in decompiled code)
fn extract_2d_array_access(
    expr: &Expr,
    outer_var: &str,
    inner_var: &str,
    cols: &Expr,
) -> Option<(Expr, usize)> {
    match &expr.kind {
        // Linearized access: *(base + (i * cols + j) * elem_size)
        ExprKind::Deref { addr, size } => {
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left: base,
                right: offset,
            } = &addr.kind
            {
                // Check for scaled offset: (i * cols + j) * elem_size
                if let Some((elem_size, index_expr)) = extract_scaled_index(offset) {
                    if is_2d_index_expr(&index_expr, outer_var, inner_var, cols) {
                        return Some(((**base).clone(), elem_size));
                    }
                }

                // Check for unscaled offset: i * cols + j
                if is_2d_index_expr(offset, outer_var, inner_var, cols) {
                    return Some(((**base).clone(), *size as usize));
                }
            }
            None
        }

        // Array access with linearized index
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            if is_2d_index_expr(index, outer_var, inner_var, cols) {
                return Some(((**base).clone(), *element_size));
            }
            None
        }

        _ => None,
    }
}

/// Extract scaled index: expr * scale_factor
fn extract_scaled_index(expr: &Expr) -> Option<(usize, Expr)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Mul,
        left,
        right,
    } = &expr.kind
    {
        if let Some(scale) = get_const_value(right) {
            return Some((scale as usize, (**left).clone()));
        }
        if let Some(scale) = get_const_value(left) {
            return Some((scale as usize, (**right).clone()));
        }
    }
    None
}

/// Check if an expression is a 2D index: outer_var * cols + inner_var
fn is_2d_index_expr(expr: &Expr, outer_var: &str, inner_var: &str, cols: &Expr) -> bool {
    // Pattern: outer_var * cols + inner_var
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &expr.kind
    {
        // Check: (outer_var * cols) + inner_var
        if get_var_name(right).as_deref() == Some(inner_var) {
            if let ExprKind::BinOp {
                op: BinOpKind::Mul,
                left: mul_left,
                right: mul_right,
            } = &left.kind
            {
                let left_is_outer = get_var_name(mul_left).as_deref() == Some(outer_var);
                let right_is_outer = get_var_name(mul_right).as_deref() == Some(outer_var);

                let left_is_cols = exprs_equal(mul_left, cols);
                let right_is_cols = exprs_equal(mul_right, cols);

                if (left_is_outer && right_is_cols) || (right_is_outer && left_is_cols) {
                    return true;
                }
            }
        }

        // Check: inner_var + (outer_var * cols)
        if get_var_name(left).as_deref() == Some(inner_var) {
            if let ExprKind::BinOp {
                op: BinOpKind::Mul,
                left: mul_left,
                right: mul_right,
            } = &right.kind
            {
                let left_is_outer = get_var_name(mul_left).as_deref() == Some(outer_var);
                let right_is_outer = get_var_name(mul_right).as_deref() == Some(outer_var);

                let left_is_cols = exprs_equal(mul_left, cols);
                let right_is_cols = exprs_equal(mul_right, cols);

                if (left_is_outer && right_is_cols) || (right_is_outer && left_is_cols) {
                    return true;
                }
            }
        }
    }
    false
}

/// Simple expression equality check.
fn exprs_equal(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::IntLit(va), ExprKind::IntLit(vb)) => va == vb,
        (ExprKind::Var(va), ExprKind::Var(vb)) => va.name == vb.name,
        _ => false, // Conservative: assume not equal for complex expressions
    }
}

/// Check if expression is loop-invariant with respect to both loop variables.
fn is_loop_invariant_2d(expr: &Expr, outer_var: &str, inner_var: &str) -> bool {
    is_loop_invariant(expr, outer_var) && is_loop_invariant(expr, inner_var)
}

/// Detect memory operation patterns in a for loop.
fn detect_memory_pattern(
    init: Option<&Expr>,
    condition: &Expr,
    update: Option<&Expr>,
    body: &[StructuredNode],
) -> Option<LoopPattern> {
    // Extract loop variable and bounds
    let (loop_var, start_val, bound) = extract_loop_bounds(init?, condition)?;

    // Verify start is 0 (common case for memcpy/memset)
    if start_val != 0 {
        return None;
    }

    // Verify update is simple increment (i++ or i += 1)
    if !is_simple_increment(update?, &loop_var) {
        return None;
    }

    // Extract single assignment from body
    let assignment = extract_single_assignment(body)?;

    // Analyze the assignment pattern
    analyze_assignment_pattern(&assignment, &loop_var, &bound)
}

/// Extract loop variable, start value, and bound from init and condition.
fn extract_loop_bounds(init: &Expr, condition: &Expr) -> Option<(String, i128, Expr)> {
    // init: var = start_value
    let (var_name, start_val) = match &init.kind {
        ExprKind::Assign { lhs, rhs } => {
            let name = get_var_name(lhs)?;
            let start = get_const_value(rhs)?;
            (name, start)
        }
        _ => return None,
    };

    // condition: var < bound or var <= bound-1
    let bound = match &condition.kind {
        ExprKind::BinOp { op, left, right } => {
            let cond_var = get_var_name(left)?;
            if cond_var != var_name {
                return None;
            }
            match op {
                BinOpKind::Lt | BinOpKind::ULt => (**right).clone(),
                BinOpKind::Le | BinOpKind::ULe => {
                    // var <= N means bound is N+1
                    Expr::binop(BinOpKind::Add, (**right).clone(), Expr::int(1))
                }
                _ => return None,
            }
        }
        _ => return None,
    };

    Some((var_name, start_val, bound))
}

/// Check if update expression is a simple increment (i++ or i += 1).
fn is_simple_increment(update: &Expr, loop_var: &str) -> bool {
    match &update.kind {
        // i = i + 1
        ExprKind::Assign { lhs, rhs } => {
            let name = match get_var_name(lhs) {
                Some(n) => n,
                None => return false,
            };
            if name != loop_var {
                return false;
            }

            // rhs should be var + 1
            if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                if *op != BinOpKind::Add {
                    return false;
                }
                let left_var = get_var_name(left);
                let right_val = get_const_value(right);

                if left_var == Some(loop_var.to_string()) && right_val == Some(1) {
                    return true;
                }
            }
            false
        }
        // i++ (compound assignment)
        ExprKind::CompoundAssign { lhs, op, rhs } => {
            let name = match get_var_name(lhs) {
                Some(n) => n,
                None => return false,
            };
            if name != loop_var {
                return false;
            }
            *op == BinOpKind::Add && get_const_value(rhs) == Some(1)
        }
        _ => false,
    }
}

/// Extract a single assignment statement from the loop body.
fn extract_single_assignment(body: &[StructuredNode]) -> Option<Expr> {
    if body.len() != 1 {
        return None;
    }

    match &body[0] {
        StructuredNode::Expr(expr) => {
            if matches!(expr.kind, ExprKind::Assign { .. }) {
                Some(expr.clone())
            } else {
                None
            }
        }
        StructuredNode::Block { statements, .. } => {
            if statements.len() == 1 {
                if matches!(statements[0].kind, ExprKind::Assign { .. }) {
                    Some(statements[0].clone())
                } else {
                    None
                }
            } else {
                None
            }
        }
        StructuredNode::Sequence(nodes) => {
            if nodes.len() == 1 {
                extract_single_assignment(nodes)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Analyze assignment pattern to detect memcpy or memset.
fn analyze_assignment_pattern(
    assignment: &Expr,
    loop_var: &str,
    bound: &Expr,
) -> Option<LoopPattern> {
    let (lhs, rhs) = match &assignment.kind {
        ExprKind::Assign { lhs, rhs } => (lhs, rhs),
        _ => return None,
    };

    // LHS must be array access with loop variable: dst[i]
    let (dst_base, dst_index, element_size) = extract_array_access(lhs)?;
    if get_var_name(&dst_index)? != loop_var {
        return None;
    }

    // Calculate total size: bound * element_size
    let size = if element_size > 1 {
        Expr::binop(
            BinOpKind::Mul,
            bound.clone(),
            Expr::int(element_size as i128),
        )
    } else {
        bound.clone()
    };

    // Check RHS pattern
    // Pattern 1: dst[i] = src[i] -> memcpy
    if let Some((src_base, src_index, src_elem_size)) = extract_array_access(rhs) {
        if get_var_name(&src_index)? == loop_var && element_size == src_elem_size {
            return Some(LoopPattern::Memcpy {
                dst: dst_base,
                src: src_base,
                size,
            });
        }
    }

    // Pattern 2: dst[i] = constant -> memset
    if let Some(val) = get_const_value(rhs) {
        // memset only works for byte values (0 is most common)
        if (0..=255).contains(&val) {
            return Some(LoopPattern::Memset {
                dst: dst_base,
                value: Expr::int(val),
                size,
            });
        }
    }

    // Pattern 3: dst[i] = simple_var (not dependent on i) -> memset
    if is_loop_invariant(rhs, loop_var) {
        // For non-zero values, this is more like a fill operation
        // but memset can handle single-byte fills
        if element_size == 1 {
            return Some(LoopPattern::Memset {
                dst: dst_base,
                value: (**rhs).clone(),
                size,
            });
        }
    }

    None
}

/// Extract array access pattern: base[index] or *(base + index * size)
fn extract_array_access(expr: &Expr) -> Option<(Expr, Expr, usize)> {
    match &expr.kind {
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => Some(((**base).clone(), (**index).clone(), *element_size)),

        ExprKind::Deref { addr, size } => {
            // Try to extract base + index * element_size pattern
            if let ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } = &addr.kind
            {
                // Check for scaled index: base + index * size
                if let ExprKind::BinOp {
                    op: BinOpKind::Mul,
                    left: idx,
                    right: scale,
                } = &right.kind
                {
                    if let Some(elem_size) = get_const_value(scale) {
                        return Some(((**left).clone(), (**idx).clone(), elem_size as usize));
                    }
                }

                // Check for unscaled: base + index (element_size = deref size)
                return Some(((**left).clone(), (**right).clone(), *size as usize));
            }
            None
        }

        _ => None,
    }
}

/// Get variable name from expression.
fn get_var_name(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        _ => None,
    }
}

/// Get constant value from expression.
fn get_const_value(expr: &Expr) -> Option<i128> {
    match &expr.kind {
        ExprKind::IntLit(val) => Some(*val),
        _ => None,
    }
}

/// Check if expression is loop-invariant (doesn't depend on loop variable).
fn is_loop_invariant(expr: &Expr, loop_var: &str) -> bool {
    match &expr.kind {
        ExprKind::Var(var) => var.name != loop_var,
        ExprKind::IntLit(_) => true,
        ExprKind::BinOp { left, right, .. } => {
            is_loop_invariant(left, loop_var) && is_loop_invariant(right, loop_var)
        }
        ExprKind::UnaryOp { operand, .. } => is_loop_invariant(operand, loop_var),
        ExprKind::Cast { expr, .. } => is_loop_invariant(expr, loop_var),
        // Function calls, derefs, etc. are not considered loop-invariant for safety
        _ => false,
    }
}

/// Convert detected pattern to function call expression.
fn pattern_to_call(pattern: LoopPattern) -> Expr {
    match pattern {
        LoopPattern::Memcpy { dst, src, size } => Expr::call(
            CallTarget::Named("memcpy".to_string()),
            vec![dst, src, size],
        ),
        LoopPattern::Memset { dst, value, size } => Expr::call(
            CallTarget::Named("memset".to_string()),
            vec![dst, value, size],
        ),
        LoopPattern::Memcpy2D {
            dst,
            src,
            rows,
            cols,
            element_size,
        } => {
            // Total size = rows * cols * element_size
            let total_size = if element_size > 1 {
                Expr::binop(
                    BinOpKind::Mul,
                    Expr::binop(BinOpKind::Mul, rows, cols),
                    Expr::int(element_size as i128),
                )
            } else {
                Expr::binop(BinOpKind::Mul, rows, cols)
            };
            Expr::call(
                CallTarget::Named("memcpy".to_string()),
                vec![dst, src, total_size],
            )
        }
        LoopPattern::Memset2D {
            dst,
            value,
            rows,
            cols,
            element_size,
        } => {
            // Total size = rows * cols * element_size
            let total_size = if element_size > 1 {
                Expr::binop(
                    BinOpKind::Mul,
                    Expr::binop(BinOpKind::Mul, rows, cols),
                    Expr::int(element_size as i128),
                )
            } else {
                Expr::binop(BinOpKind::Mul, rows, cols)
            };
            Expr::call(
                CallTarget::Named("memset".to_string()),
                vec![dst, value, total_size],
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};

    fn make_var(name: &str) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Temp(0),
            name: name.to_string(),
            size: 8,
        })
    }

    fn make_array_access(base: &str, index: &str, elem_size: usize) -> Expr {
        Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(make_var(base)),
                index: Box::new(make_var(index)),
                element_size: elem_size,
            },
        }
    }

    #[test]
    fn test_extract_loop_bounds() {
        // init: i = 0
        let init = Expr::assign(make_var("i"), Expr::int(0));

        // condition: i < n
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n"));

        let result = extract_loop_bounds(&init, &condition);
        assert!(result.is_some());
        let (var, start, _bound) = result.unwrap();
        assert_eq!(var, "i");
        assert_eq!(start, 0);
    }

    #[test]
    fn test_is_simple_increment() {
        // i = i + 1
        let update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );

        assert!(is_simple_increment(&update, "i"));
        assert!(!is_simple_increment(&update, "j"));
    }

    #[test]
    fn test_detect_memcpy_pattern() {
        // for (i = 0; i < n; i++) { dst[i] = src[i]; }
        let init = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n"));
        let update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );
        let body_assign = Expr::assign(
            make_array_access("dst", "i", 1),
            make_array_access("src", "i", 1),
        );

        let body = vec![StructuredNode::Expr(body_assign)];

        let pattern = detect_memory_pattern(Some(&init), &condition, Some(&update), &body);

        assert!(pattern.is_some());
        match pattern.unwrap() {
            LoopPattern::Memcpy { .. } => (),
            _ => panic!("Expected Memcpy pattern"),
        }
    }

    #[test]
    fn test_detect_memset_pattern() {
        // for (i = 0; i < n; i++) { dst[i] = 0; }
        let init = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n"));
        let update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );
        let body_assign = Expr::assign(make_array_access("dst", "i", 1), Expr::int(0));

        let body = vec![StructuredNode::Expr(body_assign)];

        let pattern = detect_memory_pattern(Some(&init), &condition, Some(&update), &body);

        assert!(pattern.is_some());
        match pattern.unwrap() {
            LoopPattern::Memset { value, .. } => {
                assert_eq!(get_const_value(&value), Some(0));
            }
            _ => panic!("Expected Memset pattern"),
        }
    }

    #[test]
    fn test_no_pattern_multi_statement_body() {
        // for (i = 0; i < n; i++) { dst[i] = src[i]; x++; }
        let init = Expr::assign(make_var("i"), Expr::int(0));
        let condition = Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n"));
        let update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );

        // Two statements - should not match
        let body = vec![
            StructuredNode::Expr(Expr::assign(
                make_array_access("dst", "i", 1),
                make_array_access("src", "i", 1),
            )),
            StructuredNode::Expr(Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(1))),
        ];

        let pattern = detect_memory_pattern(Some(&init), &condition, Some(&update), &body);
        assert!(pattern.is_none());
    }

    #[test]
    fn test_is_loop_invariant() {
        assert!(is_loop_invariant(&Expr::int(5), "i"));
        assert!(is_loop_invariant(&make_var("x"), "i"));
        assert!(!is_loop_invariant(&make_var("i"), "i"));
        assert!(is_loop_invariant(
            &Expr::binop(BinOpKind::Add, make_var("x"), Expr::int(1)),
            "i"
        ));
        assert!(!is_loop_invariant(
            &Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
            "i"
        ));
    }

    #[test]
    fn test_transform_preserves_unmatched_loops() {
        // A loop that doesn't match any pattern should be unchanged
        let for_loop = StructuredNode::For {
            init: Some(Expr::assign(make_var("i"), Expr::int(0))),
            condition: Expr::binop(BinOpKind::Lt, make_var("i"), make_var("n")),
            update: Some(Expr::assign(
                make_var("i"),
                Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
            )),
            body: vec![StructuredNode::Expr(Expr::call(
                CallTarget::Named("printf".to_string()),
                vec![make_var("i")],
            ))],
            header: None,
            exit_block: None,
        };

        let result = transform_node(for_loop.clone());

        // Should still be a For loop, not transformed
        assert!(matches!(result, StructuredNode::For { .. }));
    }

    // --- 2D Loop Pattern Tests ---

    fn make_2d_index(outer_var: &str, inner_var: &str, cols: &Expr) -> Expr {
        // outer_var * cols + inner_var
        Expr::binop(
            BinOpKind::Add,
            Expr::binop(BinOpKind::Mul, make_var(outer_var), cols.clone()),
            make_var(inner_var),
        )
    }

    fn make_2d_array_access(base: &str, outer_var: &str, inner_var: &str, cols: &Expr) -> Expr {
        Expr {
            kind: ExprKind::ArrayAccess {
                base: Box::new(make_var(base)),
                index: Box::new(make_2d_index(outer_var, inner_var, cols)),
                element_size: 1,
            },
        }
    }

    #[test]
    fn test_is_2d_index_expr() {
        let cols = make_var("cols");

        // Test: i * cols + j (valid 2D index)
        let valid_idx = make_2d_index("i", "j", &cols);
        assert!(is_2d_index_expr(&valid_idx, "i", "j", &cols));

        // Test: j + i * cols (reversed order - also valid)
        let reversed_idx = Expr::binop(
            BinOpKind::Add,
            make_var("j"),
            Expr::binop(BinOpKind::Mul, make_var("i"), cols.clone()),
        );
        assert!(is_2d_index_expr(&reversed_idx, "i", "j", &cols));

        // Test: cols * i + j (cols and i swapped in mul - also valid)
        let swapped_mul = Expr::binop(
            BinOpKind::Add,
            Expr::binop(BinOpKind::Mul, cols.clone(), make_var("i")),
            make_var("j"),
        );
        assert!(is_2d_index_expr(&swapped_mul, "i", "j", &cols));

        // Test: wrong variable names (invalid)
        assert!(!is_2d_index_expr(&valid_idx, "x", "y", &cols));
    }

    #[test]
    fn test_2d_memset_pattern() {
        let rows = make_var("rows");
        let cols = make_var("cols");

        // Create nested for loops:
        // for (i = 0; i < rows; i++)
        //     for (j = 0; j < cols; j++)
        //         dst[i * cols + j] = 0;
        let outer_init = Expr::assign(make_var("i"), Expr::int(0));
        let outer_cond = Expr::binop(BinOpKind::Lt, make_var("i"), rows.clone());
        let outer_update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );

        let inner_init = Expr::assign(make_var("j"), Expr::int(0));
        let inner_cond = Expr::binop(BinOpKind::Lt, make_var("j"), cols.clone());
        let inner_update = Expr::assign(
            make_var("j"),
            Expr::binop(BinOpKind::Add, make_var("j"), Expr::int(1)),
        );

        let inner_body = vec![StructuredNode::Expr(Expr::assign(
            make_2d_array_access("dst", "i", "j", &cols),
            Expr::int(0),
        ))];

        let inner_for = StructuredNode::For {
            init: Some(inner_init),
            condition: inner_cond,
            update: Some(inner_update),
            body: inner_body,
            header: None,
            exit_block: None,
        };

        let outer_body = vec![inner_for];

        let pattern = detect_2d_memory_pattern(
            Some(&outer_init),
            &outer_cond,
            Some(&outer_update),
            &outer_body,
        );

        assert!(pattern.is_some());
        assert!(matches!(pattern.unwrap(), LoopPattern::Memset2D { .. }));
    }

    #[test]
    fn test_2d_memcpy_pattern() {
        let rows = make_var("rows");
        let cols = make_var("cols");

        // Create nested for loops:
        // for (i = 0; i < rows; i++)
        //     for (j = 0; j < cols; j++)
        //         dst[i * cols + j] = src[i * cols + j];
        let outer_init = Expr::assign(make_var("i"), Expr::int(0));
        let outer_cond = Expr::binop(BinOpKind::Lt, make_var("i"), rows.clone());
        let outer_update = Expr::assign(
            make_var("i"),
            Expr::binop(BinOpKind::Add, make_var("i"), Expr::int(1)),
        );

        let inner_init = Expr::assign(make_var("j"), Expr::int(0));
        let inner_cond = Expr::binop(BinOpKind::Lt, make_var("j"), cols.clone());
        let inner_update = Expr::assign(
            make_var("j"),
            Expr::binop(BinOpKind::Add, make_var("j"), Expr::int(1)),
        );

        let inner_body = vec![StructuredNode::Expr(Expr::assign(
            make_2d_array_access("dst", "i", "j", &cols),
            make_2d_array_access("src", "i", "j", &cols),
        ))];

        let inner_for = StructuredNode::For {
            init: Some(inner_init),
            condition: inner_cond,
            update: Some(inner_update),
            body: inner_body,
            header: None,
            exit_block: None,
        };

        let outer_body = vec![inner_for];

        let pattern = detect_2d_memory_pattern(
            Some(&outer_init),
            &outer_cond,
            Some(&outer_update),
            &outer_body,
        );

        assert!(pattern.is_some());
        assert!(matches!(pattern.unwrap(), LoopPattern::Memcpy2D { .. }));
    }
}
