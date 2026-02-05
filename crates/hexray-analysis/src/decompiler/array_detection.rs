//! Array access pattern detection for decompiled expressions.
//!
//! This module detects common array access patterns in compiled code and
//! transforms them into high-level array access expressions.
//!
//! # Patterns Detected
//!
//! ## Simple Array Access
//! `*(base + index * element_size)` → `base\[index\]`
//!
//! ## Struct Array Access
//! `*(base + index * stride + offset)` → `arr\[index\].field`
//!
//! ## Fixed Index Access
//! `*(base + constant)` → `base\[constant / element_size\]`
//!
//! ## Address-of Array Element
//! `base + index * element_size` → `&base\[index\]`
//!
//! # Common Addressing Modes
//!
//! | Instruction Pattern           | Expression Pattern         | Result         |
//! |-------------------------------|---------------------------|----------------|
//! | `[rbx + rcx*4]`              | `*(rbx + rcx * 4)`        | `rbx[rcx]`     |
//! | `[rbx + rcx*8 + 0x10]`       | `*(rbx + rcx * 8 + 0x10)` | `rbx[rcx + 2]` |
//! | `lea rax, [rbx + rcx*4]`     | `rbx + rcx * 4`           | `&rbx[rcx]`    |
//!
//! # Array Bounds Inference
//!
//! This module also provides array bounds inference from loop bounds:
//! - When a loop iterates `for (i = 0; i < N; i++)` accessing `arr[i]`,
//!   we infer that `arr` has at least `N` elements.

use super::expression::{BinOpKind, Expr, ExprKind};
use super::structurer::StructuredNode;
use std::collections::HashMap;

/// Result of array pattern detection.
#[derive(Debug, Clone)]
pub struct ArrayAccessInfo {
    /// The base pointer expression.
    pub base: Expr,
    /// The index expression (may include constant offset).
    pub index: Expr,
    /// Size of each element in bytes.
    pub element_size: usize,
    /// Whether this is an address-of pattern (LEA) vs dereference.
    pub is_address_of: bool,
}

/// Attempts to detect an array access pattern in a dereference expression.
///
/// Matches patterns like:
/// - `*(base + index * size)` -> array access with computed index
/// - `*(base + constant)` -> array access with fixed index (if constant is aligned)
/// - `*(base + index * stride + offset)` -> struct array with field offset
///
/// Returns `Some(ArrayAccessInfo)` if a pattern is detected, `None` otherwise.
pub fn detect_array_access(addr: &Expr, deref_size: u8) -> Option<ArrayAccessInfo> {
    // Try the main pattern: base + index * size
    if let Some(info) = try_detect_scaled_access(addr, deref_size) {
        return Some(info);
    }

    // Try constant offset pattern: base + constant
    if let Some(info) = try_detect_constant_offset(addr, deref_size) {
        return Some(info);
    }

    // Try shift pattern: base + (index << shift)
    if let Some(info) = try_detect_shift_pattern(addr, deref_size) {
        return Some(info);
    }

    // Try struct array pattern: base + index * stride + field_offset
    if let Some(info) = try_detect_struct_array_access(addr, deref_size) {
        return Some(info);
    }

    None
}

/// Detects address-of array element pattern (for LEA instruction results).
///
/// Matches patterns like:
/// - `base + index * size` → `&base\[index\]`
/// - `base + constant` → `&base\[constant / size\]` (for aligned constants)
pub fn detect_address_of_array_element(
    addr: &Expr,
    hinted_size: Option<usize>,
) -> Option<ArrayAccessInfo> {
    // Use hinted size or try common element sizes
    let sizes_to_try: Vec<usize> = if let Some(size) = hinted_size {
        vec![size]
    } else {
        vec![8, 4, 2, 1] // Try in order of most common pointer/int sizes
    };

    for size in &sizes_to_try {
        if let Some(mut info) = try_detect_scaled_access(addr, *size as u8) {
            info.is_address_of = true;
            return Some(info);
        }
        if let Some(mut info) = try_detect_shift_pattern(addr, *size as u8) {
            info.is_address_of = true;
            return Some(info);
        }
    }

    // Try constant offset for address-of
    for size in &sizes_to_try {
        if let Some(mut info) = try_detect_constant_offset(addr, *size as u8) {
            info.is_address_of = true;
            return Some(info);
        }
    }

    None
}

/// Detects `base + index * element_size` pattern.
fn try_detect_scaled_access(addr: &Expr, expected_size: u8) -> Option<ArrayAccessInfo> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try: base + (index * size)
        if let Some((index, element_size)) = extract_mul_by_constant(right) {
            if element_size > 0 && (expected_size == 0 || element_size == expected_size as i128) {
                return Some(ArrayAccessInfo {
                    base: (**left).clone(),
                    index,
                    element_size: element_size as usize,
                    is_address_of: false,
                });
            }
        }

        // Try: (index * size) + base (commutative)
        if let Some((index, element_size)) = extract_mul_by_constant(left) {
            if element_size > 0 && (expected_size == 0 || element_size == expected_size as i128) {
                return Some(ArrayAccessInfo {
                    base: (**right).clone(),
                    index,
                    element_size: element_size as usize,
                    is_address_of: false,
                });
            }
        }
    }

    None
}

/// Detects `base + (index << shift)` pattern where `1 << shift == element_size`.
fn try_detect_shift_pattern(addr: &Expr, expected_size: u8) -> Option<ArrayAccessInfo> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try: base + (index << shift)
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(right) {
            let element_size = 1i128 << shift_amount;
            if expected_size == 0 || element_size == expected_size as i128 {
                return Some(ArrayAccessInfo {
                    base: (**left).clone(),
                    index,
                    element_size: element_size as usize,
                    is_address_of: false,
                });
            }
        }

        // Try: (index << shift) + base (commutative)
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(left) {
            let element_size = 1i128 << shift_amount;
            if expected_size == 0 || element_size == expected_size as i128 {
                return Some(ArrayAccessInfo {
                    base: (**right).clone(),
                    index,
                    element_size: element_size as usize,
                    is_address_of: false,
                });
            }
        }
    }

    None
}

/// Detects `base + constant` pattern where constant is a multiple of element_size.
fn try_detect_constant_offset(addr: &Expr, expected_size: u8) -> Option<ArrayAccessInfo> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try: base + constant
        if let ExprKind::IntLit(offset) = &right.kind {
            if *offset != 0 {
                return try_create_constant_index_access(left, *offset, expected_size);
            }
        }

        // Try: constant + base (less common but valid)
        if let ExprKind::IntLit(offset) = &left.kind {
            if *offset != 0 {
                return try_create_constant_index_access(right, *offset, expected_size);
            }
        }
    }

    // Handle subtraction: base - constant (negative index)
    if let ExprKind::BinOp {
        op: BinOpKind::Sub,
        left,
        right,
    } = &addr.kind
    {
        if let ExprKind::IntLit(offset) = &right.kind {
            if *offset != 0 {
                return try_create_constant_index_access(left, -*offset, expected_size);
            }
        }
    }

    None
}

/// Creates an array access with a constant index from `base + offset`.
fn try_create_constant_index_access(
    base: &Expr,
    offset: i128,
    expected_size: u8,
) -> Option<ArrayAccessInfo> {
    let element_size = if expected_size > 0 {
        expected_size as i128
    } else {
        // Try to infer element size from alignment of offset
        infer_element_size(offset)
    };

    // Check if offset is aligned to element size
    if element_size > 0 && offset % element_size == 0 {
        let index = offset / element_size;
        return Some(ArrayAccessInfo {
            base: base.clone(),
            index: Expr::int(index),
            element_size: element_size as usize,
            is_address_of: false,
        });
    }

    None
}

/// Detects struct array pattern: `base + index * stride + field_offset`.
///
/// This handles cases like `arr[i].field` where the compiler generates:
/// `base + i * sizeof(struct) + offsetof(struct, field)`
fn try_detect_struct_array_access(addr: &Expr, deref_size: u8) -> Option<ArrayAccessInfo> {
    // Pattern: (base + index * stride) + field_offset
    // or: base + (index * stride + field_offset)

    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try: (scaled_access) + constant
        if let ExprKind::IntLit(field_offset) = &right.kind {
            if let Some(mut info) = try_detect_scaled_access(left, 0) {
                // Adjust index to include field offset
                // new_index = old_index + field_offset / stride (if aligned)
                // For now, we keep it simple and adjust the base or leave as-is
                // if the field_offset is not a multiple of element_size

                if *field_offset % (info.element_size as i128) == 0 {
                    // Aligned: can add to index
                    let additional_index = *field_offset / (info.element_size as i128);
                    info.index =
                        Expr::binop(BinOpKind::Add, info.index, Expr::int(additional_index));
                    return Some(info);
                }
                // Unaligned: this is likely a struct field access
                // For now, we don't transform this as it needs more context
            }
        }

        // Try: constant + (scaled_access)
        if let ExprKind::IntLit(field_offset) = &left.kind {
            if let Some(mut info) = try_detect_scaled_access(right, 0) {
                if *field_offset % (info.element_size as i128) == 0 {
                    let additional_index = *field_offset / (info.element_size as i128);
                    info.index =
                        Expr::binop(BinOpKind::Add, Expr::int(additional_index), info.index);
                    return Some(info);
                }
            }
        }
    }

    // Also try for shift patterns
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        if let ExprKind::IntLit(field_offset) = &right.kind {
            if let Some(mut info) = try_detect_shift_pattern(left, 0) {
                if *field_offset % (info.element_size as i128) == 0 {
                    let additional_index = *field_offset / (info.element_size as i128);
                    info.index =
                        Expr::binop(BinOpKind::Add, info.index, Expr::int(additional_index));
                    return Some(info);
                }
            }
        }
    }

    let _ = deref_size; // Silence unused warning, could be used for type inference later
    None
}

/// Extracts (operand, constant) from `operand * constant` or `constant * operand`.
fn extract_mul_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Mul,
        left,
        right,
    } = &expr.kind
    {
        // Try: expr * constant
        if let ExprKind::IntLit(n) = &right.kind {
            if *n > 0 && *n <= 1024 {
                // Reasonable element size limit
                return Some(((**left).clone(), *n));
            }
        }
        // Try: constant * expr
        if let ExprKind::IntLit(n) = &left.kind {
            if *n > 0 && *n <= 1024 {
                return Some(((**right).clone(), *n));
            }
        }
    }
    None
}

/// Extracts (operand, shift_amount) from `operand << constant`.
fn extract_shift_left_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    {
        if let ExprKind::IntLit(n) = &right.kind {
            if *n >= 0 && *n <= 6 {
                // Shift 0-6 = sizes 1-64
                return Some(((**left).clone(), *n));
            }
        }
    }
    None
}

/// Infers element size from a constant offset based on alignment.
fn infer_element_size(offset: i128) -> i128 {
    let offset_abs = offset.abs();

    // Check alignment from largest to smallest
    if offset_abs >= 8 && offset_abs % 8 == 0 {
        8 // 64-bit (pointer, long)
    } else if offset_abs >= 4 && offset_abs % 4 == 0 {
        4 // 32-bit (int, float)
    } else if offset_abs >= 2 && offset_abs % 2 == 0 {
        2 // 16-bit (short)
    } else {
        1 // 8-bit (char, byte)
    }
}

/// Transforms a dereference expression into an array access if a pattern is detected.
///
/// This is the main entry point for array detection during expression simplification.
pub fn try_transform_deref_to_array_access(addr: &Expr, size: u8) -> Option<Expr> {
    detect_array_access(addr, size)
        .map(|info| Expr::array_access(info.base, info.index, info.element_size))
}

/// Transforms an address expression into an address-of array element if a pattern is detected.
///
/// Used for LEA instruction results.
pub fn try_transform_to_address_of_array(addr: &Expr, hinted_size: Option<usize>) -> Option<Expr> {
    detect_address_of_array_element(addr, hinted_size).map(|info| {
        let array_access = Expr::array_access(info.base, info.index, info.element_size);
        Expr::address_of(array_access)
    })
}

/// Checks if an expression looks like an array base (pointer or variable).
pub fn is_likely_array_base(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Var(_) => true,
        ExprKind::Deref { .. } => true,  // Pointer through memory
        ExprKind::GotRef { .. } => true, // Global array
        ExprKind::AddressOf(_) => true,  // &something
        ExprKind::ArrayAccess { .. } => true, // Multidimensional array
        _ => false,
    }
}

// =============================================================================
// Array Bounds Inference from Loop Bounds
// =============================================================================

/// Information about an inferred array bound.
#[derive(Debug, Clone)]
pub struct ArrayBoundInfo {
    /// The variable name of the array base.
    pub array_name: String,
    /// The inferred minimum size (number of elements).
    pub min_size: ArrayBoundExpr,
    /// The element size in bytes.
    pub element_size: usize,
    /// Confidence level of the inference.
    pub confidence: BoundConfidence,
}

/// Expression representing an array bound.
#[derive(Debug, Clone)]
pub enum ArrayBoundExpr {
    /// A constant bound (e.g., `arr[10]` means size >= 11).
    Constant(i128),
    /// A variable bound (e.g., `for i < n` means size >= n).
    Variable(String),
    /// A computed bound (e.g., `n * m`).
    Product(Box<ArrayBoundExpr>, Box<ArrayBoundExpr>),
    /// A sum of bounds.
    Sum(Box<ArrayBoundExpr>, Box<ArrayBoundExpr>),
}

impl std::fmt::Display for ArrayBoundExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArrayBoundExpr::Constant(n) => write!(f, "{}", n),
            ArrayBoundExpr::Variable(name) => write!(f, "{}", name),
            ArrayBoundExpr::Product(a, b) => write!(f, "({} * {})", a, b),
            ArrayBoundExpr::Sum(a, b) => write!(f, "({} + {})", a, b),
        }
    }
}

/// Confidence level of an inferred bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BoundConfidence {
    /// Low confidence - might be wrong.
    Low,
    /// Medium confidence - likely correct.
    Medium,
    /// High confidence - almost certainly correct.
    High,
}

/// Collected array bounds from analyzing structured code.
#[derive(Debug, Clone, Default)]
pub struct ArrayBounds {
    /// Map from array variable name to inferred bounds.
    bounds: HashMap<String, Vec<ArrayBoundInfo>>,
}

impl ArrayBounds {
    /// Creates a new empty bounds collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a bound for an array.
    pub fn add_bound(&mut self, info: ArrayBoundInfo) {
        self.bounds
            .entry(info.array_name.clone())
            .or_default()
            .push(info);
    }

    /// Gets all bounds for an array.
    pub fn get_bounds(&self, array_name: &str) -> Option<&Vec<ArrayBoundInfo>> {
        self.bounds.get(array_name)
    }

    /// Gets the best (highest confidence) constant bound for an array.
    pub fn get_best_constant_bound(&self, array_name: &str) -> Option<i128> {
        self.bounds.get(array_name).and_then(|bounds| {
            bounds
                .iter()
                .filter_map(|b| {
                    if let ArrayBoundExpr::Constant(n) = b.min_size {
                        Some((n, b.confidence))
                    } else {
                        None
                    }
                })
                .max_by_key(|(_, conf)| *conf)
                .map(|(n, _)| n)
        })
    }

    /// Gets all arrays with inferred bounds.
    pub fn arrays(&self) -> impl Iterator<Item = &str> {
        self.bounds.keys().map(String::as_str)
    }

    /// Merges another bounds collection into this one.
    pub fn merge(&mut self, other: ArrayBounds) {
        for (name, bounds) in other.bounds {
            self.bounds.entry(name).or_default().extend(bounds);
        }
    }
}

/// Infers array bounds from structured code by analyzing loop patterns.
pub fn infer_array_bounds(nodes: &[StructuredNode]) -> ArrayBounds {
    let mut bounds = ArrayBounds::new();

    for node in nodes {
        collect_bounds_from_node(node, &mut bounds);
    }

    bounds
}

/// Recursively collects array bounds from a structured node.
fn collect_bounds_from_node(node: &StructuredNode, bounds: &mut ArrayBounds) {
    match node {
        StructuredNode::For {
            init,
            condition,
            update,
            body,
            ..
        } => {
            // Try to extract loop variable and bounds
            if let (Some(init_expr), Some(update_expr)) = (init, update) {
                if let Some((loop_var, start, bound)) =
                    extract_loop_bounds_for_inference(init_expr, condition)
                {
                    // Check for simple increment
                    if is_simple_increment_for_inference(update_expr, &loop_var) {
                        // Scan body for array accesses using the loop variable
                        collect_array_accesses_in_loop(body, &loop_var, start, &bound, bounds);
                    }
                }
            }
            // Recurse into body
            for child in body {
                collect_bounds_from_node(child, bounds);
            }
        }

        StructuredNode::While { body, .. } | StructuredNode::DoWhile { body, .. } => {
            // Could analyze while loops too, but for loops are more reliable
            for child in body {
                collect_bounds_from_node(child, bounds);
            }
        }

        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            for child in then_body {
                collect_bounds_from_node(child, bounds);
            }
            if let Some(else_nodes) = else_body {
                for child in else_nodes {
                    collect_bounds_from_node(child, bounds);
                }
            }
        }

        StructuredNode::Switch { cases, default, .. } => {
            for (_, case_body) in cases {
                for child in case_body {
                    collect_bounds_from_node(child, bounds);
                }
            }
            if let Some(default_body) = default {
                for child in default_body {
                    collect_bounds_from_node(child, bounds);
                }
            }
        }

        StructuredNode::Sequence(nodes) => {
            for child in nodes {
                collect_bounds_from_node(child, bounds);
            }
        }

        StructuredNode::Block { statements, .. } => {
            // Block contains expressions, not structured nodes
            for expr in statements {
                scan_expr_for_constant_indices(expr, bounds);
            }
        }

        StructuredNode::TryCatch {
            try_body,
            catch_handlers,
        } => {
            for child in try_body {
                collect_bounds_from_node(child, bounds);
            }
            for handler in catch_handlers {
                for child in &handler.body {
                    collect_bounds_from_node(child, bounds);
                }
            }
        }

        // Leaf nodes with expressions - scan for direct array accesses
        StructuredNode::Expr(expr) => {
            scan_expr_for_constant_indices(expr, bounds);
        }

        _ => {}
    }
}

/// Extracts loop bounds from init and condition expressions.
fn extract_loop_bounds_for_inference(
    init: &Expr,
    condition: &Expr,
) -> Option<(String, i128, ArrayBoundExpr)> {
    // init: var = start_value
    let (var_name, start_val) = match &init.kind {
        ExprKind::Assign { lhs, rhs } => {
            let name = get_var_name(lhs)?;
            let start = get_const_value(rhs).unwrap_or(0);
            (name, start)
        }
        _ => return None,
    };

    // condition: var < bound or var <= bound-1 or var != bound
    let bound = match &condition.kind {
        ExprKind::BinOp { op, left, right } => {
            let cond_var = get_var_name(left)?;
            if cond_var != var_name {
                return None;
            }
            match op {
                BinOpKind::Lt | BinOpKind::ULt | BinOpKind::Ne => expr_to_bound(right),
                BinOpKind::Le | BinOpKind::ULe => {
                    // var <= N means bound is N+1
                    let inner = expr_to_bound(right);
                    ArrayBoundExpr::Sum(Box::new(inner), Box::new(ArrayBoundExpr::Constant(1)))
                }
                _ => return None,
            }
        }
        _ => return None,
    };

    Some((var_name, start_val, bound))
}

/// Converts an expression to an ArrayBoundExpr.
fn expr_to_bound(expr: &Expr) -> ArrayBoundExpr {
    match &expr.kind {
        ExprKind::IntLit(n) => ArrayBoundExpr::Constant(*n),
        ExprKind::Var(var) => ArrayBoundExpr::Variable(var.name.clone()),
        ExprKind::BinOp {
            op: BinOpKind::Mul,
            left,
            right,
        } => ArrayBoundExpr::Product(
            Box::new(expr_to_bound(left)),
            Box::new(expr_to_bound(right)),
        ),
        ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } => ArrayBoundExpr::Sum(
            Box::new(expr_to_bound(left)),
            Box::new(expr_to_bound(right)),
        ),
        _ => ArrayBoundExpr::Variable(format!("<{}>", expr)),
    }
}

/// Checks if an update expression is a simple increment.
fn is_simple_increment_for_inference(update: &Expr, loop_var: &str) -> bool {
    match &update.kind {
        ExprKind::Assign { lhs, rhs } => {
            let name = match get_var_name(lhs) {
                Some(n) => n,
                None => return false,
            };
            if name != loop_var {
                return false;
            }
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

/// Scans loop body for array accesses using the loop variable.
fn collect_array_accesses_in_loop(
    body: &[StructuredNode],
    loop_var: &str,
    start: i128,
    bound: &ArrayBoundExpr,
    bounds: &mut ArrayBounds,
) {
    for node in body {
        match node {
            StructuredNode::Expr(expr) => {
                collect_array_accesses_from_expr(expr, loop_var, start, bound, bounds);
            }
            StructuredNode::Block { statements, .. } => {
                // Block contains expressions, not structured nodes
                for expr in statements {
                    collect_array_accesses_from_expr(expr, loop_var, start, bound, bounds);
                }
            }
            StructuredNode::Sequence(nodes) => {
                collect_array_accesses_in_loop(nodes, loop_var, start, bound, bounds);
            }
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                collect_array_accesses_in_loop(then_body, loop_var, start, bound, bounds);
                if let Some(else_nodes) = else_body {
                    collect_array_accesses_in_loop(else_nodes, loop_var, start, bound, bounds);
                }
            }
            _ => {}
        }
    }
}

/// Collects array accesses from an expression.
fn collect_array_accesses_from_expr(
    expr: &Expr,
    loop_var: &str,
    _start: i128,
    bound: &ArrayBoundExpr,
    bounds: &mut ArrayBounds,
) {
    match &expr.kind {
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            // Check if index uses the loop variable
            if expr_uses_var(index, loop_var) {
                if let Some(array_name) = get_var_name(base) {
                    bounds.add_bound(ArrayBoundInfo {
                        array_name,
                        min_size: bound.clone(),
                        element_size: *element_size,
                        confidence: BoundConfidence::High,
                    });
                }
            }
            // Recurse into base and index
            collect_array_accesses_from_expr(base, loop_var, _start, bound, bounds);
            collect_array_accesses_from_expr(index, loop_var, _start, bound, bounds);
        }
        ExprKind::Assign { lhs, rhs } => {
            collect_array_accesses_from_expr(lhs, loop_var, _start, bound, bounds);
            collect_array_accesses_from_expr(rhs, loop_var, _start, bound, bounds);
        }
        ExprKind::BinOp { left, right, .. } => {
            collect_array_accesses_from_expr(left, loop_var, _start, bound, bounds);
            collect_array_accesses_from_expr(right, loop_var, _start, bound, bounds);
        }
        ExprKind::UnaryOp { operand, .. } => {
            collect_array_accesses_from_expr(operand, loop_var, _start, bound, bounds);
        }
        ExprKind::Deref { addr, .. } => {
            collect_array_accesses_from_expr(addr, loop_var, _start, bound, bounds);
        }
        ExprKind::Call { args, .. } => {
            for arg in args {
                collect_array_accesses_from_expr(arg, loop_var, _start, bound, bounds);
            }
        }
        ExprKind::Cast { expr: inner, .. } => {
            collect_array_accesses_from_expr(inner, loop_var, _start, bound, bounds);
        }
        _ => {}
    }
}

/// Checks if an expression uses a specific variable.
fn expr_uses_var(expr: &Expr, var_name: &str) -> bool {
    match &expr.kind {
        ExprKind::Var(var) => var.name == var_name,
        ExprKind::BinOp { left, right, .. } => {
            expr_uses_var(left, var_name) || expr_uses_var(right, var_name)
        }
        ExprKind::UnaryOp { operand, .. } => expr_uses_var(operand, var_name),
        ExprKind::Cast { expr: inner, .. } => expr_uses_var(inner, var_name),
        ExprKind::ArrayAccess { base, index, .. } => {
            expr_uses_var(base, var_name) || expr_uses_var(index, var_name)
        }
        _ => false,
    }
}

/// Scans expression for constant array indices to infer minimum bounds.
fn scan_expr_for_constant_indices(expr: &Expr, bounds: &mut ArrayBounds) {
    match &expr.kind {
        ExprKind::ArrayAccess {
            base,
            index,
            element_size,
        } => {
            // If index is a constant, we know array size must be at least index+1
            if let ExprKind::IntLit(idx) = &index.kind {
                if let Some(array_name) = get_var_name(base) {
                    if *idx >= 0 {
                        bounds.add_bound(ArrayBoundInfo {
                            array_name,
                            min_size: ArrayBoundExpr::Constant(*idx + 1),
                            element_size: *element_size,
                            confidence: BoundConfidence::Medium, // Might be out of bounds access
                        });
                    }
                }
            }
            scan_expr_for_constant_indices(base, bounds);
            scan_expr_for_constant_indices(index, bounds);
        }
        ExprKind::Assign { lhs, rhs } => {
            scan_expr_for_constant_indices(lhs, bounds);
            scan_expr_for_constant_indices(rhs, bounds);
        }
        ExprKind::BinOp { left, right, .. } => {
            scan_expr_for_constant_indices(left, bounds);
            scan_expr_for_constant_indices(right, bounds);
        }
        ExprKind::UnaryOp { operand, .. } => {
            scan_expr_for_constant_indices(operand, bounds);
        }
        ExprKind::Deref { addr, .. } => {
            scan_expr_for_constant_indices(addr, bounds);
        }
        ExprKind::Call { args, .. } => {
            for arg in args {
                scan_expr_for_constant_indices(arg, bounds);
            }
        }
        ExprKind::Cast { expr: inner, .. } => {
            scan_expr_for_constant_indices(inner, bounds);
        }
        _ => {}
    }
}

/// Gets the variable name from an expression.
fn get_var_name(expr: &Expr) -> Option<String> {
    match &expr.kind {
        ExprKind::Var(var) => Some(var.name.clone()),
        _ => None,
    }
}

/// Gets constant value from an expression.
fn get_const_value(expr: &Expr) -> Option<i128> {
    match &expr.kind {
        ExprKind::IntLit(val) => Some(*val),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::Variable;

    fn var(name: &str) -> Expr {
        Expr::var(Variable::reg(name, 8))
    }

    #[test]
    fn test_simple_scaled_access() {
        // rbx + rcx * 4 (4-byte elements)
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::binop(BinOpKind::Mul, var("rcx"), Expr::int(4)),
        );

        let result = detect_array_access(&addr, 4);
        assert!(result.is_some(), "Expected to detect array access");

        let info = result.unwrap();
        assert_eq!(info.element_size, 4);
        assert!(!info.is_address_of);

        // Verify the expression transformation
        let transformed = try_transform_deref_to_array_access(&addr, 4).unwrap();
        assert_eq!(transformed.to_string(), "rbx[rcx]");
    }

    #[test]
    fn test_scaled_access_commutative() {
        // rcx * 8 + rbx (commutative order)
        let addr = Expr::binop(
            BinOpKind::Add,
            Expr::binop(BinOpKind::Mul, var("rcx"), Expr::int(8)),
            var("rbx"),
        );

        let result = detect_array_access(&addr, 8);
        assert!(
            result.is_some(),
            "Expected to detect array access (commutative)"
        );

        let info = result.unwrap();
        assert_eq!(info.element_size, 8);
    }

    #[test]
    fn test_shift_pattern() {
        // rbx + (rcx << 2) equivalent to rbx + rcx * 4
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::binop(BinOpKind::Shl, var("rcx"), Expr::int(2)),
        );

        let result = detect_array_access(&addr, 4);
        assert!(result.is_some(), "Expected to detect shift pattern");

        let info = result.unwrap();
        assert_eq!(info.element_size, 4);
    }

    #[test]
    fn test_constant_offset_aligned() {
        // rbx + 0x10 (4-byte elements) -> rbx[4]
        let addr = Expr::binop(BinOpKind::Add, var("rbx"), Expr::int(0x10));

        let result = detect_array_access(&addr, 4);
        assert!(
            result.is_some(),
            "Expected to detect constant offset pattern"
        );

        let info = result.unwrap();
        assert_eq!(info.element_size, 4);

        // Check the index is 4 (0x10 / 4)
        if let ExprKind::IntLit(idx) = &info.index.kind {
            assert_eq!(*idx, 4);
        } else {
            panic!("Expected integer index");
        }
    }

    #[test]
    fn test_constant_offset_8byte() {
        // rbx + 0x18 (8-byte elements) -> rbx[3]
        let addr = Expr::binop(BinOpKind::Add, var("rbx"), Expr::int(0x18));

        let result = detect_array_access(&addr, 8);
        assert!(
            result.is_some(),
            "Expected to detect constant offset pattern"
        );

        let info = result.unwrap();
        assert_eq!(info.element_size, 8);

        if let ExprKind::IntLit(idx) = &info.index.kind {
            assert_eq!(*idx, 3); // 0x18 / 8 = 3
        } else {
            panic!("Expected integer index");
        }
    }

    #[test]
    fn test_negative_constant_offset() {
        // rbx - 0x8 (8-byte elements) -> rbx[-1]
        let addr = Expr::binop(BinOpKind::Sub, var("rbx"), Expr::int(0x8));

        let result = detect_array_access(&addr, 8);
        assert!(
            result.is_some(),
            "Expected to detect negative offset pattern"
        );

        let info = result.unwrap();
        if let ExprKind::IntLit(idx) = &info.index.kind {
            assert_eq!(*idx, -1);
        } else {
            panic!("Expected integer index");
        }
    }

    #[test]
    fn test_struct_array_access() {
        // (rbx + rcx * 16) + 8 -> access to 8-byte field in 16-byte struct
        // With deref_size=16 and aligned offset, we treat it as stride-based access
        let scaled = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::binop(BinOpKind::Mul, var("rcx"), Expr::int(16)),
        );
        let addr = Expr::binop(BinOpKind::Add, scaled, Expr::int(8));

        // When deref_size matches the field offset alignment (8), we detect it
        // as accessing 8-byte elements. The index gets adjusted.
        let result = detect_array_access(&addr, 8);
        assert!(result.is_some(), "Expected to detect struct array pattern");

        let info = result.unwrap();
        // Since 8 aligns to the 8-byte offset, we get 8-byte elements
        // with the constant offset handled separately
        assert!(
            info.element_size == 8 || info.element_size == 16,
            "Expected element_size 8 or 16, got {}",
            info.element_size
        );
    }

    #[test]
    fn test_address_of_array_element() {
        // LEA pattern: rbx + rcx * 4 -> &rbx[rcx]
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::binop(BinOpKind::Mul, var("rcx"), Expr::int(4)),
        );

        let result = detect_address_of_array_element(&addr, Some(4));
        assert!(result.is_some(), "Expected to detect address-of pattern");

        let info = result.unwrap();
        assert!(info.is_address_of);
        assert_eq!(info.element_size, 4);

        // Test the full transformation
        let transformed = try_transform_to_address_of_array(&addr, Some(4)).unwrap();
        assert_eq!(transformed.to_string(), "&rbx[rcx]");
    }

    #[test]
    fn test_no_match_unaligned() {
        // rbx + 5 with 4-byte expected size - unaligned, should not match
        let addr = Expr::binop(BinOpKind::Add, var("rbx"), Expr::int(5));

        let result = detect_array_access(&addr, 4);
        assert!(result.is_none(), "Should not match unaligned offset");
    }

    #[test]
    fn test_no_match_non_power_of_two() {
        // rbx + rcx * 3 - unusual element size
        // While 3 is valid, it's less common; our detection still handles it
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::binop(BinOpKind::Mul, var("rcx"), Expr::int(3)),
        );

        let result = detect_array_access(&addr, 3);
        assert!(result.is_some(), "Should still match with size 3");

        let info = result.unwrap();
        assert_eq!(info.element_size, 3);
    }

    #[test]
    fn test_display_format() {
        let arr_access = Expr::array_access(var("arr"), var("i"), 4);
        assert_eq!(arr_access.to_string(), "arr[i]");

        // With constant index
        let arr_const = Expr::array_access(var("data"), Expr::int(5), 8);
        assert_eq!(arr_const.to_string(), "data[5]");

        // Address-of array element
        let addr_of = Expr::address_of(Expr::array_access(var("buf"), var("idx"), 1));
        assert_eq!(addr_of.to_string(), "&buf[idx]");
    }

    #[test]
    fn test_nested_array_access() {
        // ptr[i] where ptr itself is an array access
        let inner = Expr::array_access(var("arr"), var("i"), 8);
        let outer = Expr::array_access(inner, var("j"), 4);
        assert_eq!(outer.to_string(), "arr[i][j]");
    }

    #[test]
    fn test_complex_index_expression() {
        // arr[i + j]
        let index = Expr::binop(BinOpKind::Add, var("i"), var("j"));
        let access = Expr::array_access(var("arr"), index, 4);
        assert_eq!(access.to_string(), "arr[i + j]");
    }

    #[test]
    fn test_infer_element_size() {
        assert_eq!(infer_element_size(8), 8);
        assert_eq!(infer_element_size(16), 8);
        assert_eq!(infer_element_size(24), 8);
        assert_eq!(infer_element_size(4), 4);
        assert_eq!(infer_element_size(12), 4);
        assert_eq!(infer_element_size(2), 2);
        assert_eq!(infer_element_size(6), 2);
        assert_eq!(infer_element_size(1), 1);
        assert_eq!(infer_element_size(3), 1);
        assert_eq!(infer_element_size(-8), 8);
        assert_eq!(infer_element_size(-4), 4);
    }

    // --- Array Bounds Inference Tests ---

    #[test]
    fn test_array_bound_expr_display() {
        let const_bound = ArrayBoundExpr::Constant(10);
        assert_eq!(const_bound.to_string(), "10");

        let var_bound = ArrayBoundExpr::Variable("n".to_string());
        assert_eq!(var_bound.to_string(), "n");

        let product = ArrayBoundExpr::Product(
            Box::new(ArrayBoundExpr::Variable("m".to_string())),
            Box::new(ArrayBoundExpr::Variable("n".to_string())),
        );
        assert_eq!(product.to_string(), "(m * n)");

        let sum = ArrayBoundExpr::Sum(
            Box::new(ArrayBoundExpr::Variable("n".to_string())),
            Box::new(ArrayBoundExpr::Constant(1)),
        );
        assert_eq!(sum.to_string(), "(n + 1)");
    }

    #[test]
    fn test_array_bounds_collection() {
        let mut bounds = ArrayBounds::new();

        bounds.add_bound(ArrayBoundInfo {
            array_name: "arr".to_string(),
            min_size: ArrayBoundExpr::Constant(10),
            element_size: 4,
            confidence: BoundConfidence::High,
        });

        bounds.add_bound(ArrayBoundInfo {
            array_name: "arr".to_string(),
            min_size: ArrayBoundExpr::Variable("n".to_string()),
            element_size: 4,
            confidence: BoundConfidence::Medium,
        });

        let arr_bounds = bounds.get_bounds("arr");
        assert!(arr_bounds.is_some());
        assert_eq!(arr_bounds.unwrap().len(), 2);

        let best = bounds.get_best_constant_bound("arr");
        assert_eq!(best, Some(10));
    }

    #[test]
    fn test_infer_bounds_from_for_loop() {
        // Create: for (i = 0; i < n; i++) { arr[i] = 0; }
        let i_var = Variable::reg("i", 8);
        let arr_var = Variable::reg("arr", 8);
        let n_var = Variable::reg("n", 8);

        let init = Expr::assign(Expr::var(i_var.clone()), Expr::int(0));

        let condition = Expr::binop(
            BinOpKind::Lt,
            Expr::var(i_var.clone()),
            Expr::var(n_var.clone()),
        );

        let update = Expr::assign(
            Expr::var(i_var.clone()),
            Expr::binop(BinOpKind::Add, Expr::var(i_var.clone()), Expr::int(1)),
        );

        let body_stmt = Expr::assign(
            Expr::array_access(Expr::var(arr_var), Expr::var(i_var), 4),
            Expr::int(0),
        );

        let for_loop = StructuredNode::For {
            init: Some(init),
            condition,
            update: Some(update),
            body: vec![StructuredNode::Expr(body_stmt)],
            header: None,
            exit_block: None,
        };

        let bounds = infer_array_bounds(&[for_loop]);

        let arr_bounds = bounds.get_bounds("arr");
        assert!(arr_bounds.is_some());
        let arr_bounds = arr_bounds.unwrap();
        assert!(!arr_bounds.is_empty());

        // Should have inferred size >= n
        let first_bound = &arr_bounds[0];
        assert_eq!(first_bound.element_size, 4);
        assert_eq!(first_bound.confidence, BoundConfidence::High);
        if let ArrayBoundExpr::Variable(name) = &first_bound.min_size {
            assert_eq!(name, "n");
        } else {
            panic!("Expected variable bound 'n'");
        }
    }

    #[test]
    fn test_infer_bounds_from_constant_access() {
        // arr[5] = 10;
        let arr_var = Variable::reg("arr", 8);

        let stmt = Expr::assign(
            Expr::array_access(Expr::var(arr_var), Expr::int(5), 4),
            Expr::int(10),
        );

        let node = StructuredNode::Expr(stmt);
        let bounds = infer_array_bounds(&[node]);

        let arr_bounds = bounds.get_bounds("arr");
        assert!(arr_bounds.is_some());
        let arr_bounds = arr_bounds.unwrap();
        assert!(!arr_bounds.is_empty());

        // Should have inferred size >= 6 (index 5 means at least 6 elements)
        let first_bound = &arr_bounds[0];
        assert_eq!(first_bound.element_size, 4);
        if let ArrayBoundExpr::Constant(n) = &first_bound.min_size {
            assert_eq!(*n, 6); // 5 + 1
        } else {
            panic!("Expected constant bound 6");
        }
    }

    #[test]
    fn test_bound_confidence_ordering() {
        assert!(BoundConfidence::Low < BoundConfidence::Medium);
        assert!(BoundConfidence::Medium < BoundConfidence::High);
    }

    #[test]
    fn test_array_bounds_merge() {
        let mut bounds1 = ArrayBounds::new();
        bounds1.add_bound(ArrayBoundInfo {
            array_name: "arr1".to_string(),
            min_size: ArrayBoundExpr::Constant(10),
            element_size: 4,
            confidence: BoundConfidence::High,
        });

        let mut bounds2 = ArrayBounds::new();
        bounds2.add_bound(ArrayBoundInfo {
            array_name: "arr2".to_string(),
            min_size: ArrayBoundExpr::Constant(20),
            element_size: 8,
            confidence: BoundConfidence::Medium,
        });

        bounds1.merge(bounds2);

        assert!(bounds1.get_bounds("arr1").is_some());
        assert!(bounds1.get_bounds("arr2").is_some());
    }
}
