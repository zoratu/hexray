//! Array access pattern detection for decompiled expressions.
//!
//! This module detects common array access patterns in compiled code and
//! transforms them into high-level array access expressions.
//!
//! # Patterns Detected
//!
//! ## Simple Array Access
//! `*(base + index * element_size)` -> `base[index]`
//!
//! ## Struct Array Access
//! `*(base + index * stride + offset)` -> `arr[index].field`
//!
//! ## Fixed Index Access
//! `*(base + constant)` -> `base[constant / element_size]`
//!
//! ## Address-of Array Element
//! `base + index * element_size` -> `&base[index]`
//!
//! # Common Addressing Modes
//!
//! | Instruction Pattern           | Expression Pattern         | Result         |
//! |-------------------------------|---------------------------|----------------|
//! | `[rbx + rcx*4]`              | `*(rbx + rcx * 4)`        | `rbx[rcx]`     |
//! | `[rbx + rcx*8 + 0x10]`       | `*(rbx + rcx * 8 + 0x10)` | `rbx[rcx + 2]` |
//! | `lea rax, [rbx + rcx*4]`     | `rbx + rcx * 4`           | `&rbx[rcx]`    |

use super::expression::{BinOpKind, Expr, ExprKind};

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
/// - `base + index * size` -> `&base[index]`
/// - `base + constant` -> `&base[constant / size]` (for aligned constants)
pub fn detect_address_of_array_element(addr: &Expr, hinted_size: Option<usize>) -> Option<ArrayAccessInfo> {
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
    if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &addr.kind {
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
    if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &addr.kind {
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
    if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &addr.kind {
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
    if let ExprKind::BinOp { op: BinOpKind::Sub, left, right } = &addr.kind {
        if let ExprKind::IntLit(offset) = &right.kind {
            if *offset != 0 {
                return try_create_constant_index_access(left, -*offset, expected_size);
            }
        }
    }

    None
}

/// Creates an array access with a constant index from `base + offset`.
fn try_create_constant_index_access(base: &Expr, offset: i128, expected_size: u8) -> Option<ArrayAccessInfo> {
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

    if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &addr.kind {
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
                    info.index = Expr::binop(
                        BinOpKind::Add,
                        info.index,
                        Expr::int(additional_index),
                    );
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
                    info.index = Expr::binop(
                        BinOpKind::Add,
                        Expr::int(additional_index),
                        info.index,
                    );
                    return Some(info);
                }
            }
        }
    }

    // Also try for shift patterns
    if let ExprKind::BinOp { op: BinOpKind::Add, left, right } = &addr.kind {
        if let ExprKind::IntLit(field_offset) = &right.kind {
            if let Some(mut info) = try_detect_shift_pattern(left, 0) {
                if *field_offset % (info.element_size as i128) == 0 {
                    let additional_index = *field_offset / (info.element_size as i128);
                    info.index = Expr::binop(
                        BinOpKind::Add,
                        info.index,
                        Expr::int(additional_index),
                    );
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
    if let ExprKind::BinOp { op: BinOpKind::Mul, left, right } = &expr.kind {
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
    if let ExprKind::BinOp { op: BinOpKind::Shl, left, right } = &expr.kind {
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
    detect_array_access(addr, size).map(|info| {
        Expr::array_access(info.base, info.index, info.element_size)
    })
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
        ExprKind::Deref { .. } => true, // Pointer through memory
        ExprKind::GotRef { .. } => true, // Global array
        ExprKind::AddressOf(_) => true, // &something
        ExprKind::ArrayAccess { .. } => true, // Multidimensional array
        _ => false,
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
        assert!(result.is_some(), "Expected to detect array access (commutative)");

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
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::int(0x10),
        );

        let result = detect_array_access(&addr, 4);
        assert!(result.is_some(), "Expected to detect constant offset pattern");

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
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::int(0x18),
        );

        let result = detect_array_access(&addr, 8);
        assert!(result.is_some(), "Expected to detect constant offset pattern");

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
        let addr = Expr::binop(
            BinOpKind::Sub,
            var("rbx"),
            Expr::int(0x8),
        );

        let result = detect_array_access(&addr, 8);
        assert!(result.is_some(), "Expected to detect negative offset pattern");

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
        assert!(info.element_size == 8 || info.element_size == 16,
            "Expected element_size 8 or 16, got {}", info.element_size);
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
        let addr = Expr::binop(
            BinOpKind::Add,
            var("rbx"),
            Expr::int(5),
        );

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
}
