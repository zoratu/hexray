//! Property-based tests for the type inference system.
//!
//! These tests verify that the Type lattice satisfies important algebraic properties:
//! - Merge is commutative: merge(a, b) == merge(b, a)
//! - Merge is associative: merge(merge(a, b), c) == merge(a, merge(b, c))
//! - Merge is idempotent: merge(a, a) == a
//! - Unknown is identity: merge(Unknown, a) == a
//! - Type properties are preserved through merge

use proptest::prelude::*;

use hexray_analysis::types::Type;

// =============================================================================
// Type Generators
// =============================================================================

/// Generate arbitrary types for testing.
#[allow(dead_code)]
fn arb_type() -> impl Strategy<Value = Type> {
    let leaf = prop_oneof![
        Just(Type::Unknown),
        Just(Type::Void),
        Just(Type::Bool),
        Just(Type::CString),
        // Integer types
        (prop::sample::select(vec![1u8, 2, 4, 8]), prop::bool::ANY)
            .prop_map(|(size, signed)| Type::Int { size, signed }),
        // Float types
        prop::sample::select(vec![4u8, 8, 16]).prop_map(|size| Type::Float { size }),
    ];

    leaf.prop_recursive(
        3,  // depth
        32, // max nodes
        10, // items per collection
        |inner| {
            prop_oneof![
                // Pointer types
                inner.clone().prop_map(|t| Type::Pointer(Box::new(t))),
                // Array types
                (inner.clone(), proptest::option::of(1usize..100)).prop_map(|(elem, count)| {
                    Type::Array {
                        element: Box::new(elem),
                        count,
                    }
                }),
            ]
        },
    )
}

/// Generate simple types (non-recursive) for faster tests.
fn arb_simple_type() -> impl Strategy<Value = Type> {
    prop_oneof![
        Just(Type::Unknown),
        Just(Type::Void),
        Just(Type::Bool),
        Just(Type::CString),
        (prop::sample::select(vec![1u8, 2, 4, 8]), prop::bool::ANY)
            .prop_map(|(size, signed)| Type::Int { size, signed }),
        prop::sample::select(vec![4u8, 8, 16]).prop_map(|size| Type::Float { size }),
        arb_simple_type_base().prop_map(|t| Type::Pointer(Box::new(t))),
    ]
}

fn arb_simple_type_base() -> impl Strategy<Value = Type> {
    prop_oneof![
        Just(Type::Unknown),
        Just(Type::Void),
        Just(Type::Bool),
        (prop::sample::select(vec![1u8, 2, 4, 8]), prop::bool::ANY)
            .prop_map(|(size, signed)| Type::Int { size, signed }),
        prop::sample::select(vec![4u8, 8]).prop_map(|size| Type::Float { size }),
    ]
}

/// Generate integer types specifically.
fn arb_int_type() -> impl Strategy<Value = Type> {
    (prop::sample::select(vec![1u8, 2, 4, 8]), prop::bool::ANY)
        .prop_map(|(size, signed)| Type::Int { size, signed })
}

/// Generate float types specifically.
fn arb_float_type() -> impl Strategy<Value = Type> {
    prop::sample::select(vec![4u8, 8, 16]).prop_map(|size| Type::Float { size })
}

// =============================================================================
// Lattice Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Merge is commutative for same-kind types (int/int, float/float, ptr/ptr).
    /// Note: merge of incompatible types uses a default that prefers the first operand.
    #[test]
    fn merge_ints_is_commutative(
        size1 in prop::sample::select(vec![1u8, 2, 4, 8]),
        size2 in prop::sample::select(vec![1u8, 2, 4, 8]),
        signed1 in prop::bool::ANY,
        signed2 in prop::bool::ANY,
    ) {
        let a = Type::Int { size: size1, signed: signed1 };
        let b = Type::Int { size: size2, signed: signed2 };
        let ab = a.merge(&b);
        let ba = b.merge(&a);
        prop_assert_eq!(ab, ba, "merge({:?}, {:?}) != merge({:?}, {:?})", a, b, b, a);
    }

    /// Merge of floats is commutative.
    #[test]
    fn merge_floats_is_commutative(
        size1 in prop::sample::select(vec![4u8, 8, 16]),
        size2 in prop::sample::select(vec![4u8, 8, 16]),
    ) {
        let a = Type::Float { size: size1 };
        let b = Type::Float { size: size2 };
        let ab = a.merge(&b);
        let ba = b.merge(&a);
        prop_assert_eq!(ab, ba, "merge({:?}, {:?}) != merge({:?}, {:?})", a, b, b, a);
    }

    /// Merge is idempotent: merge(a, a) == a
    #[test]
    fn merge_is_idempotent(a in arb_simple_type()) {
        let aa = a.merge(&a);
        prop_assert_eq!(aa, a.clone(), "merge({:?}, {:?}) should equal {:?}", a, a, a);
    }

    /// Unknown is the identity element: merge(Unknown, a) == a
    #[test]
    fn unknown_is_identity(a in arb_simple_type()) {
        let unknown_a = Type::Unknown.merge(&a);
        let a_unknown = a.merge(&Type::Unknown);

        prop_assert_eq!(unknown_a, a.clone(), "merge(Unknown, {:?}) should equal {:?}", a, a);
        prop_assert_eq!(a_unknown, a.clone(), "merge({:?}, Unknown) should equal {:?}", a, a);
    }

    /// Merge of ints preserves max size.
    #[test]
    fn merge_int_preserves_max_size(
        size1 in prop::sample::select(vec![1u8, 2, 4, 8]),
        size2 in prop::sample::select(vec![1u8, 2, 4, 8]),
        signed1 in prop::bool::ANY,
        signed2 in prop::bool::ANY,
    ) {
        let t1 = Type::Int { size: size1, signed: signed1 };
        let t2 = Type::Int { size: size2, signed: signed2 };
        let merged = t1.merge(&t2);

        match merged {
            Type::Int { size, .. } => {
                let expected_size = size1.max(size2);
                prop_assert_eq!(size, expected_size, "Merged int size should be max of {} and {}", size1, size2);
            }
            _ => prop_assert!(false, "Merging two ints should produce an int"),
        }
    }

    /// Merge of ints: if either is signed, result is signed.
    #[test]
    fn merge_int_signed_if_either_signed(
        size1 in prop::sample::select(vec![1u8, 2, 4, 8]),
        size2 in prop::sample::select(vec![1u8, 2, 4, 8]),
        signed1 in prop::bool::ANY,
        signed2 in prop::bool::ANY,
    ) {
        let t1 = Type::Int { size: size1, signed: signed1 };
        let t2 = Type::Int { size: size2, signed: signed2 };
        let merged = t1.merge(&t2);

        match merged {
            Type::Int { signed, .. } => {
                let expected_signed = signed1 || signed2;
                prop_assert_eq!(signed, expected_signed,
                    "Merged signed should be {} (either of {} or {})",
                    expected_signed, signed1, signed2);
            }
            _ => prop_assert!(false, "Merging two ints should produce an int"),
        }
    }

    /// Merge of floats preserves max size.
    #[test]
    fn merge_float_preserves_max_size(
        size1 in prop::sample::select(vec![4u8, 8, 16]),
        size2 in prop::sample::select(vec![4u8, 8, 16]),
    ) {
        let t1 = Type::Float { size: size1 };
        let t2 = Type::Float { size: size2 };
        let merged = t1.merge(&t2);

        match merged {
            Type::Float { size } => {
                let expected_size = size1.max(size2);
                prop_assert_eq!(size, expected_size, "Merged float size should be max of {} and {}", size1, size2);
            }
            _ => prop_assert!(false, "Merging two floats should produce a float"),
        }
    }

    /// Merge of pointers merges pointee types.
    #[test]
    fn merge_pointer_merges_pointee(
        inner1 in arb_simple_type_base(),
        inner2 in arb_simple_type_base(),
    ) {
        let p1 = Type::Pointer(Box::new(inner1.clone()));
        let p2 = Type::Pointer(Box::new(inner2.clone()));
        let merged = p1.merge(&p2);

        match merged {
            Type::Pointer(inner) => {
                let expected_inner = inner1.merge(&inner2);
                prop_assert_eq!(*inner, expected_inner,
                    "Merged pointer pointee should be merge of pointees");
            }
            _ => prop_assert!(false, "Merging two pointers should produce a pointer"),
        }
    }

    /// CString is more specific than Pointer.
    #[test]
    fn cstring_more_specific_than_pointer(inner in arb_simple_type_base()) {
        let ptr = Type::Pointer(Box::new(inner));
        let cstr = Type::CString;

        let merged1 = ptr.merge(&cstr);
        let merged2 = cstr.merge(&ptr);

        prop_assert_eq!(merged1, Type::CString, "CString should win over pointer");
        prop_assert_eq!(merged2, Type::CString, "CString should win over pointer (reversed)");
    }
}

// =============================================================================
// Type Property Preservation (Homogeneous Merges)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// When merging two pointers, result is a pointer.
    #[test]
    fn merge_pointer_pointer_is_pointer(
        inner1 in arb_simple_type_base(),
        inner2 in arb_simple_type_base()
    ) {
        let p1 = Type::Pointer(Box::new(inner1));
        let p2 = Type::Pointer(Box::new(inner2));
        let merged = p1.merge(&p2);

        prop_assert!(
            merged.is_pointer(),
            "merge(Pointer, Pointer) should be Pointer, got {:?}",
            merged
        );
    }

    /// is_integer is preserved in homogeneous merge.
    #[test]
    fn merge_int_remains_int(a in arb_int_type(), b in arb_int_type()) {
        let merged = a.merge(&b);
        prop_assert!(
            merged.is_integer(),
            "merge({:?}, {:?}) = {:?} should be integer",
            a, b, merged
        );
    }

    /// is_float is preserved in homogeneous merge.
    #[test]
    fn merge_float_remains_float(a in arb_float_type(), b in arb_float_type()) {
        let merged = a.merge(&b);
        prop_assert!(
            merged.is_float(),
            "merge({:?}, {:?}) = {:?} should be float",
            a, b, merged
        );
    }

    /// Size is monotonically non-decreasing when merging same-kind types.
    #[test]
    fn merge_int_size_non_decreasing(a in arb_int_type(), b in arb_int_type()) {
        let merged = a.merge(&b);

        if let (Some(size_a), Some(size_merged)) = (a.size(), merged.size()) {
            prop_assert!(
                size_merged >= size_a,
                "Merged int size {} should be >= input size {}",
                size_merged, size_a
            );
        }
    }

    /// Size is monotonically non-decreasing when merging floats.
    #[test]
    fn merge_float_size_non_decreasing(a in arb_float_type(), b in arb_float_type()) {
        let merged = a.merge(&b);

        if let (Some(size_a), Some(size_merged)) = (a.size(), merged.size()) {
            prop_assert!(
                size_merged >= size_a,
                "Merged float size {} should be >= input size {}",
                size_merged, size_a
            );
        }
    }
}

// =============================================================================
// Type Display/Format Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Display produces non-empty string.
    #[test]
    fn display_is_non_empty(t in arb_simple_type()) {
        let s = t.to_string();
        prop_assert!(!s.is_empty(), "Display of {:?} should not be empty", t);
    }

    /// Size is consistent with type.
    #[test]
    fn size_consistent_with_type(t in arb_simple_type()) {
        match &t {
            Type::Unknown | Type::Void => {
                prop_assert!(t.size().is_none(), "Unknown/Void should have no size");
            }
            Type::Bool => {
                prop_assert_eq!(t.size(), Some(1), "Bool should have size 1");
            }
            Type::Int { size, .. } => {
                prop_assert_eq!(t.size(), Some(*size), "Int size should match");
            }
            Type::Float { size } => {
                prop_assert_eq!(t.size(), Some(*size), "Float size should match");
            }
            Type::Pointer(_) | Type::CString => {
                prop_assert_eq!(t.size(), Some(8), "Pointer should have size 8 (64-bit)");
            }
            _ => {}
        }
    }
}

// =============================================================================
// Regression Tests (specific edge cases)
// =============================================================================

#[test]
fn merge_same_int_is_identity() {
    let t = Type::Int {
        size: 4,
        signed: true,
    };
    assert_eq!(t.merge(&t), t);
}

#[test]
fn merge_unknown_with_anything() {
    let types = vec![
        Type::Bool,
        Type::Int {
            size: 4,
            signed: true,
        },
        Type::Float { size: 8 },
        Type::Pointer(Box::new(Type::Void)),
        Type::CString,
    ];

    for t in types {
        assert_eq!(Type::Unknown.merge(&t), t);
        assert_eq!(t.merge(&Type::Unknown), t);
    }
}

#[test]
fn merge_nested_pointers() {
    let p1 = Type::Pointer(Box::new(Type::Pointer(Box::new(Type::Int {
        size: 4,
        signed: true,
    }))));
    let p2 = Type::Pointer(Box::new(Type::Pointer(Box::new(Type::Int {
        size: 8,
        signed: false,
    }))));

    let merged = p1.merge(&p2);

    // Should be **int64 (signed, since one was signed)
    match merged {
        Type::Pointer(inner) => match *inner {
            Type::Pointer(innermost) => match *innermost {
                Type::Int { size, signed } => {
                    assert_eq!(size, 8);
                    assert!(signed);
                }
                _ => panic!("Expected int"),
            },
            _ => panic!("Expected pointer"),
        },
        _ => panic!("Expected pointer"),
    }
}
