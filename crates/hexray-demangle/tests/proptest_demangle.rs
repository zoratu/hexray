//! Property-based tests for symbol demangling.
//!
//! These tests verify that demangling functions handle arbitrary input safely
//! and produce consistent results.

use proptest::prelude::*;

use hexray_demangle::{demangle, demangle_or_original};

// =============================================================================
// Demangling Safety Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    /// Demangling arbitrary strings never panics.
    #[test]
    fn demangle_never_panics(s in ".*") {
        let _ = demangle(&s);
    }


    /// demangle_or_original never panics and always returns something.
    #[test]
    fn demangle_or_original_never_panics(s in ".*") {
        let result = demangle_or_original(&s);
        prop_assert!(!result.is_empty() || s.is_empty(), "Result should not be empty unless input is empty");
    }

    /// demangle_or_original returns original for non-mangled names.
    #[test]
    fn demangle_or_original_preserves_unmangled(s in "[a-zA-Z_][a-zA-Z0-9_]*") {
        // Simple identifiers that don't look mangled
        if !s.starts_with("_Z") && !s.starts_with("?") && !s.starts_with("_R") {
            let result = demangle_or_original(&s);
            prop_assert_eq!(result.as_str(), s.as_str(), "Unmangled names should be preserved");
        }
    }
}

// =============================================================================
// Demangling Determinism Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Demangling is deterministic.
    #[test]
    fn demangle_is_deterministic(s in ".*") {
        let result1 = demangle(&s);
        let result2 = demangle(&s);

        match (&result1, &result2) {
            (Some(d1), Some(d2)) => prop_assert_eq!(d1, d2, "Demangled results should match"),
            (None, None) => {}
            _ => prop_assert!(false, "Demangle results should be consistent"),
        }
    }

    /// demangle_or_original is deterministic.
    #[test]
    fn demangle_or_original_is_deterministic(s in ".*") {
        let result1 = demangle_or_original(&s);
        let result2 = demangle_or_original(&s);
        prop_assert_eq!(result1, result2, "Results should match");
    }
}

// =============================================================================
// Itanium C++ ABI Mangling Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Itanium mangled names starting with _Z should not panic.
    #[test]
    fn itanium_prefix_handling(suffix in "[a-zA-Z0-9_]*") {
        let mangled = format!("_Z{}", suffix);
        let _ = demangle(&mangled);
    }

    /// Nested name handling (N...E format).
    #[test]
    fn itanium_nested_name_handling(
        parts in prop::collection::vec("[0-9]+[a-zA-Z_]+", 1..5)
    ) {
        // Build something like _ZN3foo3barE
        let inner: String = parts.join("");
        let mangled = format!("_ZN{}E", inner);
        let _ = demangle(&mangled);
    }

    /// Function with parameters handling.
    #[test]
    fn itanium_function_params_handling(
        name_len in 1usize..20,
        name in "[a-zA-Z_][a-zA-Z0-9_]*",
        params in "[vibcsilfdDeFv]*"  // Basic type codes
    ) {
        let mangled = format!("_Z{}{}{}", name_len, &name[..name_len.min(name.len())], params);
        let _ = demangle(&mangled);
    }

    /// Template handling (I...E format).
    #[test]
    fn itanium_template_handling(
        name_len in 1usize..10,
        name in "[a-zA-Z_][a-zA-Z0-9_]*",
        template_param in "[vibcsilfd]"
    ) {
        let short_name = &name[..name_len.min(name.len())];
        let mangled = format!("_Z{}{}I{}E", short_name.len(), short_name, template_param);
        let _ = demangle(&mangled);
    }
}

// =============================================================================
// Rust v0 Mangling Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Rust v0 mangled names starting with _R should not panic.
    #[test]
    fn rust_v0_prefix_handling(suffix in "[a-zA-Z0-9_]*") {
        let mangled = format!("_R{}", suffix);
        let _ = demangle(&mangled);
    }

    /// Rust crate and function path handling.
    #[test]
    fn rust_v0_path_handling(
        crate_len in 1usize..20,
        crate_name in "[a-z][a-z0-9_]*",
        func_len in 1usize..20,
        func_name in "[a-z][a-z0-9_]*"
    ) {
        let cn = &crate_name[..crate_len.min(crate_name.len())];
        let fn_ = &func_name[..func_len.min(func_name.len())];
        // Rust v0 format: _RNvC{crate_len}{crate}{func_len}{func}
        let mangled = format!("_RNvC{}{}{}{}", cn.len(), cn, fn_.len(), fn_);
        let _ = demangle(&mangled);
    }

    /// Rust impl handling.
    #[test]
    fn rust_v0_impl_handling(
        type_len in 1usize..10,
        type_name in "[A-Z][a-zA-Z0-9]*"
    ) {
        let tn = &type_name[..type_len.min(type_name.len())];
        // Simplified impl format
        let mangled = format!("_RNvMs_{}{}", tn.len(), tn);
        let _ = demangle(&mangled);
    }
}

// =============================================================================
// MSVC Mangling Properties (if supported)
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// MSVC mangled names starting with ? should not panic.
    #[test]
    fn msvc_prefix_handling(suffix in "[a-zA-Z0-9@_$]*") {
        let mangled = format!("?{}", suffix);
        let _ = demangle(&mangled);
    }

    /// MSVC simple function name handling.
    #[test]
    fn msvc_simple_function(
        name in "[a-zA-Z_][a-zA-Z0-9_]*",
        access in prop::sample::select(vec!["A", "B", "C", "D", "E", "I", "M", "Q", "U"]),
    ) {
        // MSVC format: ?name@@YA...
        let mangled = format!("?{}@@Y{}XZ", name, access);
        let _ = demangle(&mangled);
    }

    /// MSVC class method handling.
    #[test]
    fn msvc_class_method(
        class_name in "[A-Z][a-zA-Z0-9]*",
        method_name in "[a-zA-Z_][a-zA-Z0-9_]*"
    ) {
        // MSVC format: ?method@class@@...
        let mangled = format!("?{}@{}@@QEAAXXZ", method_name, class_name);
        let _ = demangle(&mangled);
    }
}

// =============================================================================
// Edge Cases and Boundary Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Very long mangled names should not cause stack overflow.
    #[test]
    fn long_names_no_stack_overflow(
        repeat in 10usize..100,
        segment in "[a-zA-Z]{3,10}"
    ) {
        // Create a very long nested name
        let inner: String = (0..repeat).map(|_| format!("{}{}", segment.len(), segment)).collect();
        let mangled = format!("_ZN{}E", inner);
        let _ = demangle(&mangled);
    }

    /// Empty and whitespace strings.
    #[test]
    fn whitespace_handling(spaces in "[ \t\n\r]*") {
        let _ = demangle(&spaces);
        let result = demangle_or_original(&spaces);
        prop_assert_eq!(result.as_str(), spaces.as_str(), "Whitespace should be preserved");
    }

    /// Unicode handling.
    #[test]
    fn unicode_handling(s in "\\PC*") {
        // Arbitrary unicode strings
        let _ = demangle(&s);
        // Should not panic
    }

    /// Null bytes in input.
    #[test]
    fn null_byte_handling(
        prefix in "[a-zA-Z_]*",
        suffix in "[a-zA-Z_]*"
    ) {
        let with_null = format!("{}\0{}", prefix, suffix);
        let _ = demangle(&with_null);
    }
}

// =============================================================================
// Output Quality Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Successfully demangled names should be human-readable.
    #[test]
    fn demangled_is_readable(s in "_Z[0-9][a-z]+") {
        if let Some(demangled) = demangle(&s) {
            // Demangled output should not contain mangling artifacts
            prop_assert!(
                !demangled.contains("_Z") || demangled.contains("operator"),
                "Demangled name should not contain raw _Z prefix: {}",
                demangled
            );
        }
    }

    /// Demangled output length is reasonable.
    #[test]
    fn demangled_reasonable_length(s in "_Z[0-9]{1,3}[a-z]{1,20}") {
        if let Some(demangled) = demangle(&s) {
            // Demangled name shouldn't be excessively long
            prop_assert!(
                demangled.len() < s.len() * 10,
                "Demangled name is unreasonably long: {} chars for {} char input",
                demangled.len(),
                s.len()
            );
        }
    }
}
