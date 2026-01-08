//! # hexray-demangle
//!
//! Symbol demangling for hexray.
//!
//! Supports:
//! - Itanium C++ ABI (GCC, Clang)
//! - Rust v0 mangling scheme
//!
//! Note: This is a stub implementation. Full demangling is complex
//! and would be implemented incrementally.

/// Attempt to demangle a symbol name.
///
/// Returns the demangled name if successful, or None if the symbol
/// is not mangled or uses an unsupported scheme.
pub fn demangle(name: &str) -> Option<String> {
    // Try C++ Itanium ABI
    if let Some(demangled) = demangle_itanium(name) {
        return Some(demangled);
    }

    // Try Rust v0
    if let Some(demangled) = demangle_rust_v0(name) {
        return Some(demangled);
    }

    None
}

/// Demangle an Itanium C++ ABI symbol.
///
/// Symbols start with `_Z` followed by the mangled name.
fn demangle_itanium(name: &str) -> Option<String> {
    if !name.starts_with("_Z") {
        return None;
    }

    // Very basic implementation - just handles simple function names
    // A full implementation would need a proper parser
    let mangled = &name[2..];

    // Try to extract a simple name
    // Format: _Z<length><name>... for simple functions
    let mut chars = mangled.chars().peekable();
    let mut length_str = String::new();

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            length_str.push(chars.next().unwrap());
        } else {
            break;
        }
    }

    if length_str.is_empty() {
        return None;
    }

    let length: usize = length_str.parse().ok()?;
    let remaining: String = chars.collect();

    if remaining.len() >= length {
        let func_name = &remaining[..length];
        Some(format!("{}()", func_name))
    } else {
        None
    }
}

/// Demangle a Rust v0 mangled symbol.
///
/// Rust v0 symbols start with `_R`.
fn demangle_rust_v0(name: &str) -> Option<String> {
    if !name.starts_with("_R") {
        return None;
    }

    // Very basic implementation
    // Rust v0 mangling is complex; this is just a stub
    // See: https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html

    // For now, just return the raw name without the prefix
    // A full implementation would parse the entire mangling scheme
    Some(format!("<rust: {}>", &name[2..]))
}

/// Returns the demangled name or the original if demangling fails.
pub fn demangle_or_original(name: &str) -> String {
    demangle(name).unwrap_or_else(|| name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_cpp_demangle() {
        // _Z4mainv -> main()
        let result = demangle("_Z4main");
        assert_eq!(result, Some("main()".to_string()));
    }

    #[test]
    fn test_non_mangled() {
        assert_eq!(demangle("printf"), None);
        assert_eq!(demangle("main"), None);
    }

    #[test]
    fn test_demangle_or_original() {
        assert_eq!(demangle_or_original("printf"), "printf");
        assert_eq!(demangle_or_original("_Z4main"), "main()");
    }
}
