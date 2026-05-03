//! Shared helpers for recognizing known noreturn functions.

use hexray_core::Symbol;
use std::collections::HashSet;

/// Returns true when `name` is a known noreturn function.
pub fn is_noreturn_function_name(name: &str) -> bool {
    // Mach-O, PLT, and thunk symbols often grow one or more leading underscores.
    let name = name.trim_start_matches('_');

    matches!(
        name,
        "exit"
            | "Exit"
            | "abort"
            | "assert"
            | "assert_fail"
            | "assert_rtn"
            | "panic"
            | "cxa_throw"
            | "cxa_rethrow"
            | "cxa_bad_cast"
            | "cxa_bad_typeid"
            | "Unwind_Resume"
            | "err"
            | "errx"
            | "verr"
            | "verrx"
            | "longjmp"
            | "siglongjmp"
            | "pthread_exit"
            | "thrd_exit"
            | "quick_exit"
            | "stack_chk_fail"
            | "fortify_fail"
    )
}

/// Collect the addresses of known noreturn symbols.
pub fn collect_noreturn_targets<'a>(symbols: impl IntoIterator<Item = &'a Symbol>) -> HashSet<u64> {
    symbols
        .into_iter()
        .filter(|symbol| is_noreturn_function_name(&symbol.name))
        .map(|symbol| symbol.address)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{collect_noreturn_targets, is_noreturn_function_name};
    use hexray_core::{Symbol, SymbolBinding, SymbolKind};
    use std::collections::HashSet;

    #[test]
    fn matches_macho_prefixed_names() {
        for name in ["_exit", "__assert_rtn", "_abort", "__stack_chk_fail"] {
            assert!(is_noreturn_function_name(name), "{name} should be noreturn");
        }
    }

    #[test]
    fn rejects_normal_functions() {
        for name in ["printf", "_malloc", "main", ""] {
            assert!(
                !is_noreturn_function_name(name),
                "{name} should not be noreturn"
            );
        }
    }

    #[test]
    fn collects_noreturn_symbol_addresses() {
        let symbols = vec![
            Symbol {
                name: "_exit".to_string(),
                address: 0x1000,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "printf".to_string(),
                address: 0x2000,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
        ];

        let targets = collect_noreturn_targets(symbols.iter());
        assert_eq!(targets, HashSet::from([0x1000]));
    }
}
