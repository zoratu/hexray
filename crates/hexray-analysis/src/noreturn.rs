//! Shared helpers for recognizing known noreturn functions.

use hexray_core::Symbol;
use std::collections::HashSet;

/// Returns true when `name` is a known noreturn function.
pub fn is_noreturn_function_name(name: &str) -> bool {
    // Mach-O, PLT, and thunk symbols often grow one or more leading underscores.
    let name = name.trim_start_matches('_');
    let name = name
        .split_once("@plt")
        .map(|(base, _)| base)
        .unwrap_or(name);
    let name = name
        .split_once("@@")
        .map(|(base, _)| base)
        .unwrap_or_else(|| name.split('@').next().unwrap_or(name));

    is_asan_report_function(name)
        || matches!(
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

/// Returns true when `name` names a recoverable UBSan helper.
pub fn is_ubsan_handler_function_name(name: &str) -> bool {
    name.trim_start_matches('_').starts_with("ubsan_handle_")
}

fn is_asan_report_function(name: &str) -> bool {
    name.starts_with("asan_report_") && !name.ends_with("_noabort")
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
    use super::{
        collect_noreturn_targets, is_noreturn_function_name, is_ubsan_handler_function_name,
    };
    use hexray_core::{Symbol, SymbolBinding, SymbolKind};
    use std::collections::HashSet;

    #[test]
    fn matches_macho_prefixed_names() {
        for name in ["_exit", "__assert_rtn", "_abort", "__stack_chk_fail"] {
            assert!(is_noreturn_function_name(name), "{name} should be noreturn");
        }
    }

    #[test]
    fn matches_versioned_and_plt_noreturn_names() {
        for name in [
            "__stack_chk_fail@GLIBC_2.4",
            "__stack_chk_fail@GLIBC_2.4@plt",
            "__fortify_fail@plt",
        ] {
            assert!(is_noreturn_function_name(name), "{name} should be noreturn");
        }
    }

    #[test]
    fn rejects_normal_functions() {
        for name in [
            "printf",
            "_malloc",
            "main",
            "",
            "__asan_report_load4_noabort",
        ] {
            assert!(
                !is_noreturn_function_name(name),
                "{name} should not be noreturn"
            );
        }
    }

    #[test]
    fn matches_asan_report_functions() {
        for name in [
            "__asan_report_load1",
            "__asan_report_load4",
            "__asan_report_load_n",
            "__asan_report_store1",
            "__asan_report_store16",
            "__asan_report_store_n",
        ] {
            assert!(is_noreturn_function_name(name), "{name} should be noreturn");
        }
    }

    #[test]
    fn matches_ubsan_handler_functions() {
        for name in [
            "__ubsan_handle_add_overflow",
            "__ubsan_handle_divrem_overflow@plt",
            "___ubsan_handle_pointer_overflow",
        ] {
            assert!(
                is_ubsan_handler_function_name(name),
                "{name} should be recognized as a UBSan helper"
            );
        }
        assert!(!is_ubsan_handler_function_name("__asan_report_load4"));
    }

    #[test]
    fn collects_noreturn_symbol_addresses() {
        let symbols = [
            Symbol {
                name: "_exit".to_string(),
                address: 0x1000,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "__asan_report_load4".to_string(),
                address: 0x1800,
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
        assert_eq!(targets, HashSet::from([0x1000, 0x1800]));
    }
}
