//! Shared helpers for recognizing known noreturn functions.

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

#[cfg(test)]
mod tests {
    use super::is_noreturn_function_name;

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
}
