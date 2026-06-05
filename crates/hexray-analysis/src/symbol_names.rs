/// Strips the trailing argument-list parens from a demangled C++ symbol
/// while preserving parens that are part of the identifier itself
/// (`Foo::operator()()` → `Foo::operator()`, never collapses to
/// `Foo::operator`). Walks BACKWARD from the closing `)` and matches it
/// against the nearest unbalanced `(`, so any earlier `()`/`<>` that
/// belong to operator names or template arguments are left intact.
///
/// Returns the input unchanged when it doesn't end in `)` — the
/// signature half is presumably already gone, or what's there isn't a
/// signature at all.
pub(crate) fn strip_demangled_signature(name: &str) -> &str {
    let bytes = name.as_bytes();
    if !bytes.ends_with(b")") {
        return name;
    }
    let mut depth = 0i32;
    let mut idx = bytes.len();
    while idx > 0 {
        idx -= 1;
        match bytes[idx] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return std::str::from_utf8(&bytes[..idx]).unwrap_or(name);
                }
            }
            _ => {}
        }
    }
    // Unbalanced — leave as-is so we don't slice arbitrarily.
    name
}

/// Strip the Itanium-ABI ctor/dtor / clone disambiguator labels that the
/// demangler appends to special-member functions and gcc cold/clone
/// helpers (`Dog::Dog() [base]`, `Dog::~Dog() [deleting]`,
/// `may_throw(int) [clone .cold]`, `widen(int) [clone .isra.0]`).
/// Without this the trailing `[label]` keeps `strip_demangled_signature`
/// from seeing the `(args)` it would otherwise remove, so emitted call
/// sites end up with stray `(args)(...)`.
pub(crate) fn strip_demangler_disambiguator_labels(name: &str) -> &str {
    let mut s = name.trim_end();
    loop {
        let trimmed = s.trim_end();
        let Some(open) = trimmed.rfind(" [") else {
            return s;
        };
        if !trimmed.ends_with(']') {
            return s;
        }
        let inside = &trimmed[open + 2..trimmed.len() - 1];
        // Only consume known disambiguators. `[base]` / `[complete]` /
        // `[allocating]` / `[deleting]` are ctor/dtor variants;
        // `[clone .…]` covers gcc cold-clone / isra / part-of-N partitions.
        let recognised = matches!(inside, "base" | "complete" | "allocating" | "deleting")
            || inside.starts_with("clone .")
            || inside.starts_with("clone ");
        if !recognised {
            return s;
        }
        s = trimmed[..open].trim_end();
    }
}

#[cfg(test)]
mod tests {
    use super::{strip_demangled_signature, strip_demangler_disambiguator_labels};

    #[test]
    fn strips_only_outer_demangled_signature() {
        let name = "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset()";

        assert_eq!(
            strip_demangled_signature(name),
            "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset"
        );
    }

    #[test]
    fn preserves_operator_call_name() {
        // `_ZN3FooclEv` demangles to `Foo::operator()()` — the *first*
        // top-level `(` belongs to the operator name itself, not the
        // signature. The backward-walk strip must remove only the
        // trailing `()` and leave the operator's own `()` intact.
        // (Codex review on PR #12.)
        assert_eq!(
            strip_demangled_signature("Foo::operator()()"),
            "Foo::operator()"
        );
        assert_eq!(
            strip_demangled_signature("Foo::operator()(int)"),
            "Foo::operator()"
        );
        // A genuine signature with a `()` inside a parameter type must
        // still strip the *outer* args, not the inner default-init.
        assert_eq!(
            strip_demangled_signature("Foo::bar(std::function<void()>)"),
            "Foo::bar"
        );
    }

    #[test]
    fn returns_input_when_no_trailing_paren_group() {
        // `name` ends in something other than `)`, so there's no
        // signature to strip.
        assert_eq!(strip_demangled_signature("printf"), "printf");
        assert_eq!(
            strip_demangled_signature("std::vector<int>"),
            "std::vector<int>"
        );
    }

    #[test]
    fn strips_ctor_dtor_disambiguators() {
        // `_ZN3DogC2Ev` demangles to `Dog::Dog() [base]`; the trailing
        // `[base]` keeps the signature stripper from seeing the embedded
        // `()` and produces stray `(args)(...)` at the emit site.
        assert_eq!(
            strip_demangler_disambiguator_labels("Dog::Dog() [base]"),
            "Dog::Dog()"
        );
        assert_eq!(
            strip_demangler_disambiguator_labels("Dog::Dog() [complete]"),
            "Dog::Dog()"
        );
        assert_eq!(
            strip_demangler_disambiguator_labels("Dog::~Dog() [deleting]"),
            "Dog::~Dog()"
        );
        assert_eq!(
            strip_demangler_disambiguator_labels("foo(int) [clone .cold]"),
            "foo(int)"
        );
        assert_eq!(
            strip_demangler_disambiguator_labels("widen(int) [clone .isra.0]"),
            "widen(int)"
        );
    }

    #[test]
    fn keeps_unrecognised_bracketed_suffixes() {
        // We only consume known disambiguators — anything else is part
        // of the identifier and must stay (e.g. user-typedef'd array
        // type as part of a parameter).
        assert_eq!(
            strip_demangler_disambiguator_labels("user::weird [tag]"),
            "user::weird [tag]"
        );
    }
}
