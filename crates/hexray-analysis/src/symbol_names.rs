/// Strips the top-level argument list from a demangled C++ symbol while preserving
/// parentheses that appear inside template arguments.
pub(crate) fn strip_demangled_signature(name: &str) -> &str {
    if !name.ends_with(')') {
        return name;
    }

    let mut depth = 0i32;

    for (i, byte) in name.bytes().enumerate() {
        match byte {
            b'<' => depth += 1,
            b'>' => depth = (depth - 1).max(0),
            b'(' if depth == 0 => return &name[..i],
            _ => {}
        }
    }

    name
}

#[cfg(test)]
mod tests {
    use super::strip_demangled_signature;

    #[test]
    fn strips_only_outer_demangled_signature() {
        let name = "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset()";

        assert_eq!(
            strip_demangled_signature(name),
            "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset"
        );
    }
}
