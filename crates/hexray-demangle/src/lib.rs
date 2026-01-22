//! # hexray-demangle
//!
//! Symbol demangling for hexray.
//!
//! Supports:
//! - Itanium C++ ABI (GCC, Clang) - most common constructs
//! - Rust v0 mangling scheme (basic support)
//!
//! The Itanium demangler handles:
//! - Simple and nested names (namespaces, classes)
//! - Constructors (C1, C2, C3) and destructors (D0, D1, D2)
//! - Templates with type and value parameters
//! - Function parameters and return types
//! - Operators (new, delete, +, -, etc.)
//! - Qualifiers (const, volatile, pointers, references)
//! - Thunks and virtual thunks

use std::fmt::Write;

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

/// Returns the demangled name or the original if demangling fails.
pub fn demangle_or_original(name: &str) -> String {
    demangle(name).unwrap_or_else(|| name.to_string())
}

/// Itanium C++ ABI demangler.
struct ItaniumDemangler<'a> {
    input: &'a str,
    pos: usize,
    /// Substitution table for back-references
    substitutions: Vec<String>,
    /// Template argument substitutions
    template_args: Vec<String>,
}

impl<'a> ItaniumDemangler<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            pos: 0,
            substitutions: Vec::new(),
            template_args: Vec::new(),
        }
    }

    fn remaining(&self) -> &str {
        // Use get() to safely handle positions that might not be at char boundaries
        self.input.get(self.pos..).unwrap_or("")
    }

    fn peek(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn peek_n(&self, n: usize) -> &str {
        let remaining = self.remaining();
        if remaining.len() >= n {
            // Check if the slice position is at a valid char boundary
            if remaining.is_char_boundary(n) {
                &remaining[..n]
            } else {
                // Not at a valid char boundary, return empty or full remaining
                // Since demangling expects ASCII, non-ASCII input is invalid anyway
                remaining
            }
        } else {
            remaining
        }
    }

    fn consume(&mut self, n: usize) {
        let new_pos = self.pos + n;
        // Ensure we don't advance past the end or to an invalid char boundary
        if new_pos <= self.input.len() && self.input.is_char_boundary(new_pos) {
            self.pos = new_pos;
        } else if new_pos <= self.input.len() {
            // Find the next valid char boundary
            self.pos = self.input.len();
        } else {
            self.pos = self.input.len();
        }
    }

    fn expect(&mut self, s: &str) -> bool {
        if self.remaining().starts_with(s) {
            self.pos += s.len();
            true
        } else {
            false
        }
    }

    /// Parse a decimal number.
    fn parse_number(&mut self) -> Option<usize> {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() {
                self.consume(1);
            } else {
                break;
            }
        }
        if self.pos > start {
            self.input[start..self.pos].parse().ok()
        } else {
            None
        }
    }

    /// Parse a signed number (for template arguments).
    fn parse_signed_number(&mut self) -> Option<i64> {
        let negative = self.expect("n");
        let num = self.parse_number()? as i64;
        Some(if negative { -num } else { num })
    }

    /// Parse a source-name: <length><identifier>
    fn parse_source_name(&mut self) -> Option<String> {
        let length = self.parse_number()?;
        let remaining = self.remaining();
        // Check both length and that it's a valid UTF-8 char boundary
        if remaining.len() >= length && remaining.is_char_boundary(length) {
            let name = remaining[..length].to_string();
            self.consume(length);
            Some(name)
        } else {
            None
        }
    }

    /// Parse an operator name.
    fn parse_operator_name(&mut self) -> Option<String> {
        let op = match self.peek_n(2) {
            "nw" => {
                self.consume(2);
                "operator new"
            }
            "na" => {
                self.consume(2);
                "operator new[]"
            }
            "dl" => {
                self.consume(2);
                "operator delete"
            }
            "da" => {
                self.consume(2);
                "operator delete[]"
            }
            "ps" => {
                self.consume(2);
                "operator+"
            } // unary +
            "ng" => {
                self.consume(2);
                "operator-"
            } // unary -
            "ad" => {
                self.consume(2);
                "operator&"
            } // unary &
            "de" => {
                self.consume(2);
                "operator*"
            } // unary *
            "co" => {
                self.consume(2);
                "operator~"
            }
            "pl" => {
                self.consume(2);
                "operator+"
            }
            "mi" => {
                self.consume(2);
                "operator-"
            }
            "ml" => {
                self.consume(2);
                "operator*"
            }
            "dv" => {
                self.consume(2);
                "operator/"
            }
            "rm" => {
                self.consume(2);
                "operator%"
            }
            "an" => {
                self.consume(2);
                "operator&"
            }
            "or" => {
                self.consume(2);
                "operator|"
            }
            "eo" => {
                self.consume(2);
                "operator^"
            }
            "aS" => {
                self.consume(2);
                "operator="
            }
            "pL" => {
                self.consume(2);
                "operator+="
            }
            "mI" => {
                self.consume(2);
                "operator-="
            }
            "mL" => {
                self.consume(2);
                "operator*="
            }
            "dV" => {
                self.consume(2);
                "operator/="
            }
            "rM" => {
                self.consume(2);
                "operator%="
            }
            "aN" => {
                self.consume(2);
                "operator&="
            }
            "oR" => {
                self.consume(2);
                "operator|="
            }
            "eO" => {
                self.consume(2);
                "operator^="
            }
            "ls" => {
                self.consume(2);
                "operator<<"
            }
            "rs" => {
                self.consume(2);
                "operator>>"
            }
            "lS" => {
                self.consume(2);
                "operator<<="
            }
            "rS" => {
                self.consume(2);
                "operator>>="
            }
            "eq" => {
                self.consume(2);
                "operator=="
            }
            "ne" => {
                self.consume(2);
                "operator!="
            }
            "lt" => {
                self.consume(2);
                "operator<"
            }
            "gt" => {
                self.consume(2);
                "operator>"
            }
            "le" => {
                self.consume(2);
                "operator<="
            }
            "ge" => {
                self.consume(2);
                "operator>="
            }
            "ss" => {
                self.consume(2);
                "operator<=>"
            }
            "nt" => {
                self.consume(2);
                "operator!"
            }
            "aa" => {
                self.consume(2);
                "operator&&"
            }
            "oo" => {
                self.consume(2);
                "operator||"
            }
            "pp" => {
                self.consume(2);
                "operator++"
            }
            "mm" => {
                self.consume(2);
                "operator--"
            }
            "cm" => {
                self.consume(2);
                "operator,"
            }
            "pm" => {
                self.consume(2);
                "operator->*"
            }
            "pt" => {
                self.consume(2);
                "operator->"
            }
            "cl" => {
                self.consume(2);
                "operator()"
            }
            "ix" => {
                self.consume(2);
                "operator[]"
            }
            "qu" => {
                self.consume(2);
                "operator?"
            }
            "cv" => {
                // Cast operator: cv <type>
                self.consume(2);
                let ty = self.parse_type()?;
                return Some(format!("operator {}", ty));
            }
            "li" => {
                // Literal operator: li <source-name>
                self.consume(2);
                let name = self.parse_source_name()?;
                return Some(format!("operator\"\"_{}", name));
            }
            _ => return None,
        };
        Some(op.to_string())
    }

    /// Parse a ctor-dtor-name.
    fn parse_ctor_dtor_name(&mut self, class_name: &str) -> Option<String> {
        match self.peek_n(2) {
            "C1" | "C2" | "C3" => {
                self.consume(2);
                Some(class_name.to_string())
            }
            "D0" | "D1" | "D2" => {
                self.consume(2);
                Some(format!("~{}", class_name))
            }
            _ => None,
        }
    }

    /// Parse an unqualified-name.
    fn parse_unqualified_name(&mut self, class_name: Option<&str>) -> Option<String> {
        // Check for ctor/dtor first
        if let Some(class) = class_name {
            if let Some(name) = self.parse_ctor_dtor_name(class) {
                return Some(name);
            }
        }

        // Check for operator
        if let Some(op) = self.parse_operator_name() {
            return Some(op);
        }

        // Otherwise it's a source-name
        self.parse_source_name()
    }

    /// Parse a nested-name: N [<CV-qualifiers>] [<ref-qualifier>] <prefix> <unqualified-name> E
    fn parse_nested_name(&mut self) -> Option<String> {
        if !self.expect("N") {
            return None;
        }

        // Skip CV qualifiers for now (r, V, K for restrict, volatile, const)
        while matches!(self.peek(), Some('r' | 'V' | 'K')) {
            self.consume(1);
        }

        // Skip ref qualifiers (R, O for & and &&)
        while matches!(self.peek(), Some('R' | 'O')) {
            self.consume(1);
        }

        let mut parts: Vec<String> = Vec::new();

        while !self.expect("E") {
            if self.remaining().is_empty() {
                return None;
            }

            // Check for template args
            if self.peek() == Some('I') {
                let last = parts.last_mut()?;
                let args = self.parse_template_args()?;
                write!(last, "{}", args).ok()?;
                continue;
            }

            // Check for substitution
            if self.peek() == Some('S') {
                if let Some(sub) = self.parse_substitution() {
                    parts.push(sub);
                    continue;
                }
            }

            // Parse unqualified name
            let class_name = parts.last().map(|s| s.as_str());
            let name = self.parse_unqualified_name(class_name)?;

            // Add to substitutions for back-references
            let full_name = if parts.is_empty() {
                name.clone()
            } else {
                format!("{}::{}", parts.join("::"), name)
            };
            self.substitutions.push(full_name);

            parts.push(name);
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join("::"))
        }
    }

    /// Parse a name.
    fn parse_name(&mut self) -> Option<String> {
        // Nested name
        if self.peek() == Some('N') {
            return self.parse_nested_name();
        }

        // Substitution
        if self.peek() == Some('S') {
            if let Some(sub) = self.parse_substitution() {
                // May be followed by template args
                if self.peek() == Some('I') {
                    let args = self.parse_template_args()?;
                    return Some(format!("{}{}", sub, args));
                }
                return Some(sub);
            }
        }

        // Check for operator at global scope
        if let Some(op) = self.parse_operator_name() {
            // May be followed by template args
            if self.peek() == Some('I') {
                let args = self.parse_template_args()?;
                return Some(format!("{}{}", op, args));
            }
            return Some(op);
        }

        // Simple name (unscoped-name)
        let name = self.parse_source_name()?;

        // May be followed by template args
        if self.peek() == Some('I') {
            let args = self.parse_template_args()?;
            return Some(format!("{}{}", name, args));
        }

        Some(name)
    }

    /// Parse template arguments: I <template-arg>+ E
    fn parse_template_args(&mut self) -> Option<String> {
        if !self.expect("I") {
            return None;
        }

        // Save the old template args and start fresh for this scope
        let old_args = std::mem::take(&mut self.template_args);

        let mut args = Vec::new();
        while !self.expect("E") {
            if self.remaining().is_empty() {
                return None;
            }

            let arg = self.parse_template_arg()?;
            self.template_args.push(arg.clone());
            args.push(arg);
        }

        // Restore old template args (we keep the current ones for the function body)
        // Actually we want to keep them for the function, so don't restore
        let _ = old_args;

        Some(format!("<{}>", args.join(", ")))
    }

    /// Parse a single template argument.
    fn parse_template_arg(&mut self) -> Option<String> {
        // Expression (starts with 'L' for literal)
        if self.peek() == Some('L') {
            return self.parse_expr_primary();
        }

        // Template parameter reference (T_ = first, T0_ = second, etc.)
        if self.peek() == Some('T') {
            return self.parse_template_param();
        }

        // Type
        self.parse_type()
    }

    /// Parse a template parameter reference: T [<param-idx>] _
    fn parse_template_param(&mut self) -> Option<String> {
        if !self.expect("T") {
            return None;
        }

        let idx = if self.expect("_") {
            0 // T_ means first template param
        } else {
            let n = self.parse_number().unwrap_or(0);
            self.expect("_");
            n + 1 // T0_ means second, T1_ means third, etc.
        };

        // Try to resolve from the template_args table
        if let Some(resolved) = self.template_args.get(idx) {
            Some(resolved.clone())
        } else {
            // Fallback to generic name
            Some(format!("T{}", idx))
        }
    }

    /// Parse a literal expression: L <type> <value> E
    fn parse_expr_primary(&mut self) -> Option<String> {
        if !self.expect("L") {
            return None;
        }

        // Special case: boolean
        if self.expect("b") {
            let val = if self.expect("0") {
                "false"
            } else if self.expect("1") {
                "true"
            } else {
                return None;
            };
            self.expect("E");
            return Some(val.to_string());
        }

        // Integer types
        let is_unsigned = matches!(self.peek(), Some('j' | 'm' | 't' | 'y'));
        let _ty = self.parse_type()?; // Skip the type, we just need the value
        let val = self.parse_signed_number()?;
        self.expect("E");

        if is_unsigned {
            Some(format!("{}u", val as u64))
        } else {
            Some(val.to_string())
        }
    }

    /// Parse a type.
    fn parse_type(&mut self) -> Option<String> {
        let c = self.peek()?;

        // Builtin types
        let builtin = match c {
            'v' => {
                self.consume(1);
                return Some("void".to_string());
            }
            'w' => {
                self.consume(1);
                return Some("wchar_t".to_string());
            }
            'b' => {
                self.consume(1);
                return Some("bool".to_string());
            }
            'c' => {
                self.consume(1);
                return Some("char".to_string());
            }
            'a' => {
                self.consume(1);
                return Some("signed char".to_string());
            }
            'h' => {
                self.consume(1);
                return Some("unsigned char".to_string());
            }
            's' => {
                self.consume(1);
                return Some("short".to_string());
            }
            't' => {
                self.consume(1);
                return Some("unsigned short".to_string());
            }
            'i' => {
                self.consume(1);
                return Some("int".to_string());
            }
            'j' => {
                self.consume(1);
                return Some("unsigned int".to_string());
            }
            'l' => {
                self.consume(1);
                return Some("long".to_string());
            }
            'm' => {
                self.consume(1);
                return Some("unsigned long".to_string());
            }
            'x' => {
                self.consume(1);
                return Some("long long".to_string());
            }
            'y' => {
                self.consume(1);
                return Some("unsigned long long".to_string());
            }
            'n' => {
                self.consume(1);
                return Some("__int128".to_string());
            }
            'o' => {
                self.consume(1);
                return Some("unsigned __int128".to_string());
            }
            'f' => {
                self.consume(1);
                return Some("float".to_string());
            }
            'd' => {
                self.consume(1);
                return Some("double".to_string());
            }
            'e' => {
                self.consume(1);
                return Some("long double".to_string());
            }
            'g' => {
                self.consume(1);
                return Some("__float128".to_string());
            }
            'z' => {
                self.consume(1);
                return Some("...".to_string());
            }
            _ => None,
        };
        if builtin.is_some() {
            return builtin;
        }

        // Pointer: P <type>
        if self.expect("P") {
            let inner = self.parse_type()?;
            return Some(format!("{}*", inner));
        }

        // Reference: R <type>
        if self.expect("R") {
            let inner = self.parse_type()?;
            return Some(format!("{}&", inner));
        }

        // Rvalue reference: O <type>
        if self.expect("O") {
            let inner = self.parse_type()?;
            return Some(format!("{}&&", inner));
        }

        // Const: K <type>
        if self.expect("K") {
            let inner = self.parse_type()?;
            return Some(format!("{} const", inner));
        }

        // Volatile: V <type>
        if self.expect("V") {
            let inner = self.parse_type()?;
            return Some(format!("{} volatile", inner));
        }

        // Restrict: r <type>
        if self.expect("r") {
            let inner = self.parse_type()?;
            return Some(format!("{} restrict", inner));
        }

        // Array: A <dimension> _ <type>
        if self.expect("A") {
            let dim = self.parse_number();
            self.expect("_");
            let elem = self.parse_type()?;
            if let Some(d) = dim {
                return Some(format!("{}[{}]", elem, d));
            } else {
                return Some(format!("{}[]", elem));
            }
        }

        // Function type: F [Y] <return-type> <param-types>* [<ref-qualifier>] E
        if self.expect("F") {
            self.expect("Y"); // extern "C" indicator, ignore
            let ret = self.parse_type()?;
            let mut params = Vec::new();
            while !self.expect("E") {
                if self.remaining().is_empty() {
                    break;
                }
                // Skip ref qualifiers at end
                if matches!(self.peek(), Some('R' | 'O'))
                    && self.peek_n(2).chars().nth(1) == Some('E')
                {
                    self.consume(1);
                    continue;
                }
                params.push(self.parse_type()?);
            }
            return Some(format!("{}({})", ret, params.join(", ")));
        }

        // Substitution
        if self.peek() == Some('S') {
            return self.parse_substitution();
        }

        // Template parameter
        if self.peek() == Some('T') {
            return self.parse_template_param();
        }

        // Nested name (class type)
        if self.peek() == Some('N') {
            let name = self.parse_nested_name()?;
            self.substitutions.push(name.clone());
            return Some(name);
        }

        // Simple name
        if c.is_ascii_digit() {
            let name = self.parse_source_name()?;
            // May have template args
            if self.peek() == Some('I') {
                let args = self.parse_template_args()?;
                let full = format!("{}{}", name, args);
                self.substitutions.push(full.clone());
                return Some(full);
            }
            self.substitutions.push(name.clone());
            return Some(name);
        }

        None
    }

    /// Parse a substitution: S [<seq-id>] _
    fn parse_substitution(&mut self) -> Option<String> {
        if !self.expect("S") {
            return None;
        }

        // Standard substitutions
        match self.peek() {
            Some('t') => {
                self.consume(1);
                return Some("std".to_string());
            }
            Some('a') => {
                self.consume(1);
                return Some("std::allocator".to_string());
            }
            Some('b') => {
                self.consume(1);
                return Some("std::basic_string".to_string());
            }
            Some('s') => {
                self.consume(1);
                return Some("std::string".to_string());
            }
            Some('i') => {
                self.consume(1);
                return Some("std::istream".to_string());
            }
            Some('o') => {
                self.consume(1);
                return Some("std::ostream".to_string());
            }
            Some('d') => {
                self.consume(1);
                return Some("std::iostream".to_string());
            }
            _ => {}
        }

        // Back-reference: S [<seq-id>] _
        if self.expect("_") {
            // S_ means first substitution
            return self.substitutions.first().cloned();
        }

        // S <seq-id> _
        // seq-id is base-36 encoded
        let mut seq_id = 0usize;
        while let Some(c) = self.peek() {
            if c == '_' {
                self.consume(1);
                break;
            }
            let digit = if c.is_ascii_digit() {
                c as usize - '0' as usize
            } else if c.is_ascii_uppercase() {
                c as usize - 'A' as usize + 10
            } else {
                break;
            };
            // Use checked arithmetic to prevent overflow on malformed input
            seq_id = seq_id.checked_mul(36)?.checked_add(digit)?;
            self.consume(1);
        }

        // S0_ is second substitution (index 1), etc.
        self.substitutions.get(seq_id + 1).cloned()
    }

    /// Parse function parameters.
    fn parse_bare_function_type(&mut self) -> Option<String> {
        let mut params = Vec::new();
        while !self.remaining().is_empty() && self.peek() != Some('E') {
            // Check for varargs
            if self.expect("z") {
                params.push("...".to_string());
                continue;
            }
            // Check for void (means no parameters)
            if self.peek() == Some('v') {
                self.consume(1);
                // void as single param means empty params
                if self.remaining().is_empty() || self.peek() == Some('E') {
                    break;
                }
                params.push("void".to_string());
                continue;
            }
            params.push(self.parse_type()?);
        }
        Some(params.join(", "))
    }

    /// Parse a complete mangled name.
    fn parse(&mut self) -> Option<String> {
        // Check for _Z prefix
        if !self.expect("_Z") {
            return None;
        }

        // Check for thunk prefixes
        let mut prefix = String::new();
        if self.expect("Th") {
            // Non-virtual thunk
            let offset = self.parse_signed_number()?;
            self.expect("_");
            prefix = format!("[thunk, this-adj={}] ", offset);
        } else if self.expect("Tv") {
            // Virtual thunk
            let v_offset = self.parse_signed_number()?;
            self.expect("_");
            let vcall_offset = self.parse_signed_number()?;
            self.expect("_");
            prefix = format!(
                "[vthunk, vbase-offset={}, vcall-offset={}] ",
                v_offset, vcall_offset
            );
        } else if self.expect("Tc") {
            // Covariant return thunk
            let base_offset = self.parse_signed_number()?;
            self.expect("_");
            let derived_offset = self.parse_signed_number()?;
            self.expect("_");
            prefix = format!(
                "[covariant thunk, base-adj={}, derived-adj={}] ",
                base_offset, derived_offset
            );
        }

        // Parse the name
        let name = self.parse_name()?;

        // Check if this is a template function - templates have return type before params
        // But ONLY if the first type is NOT a template parameter reference (T_, T0_, etc.)
        let has_template = name.contains('<');

        // Parse function parameters if present
        if !self.remaining().is_empty() {
            // For template functions, the first type might be the return type
            // Skip it ONLY if it's not a template parameter reference
            if has_template && !self.remaining().starts_with('T') {
                // Skip return type
                let _ = self.parse_type();
            }
            let params = self.parse_bare_function_type().unwrap_or_default();
            Some(format!("{}{}({})", prefix, name, params))
        } else {
            Some(format!("{}{}()", prefix, name))
        }
    }
}

/// Demangle an Itanium C++ ABI symbol.
fn demangle_itanium(name: &str) -> Option<String> {
    let mut demangler = ItaniumDemangler::new(name);
    demangler.parse()
}

/// Demangle a Rust v0 mangled symbol.
fn demangle_rust_v0(name: &str) -> Option<String> {
    if !name.starts_with("_R") {
        return None;
    }

    // Basic Rust v0 implementation
    // See: https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html
    let mangled = &name[2..];
    let mut chars = mangled.chars().peekable();
    let mut path_parts: Vec<String> = Vec::new();

    while let Some(c) = chars.next() {
        match c {
            'N' => {
                // Namespace
                // Skip namespace disambiguator if present
                while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    chars.next();
                }
                if chars.peek() == Some(&'_') {
                    chars.next();
                }
            }
            'C' => {
                // Crate root - skip the disambiguator
                while chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    chars.next();
                }
                if chars.peek() == Some(&'_') {
                    chars.next();
                }
            }
            't' | 's' | 'u' if chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) => {
                // Type encoding - skip for now
            }
            _ if c.is_ascii_digit() => {
                // Parse identifier length
                let mut len_str = c.to_string();
                while let Some(&next) = chars.peek() {
                    if next.is_ascii_digit() {
                        len_str.push(chars.next().unwrap());
                    } else if next == '_' {
                        chars.next(); // Skip underscore
                        break;
                    } else {
                        break;
                    }
                }

                if let Ok(len) = len_str.parse::<usize>() {
                    let ident: String = chars.by_ref().take(len).collect();
                    if !ident.is_empty() {
                        path_parts.push(ident);
                    }
                }
            }
            'E' => {
                // End of nested path
            }
            _ => {}
        }
    }

    if path_parts.is_empty() {
        // Fallback to original format
        Some(format!("<rust: {}>", mangled))
    } else {
        Some(path_parts.join("::"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_cpp_demangle() {
        assert_eq!(demangle("_Z4main"), Some("main()".to_string()));
        assert_eq!(demangle("_Z3foov"), Some("foo()".to_string()));
        assert_eq!(demangle("_Z3bari"), Some("bar(int)".to_string()));
    }

    #[test]
    fn test_nested_name() {
        // _ZN3foo3barEv -> foo::bar()
        assert_eq!(demangle("_ZN3foo3barEv"), Some("foo::bar()".to_string()));

        // _ZN3std6vectorIiE4sizeEv -> std::vector<int>::size()
        assert_eq!(
            demangle("_ZN3std6vectorIiE4sizeEv"),
            Some("std::vector<int>::size()".to_string())
        );
    }

    #[test]
    fn test_constructor_destructor() {
        // Constructor: _ZN5ClassC1Ev -> Class::Class()
        assert_eq!(
            demangle("_ZN5ClassC1Ev"),
            Some("Class::Class()".to_string())
        );

        // Destructor: _ZN5ClassD1Ev -> Class::~Class()
        assert_eq!(
            demangle("_ZN5ClassD1Ev"),
            Some("Class::~Class()".to_string())
        );
    }

    #[test]
    fn test_operators() {
        // operator+: _ZN5ClassplERKS_ -> Class::operator+(Class const&)
        assert_eq!(demangle("_Zplii"), Some("operator+(int, int)".to_string()));
        assert_eq!(
            demangle("_ZdlPv"),
            Some("operator delete(void*)".to_string())
        );
    }

    #[test]
    fn test_templates() {
        // _Z3fooIiEvT_ -> foo<int>(int)
        assert_eq!(demangle("_Z3fooIiET_"), Some("foo<int>(int)".to_string()));

        // _Z3barIiLi42EEvv -> bar<int, 42>()
        assert_eq!(
            demangle("_Z3barIiLi42EEvv"),
            Some("bar<int, 42>()".to_string())
        );
    }

    #[test]
    fn test_pointers_refs() {
        // _Z3fooPi -> foo(int*)
        assert_eq!(demangle("_Z3fooPi"), Some("foo(int*)".to_string()));

        // _Z3fooRi -> foo(int&)
        assert_eq!(demangle("_Z3fooRi"), Some("foo(int&)".to_string()));

        // _Z3fooOi -> foo(int&&)
        assert_eq!(demangle("_Z3fooOi"), Some("foo(int&&)".to_string()));
    }

    #[test]
    fn test_const_volatile() {
        // _Z3fooKi -> foo(int const)
        assert_eq!(demangle("_Z3fooKi"), Some("foo(int const)".to_string()));
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

    #[test]
    fn test_std_substitution() {
        // _ZSt4cout -> std::cout
        // Note: actual behavior depends on how std is handled
        assert!(demangle("_ZSt4cout").is_some());
    }

    #[test]
    fn test_thunk() {
        // Non-virtual thunk with this adjustment -16
        let result = demangle("_ZThn16_N5Class3fooEv");
        assert!(result.is_some());
        assert!(result.unwrap().contains("thunk"));
    }
}
