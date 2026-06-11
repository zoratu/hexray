//! Number / string / character formatting helpers used throughout the
//! pseudocode emitter.
//!
//! Each helper is a pure function on primitive integer / `&str` inputs
//! and is consumed exclusively by the `PseudoCodeEmitter` impl in
//! [`super`].

/// Formats an integer for C output.
/// Uses decimal for "normal" values and hex for large addresses.
pub(super) fn recognize_magic_constant(value: i128) -> Option<&'static str> {
    let n = value as u64;
    match n {
        0xDEADBEEFDEADBEEF => Some("DEADBEEF_DEADBEEF"),
        0xdead000000000000 => Some("POISON_POINTER_DELTA"),
        0xDEADBEEF => Some("DEADBEEF"),
        0xFEEDFACE => Some("FEEDFACE"),
        0xCAFEBABE => Some("CAFEBABE"),
        0xDEADC0DE => Some("DEADC0DE"),
        0xBADC0DE => Some("BADC0DE"),
        0xCCCCCCCC => Some("CCCCCCCC"),
        0xCDCDCDCD => Some("CDCDCDCD"),
        0x00100100 => Some("LIST_POISON1"),
        0x00200200 => Some("LIST_POISON2"),
        _ => {
            if value < 0 {
                let abs_val = (-value) as u64;
                match abs_val {
                    0xDEADBEEF => Some("DEADBEEF"),
                    0xFEEDFACE => Some("FEEDFACE"),
                    0xCAFEBABE => Some("CAFEBABE"),
                    0xDEADC0DE => Some("DEADC0DE"),
                    0xBADC0DE => Some("BADC0DE"),
                    0xCCCCCCCC => Some("CCCCCCCC"),
                    0xCDCDCDCD => Some("CDCDCDCD"),
                    _ => None,
                }
            } else {
                None
            }
        }
    }
}

pub(super) fn format_integer(n: i128) -> String {
    if let Some(constant_name) = recognize_magic_constant(n) {
        return constant_name.to_string();
    }

    if n < 0 {
        // Negative numbers in decimal
        format!("{}", n)
    } else if n <= 255 {
        // Small values in decimal
        format!("{}", n)
    } else if n <= 0xFFFF && !looks_like_address(n) {
        // Medium values in decimal if they don't look like addresses
        format!("{}", n)
    } else {
        // Large values (likely addresses) in hex
        format!("{:#x}", n)
    }
}

/// Formats an `f64` value as a C double literal — e.g. `3.14`,
/// `-1.5`, `0.0`. Uses Rust's default `{}` formatting, which round-
/// trips IEEE-754 doubles to the shortest decimal that parses back to
/// the same bit pattern. Always ensures a `.` appears so the literal
/// parses as a `double` in C rather than as an integer.
pub(super) fn format_float_literal_f64(value: f64) -> String {
    let mut s = format!("{value}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') {
        s.push_str(".0");
    }
    s
}

/// Formats an `f32` value as a C float literal with an `f` suffix —
/// e.g. `3.14f`, `-1.5f`, `0.0f`. The `f` suffix disambiguates from
/// `double` so a recovered `float` constant doesn't get widened on
/// rebuild.
pub(super) fn format_float_literal_f32(value: f32) -> String {
    let mut s = format!("{value}");
    if !s.contains('.') && !s.contains('e') && !s.contains('E') {
        s.push_str(".0");
    }
    s.push('f');
    s
}

/// Returns true when `name` looks like a compiler-generated local
/// pool label rather than a user-defined global. These show up as
/// `.LCPI0_0`/`.LCPI1_0` (clang/LLVM), `.LC0`/`.LC1` (GCC), and
/// similar `.L`-prefixed local labels. Such names are not meaningful
/// to a human reader; when one of them is the only "symbol" at a
/// rip-relative float load, materializing the literal `3.14` is more
/// useful than the opaque label.
pub(super) fn is_compiler_local_pool_label(name: &str) -> bool {
    // ELF locals universally start with `.L`. Mach-O uses `L` (no dot)
    // but Mach-O constant-pool emitters typically name slots like
    // `lCPI0_0` — accept that too. We also accept these labels
    // appearing as an INTERIOR token: when a scalar load targets an
    // offset inside a larger pool symbol, `format_global_value` can
    // return something like `*(uint64_t*)(.LCPI0_0 + 8)`, where the
    // leading character is `*` but the meaningful identifier is the
    // embedded `.LCPI0_0`. Codex review on PR #26 pass 9.
    if name.starts_with(".L") || name.starts_with("LCPI") || name.starts_with("lCPI") {
        return true;
    }
    name.contains(".LCPI")
        || name.contains(".LC")
        || name.contains("(.L")
        || name.contains("(LCPI")
        || name.contains("(lCPI")
}

/// Heuristic: do these `f64` bytes look like a real compiler-emitted
/// float constant, as opposed to a misread integer / pointer / zeroed
/// rodata slot?
///
/// The screen is intentionally narrow: compiler-emitted `.rodata.cst8`
/// entries are almost always normalized, finite, non-zero magnitudes
/// in human-comprehensible ranges. Denormals, NaNs, infs, and tiny
/// values produced by reinterpreting `uint64_t x = 42` as a double
/// (which becomes ~2e-322) are all excluded.
pub(super) fn looks_like_real_float_constant_f64(value: f64) -> bool {
    if !value.is_finite() || value.is_subnormal() {
        return false;
    }
    // Zero is a legitimate `.rodata.cst*` constant — a compiler
    // emits `+0.0` and especially `-0.0` (bit pattern
    // `0x8000_0000_0000_0000`) into the constant pool because the
    // `xor self-zero` idiom can't reproduce negative zero. The
    // float-pool gate already prevents generic-rodata zeros from
    // being materialized, so accepting zero here is safe. Codex
    // review on PR #26 pass 12.
    if value == 0.0 {
        return true;
    }
    let abs = value.abs();
    // 1e-300..1e300 covers everything from sub-picometer physics
    // constants to astronomical magnitudes — any normalized double a
    // compiler would emit in a constant pool fits here. The lower
    // bound also filters out misread pointers like 0x0000_0000_0000_002a,
    // which as f64 ≈ 2.07e-322 (subnormal) is rejected above, but
    // 0x3e00_0000_0000_0000 ≈ 3.18e-145 would otherwise sneak
    // through.
    (1e-300..=1e300).contains(&abs)
}

/// Heuristic: do these `f32` bytes look like a real compiler-emitted
/// float constant? Same idea as the f64 variant; range scaled for the
/// narrower exponent.
pub(super) fn looks_like_real_float_constant_f32(value: f32) -> bool {
    if !value.is_finite() || value.is_subnormal() {
        return false;
    }
    // Zero allowed for the same reason as the f64 variant — `-0.0f`
    // is a real `.rodata.cst4` constant the xor-zero idiom can't
    // reproduce. Codex review on PR #26 pass 12.
    if value == 0.0 {
        return true;
    }
    let abs = value.abs();
    (1e-30..=1e30).contains(&abs)
}

/// Heuristic: does this value look like a memory address?
pub(super) fn looks_like_address(n: i128) -> bool {
    // Common address ranges for x86-64
    let n = n as u64;
    // Stack addresses (high memory)
    if n >= 0x7FFF_0000_0000 {
        return true;
    }
    // Code/data addresses (typically 0x400000+ for ELF, 0x100000000+ for Mach-O)
    if n >= 0x400000 && (n & 0xFFF) == 0 {
        return true; // Page-aligned addresses
    }
    false
}

/// Escapes a string for C output.
pub(super) fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_ascii_control() => {
                result.push_str(&format!("\\x{:02x}", c as u8));
            }
            c => result.push(c),
        }
    }
    result
}

/// Checks if a formatted expression string suggests a byte/character context.
///
/// This looks for patterns like:
/// - Array subscript: `x[0]`, `ptr[i]`
/// - 8-bit dereference: `*(uint8_t*)`
/// - Char pointer dereference: `*str`
pub(super) fn looks_like_char_context(s: &str) -> bool {
    // Array subscript pattern - often used for string/byte access
    // e.g., "str[0]", "buf[i]", "rbp[-0x7][1]"
    if s.ends_with(']') && s.contains('[') {
        return true;
    }
    // Explicit 8-bit dereference
    if s.contains("uint8_t") || s.contains("int8_t") || s.contains("char") {
        return true;
    }
    false
}

/// Checks if a value is likely a character value worth displaying as a char literal.
///
/// This includes:
/// - Printable ASCII characters (32-126)
/// - Common special characters (null, tab, newline, carriage return)
pub(super) fn is_printable_char_value(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    let n = n as u8;
    // Printable ASCII range only (not special characters like 0, 9, 10, 13)
    // Those special characters should only be shown as char literals in byte contexts
    (32..=126).contains(&n)
}

/// Checks if a value is a special character (null, tab, newline, CR).
/// These should only be shown as character literals in explicit byte contexts.
pub(super) fn is_special_char_value(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    matches!(n as u8, 0 | 9 | 10 | 13)
}

/// Checks if a value is very likely to be a character constant.
/// These are values that almost certainly represent characters in comparisons,
/// specifically punctuation/escape characters that would be meaningless as numbers.
///
/// Note: We explicitly EXCLUDE letters (A-Z, a-z) and digits ('0'-'9') from this
/// function because values like 90 ('Z'), 80 ('P'), 70 ('F'), 60 are commonly used
/// as numeric thresholds (grades, percentages, etc.). These should only be shown
/// as char literals when there's explicit byte context (int8_t, char*, derefs, etc.).
///
/// We also exclude 0 (null) because 0 is commonly used as a regular integer
/// (false, count, etc.). Null comparisons like `str[i] == 0` are handled by the
/// byte-context detection instead.
///
/// We intentionally exclude less-common control characters (7=\a, 8=\b, 11=\v, 12=\f)
/// because comparisons like `x > 8` are often numeric bounds checks, not character
/// comparisons. Those are still formatted as escape sequences in byte contexts.
pub(super) fn is_likely_character_constant(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    let c = n as u8;
    // Only punctuation/escape characters that would be meaningless as raw numbers
    matches!(
        c,
        b'\\'  // Backslash - 92
            | b'\''  // Single quote - 39
            | b'"' // Double quote - 34
    )
}

/// Formats an integer as a C character literal.
pub(super) fn format_as_char_literal(n: i128) -> String {
    if !(0..=127).contains(&n) {
        return format!("{}", n);
    }
    let c = n as u8;
    match c {
        0 => "'\\0'".to_string(),
        7 => "'\\a'".to_string(),  // Bell
        8 => "'\\b'".to_string(),  // Backspace
        9 => "'\\t'".to_string(),  // Tab
        10 => "'\\n'".to_string(), // Newline
        11 => "'\\v'".to_string(), // Vertical tab
        12 => "'\\f'".to_string(), // Form feed
        13 => "'\\r'".to_string(), // Carriage return
        b'\\' => "'\\\\'".to_string(),
        b'\'' => "'\\''".to_string(),
        32..=126 => format!("'{}'", c as char),
        _ => format!("{}", n),
    }
}
