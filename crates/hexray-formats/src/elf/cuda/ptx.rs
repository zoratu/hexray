//! PTX sidecar parser.
//!
//! PTX is NVIDIA's virtual ISA — human-readable text stored alongside
//! SASS in a CUBIN (`.nv_debug_ptx_txt`) or as a standalone blob inside
//! a host fatbin. For M8 we do *just* the sidecar work: parse the
//! module header (`.version` / `.target` / `.address_size`) and index
//! every `.entry` / `.func` directive so callers can cross-link PTX
//! symbols with SASS kernels by name.
//!
//! We **do not** build a PTX AST. Codex's M8 design explicitly classes
//! full PTX parsing as v3 work. What M8 ships is enough to:
//!
//! 1. confirm a cubin / fatbin actually contains PTX
//! 2. show the PTX `.version` + `.target` per CUBIN in `hexray info`
//! 3. map a SASS kernel name to its matching PTX function body span
//!
//! Everything beyond that — instruction decoding, register allocation,
//! control-flow — stays on the TODO for the cheap-sidecar plan.

use core::ops::Range;

/// Parsed module-level PTX directives.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PtxModuleHeader {
    /// `.version M.N` → `(major, minor)`.
    pub version: Option<(u8, u8)>,
    /// `.target sm_XY` target directive (raw string so `sm_90a` stays
    /// intact without needing to cross-import the core arch enum here).
    pub target: Option<String>,
    /// `.address_size 32` or `64`.
    pub address_size: Option<u8>,
}

/// One function-entry recovered from a PTX blob. Spans are byte offsets
/// into the original blob — callers can slice back out to show the body
/// verbatim in a UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtxFunction {
    /// `.entry` for kernels, `.func` for `__device__` helpers.
    pub kind: PtxFunctionKind,
    /// The function's (possibly mangled) symbol name. Matches the SASS
    /// side's `Kernel::name` when the two describe the same function.
    pub name: String,
    /// Byte offset of the opening `{` into the PTX blob.
    pub body_start: usize,
    /// Byte offset of the matching `}` (exclusive), or `body_start`
    /// when the closing brace couldn't be matched.
    pub body_end: usize,
    /// Byte range covering the directive header (signature, up to but
    /// not including the body brace). Useful for rendering the
    /// parameter list.
    pub header: Range<usize>,
    /// `true` when the entry carried `.visible` before the directive.
    pub visible: bool,
}

/// `.entry` vs `.func`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PtxFunctionKind {
    /// `.entry` — `__global__` kernel, callable from the host.
    Entry,
    /// `.func` — `__device__` helper callable only from the GPU.
    Func,
}

/// A fully-indexed PTX blob. Owns its normalised text buffer so both
/// `.nv_debug_ptx_txt` (NUL-delimited) and plain-text PTX files are
/// handled by the same API.
#[derive(Debug, Clone, Default)]
pub struct PtxIndex<'a> {
    /// Holds the PTX text, either borrowed from the caller's buffer
    /// (standalone `.ptx` files) or owned (NUL-normalised CUBIN
    /// sections). Either way, byte offsets in `functions` index into
    /// this string.
    pub raw: std::borrow::Cow<'a, str>,
    pub header: PtxModuleHeader,
    pub functions: Vec<PtxFunction>,
}

impl<'a> PtxIndex<'a> {
    /// Parse a PTX source blob. Malformed blobs yield an index with the
    /// fields we could recover; nothing in this function panics.
    pub fn parse(raw: &'a str) -> Self {
        let header = parse_header(raw);
        let functions = parse_functions(raw);
        Self {
            raw: std::borrow::Cow::Borrowed(raw),
            header,
            functions,
        }
    }

    /// Parse a PTX blob from NUL-delimited bytes, as stored in a CUBIN's
    /// `.nv_debug_ptx_txt` section. Leading NUL padding is trimmed and
    /// embedded NULs are replaced with spaces so the tokeniser sees a
    /// plausible whitespace-separated stream.
    pub fn from_nul_delimited_bytes(bytes: &[u8]) -> Option<Self> {
        // Strip leading NULs (`.nv_debug_ptx_txt` starts with an
        // alignment pad) and fold internal NULs into spaces.
        let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
        let trailing = bytes
            .iter()
            .rposition(|b| *b != 0)
            .map(|x| x + 1)
            .unwrap_or(bytes.len());
        if start >= trailing {
            return None;
        }
        let mut owned = String::with_capacity(trailing - start);
        for &b in &bytes[start..trailing] {
            owned.push(if b == 0 { '\n' } else { b as char });
        }
        let header = parse_header(&owned);
        let functions = parse_functions(&owned);
        Some(Self {
            raw: std::borrow::Cow::Owned(owned),
            header,
            functions,
        })
    }

    /// Look up a function by exact name. O(n).
    pub fn function_by_name(&self, name: &str) -> Option<&PtxFunction> {
        self.functions.iter().find(|f| f.name == name)
    }

    /// Byte slice of one function's body (between `{` and `}`).
    pub fn function_body(&self, f: &PtxFunction) -> &str {
        &self.raw[f.body_start..f.body_end.min(self.raw.len())]
    }

    /// Byte slice of the directive header (signature).
    pub fn function_header(&self, f: &PtxFunction) -> &str {
        &self.raw[f.header.clone()]
    }
}

// ---- header ----------------------------------------------------------------

fn parse_header(raw: &str) -> PtxModuleHeader {
    let mut h = PtxModuleHeader::default();
    let mut iter = TokenIter::new(raw);
    while let Some(tok) = iter.next() {
        match tok {
            Token::Directive(d) => {
                match d {
                    ".version" => {
                        if let Some(Token::Word(word)) = iter.next() {
                            h.version = parse_version(word);
                        }
                    }
                    ".target" => {
                        if let Some(Token::Word(w)) = iter.next() {
                            h.target = Some(w.to_string());
                        }
                    }
                    ".address_size" => {
                        if let Some(Token::Word(w)) = iter.next() {
                            h.address_size = w.parse::<u8>().ok();
                        }
                    }
                    ".entry" | ".func" | ".weak" | ".extern" | ".visible" => {
                        // First function directive — stop collecting
                        // module-level state.
                        break;
                    }
                    _ => {}
                }
            }
            Token::Brace => break,
            _ => {}
        }
    }
    h
}

fn parse_version(s: &str) -> Option<(u8, u8)> {
    let mut parts = s.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

// ---- functions -------------------------------------------------------------

fn parse_functions(raw: &str) -> Vec<PtxFunction> {
    let mut out = Vec::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    let mut visible = false;

    while i < bytes.len() {
        // Skip whitespace + line comments.
        if let Some(adv) = skip_trivia(bytes, i) {
            i = adv;
            continue;
        }

        if let Some(word) = word_at(bytes, i) {
            let (w, next) = word;
            match w {
                ".visible" | ".weak" | ".extern" => {
                    visible = visible || w == ".visible";
                    i = next;
                    continue;
                }
                ".entry" | ".func" => {
                    let kind = if w == ".entry" {
                        PtxFunctionKind::Entry
                    } else {
                        PtxFunctionKind::Func
                    };
                    let directive_start = i;
                    // The next identifier is the function name. Skip
                    // any `(...)` return-type group on `.func`.
                    let mut cursor = next;
                    cursor = skip_ws(bytes, cursor);
                    if bytes.get(cursor).copied() == Some(b'(') {
                        cursor = match_paren(bytes, cursor).unwrap_or(bytes.len());
                        cursor = skip_ws(bytes, cursor);
                    }
                    let Some((name, after_name)) = identifier_at(bytes, cursor) else {
                        // Can't locate a name — skip past this token.
                        i = next;
                        visible = false;
                        continue;
                    };

                    // Find the opening brace.
                    let mut k = after_name;
                    while k < bytes.len() && bytes[k] != b'{' && bytes[k] != b';' {
                        k += 1;
                    }
                    let header_end = k;
                    let (body_start, body_end) = if bytes.get(k).copied() == Some(b'{') {
                        let start = k + 1;
                        let end = match_brace(bytes, k).unwrap_or(start);
                        (start, end)
                    } else {
                        // Forward declarations end with `;` — record
                        // zero-length bodies but still add the entry
                        // so name lookups find it.
                        (k, k)
                    };

                    out.push(PtxFunction {
                        kind,
                        name: name.to_string(),
                        body_start,
                        body_end,
                        header: directive_start..header_end,
                        visible,
                    });

                    i = body_end.max(header_end);
                    visible = false;
                    continue;
                }
                _ => {
                    // Non-function directive (e.g. `.reg`, `.global`).
                    // Skip to the end of its statement (next `;`).
                    i = bytes[i..]
                        .iter()
                        .position(|b| *b == b';' || *b == b'\n')
                        .map(|p| i + p + 1)
                        .unwrap_or(bytes.len());
                    visible = false;
                    continue;
                }
            }
        }
        // Step past any byte we couldn't recognise.
        i += 1;
    }

    out
}

fn skip_trivia(bytes: &[u8], mut i: usize) -> Option<usize> {
    let start = i;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else {
            break;
        }
    }
    if i > start {
        Some(i)
    } else {
        None
    }
}

fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_whitespace() {
        i += 1;
    }
    i
}

/// Read a whitespace-delimited "word" (directive or identifier) at `i`.
/// Returns the word and the byte offset just past it.
fn word_at(bytes: &[u8], i: usize) -> Option<(&str, usize)> {
    let start = i;
    if start >= bytes.len() {
        return None;
    }
    let b0 = bytes[start];
    if !(b0 == b'.' || b0 == b'_' || b0 == b'%' || b0.is_ascii_alphanumeric()) {
        return None;
    }
    let mut j = start;
    while j < bytes.len() {
        let b = bytes[j];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'%' {
            j += 1;
        } else {
            break;
        }
    }
    if j == start {
        return None;
    }
    std::str::from_utf8(&bytes[start..j]).ok().map(|s| (s, j))
}

/// Parse a plain C-like identifier (no leading `.` or `%`).
fn identifier_at(bytes: &[u8], i: usize) -> Option<(&str, usize)> {
    let (w, next) = word_at(bytes, i)?;
    if w.starts_with('.') || w.starts_with('%') {
        return None;
    }
    Some((w, next))
}

fn match_brace(bytes: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(open).copied(), Some(b'{'));
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn match_paren(bytes: &[u8], open: usize) -> Option<usize> {
    debug_assert_eq!(bytes.get(open).copied(), Some(b'('));
    let mut depth = 0usize;
    let mut i = open;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ---- tiny tokeniser, used only by parse_header ----------------------------

#[derive(Debug, Clone, Copy)]
enum Token<'a> {
    Directive(&'a str),
    Word(&'a str),
    /// `{` or `}` — content not needed since callers just want to know
    /// when the module header is closing.
    Brace,
}

struct TokenIter<'a> {
    raw: &'a [u8],
    pos: usize,
}

impl<'a> TokenIter<'a> {
    fn new(raw: &'a str) -> Self {
        Self {
            raw: raw.as_bytes(),
            pos: 0,
        }
    }
}

impl<'a> Iterator for TokenIter<'a> {
    type Item = Token<'a>;
    fn next(&mut self) -> Option<Token<'a>> {
        while self.pos < self.raw.len() {
            if let Some(adv) = skip_trivia(self.raw, self.pos) {
                self.pos = adv;
                continue;
            }
            let b = self.raw[self.pos];
            if b == b'{' || b == b'}' {
                self.pos += 1;
                let _ = b;
                return Some(Token::Brace);
            }
            if let Some((w, next)) = word_at(self.raw, self.pos) {
                self.pos = next;
                return Some(if w.starts_with('.') {
                    Token::Directive(w)
                } else {
                    Token::Word(w)
                });
            }
            self.pos += 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = r#"
        .version 9.2
        .target sm_80
        .address_size 64

        .visible .entry vector_add(
            .param .u64 vector_add_param_0,
            .param .u32 vector_add_param_1
        ) {
            .reg .b32 %r<3>;
            ld.param.u64 %r1, [vector_add_param_0];
            ret;
        }

        .func (.reg .b32 %ret) device_helper(.reg .b32 %x) {
            add.s32 %ret, %x, 1;
            ret;
        }
    "#;

    #[test]
    fn parses_module_header() {
        let idx = PtxIndex::parse(TINY);
        assert_eq!(idx.header.version, Some((9, 2)));
        assert_eq!(idx.header.target.as_deref(), Some("sm_80"));
        assert_eq!(idx.header.address_size, Some(64));
    }

    #[test]
    fn parses_entry_and_func() {
        let idx = PtxIndex::parse(TINY);
        assert_eq!(idx.functions.len(), 2);

        let entry = idx.function_by_name("vector_add").unwrap();
        assert_eq!(entry.kind, PtxFunctionKind::Entry);
        assert!(entry.visible);
        let body = idx.function_body(entry);
        assert!(body.contains("ld.param.u64"));
        assert!(body.contains("ret;"));

        let helper = idx.function_by_name("device_helper").unwrap();
        assert_eq!(helper.kind, PtxFunctionKind::Func);
        assert!(!helper.visible);
        assert!(idx.function_body(helper).contains("add.s32"));
    }

    #[test]
    fn handles_malformed_gracefully() {
        // Missing closing brace — body_end collapses to body_start.
        let src = ".visible .entry broken( .param .u32 x ) {";
        let idx = PtxIndex::parse(src);
        assert_eq!(idx.functions.len(), 1);
        let f = &idx.functions[0];
        assert_eq!(f.name, "broken");
        assert_eq!(f.body_start, f.body_end);
    }

    #[test]
    fn handles_forward_declaration_with_semicolon() {
        let src = r#"
            .extern .func (.param .b32 ret) external_helper(.param .b32 x);
        "#;
        let idx = PtxIndex::parse(src);
        assert_eq!(idx.functions.len(), 1);
        assert_eq!(idx.functions[0].name, "external_helper");
        assert_eq!(
            idx.functions[0].body_start, idx.functions[0].body_end,
            "forward decl should have empty body span"
        );
    }

    #[test]
    fn empty_input_is_fine() {
        let idx = PtxIndex::parse("");
        assert_eq!(idx.header, PtxModuleHeader::default());
        assert!(idx.functions.is_empty());
    }
}
