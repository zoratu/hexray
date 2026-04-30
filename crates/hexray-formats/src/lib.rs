//! # hexray-formats
//!
//! Binary format parsers for hexray. This crate provides parsers for:
//! - ELF (Executable and Linkable Format) - Linux/Unix binaries
//! - Mach-O - macOS/iOS binaries
//! - PE (Portable Executable) - Windows binaries
//! - DWARF - Debug information format
//!
//! These parsers are built from scratch for educational purposes.

#![forbid(unsafe_code)]
// Adversarial-input hardening — DOCUMENTED, NOT YET ENFORCED.
//
// Per https://corrode.dev/blog/bugs-rust-wont-catch/, panic /
// index-out-of-bounds / overflow on attacker-controlled input is a
// DoS surface even with Rust's memory safety. This crate parses
// untrusted binaries, so every `.unwrap()`, `[idx]`, and `+`/`*`
// without bounds checks is a fuzz-discoverable crash bug.
//
// Hundreds of pre-existing call sites violate this — flipping any
// of the lints below to `warn` or `deny` floods the build. New
// code on parsing paths should prefer `.get()` / `checked_*` /
// `try_into()` / `try_from()`. PR review is the enforcement
// mechanism until the bulk refactor lands. See
// `scripts/run-fuzz-corpus` for the runtime check that catches
// any regression that does slip through.
// `unwrap_used` and `expect_used` are now ENFORCED — no remaining
// call sites in this crate. New code must propagate errors.
#![deny(clippy::unwrap_used, clippy::expect_used)]
// Test code is the conventional place for `unwrap()` / `expect()` —
// the lints would fire at every assertion-style helper otherwise.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
// `indexing_slicing`, `arithmetic_side_effects`, `panic` still
// allowed: thousands of pre-existing call sites in instruction
// decoders / format-header parsers do bit math and direct slice
// indexing where bounds are checked once at the top of the parse.
// Refactoring all of them is its own multi-day project; the
// runtime fuzz gate (`scripts/run-fuzz-corpus`) catches regressions
// in the interim, and reviewers should still steer new parsing
// paths toward `.get()` / `checked_*`.
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

pub mod cuda;
pub mod dwarf;
pub mod elf;
pub mod error;
pub mod macho;
pub mod pe;
pub mod traits;

pub use cuda::{
    FatbinEntry, FatbinEntryKind, FatbinError, FatbinWrapper, HipBundleEntry, HipBundleEntryKind,
    HipBundleError, HipBundleWrapper,
};
pub use elf::{
    AmdKernel, AmdKernelResourceUsage, AmdMetadata, AmdMetadataArg, AmdMetadataKernel,
    CodeObjectDiagnostic, CodeObjectDiagnosticKind, CodeObjectError, CodeObjectView,
    CubinDiagnostic, CubinDiagnosticKind, CubinError, CubinView, Elf, ElfType, Kernel,
    KernelConfidence, KernelDescriptor, KernelModuleInfo, KernelResourceUsage, MemoryRegion,
    MemorySpace, NvInfoAttribute, NvInfoBlob, NvInfoEntryRef, NvInfoFormat, ParamCbank, ParamInfo,
    PtxFunction, PtxFunctionKind, PtxIndex, PtxModuleHeader, Relocation, RelocationType,
    ScaleKinfo, ScaleKinfoArg, ScaleKinfoError, SchemaError, KERNEL_DESCRIPTOR_SIZE,
};
pub use error::ParseError;
pub use macho::MachO;
pub use pe::Pe;
pub use traits::{BinaryFormat, Section};

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryType {
    Elf,
    MachO,
    Pe,
    Unknown,
}

/// Convert a name from raw binary bytes (symbol name, section name,
/// load-command field) to a `String` suitable for display.
///
/// Symbol and section names in ELF, Mach-O, and PE are byte sequences
/// — the format spec doesn't require UTF-8. The natural Rust convention
/// `String::from_utf8_lossy` collapses every invalid byte to
/// `\u{FFFD}`, which destroys information: an attacker-crafted symbol
/// `\xff\xfe` and a different one `\xff\xfd` both render as the same
/// `��` and can't be distinguished in output, logs, or comparisons.
///
/// This helper preserves the bytes:
/// - Valid UTF-8 input passes through unchanged.
/// - Invalid input is rendered with `std::ascii::escape_default`, so
///   `\xff` shows as `\xff` and stays distinguishable / round-trippable.
///
/// Use this anywhere a binary-format byte buffer becomes a name
/// surfaced to the analyzer or printed to the user.
pub fn name_from_bytes(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => bytes
            .iter()
            .flat_map(|&b| std::ascii::escape_default(b))
            .map(char::from)
            .collect(),
    }
}

/// Detect the binary format from magic bytes.
pub fn detect_format(data: &[u8]) -> BinaryType {
    if data.len() < 4 {
        return BinaryType::Unknown;
    }

    // Check ELF magic
    if data[0..4] == [0x7f, b'E', b'L', b'F'] {
        return BinaryType::Elf;
    }

    // Check PE/DOS magic ("MZ")
    if data[0..2] == [0x4D, 0x5A] {
        // Verify it's actually a PE by checking for PE signature
        if data.len() >= 64 {
            let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
            if pe_offset + 4 <= data.len() {
                let pe_sig = u32::from_le_bytes([
                    data[pe_offset],
                    data[pe_offset + 1],
                    data[pe_offset + 2],
                    data[pe_offset + 3],
                ]);
                if pe_sig == 0x00004550 {
                    // "PE\0\0"
                    return BinaryType::Pe;
                }
            }
        }
    }

    // Check Mach-O magic (both endianness)
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
    match magic {
        0xFEEDFACE | 0xCEFAEDFE |  // 32-bit
        0xFEEDFACF | 0xCFFAEDFE |  // 64-bit
        0xCAFEBABE | 0xBEBAFECA    // Fat binary
        => return BinaryType::MachO,
        _ => {}
    }

    BinaryType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_from_bytes_passes_ascii_through_unchanged() {
        assert_eq!(name_from_bytes(b"qsort"), "qsort");
        assert_eq!(name_from_bytes(b"__TEXT"), "__TEXT");
        assert_eq!(name_from_bytes(b".rela.plt"), ".rela.plt");
    }

    #[test]
    fn name_from_bytes_passes_valid_multibyte_utf8_through() {
        // `é` is two bytes in UTF-8 (0xc3 0xa9), `★` is three (0xe2 0x98
        // 0x85). Both forms are valid; the helper must not escape them.
        assert_eq!(name_from_bytes("héllo".as_bytes()), "héllo");
        assert_eq!(name_from_bytes("★star".as_bytes()), "★star");
    }

    #[test]
    fn name_from_bytes_returns_empty_string_for_empty_input() {
        assert_eq!(name_from_bytes(b""), "");
    }

    #[test]
    fn name_from_bytes_preserves_embedded_nulls_in_valid_utf8() {
        // `\0` is valid UTF-8 (U+0000). It survives the to_string()
        // path; the resulting String contains the literal NUL byte.
        let out = name_from_bytes(b"a\0b");
        assert_eq!(out.len(), 3);
        assert_eq!(out.as_bytes(), b"a\0b");
    }

    #[test]
    fn name_from_bytes_escapes_invalid_utf8_via_ascii_escape() {
        // 0xff alone is not a valid UTF-8 byte → entire input goes
        // through escape_default. `0xff` becomes the literal `\xff`.
        assert_eq!(name_from_bytes(&[0xff]), r"\xff");
        assert_eq!(name_from_bytes(&[0xff, 0xfe]), r"\xff\xfe");
    }

    #[test]
    fn name_from_bytes_distinguishes_different_invalid_byte_sequences() {
        // The motivating case the helper was added for. `from_utf8_lossy`
        // collapses both inputs to `��`; we keep them distinguishable.
        let a = name_from_bytes(&[0xff, 0xfe]);
        let b = name_from_bytes(&[0xff, 0xfd]);
        assert_ne!(a, b);
        assert_eq!(a, r"\xff\xfe");
        assert_eq!(b, r"\xff\xfd");
    }

    #[test]
    fn name_from_bytes_escapes_mixed_valid_and_invalid_bytes() {
        // When any byte makes the input invalid, the entire run goes
        // through escape_default — including the printable ASCII bytes
        // that are also in the slice. ASCII pass-through under
        // escape_default keeps them readable; the high byte gets the
        // `\xff` form.
        assert_eq!(name_from_bytes(b"hi\xff"), r"hi\xff");
    }

    #[test]
    fn name_from_bytes_escapes_low_control_bytes_only_when_input_invalid() {
        // Mixed: control byte + invalid byte. escape_default emits
        // the canonical `\n`, `\t`, etc. escapes for control chars
        // even though they're valid UTF-8 — that only matters here
        // because the trailing 0xff forces the whole input through
        // the escape path.
        assert_eq!(name_from_bytes(b"a\nb\xff"), r"a\nb\xff");
        // Same control byte in valid input passes through as a real
        // newline character (no escaping).
        let out = name_from_bytes(b"a\nb");
        assert_eq!(out.as_bytes(), b"a\nb");
    }
}
