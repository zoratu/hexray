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
#![allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::expect_used,
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
