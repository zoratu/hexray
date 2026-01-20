//! # hexray-formats
//!
//! Binary format parsers for hexray. This crate provides parsers for:
//! - ELF (Executable and Linkable Format) - Linux/Unix binaries
//! - Mach-O - macOS/iOS binaries
//! - PE (Portable Executable) - Windows binaries
//! - DWARF - Debug information format
//!
//! These parsers are built from scratch for educational purposes.

pub mod dwarf;
pub mod elf;
pub mod error;
pub mod macho;
pub mod pe;
pub mod traits;

pub use elf::{Elf, ElfType, KernelModuleInfo, Relocation, RelocationType};
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
