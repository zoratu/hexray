//! ELF program header (segment) parsing.

use super::header::ElfClass;
use crate::ParseError;
use hexray_core::Endianness;

// Segment types
pub const PT_NULL: u32 = 0;
pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_NOTE: u32 = 4;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

// Segment flags
pub const PF_X: u32 = 0x1; // Execute
pub const PF_W: u32 = 0x2; // Write
pub const PF_R: u32 = 0x4; // Read

/// A parsed program header (segment).
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    /// Segment type.
    pub p_type: u32,
    /// Segment flags.
    pub p_flags: u32,
    /// Offset in file.
    pub p_offset: u64,
    /// Virtual address in memory.
    pub p_vaddr: u64,
    /// Physical address (usually same as vaddr).
    pub p_paddr: u64,
    /// Size in file.
    pub p_filesz: u64,
    /// Size in memory.
    pub p_memsz: u64,
    /// Alignment.
    pub p_align: u64,
}

impl ProgramHeader {
    /// Parse a program header from bytes.
    pub fn parse(data: &[u8], class: ElfClass, endianness: Endianness) -> Result<Self, ParseError> {
        match class {
            ElfClass::Elf32 => Self::parse_elf32(data, endianness),
            ElfClass::Elf64 => Self::parse_elf64(data, endianness),
        }
    }

    fn parse_elf32(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 32;
        if data.len() < SIZE {
            return Err(ParseError::too_short(SIZE, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            p_type: read_u32(0),
            p_offset: read_u32(4) as u64,
            p_vaddr: read_u32(8) as u64,
            p_paddr: read_u32(12) as u64,
            p_filesz: read_u32(16) as u64,
            p_memsz: read_u32(20) as u64,
            p_flags: read_u32(24),
            p_align: read_u32(28) as u64,
        })
    }

    fn parse_elf64(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 56;
        if data.len() < SIZE {
            return Err(ParseError::too_short(SIZE, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        Ok(Self {
            p_type: read_u32(0),
            p_flags: read_u32(4),
            p_offset: read_u64(8),
            p_vaddr: read_u64(16),
            p_paddr: read_u64(24),
            p_filesz: read_u64(32),
            p_memsz: read_u64(40),
            p_align: read_u64(48),
        })
    }

    /// Returns the segment type as a string.
    pub fn type_name(&self) -> &'static str {
        match self.p_type {
            PT_NULL => "NULL",
            PT_LOAD => "LOAD",
            PT_DYNAMIC => "DYNAMIC",
            PT_INTERP => "INTERP",
            PT_NOTE => "NOTE",
            PT_PHDR => "PHDR",
            PT_TLS => "TLS",
            PT_GNU_EH_FRAME => "GNU_EH_FRAME",
            PT_GNU_STACK => "GNU_STACK",
            PT_GNU_RELRO => "GNU_RELRO",
            _ => "UNKNOWN",
        }
    }

    /// Returns true if this segment is loadable.
    pub fn is_load(&self) -> bool {
        self.p_type == PT_LOAD
    }

    /// Returns true if this segment is executable.
    pub fn is_executable(&self) -> bool {
        self.p_flags & PF_X != 0
    }

    /// Returns true if this segment is writable.
    pub fn is_writable(&self) -> bool {
        self.p_flags & PF_W != 0
    }

    /// Returns true if this segment is readable.
    pub fn is_readable(&self) -> bool {
        self.p_flags & PF_R != 0
    }

    /// Returns the flags as a string (e.g., "RWX").
    pub fn flags_string(&self) -> String {
        let mut s = String::with_capacity(3);
        if self.is_readable() {
            s.push('R');
        }
        if self.is_writable() {
            s.push('W');
        }
        if self.is_executable() {
            s.push('X');
        }
        s
    }
}
