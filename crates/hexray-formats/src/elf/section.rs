//! ELF section header parsing.

use super::header::ElfClass;
use crate::{ParseError, Section};
use hexray_core::Endianness;

// Section types
pub const SHT_NULL: u32 = 0;
pub const SHT_PROGBITS: u32 = 1;
pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_RELA: u32 = 4;
pub const SHT_HASH: u32 = 5;
pub const SHT_DYNAMIC: u32 = 6;
pub const SHT_NOTE: u32 = 7;
pub const SHT_NOBITS: u32 = 8;
pub const SHT_REL: u32 = 9;
pub const SHT_DYNSYM: u32 = 11;

// Section flags
pub const SHF_WRITE: u64 = 0x1;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;

/// A parsed section header.
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Section name (index into string table).
    pub sh_name: u32,
    /// Section type.
    pub sh_type: u32,
    /// Section flags.
    pub sh_flags: u64,
    /// Virtual address in memory.
    pub sh_addr: u64,
    /// Offset in file.
    pub sh_offset: u64,
    /// Size in bytes.
    pub sh_size: u64,
    /// Link to another section.
    pub sh_link: u32,
    /// Additional section info.
    pub sh_info: u32,
    /// Address alignment.
    pub sh_addralign: u64,
    /// Entry size (for tables).
    pub sh_entsize: u64,
    /// Cached section name (set after parsing).
    name_cache: Option<String>,
    /// Cached section data (set after parsing).
    data_cache: Option<Vec<u8>>,
}

impl SectionHeader {
    /// Parse a section header from bytes.
    pub fn parse(data: &[u8], class: ElfClass, endianness: Endianness) -> Result<Self, ParseError> {
        match class {
            ElfClass::Elf32 => Self::parse_elf32(data, endianness),
            ElfClass::Elf64 => Self::parse_elf64(data, endianness),
        }
    }

    fn parse_elf32(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 40;
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
            sh_name: read_u32(0),
            sh_type: read_u32(4),
            sh_flags: read_u32(8) as u64,
            sh_addr: read_u32(12) as u64,
            sh_offset: read_u32(16) as u64,
            sh_size: read_u32(20) as u64,
            sh_link: read_u32(24),
            sh_info: read_u32(28),
            sh_addralign: read_u32(32) as u64,
            sh_entsize: read_u32(36) as u64,
            name_cache: None,
            data_cache: None,
        })
    }

    fn parse_elf64(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 64;
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
            sh_name: read_u32(0),
            sh_type: read_u32(4),
            sh_flags: read_u64(8),
            sh_addr: read_u64(16),
            sh_offset: read_u64(24),
            sh_size: read_u64(32),
            sh_link: read_u32(40),
            sh_info: read_u32(44),
            sh_addralign: read_u64(48),
            sh_entsize: read_u64(56),
            name_cache: None,
            data_cache: None,
        })
    }

    /// Returns the section type as a string.
    pub fn type_name(&self) -> &'static str {
        match self.sh_type {
            SHT_NULL => "NULL",
            SHT_PROGBITS => "PROGBITS",
            SHT_SYMTAB => "SYMTAB",
            SHT_STRTAB => "STRTAB",
            SHT_RELA => "RELA",
            SHT_HASH => "HASH",
            SHT_DYNAMIC => "DYNAMIC",
            SHT_NOTE => "NOTE",
            SHT_NOBITS => "NOBITS",
            SHT_REL => "REL",
            SHT_DYNSYM => "DYNSYM",
            _ => "UNKNOWN",
        }
    }

    /// Sets the cached section name.
    pub fn set_name(&mut self, name: String) {
        self.name_cache = Some(name);
    }

    /// Sets the cached section data.
    pub fn set_data(&mut self, data: Vec<u8>) {
        self.data_cache = Some(data);
    }
}

impl Section for SectionHeader {
    fn name(&self) -> &str {
        self.name_cache.as_deref().unwrap_or("")
    }

    fn virtual_address(&self) -> u64 {
        self.sh_addr
    }

    fn size(&self) -> u64 {
        self.sh_size
    }

    fn data(&self) -> &[u8] {
        self.data_cache.as_deref().unwrap_or(&[])
    }

    fn is_executable(&self) -> bool {
        self.sh_flags & SHF_EXECINSTR != 0
    }

    fn is_writable(&self) -> bool {
        self.sh_flags & SHF_WRITE != 0
    }

    fn is_allocated(&self) -> bool {
        self.sh_flags & SHF_ALLOC != 0
    }
}
