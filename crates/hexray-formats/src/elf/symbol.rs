//! ELF symbol table parsing.

use super::header::ElfClass;
use crate::ParseError;
use hexray_core::{Endianness, Symbol, SymbolBinding, SymbolKind};

// Symbol binding (upper 4 bits of st_info)
const STB_LOCAL: u8 = 0;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;

// Symbol type (lower 4 bits of st_info)
const STT_NOTYPE: u8 = 0;
const STT_OBJECT: u8 = 1;
const STT_FUNC: u8 = 2;
const STT_SECTION: u8 = 3;
const STT_FILE: u8 = 4;
const STT_COMMON: u8 = 5;
const STT_TLS: u8 = 6;

// Special section indices
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;
pub const SHN_COMMON: u16 = 0xfff2;

/// A raw symbol table entry.
#[derive(Debug, Clone)]
pub struct SymbolEntry {
    /// Symbol name (index into string table).
    pub st_name: u32,
    /// Symbol info (type and binding).
    pub st_info: u8,
    /// Symbol visibility.
    pub st_other: u8,
    /// Section index.
    pub st_shndx: u16,
    /// Symbol value (address).
    pub st_value: u64,
    /// Symbol size.
    pub st_size: u64,
}

impl SymbolEntry {
    /// Parse a symbol entry from bytes.
    pub fn parse(data: &[u8], class: ElfClass, endianness: Endianness) -> Result<Self, ParseError> {
        match class {
            ElfClass::Elf32 => Self::parse_elf32(data, endianness),
            ElfClass::Elf64 => Self::parse_elf64(data, endianness),
        }
    }

    fn parse_elf32(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 16;
        if data.len() < SIZE {
            return Err(ParseError::too_short(SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

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
            st_name: read_u32(0),
            st_value: read_u32(4) as u64,
            st_size: read_u32(8) as u64,
            st_info: data[12],
            st_other: data[13],
            st_shndx: read_u16(14),
        })
    }

    fn parse_elf64(data: &[u8], endianness: Endianness) -> Result<Self, ParseError> {
        const SIZE: usize = 24;
        if data.len() < SIZE {
            return Err(ParseError::too_short(SIZE, data.len()));
        }

        let read_u16 = |offset: usize| -> u16 {
            let bytes = [data[offset], data[offset + 1]];
            match endianness {
                Endianness::Little => u16::from_le_bytes(bytes),
                Endianness::Big => u16::from_be_bytes(bytes),
            }
        };

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
            st_name: read_u32(0),
            st_info: data[4],
            st_other: data[5],
            st_shndx: read_u16(6),
            st_value: read_u64(8),
            st_size: read_u64(16),
        })
    }

    /// Returns the symbol binding.
    pub fn binding(&self) -> SymbolBinding {
        match self.st_info >> 4 {
            STB_LOCAL => SymbolBinding::Local,
            STB_GLOBAL => SymbolBinding::Global,
            STB_WEAK => SymbolBinding::Weak,
            other => SymbolBinding::Other(other),
        }
    }

    /// Returns the symbol type.
    pub fn kind(&self) -> SymbolKind {
        match self.st_info & 0xf {
            STT_NOTYPE => SymbolKind::None,
            STT_OBJECT => SymbolKind::Object,
            STT_FUNC => SymbolKind::Function,
            STT_SECTION => SymbolKind::Section,
            STT_FILE => SymbolKind::File,
            STT_COMMON => SymbolKind::Common,
            STT_TLS => SymbolKind::Tls,
            other => SymbolKind::Other(other),
        }
    }

    /// Converts this entry to a Symbol.
    pub fn to_symbol(&self, name: String) -> Symbol {
        Symbol {
            name,
            address: self.st_value,
            size: self.st_size,
            kind: self.kind(),
            binding: self.binding(),
            section_index: if self.st_shndx == SHN_UNDEF {
                None
            } else {
                Some(self.st_shndx as u32)
            },
        }
    }
}
