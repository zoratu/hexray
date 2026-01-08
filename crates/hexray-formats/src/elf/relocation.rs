//! ELF relocation parsing.
//!
//! Relocations are used in relocatable objects (.o files, kernel modules)
//! to specify how addresses should be patched when linking.

use super::header::ElfClass;
use super::section::{SHT_REL, SHT_RELA};
use super::SectionHeader;
use crate::ParseError;
use hexray_core::Endianness;

/// x86_64 relocation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    /// No relocation
    None,
    /// Direct 64-bit
    R64,
    /// PC-relative 32-bit
    Pc32,
    /// GOT entry 32-bit
    Got32,
    /// PLT entry 32-bit
    Plt32,
    /// Copy symbol at runtime
    Copy,
    /// Create GOT entry
    GlobDat,
    /// Create PLT entry
    JumpSlot,
    /// Adjust by program base
    Relative,
    /// 32-bit GOT PC-relative offset
    GotPcRel,
    /// Direct 32-bit zero extended
    R32,
    /// Direct 32-bit sign extended
    R32S,
    /// Direct 16-bit
    R16,
    /// PC-relative 16-bit
    Pc16,
    /// Direct 8-bit
    R8,
    /// PC-relative 8-bit
    Pc8,
    /// PC-relative 64-bit
    Pc64,
    /// 64-bit GOT offset
    GotOff64,
    /// 32-bit signed PC-relative offset to GOT
    GotPc32,
    /// Unknown relocation type
    Unknown(u32),
}

impl RelocationType {
    /// Parse an x86_64 relocation type.
    pub fn from_x86_64(r_type: u32) -> Self {
        match r_type {
            0 => Self::None,
            1 => Self::R64,
            2 => Self::Pc32,
            3 => Self::Got32,
            4 => Self::Plt32,
            5 => Self::Copy,
            6 => Self::GlobDat,
            7 => Self::JumpSlot,
            8 => Self::Relative,
            9 => Self::GotPcRel,
            10 => Self::R32,
            11 => Self::R32S,
            12 => Self::R16,
            13 => Self::Pc16,
            14 => Self::R8,
            15 => Self::Pc8,
            24 => Self::Pc64,
            25 => Self::GotOff64,
            26 => Self::GotPc32,
            other => Self::Unknown(other),
        }
    }

    /// Parse an ARM64 relocation type.
    pub fn from_arm64(r_type: u32) -> Self {
        match r_type {
            0 => Self::None,
            257 => Self::R64,        // R_AARCH64_ABS64
            258 => Self::R32,        // R_AARCH64_ABS32
            259 => Self::R16,        // R_AARCH64_ABS16
            260 => Self::Pc64,       // R_AARCH64_PREL64
            261 => Self::Pc32,       // R_AARCH64_PREL32
            262 => Self::Pc16,       // R_AARCH64_PREL16
            // Many more ARM64 relocations exist
            other => Self::Unknown(other),
        }
    }
}

/// A parsed relocation entry.
#[derive(Debug, Clone)]
pub struct Relocation {
    /// Offset within the section where the relocation applies.
    pub offset: u64,
    /// Symbol table index.
    pub symbol_index: u32,
    /// Relocation type.
    pub r_type: RelocationType,
    /// Addend (for RELA relocations).
    pub addend: i64,
    /// Section index this relocation applies to.
    pub section_index: usize,
}

impl Relocation {
    /// Parse relocations from a REL section (no addend).
    pub fn parse_rel(
        data: &[u8],
        section: &SectionHeader,
        section_index: usize,
        class: ElfClass,
        endianness: Endianness,
        is_x86_64: bool,
    ) -> Result<Vec<Self>, ParseError> {
        if section.sh_type != SHT_REL {
            return Ok(Vec::new());
        }

        let entry_size = section.sh_entsize as usize;
        if entry_size == 0 {
            return Ok(Vec::new());
        }

        let mut relocations = Vec::new();
        let mut offset = 0;

        while offset + entry_size <= data.len() {
            let reloc = match class {
                ElfClass::Elf32 => Self::parse_rel32(&data[offset..], endianness, section_index, is_x86_64)?,
                ElfClass::Elf64 => Self::parse_rel64(&data[offset..], endianness, section_index, is_x86_64)?,
            };
            relocations.push(reloc);
            offset += entry_size;
        }

        Ok(relocations)
    }

    /// Parse relocations from a RELA section (with addend).
    pub fn parse_rela(
        data: &[u8],
        section: &SectionHeader,
        section_index: usize,
        class: ElfClass,
        endianness: Endianness,
        is_x86_64: bool,
    ) -> Result<Vec<Self>, ParseError> {
        if section.sh_type != SHT_RELA {
            return Ok(Vec::new());
        }

        let entry_size = section.sh_entsize as usize;
        if entry_size == 0 {
            return Ok(Vec::new());
        }

        let mut relocations = Vec::new();
        let mut offset = 0;

        while offset + entry_size <= data.len() {
            let reloc = match class {
                ElfClass::Elf32 => Self::parse_rela32(&data[offset..], endianness, section_index, is_x86_64)?,
                ElfClass::Elf64 => Self::parse_rela64(&data[offset..], endianness, section_index, is_x86_64)?,
            };
            relocations.push(reloc);
            offset += entry_size;
        }

        Ok(relocations)
    }

    fn parse_rel32(data: &[u8], endianness: Endianness, section_index: usize, is_x86_64: bool) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::too_short(8, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let r_offset = read_u32(0);
        let r_info = read_u32(4);

        let symbol_index = r_info >> 8;
        let r_type_raw = r_info & 0xff;
        let r_type = if is_x86_64 {
            RelocationType::from_x86_64(r_type_raw)
        } else {
            RelocationType::from_arm64(r_type_raw)
        };

        Ok(Self {
            offset: r_offset as u64,
            symbol_index,
            r_type,
            addend: 0,
            section_index,
        })
    }

    fn parse_rel64(data: &[u8], endianness: Endianness, section_index: usize, is_x86_64: bool) -> Result<Self, ParseError> {
        if data.len() < 16 {
            return Err(ParseError::too_short(16, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        let r_offset = read_u64(0);
        let r_info = read_u64(8);

        let symbol_index = (r_info >> 32) as u32;
        let r_type_raw = (r_info & 0xffffffff) as u32;
        let r_type = if is_x86_64 {
            RelocationType::from_x86_64(r_type_raw)
        } else {
            RelocationType::from_arm64(r_type_raw)
        };

        Ok(Self {
            offset: r_offset,
            symbol_index,
            r_type,
            addend: 0,
            section_index,
        })
    }

    fn parse_rela32(data: &[u8], endianness: Endianness, section_index: usize, is_x86_64: bool) -> Result<Self, ParseError> {
        if data.len() < 12 {
            return Err(ParseError::too_short(12, data.len()));
        }

        let read_u32 = |offset: usize| -> u32 {
            let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            match endianness {
                Endianness::Little => u32::from_le_bytes(bytes),
                Endianness::Big => u32::from_be_bytes(bytes),
            }
        };

        let read_i32 = |offset: usize| -> i32 {
            let bytes = [data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
            match endianness {
                Endianness::Little => i32::from_le_bytes(bytes),
                Endianness::Big => i32::from_be_bytes(bytes),
            }
        };

        let r_offset = read_u32(0);
        let r_info = read_u32(4);
        let r_addend = read_i32(8);

        let symbol_index = r_info >> 8;
        let r_type_raw = r_info & 0xff;
        let r_type = if is_x86_64 {
            RelocationType::from_x86_64(r_type_raw)
        } else {
            RelocationType::from_arm64(r_type_raw)
        };

        Ok(Self {
            offset: r_offset as u64,
            symbol_index,
            r_type,
            addend: r_addend as i64,
            section_index,
        })
    }

    fn parse_rela64(data: &[u8], endianness: Endianness, section_index: usize, is_x86_64: bool) -> Result<Self, ParseError> {
        if data.len() < 24 {
            return Err(ParseError::too_short(24, data.len()));
        }

        let read_u64 = |offset: usize| -> u64 {
            let bytes = [
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ];
            match endianness {
                Endianness::Little => u64::from_le_bytes(bytes),
                Endianness::Big => u64::from_be_bytes(bytes),
            }
        };

        let read_i64 = |offset: usize| -> i64 {
            let bytes = [
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ];
            match endianness {
                Endianness::Little => i64::from_le_bytes(bytes),
                Endianness::Big => i64::from_be_bytes(bytes),
            }
        };

        let r_offset = read_u64(0);
        let r_info = read_u64(8);
        let r_addend = read_i64(16);

        let symbol_index = (r_info >> 32) as u32;
        let r_type_raw = (r_info & 0xffffffff) as u32;
        let r_type = if is_x86_64 {
            RelocationType::from_x86_64(r_type_raw)
        } else {
            RelocationType::from_arm64(r_type_raw)
        };

        Ok(Self {
            offset: r_offset,
            symbol_index,
            r_type,
            addend: r_addend,
            section_index,
        })
    }
}
