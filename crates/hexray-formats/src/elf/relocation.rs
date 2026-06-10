//!
//! Relocations are used in relocatable objects (.o files, kernel modules)
//! to specify how addresses should be patched when linking.

use super::header::ElfClass;
use super::section::{SHT_REL, SHT_RELA};
use super::SectionHeader;
use crate::ParseError;
use hexray_core::Endianness;

// Bounds-checked endian-aware fixed-width readers. Callers verify the
// buffer length at function entry; these helpers return `0` on
// out-of-range access so clippy's `indexing_slicing` /
// `arithmetic_side_effects` lints don't fire at every read site.
#[inline]
fn read_u32(data: &[u8], at: usize, endianness: Endianness) -> u32 {
    let end = at.saturating_add(4);
    let arr: [u8; 4] = data
        .get(at..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => u32::from_le_bytes(arr),
        Endianness::Big => u32::from_be_bytes(arr),
    }
}

#[inline]
fn read_i32(data: &[u8], at: usize, endianness: Endianness) -> i32 {
    let end = at.saturating_add(4);
    let arr: [u8; 4] = data
        .get(at..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => i32::from_le_bytes(arr),
        Endianness::Big => i32::from_be_bytes(arr),
    }
}

#[inline]
fn read_u64(data: &[u8], at: usize, endianness: Endianness) -> u64 {
    let end = at.saturating_add(8);
    let arr: [u8; 8] = data
        .get(at..end)
        .unwrap_or(&[0; 8])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => u64::from_le_bytes(arr),
        Endianness::Big => u64::from_be_bytes(arr),
    }
}

#[inline]
fn read_i64(data: &[u8], at: usize, endianness: Endianness) -> i64 {
    let end = at.saturating_add(8);
    let arr: [u8; 8] = data
        .get(at..end)
        .unwrap_or(&[0; 8])
        .try_into()
        .unwrap_or_default();
    match endianness {
        Endianness::Little => i64::from_le_bytes(arr),
        Endianness::Big => i64::from_be_bytes(arr),
    }
}

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
    /// TLS offset from thread pointer
    Tpoff64,
    /// TLS module ID for Global Dynamic descriptors
    DtpMod64,
    /// TLS offset within the module for Global Dynamic descriptors
    DtpOff64,
    /// 64-bit GOT offset
    GotOff64,
    /// 32-bit signed PC-relative offset to GOT
    GotPc32,
    /// Relaxable GOT PC-relative (for mov from GOT)
    GotPcRelX,
    /// Relaxable GOT PC-relative with REX prefix
    RexGotPcRelX,
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
            16 => Self::DtpMod64,
            17 => Self::DtpOff64,
            18 => Self::Tpoff64,
            24 => Self::Pc64,
            25 => Self::GotOff64,
            26 => Self::GotPc32,
            41 => Self::GotPcRelX,
            42 => Self::RexGotPcRelX,
            other => Self::Unknown(other),
        }
    }

    /// Parse an ARM64 relocation type.
    pub fn from_arm64(r_type: u32) -> Self {
        match r_type {
            0 => Self::None,
            257 => Self::R64,  // R_AARCH64_ABS64
            258 => Self::R32,  // R_AARCH64_ABS32
            259 => Self::R16,  // R_AARCH64_ABS16
            260 => Self::Pc64, // R_AARCH64_PREL64
            261 => Self::Pc32, // R_AARCH64_PREL32
            262 => Self::Pc16, // R_AARCH64_PREL16
            // R_AARCH64_JUMP26 (B) / R_AARCH64_CALL26 (BL): 26-bit
            // signed branch displacement encoded into the lower 26
            // bits of the 4-byte branch instruction. For our
            // "what symbol does this call target" purposes these
            // are functionally PLT-style PC-relative calls — we
            // alias them to `Plt32` so the relocation_table
            // call-resolution path (`build_relocation_table` in
            // the hexray bin) recognises them. Without this map,
            // every PLT call in an aarch64 `.o` falls into
            // `Unknown(282/283)` and emits as `sub_<addr>()`
            // instead of e.g. `__cxa_throw`/`memset`.
            282 => Self::Plt32, // R_AARCH64_JUMP26
            283 => Self::Plt32, // R_AARCH64_CALL26
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
    /// `true` when the addend lives in the patch slot itself (SHT_REL —
    /// `addend` above is left zero by the parser, and the bytes at
    /// `offset` carry the implicit value). `false` when the addend
    /// was already captured into `addend` from the relocation entry
    /// (SHT_RELA — the patch slot is not part of the relocation
    /// expression and must NOT be folded back in, even when its
    /// contents are non-zero).
    pub addend_in_slot: bool,
    /// Section index of the symbol table this relocation's
    /// `symbol_index` is scoped to (i.e. the `sh_link` of the
    /// `.rela.*` / `.rel.*` section the entry came from). Needed
    /// when an ELF file carries more than one symbol table
    /// (`.symtab` AND `.dynsym`), because the flattened
    /// `Elf::raw_symbols` interleaves them and a bare
    /// `raw_symbols[symbol_index]` lookup would pull from the
    /// wrong table for any relocation whose linked table isn't
    /// the first one walked.
    pub linked_symtab_section: u32,
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
        let linked_symtab_section = section.sh_link;
        if section.sh_type != SHT_REL {
            return Ok(Vec::new());
        }

        // Refuse `sh_entsize` strides smaller than the natural Rel size
        // (8 bytes ELF32, 16 bytes ELF64). A 1-byte stride would let
        // `sh_size` bytes spawn `sh_size` synthetic relocations, the
        // same shape the soak found for symbol-table parsing.
        let entry_size = section.sh_entsize as usize;
        let min_entry_size = match class {
            ElfClass::Elf32 => 8,
            ElfClass::Elf64 => 16,
        };
        if entry_size < min_entry_size {
            return Ok(Vec::new());
        }

        let mut relocations = Vec::new();
        let mut offset = 0usize;

        while let Some(end) = offset.checked_add(entry_size) {
            if end > data.len() {
                break;
            }
            let Some(slice) = data.get(offset..end) else {
                break;
            };
            let mut reloc = match class {
                ElfClass::Elf32 => Self::parse_rel32(slice, endianness, section_index, is_x86_64)?,
                ElfClass::Elf64 => Self::parse_rel64(slice, endianness, section_index, is_x86_64)?,
            };
            reloc.linked_symtab_section = linked_symtab_section;
            relocations.push(reloc);
            offset = end;
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
        let linked_symtab_section = section.sh_link;
        if section.sh_type != SHT_RELA {
            return Ok(Vec::new());
        }

        // Natural `Rela` is 12 (ELF32) / 24 (ELF64) bytes; reject any
        // `sh_entsize` smaller than that for the same reason as
        // [`parse_rel`].
        let entry_size = section.sh_entsize as usize;
        let min_entry_size = match class {
            ElfClass::Elf32 => 12,
            ElfClass::Elf64 => 24,
        };
        if entry_size < min_entry_size {
            return Ok(Vec::new());
        }

        let mut relocations = Vec::new();
        let mut offset = 0usize;

        while let Some(end) = offset.checked_add(entry_size) {
            if end > data.len() {
                break;
            }
            let Some(slice) = data.get(offset..end) else {
                break;
            };
            let mut reloc = match class {
                ElfClass::Elf32 => Self::parse_rela32(slice, endianness, section_index, is_x86_64)?,
                ElfClass::Elf64 => Self::parse_rela64(slice, endianness, section_index, is_x86_64)?,
            };
            reloc.linked_symtab_section = linked_symtab_section;
            relocations.push(reloc);
            offset = end;
        }

        Ok(relocations)
    }

    fn parse_rel32(
        data: &[u8],
        endianness: Endianness,
        section_index: usize,
        is_x86_64: bool,
    ) -> Result<Self, ParseError> {
        if data.len() < 8 {
            return Err(ParseError::too_short(8, data.len()));
        }

        let r_offset = read_u32(data, 0, endianness);
        let r_info = read_u32(data, 4, endianness);

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
            linked_symtab_section: 0,
            addend_in_slot: true,
        })
    }

    fn parse_rel64(
        data: &[u8],
        endianness: Endianness,
        section_index: usize,
        is_x86_64: bool,
    ) -> Result<Self, ParseError> {
        if data.len() < 16 {
            return Err(ParseError::too_short(16, data.len()));
        }

        let r_offset = read_u64(data, 0, endianness);
        let r_info = read_u64(data, 8, endianness);

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
            linked_symtab_section: 0,
            addend_in_slot: true,
        })
    }

    fn parse_rela32(
        data: &[u8],
        endianness: Endianness,
        section_index: usize,
        is_x86_64: bool,
    ) -> Result<Self, ParseError> {
        if data.len() < 12 {
            return Err(ParseError::too_short(12, data.len()));
        }

        let r_offset = read_u32(data, 0, endianness);
        let r_info = read_u32(data, 4, endianness);
        let r_addend = read_i32(data, 8, endianness);

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
            linked_symtab_section: 0,
            addend_in_slot: false,
        })
    }

    fn parse_rela64(
        data: &[u8],
        endianness: Endianness,
        section_index: usize,
        is_x86_64: bool,
    ) -> Result<Self, ParseError> {
        if data.len() < 24 {
            return Err(ParseError::too_short(24, data.len()));
        }

        let r_offset = read_u64(data, 0, endianness);
        let r_info = read_u64(data, 8, endianness);
        let r_addend = read_i64(data, 16, endianness);

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
            linked_symtab_section: 0,
            addend_in_slot: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::RelocationType;

    /// R_AARCH64_JUMP26 (282) / R_AARCH64_CALL26 (283) are the aarch64
    /// `B` / `BL` branch relocations. Without mapping them here, every
    /// PLT call in an aarch64 relocatable object falls into
    /// `Unknown(283)` and the bin's `build_relocation_table` never
    /// inserts a name for the call site — `__cxa_throw`, `memset`,
    /// every external call shows as `sub_<addr>()` in the decompiled
    /// output. They're functionally PC-relative PLT calls for our
    /// "what symbol does this call target" purposes, so alias to
    /// `Plt32`.
    #[test]
    fn arm64_call26_and_jump26_map_to_plt32() {
        assert_eq!(RelocationType::from_arm64(283), RelocationType::Plt32);
        assert_eq!(RelocationType::from_arm64(282), RelocationType::Plt32);
        // Sanity check: existing mappings unaffected.
        assert_eq!(RelocationType::from_arm64(257), RelocationType::R64);
        assert_eq!(RelocationType::from_arm64(261), RelocationType::Pc32);
    }
}
