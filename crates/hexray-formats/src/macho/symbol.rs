//! Mach-O symbol table parsing.

use crate::ParseError;
use hexray_core::{Symbol, SymbolBinding, SymbolKind};

// Symbol type masks
const N_STAB: u8 = 0xE0;  // Debugging symbol
const N_PEXT: u8 = 0x10;  // Private external
const N_TYPE: u8 = 0x0E;  // Type mask
const N_EXT: u8 = 0x01;   // External symbol

// Symbol types (N_TYPE values)
const N_UNDF: u8 = 0x0;   // Undefined
const N_ABS: u8 = 0x2;    // Absolute
const N_SECT: u8 = 0xE;   // Defined in section
const N_PBUD: u8 = 0xC;   // Prebound undefined
const N_INDR: u8 = 0xA;   // Indirect

/// A Mach-O symbol table entry (nlist).
#[derive(Debug, Clone)]
pub struct Nlist {
    /// Index into string table.
    pub n_strx: u32,
    /// Type and binding info.
    pub n_type: u8,
    /// Section number.
    pub n_sect: u8,
    /// Description (for stabs, this has meaning).
    pub n_desc: u16,
    /// Symbol value (address).
    pub n_value: u64,
}

impl Nlist {
    /// Parse an nlist entry from bytes.
    pub fn parse(data: &[u8], is_64: bool) -> Result<Self, ParseError> {
        let entry_size = if is_64 { 16 } else { 12 };
        if data.len() < entry_size {
            return Err(ParseError::too_short(entry_size, data.len()));
        }

        let n_strx = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let n_type = data[4];
        let n_sect = data[5];
        let n_desc = u16::from_le_bytes([data[6], data[7]]);

        let n_value = if is_64 {
            u64::from_le_bytes([
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15],
            ])
        } else {
            u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as u64
        };

        Ok(Self {
            n_strx,
            n_type,
            n_sect,
            n_desc,
            n_value,
        })
    }

    /// Returns true if this is a debugging symbol.
    pub fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }

    /// Returns true if this is an external symbol.
    pub fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }

    /// Returns true if this is a private external symbol.
    pub fn is_private_external(&self) -> bool {
        self.n_type & N_PEXT != 0
    }

    /// Returns true if this symbol is defined.
    pub fn is_defined(&self) -> bool {
        let typ = self.n_type & N_TYPE;
        typ == N_SECT || typ == N_ABS
    }

    /// Returns true if this symbol is undefined.
    pub fn is_undefined(&self) -> bool {
        let typ = self.n_type & N_TYPE;
        typ == N_UNDF && self.n_value == 0
    }

    /// Returns the symbol binding.
    pub fn binding(&self) -> SymbolBinding {
        if self.is_private_external() {
            SymbolBinding::Local
        } else if self.is_external() {
            SymbolBinding::Global
        } else {
            SymbolBinding::Local
        }
    }

    /// Returns the symbol kind.
    ///
    /// Note: Mach-O doesn't distinguish between functions and objects
    /// in the symbol type. We'd need to look at the section to determine this.
    pub fn kind(&self) -> SymbolKind {
        if self.is_stab() {
            SymbolKind::Other(self.n_type)
        } else if !self.is_defined() {
            SymbolKind::None
        } else {
            // We can't easily tell if it's a function or object
            // without looking at the section flags
            SymbolKind::None
        }
    }

    /// Convert to a Symbol.
    pub fn to_symbol(&self, name: String) -> Symbol {
        Symbol {
            name,
            address: self.n_value,
            size: 0, // Mach-O nlist doesn't store size
            kind: self.kind(),
            binding: self.binding(),
            section_index: if self.n_sect > 0 {
                Some(self.n_sect as u32 - 1) // n_sect is 1-based
            } else {
                None
            },
        }
    }
}
