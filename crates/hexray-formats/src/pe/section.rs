//! PE section parsing.

use super::header::{
    IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use crate::ParseError;

/// Section header size
pub const SECTION_HEADER_SIZE: usize = 40;

/// PE Section Header
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Section name (8 bytes, null-padded)
    pub name: String,
    /// Virtual size
    pub virtual_size: u32,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Size of raw data
    pub size_of_raw_data: u32,
    /// Pointer to raw data
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_linenumbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_linenumbers: u16,
    /// Characteristics
    pub characteristics: u32,
    /// Cached section data
    data_cache: Vec<u8>,
    /// Image base (for computing absolute virtual addresses)
    image_base: u64,
}

impl SectionHeader {
    /// Parse a section header from bytes.
    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        if data.len() < SECTION_HEADER_SIZE {
            return Err(ParseError::too_short(SECTION_HEADER_SIZE, data.len()));
        }

        // Parse name (8 bytes, null-terminated)
        let name_bytes = &data[0..8];
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();

        Ok(Self {
            name,
            virtual_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            virtual_address: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            size_of_raw_data: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            pointer_to_raw_data: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            pointer_to_relocations: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            pointer_to_linenumbers: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            number_of_relocations: u16::from_le_bytes([data[32], data[33]]),
            number_of_linenumbers: u16::from_le_bytes([data[34], data[35]]),
            characteristics: u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
            data_cache: Vec::new(),
            image_base: 0, // Will be set by populate_data
        })
    }

    /// Populate the section data cache from file data.
    pub fn populate_data(&mut self, file_data: &[u8], image_base: u64) {
        self.image_base = image_base;
        let start = self.pointer_to_raw_data as usize;
        let size = self.size_of_raw_data as usize;
        let end = start + size;
        if end <= file_data.len() {
            self.data_cache = file_data[start..end].to_vec();
        }
    }

    /// Returns true if this section contains code.
    pub fn is_code(&self) -> bool {
        self.characteristics & IMAGE_SCN_CNT_CODE != 0
    }

    /// Returns true if this section is executable.
    pub fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    /// Returns true if this section is readable.
    pub fn is_readable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_READ != 0
    }

    /// Returns true if this section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    /// Get flags string (R/W/X)
    pub fn flags_string(&self) -> String {
        let mut flags = String::with_capacity(3);
        flags.push(if self.is_readable() { 'R' } else { '-' });
        flags.push(if self.is_writable() { 'W' } else { '-' });
        flags.push(if self.is_executable() { 'X' } else { '-' });
        flags
    }
}

impl crate::Section for SectionHeader {
    fn name(&self) -> &str {
        &self.name
    }

    fn virtual_address(&self) -> u64 {
        self.image_base + self.virtual_address as u64
    }

    fn size(&self) -> u64 {
        self.virtual_size as u64
    }

    fn data(&self) -> &[u8] {
        &self.data_cache
    }

    fn is_executable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
    }

    fn is_writable(&self) -> bool {
        self.characteristics & IMAGE_SCN_MEM_WRITE != 0
    }

    fn is_allocated(&self) -> bool {
        self.virtual_size > 0
    }
}
