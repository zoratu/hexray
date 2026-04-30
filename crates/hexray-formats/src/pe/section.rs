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

        // Parse name (8 bytes, null-terminated). Bounds were checked
        // at function entry — `data.len() >= SECTION_HEADER_SIZE`
        // (== 40) — so the .get(..N) calls below all succeed; we use
        // them anyway so the bounds check is visible to clippy.
        // try_into on a slice of the right length is infallible; the
        // .unwrap_or_default() falls back to all-zeros which can only
        // surface if the bounds check itself was wrong.
        fn read_u16(data: &[u8], at: usize) -> u16 {
            u16::from_le_bytes(
                data.get(at..at.saturating_add(2))
                    .unwrap_or(&[0; 2])
                    .try_into()
                    .unwrap_or_default(),
            )
        }
        fn read_u32(data: &[u8], at: usize) -> u32 {
            u32::from_le_bytes(
                data.get(at..at.saturating_add(4))
                    .unwrap_or(&[0; 4])
                    .try_into()
                    .unwrap_or_default(),
            )
        }
        let name_bytes = data.get(..8).unwrap_or(&[]);
        let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
        let name = crate::name_from_bytes(name_bytes.get(..name_end).unwrap_or(&[]));

        Ok(Self {
            name,
            virtual_size: read_u32(data, 8),
            virtual_address: read_u32(data, 12),
            size_of_raw_data: read_u32(data, 16),
            pointer_to_raw_data: read_u32(data, 20),
            pointer_to_relocations: read_u32(data, 24),
            pointer_to_linenumbers: read_u32(data, 28),
            number_of_relocations: read_u16(data, 32),
            number_of_linenumbers: read_u16(data, 34),
            characteristics: read_u32(data, 36),
            data_cache: Vec::new(),
            image_base: 0, // Will be set by populate_data
        })
    }

    /// Populate the section data cache from file data.
    pub fn populate_data(&mut self, file_data: &[u8], image_base: u64) {
        self.image_base = image_base;
        let start = self.pointer_to_raw_data as usize;
        let size = self.size_of_raw_data as usize;
        let end = start.saturating_add(size);
        if let Some(slice) = file_data.get(start..end) {
            self.data_cache = slice.to_vec();
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
        self.image_base.saturating_add(self.virtual_address as u64)
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
