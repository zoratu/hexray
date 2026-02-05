//! DWARF5 .debug_rnglists section support.
//!
//! The .debug_rnglists section contains range lists that describe non-contiguous
//! address ranges. This replaces the DWARF4 .debug_ranges section with a more
//! compact representation.
//!
//! # Range List Entries (RLE)
//!
//! Each entry starts with a 1-byte operator:
//! - `DW_RLE_end_of_list` (0x00): End of list
//! - `DW_RLE_base_addressx` (0x01): Set base address via index
//! - `DW_RLE_startx_endx` (0x02): Range via start/end indices
//! - `DW_RLE_startx_length` (0x03): Range via start index + length
//! - `DW_RLE_offset_pair` (0x04): Offset pair from base
//! - `DW_RLE_base_address` (0x05): Set base address directly
//! - `DW_RLE_start_end` (0x06): Range via start/end addresses
//! - `DW_RLE_start_length` (0x07): Range via start address + length

use super::leb128::decode_uleb128;
use crate::ParseError;

/// Helper to create a truncated data error.
fn truncated(expected: usize, actual: usize, context: &'static str) -> ParseError {
    ParseError::TruncatedData {
        expected,
        actual,
        context,
    }
}

/// Range list entry operators (DWARF5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwRle {
    EndOfList = 0x00,
    BaseAddressx = 0x01,
    StartxEndx = 0x02,
    StartxLength = 0x03,
    OffsetPair = 0x04,
    BaseAddress = 0x05,
    StartEnd = 0x06,
    StartLength = 0x07,
}

impl From<u8> for DwRle {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DwRle::EndOfList,
            0x01 => DwRle::BaseAddressx,
            0x02 => DwRle::StartxEndx,
            0x03 => DwRle::StartxLength,
            0x04 => DwRle::OffsetPair,
            0x05 => DwRle::BaseAddress,
            0x06 => DwRle::StartEnd,
            0x07 => DwRle::StartLength,
            _ => DwRle::EndOfList, // Unknown treated as end
        }
    }
}

/// A single address range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    /// Start address of the range.
    pub start: u64,
    /// End address of the range (exclusive).
    pub end: u64,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Returns true if this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Returns the size of this range.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

/// Parsed range list header from .debug_rnglists section.
#[derive(Debug, Clone)]
pub struct RangeListsHeader {
    /// Whether this is 64-bit DWARF format.
    pub is_64bit: bool,
    /// DWARF version (should be 5).
    pub version: u16,
    /// Address size in bytes.
    pub address_size: u8,
    /// Segment selector size.
    pub segment_selector_size: u8,
    /// Number of offsets in the offset table.
    pub offset_entry_count: u32,
}

/// Parser for DWARF5 range lists.
pub struct RangeListsParser<'a> {
    data: &'a [u8],
    address_size: u8,
}

impl<'a> RangeListsParser<'a> {
    /// Create a new range lists parser.
    pub fn new(data: &'a [u8], address_size: u8) -> Self {
        Self { data, address_size }
    }

    /// Parse a range list at the given offset.
    ///
    /// # Arguments
    /// * `offset` - Offset within the section to start parsing.
    /// * `base_address` - Initial base address for offset pairs.
    /// * `addr_table` - Optional address table for indexed lookups.
    pub fn parse_range_list(
        &self,
        offset: usize,
        base_address: u64,
        addr_table: Option<&super::addr_table::AddressTable>,
    ) -> Result<Vec<AddressRange>, ParseError> {
        let mut ranges = Vec::new();
        let mut pos = offset;
        let mut current_base = base_address;

        loop {
            if pos >= self.data.len() {
                return Err(truncated(0, 0, "range list"));
            }

            let op = DwRle::from(self.data[pos]);
            pos += 1;

            match op {
                DwRle::EndOfList => break,

                DwRle::BaseAddressx => {
                    let (index, len) = decode_uleb128(&self.data[pos..])?;
                    pos += len;
                    if let Some(table) = addr_table {
                        if let Some(addr) = table.get_address(index as usize) {
                            current_base = addr;
                        }
                    }
                }

                DwRle::StartxEndx => {
                    let (start_idx, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (end_idx, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;

                    if let Some(table) = addr_table {
                        if let (Some(start), Some(end)) = (
                            table.get_address(start_idx as usize),
                            table.get_address(end_idx as usize),
                        ) {
                            ranges.push(AddressRange::new(start, end));
                        }
                    }
                }

                DwRle::StartxLength => {
                    let (start_idx, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (length, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;

                    if let Some(table) = addr_table {
                        if let Some(start) = table.get_address(start_idx as usize) {
                            ranges.push(AddressRange::new(start, start + length));
                        }
                    }
                }

                DwRle::OffsetPair => {
                    let (start_off, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (end_off, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;

                    let start = current_base.wrapping_add(start_off);
                    let end = current_base.wrapping_add(end_off);
                    ranges.push(AddressRange::new(start, end));
                }

                DwRle::BaseAddress => {
                    current_base = self.read_address(&mut pos)?;
                }

                DwRle::StartEnd => {
                    let start = self.read_address(&mut pos)?;
                    let end = self.read_address(&mut pos)?;
                    ranges.push(AddressRange::new(start, end));
                }

                DwRle::StartLength => {
                    let start = self.read_address(&mut pos)?;
                    let (length, len) = decode_uleb128(&self.data[pos..])?;
                    pos += len;
                    ranges.push(AddressRange::new(start, start + length));
                }
            }
        }

        Ok(ranges)
    }

    /// Read an address at the current position.
    fn read_address(&self, pos: &mut usize) -> Result<u64, ParseError> {
        if self.address_size == 8 {
            if self.data.len() < *pos + 8 {
                return Err(truncated(0, 0, "range list"));
            }
            let addr = u64::from_le_bytes([
                self.data[*pos],
                self.data[*pos + 1],
                self.data[*pos + 2],
                self.data[*pos + 3],
                self.data[*pos + 4],
                self.data[*pos + 5],
                self.data[*pos + 6],
                self.data[*pos + 7],
            ]);
            *pos += 8;
            Ok(addr)
        } else {
            if self.data.len() < *pos + 4 {
                return Err(truncated(0, 0, "range list"));
            }
            let addr = u32::from_le_bytes([
                self.data[*pos],
                self.data[*pos + 1],
                self.data[*pos + 2],
                self.data[*pos + 3],
            ]);
            *pos += 4;
            Ok(addr as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_list() {
        let data = [0x00]; // DW_RLE_end_of_list
        let parser = RangeListsParser::new(&data, 8);
        let ranges = parser.parse_range_list(0, 0, None).unwrap();
        assert!(ranges.is_empty());
    }

    #[test]
    fn test_parse_start_end() {
        // DW_RLE_start_end with 4-byte addresses
        let data = [
            0x06, // DW_RLE_start_end
            0x00, 0x10, 0x00, 0x00, // start = 0x1000
            0x00, 0x20, 0x00, 0x00, // end = 0x2000
            0x00, // DW_RLE_end_of_list
        ];
        let parser = RangeListsParser::new(&data, 4);
        let ranges = parser.parse_range_list(0, 0, None).unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[0].end, 0x2000);
    }

    #[test]
    fn test_parse_offset_pair() {
        // DW_RLE_offset_pair with base address 0x1000
        let data = [
            0x04, // DW_RLE_offset_pair
            0x00, // start offset = 0 (ULEB128)
            0x80, 0x08, // end offset = 0x400 (ULEB128)
            0x00, // DW_RLE_end_of_list
        ];
        let parser = RangeListsParser::new(&data, 4);
        let ranges = parser.parse_range_list(0, 0x1000, None).unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[0].end, 0x1400);
    }

    #[test]
    fn test_parse_start_length() {
        // DW_RLE_start_length with 4-byte address
        let data = [
            0x07, // DW_RLE_start_length
            0x00, 0x10, 0x00, 0x00, // start = 0x1000
            0x80, 0x08, // length = 0x400 (ULEB128)
            0x00, // DW_RLE_end_of_list
        ];
        let parser = RangeListsParser::new(&data, 4);
        let ranges = parser.parse_range_list(0, 0, None).unwrap();

        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[0].end, 0x1400);
    }

    #[test]
    fn test_address_range_contains() {
        let range = AddressRange::new(0x1000, 0x2000);
        assert!(!range.contains(0x0fff));
        assert!(range.contains(0x1000));
        assert!(range.contains(0x1500));
        assert!(!range.contains(0x2000)); // End is exclusive
    }
}
