//! DWARF5 .debug_loclists section support.
//!
//! The .debug_loclists section contains location lists that describe where
//! a variable is stored at different points in the program. This replaces
//! the DWARF4 .debug_loc section with a more compact representation.
//!
//! # Location List Entries (LLE)
//!
//! Each entry starts with a 1-byte operator:
//! - `DW_LLE_end_of_list` (0x00): End of list
//! - `DW_LLE_base_addressx` (0x01): Set base address via index
//! - `DW_LLE_startx_endx` (0x02): Range via start/end indices
//! - `DW_LLE_startx_length` (0x03): Range via start index + length
//! - `DW_LLE_offset_pair` (0x04): Offset pair from base
//! - `DW_LLE_default_location` (0x05): Default location (all addresses)
//! - `DW_LLE_base_address` (0x06): Set base address directly
//! - `DW_LLE_start_end` (0x07): Range via start/end addresses
//! - `DW_LLE_start_length` (0x08): Range via start address + length

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

/// Location list entry operators (DWARF5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DwLle {
    EndOfList = 0x00,
    BaseAddressx = 0x01,
    StartxEndx = 0x02,
    StartxLength = 0x03,
    OffsetPair = 0x04,
    DefaultLocation = 0x05,
    BaseAddress = 0x06,
    StartEnd = 0x07,
    StartLength = 0x08,
}

impl From<u8> for DwLle {
    fn from(value: u8) -> Self {
        match value {
            0x00 => DwLle::EndOfList,
            0x01 => DwLle::BaseAddressx,
            0x02 => DwLle::StartxEndx,
            0x03 => DwLle::StartxLength,
            0x04 => DwLle::OffsetPair,
            0x05 => DwLle::DefaultLocation,
            0x06 => DwLle::BaseAddress,
            0x07 => DwLle::StartEnd,
            0x08 => DwLle::StartLength,
            _ => DwLle::EndOfList, // Unknown treated as end
        }
    }
}

/// A location description for a variable.
#[derive(Debug, Clone)]
pub struct LocationEntry {
    /// Start address of this location's validity (None for default location).
    pub start: Option<u64>,
    /// End address of this location's validity (exclusive, None for default).
    pub end: Option<u64>,
    /// The DWARF expression describing the location.
    pub expression: Vec<u8>,
}

impl LocationEntry {
    /// Create a new location entry with a specific address range.
    pub fn new(start: u64, end: u64, expression: Vec<u8>) -> Self {
        Self {
            start: Some(start),
            end: Some(end),
            expression,
        }
    }

    /// Create a default location entry (valid everywhere).
    pub fn default_location(expression: Vec<u8>) -> Self {
        Self {
            start: None,
            end: None,
            expression,
        }
    }

    /// Returns true if this location is valid at the given address.
    pub fn is_valid_at(&self, addr: u64) -> bool {
        match (self.start, self.end) {
            (Some(start), Some(end)) => addr >= start && addr < end,
            (None, None) => true, // Default location
            _ => false,
        }
    }

    /// Returns true if this is a default location.
    pub fn is_default(&self) -> bool {
        self.start.is_none() && self.end.is_none()
    }
}

/// Parser for DWARF5 location lists.
pub struct LocationListsParser<'a> {
    data: &'a [u8],
    address_size: u8,
}

impl<'a> LocationListsParser<'a> {
    /// Create a new location lists parser.
    pub fn new(data: &'a [u8], address_size: u8) -> Self {
        Self { data, address_size }
    }

    /// Parse a location list at the given offset.
    ///
    /// # Arguments
    /// * `offset` - Offset within the section to start parsing.
    /// * `base_address` - Initial base address for offset pairs.
    /// * `addr_table` - Optional address table for indexed lookups.
    pub fn parse_location_list(
        &self,
        offset: usize,
        base_address: u64,
        addr_table: Option<&super::addr_table::AddressTable>,
    ) -> Result<Vec<LocationEntry>, ParseError> {
        let mut locations = Vec::new();
        let mut pos = offset;
        let mut current_base = base_address;

        loop {
            if pos >= self.data.len() {
                return Err(truncated(0, 0, "location list"));
            }

            let op = DwLle::from(self.data[pos]);
            pos += 1;

            match op {
                DwLle::EndOfList => break,

                DwLle::BaseAddressx => {
                    let (index, len) = decode_uleb128(&self.data[pos..])?;
                    pos += len;
                    if let Some(table) = addr_table {
                        if let Some(addr) = table.get_address(index as usize) {
                            current_base = addr;
                        }
                    }
                }

                DwLle::StartxEndx => {
                    let (start_idx, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (end_idx, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;
                    let expr = self.read_expression(&mut pos)?;

                    if let Some(table) = addr_table {
                        if let (Some(start), Some(end)) = (
                            table.get_address(start_idx as usize),
                            table.get_address(end_idx as usize),
                        ) {
                            locations.push(LocationEntry::new(start, end, expr));
                        }
                    }
                }

                DwLle::StartxLength => {
                    let (start_idx, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (length, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;
                    let expr = self.read_expression(&mut pos)?;

                    if let Some(table) = addr_table {
                        if let Some(start) = table.get_address(start_idx as usize) {
                            locations.push(LocationEntry::new(start, start + length, expr));
                        }
                    }
                }

                DwLle::OffsetPair => {
                    let (start_off, len1) = decode_uleb128(&self.data[pos..])?;
                    pos += len1;
                    let (end_off, len2) = decode_uleb128(&self.data[pos..])?;
                    pos += len2;
                    let expr = self.read_expression(&mut pos)?;

                    let start = current_base.wrapping_add(start_off);
                    let end = current_base.wrapping_add(end_off);
                    locations.push(LocationEntry::new(start, end, expr));
                }

                DwLle::DefaultLocation => {
                    let expr = self.read_expression(&mut pos)?;
                    locations.push(LocationEntry::default_location(expr));
                }

                DwLle::BaseAddress => {
                    current_base = self.read_address(&mut pos)?;
                }

                DwLle::StartEnd => {
                    let start = self.read_address(&mut pos)?;
                    let end = self.read_address(&mut pos)?;
                    let expr = self.read_expression(&mut pos)?;
                    locations.push(LocationEntry::new(start, end, expr));
                }

                DwLle::StartLength => {
                    let start = self.read_address(&mut pos)?;
                    let (length, len) = decode_uleb128(&self.data[pos..])?;
                    pos += len;
                    let expr = self.read_expression(&mut pos)?;
                    locations.push(LocationEntry::new(start, start + length, expr));
                }
            }
        }

        Ok(locations)
    }

    /// Read an address at the current position.
    fn read_address(&self, pos: &mut usize) -> Result<u64, ParseError> {
        if self.address_size == 8 {
            if self.data.len() < *pos + 8 {
                return Err(truncated(0, 0, "location list"));
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
                return Err(truncated(0, 0, "location list"));
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

    /// Read a location expression (ULEB128 length followed by bytes).
    fn read_expression(&self, pos: &mut usize) -> Result<Vec<u8>, ParseError> {
        let (length, len) = decode_uleb128(&self.data[*pos..])?;
        *pos += len;

        let length = length as usize;
        if self.data.len() < *pos + length {
            return Err(truncated(0, 0, "location list"));
        }

        let expr = self.data[*pos..*pos + length].to_vec();
        *pos += length;
        Ok(expr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_list() {
        let data = [0x00]; // DW_LLE_end_of_list
        let parser = LocationListsParser::new(&data, 8);
        let locs = parser.parse_location_list(0, 0, None).unwrap();
        assert!(locs.is_empty());
    }

    #[test]
    fn test_parse_default_location() {
        // DW_LLE_default_location with 2-byte expression
        let data = [
            0x05, // DW_LLE_default_location
            0x02, // expression length = 2
            0x50, 0x00, // DW_OP_reg0
            0x00, // DW_LLE_end_of_list
        ];
        let parser = LocationListsParser::new(&data, 4);
        let locs = parser.parse_location_list(0, 0, None).unwrap();

        assert_eq!(locs.len(), 1);
        assert!(locs[0].is_default());
        assert_eq!(locs[0].expression, vec![0x50, 0x00]);
    }

    #[test]
    fn test_parse_start_end() {
        // DW_LLE_start_end with 4-byte addresses
        let data = [
            0x07, // DW_LLE_start_end
            0x00, 0x10, 0x00, 0x00, // start = 0x1000
            0x00, 0x20, 0x00, 0x00, // end = 0x2000
            0x01, // expression length = 1
            0x50, // DW_OP_reg0
            0x00, // DW_LLE_end_of_list
        ];
        let parser = LocationListsParser::new(&data, 4);
        let locs = parser.parse_location_list(0, 0, None).unwrap();

        assert_eq!(locs.len(), 1);
        assert_eq!(locs[0].start, Some(0x1000));
        assert_eq!(locs[0].end, Some(0x2000));
        assert_eq!(locs[0].expression, vec![0x50]);
    }

    #[test]
    fn test_location_validity() {
        let loc = LocationEntry::new(0x1000, 0x2000, vec![0x50]);
        assert!(!loc.is_valid_at(0x0fff));
        assert!(loc.is_valid_at(0x1000));
        assert!(loc.is_valid_at(0x1500));
        assert!(!loc.is_valid_at(0x2000)); // End is exclusive

        let default = LocationEntry::default_location(vec![0x50]);
        assert!(default.is_valid_at(0));
        assert!(default.is_valid_at(0x1000));
        assert!(default.is_valid_at(u64::MAX));
    }
}
