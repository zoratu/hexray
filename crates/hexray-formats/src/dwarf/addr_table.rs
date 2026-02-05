//! DWARF5 .debug_addr section support.
//!
//! The .debug_addr section contains a table of addresses, allowing indirect
//! address references via indices. This is a DWARF5 feature that enables more
//! compact debug info representation and supports split DWARF.
//!
//! # Section Format (DWARF5)
//!
//! ```text
//! Header:
//!   unit_length: 4 bytes (or 12 for 64-bit DWARF)
//!   version: 2 bytes (must be 5)
//!   address_size: 1 byte
//!   segment_selector_size: 1 byte
//!
//! Body:
//!   address[0]: address_size bytes (index 0)
//!   address[1]: address_size bytes (index 1)
//!   ...
//! ```

use crate::ParseError;

/// Helper to create a truncated data error.
fn truncated(expected: usize, actual: usize, context: &'static str) -> ParseError {
    ParseError::TruncatedData {
        expected,
        actual,
        context,
    }
}

/// Parsed address table from .debug_addr section.
#[derive(Debug, Clone)]
pub struct AddressTable {
    /// Whether this is 64-bit DWARF format.
    pub is_64bit: bool,
    /// DWARF version (should be 5).
    pub version: u16,
    /// Address size in bytes (typically 4 or 8).
    pub address_size: u8,
    /// Segment selector size (usually 0).
    pub segment_selector_size: u8,
    /// The addresses (one per index).
    addresses: Vec<u64>,
}

impl AddressTable {
    /// Parse the address table from raw section data.
    ///
    /// # Arguments
    /// * `data` - The .debug_addr section data.
    /// * `offset` - Starting offset within the section (from DW_AT_addr_base).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        if data.len() < offset + 4 {
            return Err(truncated(0, 0, "address table"));
        }

        let mut pos = offset;

        // Parse unit length to determine 32/64-bit format
        let initial_length =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let (is_64bit, unit_length) = if initial_length == 0xffff_ffff {
            // 64-bit DWARF
            if data.len() < pos + 8 {
                return Err(truncated(0, 0, "address table"));
            }
            let len = u64::from_le_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
                data[pos + 4],
                data[pos + 5],
                data[pos + 6],
                data[pos + 7],
            ]);
            pos += 8;
            (true, len as usize)
        } else {
            (false, initial_length as usize)
        };

        // Parse version (must be 5)
        if data.len() < pos + 4 {
            return Err(truncated(0, 0, "address table"));
        }
        let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;

        let address_size = data[pos];
        pos += 1;

        let segment_selector_size = data[pos];
        pos += 1;

        if version != 5 {
            return Err(ParseError::UnsupportedVersion {
                format: "DWARF address table",
                version: version as u32,
            });
        }

        if address_size != 4 && address_size != 8 {
            return Err(ParseError::InvalidValue("address size must be 4 or 8"));
        }

        // Calculate how many addresses we have
        let header_size = 4; // version (2) + address_size (1) + segment_selector_size (1)
        let body_size = unit_length.saturating_sub(header_size);
        let entry_size = (address_size + segment_selector_size) as usize;
        let address_count = if entry_size > 0 {
            body_size / entry_size
        } else {
            0
        };

        // Parse the addresses
        let mut addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            // Skip segment selector if present
            pos += segment_selector_size as usize;

            let addr = if address_size == 8 {
                if data.len() < pos + 8 {
                    break;
                }
                let a = u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                pos += 8;
                a
            } else {
                if data.len() < pos + 4 {
                    break;
                }
                let a =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                pos += 4;
                a as u64
            };
            addresses.push(addr);
        }

        Ok(Self {
            is_64bit,
            version,
            address_size,
            segment_selector_size,
            addresses,
        })
    }

    /// Look up an address by index.
    pub fn get_address(&self, index: usize) -> Option<u64> {
        self.addresses.get(index).copied()
    }

    /// Returns the number of addresses.
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_section() {
        let data = [];
        assert!(AddressTable::parse(&data, 0).is_err());
    }

    #[test]
    fn test_parse_32bit_table() {
        // Create a minimal 32-bit address table (4-byte addresses)
        // unit_length: 8 (header + 1 address)
        // version: 5
        // address_size: 4
        // segment_selector_size: 0
        // address[0]: 0x1000
        let data = [
            0x08, 0x00, 0x00, 0x00, // unit_length = 8
            0x05, 0x00, // version = 5
            0x04, // address_size = 4
            0x00, // segment_selector_size = 0
            0x00, 0x10, 0x00, 0x00, // address[0] = 0x1000
        ];

        let table = AddressTable::parse(&data, 0).unwrap();
        assert!(!table.is_64bit);
        assert_eq!(table.version, 5);
        assert_eq!(table.address_size, 4);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_address(0), Some(0x1000));
    }

    #[test]
    fn test_parse_64bit_addresses() {
        // 64-bit addresses
        let data = [
            0x0c, 0x00, 0x00, 0x00, // unit_length = 12
            0x05, 0x00, // version = 5
            0x08, // address_size = 8
            0x00, // segment_selector_size = 0
            0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // address[0] = 0x1000
        ];

        let table = AddressTable::parse(&data, 0).unwrap();
        assert_eq!(table.address_size, 8);
        assert_eq!(table.get_address(0), Some(0x1000));
    }

    #[test]
    fn test_multiple_addresses() {
        let data = [
            0x0c, 0x00, 0x00, 0x00, // unit_length = 12
            0x05, 0x00, // version = 5
            0x04, // address_size = 4
            0x00, // segment_selector_size = 0
            0x00, 0x10, 0x00, 0x00, // address[0] = 0x1000
            0x00, 0x20, 0x00, 0x00, // address[1] = 0x2000
        ];

        let table = AddressTable::parse(&data, 0).unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(table.get_address(0), Some(0x1000));
        assert_eq!(table.get_address(1), Some(0x2000));
    }
}
