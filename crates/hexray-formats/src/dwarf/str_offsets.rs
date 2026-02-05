//! DWARF5 .debug_str_offsets section support.
//!
//! The .debug_str_offsets section contains a table of offsets into .debug_str,
//! allowing indirect string references via indices. This is a DWARF5 feature
//! that enables more compact debug info representation.
//!
//! # Section Format (DWARF5)
//!
//! ```text
//! Header:
//!   unit_length: 4 bytes (or 12 for 64-bit DWARF)
//!   version: 2 bytes (must be 5)
//!   padding: 2 bytes
//!
//! Body:
//!   offset[0]: 4/8 bytes (index 0)
//!   offset[1]: 4/8 bytes (index 1)
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

/// Parsed string offsets table from .debug_str_offsets section.
#[derive(Debug, Clone)]
pub struct StringOffsetsTable {
    /// Whether this is 64-bit DWARF format.
    pub is_64bit: bool,
    /// DWARF version (should be 5).
    pub version: u16,
    /// The offsets into .debug_str (one per index).
    offsets: Vec<u64>,
}

impl StringOffsetsTable {
    /// Parse the string offsets table from raw section data.
    ///
    /// # Arguments
    /// * `data` - The .debug_str_offsets section data.
    /// * `offset` - Starting offset within the section (from DW_AT_str_offsets_base).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, ParseError> {
        if data.len() < offset + 4 {
            return Err(truncated(offset + 4, data.len(), "string offsets header"));
        }

        let mut pos = offset;

        // Parse unit length to determine 32/64-bit format
        let initial_length =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;

        let (is_64bit, unit_length) = if initial_length == 0xffff_ffff {
            // 64-bit DWARF
            if data.len() < pos + 8 {
                return Err(truncated(offset + 4, data.len(), "string offsets header"));
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
            return Err(truncated(offset + 4, data.len(), "string offsets header"));
        }
        let version = u16::from_le_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        // Skip padding
        pos += 2;

        if version != 5 {
            return Err(ParseError::UnsupportedVersion {
                format: "DWARF string offsets",
                version: version as u32,
            });
        }

        // Calculate how many offsets we have
        let offset_size = if is_64bit { 8 } else { 4 };
        let body_size = unit_length.saturating_sub(4); // Subtract version + padding
        let offset_count = body_size / offset_size;

        // Parse the offsets
        let mut offsets = Vec::with_capacity(offset_count);
        for _ in 0..offset_count {
            if is_64bit {
                if data.len() < pos + 8 {
                    break;
                }
                let off = u64::from_le_bytes([
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                    data[pos + 4],
                    data[pos + 5],
                    data[pos + 6],
                    data[pos + 7],
                ]);
                offsets.push(off);
                pos += 8;
            } else {
                if data.len() < pos + 4 {
                    break;
                }
                let off =
                    u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                offsets.push(off as u64);
                pos += 4;
            }
        }

        Ok(Self {
            is_64bit,
            version,
            offsets,
        })
    }

    /// Look up a string by index, returning the offset into .debug_str.
    pub fn get_str_offset(&self, index: usize) -> Option<u64> {
        self.offsets.get(index).copied()
    }

    /// Look up a string by index from .debug_str data.
    pub fn get_string<'a>(&self, index: usize, debug_str: &'a [u8]) -> Option<&'a str> {
        let offset = self.get_str_offset(index)? as usize;
        read_null_terminated_str(debug_str, offset)
    }

    /// Returns the number of string offsets.
    pub fn len(&self) -> usize {
        self.offsets.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.offsets.is_empty()
    }
}

/// Read a null-terminated string from a byte slice.
fn read_null_terminated_str(data: &[u8], offset: usize) -> Option<&str> {
    if offset >= data.len() {
        return None;
    }
    let bytes = &data[offset..];
    let end = bytes.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&bytes[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_section() {
        let data = [];
        assert!(StringOffsetsTable::parse(&data, 0).is_err());
    }

    #[test]
    fn test_parse_32bit_table() {
        // Create a minimal 32-bit string offsets table
        // unit_length: 8 (version + padding + 1 offset)
        // version: 5
        // padding: 0
        // offset[0]: 0x42
        let data = [
            0x08, 0x00, 0x00, 0x00, // unit_length = 8
            0x05, 0x00, // version = 5
            0x00, 0x00, // padding
            0x42, 0x00, 0x00, 0x00, // offset[0] = 0x42
        ];

        let table = StringOffsetsTable::parse(&data, 0).unwrap();
        assert!(!table.is_64bit);
        assert_eq!(table.version, 5);
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_str_offset(0), Some(0x42));
    }

    #[test]
    fn test_string_lookup() {
        // String offsets table with one entry pointing to offset 0
        let str_offsets = [
            0x08, 0x00, 0x00, 0x00, // unit_length = 8
            0x05, 0x00, // version = 5
            0x00, 0x00, // padding
            0x00, 0x00, 0x00, 0x00, // offset[0] = 0
        ];

        // .debug_str section with "hello" at offset 0
        let debug_str = b"hello\0world\0";

        let table = StringOffsetsTable::parse(&str_offsets, 0).unwrap();
        assert_eq!(table.get_string(0, debug_str), Some("hello"));
    }
}
