//! LEB128 (Little Endian Base 128) encoding/decoding.
//!
//! DWARF uses LEB128 for variable-length integers. This encoding uses
//! 7 bits per byte, with the high bit indicating continuation.

use crate::ParseError;

/// Decode an unsigned LEB128 value from bytes.
/// Returns the value and the number of bytes consumed.
pub fn decode_uleb128(data: &[u8]) -> Result<(u64, usize), ParseError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    let mut index = 0;

    loop {
        if index >= data.len() {
            return Err(ParseError::TruncatedData {
                expected: index + 1,
                actual: data.len(),
                context: "ULEB128 value",
            });
        }

        let byte = data[index];
        index += 1;

        // Extract 7 bits and add to result
        let low_bits = (byte & 0x7F) as u64;

        // Check for overflow
        if shift >= 64 || (shift == 63 && low_bits > 1) {
            return Err(ParseError::InvalidValue("ULEB128 overflow"));
        }

        result |= low_bits << shift;
        shift += 7;

        // High bit clear means this is the last byte
        if byte & 0x80 == 0 {
            break;
        }
    }

    Ok((result, index))
}

/// Decode a signed LEB128 value from bytes.
/// Returns the value and the number of bytes consumed.
#[allow(unused_assignments)]
pub fn decode_sleb128(data: &[u8]) -> Result<(i64, usize), ParseError> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut index = 0;
    let mut last_byte = 0u8;

    loop {
        if index >= data.len() {
            return Err(ParseError::TruncatedData {
                expected: index + 1,
                actual: data.len(),
                context: "SLEB128 value",
            });
        }

        let byte = data[index];
        last_byte = byte;
        index += 1;

        // Extract 7 bits and add to result
        let low_bits = (byte & 0x7F) as i64;
        result |= low_bits << shift;
        shift += 7;

        // High bit clear means this is the last byte
        if byte & 0x80 == 0 {
            break;
        }

        // Check for overflow
        if shift >= 64 {
            return Err(ParseError::InvalidValue("SLEB128 overflow"));
        }
    }

    // Sign extend if the sign bit (bit 6 of last byte) is set
    if shift < 64 && (last_byte & 0x40) != 0 {
        result |= !0i64 << shift;
    }

    Ok((result, index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128_single_byte() {
        // Values 0-127 fit in a single byte
        assert_eq!(decode_uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_uleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_uleb128(&[0x7F]).unwrap(), (127, 1));
    }

    #[test]
    fn test_uleb128_multi_byte() {
        // 128 = 0x80 + 0x01
        assert_eq!(decode_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        // 624485 = 0xE5 0x8E 0x26
        assert_eq!(decode_uleb128(&[0xE5, 0x8E, 0x26]).unwrap(), (624485, 3));
    }

    #[test]
    fn test_sleb128_positive() {
        assert_eq!(decode_sleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_sleb128(&[0x01]).unwrap(), (1, 1));
        assert_eq!(decode_sleb128(&[0x3F]).unwrap(), (63, 1));
    }

    #[test]
    fn test_sleb128_negative() {
        // -1 = 0x7F
        assert_eq!(decode_sleb128(&[0x7F]).unwrap(), (-1, 1));
        // -123456 = 0xC0 0xBB 0x78
        assert_eq!(decode_sleb128(&[0xC0, 0xBB, 0x78]).unwrap(), (-123456, 3));
    }
}
