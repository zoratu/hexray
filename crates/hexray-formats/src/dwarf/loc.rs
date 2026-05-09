//! DWARF4 `.debug_loc` location list support.
//!
//! DWARF versions before 5 encode location lists as a sequence of
//! `(begin, end, expr_len, expr_bytes)` tuples terminated by a zero
//! range. A special base-address-selection entry uses `begin =
//! all-ones` and stores the new base address in `end`.

use super::loclists::LocationEntry;
use crate::ParseError;

fn truncated(expected: usize, actual: usize, context: &'static str) -> ParseError {
    ParseError::TruncatedData {
        expected,
        actual,
        context,
    }
}

/// Parser for DWARF2/3/4 `.debug_loc` location lists.
pub struct DebugLocParser<'a> {
    data: &'a [u8],
    address_size: u8,
}

impl<'a> DebugLocParser<'a> {
    /// Create a new `.debug_loc` parser.
    pub fn new(data: &'a [u8], address_size: u8) -> Self {
        Self { data, address_size }
    }

    /// Parse a location list at `offset`.
    pub fn parse_location_list(&self, offset: usize) -> Result<Vec<LocationEntry>, ParseError> {
        let mut locations = Vec::new();
        let mut pos = offset;
        let mut current_base: Option<u64> = None;
        let base_selector = if self.address_size == 8 {
            u64::MAX
        } else {
            u32::MAX as u64
        };

        loop {
            let begin = self.read_address(&mut pos)?;
            let end = self.read_address(&mut pos)?;

            if begin == 0 && end == 0 {
                break;
            }

            if begin == base_selector {
                current_base = Some(end);
                continue;
            }

            let expr_len = self.read_u16(&mut pos)? as usize;
            let expr_end = pos
                .checked_add(expr_len)
                .ok_or(ParseError::InvalidValue("debug_loc expression overflow"))?;
            let expr = self
                .data
                .get(pos..expr_end)
                .ok_or_else(|| truncated(expr_end, self.data.len(), "debug_loc expression"))?
                .to_vec();
            pos = expr_end;

            let (start, finish) = if let Some(base) = current_base {
                (base.wrapping_add(begin), base.wrapping_add(end))
            } else {
                (begin, end)
            };
            locations.push(LocationEntry::new(start, finish, expr));
        }

        Ok(locations)
    }

    fn read_u16(&self, pos: &mut usize) -> Result<u16, ParseError> {
        let end = pos
            .checked_add(2)
            .ok_or(ParseError::InvalidValue("debug_loc position overflow"))?;
        let bytes = self
            .data
            .get(*pos..end)
            .ok_or_else(|| truncated(end, self.data.len(), "debug_loc"))?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| truncated(end, self.data.len(), "debug_loc"))?;
        *pos = end;
        Ok(u16::from_le_bytes(arr))
    }

    fn read_address(&self, pos: &mut usize) -> Result<u64, ParseError> {
        if self.address_size == 8 {
            let end = pos
                .checked_add(8)
                .ok_or(ParseError::InvalidValue("debug_loc position overflow"))?;
            let bytes = self
                .data
                .get(*pos..end)
                .ok_or_else(|| truncated(end, self.data.len(), "debug_loc"))?;
            let arr: [u8; 8] = bytes
                .try_into()
                .map_err(|_| truncated(end, self.data.len(), "debug_loc"))?;
            *pos = end;
            Ok(u64::from_le_bytes(arr))
        } else {
            let end = pos
                .checked_add(4)
                .ok_or(ParseError::InvalidValue("debug_loc position overflow"))?;
            let bytes = self
                .data
                .get(*pos..end)
                .ok_or_else(|| truncated(end, self.data.len(), "debug_loc"))?;
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| truncated(end, self.data.len(), "debug_loc"))?;
            *pos = end;
            Ok(u32::from_le_bytes(arr) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_64bit_loclist() {
        let data = [
            0x80, 0x11, 0, 0, 0, 0, 0, 0, // begin = 0x1180
            0x86, 0x11, 0, 0, 0, 0, 0, 0, // end = 0x1186
            0x01, 0x00, // expr len = 1
            0x55, // DW_OP_reg5
            0, 0, 0, 0, 0, 0, 0, 0, // end marker begin
            0, 0, 0, 0, 0, 0, 0, 0, // end marker end
        ];
        let parser = DebugLocParser::new(&data, 8);
        let locations = parser.parse_location_list(0).unwrap();

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].start, Some(0x1180));
        assert_eq!(locations[0].end, Some(0x1186));
        assert_eq!(locations[0].expression, vec![0x55]);
    }

    #[test]
    fn test_parse_base_address_selection() {
        let data = [
            0xff, 0xff, 0xff, 0xff, // base selector
            0x00, 0x10, 0x00, 0x00, // base = 0x1000
            0x10, 0x00, 0x00, 0x00, // start offset = 0x10
            0x20, 0x00, 0x00, 0x00, // end offset = 0x20
            0x01, 0x00, // expr len = 1
            0x54, // DW_OP_reg4
            0, 0, 0, 0, // end marker begin
            0, 0, 0, 0, // end marker end
        ];
        let parser = DebugLocParser::new(&data, 4);
        let locations = parser.parse_location_list(0).unwrap();

        assert_eq!(locations.len(), 1);
        assert_eq!(locations[0].start, Some(0x1010));
        assert_eq!(locations[0].end, Some(0x1020));
        assert_eq!(locations[0].expression, vec![0x54]);
    }
}
