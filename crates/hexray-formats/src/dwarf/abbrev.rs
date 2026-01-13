//! DWARF abbreviation table parsing (.debug_abbrev).
//!
//! The abbreviation table defines the structure of DIEs (Debug Information Entries).
//! Each abbreviation specifies a tag and a list of attribute specifications.

use std::collections::HashMap;

use super::leb128::{decode_sleb128, decode_uleb128};
use super::types::{DwAt, DwForm, DwTag};
use crate::ParseError;

/// An attribute specification in an abbreviation.
#[derive(Debug, Clone)]
pub struct AttributeSpec {
    /// The attribute name (DW_AT_*).
    pub name: DwAt,
    /// The attribute form (DW_FORM_*).
    pub form: DwForm,
    /// Implicit constant value (for DW_FORM_implicit_const).
    pub implicit_const: Option<i64>,
}

/// An abbreviation entry.
#[derive(Debug, Clone)]
pub struct Abbreviation {
    /// The abbreviation code.
    pub code: u64,
    /// The tag for this abbreviation (DW_TAG_*).
    pub tag: DwTag,
    /// Whether DIEs with this abbreviation have children.
    pub has_children: bool,
    /// The attribute specifications.
    pub attributes: Vec<AttributeSpec>,
}

/// A table of abbreviations.
#[derive(Debug, Default)]
pub struct AbbreviationTable {
    /// Map from abbreviation code to abbreviation.
    pub entries: HashMap<u64, Abbreviation>,
}

impl AbbreviationTable {
    /// Parse an abbreviation table from the .debug_abbrev section.
    ///
    /// # Arguments
    /// * `data` - The bytes of the .debug_abbrev section starting at the table offset.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), ParseError> {
        let mut table = AbbreviationTable::default();
        let mut offset = 0;

        loop {
            // Read abbreviation code
            let (code, len) = decode_uleb128(&data[offset..])?;
            offset += len;

            // Code 0 marks end of abbreviation table
            if code == 0 {
                break;
            }

            // Read tag
            let (tag_value, len) = decode_uleb128(&data[offset..])?;
            offset += len;
            let tag = DwTag::from(tag_value as u16);

            // Read children flag
            if offset >= data.len() {
                return Err(ParseError::TruncatedData {
                    expected: offset + 1,
                    actual: data.len(),
                    context: "abbreviation children flag",
                });
            }
            let has_children = data[offset] != 0;
            offset += 1;

            // Read attribute specifications
            let mut attributes = Vec::new();
            loop {
                // Read attribute name
                let (name_value, len) = decode_uleb128(&data[offset..])?;
                offset += len;

                // Read attribute form
                let (form_value, len) = decode_uleb128(&data[offset..])?;
                offset += len;

                // (0, 0) marks end of attribute list
                if name_value == 0 && form_value == 0 {
                    break;
                }

                let name = DwAt::from(name_value as u16);
                let form = DwForm::from(form_value as u8);

                // Handle implicit constant (DWARF 5)
                let implicit_const = if matches!(form, DwForm::ImplicitConst) {
                    let (value, len) = decode_sleb128(&data[offset..])?;
                    offset += len;
                    Some(value)
                } else {
                    None
                };

                attributes.push(AttributeSpec {
                    name,
                    form,
                    implicit_const,
                });
            }

            table.entries.insert(
                code,
                Abbreviation {
                    code,
                    tag,
                    has_children,
                    attributes,
                },
            );
        }

        Ok((table, offset))
    }

    /// Get an abbreviation by code.
    pub fn get(&self, code: u64) -> Option<&Abbreviation> {
        self.entries.get(&code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_table() {
        // Just a terminator
        let data = [0x00];
        let (table, size) = AbbreviationTable::parse(&data).unwrap();
        assert!(table.entries.is_empty());
        assert_eq!(size, 1);
    }

    #[test]
    fn test_parse_simple_abbrev() {
        // Simple abbreviation:
        // code=1, tag=DW_TAG_compile_unit (0x11), children=1
        // DW_AT_name (0x03), DW_FORM_string (0x08)
        // 0, 0 (end attributes)
        // 0 (end table)
        let data = [
            0x01, // code = 1
            0x11, // tag = DW_TAG_compile_unit
            0x01, // has_children = true
            0x03, // DW_AT_name
            0x08, // DW_FORM_string
            0x00, 0x00, // end attributes
            0x00, // end table
        ];

        let (table, _) = AbbreviationTable::parse(&data).unwrap();
        assert_eq!(table.entries.len(), 1);

        let abbrev = table.get(1).unwrap();
        assert_eq!(abbrev.code, 1);
        assert!(matches!(abbrev.tag, DwTag::CompileUnit));
        assert!(abbrev.has_children);
        assert_eq!(abbrev.attributes.len(), 1);
        assert!(matches!(abbrev.attributes[0].name, DwAt::Name));
        assert!(matches!(abbrev.attributes[0].form, DwForm::String));
    }
}
