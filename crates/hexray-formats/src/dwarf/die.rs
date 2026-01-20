//! DWARF Debug Information Entry (DIE) parsing.
//!
//! DIEs are the fundamental units of DWARF information. Each DIE describes
//! a programming language entity (function, variable, type, etc.).

use super::abbrev::{AbbreviationTable, AttributeSpec};
use super::leb128::{decode_sleb128, decode_uleb128};
use super::types::{DwAt, DwForm, DwTag};
use crate::ParseError;

/// An attribute value.
#[derive(Debug, Clone)]
pub enum AttributeValue {
    /// An address value.
    Address(u64),
    /// A block of bytes.
    Block(Vec<u8>),
    /// Unsigned constant.
    Unsigned(u64),
    /// Signed constant.
    Signed(i64),
    /// A string value.
    String(String),
    /// An offset into .debug_str.
    StringOffset(u64),
    /// A flag (boolean).
    Flag(bool),
    /// A reference to another DIE (offset from start of compilation unit).
    Reference(u64),
    /// A reference to another DIE (offset from start of .debug_info).
    RefAddr(u64),
    /// An offset into another section.
    SecOffset(u64),
    /// An expression location.
    ExprLoc(Vec<u8>),
    /// An index into .debug_str_offsets.
    StringIndex(u64),
    /// An index into .debug_addr.
    AddressIndex(u64),
    /// A 16-byte value.
    Data16([u8; 16]),
    /// An 8-byte type signature.
    RefSig8(u64),
}

/// A single attribute of a DIE.
#[derive(Debug, Clone)]
pub struct Attribute {
    /// The attribute name.
    pub name: DwAt,
    /// The attribute value.
    pub value: AttributeValue,
}

/// A Debug Information Entry.
#[derive(Debug, Clone)]
pub struct Die {
    /// Offset of this DIE from the start of the compilation unit.
    pub offset: u64,
    /// The tag indicating what this DIE represents.
    pub tag: DwTag,
    /// Whether this DIE has children.
    pub has_children: bool,
    /// The attributes of this DIE.
    pub attributes: Vec<Attribute>,
    /// Child DIEs (if any).
    pub children: Vec<Die>,
}

impl Die {
    /// Get an attribute by name.
    pub fn attr(&self, name: DwAt) -> Option<&AttributeValue> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| &a.value)
    }

    /// Get the name attribute as a string.
    pub fn name(&self) -> Option<&str> {
        match self.attr(DwAt::Name)? {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the low PC (start address) of this DIE.
    pub fn low_pc(&self) -> Option<u64> {
        match self.attr(DwAt::LowPc)? {
            AttributeValue::Address(addr) => Some(*addr),
            AttributeValue::Unsigned(val) => Some(*val),
            _ => None,
        }
    }

    /// Get the high PC (end address or size) of this DIE.
    pub fn high_pc(&self) -> Option<u64> {
        match self.attr(DwAt::HighPc)? {
            AttributeValue::Address(addr) => Some(*addr),
            AttributeValue::Unsigned(val) => Some(*val),
            _ => None,
        }
    }

    /// Get the declaration file index.
    pub fn decl_file(&self) -> Option<u64> {
        match self.attr(DwAt::DeclFile)? {
            AttributeValue::Unsigned(val) => Some(*val),
            _ => None,
        }
    }

    /// Get the declaration line number.
    pub fn decl_line(&self) -> Option<u64> {
        match self.attr(DwAt::DeclLine)? {
            AttributeValue::Unsigned(val) => Some(*val),
            _ => None,
        }
    }

    /// Get the type reference.
    pub fn type_ref(&self) -> Option<u64> {
        match self.attr(DwAt::Type)? {
            AttributeValue::Reference(offset) => Some(*offset),
            AttributeValue::RefAddr(offset) => Some(*offset),
            _ => None,
        }
    }

    /// Get the variable location as a frame-base offset, if applicable.
    ///
    /// This parses the DW_AT_location attribute and extracts the offset
    /// for variables stored relative to the frame base (DW_OP_fbreg).
    /// Returns None if the variable has a more complex location expression.
    pub fn frame_base_offset(&self) -> Option<i64> {
        let loc_data = match self.attr(DwAt::Location)? {
            AttributeValue::ExprLoc(data) => data,
            AttributeValue::Block(data) => data,
            _ => return None,
        };

        // Parse simple DW_OP_fbreg expressions
        // DW_OP_fbreg (0x91) followed by a SLEB128 offset
        if loc_data.is_empty() {
            return None;
        }

        if loc_data[0] == 0x91 {
            // DW_OP_fbreg
            let (offset, _) = decode_sleb128(&loc_data[1..]).ok()?;
            return Some(offset);
        }

        // Also handle DW_OP_breg6 (rbp-relative on x86_64)
        // DW_OP_breg6 = 0x76 (base register 6 = rbp on x86_64)
        if loc_data[0] == 0x76 {
            let (offset, _) = decode_sleb128(&loc_data[1..]).ok()?;
            return Some(offset);
        }

        // DW_OP_breg29 (x29/fp-relative on ARM64)
        // DW_OP_breg<n> = 0x70 + n, so breg29 = 0x70 + 29 = 0x8d
        if loc_data[0] == 0x8d {
            let (offset, _) = decode_sleb128(&loc_data[1..]).ok()?;
            return Some(offset);
        }

        // DW_OP_breg31 (sp-relative on ARM64)
        // breg31 = 0x70 + 31 = 0x8f
        if loc_data[0] == 0x8f {
            let (offset, _) = decode_sleb128(&loc_data[1..]).ok()?;
            return Some(offset);
        }

        None
    }

    /// Check if this DIE represents a parameter.
    pub fn is_parameter(&self) -> bool {
        matches!(self.tag, DwTag::FormalParameter)
    }

    /// Check if this DIE represents a local variable.
    pub fn is_variable(&self) -> bool {
        matches!(self.tag, DwTag::Variable)
    }
}

/// Context for parsing DIEs.
pub struct DieParser<'a> {
    /// The raw .debug_info data.
    data: &'a [u8],
    /// The abbreviation table for this compilation unit.
    abbrev_table: &'a AbbreviationTable,
    /// Address size for this compilation unit.
    address_size: u8,
    /// Whether this is 64-bit DWARF.
    is_64bit: bool,
    /// Current offset within the compilation unit.
    offset: usize,
    /// Base offset of the compilation unit in .debug_info.
    cu_offset: usize,
}

impl<'a> DieParser<'a> {
    /// Create a new DIE parser.
    pub fn new(
        data: &'a [u8],
        abbrev_table: &'a AbbreviationTable,
        address_size: u8,
        is_64bit: bool,
        cu_offset: usize,
        die_offset: usize,
    ) -> Self {
        Self {
            data,
            abbrev_table,
            address_size,
            is_64bit,
            offset: die_offset,
            cu_offset,
        }
    }

    /// Parse a single DIE and its children.
    pub fn parse_die(&mut self) -> Result<Option<Die>, ParseError> {
        let die_offset = self.offset - self.cu_offset;

        // Read abbreviation code
        let (abbrev_code, len) = decode_uleb128(&self.data[self.offset..])?;
        self.offset += len;

        // Code 0 means null entry (end of siblings)
        if abbrev_code == 0 {
            return Ok(None);
        }

        // Look up abbreviation
        let abbrev = self
            .abbrev_table
            .get(abbrev_code)
            .ok_or(ParseError::InvalidValue("unknown abbreviation code"))?;

        // Parse attributes
        let mut attributes = Vec::with_capacity(abbrev.attributes.len());
        for attr_spec in &abbrev.attributes {
            let value = self.parse_attribute_value(attr_spec)?;
            attributes.push(Attribute {
                name: attr_spec.name,
                value,
            });
        }

        // Parse children if present
        let children = if abbrev.has_children {
            self.parse_children()?
        } else {
            Vec::new()
        };

        Ok(Some(Die {
            offset: die_offset as u64,
            tag: abbrev.tag,
            has_children: abbrev.has_children,
            attributes,
            children,
        }))
    }

    /// Parse all sibling DIEs until null entry.
    fn parse_children(&mut self) -> Result<Vec<Die>, ParseError> {
        let mut children = Vec::new();
        while let Some(die) = self.parse_die()? {
            children.push(die);
        }
        Ok(children)
    }

    /// Parse an attribute value based on its form.
    fn parse_attribute_value(
        &mut self,
        spec: &AttributeSpec,
    ) -> Result<AttributeValue, ParseError> {
        match spec.form {
            DwForm::Addr => {
                let value = self.read_address()?;
                Ok(AttributeValue::Address(value))
            }
            DwForm::Block1 => {
                let len = self.read_u8()? as usize;
                let block = self.read_bytes(len)?;
                Ok(AttributeValue::Block(block))
            }
            DwForm::Block2 => {
                let len = self.read_u16()? as usize;
                let block = self.read_bytes(len)?;
                Ok(AttributeValue::Block(block))
            }
            DwForm::Block4 => {
                let len = self.read_u32()? as usize;
                let block = self.read_bytes(len)?;
                Ok(AttributeValue::Block(block))
            }
            DwForm::Block => {
                let (len, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                let block = self.read_bytes(len as usize)?;
                Ok(AttributeValue::Block(block))
            }
            DwForm::Data1 => {
                let value = self.read_u8()? as u64;
                Ok(AttributeValue::Unsigned(value))
            }
            DwForm::Data2 => {
                let value = self.read_u16()? as u64;
                Ok(AttributeValue::Unsigned(value))
            }
            DwForm::Data4 => {
                let value = self.read_u32()? as u64;
                Ok(AttributeValue::Unsigned(value))
            }
            DwForm::Data8 => {
                let value = self.read_u64()?;
                Ok(AttributeValue::Unsigned(value))
            }
            DwForm::Data16 => {
                let mut data = [0u8; 16];
                if self.offset + 16 > self.data.len() {
                    return Err(ParseError::TruncatedData {
                        expected: self.offset + 16,
                        actual: self.data.len(),
                        context: "DW_FORM_data16",
                    });
                }
                data.copy_from_slice(&self.data[self.offset..self.offset + 16]);
                self.offset += 16;
                Ok(AttributeValue::Data16(data))
            }
            DwForm::String => {
                let s = self.read_string()?;
                Ok(AttributeValue::String(s))
            }
            DwForm::Strp | DwForm::LineStrp => {
                let offset = self.read_offset()?;
                Ok(AttributeValue::StringOffset(offset))
            }
            DwForm::Udata => {
                let (value, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                Ok(AttributeValue::Unsigned(value))
            }
            DwForm::Sdata => {
                let (value, consumed) = decode_sleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                Ok(AttributeValue::Signed(value))
            }
            DwForm::Flag => {
                let value = self.read_u8()?;
                Ok(AttributeValue::Flag(value != 0))
            }
            DwForm::FlagPresent => Ok(AttributeValue::Flag(true)),
            DwForm::Ref1 => {
                let offset = self.read_u8()? as u64;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::Ref2 => {
                let offset = self.read_u16()? as u64;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::Ref4 => {
                let offset = self.read_u32()? as u64;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::Ref8 => {
                let offset = self.read_u64()?;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::RefUdata => {
                let (offset, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::RefAddr => {
                let offset = self.read_offset()?;
                Ok(AttributeValue::RefAddr(offset))
            }
            DwForm::RefSig8 => {
                let sig = self.read_u64()?;
                Ok(AttributeValue::RefSig8(sig))
            }
            DwForm::SecOffset => {
                let offset = self.read_offset()?;
                Ok(AttributeValue::SecOffset(offset))
            }
            DwForm::Exprloc => {
                let (len, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                let block = self.read_bytes(len as usize)?;
                Ok(AttributeValue::ExprLoc(block))
            }
            DwForm::Strx | DwForm::Strx1 | DwForm::Strx2 | DwForm::Strx3 | DwForm::Strx4 => {
                let index = match spec.form {
                    DwForm::Strx1 => self.read_u8()? as u64,
                    DwForm::Strx2 => self.read_u16()? as u64,
                    DwForm::Strx3 => {
                        let b0 = self.read_u8()? as u64;
                        let b1 = self.read_u8()? as u64;
                        let b2 = self.read_u8()? as u64;
                        b0 | (b1 << 8) | (b2 << 16)
                    }
                    DwForm::Strx4 => self.read_u32()? as u64,
                    _ => {
                        let (val, consumed) = decode_uleb128(&self.data[self.offset..])?;
                        self.offset += consumed;
                        val
                    }
                };
                Ok(AttributeValue::StringIndex(index))
            }
            DwForm::Addrx | DwForm::Addrx1 | DwForm::Addrx2 | DwForm::Addrx3 | DwForm::Addrx4 => {
                let index = match spec.form {
                    DwForm::Addrx1 => self.read_u8()? as u64,
                    DwForm::Addrx2 => self.read_u16()? as u64,
                    DwForm::Addrx3 => {
                        let b0 = self.read_u8()? as u64;
                        let b1 = self.read_u8()? as u64;
                        let b2 = self.read_u8()? as u64;
                        b0 | (b1 << 8) | (b2 << 16)
                    }
                    DwForm::Addrx4 => self.read_u32()? as u64,
                    _ => {
                        let (val, consumed) = decode_uleb128(&self.data[self.offset..])?;
                        self.offset += consumed;
                        val
                    }
                };
                Ok(AttributeValue::AddressIndex(index))
            }
            DwForm::ImplicitConst => {
                let value = spec
                    .implicit_const
                    .ok_or(ParseError::InvalidValue("missing implicit constant value"))?;
                Ok(AttributeValue::Signed(value))
            }
            DwForm::Indirect => {
                // Read the actual form
                let (form_value, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                let actual_spec = AttributeSpec {
                    name: spec.name,
                    form: DwForm::from(form_value as u8),
                    implicit_const: None,
                };
                self.parse_attribute_value(&actual_spec)
            }
            DwForm::Loclistx | DwForm::Rnglistx => {
                let (index, consumed) = decode_uleb128(&self.data[self.offset..])?;
                self.offset += consumed;
                Ok(AttributeValue::SecOffset(index))
            }
            DwForm::RefSup4 => {
                let offset = self.read_u32()? as u64;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::RefSup8 => {
                let offset = self.read_u64()?;
                Ok(AttributeValue::Reference(offset))
            }
            DwForm::StrpSup => {
                let offset = self.read_offset()?;
                Ok(AttributeValue::StringOffset(offset))
            }
            DwForm::Unknown(_) => Err(ParseError::InvalidValue("unknown DWARF form")),
        }
    }

    fn read_u8(&mut self) -> Result<u8, ParseError> {
        if self.offset >= self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + 1,
                actual: self.data.len(),
                context: "u8",
            });
        }
        let value = self.data[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ParseError> {
        if self.offset + 2 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + 2,
                actual: self.data.len(),
                context: "u16",
            });
        }
        let value = u16::from_le_bytes([self.data[self.offset], self.data[self.offset + 1]]);
        self.offset += 2;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, ParseError> {
        if self.offset + 4 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + 4,
                actual: self.data.len(),
                context: "u32",
            });
        }
        let value = u32::from_le_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(value)
    }

    fn read_u64(&mut self) -> Result<u64, ParseError> {
        if self.offset + 8 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + 8,
                actual: self.data.len(),
                context: "u64",
            });
        }
        let value = u64::from_le_bytes([
            self.data[self.offset],
            self.data[self.offset + 1],
            self.data[self.offset + 2],
            self.data[self.offset + 3],
            self.data[self.offset + 4],
            self.data[self.offset + 5],
            self.data[self.offset + 6],
            self.data[self.offset + 7],
        ]);
        self.offset += 8;
        Ok(value)
    }

    fn read_address(&mut self) -> Result<u64, ParseError> {
        match self.address_size {
            4 => Ok(self.read_u32()? as u64),
            8 => self.read_u64(),
            _ => Err(ParseError::InvalidValue("unsupported address size")),
        }
    }

    fn read_offset(&mut self) -> Result<u64, ParseError> {
        if self.is_64bit {
            self.read_u64()
        } else {
            Ok(self.read_u32()? as u64)
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, ParseError> {
        if self.offset + len > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + len,
                actual: self.data.len(),
                context: "byte block",
            });
        }
        let bytes = self.data[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(bytes)
    }

    fn read_string(&mut self) -> Result<String, ParseError> {
        let start = self.offset;
        while self.offset < self.data.len() && self.data[self.offset] != 0 {
            self.offset += 1;
        }
        if self.offset >= self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: self.offset + 1,
                actual: self.data.len(),
                context: "null-terminated string",
            });
        }
        let s = String::from_utf8_lossy(&self.data[start..self.offset]).into_owned();
        self.offset += 1; // Skip null terminator
        Ok(s)
    }
}
