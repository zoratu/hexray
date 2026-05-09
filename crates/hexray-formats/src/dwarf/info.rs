//!
//! This module parses the .debug_info section which contains the main debugging
//! information organized into compilation units.

use super::abbrev::AbbreviationTable;
use super::addr_table::AddressTable;
use super::die::{AttributeValue, Die, DieParser};
use super::str_offsets::StringOffsetsTable;
use super::types::DwLang;
use super::DwAt;
use crate::ParseError;

// Bounds-checked little-endian readers used by the CU header parser.
#[inline]
fn read_le2(data: &[u8], at: usize) -> u16 {
    let end = at.saturating_add(2);
    let arr: [u8; 2] = data
        .get(at..end)
        .unwrap_or(&[0; 2])
        .try_into()
        .unwrap_or_default();
    u16::from_le_bytes(arr)
}

#[inline]
fn read_le4(data: &[u8], at: usize) -> u32 {
    let end = at.saturating_add(4);
    let arr: [u8; 4] = data
        .get(at..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    u32::from_le_bytes(arr)
}

#[inline]
fn read_le8(data: &[u8], at: usize) -> u64 {
    let end = at.saturating_add(8);
    let arr: [u8; 8] = data
        .get(at..end)
        .unwrap_or(&[0; 8])
        .try_into()
        .unwrap_or_default();
    u64::from_le_bytes(arr)
}

/// A DWARF compilation unit header.
#[derive(Debug, Clone)]
pub struct CompilationUnitHeader {
    /// Unit length (excluding the length field itself).
    pub unit_length: u64,
    /// DWARF version.
    pub version: u16,
    /// Unit type (DWARF 5).
    pub unit_type: u8,
    /// Address size in bytes.
    pub address_size: u8,
    /// Offset into .debug_abbrev section.
    pub debug_abbrev_offset: u64,
    /// Whether this is 64-bit DWARF.
    pub is_64bit: bool,
    /// Offset of this CU in .debug_info.
    pub offset: u64,
}

/// A parsed compilation unit.
#[derive(Debug)]
pub struct CompilationUnit {
    /// The compilation unit header.
    pub header: CompilationUnitHeader,
    /// The root DIE of this compilation unit.
    pub root_die: Die,
}

impl CompilationUnit {
    /// Get the name of the compilation unit (source file).
    pub fn name(&self) -> Option<&str> {
        self.root_die.name()
    }

    /// Get the compilation directory.
    pub fn comp_dir(&self) -> Option<&str> {
        use super::die::AttributeValue;
        use super::types::DwAt;
        match self.root_die.attr(DwAt::CompDir)? {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the producer (compiler) string.
    pub fn producer(&self) -> Option<&str> {
        use super::die::AttributeValue;
        use super::types::DwAt;
        match self.root_die.attr(DwAt::Producer)? {
            AttributeValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get the source language.
    pub fn language(&self) -> Option<DwLang> {
        use super::die::AttributeValue;
        use super::types::DwAt;
        match self.root_die.attr(DwAt::Language)? {
            AttributeValue::Unsigned(val) => Some(DwLang::from(*val as u16)),
            _ => None,
        }
    }

    /// Get the low PC (start address) of this compilation unit.
    pub fn low_pc(&self) -> Option<u64> {
        self.root_die.low_pc()
    }

    /// Get the high PC (end address) of this compilation unit.
    pub fn high_pc(&self) -> Option<u64> {
        self.root_die.high_pc()
    }

    /// Get the offset into .debug_line for line number info.
    pub fn stmt_list(&self) -> Option<u64> {
        use super::die::AttributeValue;
        use super::types::DwAt;
        match self.root_die.attr(DwAt::StmtList)? {
            AttributeValue::SecOffset(offset) => Some(*offset),
            AttributeValue::Unsigned(offset) => Some(*offset),
            _ => None,
        }
    }

    /// Find a subprogram (function) DIE by address.
    pub fn find_subprogram(&self, address: u64) -> Option<&Die> {
        Self::find_subprogram_in(&self.root_die, address)
    }

    fn find_subprogram_in(die: &Die, address: u64) -> Option<&Die> {
        use super::die::AttributeValue;
        use super::types::DwAt;
        use super::types::DwTag;

        // Check if this DIE is a subprogram containing the address
        if matches!(die.tag, DwTag::Subprogram | DwTag::InlinedSubroutine) {
            if let (Some(low_pc), Some(high_pc_val)) = (die.low_pc(), die.attr(DwAt::HighPc)) {
                let high_pc = match high_pc_val {
                    // High PC can be an address or a size offset
                    AttributeValue::Address(addr) => *addr,
                    AttributeValue::Unsigned(size) => low_pc.saturating_add(*size),
                    _ => return None,
                };
                if address >= low_pc && address < high_pc {
                    return Some(die);
                }
            }
        }

        // Search children
        for child in &die.children {
            if let Some(found) = Self::find_subprogram_in(child, address) {
                return Some(found);
            }
        }

        None
    }

    /// Find a variable DIE by name within a subprogram.
    pub fn find_variable<'a>(&'a self, subprogram: &'a Die, name: &str) -> Option<&'a Die> {
        Self::find_variable_in(subprogram, name)
    }

    fn find_variable_in<'a>(die: &'a Die, name: &str) -> Option<&'a Die> {
        use super::types::DwTag;

        if matches!(die.tag, DwTag::Variable | DwTag::FormalParameter) && die.name() == Some(name) {
            return Some(die);
        }

        for child in &die.children {
            if let Some(found) = Self::find_variable_in(child, name) {
                return Some(found);
            }
        }

        None
    }

    /// Iterate over all subprograms in this compilation unit.
    pub fn subprograms(&self) -> impl Iterator<Item = &Die> {
        SubprogramIterator::new(&self.root_die)
    }

    /// Iterate over all variables in a DIE and its children.
    pub fn variables<'a>(&'a self, die: &'a Die) -> impl Iterator<Item = &'a Die> {
        VariableIterator::new(die)
    }

    /// Find a DIE by its offset from the start of the compilation unit.
    pub fn find_die_by_offset(&self, offset: u64) -> Option<&Die> {
        Self::find_die_by_offset_in(&self.root_die, offset)
    }

    fn find_die_by_offset_in(die: &Die, offset: u64) -> Option<&Die> {
        if die.offset == offset {
            return Some(die);
        }

        for child in &die.children {
            if let Some(found) = Self::find_die_by_offset_in(child, offset) {
                return Some(found);
            }
        }

        None
    }
}

/// Iterator over subprograms in a DIE tree.
struct SubprogramIterator<'a> {
    stack: Vec<&'a Die>,
}

impl<'a> SubprogramIterator<'a> {
    fn new(root: &'a Die) -> Self {
        Self { stack: vec![root] }
    }
}

impl<'a> Iterator for SubprogramIterator<'a> {
    type Item = &'a Die;

    fn next(&mut self) -> Option<Self::Item> {
        use super::types::DwTag;

        while let Some(die) = self.stack.pop() {
            // Add children to stack
            for child in die.children.iter().rev() {
                self.stack.push(child);
            }

            // Return if this is a subprogram
            if matches!(die.tag, DwTag::Subprogram) {
                return Some(die);
            }
        }
        None
    }
}

/// Iterator over variables in a DIE tree.
struct VariableIterator<'a> {
    stack: Vec<&'a Die>,
}

impl<'a> VariableIterator<'a> {
    fn new(root: &'a Die) -> Self {
        Self { stack: vec![root] }
    }
}

impl<'a> Iterator for VariableIterator<'a> {
    type Item = &'a Die;

    fn next(&mut self) -> Option<Self::Item> {
        use super::types::DwTag;

        while let Some(die) = self.stack.pop() {
            // Add children to stack
            for child in die.children.iter().rev() {
                self.stack.push(child);
            }

            // Return if this is a variable or parameter
            if matches!(die.tag, DwTag::Variable | DwTag::FormalParameter) {
                return Some(die);
            }
        }
        None
    }
}

/// Parser for the .debug_info section.
pub struct DebugInfoParser<'a> {
    /// The raw .debug_info data.
    debug_info: &'a [u8],
    /// The raw .debug_abbrev data.
    debug_abbrev: &'a [u8],
    /// The raw .debug_str data (for string references).
    debug_str: Option<&'a [u8]>,
    /// Optional DWARF5 string-offsets section.
    debug_str_offsets: Option<&'a [u8]>,
    /// Optional DWARF5 address table section.
    debug_addr: Option<&'a [u8]>,
}

impl<'a> DebugInfoParser<'a> {
    /// Create a new debug info parser.
    pub fn new(debug_info: &'a [u8], debug_abbrev: &'a [u8], debug_str: Option<&'a [u8]>) -> Self {
        Self::with_tables(debug_info, debug_abbrev, debug_str, None, None)
    }

    /// Create a new debug info parser with optional DWARF5 tables.
    pub fn with_tables(
        debug_info: &'a [u8],
        debug_abbrev: &'a [u8],
        debug_str: Option<&'a [u8]>,
        debug_str_offsets: Option<&'a [u8]>,
        debug_addr: Option<&'a [u8]>,
    ) -> Self {
        Self {
            debug_info,
            debug_abbrev,
            debug_str,
            debug_str_offsets,
            debug_addr,
        }
    }

    /// Parse all compilation units in the .debug_info section.
    pub fn parse_all(&self) -> Result<Vec<CompilationUnit>, ParseError> {
        let mut units = Vec::new();
        let mut offset = 0;

        while offset < self.debug_info.len() {
            let (unit, next_offset) = self.parse_compilation_unit(offset)?;
            units.push(unit);
            offset = next_offset;
        }

        Ok(units)
    }

    /// Parse a single compilation unit at the given offset.
    fn parse_compilation_unit(
        &self,
        offset: usize,
    ) -> Result<(CompilationUnit, usize), ParseError> {
        let data = self
            .debug_info
            .get(offset..)
            .ok_or(ParseError::TruncatedData {
                expected: offset,
                actual: self.debug_info.len(),
                context: "compilation unit header",
            })?;

        // Parse unit length
        let (unit_length, is_64bit) = if data.len() < 4 {
            return Err(ParseError::TruncatedData {
                expected: 4,
                actual: data.len(),
                context: "compilation unit header",
            });
        } else {
            let first_word = read_le4(data, 0);
            if first_word == 0xFFFFFFFF {
                // 64-bit DWARF
                if data.len() < 12 {
                    return Err(ParseError::TruncatedData {
                        expected: 12,
                        actual: data.len(),
                        context: "64-bit compilation unit header",
                    });
                }
                (read_le8(data, 4), true)
            } else {
                (first_word as u64, false)
            }
        };

        let header_offset: usize = if is_64bit { 12 } else { 4 };
        let mut local_offset = header_offset;

        // Parse version
        let version = read_le2(data, local_offset);
        local_offset = local_offset.saturating_add(2);

        // DWARF 5 has unit_type before address_size
        let (unit_type, address_size, debug_abbrev_offset) = if version >= 5 {
            let unit_type = data.get(local_offset).copied().unwrap_or(0);
            local_offset = local_offset.saturating_add(1);
            let address_size = data.get(local_offset).copied().unwrap_or(0);
            local_offset = local_offset.saturating_add(1);
            let abbrev_offset = if is_64bit {
                let off = read_le8(data, local_offset);
                local_offset = local_offset.saturating_add(8);
                off
            } else {
                let off = read_le4(data, local_offset) as u64;
                local_offset = local_offset.saturating_add(4);
                off
            };
            (unit_type, address_size, abbrev_offset)
        } else {
            // DWARF 2/3/4
            let abbrev_offset = if is_64bit {
                let off = read_le8(data, local_offset);
                local_offset = local_offset.saturating_add(8);
                off
            } else {
                let off = read_le4(data, local_offset) as u64;
                local_offset = local_offset.saturating_add(4);
                off
            };
            let address_size = data.get(local_offset).copied().unwrap_or(0);
            local_offset = local_offset.saturating_add(1);
            (0x01, address_size, abbrev_offset) // 0x01 = DW_UT_compile
        };

        // DWARF5 skeleton and split-compile units carry an 8-byte
        // DWO ID between the fixed header and the root DIE.
        if version >= 5 && matches!(unit_type, 0x04 | 0x05) {
            local_offset = local_offset.saturating_add(8);
        }

        let header = CompilationUnitHeader {
            unit_length,
            version,
            unit_type,
            address_size,
            debug_abbrev_offset,
            is_64bit,
            offset: offset as u64,
        };

        // Parse abbreviation table
        let abbrev_data = self
            .debug_abbrev
            .get(debug_abbrev_offset as usize..)
            .ok_or(ParseError::TruncatedData {
                expected: debug_abbrev_offset as usize,
                actual: self.debug_abbrev.len(),
                context: "abbrev offset",
            })?;
        let (abbrev_table, _) = AbbreviationTable::parse(abbrev_data)?;

        // Calculate the end of this compilation unit
        let cu_end = offset
            .saturating_add(header_offset)
            .saturating_add(unit_length as usize);

        // Parse the root DIE
        let die_start = offset.saturating_add(local_offset);
        let mut parser = DieParser::new(
            self.debug_info,
            &abbrev_table,
            address_size,
            is_64bit,
            offset,
            die_start,
        );

        let mut root_die = parser.parse_die()?.ok_or(ParseError::InvalidValue(
            "missing root DIE in compilation unit",
        ))?;
        self.resolve_unit_references(&mut root_die);

        Ok((CompilationUnit { header, root_die }, cu_end))
    }

    fn resolve_unit_references(&self, die: &mut Die) {
        let str_offsets = self.string_offsets_table(die);
        let addr_table = self.address_table(die);
        self.resolve_die_references(die, str_offsets.as_ref(), addr_table.as_ref());
    }

    fn string_offsets_table(&self, root: &Die) -> Option<StringOffsetsTable> {
        let data = self.debug_str_offsets?;
        let base = match root.attr(DwAt::StrOffsetsBase) {
            Some(AttributeValue::SecOffset(offset)) | Some(AttributeValue::Unsigned(offset)) => {
                *offset as usize
            }
            _ => 0,
        };
        StringOffsetsTable::parse(data, base).ok().or_else(|| {
            (base != 0)
                .then(|| StringOffsetsTable::parse(data, 0).ok())
                .flatten()
        })
    }

    fn address_table(&self, root: &Die) -> Option<AddressTable> {
        let data = self.debug_addr?;
        let base = match root.attr(DwAt::AddrBase) {
            Some(AttributeValue::SecOffset(offset)) | Some(AttributeValue::Unsigned(offset)) => {
                *offset as usize
            }
            _ => 0,
        };
        AddressTable::parse(data, base).ok().or_else(|| {
            (base != 0)
                .then(|| AddressTable::parse(data, 0).ok())
                .flatten()
        })
    }

    fn resolve_die_references(
        &self,
        die: &mut Die,
        str_offsets: Option<&StringOffsetsTable>,
        addr_table: Option<&AddressTable>,
    ) {
        for attr in &mut die.attributes {
            match &attr.value {
                AttributeValue::StringOffset(offset) => {
                    if let Some(value) = self.get_string(*offset) {
                        attr.value = AttributeValue::String(value.to_string());
                    }
                }
                AttributeValue::StringIndex(index) => {
                    if let (Some(table), Some(debug_str)) = (str_offsets, self.debug_str) {
                        if let Some(value) = table.get_string(*index as usize, debug_str) {
                            attr.value = AttributeValue::String(value.to_string());
                        }
                    }
                }
                AttributeValue::AddressIndex(index) => {
                    if let Some(table) = addr_table {
                        if let Some(address) = table.get_address(*index as usize) {
                            attr.value = AttributeValue::Address(address);
                        }
                    }
                }
                _ => {}
            }
        }

        for child in &mut die.children {
            self.resolve_die_references(child, str_offsets, addr_table);
        }
    }

    /// Look up a string in .debug_str by offset.
    #[allow(dead_code)]
    pub fn get_string(&self, offset: u64) -> Option<&str> {
        let debug_str = self.debug_str?;
        let start = offset as usize;
        let tail = debug_str.get(start..)?;
        let pos = tail.iter().position(|&b| b == 0)?;
        let end = start.checked_add(pos)?;
        std::str::from_utf8(debug_str.get(start..end)?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dwarf::die::Attribute;
    use crate::dwarf::types::{DwAt, DwTag};

    #[test]
    fn test_resolve_string_offsets_rewrites_name_attributes() {
        let parser = DebugInfoParser::new(&[], &[], Some(b"outer\0inner\0"));
        let mut die = Die {
            offset: 0,
            tag: DwTag::Subprogram,
            has_children: true,
            attributes: vec![Attribute {
                name: DwAt::Name,
                value: AttributeValue::StringOffset(0),
            }],
            children: vec![Die {
                offset: 1,
                tag: DwTag::Variable,
                has_children: false,
                attributes: vec![Attribute {
                    name: DwAt::Name,
                    value: AttributeValue::StringOffset(6),
                }],
                children: Vec::new(),
            }],
        };

        parser.resolve_unit_references(&mut die);

        assert_eq!(die.name(), Some("outer"));
        assert_eq!(die.children[0].name(), Some("inner"));
    }
}
