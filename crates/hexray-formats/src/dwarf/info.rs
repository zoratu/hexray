//! DWARF compilation unit parsing (.debug_info).
//!
//! This module parses the .debug_info section which contains the main debugging
//! information organized into compilation units.

use super::abbrev::AbbreviationTable;
use super::die::{Die, DieParser};
use super::types::DwLang;
use crate::ParseError;

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
        use super::types::DwTag;
        use super::die::AttributeValue;
        use super::types::DwAt;

        // Check if this DIE is a subprogram containing the address
        if matches!(die.tag, DwTag::Subprogram | DwTag::InlinedSubroutine) {
            if let (Some(low_pc), Some(high_pc_val)) = (die.low_pc(), die.attr(DwAt::HighPc)) {
                let high_pc = match high_pc_val {
                    // High PC can be an address or a size offset
                    AttributeValue::Address(addr) => *addr,
                    AttributeValue::Unsigned(size) => low_pc + size,
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

        if matches!(die.tag, DwTag::Variable | DwTag::FormalParameter) {
            if die.name() == Some(name) {
                return Some(die);
            }
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
}

impl<'a> DebugInfoParser<'a> {
    /// Create a new debug info parser.
    pub fn new(
        debug_info: &'a [u8],
        debug_abbrev: &'a [u8],
        debug_str: Option<&'a [u8]>,
    ) -> Self {
        Self {
            debug_info,
            debug_abbrev,
            debug_str,
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
    fn parse_compilation_unit(&self, offset: usize) -> Result<(CompilationUnit, usize), ParseError> {
        let data = &self.debug_info[offset..];

        // Parse unit length
        let (unit_length, is_64bit) = if data.len() < 4 {
            return Err(ParseError::TruncatedData {
                expected: 4,
                actual: data.len(),
                context: "compilation unit header",
            });
        } else {
            let first_word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            if first_word == 0xFFFFFFFF {
                // 64-bit DWARF
                if data.len() < 12 {
                    return Err(ParseError::TruncatedData {
                        expected: 12,
                        actual: data.len(),
                        context: "64-bit compilation unit header",
                    });
                }
                let len = u64::from_le_bytes([
                    data[4], data[5], data[6], data[7],
                    data[8], data[9], data[10], data[11],
                ]);
                (len, true)
            } else {
                (first_word as u64, false)
            }
        };

        let header_offset = if is_64bit { 12 } else { 4 };
        let mut local_offset = header_offset;

        // Parse version
        let version = u16::from_le_bytes([data[local_offset], data[local_offset + 1]]);
        local_offset += 2;

        // DWARF 5 has unit_type before address_size
        let (unit_type, address_size, debug_abbrev_offset) = if version >= 5 {
            let unit_type = data[local_offset];
            local_offset += 1;
            let address_size = data[local_offset];
            local_offset += 1;
            let abbrev_offset = if is_64bit {
                let off = u64::from_le_bytes([
                    data[local_offset], data[local_offset + 1],
                    data[local_offset + 2], data[local_offset + 3],
                    data[local_offset + 4], data[local_offset + 5],
                    data[local_offset + 6], data[local_offset + 7],
                ]);
                local_offset += 8;
                off
            } else {
                let off = u32::from_le_bytes([
                    data[local_offset], data[local_offset + 1],
                    data[local_offset + 2], data[local_offset + 3],
                ]) as u64;
                local_offset += 4;
                off
            };
            (unit_type, address_size, abbrev_offset)
        } else {
            // DWARF 2/3/4
            let abbrev_offset = if is_64bit {
                let off = u64::from_le_bytes([
                    data[local_offset], data[local_offset + 1],
                    data[local_offset + 2], data[local_offset + 3],
                    data[local_offset + 4], data[local_offset + 5],
                    data[local_offset + 6], data[local_offset + 7],
                ]);
                local_offset += 8;
                off
            } else {
                let off = u32::from_le_bytes([
                    data[local_offset], data[local_offset + 1],
                    data[local_offset + 2], data[local_offset + 3],
                ]) as u64;
                local_offset += 4;
                off
            };
            let address_size = data[local_offset];
            local_offset += 1;
            (0x01, address_size, abbrev_offset) // 0x01 = DW_UT_compile
        };

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
        let abbrev_data = &self.debug_abbrev[debug_abbrev_offset as usize..];
        let (abbrev_table, _) = AbbreviationTable::parse(abbrev_data)?;

        // Calculate the end of this compilation unit
        let cu_end = offset + header_offset + unit_length as usize;

        // Parse the root DIE
        let die_start = offset + local_offset;
        let mut parser = DieParser::new(
            self.debug_info,
            &abbrev_table,
            address_size,
            is_64bit,
            offset,
            die_start,
        );

        let root_die = parser.parse_die()?.ok_or_else(|| {
            ParseError::InvalidValue("missing root DIE in compilation unit")
        })?;

        Ok((CompilationUnit { header, root_die }, cu_end))
    }

    /// Look up a string in .debug_str by offset.
    #[allow(dead_code)]
    pub fn get_string(&self, offset: u64) -> Option<&str> {
        let debug_str = self.debug_str?;
        let start = offset as usize;
        if start >= debug_str.len() {
            return None;
        }

        let end = debug_str[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| start + pos)?;

        std::str::from_utf8(&debug_str[start..end]).ok()
    }
}
