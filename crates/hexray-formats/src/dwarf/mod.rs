//! DWARF debug information parsing.
//!
//! This module provides parsing for DWARF debugging information commonly found
//! in ELF and Mach-O binaries compiled with debug info. DWARF contains:
//!
//! - Type information (structs, enums, typedefs)
//! - Function information (parameters, local variables)
//! - Line number mapping (address to source location)
//! - Source file information
//!
//! # Structure
//!
//! DWARF data is organized into several sections:
//! - `.debug_info` - Main debug info (compilation units, DIEs)
//! - `.debug_abbrev` - Abbreviation tables defining DIE structure
//! - `.debug_line` - Line number programs
//! - `.debug_str` - String table
//! - `.debug_loc` - Location lists
//! - `.debug_ranges` - Address ranges
//!
//! # Example
//!
//! ```ignore
//! use hexray_formats::dwarf::{DebugInfo, DebugInfoParser};
//!
//! // Get section data from ELF/Mach-O
//! let debug_info_data = elf.section_data(".debug_info")?;
//! let debug_abbrev_data = elf.section_data(".debug_abbrev")?;
//! let debug_str_data = elf.section_data(".debug_str");
//! let debug_line_data = elf.section_data(".debug_line");
//!
//! // Parse debug info
//! let parser = DebugInfoParser::new(
//!     debug_info_data,
//!     debug_abbrev_data,
//!     debug_str_data,
//! );
//! let compilation_units = parser.parse_all()?;
//!
//! // Find function info
//! for cu in &compilation_units {
//!     if let Some(func) = cu.find_subprogram(address) {
//!         println!("Function: {:?}", func.name());
//!     }
//! }
//! ```

mod abbrev;
mod die;
pub mod eh_frame;
mod info;
mod leb128;
mod line;
pub mod lsda;
mod types;

pub use abbrev::{Abbreviation, AbbreviationTable, AttributeSpec};
pub use die::{Attribute, AttributeValue, Die, DieParser};
pub use eh_frame::{parse_eh_frame, CfiInstruction, Cie, EhFrame, EhFrameParser, Fde};
pub use info::{CompilationUnit, CompilationUnitHeader, DebugInfoParser};
pub use leb128::{decode_sleb128, decode_uleb128};
pub use line::{FileEntry, LineNumberProgram, LineNumberProgramHeader, LineRow};
pub use lsda::{
    ActionRecord, CallSite, CatchHandler, CatchType, CleanupHandler, ExceptionHandlingInfo, Lsda,
    LsdaParser, TryBlock,
};
pub use types::{DwAt, DwAte, DwForm, DwLang, DwLne, DwLns, DwTag};

/// High-level debug information interface.
///
/// This struct provides a convenient interface for querying debug information
/// across all compilation units.
#[derive(Debug)]
pub struct DebugInfo {
    /// Parsed compilation units.
    pub compilation_units: Vec<CompilationUnit>,
    /// Parsed line number programs (indexed by offset in .debug_line).
    pub line_programs: Vec<(u64, LineNumberProgram)>,
}

impl DebugInfo {
    /// Create a new debug info container from parsed data.
    pub fn new(
        compilation_units: Vec<CompilationUnit>,
        line_programs: Vec<(u64, LineNumberProgram)>,
    ) -> Self {
        Self {
            compilation_units,
            line_programs,
        }
    }

    /// Find the source location for an address.
    pub fn find_location(&self, address: u64) -> Option<SourceLocation<'_>> {
        // First find the compilation unit containing this address
        for cu in &self.compilation_units {
            if let (Some(low), Some(high)) = (cu.low_pc(), cu.high_pc()) {
                // High PC might be a size, not an address
                let high_addr = if high < low { low + high } else { high };
                if address >= low && address < high_addr {
                    // Found the compilation unit, now look up line info
                    if let Some(stmt_list) = cu.stmt_list() {
                        if let Some((_, prog)) =
                            self.line_programs.iter().find(|(off, _)| *off == stmt_list)
                        {
                            if let Some(row) = prog.find_location(address) {
                                let file_name = prog.file_name(row.file);
                                return Some(SourceLocation {
                                    file: file_name,
                                    line: row.line,
                                    column: row.column,
                                    compilation_unit: Some(cu),
                                });
                            }
                        }
                    }
                    break;
                }
            }
        }
        None
    }

    /// Find the function (subprogram) containing an address.
    pub fn find_function(&self, address: u64) -> Option<FunctionInfo<'_>> {
        for cu in &self.compilation_units {
            if let Some(die) = cu.find_subprogram(address) {
                return Some(FunctionInfo {
                    die,
                    compilation_unit: cu,
                });
            }
        }
        None
    }

    /// Get all functions defined in the debug info.
    pub fn functions(&self) -> impl Iterator<Item = FunctionInfo<'_>> {
        self.compilation_units.iter().flat_map(|cu| {
            cu.subprograms().map(move |die| FunctionInfo {
                die,
                compilation_unit: cu,
            })
        })
    }

    /// Find a compilation unit by name.
    pub fn find_compilation_unit(&self, name: &str) -> Option<&CompilationUnit> {
        self.compilation_units
            .iter()
            .find(|cu| cu.name().map(|n| n.contains(name)).unwrap_or(false))
    }
}

/// Source location information.
#[derive(Debug)]
pub struct SourceLocation<'a> {
    /// The source file name (may be None if not found).
    pub file: Option<&'a str>,
    /// The line number (1-based).
    pub line: u64,
    /// The column number (0 means unknown).
    pub column: u64,
    /// The compilation unit this location belongs to.
    pub compilation_unit: Option<&'a CompilationUnit>,
}

/// Function information from debug data.
#[derive(Debug)]
pub struct FunctionInfo<'a> {
    /// The DIE representing this function.
    pub die: &'a Die,
    /// The compilation unit this function belongs to.
    pub compilation_unit: &'a CompilationUnit,
}

impl<'a> FunctionInfo<'a> {
    /// Get the function name.
    pub fn name(&self) -> Option<&str> {
        self.die.name()
    }

    /// Get the function's low PC (start address).
    pub fn low_pc(&self) -> Option<u64> {
        self.die.low_pc()
    }

    /// Get the function's high PC (end address or size).
    pub fn high_pc(&self) -> Option<u64> {
        self.die.high_pc()
    }

    /// Get the declaration file index.
    pub fn decl_file(&self) -> Option<u64> {
        self.die.decl_file()
    }

    /// Get the declaration line number.
    pub fn decl_line(&self) -> Option<u64> {
        self.die.decl_line()
    }

    /// Get the function's parameters.
    pub fn parameters(&self) -> impl Iterator<Item = &Die> {
        self.die
            .children
            .iter()
            .filter(|d| matches!(d.tag, DwTag::FormalParameter))
    }

    /// Get the function's local variables.
    pub fn local_variables(&self) -> impl Iterator<Item = &Die> {
        self.die
            .children
            .iter()
            .filter(|d| matches!(d.tag, DwTag::Variable))
    }

    /// Get all variable names mapped to their stack offsets.
    ///
    /// Returns a map from stack offset (as i128 to match NamingContext) to variable name.
    /// This includes both parameters and local variables.
    pub fn variable_names(&self) -> std::collections::HashMap<i128, String> {
        let mut names = std::collections::HashMap::new();

        // Collect parameters
        for param in self.parameters() {
            if let (Some(name), Some(offset)) = (param.name(), param.frame_base_offset()) {
                names.insert(offset as i128, name.to_string());
            }
        }

        // Collect local variables
        for var in self.local_variables() {
            if let (Some(name), Some(offset)) = (var.name(), var.frame_base_offset()) {
                names.insert(offset as i128, name.to_string());
            }
        }

        names
    }

    /// Get parameter info: (name, stack_offset) pairs.
    pub fn parameter_info(&self) -> Vec<(String, Option<i64>)> {
        self.parameters()
            .filter_map(|p| {
                p.name()
                    .map(|name| (name.to_string(), p.frame_base_offset()))
            })
            .collect()
    }

    /// Get local variable info: (name, stack_offset) pairs.
    pub fn local_variable_info(&self) -> Vec<(String, Option<i64>)> {
        self.local_variables()
            .filter_map(|v| {
                v.name()
                    .map(|name| (name.to_string(), v.frame_base_offset()))
            })
            .collect()
    }
}

/// Parse debug info from raw section data.
///
/// # Arguments
/// * `debug_info` - The .debug_info section data.
/// * `debug_abbrev` - The .debug_abbrev section data.
/// * `debug_str` - Optional .debug_str section data.
/// * `debug_line` - Optional .debug_line section data.
/// * `address_size` - The address size (4 or 8 bytes).
pub fn parse_debug_info(
    debug_info: &[u8],
    debug_abbrev: &[u8],
    debug_str: Option<&[u8]>,
    debug_line: Option<&[u8]>,
    address_size: u8,
) -> Result<DebugInfo, crate::ParseError> {
    // Parse compilation units
    let parser = DebugInfoParser::new(debug_info, debug_abbrev, debug_str);
    let compilation_units = parser.parse_all()?;

    // Parse line number programs
    let mut line_programs = Vec::new();
    if let Some(line_data) = debug_line {
        let mut offset = 0;
        while offset < line_data.len() {
            match LineNumberProgram::parse(&line_data[offset..], address_size) {
                Ok(prog) => {
                    let prog_len = if prog.header.is_64bit {
                        12 + prog.header.unit_length as usize
                    } else {
                        4 + prog.header.unit_length as usize
                    };
                    line_programs.push((offset as u64, prog));
                    offset += prog_len;
                }
                Err(_) => break,
            }
        }
    }

    Ok(DebugInfo::new(compilation_units, line_programs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leb128() {
        // Test ULEB128
        assert_eq!(decode_uleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_uleb128(&[0x7F]).unwrap(), (127, 1));
        assert_eq!(decode_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));

        // Test SLEB128
        assert_eq!(decode_sleb128(&[0x00]).unwrap(), (0, 1));
        assert_eq!(decode_sleb128(&[0x7F]).unwrap(), (-1, 1));
        assert_eq!(decode_sleb128(&[0x80, 0x01]).unwrap(), (128, 2));
    }

    #[test]
    fn test_dw_tag_conversion() {
        assert!(matches!(DwTag::from(0x11), DwTag::CompileUnit));
        assert!(matches!(DwTag::from(0x2E), DwTag::Subprogram));
        assert!(matches!(DwTag::from(0x34), DwTag::Variable));
        assert!(matches!(DwTag::from(0xFF), DwTag::Unknown(0xFF)));
    }

    #[test]
    fn test_dw_form_conversion() {
        assert!(matches!(DwForm::from(0x01), DwForm::Addr));
        assert!(matches!(DwForm::from(0x08), DwForm::String));
        assert!(matches!(DwForm::from(0x0F), DwForm::Udata));
        assert!(matches!(DwForm::from(0xFF), DwForm::Unknown(0xFF)));
    }
}
