//! DWARF line number program parsing (.debug_line).
//!
//! The line number program maps machine code addresses to source file locations.

use super::leb128::{decode_sleb128, decode_uleb128};
use super::types::{DwLne, DwLns};
use crate::ParseError;

/// A file entry in the line number program.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// The file name.
    pub name: String,
    /// Directory index (0-based, 0 = compilation directory).
    pub directory_index: u64,
    /// Last modification time (0 if unknown).
    pub mod_time: u64,
    /// File size in bytes (0 if unknown).
    pub size: u64,
}

/// A row in the line number matrix.
#[derive(Debug, Clone)]
pub struct LineRow {
    /// The machine code address.
    pub address: u64,
    /// The source file index (1-based).
    pub file: u64,
    /// The source line number (1-based).
    pub line: u64,
    /// The source column number (0 means unknown).
    pub column: u64,
    /// Whether this is a recommended breakpoint location.
    pub is_stmt: bool,
    /// Whether this is the first byte after a basic block.
    pub basic_block: bool,
    /// Whether this marks the end of a text sequence.
    pub end_sequence: bool,
    /// Whether this is one instruction past a prologue.
    pub prologue_end: bool,
    /// Whether this is the first instruction of an epilogue.
    pub epilogue_begin: bool,
    /// The instruction set architecture value.
    pub isa: u64,
    /// The block discriminator.
    pub discriminator: u64,
}

impl LineRow {
    /// Create a new line row with default values.
    fn new(is_stmt_default: bool) -> Self {
        Self {
            address: 0,
            file: 1,
            line: 1,
            column: 0,
            is_stmt: is_stmt_default,
            basic_block: false,
            end_sequence: false,
            prologue_end: false,
            epilogue_begin: false,
            isa: 0,
            discriminator: 0,
        }
    }

    /// Reset for a new sequence.
    fn reset(&mut self, is_stmt_default: bool) {
        self.address = 0;
        self.file = 1;
        self.line = 1;
        self.column = 0;
        self.is_stmt = is_stmt_default;
        self.basic_block = false;
        self.end_sequence = false;
        self.prologue_end = false;
        self.epilogue_begin = false;
        self.isa = 0;
        self.discriminator = 0;
    }
}

/// The header of a line number program.
#[derive(Debug, Clone)]
pub struct LineNumberProgramHeader {
    /// Unit length (excluding the length field itself).
    pub unit_length: u64,
    /// DWARF version.
    pub version: u16,
    /// Header length.
    pub header_length: u64,
    /// Minimum instruction length.
    pub min_instruction_length: u8,
    /// Maximum operations per instruction (DWARF 4+).
    pub max_ops_per_instruction: u8,
    /// Default is_stmt value.
    pub default_is_stmt: bool,
    /// Line base for special opcodes.
    pub line_base: i8,
    /// Line range for special opcodes.
    pub line_range: u8,
    /// Opcode base (first special opcode).
    pub opcode_base: u8,
    /// Standard opcode lengths.
    pub standard_opcode_lengths: Vec<u8>,
    /// Include directories.
    pub include_directories: Vec<String>,
    /// File entries.
    pub file_names: Vec<FileEntry>,
    /// Whether this is 64-bit DWARF.
    pub is_64bit: bool,
    /// Address size.
    pub address_size: u8,
}

/// A parsed line number program.
#[derive(Debug)]
pub struct LineNumberProgram {
    /// The program header.
    pub header: LineNumberProgramHeader,
    /// The line number rows.
    pub rows: Vec<LineRow>,
}

impl LineNumberProgram {
    /// Parse a line number program from .debug_line data.
    ///
    /// # Arguments
    /// * `data` - The raw section data starting at the program offset.
    /// * `address_size` - The address size (4 or 8 bytes).
    pub fn parse(data: &[u8], address_size: u8) -> Result<Self, ParseError> {
        let mut offset = 0;

        // Parse unit length (determines 32-bit vs 64-bit DWARF)
        let (unit_length, is_64bit) = if data.len() < 4 {
            return Err(ParseError::TruncatedData {
                expected: 4,
                actual: data.len(),
                context: "line number program header",
            });
        } else {
            let first_word = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            offset += 4;

            if first_word == 0xFFFFFFFF {
                // 64-bit DWARF
                if data.len() < 12 {
                    return Err(ParseError::TruncatedData {
                        expected: 12,
                        actual: data.len(),
                        context: "64-bit line number program header",
                    });
                }
                let len = u64::from_le_bytes([
                    data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
                ]);
                offset += 8;
                (len, true)
            } else {
                (first_word as u64, false)
            }
        };

        // Version
        let version = u16::from_le_bytes([data[offset], data[offset + 1]]);
        offset += 2;

        // Address size and segment selector size (DWARF 5)
        let actual_address_size = if version >= 5 {
            let addr_size = data[offset];
            offset += 1;
            let _segment_selector_size = data[offset];
            offset += 1;
            addr_size
        } else {
            address_size
        };

        // Header length
        let header_length = if is_64bit {
            let len = u64::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            offset += 8;
            len
        } else {
            let len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as u64;
            offset += 4;
            len
        };

        let header_end = offset + header_length as usize;

        // Minimum instruction length
        let min_instruction_length = data[offset];
        offset += 1;

        // Maximum operations per instruction (DWARF 4+)
        let max_ops_per_instruction = if version >= 4 {
            let val = data[offset];
            offset += 1;
            val
        } else {
            1
        };

        // Default is_stmt
        let default_is_stmt = data[offset] != 0;
        offset += 1;

        // Line base
        let line_base = data[offset] as i8;
        offset += 1;

        // Line range
        let line_range = data[offset];
        offset += 1;

        // Opcode base
        let opcode_base = data[offset];
        offset += 1;

        // Standard opcode lengths
        let mut standard_opcode_lengths = Vec::with_capacity((opcode_base - 1) as usize);
        for _ in 0..(opcode_base - 1) {
            standard_opcode_lengths.push(data[offset]);
            offset += 1;
        }

        // Parse directory and file entries differently for DWARF 5
        let (include_directories, file_names) = if version >= 5 {
            Self::parse_v5_directories_and_files(data, &mut offset)?
        } else {
            Self::parse_v4_directories_and_files(data, &mut offset)?
        };

        // Skip to end of header
        offset = header_end;

        let header = LineNumberProgramHeader {
            unit_length,
            version,
            header_length,
            min_instruction_length,
            max_ops_per_instruction,
            default_is_stmt,
            line_base,
            line_range,
            opcode_base,
            standard_opcode_lengths,
            include_directories,
            file_names,
            is_64bit,
            address_size: actual_address_size,
        };

        // Execute the line number program
        let rows = Self::execute_program(data, offset, &header)?;

        Ok(Self { header, rows })
    }

    /// Parse DWARF 4 and earlier directory and file entries.
    fn parse_v4_directories_and_files(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<(Vec<String>, Vec<FileEntry>), ParseError> {
        // Include directories (null-terminated strings, empty string ends list)
        let mut include_directories = Vec::new();
        loop {
            let start = *offset;
            while *offset < data.len() && data[*offset] != 0 {
                *offset += 1;
            }
            if *offset >= data.len() {
                return Err(ParseError::TruncatedData {
                    expected: *offset + 1,
                    actual: data.len(),
                    context: "include directory",
                });
            }
            let dir = String::from_utf8_lossy(&data[start..*offset]).into_owned();
            *offset += 1; // Skip null terminator

            if dir.is_empty() {
                break;
            }
            include_directories.push(dir);
        }

        // File names
        let mut file_names = Vec::new();
        loop {
            let start = *offset;
            while *offset < data.len() && data[*offset] != 0 {
                *offset += 1;
            }
            if *offset >= data.len() {
                return Err(ParseError::TruncatedData {
                    expected: *offset + 1,
                    actual: data.len(),
                    context: "file name",
                });
            }
            let name = String::from_utf8_lossy(&data[start..*offset]).into_owned();
            *offset += 1; // Skip null terminator

            if name.is_empty() {
                break;
            }

            let (directory_index, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
            let (mod_time, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
            let (size, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;

            file_names.push(FileEntry {
                name,
                directory_index,
                mod_time,
                size,
            });
        }

        Ok((include_directories, file_names))
    }

    /// Parse DWARF 5 directory and file entries.
    fn parse_v5_directories_and_files(
        data: &[u8],
        offset: &mut usize,
    ) -> Result<(Vec<String>, Vec<FileEntry>), ParseError> {
        // Directory entry format count
        let dir_entry_format_count = data[*offset];
        *offset += 1;

        // Skip directory entry formats for now (we only handle DW_LNCT_path)
        for _ in 0..dir_entry_format_count {
            let (_content_type, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
            let (_form, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
        }

        // Directory count
        let (dir_count, consumed) = decode_uleb128(&data[*offset..])?;
        *offset += consumed;

        // Parse directories (simplified - assumes string form)
        let mut include_directories = Vec::new();
        for _ in 0..dir_count {
            let start = *offset;
            while *offset < data.len() && data[*offset] != 0 {
                *offset += 1;
            }
            let dir = String::from_utf8_lossy(&data[start..*offset]).into_owned();
            *offset += 1;
            include_directories.push(dir);
        }

        // File entry format count
        let file_entry_format_count = data[*offset];
        *offset += 1;

        // Skip file entry formats
        for _ in 0..file_entry_format_count {
            let (_content_type, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
            let (_form, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;
        }

        // File count
        let (file_count, consumed) = decode_uleb128(&data[*offset..])?;
        *offset += consumed;

        // Parse files (simplified)
        let mut file_names = Vec::new();
        for _ in 0..file_count {
            let start = *offset;
            while *offset < data.len() && data[*offset] != 0 {
                *offset += 1;
            }
            let name = String::from_utf8_lossy(&data[start..*offset]).into_owned();
            *offset += 1;

            let (directory_index, consumed) = decode_uleb128(&data[*offset..])?;
            *offset += consumed;

            file_names.push(FileEntry {
                name,
                directory_index,
                mod_time: 0,
                size: 0,
            });
        }

        Ok((include_directories, file_names))
    }

    /// Execute the line number program and generate rows.
    fn execute_program(
        data: &[u8],
        mut offset: usize,
        header: &LineNumberProgramHeader,
    ) -> Result<Vec<LineRow>, ParseError> {
        let mut rows = Vec::new();
        let mut state = LineRow::new(header.default_is_stmt);

        let program_end = if header.is_64bit {
            12 + header.unit_length as usize
        } else {
            4 + header.unit_length as usize
        };

        while offset < program_end && offset < data.len() {
            let opcode = data[offset];
            offset += 1;

            if opcode == 0 {
                // Extended opcode
                let (len, consumed) = decode_uleb128(&data[offset..])?;
                offset += consumed;

                if len == 0 {
                    continue;
                }

                let ext_opcode = data[offset];
                offset += 1;

                match ext_opcode {
                    op if op == DwLne::EndSequence as u8 => {
                        state.end_sequence = true;
                        rows.push(state.clone());
                        state.reset(header.default_is_stmt);
                    }
                    op if op == DwLne::SetAddress as u8 => {
                        state.address = match header.address_size {
                            4 => {
                                let addr = u32::from_le_bytes([
                                    data[offset],
                                    data[offset + 1],
                                    data[offset + 2],
                                    data[offset + 3],
                                ]) as u64;
                                offset += 4;
                                addr
                            }
                            8 => {
                                let addr = u64::from_le_bytes([
                                    data[offset],
                                    data[offset + 1],
                                    data[offset + 2],
                                    data[offset + 3],
                                    data[offset + 4],
                                    data[offset + 5],
                                    data[offset + 6],
                                    data[offset + 7],
                                ]);
                                offset += 8;
                                addr
                            }
                            _ => return Err(ParseError::InvalidValue("unsupported address size")),
                        };
                    }
                    op if op == DwLne::DefineFile as u8 => {
                        // Skip the file definition
                        while offset < data.len() && data[offset] != 0 {
                            offset += 1;
                        }
                        offset += 1;
                        let (_, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        let (_, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        let (_, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                    }
                    op if op == DwLne::SetDiscriminator as u8 => {
                        let (discriminator, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        state.discriminator = discriminator;
                    }
                    _ => {
                        // Skip unknown extended opcode
                        offset += (len as usize) - 1;
                    }
                }
            } else if opcode < header.opcode_base {
                // Standard opcode
                match opcode {
                    op if op == DwLns::Copy as u8 => {
                        rows.push(state.clone());
                        state.basic_block = false;
                        state.prologue_end = false;
                        state.epilogue_begin = false;
                        state.discriminator = 0;
                    }
                    op if op == DwLns::AdvancePc as u8 => {
                        let (advance, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        state.address += advance * header.min_instruction_length as u64;
                    }
                    op if op == DwLns::AdvanceLine as u8 => {
                        let (advance, consumed) = decode_sleb128(&data[offset..])?;
                        offset += consumed;
                        state.line = (state.line as i64 + advance) as u64;
                    }
                    op if op == DwLns::SetFile as u8 => {
                        let (file, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        state.file = file;
                    }
                    op if op == DwLns::SetColumn as u8 => {
                        let (column, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        state.column = column;
                    }
                    op if op == DwLns::NegateStmt as u8 => {
                        state.is_stmt = !state.is_stmt;
                    }
                    op if op == DwLns::SetBasicBlock as u8 => {
                        state.basic_block = true;
                    }
                    op if op == DwLns::ConstAddPc as u8 => {
                        let adjusted_opcode = 255 - header.opcode_base;
                        let address_advance = adjusted_opcode / header.line_range;
                        state.address +=
                            address_advance as u64 * header.min_instruction_length as u64;
                    }
                    op if op == DwLns::FixedAdvancePc as u8 => {
                        let advance = u16::from_le_bytes([data[offset], data[offset + 1]]) as u64;
                        offset += 2;
                        state.address += advance;
                    }
                    op if op == DwLns::SetPrologueEnd as u8 => {
                        state.prologue_end = true;
                    }
                    op if op == DwLns::SetEpilogueBegin as u8 => {
                        state.epilogue_begin = true;
                    }
                    op if op == DwLns::SetIsa as u8 => {
                        let (isa, consumed) = decode_uleb128(&data[offset..])?;
                        offset += consumed;
                        state.isa = isa;
                    }
                    _ => {
                        // Skip unknown standard opcode
                        let idx = (opcode - 1) as usize;
                        if idx < header.standard_opcode_lengths.len() {
                            let arg_count = header.standard_opcode_lengths[idx];
                            for _ in 0..arg_count {
                                let (_, consumed) = decode_uleb128(&data[offset..])?;
                                offset += consumed;
                            }
                        }
                    }
                }
            } else {
                // Special opcode
                let adjusted_opcode = opcode - header.opcode_base;
                let address_advance = adjusted_opcode / header.line_range;
                let line_advance =
                    header.line_base as i64 + (adjusted_opcode % header.line_range) as i64;

                state.address += address_advance as u64 * header.min_instruction_length as u64;
                state.line = (state.line as i64 + line_advance) as u64;

                rows.push(state.clone());
                state.basic_block = false;
                state.prologue_end = false;
                state.epilogue_begin = false;
                state.discriminator = 0;
            }
        }

        Ok(rows)
    }

    /// Find the source location for an address.
    pub fn find_location(&self, address: u64) -> Option<&LineRow> {
        // Binary search for the row with the highest address <= target
        let idx = self.rows.partition_point(|r| r.address <= address);
        if idx > 0 {
            let row = &self.rows[idx - 1];
            if !row.end_sequence {
                return Some(row);
            }
        }
        None
    }

    /// Get the file name for a file index.
    pub fn file_name(&self, file_index: u64) -> Option<&str> {
        if file_index == 0 || file_index > self.header.file_names.len() as u64 {
            return None;
        }
        Some(&self.header.file_names[(file_index - 1) as usize].name)
    }
}
