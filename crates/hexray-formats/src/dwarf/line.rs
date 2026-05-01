//!
//! The line number program maps machine code addresses to source file locations.

use super::leb128::{decode_sleb128, decode_uleb128};
use super::types::{DwLne, DwLns};
use crate::ParseError;

// ---- bounds-checked little-endian readers ----------------------------------

#[inline]
fn read_u16(data: &[u8], at: usize) -> u16 {
    let end = at.saturating_add(2);
    let arr: [u8; 2] = data
        .get(at..end)
        .unwrap_or(&[0; 2])
        .try_into()
        .unwrap_or_default();
    u16::from_le_bytes(arr)
}

#[inline]
fn read_u32(data: &[u8], at: usize) -> u32 {
    let end = at.saturating_add(4);
    let arr: [u8; 4] = data
        .get(at..end)
        .unwrap_or(&[0; 4])
        .try_into()
        .unwrap_or_default();
    u32::from_le_bytes(arr)
}

#[inline]
fn read_u64(data: &[u8], at: usize) -> u64 {
    let end = at.saturating_add(8);
    let arr: [u8; 8] = data
        .get(at..end)
        .unwrap_or(&[0; 8])
        .try_into()
        .unwrap_or_default();
    u64::from_le_bytes(arr)
}

/// Read a single byte at `pos`, returning `None` if out of range.
#[inline]
fn read_u8(data: &[u8], pos: usize) -> Option<u8> {
    data.get(pos).copied()
}

/// Decode a ULEB128 starting at `*pos`, advancing `*pos` past it.
#[inline]
fn read_uleb_at(data: &[u8], pos: &mut usize) -> Result<u64, ParseError> {
    let tail = data.get(*pos..).ok_or(ParseError::TruncatedData {
        expected: *pos,
        actual: data.len(),
        context: "ULEB128",
    })?;
    let (val, len) = decode_uleb128(tail)?;
    *pos = pos.saturating_add(len);
    Ok(val)
}

/// Decode an SLEB128 starting at `*pos`, advancing `*pos` past it.
#[inline]
fn read_sleb_at(data: &[u8], pos: &mut usize) -> Result<i64, ParseError> {
    let tail = data.get(*pos..).ok_or(ParseError::TruncatedData {
        expected: *pos,
        actual: data.len(),
        context: "SLEB128",
    })?;
    let (val, len) = decode_sleb128(tail)?;
    *pos = pos.saturating_add(len);
    Ok(val)
}

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
        let mut offset = 0usize;

        // Parse unit length (determines 32-bit vs 64-bit DWARF)
        if data.len() < 4 {
            return Err(ParseError::TruncatedData {
                expected: 4,
                actual: data.len(),
                context: "line number program header",
            });
        }
        let first_word = read_u32(data, offset);
        offset = offset.saturating_add(4);

        let (unit_length, is_64bit) = if first_word == 0xFFFFFFFF {
            // 64-bit DWARF
            if data.len() < 12 {
                return Err(ParseError::TruncatedData {
                    expected: 12,
                    actual: data.len(),
                    context: "64-bit line number program header",
                });
            }
            let len = read_u64(data, offset);
            offset = offset.saturating_add(8);
            (len, true)
        } else {
            (first_word as u64, false)
        };

        // Version
        let version = read_u16(data, offset);
        offset = offset.saturating_add(2);

        // Address size and segment selector size (DWARF 5)
        let actual_address_size = if version >= 5 {
            let addr_size = read_u8(data, offset).unwrap_or(0);
            offset = offset.saturating_add(1);
            let _segment_selector_size = read_u8(data, offset).unwrap_or(0);
            offset = offset.saturating_add(1);
            addr_size
        } else {
            address_size
        };

        // Header length
        let header_length = if is_64bit {
            let len = read_u64(data, offset);
            offset = offset.saturating_add(8);
            len
        } else {
            let len = read_u32(data, offset) as u64;
            offset = offset.saturating_add(4);
            len
        };

        let header_end = offset.saturating_add(header_length as usize);

        // Minimum instruction length
        let min_instruction_length = read_u8(data, offset).unwrap_or(1);
        offset = offset.saturating_add(1);

        // Maximum operations per instruction (DWARF 4+)
        let max_ops_per_instruction = if version >= 4 {
            let val = read_u8(data, offset).unwrap_or(1);
            offset = offset.saturating_add(1);
            val
        } else {
            1
        };

        // Default is_stmt
        let default_is_stmt = read_u8(data, offset).unwrap_or(0) != 0;
        offset = offset.saturating_add(1);

        // Line base
        let line_base = read_u8(data, offset).unwrap_or(0) as i8;
        offset = offset.saturating_add(1);

        // Line range
        let line_range = read_u8(data, offset).unwrap_or(1);
        offset = offset.saturating_add(1);

        // Opcode base
        let opcode_base = read_u8(data, offset).unwrap_or(1);
        offset = offset.saturating_add(1);

        // Standard opcode lengths
        let opcode_count = (opcode_base as usize).saturating_sub(1);
        let mut standard_opcode_lengths = Vec::with_capacity(opcode_count);
        for _ in 0..opcode_count {
            standard_opcode_lengths.push(read_u8(data, offset).unwrap_or(0));
            offset = offset.saturating_add(1);
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
            while let Some(b) = read_u8(data, *offset) {
                if b == 0 {
                    break;
                }
                *offset = offset.saturating_add(1);
            }
            if *offset >= data.len() {
                return Err(ParseError::TruncatedData {
                    expected: offset.saturating_add(1),
                    actual: data.len(),
                    context: "include directory",
                });
            }
            let dir = crate::name_from_bytes(data.get(start..*offset).unwrap_or(&[]));
            *offset = offset.saturating_add(1); // Skip null terminator

            if dir.is_empty() {
                break;
            }
            include_directories.push(dir);
        }

        // File names
        let mut file_names = Vec::new();
        loop {
            let start = *offset;
            while let Some(b) = read_u8(data, *offset) {
                if b == 0 {
                    break;
                }
                *offset = offset.saturating_add(1);
            }
            if *offset >= data.len() {
                return Err(ParseError::TruncatedData {
                    expected: offset.saturating_add(1),
                    actual: data.len(),
                    context: "file name",
                });
            }
            let name = crate::name_from_bytes(data.get(start..*offset).unwrap_or(&[]));
            *offset = offset.saturating_add(1); // Skip null terminator

            if name.is_empty() {
                break;
            }

            let directory_index = read_uleb_at(data, offset)?;
            let mod_time = read_uleb_at(data, offset)?;
            let size = read_uleb_at(data, offset)?;

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
        let dir_entry_format_count = read_u8(data, *offset).unwrap_or(0);
        *offset = offset.saturating_add(1);

        // Skip directory entry formats for now (we only handle DW_LNCT_path)
        for _ in 0..dir_entry_format_count {
            let _content_type = read_uleb_at(data, offset)?;
            let _form = read_uleb_at(data, offset)?;
        }

        // Directory count
        let dir_count = read_uleb_at(data, offset)?;

        // Parse directories (simplified - assumes string form)
        let mut include_directories = Vec::new();
        for _ in 0..dir_count {
            let start = *offset;
            while let Some(b) = read_u8(data, *offset) {
                if b == 0 {
                    break;
                }
                *offset = offset.saturating_add(1);
            }
            let dir = crate::name_from_bytes(data.get(start..*offset).unwrap_or(&[]));
            *offset = offset.saturating_add(1);
            include_directories.push(dir);
        }

        // File entry format count
        let file_entry_format_count = read_u8(data, *offset).unwrap_or(0);
        *offset = offset.saturating_add(1);

        // Skip file entry formats
        for _ in 0..file_entry_format_count {
            let _content_type = read_uleb_at(data, offset)?;
            let _form = read_uleb_at(data, offset)?;
        }

        // File count
        let file_count = read_uleb_at(data, offset)?;

        // Parse files (simplified)
        let mut file_names = Vec::new();
        for _ in 0..file_count {
            let start = *offset;
            while let Some(b) = read_u8(data, *offset) {
                if b == 0 {
                    break;
                }
                *offset = offset.saturating_add(1);
            }
            let name = crate::name_from_bytes(data.get(start..*offset).unwrap_or(&[]));
            *offset = offset.saturating_add(1);

            let directory_index = read_uleb_at(data, offset)?;

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

        let header_prefix: usize = if header.is_64bit { 12 } else { 4 };
        let program_end = header_prefix.saturating_add(header.unit_length as usize);

        while offset < program_end && offset < data.len() {
            let opcode = match read_u8(data, offset) {
                Some(b) => b,
                None => break,
            };
            offset = offset.saturating_add(1);

            if opcode == 0 {
                // Extended opcode
                let len = read_uleb_at(data, &mut offset)?;

                if len == 0 {
                    continue;
                }

                let ext_opcode = match read_u8(data, offset) {
                    Some(b) => b,
                    None => break,
                };
                offset = offset.saturating_add(1);

                match ext_opcode {
                    op if op == DwLne::EndSequence as u8 => {
                        state.end_sequence = true;
                        rows.push(state.clone());
                        state.reset(header.default_is_stmt);
                    }
                    op if op == DwLne::SetAddress as u8 => {
                        state.address = match header.address_size {
                            4 => {
                                let addr = read_u32(data, offset) as u64;
                                offset = offset.saturating_add(4);
                                addr
                            }
                            8 => {
                                let addr = read_u64(data, offset);
                                offset = offset.saturating_add(8);
                                addr
                            }
                            _ => return Err(ParseError::InvalidValue("unsupported address size")),
                        };
                    }
                    op if op == DwLne::DefineFile as u8 => {
                        // Skip the file definition name
                        while let Some(b) = read_u8(data, offset) {
                            if b == 0 {
                                break;
                            }
                            offset = offset.saturating_add(1);
                        }
                        offset = offset.saturating_add(1);
                        let _ = read_uleb_at(data, &mut offset)?;
                        let _ = read_uleb_at(data, &mut offset)?;
                        let _ = read_uleb_at(data, &mut offset)?;
                    }
                    op if op == DwLne::SetDiscriminator as u8 => {
                        let discriminator = read_uleb_at(data, &mut offset)?;
                        state.discriminator = discriminator;
                    }
                    _ => {
                        // Skip unknown extended opcode (len includes the
                        // opcode byte we already consumed).
                        let skip = (len as usize).saturating_sub(1);
                        offset = offset.saturating_add(skip);
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
                        let advance = read_uleb_at(data, &mut offset)?;
                        let delta = advance.wrapping_mul(header.min_instruction_length as u64);
                        state.address = state.address.wrapping_add(delta);
                    }
                    op if op == DwLns::AdvanceLine as u8 => {
                        let advance = read_sleb_at(data, &mut offset)?;
                        state.line = (state.line as i64).wrapping_add(advance) as u64;
                    }
                    op if op == DwLns::SetFile as u8 => {
                        state.file = read_uleb_at(data, &mut offset)?;
                    }
                    op if op == DwLns::SetColumn as u8 => {
                        state.column = read_uleb_at(data, &mut offset)?;
                    }
                    op if op == DwLns::NegateStmt as u8 => {
                        state.is_stmt = !state.is_stmt;
                    }
                    op if op == DwLns::SetBasicBlock as u8 => {
                        state.basic_block = true;
                    }
                    op if op == DwLns::ConstAddPc as u8 => {
                        let adjusted_opcode = 255u8.saturating_sub(header.opcode_base);
                        let address_advance = if header.line_range == 0 {
                            0
                        } else {
                            adjusted_opcode.checked_div(header.line_range).unwrap_or(0)
                        };
                        let delta = (address_advance as u64)
                            .wrapping_mul(header.min_instruction_length as u64);
                        state.address = state.address.wrapping_add(delta);
                    }
                    op if op == DwLns::FixedAdvancePc as u8 => {
                        let advance = read_u16(data, offset) as u64;
                        offset = offset.saturating_add(2);
                        state.address = state.address.wrapping_add(advance);
                    }
                    op if op == DwLns::SetPrologueEnd as u8 => {
                        state.prologue_end = true;
                    }
                    op if op == DwLns::SetEpilogueBegin as u8 => {
                        state.epilogue_begin = true;
                    }
                    op if op == DwLns::SetIsa as u8 => {
                        state.isa = read_uleb_at(data, &mut offset)?;
                    }
                    _ => {
                        // Skip unknown standard opcode
                        let idx = (opcode as usize).saturating_sub(1);
                        if let Some(&arg_count) = header.standard_opcode_lengths.get(idx) {
                            for _ in 0..arg_count {
                                let _ = read_uleb_at(data, &mut offset)?;
                            }
                        }
                    }
                }
            } else {
                // Special opcode
                let adjusted_opcode = opcode.saturating_sub(header.opcode_base);
                if header.line_range == 0 {
                    rows.push(state.clone());
                    continue;
                }
                let address_advance = adjusted_opcode.checked_div(header.line_range).unwrap_or(0);
                let line_advance = (header.line_base as i64).wrapping_add(
                    (adjusted_opcode.checked_rem(header.line_range).unwrap_or(0)) as i64,
                );

                let addr_delta =
                    (address_advance as u64).wrapping_mul(header.min_instruction_length as u64);
                state.address = state.address.wrapping_add(addr_delta);
                state.line = (state.line as i64).wrapping_add(line_advance) as u64;

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
        let prev = idx.checked_sub(1)?;
        let row = self.rows.get(prev)?;
        if row.end_sequence {
            None
        } else {
            Some(row)
        }
    }

    /// Get the file name for a file index.
    pub fn file_name(&self, file_index: u64) -> Option<&str> {
        if file_index == 0 || file_index > self.header.file_names.len() as u64 {
            return None;
        }
        let idx = (file_index as usize).checked_sub(1)?;
        self.header.file_names.get(idx).map(|f| f.name.as_str())
    }
}
