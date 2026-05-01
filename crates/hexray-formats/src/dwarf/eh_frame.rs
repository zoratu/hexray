//!
//! The `.eh_frame` section contains exception handling information used for:
//! - C++ exception unwinding
//! - Stack unwinding for debugging
//! - Function boundary detection (reliable!)
//!
//! # Structure
//!
//! The section consists of:
//! 1. **CIE (Common Information Entry)**: Shared info for multiple FDEs
//!    - Version, augmentation string, code/data alignment factors
//!    - Return address register, initial instructions
//! 2. **FDE (Frame Description Entry)**: Per-function info
//!    - PC range (function start/end)
//!    - Instructions for unwinding at each PC
//!    - LSDA pointer (Language Specific Data Area) for C++ exceptions
//!
//! # Example
//!
//! ```ignore
//! use hexray_formats::dwarf::eh_frame::{EhFrame, EhFrameParser};
//!
//! let eh_frame_data = elf.section_data(".eh_frame")?;
//! let parser = EhFrameParser::new(eh_frame_data, 8, false); // 64-bit, little endian
//! let eh_frame = parser.parse()?;
//!
//! // Get function boundaries
//! for fde in &eh_frame.fdes {
//!     println!("Function: {:#x} - {:#x}", fde.pc_begin, fde.pc_begin + fde.pc_range);
//! }
//! ```

// Allow DWARF standard naming conventions (DW_CFA_*, DW_EH_PE_*)
#![allow(non_upper_case_globals)]

use super::leb128::{decode_sleb128, decode_uleb128};
use crate::ParseError;

/// Decode a ULEB128 starting at `*pos` of `data`, advancing `*pos`.
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

/// Decode an SLEB128 starting at `*pos` of `data`, advancing `*pos`.
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

/// Parsed .eh_frame section data.
#[derive(Debug, Clone)]
pub struct EhFrame {
    /// Common Information Entries.
    pub cies: Vec<Cie>,
    /// Frame Description Entries.
    pub fdes: Vec<Fde>,
}

impl EhFrame {
    /// Create a new empty EhFrame.
    pub fn new() -> Self {
        Self {
            cies: Vec::new(),
            fdes: Vec::new(),
        }
    }

    /// Get function boundaries from FDEs.
    ///
    /// Returns an iterator of (start_address, end_address) pairs.
    pub fn function_boundaries(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.fdes
            .iter()
            .map(|fde| (fde.pc_begin, fde.pc_begin.saturating_add(fde.pc_range)))
    }

    /// Find the FDE containing the given address.
    pub fn find_fde(&self, address: u64) -> Option<&Fde> {
        self.fdes.iter().find(|fde| {
            address >= fde.pc_begin && address < fde.pc_begin.saturating_add(fde.pc_range)
        })
    }

    /// Get the CIE for an FDE by its CIE offset.
    pub fn cie_for_fde(&self, fde: &Fde) -> Option<&Cie> {
        self.cies.iter().find(|cie| cie.offset == fde.cie_offset)
    }
}

impl Default for EhFrame {
    fn default() -> Self {
        Self::new()
    }
}

/// Common Information Entry.
///
/// A CIE holds information that is shared among many FDEs. There may be
/// multiple CIEs in a .eh_frame section.
#[derive(Debug, Clone)]
pub struct Cie {
    /// Offset of this CIE in the .eh_frame section.
    pub offset: u64,
    /// Length of this CIE (excluding the length field itself).
    pub length: u64,
    /// CIE version (1, 3, or 4).
    pub version: u8,
    /// Augmentation string (e.g., "zR", "zPLR").
    pub augmentation: String,
    /// Code alignment factor (for address advances).
    pub code_alignment: u64,
    /// Data alignment factor (for register offsets).
    pub data_alignment: i64,
    /// Return address register number.
    pub return_register: u64,
    /// Augmentation data length (if 'z' augmentation present).
    pub augmentation_length: Option<u64>,
    /// Pointer encoding for FDE addresses (from 'R' augmentation).
    pub fde_pointer_encoding: Option<u8>,
    /// Personality function encoding (from 'P' augmentation).
    pub personality_encoding: Option<u8>,
    /// Personality function address (from 'P' augmentation).
    pub personality: Option<u64>,
    /// LSDA encoding (from 'L' augmentation).
    pub lsda_encoding: Option<u8>,
    /// Initial CFI instructions.
    pub initial_instructions: Vec<CfiInstruction>,
    /// Whether this is a 64-bit DWARF CIE.
    pub is_64bit: bool,
    /// Signal frame flag (from 'S' augmentation).
    pub is_signal_frame: bool,
}

impl Cie {
    /// Create a new CIE with default values.
    pub fn new(offset: u64) -> Self {
        Self {
            offset,
            length: 0,
            version: 1,
            augmentation: String::new(),
            code_alignment: 1,
            data_alignment: 1,
            return_register: 0,
            augmentation_length: None,
            fde_pointer_encoding: None,
            personality_encoding: None,
            personality: None,
            lsda_encoding: None,
            initial_instructions: Vec::new(),
            is_64bit: false,
            is_signal_frame: false,
        }
    }
}

/// Frame Description Entry.
///
/// An FDE contains unwinding information for a single function or code range.
/// It references a CIE for shared information.
#[derive(Debug, Clone)]
pub struct Fde {
    /// Offset of this FDE in the .eh_frame section.
    pub offset: u64,
    /// Length of this FDE (excluding the length field itself).
    pub length: u64,
    /// Offset of the associated CIE.
    pub cie_offset: u64,
    /// Start address of the code range (function start).
    pub pc_begin: u64,
    /// Size of the code range (function size).
    pub pc_range: u64,
    /// Augmentation data length (if CIE has 'z' augmentation).
    pub augmentation_length: Option<u64>,
    /// LSDA (Language Specific Data Area) pointer for C++ exceptions.
    pub lsda: Option<u64>,
    /// CFI instructions for this FDE.
    pub instructions: Vec<CfiInstruction>,
    /// Whether this is a 64-bit DWARF FDE.
    pub is_64bit: bool,
}

impl Fde {
    /// Create a new FDE with default values.
    pub fn new(offset: u64) -> Self {
        Self {
            offset,
            length: 0,
            cie_offset: 0,
            pc_begin: 0,
            pc_range: 0,
            augmentation_length: None,
            lsda: None,
            instructions: Vec::new(),
            is_64bit: false,
        }
    }

    /// Get the end address of the code range.
    pub fn pc_end(&self) -> u64 {
        self.pc_begin.saturating_add(self.pc_range)
    }
}

/// Call Frame Information instruction.
///
/// These instructions describe how to unwind the stack at each point in a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfiInstruction {
    // High 2-bit opcodes (DW_CFA_advance_loc, DW_CFA_offset, DW_CFA_restore)
    /// Advance the location counter by delta * code_alignment.
    AdvanceLoc { delta: u8 },

    /// The previous value of register is saved at CFA + (offset * data_alignment).
    Offset { register: u64, offset: u64 },

    /// The previous value of register is restored from the initial state.
    Restore { register: u64 },

    // Opcodes from 0x00
    /// No operation.
    Nop,

    /// Set the CFA rule to register + offset.
    SetLoc { address: u64 },

    /// Advance the location counter by delta * code_alignment (1-byte delta).
    AdvanceLoc1 { delta: u8 },

    /// Advance the location counter by delta * code_alignment (2-byte delta).
    AdvanceLoc2 { delta: u16 },

    /// Advance the location counter by delta * code_alignment (4-byte delta).
    AdvanceLoc4 { delta: u32 },

    /// The previous value of register is saved at CFA + (factored_offset * data_alignment).
    OffsetExtended { register: u64, factored_offset: u64 },

    /// Same as Restore, but with ULEB128 register.
    RestoreExtended { register: u64 },

    /// The previous value of register is undefined (unrecoverable).
    Undefined { register: u64 },

    /// The previous value of register is the current value (unchanged).
    SameValue { register: u64 },

    /// Register is saved in another register.
    Register { register: u64, target_register: u64 },

    /// Push all rules onto a stack.
    RememberState,

    /// Pop the most recent rules from the stack.
    RestoreState,

    /// Set the CFA rule to register + offset.
    DefCfa { register: u64, offset: u64 },

    /// Set the CFA register (keep the offset).
    DefCfaRegister { register: u64 },

    /// Set the CFA offset (keep the register).
    DefCfaOffset { offset: u64 },

    /// Set the CFA to be computed by a DWARF expression.
    DefCfaExpression { expression: Vec<u8> },

    /// Register value is recovered using a DWARF expression.
    Expression { register: u64, expression: Vec<u8> },

    /// Same as Offset, but with signed factored offset.
    OffsetExtendedSf { register: u64, factored_offset: i64 },

    /// Set CFA register with signed factored offset.
    DefCfaSf { register: u64, factored_offset: i64 },

    /// Set CFA offset with signed factored value.
    DefCfaOffsetSf { factored_offset: i64 },

    /// Register is saved at CFA + value (not factored).
    ValOffset { register: u64, factored_offset: u64 },

    /// Register is saved at CFA + signed value (not factored).
    ValOffsetSf { register: u64, factored_offset: i64 },

    /// Register value is computed by a DWARF expression.
    ValExpression { register: u64, expression: Vec<u8> },

    // GNU extensions
    /// GNU: arguments size change.
    GnuArgsSize { size: u64 },

    /// GNU: negative offset encoding.
    GnuNegOffsetExtended { register: u64, factored_offset: u64 },

    /// Vendor-specific or unknown instruction.
    Unknown { opcode: u8, operands: Vec<u8> },
}

/// Parser for .eh_frame sections.
pub struct EhFrameParser<'a> {
    /// Raw .eh_frame data.
    data: &'a [u8],
    /// Address size (4 for 32-bit, 8 for 64-bit).
    address_size: u8,
    /// Whether the data is big-endian.
    big_endian: bool,
    /// Base address for the .eh_frame section (for pcrel addressing).
    section_base: u64,
}

impl<'a> EhFrameParser<'a> {
    /// Create a new .eh_frame parser.
    ///
    /// # Arguments
    /// * `data` - The raw .eh_frame section data.
    /// * `address_size` - Address size in bytes (4 or 8).
    /// * `big_endian` - Whether the data is big-endian.
    pub fn new(data: &'a [u8], address_size: u8, big_endian: bool) -> Self {
        Self {
            data,
            address_size,
            big_endian,
            section_base: 0,
        }
    }

    /// Set the base address of the .eh_frame section.
    ///
    /// This is needed for correctly resolving PC-relative pointers.
    pub fn with_section_base(mut self, base: u64) -> Self {
        self.section_base = base;
        self
    }

    /// Parse the .eh_frame section.
    pub fn parse(&self) -> Result<EhFrame, ParseError> {
        let mut eh_frame = EhFrame::new();
        let mut offset = 0usize;

        while offset < self.data.len() {
            // Check if we have enough data for the length field
            let Some(after_initial) = offset.checked_add(4) else {
                break;
            };
            if after_initial > self.data.len() {
                break;
            }

            let entry_start = offset;

            // Parse length (4 bytes, or 12 bytes for 64-bit DWARF)
            let initial_length = self.read_u32(offset)?;
            offset = after_initial;

            // Handle terminator (zero length)
            if initial_length == 0 {
                break;
            }

            let (length, is_64bit) = if initial_length == 0xFFFFFFFF {
                // 64-bit DWARF
                let after_64bit = offset.saturating_add(8);
                if after_64bit > self.data.len() {
                    return Err(ParseError::TruncatedData {
                        expected: after_64bit,
                        actual: self.data.len(),
                        context: "eh_frame 64-bit length",
                    });
                }
                let len = self.read_u64(offset)?;
                offset = after_64bit;
                (len, true)
            } else {
                (initial_length as u64, false)
            };

            // Calculate end of this entry
            let Some(entry_end) = offset.checked_add(length as usize) else {
                break;
            };
            if entry_end > self.data.len() {
                // Truncated entry, try to continue with what we have
                break;
            }

            // Read CIE ID / CIE pointer
            let id_size = if is_64bit { 8 } else { 4 };
            let Some(after_id) = offset.checked_add(id_size) else {
                break;
            };
            if after_id > self.data.len() {
                break;
            }

            let cie_id = if is_64bit {
                self.read_u64(offset)?
            } else {
                self.read_u32(offset)? as u64
            };

            // In .eh_frame, CIE has id=0, FDE has non-zero id (pointer to CIE)
            if cie_id == 0 {
                // This is a CIE
                let cie = self.parse_cie(entry_start, offset, length, is_64bit, entry_end)?;
                eh_frame.cies.push(cie);
            } else {
                // This is an FDE
                // The CIE pointer is relative to the current position.
                // Adversarial input can have `cie_id > offset`, which would
                // underflow — bail out of this FDE entry and keep parsing
                // the rest of the .eh_frame section.
                let cie_pointer_pos = offset;
                let Some(cie_offset) = (cie_pointer_pos as u64).checked_sub(cie_id) else {
                    offset = entry_end;
                    continue;
                };

                // Find the referenced CIE
                let cie = eh_frame.cies.iter().find(|c| c.offset == cie_offset);
                let fde = self.parse_fde(
                    entry_start,
                    offset,
                    length,
                    is_64bit,
                    entry_end,
                    cie_offset,
                    cie,
                )?;
                eh_frame.fdes.push(fde);
            }

            offset = entry_end;
        }

        Ok(eh_frame)
    }

    /// Parse a CIE entry.
    fn parse_cie(
        &self,
        entry_start: usize,
        mut offset: usize,
        length: u64,
        is_64bit: bool,
        entry_end: usize,
    ) -> Result<Cie, ParseError> {
        let mut cie = Cie::new(entry_start as u64);
        cie.length = length;
        cie.is_64bit = is_64bit;

        // Skip the CIE ID (already read)
        offset = offset.saturating_add(if is_64bit { 8 } else { 4 });

        // Version
        let Some(version_byte) = self.data.get(offset).copied() else {
            return Err(ParseError::TruncatedData {
                expected: offset.saturating_add(1),
                actual: self.data.len(),
                context: "CIE version",
            });
        };
        cie.version = version_byte;
        offset = offset.saturating_add(1);

        // Augmentation string (null-terminated)
        let aug_start = offset;
        while let Some(b) = self.data.get(offset).copied() {
            if b == 0 {
                break;
            }
            offset = offset.saturating_add(1);
        }
        if offset >= self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: offset.saturating_add(1),
                actual: self.data.len(),
                context: "CIE augmentation",
            });
        }
        cie.augmentation = crate::name_from_bytes(self.data.get(aug_start..offset).unwrap_or(&[]));
        offset = offset.saturating_add(1); // Skip null terminator

        // Check for signal frame ('S' augmentation)
        if cie.augmentation.contains('S') {
            cie.is_signal_frame = true;
        }

        // For DWARF version 4+, there are address_size and segment_size fields
        if cie.version >= 4 {
            // address_size
            if self.data.get(offset).is_none() {
                return Ok(cie);
            }
            offset = offset.saturating_add(1);

            // segment_size
            if self.data.get(offset).is_none() {
                return Ok(cie);
            }
            offset = offset.saturating_add(1);
        }

        // Code alignment factor (ULEB128)
        cie.code_alignment = read_uleb_at(self.data, &mut offset)?;

        // Data alignment factor (SLEB128)
        cie.data_alignment = read_sleb_at(self.data, &mut offset)?;

        // Return address register
        if cie.version == 1 {
            let Some(reg_byte) = self.data.get(offset).copied() else {
                return Ok(cie);
            };
            cie.return_register = reg_byte as u64;
            offset = offset.saturating_add(1);
        } else {
            cie.return_register = read_uleb_at(self.data, &mut offset)?;
        }

        // Parse augmentation data if augmentation string starts with 'z'
        if cie.augmentation.starts_with('z') {
            let aug_len = read_uleb_at(self.data, &mut offset)?;
            cie.augmentation_length = Some(aug_len);

            let aug_end = offset.saturating_add(aug_len as usize);

            // Parse augmentation data based on the augmentation string
            for ch in cie.augmentation.chars().skip(1) {
                if offset >= aug_end {
                    break;
                }
                match ch {
                    'L' => {
                        // LSDA encoding
                        if let Some(b) = self.data.get(offset).copied() {
                            cie.lsda_encoding = Some(b);
                            offset = offset.saturating_add(1);
                        }
                    }
                    'P' => {
                        // Personality encoding and pointer
                        if let Some(encoding) = self.data.get(offset).copied() {
                            cie.personality_encoding = Some(encoding);
                            offset = offset.saturating_add(1);

                            // Read the personality pointer
                            let (ptr, bytes) = self.read_encoded_pointer(offset, encoding)?;
                            cie.personality = Some(ptr);
                            offset = offset.saturating_add(bytes);
                        }
                    }
                    'R' => {
                        // FDE pointer encoding
                        if let Some(b) = self.data.get(offset).copied() {
                            cie.fde_pointer_encoding = Some(b);
                            offset = offset.saturating_add(1);
                        }
                    }
                    'S' => {
                        // Signal frame - already handled above
                    }
                    _ => {
                        // Unknown augmentation, skip to end
                        break;
                    }
                }
            }

            offset = aug_end;
        }

        // Parse initial instructions
        if offset < entry_end {
            let initial = self.data.get(offset..entry_end).unwrap_or(&[]);
            cie.initial_instructions = self.parse_cfi_instructions(initial, &cie)?;
        }

        Ok(cie)
    }

    /// Parse an FDE entry.
    #[allow(clippy::too_many_arguments)]
    fn parse_fde(
        &self,
        entry_start: usize,
        mut offset: usize,
        length: u64,
        is_64bit: bool,
        entry_end: usize,
        cie_offset: u64,
        cie: Option<&Cie>,
    ) -> Result<Fde, ParseError> {
        let mut fde = Fde::new(entry_start as u64);
        fde.length = length;
        fde.is_64bit = is_64bit;
        fde.cie_offset = cie_offset;

        // Skip the CIE pointer (already read)
        offset = offset.saturating_add(if is_64bit { 8 } else { 4 });

        // Get pointer encoding from CIE
        let ptr_encoding = cie
            .and_then(|c| c.fde_pointer_encoding)
            .unwrap_or(DW_EH_PE_absptr);

        // PC begin (initial location)
        let pc_begin_offset = offset;
        let (pc_begin, bytes) = self.read_encoded_pointer_with_base(
            offset,
            ptr_encoding,
            self.section_base.wrapping_add(pc_begin_offset as u64),
        )?;
        fde.pc_begin = pc_begin;
        offset = offset.saturating_add(bytes);

        // PC range (address range)
        // Note: The range is encoded the same way as pc_begin, but it's always
        // an unsigned value representing a size, not an address
        let range_encoding = ptr_encoding & 0x0F; // Just the format, not the application
        let (pc_range, bytes) = self.read_encoded_value(offset, range_encoding)?;
        fde.pc_range = pc_range;
        offset = offset.saturating_add(bytes);

        // Parse augmentation data if CIE has 'z' augmentation
        if cie
            .map(|c| c.augmentation.starts_with('z'))
            .unwrap_or(false)
        {
            let aug_len = read_uleb_at(self.data, &mut offset)?;
            fde.augmentation_length = Some(aug_len);

            let aug_end = offset.saturating_add(aug_len as usize);

            // Parse LSDA pointer if CIE has 'L' augmentation
            if let Some(c) = cie {
                if c.augmentation.contains('L') {
                    if let Some(lsda_encoding) = c.lsda_encoding {
                        if offset < aug_end && lsda_encoding != DW_EH_PE_omit {
                            let (lsda, _bytes) = self.read_encoded_pointer_with_base(
                                offset,
                                lsda_encoding,
                                self.section_base.wrapping_add(offset as u64),
                            )?;
                            if lsda != 0 {
                                fde.lsda = Some(lsda);
                            }
                        }
                    }
                }
            }

            offset = aug_end;
        }

        // Parse CFI instructions
        if offset < entry_end {
            if let Some(c) = cie {
                let body = self.data.get(offset..entry_end).unwrap_or(&[]);
                fde.instructions = self.parse_cfi_instructions(body, c)?;
            }
        }

        Ok(fde)
    }

    /// Parse CFI instructions from the given data.
    fn parse_cfi_instructions(
        &self,
        data: &[u8],
        cie: &Cie,
    ) -> Result<Vec<CfiInstruction>, ParseError> {
        let mut instructions = Vec::new();
        let mut offset = 0usize;

        while let Some(opcode) = data.get(offset).copied() {
            offset = offset.saturating_add(1);

            // Check high 2 bits for short-form instructions
            let high2 = opcode >> 6;
            let low6 = opcode & 0x3F;

            let instruction = match high2 {
                0x1 => {
                    // DW_CFA_advance_loc
                    CfiInstruction::AdvanceLoc { delta: low6 }
                }
                0x2 => {
                    // DW_CFA_offset
                    let factored_offset = read_uleb_at(data, &mut offset)?;
                    CfiInstruction::Offset {
                        register: low6 as u64,
                        offset: factored_offset,
                    }
                }
                0x3 => {
                    // DW_CFA_restore
                    CfiInstruction::Restore {
                        register: low6 as u64,
                    }
                }
                _ => {
                    // Extended opcodes
                    match opcode {
                        DW_CFA_nop => CfiInstruction::Nop,

                        DW_CFA_set_loc => {
                            let tail = data.get(offset..).unwrap_or(&[]);
                            let (addr, bytes) = self.read_address(tail, cie.is_64bit)?;
                            offset = offset.saturating_add(bytes);
                            CfiInstruction::SetLoc { address: addr }
                        }

                        DW_CFA_advance_loc1 => {
                            let Some(delta) = data.get(offset).copied() else {
                                break;
                            };
                            offset = offset.saturating_add(1);
                            CfiInstruction::AdvanceLoc1 { delta }
                        }

                        DW_CFA_advance_loc2 => {
                            let tail = data.get(offset..).unwrap_or(&[]);
                            if tail.len() < 2 {
                                break;
                            }
                            let delta = self.read_u16_from_slice(tail)?;
                            offset = offset.saturating_add(2);
                            CfiInstruction::AdvanceLoc2 { delta }
                        }

                        DW_CFA_advance_loc4 => {
                            let tail = data.get(offset..).unwrap_or(&[]);
                            if tail.len() < 4 {
                                break;
                            }
                            let delta = self.read_u32_from_slice(tail)?;
                            offset = offset.saturating_add(4);
                            CfiInstruction::AdvanceLoc4 { delta }
                        }

                        DW_CFA_offset_extended => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::OffsetExtended {
                                register,
                                factored_offset,
                            }
                        }

                        DW_CFA_restore_extended => {
                            let register = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::RestoreExtended { register }
                        }

                        DW_CFA_undefined => {
                            let register = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::Undefined { register }
                        }

                        DW_CFA_same_value => {
                            let register = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::SameValue { register }
                        }

                        DW_CFA_register => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let target_register = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::Register {
                                register,
                                target_register,
                            }
                        }

                        DW_CFA_remember_state => CfiInstruction::RememberState,

                        DW_CFA_restore_state => CfiInstruction::RestoreState,

                        DW_CFA_def_cfa => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let cfa_offset = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::DefCfa {
                                register,
                                offset: cfa_offset,
                            }
                        }

                        DW_CFA_def_cfa_register => {
                            let register = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::DefCfaRegister { register }
                        }

                        DW_CFA_def_cfa_offset => {
                            let cfa_offset = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::DefCfaOffset { offset: cfa_offset }
                        }

                        DW_CFA_def_cfa_expression => {
                            let len = read_uleb_at(data, &mut offset)?;
                            let Some(expr_end) = offset.checked_add(len as usize) else {
                                break;
                            };
                            let Some(slice) = data.get(offset..expr_end) else {
                                break;
                            };
                            let expression = slice.to_vec();
                            offset = expr_end;
                            CfiInstruction::DefCfaExpression { expression }
                        }

                        DW_CFA_expression => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let len = read_uleb_at(data, &mut offset)?;
                            let Some(expr_end) = offset.checked_add(len as usize) else {
                                break;
                            };
                            let Some(slice) = data.get(offset..expr_end) else {
                                break;
                            };
                            let expression = slice.to_vec();
                            offset = expr_end;
                            CfiInstruction::Expression {
                                register,
                                expression,
                            }
                        }

                        DW_CFA_offset_extended_sf => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_sleb_at(data, &mut offset)?;
                            CfiInstruction::OffsetExtendedSf {
                                register,
                                factored_offset,
                            }
                        }

                        DW_CFA_def_cfa_sf => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_sleb_at(data, &mut offset)?;
                            CfiInstruction::DefCfaSf {
                                register,
                                factored_offset,
                            }
                        }

                        DW_CFA_def_cfa_offset_sf => {
                            let factored_offset = read_sleb_at(data, &mut offset)?;
                            CfiInstruction::DefCfaOffsetSf { factored_offset }
                        }

                        DW_CFA_val_offset => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::ValOffset {
                                register,
                                factored_offset,
                            }
                        }

                        DW_CFA_val_offset_sf => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_sleb_at(data, &mut offset)?;
                            CfiInstruction::ValOffsetSf {
                                register,
                                factored_offset,
                            }
                        }

                        DW_CFA_val_expression => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let len = read_uleb_at(data, &mut offset)?;
                            let Some(expr_end) = offset.checked_add(len as usize) else {
                                break;
                            };
                            let Some(slice) = data.get(offset..expr_end) else {
                                break;
                            };
                            let expression = slice.to_vec();
                            offset = expr_end;
                            CfiInstruction::ValExpression {
                                register,
                                expression,
                            }
                        }

                        // GNU extensions
                        DW_CFA_GNU_args_size => {
                            let size = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::GnuArgsSize { size }
                        }

                        DW_CFA_GNU_negative_offset_extended => {
                            let register = read_uleb_at(data, &mut offset)?;
                            let factored_offset = read_uleb_at(data, &mut offset)?;
                            CfiInstruction::GnuNegOffsetExtended {
                                register,
                                factored_offset,
                            }
                        }

                        _ => {
                            // Unknown opcode - skip it
                            CfiInstruction::Unknown {
                                opcode,
                                operands: Vec::new(),
                            }
                        }
                    }
                }
            };

            instructions.push(instruction);
        }

        Ok(instructions)
    }

    /// Read a u16 from the data.
    fn read_u16(&self, offset: usize) -> Result<u16, ParseError> {
        let end = offset.checked_add(2).ok_or(ParseError::TruncatedData {
            expected: offset,
            actual: self.data.len(),
            context: "u16",
        })?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or(ParseError::TruncatedData {
                expected: end,
                actual: self.data.len(),
                context: "u16",
            })?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u16 conversion"))?;
        Ok(if self.big_endian {
            u16::from_be_bytes(arr)
        } else {
            u16::from_le_bytes(arr)
        })
    }

    /// Read a u32 from the data.
    fn read_u32(&self, offset: usize) -> Result<u32, ParseError> {
        let end = offset.checked_add(4).ok_or(ParseError::TruncatedData {
            expected: offset,
            actual: self.data.len(),
            context: "u32",
        })?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or(ParseError::TruncatedData {
                expected: end,
                actual: self.data.len(),
                context: "u32",
            })?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u32 conversion"))?;
        Ok(if self.big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        })
    }

    /// Read a u64 from the data.
    fn read_u64(&self, offset: usize) -> Result<u64, ParseError> {
        let end = offset.checked_add(8).ok_or(ParseError::TruncatedData {
            expected: offset,
            actual: self.data.len(),
            context: "u64",
        })?;
        let bytes = self
            .data
            .get(offset..end)
            .ok_or(ParseError::TruncatedData {
                expected: end,
                actual: self.data.len(),
                context: "u64",
            })?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u64 conversion"))?;
        Ok(if self.big_endian {
            u64::from_be_bytes(arr)
        } else {
            u64::from_le_bytes(arr)
        })
    }

    /// Read a u16 from a slice.
    fn read_u16_from_slice(&self, data: &[u8]) -> Result<u16, ParseError> {
        let bytes = data.get(0..2).ok_or(ParseError::TruncatedData {
            expected: 2,
            actual: data.len(),
            context: "u16",
        })?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u16 conversion"))?;
        Ok(if self.big_endian {
            u16::from_be_bytes(arr)
        } else {
            u16::from_le_bytes(arr)
        })
    }

    /// Read a u32 from a slice.
    fn read_u32_from_slice(&self, data: &[u8]) -> Result<u32, ParseError> {
        let bytes = data.get(0..4).ok_or(ParseError::TruncatedData {
            expected: 4,
            actual: data.len(),
            context: "u32",
        })?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u32 conversion"))?;
        Ok(if self.big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        })
    }

    /// Read a u64 from a slice.
    fn read_u64_from_slice(&self, data: &[u8]) -> Result<u64, ParseError> {
        let bytes = data.get(0..8).ok_or(ParseError::TruncatedData {
            expected: 8,
            actual: data.len(),
            context: "u64",
        })?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| ParseError::InvalidValue("u64 conversion"))?;
        Ok(if self.big_endian {
            u64::from_be_bytes(arr)
        } else {
            u64::from_le_bytes(arr)
        })
    }

    /// Read an address value from data.
    fn read_address(&self, data: &[u8], is_64bit: bool) -> Result<(u64, usize), ParseError> {
        if is_64bit {
            Ok((self.read_u64_from_slice(data)?, 8))
        } else {
            Ok((self.read_u32_from_slice(data)? as u64, 4))
        }
    }

    /// Read an encoded pointer value.
    fn read_encoded_pointer(
        &self,
        offset: usize,
        encoding: u8,
    ) -> Result<(u64, usize), ParseError> {
        let pc = self.section_base.wrapping_add(offset as u64);
        self.read_encoded_pointer_with_base(offset, encoding, pc)
    }

    /// Read an encoded pointer value with explicit base.
    fn read_encoded_pointer_with_base(
        &self,
        offset: usize,
        encoding: u8,
        pc: u64,
    ) -> Result<(u64, usize), ParseError> {
        if encoding == DW_EH_PE_omit {
            return Ok((0, 0));
        }

        let (value, bytes) = self.read_encoded_value(offset, encoding & 0x0F)?;

        // Apply the application modifier
        let result = match encoding & 0x70 {
            DW_EH_PE_absptr => value,
            DW_EH_PE_pcrel => {
                if value == 0 {
                    0
                } else {
                    pc.wrapping_add(value)
                }
            }
            DW_EH_PE_datarel => {
                // Data-relative encoding - relative to the start of the section
                self.section_base.wrapping_add(value)
            }
            _ => value, // textrel, funcrel, aligned - treat as absolute for now
        };

        Ok((result, bytes))
    }

    /// Read an encoded value (format only, no application).
    fn read_encoded_value(&self, offset: usize, format: u8) -> Result<(u64, usize), ParseError> {
        match format & 0x0F {
            DW_EH_PE_absptr => {
                if self.address_size == 8 {
                    Ok((self.read_u64(offset)?, 8))
                } else {
                    Ok((self.read_u32(offset)? as u64, 4))
                }
            }
            DW_EH_PE_uleb128 => {
                let tail = self.data.get(offset..).ok_or(ParseError::TruncatedData {
                    expected: offset,
                    actual: self.data.len(),
                    context: "ULEB128",
                })?;
                let (val, bytes) = decode_uleb128(tail)?;
                Ok((val, bytes))
            }
            DW_EH_PE_udata2 => Ok((self.read_u16(offset)? as u64, 2)),
            DW_EH_PE_udata4 => Ok((self.read_u32(offset)? as u64, 4)),
            DW_EH_PE_udata8 => Ok((self.read_u64(offset)?, 8)),
            DW_EH_PE_sleb128 => {
                let tail = self.data.get(offset..).ok_or(ParseError::TruncatedData {
                    expected: offset,
                    actual: self.data.len(),
                    context: "SLEB128",
                })?;
                let (val, bytes) = decode_sleb128(tail)?;
                Ok((val as u64, bytes))
            }
            DW_EH_PE_sdata2 => Ok((self.read_u16(offset)? as i16 as i64 as u64, 2)),
            DW_EH_PE_sdata4 => Ok((self.read_u32(offset)? as i32 as i64 as u64, 4)),
            DW_EH_PE_sdata8 => Ok((self.read_u64(offset)? as i64 as u64, 8)),
            _ => {
                // Unknown format, try address size
                if self.address_size == 8 {
                    Ok((self.read_u64(offset)?, 8))
                } else {
                    Ok((self.read_u32(offset)? as u64, 4))
                }
            }
        }
    }
}

// CFI opcode constants (names follow DWARF standard convention)
const DW_CFA_nop: u8 = 0x00;
const DW_CFA_set_loc: u8 = 0x01;
const DW_CFA_advance_loc1: u8 = 0x02;
const DW_CFA_advance_loc2: u8 = 0x03;
const DW_CFA_advance_loc4: u8 = 0x04;
const DW_CFA_offset_extended: u8 = 0x05;
const DW_CFA_restore_extended: u8 = 0x06;
const DW_CFA_undefined: u8 = 0x07;
const DW_CFA_same_value: u8 = 0x08;
const DW_CFA_register: u8 = 0x09;
const DW_CFA_remember_state: u8 = 0x0a;
const DW_CFA_restore_state: u8 = 0x0b;
const DW_CFA_def_cfa: u8 = 0x0c;
const DW_CFA_def_cfa_register: u8 = 0x0d;
const DW_CFA_def_cfa_offset: u8 = 0x0e;
const DW_CFA_def_cfa_expression: u8 = 0x0f;
const DW_CFA_expression: u8 = 0x10;
const DW_CFA_offset_extended_sf: u8 = 0x11;
const DW_CFA_def_cfa_sf: u8 = 0x12;
const DW_CFA_def_cfa_offset_sf: u8 = 0x13;
const DW_CFA_val_offset: u8 = 0x14;
const DW_CFA_val_offset_sf: u8 = 0x15;
const DW_CFA_val_expression: u8 = 0x16;

// GNU extensions
const DW_CFA_GNU_args_size: u8 = 0x2e;
const DW_CFA_GNU_negative_offset_extended: u8 = 0x2f;

// Pointer encoding constants
const DW_EH_PE_absptr: u8 = 0x00;
const DW_EH_PE_uleb128: u8 = 0x01;
const DW_EH_PE_udata2: u8 = 0x02;
const DW_EH_PE_udata4: u8 = 0x03;
const DW_EH_PE_udata8: u8 = 0x04;
const DW_EH_PE_sleb128: u8 = 0x09;
const DW_EH_PE_sdata2: u8 = 0x0a;
const DW_EH_PE_sdata4: u8 = 0x0b;
const DW_EH_PE_sdata8: u8 = 0x0c;

// Pointer application constants
const DW_EH_PE_pcrel: u8 = 0x10;
#[allow(dead_code)]
const DW_EH_PE_textrel: u8 = 0x20;
const DW_EH_PE_datarel: u8 = 0x30;
#[allow(dead_code)]
const DW_EH_PE_funcrel: u8 = 0x40;
#[allow(dead_code)]
const DW_EH_PE_aligned: u8 = 0x50;

const DW_EH_PE_omit: u8 = 0xff;

/// Parse .eh_frame section data.
///
/// This is a convenience function that creates a parser and parses the data.
///
/// # Arguments
/// * `data` - The raw .eh_frame section data.
/// * `address_size` - Address size in bytes (4 or 8).
/// * `big_endian` - Whether the data is big-endian.
/// * `section_base` - The base address of the .eh_frame section (for pcrel addressing).
pub fn parse_eh_frame(
    data: &[u8],
    address_size: u8,
    big_endian: bool,
    section_base: u64,
) -> Result<EhFrame, ParseError> {
    EhFrameParser::new(data, address_size, big_endian)
        .with_section_base(section_base)
        .parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_eh_frame() {
        let data: &[u8] = &[];
        let result = parse_eh_frame(data, 8, false, 0);
        assert!(result.is_ok());
        let eh_frame = result.unwrap();
        assert!(eh_frame.cies.is_empty());
        assert!(eh_frame.fdes.is_empty());
    }

    #[test]
    fn test_terminator() {
        // Zero-length entry terminates parsing
        let data: &[u8] = &[0x00, 0x00, 0x00, 0x00];
        let result = parse_eh_frame(data, 8, false, 0);
        assert!(result.is_ok());
        let eh_frame = result.unwrap();
        assert!(eh_frame.cies.is_empty());
        assert!(eh_frame.fdes.is_empty());
    }

    #[test]
    fn test_simple_cie() {
        // A minimal CIE:
        // Length: bytes after length field
        // CIE ID: 0 (4 bytes)
        // Version: 1
        // Augmentation: "" (null byte)
        // Code alignment: 1 (ULEB128)
        // Data alignment: -8 (SLEB128 = 0x78)
        // Return register: 16 (for x86_64)
        // Initial instructions: DW_CFA_def_cfa r7, 8; DW_CFA_offset r16, 1
        // Total after length: 4 + 1 + 1 + 1 + 1 + 1 + 3 + 2 + 1 = 15 bytes, pad to 16
        let data: &[u8] = &[
            0x10, 0x00, 0x00, 0x00, // Length: 16 bytes after this field
            0x00, 0x00, 0x00, 0x00, // CIE ID: 0
            0x01, // Version: 1
            0x00, // Augmentation: ""
            0x01, // Code alignment: 1
            0x78, // Data alignment: -8 (SLEB128)
            0x10, // Return register: 16
            // Initial instructions (7 bytes to reach 16)
            0x0c, 0x07, 0x08, // DW_CFA_def_cfa r7, 8
            0x90, 0x01, // DW_CFA_offset r16, 1
            0x00, 0x00, // DW_CFA_nop (padding)
        ];

        let result = parse_eh_frame(data, 8, false, 0);
        assert!(result.is_ok());
        let eh_frame = result.unwrap();

        assert_eq!(eh_frame.cies.len(), 1);
        let cie = &eh_frame.cies[0];
        assert_eq!(cie.version, 1);
        assert_eq!(cie.augmentation, "");
        assert_eq!(cie.code_alignment, 1);
        assert_eq!(cie.data_alignment, -8);
        assert_eq!(cie.return_register, 16);
        assert!(!cie.initial_instructions.is_empty());
    }

    #[test]
    fn test_cie_with_augmentation() {
        // CIE with "zR" augmentation
        // Total after length field: 4 + 1 + 3 + 1 + 1 + 1 + 1 + 1 + 3 + 2 + 2 = 20 bytes
        let data: &[u8] = &[
            0x14, 0x00, 0x00, 0x00, // Length: 20 bytes after this field
            0x00, 0x00, 0x00, 0x00, // CIE ID: 0
            0x01, // Version: 1
            b'z', b'R', 0x00, // Augmentation: "zR"
            0x01, // Code alignment: 1
            0x78, // Data alignment: -8
            0x10, // Return register: 16
            0x01, // Augmentation length: 1
            0x1b, // FDE pointer encoding: sdata4, pcrel
            // Initial instructions (8 bytes to reach 20)
            0x0c, 0x07, 0x08, // DW_CFA_def_cfa r7, 8
            0x90, 0x01, // DW_CFA_offset r16, 1
            0x00, 0x00, 0x00, // padding
        ];

        let result = parse_eh_frame(data, 8, false, 0);
        assert!(result.is_ok());
        let eh_frame = result.unwrap();

        assert_eq!(eh_frame.cies.len(), 1);
        let cie = &eh_frame.cies[0];
        assert_eq!(cie.augmentation, "zR");
        assert_eq!(cie.fde_pointer_encoding, Some(0x1b));
    }

    #[test]
    fn test_cfi_instruction_parsing() {
        // Test various CFI instructions
        let cie = Cie::new(0);
        let parser = EhFrameParser::new(&[], 8, false);

        // DW_CFA_def_cfa r7, 8
        let data = &[0x0c, 0x07, 0x08];
        let instructions = parser.parse_cfi_instructions(data, &cie).unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            CfiInstruction::DefCfa {
                register: 7,
                offset: 8
            }
        ));

        // DW_CFA_advance_loc (high 2 bits = 1, low 6 bits = delta)
        let data = &[0x44]; // 0x40 | 4 = advance_loc 4
        let instructions = parser.parse_cfi_instructions(data, &cie).unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            CfiInstruction::AdvanceLoc { delta: 4 }
        ));

        // DW_CFA_offset (high 2 bits = 2, low 6 bits = register)
        let data = &[0x86, 0x02]; // 0x80 | 6 = offset r6, ULEB128(2)
        let instructions = parser.parse_cfi_instructions(data, &cie).unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            CfiInstruction::Offset {
                register: 6,
                offset: 2
            }
        ));

        // DW_CFA_restore (high 2 bits = 3, low 6 bits = register)
        let data = &[0xc6]; // 0xc0 | 6 = restore r6
        let instructions = parser.parse_cfi_instructions(data, &cie).unwrap();
        assert_eq!(instructions.len(), 1);
        assert!(matches!(
            instructions[0],
            CfiInstruction::Restore { register: 6 }
        ));
    }

    #[test]
    fn test_function_boundaries() {
        let mut eh_frame = EhFrame::new();

        // Add some FDEs
        eh_frame.fdes.push(Fde {
            offset: 0,
            length: 0,
            cie_offset: 0,
            pc_begin: 0x1000,
            pc_range: 0x100,
            augmentation_length: None,
            lsda: None,
            instructions: Vec::new(),
            is_64bit: false,
        });

        eh_frame.fdes.push(Fde {
            offset: 0,
            length: 0,
            cie_offset: 0,
            pc_begin: 0x2000,
            pc_range: 0x200,
            augmentation_length: None,
            lsda: None,
            instructions: Vec::new(),
            is_64bit: false,
        });

        let boundaries: Vec<_> = eh_frame.function_boundaries().collect();
        assert_eq!(boundaries.len(), 2);
        assert_eq!(boundaries[0], (0x1000, 0x1100));
        assert_eq!(boundaries[1], (0x2000, 0x2200));
    }

    #[test]
    fn test_find_fde() {
        let mut eh_frame = EhFrame::new();

        eh_frame.fdes.push(Fde {
            offset: 0,
            length: 0,
            cie_offset: 0,
            pc_begin: 0x1000,
            pc_range: 0x100,
            augmentation_length: None,
            lsda: None,
            instructions: Vec::new(),
            is_64bit: false,
        });

        // Address in range
        assert!(eh_frame.find_fde(0x1000).is_some());
        assert!(eh_frame.find_fde(0x1050).is_some());
        assert!(eh_frame.find_fde(0x10FF).is_some());

        // Address out of range
        assert!(eh_frame.find_fde(0x0FFF).is_none());
        assert!(eh_frame.find_fde(0x1100).is_none());
    }

    #[test]
    fn test_64bit_dwarf() {
        // 64-bit DWARF CIE with 0xFFFFFFFF length marker
        // After length field: 8 (cie_id) + 1 (ver) + 1 (aug) + 1 (code_align) + 1 (data_align) + 1 (ret) + 3 (instr) = 16 bytes
        // Total length field says 16 bytes follow
        let data: &[u8] = &[
            0xFF, 0xFF, 0xFF, 0xFF, // 64-bit marker
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Length: 16 bytes (64-bit)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // CIE ID: 0 (64-bit)
            0x01, // Version: 1
            0x00, // Augmentation: ""
            0x01, // Code alignment: 1
            0x78, // Data alignment: -8
            0x10, // Return register: 16
            // Instructions: 3 bytes
            0x0c, 0x07, 0x08, // DW_CFA_def_cfa r7, 8
        ];

        let result = parse_eh_frame(data, 8, false, 0);
        assert!(result.is_ok());
        let eh_frame = result.unwrap();

        assert_eq!(eh_frame.cies.len(), 1);
        let cie = &eh_frame.cies[0];
        assert!(cie.is_64bit);
        assert_eq!(cie.version, 1);
    }
}
