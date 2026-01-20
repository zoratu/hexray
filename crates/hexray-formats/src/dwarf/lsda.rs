// Allow DWARF standard naming conventions (DW_EH_PE_*)
#![allow(non_upper_case_globals)]

//! LSDA (Language Specific Data Area) parsing for C++ exception handling.
//!
//! The LSDA is pointed to by FDEs in the .eh_frame section and contains:
//! - Call site table: maps PC ranges to landing pads and actions
//! - Action table: chains of actions for exception matching
//! - Type table: type_info pointers for catch clauses
//!
//! # Structure
//!
//! ```text
//! +----------------+
//! | LSDA Header    |  encoding info, table offsets
//! +----------------+
//! | Call Sites     |  (start, length, landing_pad, action)
//! +----------------+
//! | Action Table   |  (type_filter, next_action) chains
//! +----------------+
//! | Type Table     |  type_info pointers (grows backward!)
//! +----------------+
//! ```
//!
//! # Example
//!
//! ```ignore
//! use hexray_formats::dwarf::lsda::LsdaParser;
//!
//! let parser = LsdaParser::new(lsda_data, func_start, 8, false);
//! let lsda = parser.parse()?;
//!
//! for site in &lsda.call_sites {
//!     if let Some(lp) = site.landing_pad {
//!         println!("PC range {:#x}-{:#x} -> landing pad {:#x}",
//!             site.start, site.start + site.length, lp);
//!     }
//! }
//! ```

use super::leb128::{decode_sleb128, decode_uleb128};
use crate::ParseError;

/// Parsed LSDA (Language Specific Data Area).
#[derive(Debug, Clone)]
pub struct Lsda {
    /// Landing pad base (typically function start).
    pub landing_pad_base: u64,
    /// Type table encoding.
    pub type_table_encoding: u8,
    /// Call site entries.
    pub call_sites: Vec<CallSite>,
    /// Action table entries (for catch clause matching).
    pub actions: Vec<ActionRecord>,
    /// Type filter indices to type info addresses.
    pub type_table: Vec<Option<u64>>,
}

impl Lsda {
    /// Finds the landing pad for a given PC address.
    pub fn find_landing_pad(&self, pc: u64) -> Option<&CallSite> {
        self.call_sites
            .iter()
            .find(|site| pc >= site.start && pc < site.start + site.length)
    }

    /// Gets exception types caught at a landing pad.
    pub fn get_catch_types(&self, action_index: usize) -> Vec<CatchType> {
        let mut types = Vec::new();
        let mut current = action_index;

        while current > 0 && current <= self.actions.len() {
            let action = &self.actions[current - 1];

            if action.type_filter > 0 {
                // Positive filter: catch specific type
                let type_idx = action.type_filter as usize;
                let type_info = if type_idx <= self.type_table.len() {
                    self.type_table.get(type_idx - 1).copied().flatten()
                } else {
                    None
                };
                types.push(CatchType::Specific { type_info });
            } else if action.type_filter == 0 {
                // Zero filter: cleanup (finally)
                types.push(CatchType::Cleanup);
            } else {
                // Negative filter: exception specification (rarely used now)
                types.push(CatchType::ExceptionSpec {
                    filter: action.type_filter,
                });
            }

            // Follow the chain
            if action.next_action == 0 {
                break;
            }
            // next_action is a byte offset, but we indexed actions sequentially
            // This is a simplification - proper handling needs byte offset tracking
            current = (current as i64 + action.next_action) as usize;
            if current == 0 || current > self.actions.len() {
                break;
            }
        }

        types
    }
}

/// A call site entry describing a protected region.
#[derive(Debug, Clone)]
pub struct CallSite {
    /// Start of the protected region (relative to function start, then absolute).
    pub start: u64,
    /// Length of the protected region.
    pub length: u64,
    /// Landing pad address (absolute), or None if no handler.
    pub landing_pad: Option<u64>,
    /// Action table index (1-based), or 0 for no action.
    pub action_index: usize,
}

impl CallSite {
    /// Returns the end address of the protected region.
    pub fn end(&self) -> u64 {
        self.start + self.length
    }

    /// Returns true if this site has a landing pad (catch/cleanup handler).
    pub fn has_handler(&self) -> bool {
        self.landing_pad.is_some()
    }

    /// Returns true if this is just a cleanup (no catch).
    pub fn is_cleanup_only(&self) -> bool {
        self.landing_pad.is_some() && self.action_index == 0
    }
}

/// An action record in the action table.
#[derive(Debug, Clone)]
pub struct ActionRecord {
    /// Type filter:
    /// - Positive: index into type table (1-based)
    /// - Zero: cleanup (finally)
    /// - Negative: exception specification filter
    pub type_filter: i64,
    /// Offset to next action record, or 0 if end of chain.
    pub next_action: i64,
}

/// Type of exception catch.
#[derive(Debug, Clone)]
pub enum CatchType {
    /// Catch a specific type (typeinfo address if known).
    Specific { type_info: Option<u64> },
    /// Cleanup handler (finally/destructor).
    Cleanup,
    /// Exception specification (throw() / noexcept).
    ExceptionSpec { filter: i64 },
    /// Catch-all (catch(...)).
    CatchAll,
}

// Pointer encodings (DW_EH_PE_*)
const DW_EH_PE_omit: u8 = 0xff;
const DW_EH_PE_absptr: u8 = 0x00;
const DW_EH_PE_uleb128: u8 = 0x01;
const DW_EH_PE_udata2: u8 = 0x02;
const DW_EH_PE_udata4: u8 = 0x03;
const DW_EH_PE_udata8: u8 = 0x04;
const DW_EH_PE_sleb128: u8 = 0x09;
const DW_EH_PE_sdata2: u8 = 0x0a;
const DW_EH_PE_sdata4: u8 = 0x0b;
const DW_EH_PE_sdata8: u8 = 0x0c;

const DW_EH_PE_pcrel: u8 = 0x10;
const DW_EH_PE_textrel: u8 = 0x20;
const DW_EH_PE_datarel: u8 = 0x30;
const DW_EH_PE_funcrel: u8 = 0x40;
const _DW_EH_PE_aligned: u8 = 0x50;
const DW_EH_PE_indirect: u8 = 0x80;

/// Parser for LSDA data.
pub struct LsdaParser<'a> {
    /// Raw LSDA data.
    data: &'a [u8],
    /// Base address for landing pads (typically function start).
    func_start: u64,
    /// Address of the LSDA itself.
    lsda_addr: u64,
    /// Pointer size (4 or 8).
    pointer_size: u8,
    /// Big endian flag.
    big_endian: bool,
}

impl<'a> LsdaParser<'a> {
    /// Creates a new LSDA parser.
    pub fn new(
        data: &'a [u8],
        func_start: u64,
        lsda_addr: u64,
        pointer_size: u8,
        big_endian: bool,
    ) -> Self {
        Self {
            data,
            func_start,
            lsda_addr,
            pointer_size,
            big_endian,
        }
    }

    /// Parses the LSDA.
    pub fn parse(&self) -> Result<Lsda, ParseError> {
        let mut offset = 0;

        // Parse header
        // Landing pad base encoding
        let lp_start_encoding = self.read_u8(&mut offset)?;
        let landing_pad_base = if lp_start_encoding != DW_EH_PE_omit {
            self.read_encoded(&mut offset, lp_start_encoding)?
        } else {
            self.func_start
        };

        // Type table encoding
        let type_table_encoding = self.read_u8(&mut offset)?;
        let type_table_offset = if type_table_encoding != DW_EH_PE_omit {
            let (val, _) = decode_uleb128(&self.data[offset..])?;
            offset += self.uleb128_size(val);
            Some(offset + val as usize)
        } else {
            None
        };

        // Call site table encoding
        let call_site_encoding = self.read_u8(&mut offset)?;
        let (call_site_table_length, _) = decode_uleb128(&self.data[offset..])?;
        offset += self.uleb128_size(call_site_table_length);

        let call_site_table_end = offset + call_site_table_length as usize;

        // Parse call sites
        let mut call_sites = Vec::new();
        while offset < call_site_table_end && offset < self.data.len() {
            let start = self.read_encoded(&mut offset, call_site_encoding)?;
            let length = self.read_encoded(&mut offset, call_site_encoding)?;
            let landing_pad_offset = self.read_encoded(&mut offset, call_site_encoding)?;
            let (action_raw, _) = decode_uleb128(&self.data[offset..])?;
            offset += self.uleb128_size(action_raw);

            let landing_pad = if landing_pad_offset != 0 {
                Some(landing_pad_base + landing_pad_offset)
            } else {
                None
            };

            call_sites.push(CallSite {
                start: landing_pad_base + start,
                length,
                landing_pad,
                action_index: action_raw as usize,
            });
        }

        // Ensure we're at the end of call site table
        offset = call_site_table_end;

        // Parse action table
        let action_table_start = offset;
        let mut actions = Vec::new();

        // The action table continues until the type table
        let action_table_end = type_table_offset.unwrap_or(self.data.len());

        while offset < action_table_end && offset < self.data.len() {
            let (type_filter, bytes1) = decode_sleb128(&self.data[offset..])?;
            offset += bytes1;

            if offset >= action_table_end || offset >= self.data.len() {
                break;
            }

            let (next_action, bytes2) = decode_sleb128(&self.data[offset..])?;
            offset += bytes2;

            actions.push(ActionRecord {
                type_filter,
                next_action,
            });
        }

        // Parse type table (grows backward from type_table_offset)
        let mut type_table = Vec::new();
        if let Some(tt_offset) = type_table_offset {
            if type_table_encoding != DW_EH_PE_omit {
                let entry_size = self.encoded_size(type_table_encoding);
                let mut tt_pos = tt_offset;

                // Read entries backward
                while tt_pos >= entry_size && tt_pos > action_table_start {
                    tt_pos -= entry_size;
                    let mut read_pos = tt_pos;
                    let value = self.read_encoded(&mut read_pos, type_table_encoding)?;

                    if value == 0 {
                        type_table.push(None);
                    } else {
                        // The value might be relative, resolve it
                        type_table.push(Some(value));
                    }

                    // Limit to reasonable number of entries
                    if type_table.len() > 100 {
                        break;
                    }
                }
            }
        }

        Ok(Lsda {
            landing_pad_base,
            type_table_encoding,
            call_sites,
            actions,
            type_table,
        })
    }

    fn read_u8(&self, offset: &mut usize) -> Result<u8, ParseError> {
        if *offset >= self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: *offset + 1,
                actual: self.data.len(),
                context: "LSDA read_u8",
            });
        }
        let val = self.data[*offset];
        *offset += 1;
        Ok(val)
    }

    fn read_u16(&self, offset: &mut usize) -> Result<u16, ParseError> {
        if *offset + 2 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: *offset + 2,
                actual: self.data.len(),
                context: "LSDA read_u16",
            });
        }
        let bytes = &self.data[*offset..*offset + 2];
        *offset += 2;
        Ok(if self.big_endian {
            u16::from_be_bytes([bytes[0], bytes[1]])
        } else {
            u16::from_le_bytes([bytes[0], bytes[1]])
        })
    }

    fn read_u32(&self, offset: &mut usize) -> Result<u32, ParseError> {
        if *offset + 4 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: *offset + 4,
                actual: self.data.len(),
                context: "LSDA read_u32",
            });
        }
        let bytes = &self.data[*offset..*offset + 4];
        *offset += 4;
        Ok(if self.big_endian {
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        } else {
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        })
    }

    fn read_u64(&self, offset: &mut usize) -> Result<u64, ParseError> {
        if *offset + 8 > self.data.len() {
            return Err(ParseError::TruncatedData {
                expected: *offset + 8,
                actual: self.data.len(),
                context: "LSDA read_u64",
            });
        }
        let bytes = &self.data[*offset..*offset + 8];
        *offset += 8;
        Ok(if self.big_endian {
            u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        } else {
            u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])
        })
    }

    fn read_i16(&self, offset: &mut usize) -> Result<i16, ParseError> {
        Ok(self.read_u16(offset)? as i16)
    }

    fn read_i32(&self, offset: &mut usize) -> Result<i32, ParseError> {
        Ok(self.read_u32(offset)? as i32)
    }

    fn read_i64(&self, offset: &mut usize) -> Result<i64, ParseError> {
        Ok(self.read_u64(offset)? as i64)
    }

    fn read_encoded(&self, offset: &mut usize, encoding: u8) -> Result<u64, ParseError> {
        if encoding == DW_EH_PE_omit {
            return Ok(0);
        }

        let base_encoding = encoding & 0x0f;
        let modifier = encoding & 0x70;

        let raw_value: i64 = match base_encoding {
            DW_EH_PE_absptr => {
                if self.pointer_size == 8 {
                    self.read_u64(offset)? as i64
                } else {
                    self.read_u32(offset)? as i64
                }
            }
            DW_EH_PE_uleb128 => {
                let (val, bytes) = decode_uleb128(&self.data[*offset..])?;
                *offset += bytes;
                val as i64
            }
            DW_EH_PE_sleb128 => {
                let (val, bytes) = decode_sleb128(&self.data[*offset..])?;
                *offset += bytes;
                val
            }
            DW_EH_PE_udata2 => self.read_u16(offset)? as i64,
            DW_EH_PE_sdata2 => self.read_i16(offset)? as i64,
            DW_EH_PE_udata4 => self.read_u32(offset)? as i64,
            DW_EH_PE_sdata4 => self.read_i32(offset)? as i64,
            DW_EH_PE_udata8 => self.read_u64(offset)? as i64,
            DW_EH_PE_sdata8 => self.read_i64(offset)?,
            _ => {
                return Err(ParseError::InvalidStructure {
                    kind: "LSDA",
                    offset: *offset as u64,
                    reason: format!("unsupported pointer encoding: {:#x}", encoding),
                })
            }
        };

        // Apply modifier
        let base_addr = match modifier {
            0 => 0i64, // Absolute
            DW_EH_PE_pcrel => {
                // PC-relative: relative to current position in LSDA
                (self.lsda_addr
                    + (*offset as u64).saturating_sub(self.encoded_size(encoding) as u64))
                    as i64
            }
            DW_EH_PE_funcrel => self.func_start as i64,
            DW_EH_PE_datarel | DW_EH_PE_textrel => {
                // These would need additional context
                0i64
            }
            _ => 0i64,
        };

        let result = if raw_value == 0 {
            0
        } else {
            (base_addr + raw_value) as u64
        };

        // Handle indirect
        if (encoding & DW_EH_PE_indirect) != 0 && result != 0 {
            // Would need to dereference the pointer - return as-is for now
        }

        Ok(result)
    }

    fn encoded_size(&self, encoding: u8) -> usize {
        match encoding & 0x0f {
            DW_EH_PE_absptr => self.pointer_size as usize,
            DW_EH_PE_udata2 | DW_EH_PE_sdata2 => 2,
            DW_EH_PE_udata4 | DW_EH_PE_sdata4 => 4,
            DW_EH_PE_udata8 | DW_EH_PE_sdata8 => 8,
            _ => self.pointer_size as usize, // Default
        }
    }

    fn uleb128_size(&self, value: u64) -> usize {
        let mut v = value;
        let mut size = 1;
        while v >= 0x80 {
            v >>= 7;
            size += 1;
        }
        size
    }
}

/// Result of analyzing exception handling in a function.
#[derive(Debug, Clone, Default)]
pub struct ExceptionHandlingInfo {
    /// Try blocks detected from call sites.
    pub try_blocks: Vec<TryBlock>,
    /// Cleanup handlers (destructors, finally).
    pub cleanup_handlers: Vec<CleanupHandler>,
    /// Whether the function has any exception handling.
    pub has_exception_handling: bool,
}

/// A try block with associated catch handlers.
#[derive(Debug, Clone)]
pub struct TryBlock {
    /// Start address of the try block.
    pub start: u64,
    /// End address of the try block.
    pub end: u64,
    /// Catch handlers for this try block.
    pub catch_handlers: Vec<CatchHandler>,
}

/// A catch handler.
#[derive(Debug, Clone)]
pub struct CatchHandler {
    /// Landing pad address (where execution continues).
    pub landing_pad: u64,
    /// Type being caught (if specific).
    pub catch_type: CatchType,
}

/// A cleanup handler (destructor/finally).
#[derive(Debug, Clone)]
pub struct CleanupHandler {
    /// Protected region start.
    pub start: u64,
    /// Protected region end.
    pub end: u64,
    /// Landing pad for cleanup.
    pub landing_pad: u64,
}

impl ExceptionHandlingInfo {
    /// Builds exception handling info from parsed LSDA.
    pub fn from_lsda(lsda: &Lsda) -> Self {
        let mut info = ExceptionHandlingInfo::default();

        for site in &lsda.call_sites {
            if let Some(lp) = site.landing_pad {
                info.has_exception_handling = true;

                if site.action_index == 0 {
                    // Cleanup only
                    info.cleanup_handlers.push(CleanupHandler {
                        start: site.start,
                        end: site.end(),
                        landing_pad: lp,
                    });
                } else {
                    // Has catch handlers
                    let catch_types = lsda.get_catch_types(site.action_index);
                    let handlers: Vec<CatchHandler> = catch_types
                        .into_iter()
                        .map(|ct| CatchHandler {
                            landing_pad: lp,
                            catch_type: ct,
                        })
                        .collect();

                    // Check if any handler is not just cleanup
                    let has_catch = handlers
                        .iter()
                        .any(|h| !matches!(h.catch_type, CatchType::Cleanup));

                    if has_catch {
                        info.try_blocks.push(TryBlock {
                            start: site.start,
                            end: site.end(),
                            catch_handlers: handlers,
                        });
                    } else {
                        // All cleanup
                        info.cleanup_handlers.push(CleanupHandler {
                            start: site.start,
                            end: site.end(),
                            landing_pad: lp,
                        });
                    }
                }
            }
        }

        info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_call_site_end() {
        let site = CallSite {
            start: 0x1000,
            length: 0x100,
            landing_pad: Some(0x2000),
            action_index: 1,
        };
        assert_eq!(site.end(), 0x1100);
    }

    #[test]
    fn test_call_site_has_handler() {
        let with_handler = CallSite {
            start: 0,
            length: 10,
            landing_pad: Some(100),
            action_index: 1,
        };
        assert!(with_handler.has_handler());

        let without_handler = CallSite {
            start: 0,
            length: 10,
            landing_pad: None,
            action_index: 0,
        };
        assert!(!without_handler.has_handler());
    }

    #[test]
    fn test_cleanup_only() {
        let cleanup = CallSite {
            start: 0,
            length: 10,
            landing_pad: Some(100),
            action_index: 0,
        };
        assert!(cleanup.is_cleanup_only());

        let with_action = CallSite {
            start: 0,
            length: 10,
            landing_pad: Some(100),
            action_index: 1,
        };
        assert!(!with_action.is_cleanup_only());
    }

    #[test]
    fn test_exception_handling_info_from_lsda() {
        let lsda = Lsda {
            landing_pad_base: 0x1000,
            type_table_encoding: 0,
            call_sites: vec![
                CallSite {
                    start: 0x1000,
                    length: 0x100,
                    landing_pad: Some(0x1200),
                    action_index: 0, // Cleanup
                },
                CallSite {
                    start: 0x1100,
                    length: 0x50,
                    landing_pad: Some(0x1300),
                    action_index: 1, // Catch
                },
            ],
            actions: vec![ActionRecord {
                type_filter: 1,
                next_action: 0,
            }],
            type_table: vec![Some(0x5000)],
        };

        let info = ExceptionHandlingInfo::from_lsda(&lsda);
        assert!(info.has_exception_handling);
        assert_eq!(info.cleanup_handlers.len(), 1);
        assert_eq!(info.try_blocks.len(), 1);
    }
}
