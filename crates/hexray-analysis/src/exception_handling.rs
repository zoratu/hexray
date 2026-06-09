//! Exception handling integration for decompilation.
//!
//! This module provides functions to extract exception handling information
//! from binaries (ELF/Mach-O) by parsing .eh_frame and .gcc_except_table
//! sections, and converts this to the decompiler's ExceptionInfo format.
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::exception_handling::ExceptionExtractor;
//! use hexray_formats::{BinaryFormat, Elf};
//!
//! let data = std::fs::read("binary")?;
//! let elf = Elf::parse(&data)?;
//! let extractor = ExceptionExtractor::from_elf(&elf)?;
//!
//! // Get exception info for a specific function
//! if let Some(info) = extractor.get_exception_info(func_start, func_end) {
//!     println!("Found {} try blocks", info.try_blocks.len());
//! }
//! ```

use crate::decompiler::{CatchInfo, CleanupInfo, ExceptionInfo, TryBlockInfo};
use crate::rtti::RttiDatabase;
use hexray_core::{Bitness, Endianness};
use hexray_formats::dwarf::lsda::{CatchType, ExceptionHandlingInfo, LsdaParser};
use hexray_formats::dwarf::{parse_eh_frame, EhFrame, Fde};
use hexray_formats::BinaryFormat;
use std::collections::HashMap;

/// Error type for exception extraction.
#[derive(Debug)]
pub enum ExceptionError {
    /// Missing required section.
    MissingSection(String),
    /// Parse error.
    ParseError(String),
}

impl std::fmt::Display for ExceptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExceptionError::MissingSection(s) => write!(f, "Missing section: {}", s),
            ExceptionError::ParseError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for ExceptionError {}

/// Result type for exception extraction.
pub type ExceptionResult<T> = Result<T, ExceptionError>;

/// Extracts exception handling information from binaries.
#[derive(Debug)]
pub struct ExceptionExtractor {
    /// Parsed .eh_frame data.
    eh_frame: EhFrame,
    /// Raw .gcc_except_table / .eh_frame_hdr data (for LSDA).
    lsda_data: Option<Vec<u8>>,
    /// Base address of LSDA section.
    lsda_base: u64,
    /// Pointer size (4 or 8).
    pointer_size: u8,
    /// Big endian flag.
    big_endian: bool,
    /// Maps FDE pc_begin to LSDA addresses.
    fde_to_lsda: HashMap<u64, u64>,
}

impl ExceptionExtractor {
    /// Creates an extractor from ELF binary sections.
    pub fn from_elf<E: BinaryFormat>(elf: &E) -> ExceptionResult<Self> {
        let pointer_size = match elf.bitness() {
            Bitness::Bits64 => 8,
            Bitness::Bits32 => 4,
        };
        let big_endian = matches!(elf.endianness(), Endianness::Big);

        // Find .eh_frame section. For relocatable objects the FDE pointers
        // are zero-filled in the raw bytes and the real targets live in
        // .rela.eh_frame — relocated_section_data applies them so FDE
        // pc_begin / pc_range / lsda land at the right values.
        let (eh_frame_data, eh_frame_base) =
            Self::find_section_relocated(elf, &[".eh_frame", "__eh_frame"])
                .ok_or_else(|| ExceptionError::MissingSection(".eh_frame".to_string()))?;

        // Parse .eh_frame
        let eh_frame = parse_eh_frame(&eh_frame_data, pointer_size, big_endian, eh_frame_base)
            .map_err(|e| ExceptionError::ParseError(format!("eh_frame: {:?}", e)))?;

        // Find LSDA data section (gcc_except_table on Linux, __gcc_except_tab on macOS).
        // Also goes through relocated_section_data so DW.ref typeinfo
        // pointers / cleanup landing-pad offsets are resolved.
        let (lsda_data, lsda_base) =
            Self::find_section_relocated(elf, &[".gcc_except_table", "__gcc_except_tab"])
                .map(|(d, b)| (Some(d), b))
                .unwrap_or((None, 0));

        // Build FDE to LSDA map
        let fde_to_lsda = eh_frame
            .fdes
            .iter()
            .filter_map(|fde| fde.lsda.map(|lsda| (fde.pc_begin, lsda)))
            .collect();

        Ok(Self {
            eh_frame,
            lsda_data,
            lsda_base,
            pointer_size,
            big_endian,
            fde_to_lsda,
        })
    }

    /// Creates an extractor from raw section data.
    pub fn from_sections(
        eh_frame_data: &[u8],
        eh_frame_base: u64,
        lsda_data: Option<&[u8]>,
        lsda_base: u64,
        pointer_size: u8,
        big_endian: bool,
    ) -> ExceptionResult<Self> {
        let eh_frame = parse_eh_frame(eh_frame_data, pointer_size, big_endian, eh_frame_base)
            .map_err(|e| ExceptionError::ParseError(format!("eh_frame: {:?}", e)))?;

        let fde_to_lsda = eh_frame
            .fdes
            .iter()
            .filter_map(|fde| fde.lsda.map(|lsda| (fde.pc_begin, lsda)))
            .collect();

        Ok(Self {
            eh_frame,
            lsda_data: lsda_data.map(|d| d.to_vec()),
            lsda_base,
            pointer_size,
            big_endian,
            fde_to_lsda,
        })
    }

    /// Find a section by any of the given names, returning the raw bytes
    /// unchanged. Kept for callers that explicitly want pre-relocation data.
    #[allow(dead_code)]
    fn find_section<B: BinaryFormat>(binary: &B, names: &[&str]) -> Option<(Vec<u8>, u64)> {
        for section in binary.sections() {
            let name = section.name();
            if names.iter().any(|n| name == *n || name.ends_with(n)) {
                let data = section.data().to_vec();
                let base = section.virtual_address();
                return Some((data, base));
            }
        }
        None
    }

    /// Like [`Self::find_section`] but returns the data with any in-section
    /// relocations applied. For relocatable `.o` files this is what makes
    /// FDE pointers resolve at all — the raw bytes carry only the addend
    /// (often zero), with the real symbol target encoded in the matching
    /// `.rela.{name}` entry.
    fn find_section_relocated<B: BinaryFormat>(
        binary: &B,
        names: &[&str],
    ) -> Option<(Vec<u8>, u64)> {
        for name in names {
            if let Some(result) = binary.relocated_section_data(name) {
                return Some(result);
            }
        }
        None
    }

    /// Gets exception info for a function at the given address range.
    pub fn get_exception_info(&self, func_start: u64, _func_end: u64) -> Option<ExceptionInfo> {
        // Find the FDE for this function
        let fde = self.eh_frame.find_fde(func_start)?;

        // Get LSDA address if present
        let lsda_addr = fde.lsda?;

        // Get LSDA data
        let lsda_data = self.get_lsda_data(lsda_addr)?;

        // Parse LSDA
        let parser = LsdaParser::new(
            lsda_data,
            fde.pc_begin,
            lsda_addr,
            self.pointer_size,
            self.big_endian,
        );

        let lsda = parser.parse().ok()?;
        let eh_info = ExceptionHandlingInfo::from_lsda(&lsda);

        // Convert to decompiler format
        Some(Self::convert_exception_info(&eh_info, None))
    }

    /// Gets exception info for a function, with RTTI database for type names.
    pub fn get_exception_info_with_rtti(
        &self,
        func_start: u64,
        _func_end: u64,
        rtti_db: &RttiDatabase,
    ) -> Option<ExceptionInfo> {
        let fde = self.eh_frame.find_fde(func_start)?;
        let lsda_addr = fde.lsda?;
        let lsda_data = self.get_lsda_data(lsda_addr)?;

        let parser = LsdaParser::new(
            lsda_data,
            fde.pc_begin,
            lsda_addr,
            self.pointer_size,
            self.big_endian,
        );

        let lsda = parser.parse().ok()?;
        let eh_info = ExceptionHandlingInfo::from_lsda(&lsda);

        // Convert with RTTI lookup
        Some(Self::convert_exception_info(&eh_info, Some(rtti_db)))
    }

    /// Gets LSDA data for a given address.
    fn get_lsda_data(&self, lsda_addr: u64) -> Option<&[u8]> {
        let lsda_data = self.lsda_data.as_ref()?;

        // Calculate offset into LSDA section
        if lsda_addr < self.lsda_base {
            return None;
        }
        let offset = (lsda_addr - self.lsda_base) as usize;

        if offset >= lsda_data.len() {
            return None;
        }

        Some(&lsda_data[offset..])
    }

    /// Converts from hexray-formats ExceptionHandlingInfo to decompiler ExceptionInfo.
    fn convert_exception_info(
        eh_info: &ExceptionHandlingInfo,
        rtti_db: Option<&RttiDatabase>,
    ) -> ExceptionInfo {
        let try_blocks = eh_info
            .try_blocks
            .iter()
            .map(|tb| TryBlockInfo {
                start: tb.start,
                end: tb.end,
                handlers: tb
                    .catch_handlers
                    .iter()
                    .map(|ch| CatchInfo {
                        landing_pad: ch.landing_pad,
                        catch_type: Self::get_catch_type_name(&ch.catch_type, rtti_db),
                        is_catch_all: matches!(ch.catch_type, CatchType::CatchAll),
                    })
                    .collect(),
            })
            .collect();

        let cleanup_handlers = eh_info
            .cleanup_handlers
            .iter()
            .map(|ch| CleanupInfo {
                start: ch.start,
                end: ch.end,
                landing_pad: ch.landing_pad,
            })
            .collect();

        ExceptionInfo {
            try_blocks,
            cleanup_handlers,
        }
    }

    /// Gets the type name for a catch type.
    fn get_catch_type_name(
        catch_type: &CatchType,
        rtti_db: Option<&RttiDatabase>,
    ) -> Option<String> {
        match catch_type {
            CatchType::Specific { type_info } => {
                // Try to look up the type name from RTTI
                if let (Some(addr), Some(db)) = (type_info, rtti_db) {
                    if let Some(info) = db.get_typeinfo(*addr) {
                        return Some(info.name.clone());
                    }
                }
                // Return address as fallback
                type_info.map(|addr| format!("type@{:#x}", addr))
            }
            CatchType::Cleanup => Some("cleanup".to_string()),
            CatchType::ExceptionSpec { filter } => Some(format!("exception_spec({})", filter)),
            CatchType::CatchAll => Some("...".to_string()),
        }
    }

    /// Returns an iterator over all FDEs with exception handling.
    pub fn functions_with_exceptions(&self) -> impl Iterator<Item = &Fde> {
        self.eh_frame.fdes.iter().filter(|fde| fde.lsda.is_some())
    }

    /// Returns the total number of functions with exception handling.
    pub fn exception_function_count(&self) -> usize {
        self.eh_frame
            .fdes
            .iter()
            .filter(|fde| fde.lsda.is_some())
            .count()
    }

    /// Returns the total number of FDEs present in `.eh_frame`.
    pub fn fde_count(&self) -> usize {
        self.eh_frame.fdes.len()
    }

    /// Returns the unique personality functions referenced by parsed CIEs.
    pub fn personality_functions(&self) -> Vec<u64> {
        let mut personalities: Vec<u64> = self
            .eh_frame
            .cies
            .iter()
            .filter_map(|cie| cie.personality)
            .collect();
        personalities.sort_unstable();
        personalities.dedup();
        personalities
    }

    /// Returns true when an LSDA section such as `.gcc_except_table` was found.
    pub fn has_lsda_section(&self) -> bool {
        self.lsda_data.is_some()
    }

    /// Returns all function boundaries from eh_frame.
    pub fn function_boundaries(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.eh_frame.function_boundaries()
    }

    /// Checks if a function has exception handling by its start address.
    pub fn has_exception_handling(&self, func_start: u64) -> bool {
        self.fde_to_lsda.contains_key(&func_start)
    }

    /// Gets the LSDA address for a function, if any.
    pub fn lsda_address(&self, func_start: u64) -> Option<u64> {
        self.fde_to_lsda.get(&func_start).copied()
    }

    /// Gets the raw EhFrame data.
    pub fn eh_frame(&self) -> &EhFrame {
        &self.eh_frame
    }
}

/// Extracts exception info from a binary and returns a map of function address to ExceptionInfo.
pub fn extract_all_exception_info<B: BinaryFormat>(
    binary: &B,
) -> ExceptionResult<HashMap<u64, ExceptionInfo>> {
    let extractor = ExceptionExtractor::from_elf(binary)?;
    let mut result = HashMap::new();

    for fde in extractor.functions_with_exceptions() {
        if let Some(info) = extractor.get_exception_info(fde.pc_begin, fde.pc_end()) {
            result.insert(fde.pc_begin, info);
        }
    }

    Ok(result)
}

/// Extracts exception info with RTTI type names.
pub fn extract_all_exception_info_with_rtti<B: BinaryFormat>(
    binary: &B,
    rtti_db: &RttiDatabase,
) -> ExceptionResult<HashMap<u64, ExceptionInfo>> {
    let extractor = ExceptionExtractor::from_elf(binary)?;
    let mut result = HashMap::new();

    for fde in extractor.functions_with_exceptions() {
        if let Some(info) =
            extractor.get_exception_info_with_rtti(fde.pc_begin, fde.pc_end(), rtti_db)
        {
            result.insert(fde.pc_begin, info);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::ExceptionInfo;

    #[test]
    fn test_empty_exception_info() {
        let info = ExceptionInfo::default();
        assert!(info.try_blocks.is_empty());
        assert!(info.cleanup_handlers.is_empty());
    }

    #[test]
    fn test_convert_exception_info() {
        use hexray_formats::dwarf::lsda::{CatchHandler, CleanupHandler, TryBlock};

        let eh_info = ExceptionHandlingInfo {
            try_blocks: vec![TryBlock {
                start: 0x1000,
                end: 0x1100,
                catch_handlers: vec![CatchHandler {
                    landing_pad: 0x1200,
                    catch_type: CatchType::CatchAll,
                }],
            }],
            cleanup_handlers: vec![CleanupHandler {
                start: 0x2000,
                end: 0x2100,
                landing_pad: 0x2200,
            }],
            has_exception_handling: true,
        };

        let info = ExceptionExtractor::convert_exception_info(&eh_info, None);

        assert_eq!(info.try_blocks.len(), 1);
        assert_eq!(info.try_blocks[0].start, 0x1000);
        assert_eq!(info.try_blocks[0].end, 0x1100);
        assert_eq!(info.try_blocks[0].handlers.len(), 1);
        assert!(info.try_blocks[0].handlers[0].is_catch_all);

        assert_eq!(info.cleanup_handlers.len(), 1);
        assert_eq!(info.cleanup_handlers[0].landing_pad, 0x2200);
    }

    /// Relocatable `.o` files store FDE pointers as `R_*_PREL32` against a
    /// zero raw value, with the real target encoded in `.rela.eh_frame`.
    /// Without applying those relocations every FDE's `pc_begin` resolves to
    /// zero (or a near-zero artifact) and `find_fde` never matches the real
    /// function addresses the disassembler hands back to the decompiler —
    /// exception_info silently falls through and try/catch reconstruction
    /// never fires.
    ///
    /// This fixture is the canonical small repro: `g++ -O0 -c` on a function
    /// containing `try { may_throw(); } catch (E1&) { ... } catch (E2&) {
    /// ... } catch (...) { ... }`. The `caller` function lives at a non-zero
    /// post-remap address; the test asserts we can both find its FDE and
    /// pull at least one catch handler out of the LSDA — both of which fail
    /// in pre-fix builds.
    #[test]
    fn test_relocated_eh_frame_recovers_fde_for_relocatable_object_caller() {
        use hexray_formats::{BinaryFormat, Elf};

        const FIXTURE: &[u8] =
            include_bytes!("../../../tests/fixtures/cpp_exceptions_relocatable.o");

        let elf = Elf::parse(FIXTURE).expect("parse cpp_exceptions_relocatable.o");
        let extractor = ExceptionExtractor::from_elf(&elf).expect("from_elf");

        let caller = elf
            .symbols()
            .find(|s| s.name == "caller(int)" || s.name == "_Z6calleri")
            .cloned()
            .expect("caller symbol present in fixture");

        let info = extractor
            .get_exception_info(caller.address, caller.address.saturating_add(caller.size))
            .expect(
                "FDE for `caller` was not found — `.rela.eh_frame` relocations \
                 likely were not applied",
            );

        assert!(
            !info.try_blocks.is_empty(),
            "caller has a try/catch block but no try block was recovered: \
             {info:?}"
        );
        assert!(
            info.try_blocks.iter().any(|tb| !tb.handlers.is_empty()),
            "no catch handlers attached to any try block: {info:?}"
        );
    }

    #[test]
    fn test_catch_type_name() {
        assert_eq!(
            ExceptionExtractor::get_catch_type_name(&CatchType::CatchAll, None),
            Some("...".to_string())
        );

        assert_eq!(
            ExceptionExtractor::get_catch_type_name(&CatchType::Cleanup, None),
            Some("cleanup".to_string())
        );

        assert_eq!(
            ExceptionExtractor::get_catch_type_name(
                &CatchType::Specific {
                    type_info: Some(0x1234)
                },
                None
            ),
            Some("type@0x1234".to_string())
        );
    }
}
