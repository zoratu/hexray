//! PE (Portable Executable) format parser.
//!
//! This module provides a complete PE parser for Windows executables and DLLs,
//! supporting:
//! - PE32 (32-bit) and PE32+ (64-bit)
//! - Section parsing
//! - Import and export tables
//! - Symbol extraction from exports

mod exports;
mod header;
mod imports;
mod section;

pub use exports::{Export, ExportDirectory};
pub use header::{
    CoffHeader, DataDirectory, DosHeader, OptionalHeader, IMAGE_FILE_MACHINE_AMD64,
    IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_I386, PE32PLUS_MAGIC, PE32_MAGIC, PE_SIGNATURE,
};
pub use imports::{Import, ImportDescriptor};
pub use section::SectionHeader;

use crate::{BinaryFormat, ParseError, Section};
use hexray_core::{Architecture, Bitness, Endianness, Symbol, SymbolBinding, SymbolKind};

/// A parsed PE binary.
#[derive(Debug)]
pub struct Pe<'a> {
    /// Raw file data
    data: &'a [u8],
    /// DOS header
    pub dos_header: DosHeader,
    /// COFF header
    pub coff_header: CoffHeader,
    /// Optional header
    pub optional_header: OptionalHeader,
    /// Section headers
    pub sections: Vec<SectionHeader>,
    /// Parsed imports
    pub imports: Vec<Import>,
    /// Parsed exports
    pub exports: Vec<Export>,
    /// Symbols (derived from exports)
    symbols: Vec<Symbol>,
}

impl<'a> Pe<'a> {
    /// Parse a PE file from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        // Parse DOS header
        let dos_header = DosHeader::parse(data)?;

        // Verify PE signature
        let pe_offset = dos_header.e_lfanew as usize;
        let pe_end = pe_offset
            .checked_add(4)
            .ok_or(ParseError::InvalidValue("PE offset overflow"))?;
        let pe_sig_bytes: [u8; 4] = data
            .get(pe_offset..pe_end)
            .ok_or_else(|| ParseError::too_short(pe_end, data.len()))?
            .try_into()
            .unwrap_or_default();
        let pe_sig = u32::from_le_bytes(pe_sig_bytes);

        if pe_sig != PE_SIGNATURE {
            return Err(ParseError::invalid_magic("PE\\0\\0", &pe_sig_bytes));
        }

        // Parse COFF header
        let coff_offset = pe_end;
        let coff_chunk = data
            .get(coff_offset..)
            .ok_or_else(|| ParseError::too_short(coff_offset, data.len()))?;
        let coff_header = CoffHeader::parse(coff_chunk)?;

        // Parse optional header — COFF header is 20 bytes
        let opt_offset = coff_offset
            .checked_add(20)
            .ok_or(ParseError::InvalidValue("optional header offset overflow"))?;
        let opt_chunk = data
            .get(opt_offset..)
            .ok_or_else(|| ParseError::too_short(opt_offset.saturating_add(2), data.len()))?;
        let opt_magic_bytes: [u8; 2] = opt_chunk
            .get(..2)
            .ok_or_else(|| ParseError::too_short(opt_offset.saturating_add(2), data.len()))?
            .try_into()
            .unwrap_or_default();
        let opt_magic = u16::from_le_bytes(opt_magic_bytes);
        let optional_header = if opt_magic == PE32PLUS_MAGIC {
            OptionalHeader::parse_pe32plus(opt_chunk)?
        } else {
            OptionalHeader::parse_pe32(opt_chunk)?
        };

        // Parse section headers
        let sections_offset =
            opt_offset.saturating_add(coff_header.size_of_optional_header as usize);
        let mut sections = Vec::with_capacity(coff_header.number_of_sections as usize);
        let image_base = optional_header.image_base;

        for i in 0..coff_header.number_of_sections as usize {
            let Some(sec_offset) =
                sections_offset.checked_add(i.saturating_mul(section::SECTION_HEADER_SIZE))
            else {
                break;
            };
            let Some(sec_end) = sec_offset.checked_add(section::SECTION_HEADER_SIZE) else {
                break;
            };
            let Some(sec_chunk) = data.get(sec_offset..sec_end) else {
                break;
            };
            let mut section = SectionHeader::parse(sec_chunk)?;
            section.populate_data(data, image_base);
            sections.push(section);
        }

        // Parse imports
        let imports = if let Some(import_dir) =
            optional_header.data_directory(header::IMAGE_DIRECTORY_ENTRY_IMPORT)
        {
            if import_dir.virtual_address != 0 && import_dir.size != 0 {
                imports::parse_imports(
                    data,
                    import_dir.virtual_address,
                    import_dir.size,
                    &sections,
                    optional_header.is_64bit(),
                )
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Parse exports
        let exports = if let Some(export_dir) =
            optional_header.data_directory(header::IMAGE_DIRECTORY_ENTRY_EXPORT)
        {
            if export_dir.virtual_address != 0 && export_dir.size != 0 {
                exports::parse_exports(data, export_dir.virtual_address, export_dir.size, &sections)
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };

        // Build symbols from exports
        let image_base = optional_header.image_base;
        let symbols: Vec<Symbol> = exports
            .iter()
            .filter(|e| e.forwarder.is_none()) // Skip forwarders
            .map(|e| Symbol {
                name: if e.name.is_empty() {
                    format!("ordinal_{}", e.ordinal)
                } else {
                    e.name.clone()
                },
                address: image_base.saturating_add(e.rva as u64),
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: None,
            })
            .collect();

        Ok(Self {
            data,
            dos_header,
            coff_header,
            optional_header,
            sections,
            imports,
            exports,
            symbols,
        })
    }

    /// Returns true if this is a 64-bit PE.
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_64bit()
    }

    /// Returns true if this is a DLL.
    pub fn is_dll(&self) -> bool {
        self.coff_header.is_dll()
    }

    /// Get the image base address.
    pub fn image_base(&self) -> u64 {
        self.optional_header.image_base
    }

    /// Convert RVA to file offset.
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            let section_start = section.virtual_address;
            let section_end =
                section_start.saturating_add(section.virtual_size.max(section.size_of_raw_data));
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva.saturating_sub(section_start);
                return Some(
                    section
                        .pointer_to_raw_data
                        .saturating_add(offset_in_section) as usize,
                );
            }
        }
        None
    }

    /// Convert virtual address to file offset.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        if va < self.optional_header.image_base {
            return None;
        }
        let rva = va.saturating_sub(self.optional_header.image_base) as u32;
        self.rva_to_offset(rva)
    }
}

impl BinaryFormat for Pe<'_> {
    fn architecture(&self) -> Architecture {
        match self.coff_header.machine {
            IMAGE_FILE_MACHINE_AMD64 => Architecture::X86_64,
            IMAGE_FILE_MACHINE_I386 => Architecture::X86,
            IMAGE_FILE_MACHINE_ARM64 => Architecture::Arm64,
            other => Architecture::Unknown(other),
        }
    }

    fn endianness(&self) -> Endianness {
        // PE is always little-endian
        Endianness::Little
    }

    fn bitness(&self) -> Bitness {
        if self.is_64bit() {
            Bitness::Bits64
        } else {
            Bitness::Bits32
        }
    }

    fn entry_point(&self) -> Option<u64> {
        let rva = self.optional_header.address_of_entry_point;
        if rva == 0 {
            None
        } else {
            Some(self.optional_header.image_base.saturating_add(rva as u64))
        }
    }

    fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
        Box::new(
            self.sections
                .iter()
                .filter(|s| s.is_executable())
                .map(|s| s as &dyn Section),
        )
    }

    fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
        Box::new(self.sections.iter().map(|s| s as &dyn Section))
    }

    fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol> + '_> {
        Box::new(self.symbols.iter())
    }

    fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
        self.symbols.iter().find(|s| s.address == addr)
    }

    fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let offset = self.va_to_offset(addr)?;
        let available = self.data.len().checked_sub(offset)?;
        let actual_len = len.min(available);
        let end = offset.checked_add(actual_len)?;
        self.data.get(offset..end)
    }

    fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
        let rva = if addr >= self.optional_header.image_base {
            addr.saturating_sub(self.optional_header.image_base) as u32
        } else {
            return None;
        };

        for section in &self.sections {
            let section_end = section.virtual_address.saturating_add(section.virtual_size);
            if rva >= section.virtual_address && rva < section_end {
                return Some(section as &dyn Section);
            }
        }
        None
    }
}
