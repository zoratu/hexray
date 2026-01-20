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
        if pe_offset + 4 > data.len() {
            return Err(ParseError::too_short(pe_offset + 4, data.len()));
        }

        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);

        if pe_sig != PE_SIGNATURE {
            return Err(ParseError::invalid_magic(
                "PE\\0\\0",
                &data[pe_offset..pe_offset + 4],
            ));
        }

        // Parse COFF header
        let coff_offset = pe_offset + 4;
        let coff_header = CoffHeader::parse(&data[coff_offset..])?;

        // Parse optional header
        let opt_offset = coff_offset + 20;
        if opt_offset + 2 > data.len() {
            return Err(ParseError::too_short(opt_offset + 2, data.len()));
        }

        let opt_magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
        let optional_header = if opt_magic == PE32PLUS_MAGIC {
            OptionalHeader::parse_pe32plus(&data[opt_offset..])?
        } else {
            OptionalHeader::parse_pe32(&data[opt_offset..])?
        };

        // Parse section headers
        let sections_offset = opt_offset + coff_header.size_of_optional_header as usize;
        let mut sections = Vec::with_capacity(coff_header.number_of_sections as usize);
        let image_base = optional_header.image_base;

        for i in 0..coff_header.number_of_sections as usize {
            let sec_offset = sections_offset + i * section::SECTION_HEADER_SIZE;
            if sec_offset + section::SECTION_HEADER_SIZE > data.len() {
                break;
            }
            let mut section = SectionHeader::parse(&data[sec_offset..])?;
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
                address: image_base + e.rva as u64,
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
            let section_end = section_start + section.virtual_size.max(section.size_of_raw_data);
            if rva >= section_start && rva < section_end {
                let offset_in_section = rva - section_start;
                return Some((section.pointer_to_raw_data + offset_in_section) as usize);
            }
        }
        None
    }

    /// Convert virtual address to file offset.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        if va < self.optional_header.image_base {
            return None;
        }
        let rva = (va - self.optional_header.image_base) as u32;
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
            Some(self.optional_header.image_base + rva as u64)
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
        if offset >= self.data.len() {
            return None;
        }
        // Return what's available, up to the requested length
        let available = self.data.len() - offset;
        let actual_len = len.min(available);
        Some(&self.data[offset..offset + actual_len])
    }

    fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
        let rva = if addr >= self.optional_header.image_base {
            (addr - self.optional_header.image_base) as u32
        } else {
            return None;
        };

        for section in &self.sections {
            if rva >= section.virtual_address
                && rva < section.virtual_address + section.virtual_size
            {
                return Some(section as &dyn Section);
            }
        }
        None
    }
}
