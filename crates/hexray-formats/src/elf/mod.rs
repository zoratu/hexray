//! ELF (Executable and Linkable Format) parser.
//!
//! This module provides a complete ELF parser built from scratch,
//! supporting both 32-bit and 64-bit formats.

mod header;
mod section;
mod segment;
mod symbol;

pub use header::{ElfHeader, ElfClass, ElfType, Machine};
pub use section::SectionHeader;
pub use segment::ProgramHeader;
pub use symbol::SymbolEntry;

use crate::{BinaryFormat, ParseError, Section};
use hexray_core::{Architecture, Bitness, Endianness, Symbol};

/// A parsed ELF binary.
#[derive(Debug)]
pub struct Elf<'a> {
    /// Raw bytes of the file.
    data: &'a [u8],
    /// Parsed ELF header.
    pub header: ElfHeader,
    /// Section headers.
    pub sections: Vec<SectionHeader>,
    /// Program headers (segments).
    pub segments: Vec<ProgramHeader>,
    /// Parsed symbols.
    symbols: Vec<Symbol>,
    /// Section name string table.
    section_names: StringTable<'a>,
}

impl<'a> Elf<'a> {
    /// Parse an ELF file from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        // Parse the ELF header
        let header = ElfHeader::parse(data)?;

        // Parse section headers
        let sections = Self::parse_section_headers(data, &header)?;

        // Parse program headers
        let segments = Self::parse_program_headers(data, &header)?;

        // Get section name string table
        let section_names = if header.e_shstrndx > 0
            && (header.e_shstrndx as usize) < sections.len()
        {
            let shstrtab = &sections[header.e_shstrndx as usize];
            let start = shstrtab.sh_offset as usize;
            let end = start + shstrtab.sh_size as usize;
            if end <= data.len() {
                StringTable::new(&data[start..end])
            } else {
                StringTable::empty()
            }
        } else {
            StringTable::empty()
        };

        // Parse symbols
        let symbols = Self::parse_symbols(data, &sections, &header)?;

        Ok(Self {
            data,
            header,
            sections,
            segments,
            symbols,
            section_names,
        })
    }

    fn parse_section_headers(
        data: &[u8],
        header: &ElfHeader,
    ) -> Result<Vec<SectionHeader>, ParseError> {
        let mut sections = Vec::with_capacity(header.e_shnum as usize);
        let mut offset = header.e_shoff as usize;

        for i in 0..header.e_shnum {
            if offset + header.e_shentsize as usize > data.len() {
                return Err(ParseError::too_short(
                    offset + header.e_shentsize as usize,
                    data.len(),
                ));
            }

            let section = SectionHeader::parse(
                &data[offset..],
                header.class,
                header.endianness,
            )?;
            sections.push(section);
            offset += header.e_shentsize as usize;
        }

        Ok(sections)
    }

    fn parse_program_headers(
        data: &[u8],
        header: &ElfHeader,
    ) -> Result<Vec<ProgramHeader>, ParseError> {
        let mut segments = Vec::with_capacity(header.e_phnum as usize);
        let mut offset = header.e_phoff as usize;

        for _ in 0..header.e_phnum {
            if offset + header.e_phentsize as usize > data.len() {
                return Err(ParseError::too_short(
                    offset + header.e_phentsize as usize,
                    data.len(),
                ));
            }

            let segment = ProgramHeader::parse(
                &data[offset..],
                header.class,
                header.endianness,
            )?;
            segments.push(segment);
            offset += header.e_phentsize as usize;
        }

        Ok(segments)
    }

    fn parse_symbols(
        data: &[u8],
        sections: &[SectionHeader],
        header: &ElfHeader,
    ) -> Result<Vec<Symbol>, ParseError> {
        let mut symbols = Vec::new();

        // Find symbol table sections (.symtab and .dynsym)
        for (idx, section) in sections.iter().enumerate() {
            if section.sh_type != section::SHT_SYMTAB
                && section.sh_type != section::SHT_DYNSYM
            {
                continue;
            }

            // Get the associated string table
            let strtab_idx = section.sh_link as usize;
            if strtab_idx >= sections.len() {
                continue;
            }
            let strtab_section = &sections[strtab_idx];
            let strtab_start = strtab_section.sh_offset as usize;
            let strtab_end = strtab_start + strtab_section.sh_size as usize;
            if strtab_end > data.len() {
                continue;
            }
            let strtab = StringTable::new(&data[strtab_start..strtab_end]);

            // Parse symbol entries
            let sym_start = section.sh_offset as usize;
            let sym_end = sym_start + section.sh_size as usize;
            if sym_end > data.len() {
                continue;
            }

            let entry_size = section.sh_entsize as usize;
            if entry_size == 0 {
                continue;
            }

            let mut offset = sym_start;
            while offset + entry_size <= sym_end {
                let entry = SymbolEntry::parse(
                    &data[offset..],
                    header.class,
                    header.endianness,
                )?;

                let name = strtab.get(entry.st_name as usize).unwrap_or("");
                symbols.push(entry.to_symbol(name.to_string()));

                offset += entry_size;
            }
        }

        Ok(symbols)
    }

    /// Returns the section with the given name.
    pub fn section_by_name(&self, name: &str) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| {
            self.section_names
                .get(s.sh_name as usize)
                .map(|n| n == name)
                .unwrap_or(false)
        })
    }

    /// Returns the name of a section.
    pub fn section_name(&self, section: &SectionHeader) -> Option<&str> {
        self.section_names.get(section.sh_name as usize)
    }

    /// Returns the data for a section.
    pub fn section_data(&self, section: &SectionHeader) -> Option<&[u8]> {
        let start = section.sh_offset as usize;
        let end = start + section.sh_size as usize;
        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }
}

impl BinaryFormat for Elf<'_> {
    fn architecture(&self) -> Architecture {
        self.header.architecture()
    }

    fn endianness(&self) -> Endianness {
        self.header.endianness
    }

    fn bitness(&self) -> Bitness {
        match self.header.class {
            ElfClass::Elf32 => Bitness::Bits32,
            ElfClass::Elf64 => Bitness::Bits64,
        }
    }

    fn entry_point(&self) -> Option<u64> {
        if self.header.e_entry != 0 {
            Some(self.header.e_entry)
        } else {
            None
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
        // Find the segment containing this address
        for segment in &self.segments {
            if segment.p_type != segment::PT_LOAD {
                continue;
            }
            let seg_start = segment.p_vaddr;
            let seg_end = seg_start + segment.p_memsz;

            if addr >= seg_start && addr < seg_end {
                let offset_in_seg = (addr - seg_start) as usize;
                let file_offset = segment.p_offset as usize + offset_in_seg;
                let file_size = segment.p_filesz as usize;

                // Check if we're within the file-backed portion
                if offset_in_seg < file_size {
                    let available = file_size - offset_in_seg;
                    let to_read = len.min(available);
                    let end = file_offset + to_read;
                    if end <= self.data.len() {
                        return Some(&self.data[file_offset..end]);
                    }
                }
            }
        }
        None
    }

    fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
        self.sections
            .iter()
            .find(|s| {
                let start = s.sh_addr;
                let end = start + s.sh_size;
                addr >= start && addr < end
            })
            .map(|s| s as &dyn Section)
    }
}

/// A simple string table for null-terminated strings.
#[derive(Debug)]
struct StringTable<'a> {
    data: &'a [u8],
}

impl<'a> StringTable<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn empty() -> Self {
        Self { data: &[] }
    }

    fn get(&self, offset: usize) -> Option<&'a str> {
        if offset >= self.data.len() {
            return None;
        }
        let remaining = &self.data[offset..];
        let end = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&remaining[..end]).ok()
    }
}
