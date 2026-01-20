//! ELF (Executable and Linkable Format) parser.
//!
//! This module provides a complete ELF parser built from scratch,
//! supporting both 32-bit and 64-bit formats.
//!
//! Supports:
//! - Executables (ET_EXEC)
//! - Shared objects (ET_DYN)
//! - Relocatable objects (ET_REL) - including Linux kernel modules (.ko)

mod header;
mod relocation;
mod section;
mod segment;
mod symbol;

pub use header::{ElfClass, ElfHeader, ElfType, Machine};
pub use relocation::{Relocation, RelocationType};
pub use section::SectionHeader;
pub use segment::ProgramHeader;
pub use symbol::SymbolEntry;
// KernelModuleInfo is defined in this module and is public

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
    /// Relocations (for ET_REL files).
    pub relocations: Vec<Relocation>,
    /// Kernel module info (if this is a .ko file).
    pub modinfo: Option<KernelModuleInfo>,
}

/// Kernel module information parsed from .modinfo section.
#[derive(Debug, Clone, Default)]
pub struct KernelModuleInfo {
    /// Module name.
    pub name: Option<String>,
    /// Module version.
    pub version: Option<String>,
    /// Module author.
    pub author: Option<String>,
    /// Module description.
    pub description: Option<String>,
    /// Module license.
    pub license: Option<String>,
    /// Source version (srcversion).
    pub srcversion: Option<String>,
    /// Module dependencies.
    pub depends: Vec<String>,
    /// Retpoline flag.
    pub retpoline: bool,
    /// Module vermagic string.
    pub vermagic: Option<String>,
    /// All key-value pairs from modinfo.
    pub all_info: Vec<(String, String)>,
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
        let section_names =
            if header.e_shstrndx > 0 && (header.e_shstrndx as usize) < sections.len() {
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

        // Populate section name and data caches for the Section trait
        let mut sections = sections;
        let is_relocatable = header.file_type == ElfType::Relocatable;
        for section in &mut sections {
            if let Some(name) = section_names.get(section.sh_name as usize) {
                section.set_name(name.to_string());
            }
            // Mark sections from relocatable files so virtual_address() returns sh_offset
            if is_relocatable {
                section.set_relocatable(true);
            }
            // Populate data cache for sections that have file data
            // (skip NOBITS sections like .bss which have no file data)
            if section.sh_type != section::SHT_NOBITS && section.sh_size > 0 {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if end <= data.len() {
                    section.set_data(data[start..end].to_vec());
                }
            }
        }

        // Parse symbols (with section base address adjustment for ET_REL)
        let symbols = Self::parse_symbols(data, &sections, &header, &section_names)?;

        // Parse relocations for relocatable files and dynamic binaries
        // - Relocatable files: need relocations for symbol resolution in decompilation
        // - Shared objects/executables: need GOT/PLT relocations for indirect call resolution
        let relocations = Self::parse_relocations(data, &sections, &header)?;

        // Parse kernel module info if present
        let modinfo = Self::parse_modinfo(data, &sections, &section_names);

        Ok(Self {
            data,
            header,
            sections,
            segments,
            symbols,
            section_names,
            relocations,
            modinfo,
        })
    }

    fn parse_section_headers(
        data: &[u8],
        header: &ElfHeader,
    ) -> Result<Vec<SectionHeader>, ParseError> {
        let mut sections = Vec::with_capacity(header.e_shnum as usize);
        let mut offset = header.e_shoff as usize;

        for _i in 0..header.e_shnum {
            if offset + header.e_shentsize as usize > data.len() {
                return Err(ParseError::too_short(
                    offset + header.e_shentsize as usize,
                    data.len(),
                ));
            }

            let section = SectionHeader::parse(&data[offset..], header.class, header.endianness)?;
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

            let segment = ProgramHeader::parse(&data[offset..], header.class, header.endianness)?;
            segments.push(segment);
            offset += header.e_phentsize as usize;
        }

        Ok(segments)
    }

    fn parse_symbols(
        data: &[u8],
        sections: &[SectionHeader],
        header: &ElfHeader,
        section_names: &StringTable,
    ) -> Result<Vec<Symbol>, ParseError> {
        let mut symbols = Vec::new();
        let is_relocatable = header.file_type == ElfType::Relocatable;

        // Find symbol table sections (.symtab and .dynsym)
        for section in sections.iter() {
            if section.sh_type != section::SHT_SYMTAB && section.sh_type != section::SHT_DYNSYM {
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
                let entry = SymbolEntry::parse(&data[offset..], header.class, header.endianness)?;

                let mut name = strtab.get(entry.st_name as usize).unwrap_or("").to_string();

                // Section symbols (STT_SECTION) have st_name=0, so use section name instead
                if name.is_empty()
                    && entry.st_shndx > 0
                    && (entry.st_shndx as usize) < sections.len()
                {
                    let sym_section = &sections[entry.st_shndx as usize];
                    if let Some(sec_name) = section_names.get(sym_section.sh_name as usize) {
                        name = sec_name.to_string();
                    }
                }

                let mut sym = entry.to_symbol(name);

                // For relocatable files, adjust symbol address to be globally unique
                // by adding the section's file offset
                if is_relocatable
                    && entry.st_shndx > 0
                    && (entry.st_shndx as usize) < sections.len()
                {
                    let sym_section = &sections[entry.st_shndx as usize];
                    // Use section file offset + symbol value as the address
                    sym.address = sym_section.sh_offset + entry.st_value;
                }

                symbols.push(sym);

                offset += entry_size;
            }
        }

        Ok(symbols)
    }

    fn parse_relocations(
        data: &[u8],
        sections: &[SectionHeader],
        header: &ElfHeader,
    ) -> Result<Vec<Relocation>, ParseError> {
        let mut relocations = Vec::new();
        let is_x86_64 = matches!(header.machine, Machine::X86_64);

        for section in sections.iter() {
            // RELA sections have an explicit addend
            if section.sh_type == section::SHT_RELA {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if end <= data.len() {
                    // sh_info tells us which section these relocations apply to
                    let target_section = section.sh_info as usize;
                    let relocs = Relocation::parse_rela(
                        &data[start..end],
                        section,
                        target_section,
                        header.class,
                        header.endianness,
                        is_x86_64,
                    )?;
                    relocations.extend(relocs);
                }
            }
            // REL sections have implicit addend (stored in the target location)
            else if section.sh_type == section::SHT_REL {
                let start = section.sh_offset as usize;
                let end = start + section.sh_size as usize;
                if end <= data.len() {
                    let target_section = section.sh_info as usize;
                    let relocs = Relocation::parse_rel(
                        &data[start..end],
                        section,
                        target_section,
                        header.class,
                        header.endianness,
                        is_x86_64,
                    )?;
                    relocations.extend(relocs);
                }
            }
        }

        Ok(relocations)
    }

    fn parse_modinfo(
        data: &[u8],
        sections: &[SectionHeader],
        section_names: &StringTable,
    ) -> Option<KernelModuleInfo> {
        // Find .modinfo section
        let modinfo_section = sections.iter().find(|s| {
            section_names
                .get(s.sh_name as usize)
                .map(|n| n == ".modinfo")
                .unwrap_or(false)
        })?;

        let start = modinfo_section.sh_offset as usize;
        let end = start + modinfo_section.sh_size as usize;
        if end > data.len() {
            return None;
        }

        let modinfo_data = &data[start..end];
        let mut info = KernelModuleInfo::default();

        // Parse null-terminated key=value pairs
        let mut offset = 0;
        while offset < modinfo_data.len() {
            // Find the end of this entry
            let entry_end = modinfo_data[offset..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| offset + p)
                .unwrap_or(modinfo_data.len());

            if entry_end > offset {
                if let Ok(entry_str) = std::str::from_utf8(&modinfo_data[offset..entry_end]) {
                    if let Some((key, value)) = entry_str.split_once('=') {
                        let key = key.trim();
                        let value = value.trim();

                        info.all_info.push((key.to_string(), value.to_string()));

                        match key {
                            "name" => info.name = Some(value.to_string()),
                            "version" => info.version = Some(value.to_string()),
                            "author" => info.author = Some(value.to_string()),
                            "description" => info.description = Some(value.to_string()),
                            "license" => info.license = Some(value.to_string()),
                            "srcversion" => info.srcversion = Some(value.to_string()),
                            "vermagic" => info.vermagic = Some(value.to_string()),
                            "depends" => {
                                info.depends = value
                                    .split(',')
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.trim().to_string())
                                    .collect();
                            }
                            "retpoline" => info.retpoline = value == "Y",
                            _ => {}
                        }
                    }
                }
            }

            offset = entry_end + 1;
        }

        // Only return if we found at least some module info
        if info.all_info.is_empty() {
            None
        } else {
            Some(info)
        }
    }

    /// Returns true if this is a kernel module (.ko file).
    pub fn is_kernel_module(&self) -> bool {
        self.modinfo.is_some()
    }

    /// Returns true if this is a relocatable object file.
    pub fn is_relocatable(&self) -> bool {
        self.header.file_type == ElfType::Relocatable
    }

    /// Returns the raw data of the ELF file.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Get bytes from a relocatable file using section-based addressing.
    ///
    /// For relocatable files, "addresses" are actually section offsets.
    /// We use a virtual addressing scheme where each section's base address
    /// is its file offset, allowing unique addresses across sections.
    fn bytes_at_relocatable(&self, addr: u64, len: usize) -> Option<&[u8]> {
        // For relocatable files, we use section file offsets as virtual addresses
        // This allows us to have unique addresses for all sections
        for section in &self.sections {
            // Skip sections without data
            if section.sh_type == section::SHT_NOBITS || section.sh_size == 0 {
                continue;
            }

            // Use section's file offset as its base address for relocatable files
            let section_base = section.sh_offset;
            let section_end = section_base + section.sh_size;

            if addr >= section_base && addr < section_end {
                let offset_in_section = (addr - section_base) as usize;
                let file_offset = section.sh_offset as usize + offset_in_section;
                let available = (section.sh_size as usize).saturating_sub(offset_in_section);
                let to_read = len.min(available);

                if file_offset + to_read <= self.data.len() {
                    return Some(&self.data[file_offset..file_offset + to_read]);
                }
            }
        }
        None
    }

    /// For kernel modules, get the base address of a section by name.
    /// In relocatable files, this returns the section's file offset.
    pub fn section_base_address(&self, name: &str) -> Option<u64> {
        self.section_by_name(name).map(|s| s.sh_offset)
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
        // For relocatable files (including kernel modules), use section-based lookup
        if self.header.file_type == ElfType::Relocatable {
            return self.bytes_at_relocatable(addr, len);
        }

        // For executables/shared objects, use segment-based lookup
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
                // Use virtual_address() which handles relocatable files correctly
                let start = s.virtual_address();
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
