//! Mach-O (macOS/iOS) binary format parser.
//!
//! This module provides a complete Mach-O parser built from scratch,
//! supporting:
//! - 32-bit and 64-bit Mach-O files
//! - Universal (fat) binaries
//! - Common load commands
//! - Symbol tables

#![allow(dead_code)]

mod header;
mod load_command;
mod segment;
mod symbol;

pub use header::{CpuType, FatArch, FileType, MachHeader};
pub use load_command::LoadCommand;
pub use segment::{Section as MachSection, Segment};
pub use symbol::Nlist;

use crate::{BinaryFormat, ParseError, Section};
use hexray_core::{Architecture, Bitness, Endianness, Symbol, SymbolKind};

/// A parsed Mach-O binary.
#[derive(Debug)]
pub struct MachO<'a> {
    /// Raw bytes of the file.
    data: &'a [u8],
    /// Offset into data where this Mach-O starts (for fat binaries).
    offset: usize,
    /// Parsed Mach-O header.
    pub header: MachHeader,
    /// Load commands.
    pub load_commands: Vec<LoadCommand>,
    /// Segments.
    pub segments: Vec<Segment>,
    /// Parsed symbols.
    symbols: Vec<Symbol>,
    /// String table data.
    strtab: &'a [u8],
}

impl<'a> MachO<'a> {
    /// Parse a Mach-O file from raw bytes.
    ///
    /// This handles both regular Mach-O files and universal (fat) binaries.
    /// For fat binaries, it selects the best architecture match for the host.
    pub fn parse(data: &'a [u8]) -> Result<Self, ParseError> {
        Self::parse_at(data, 0)
    }

    /// Parse a Mach-O file at a specific offset.
    pub fn parse_at(data: &'a [u8], offset: usize) -> Result<Self, ParseError> {
        Self::parse_at_internal(data, offset, true)
    }

    /// Internal parse function with recursion control.
    fn parse_at_internal(
        data: &'a [u8],
        offset: usize,
        allow_fat: bool,
    ) -> Result<Self, ParseError> {
        if data.len() < offset.saturating_add(4) {
            return Err(ParseError::too_short(4, data.len().saturating_sub(offset)));
        }

        let magic = u32::from_ne_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Check for fat binary (only at top level)
        if allow_fat && (magic == header::FAT_MAGIC || magic == header::FAT_CIGAM) {
            return Self::parse_fat(data);
        }

        // Parse regular Mach-O
        let header = MachHeader::parse(&data[offset..])?;
        let is_64 = header.is_64bit();

        // Parse load commands
        let lc_offset = offset + header.header_size();
        let load_commands = Self::parse_load_commands(
            &data[lc_offset..],
            header.ncmds as usize,
            header.sizeofcmds as usize,
            is_64,
        )?;

        // Extract segments and populate section data
        let mut segments: Vec<Segment> = load_commands
            .iter()
            .filter_map(|lc| {
                if let LoadCommand::Segment(seg) = lc {
                    Some(seg.clone())
                } else if let LoadCommand::Segment64(seg) = lc {
                    Some(seg.clone())
                } else {
                    None
                }
            })
            .collect();

        // Populate section data caches
        // For fat binaries, section offsets are relative to the slice, not the whole file
        // So we need to pass the slice starting at 'offset'
        let slice_data = &data[offset..];
        for segment in &mut segments {
            for section in &mut segment.sections {
                section.populate_data(slice_data);
            }
        }

        // Find string table and symbol table
        let mut strtab: &[u8] = &[];
        let mut symtab_offset = 0usize;
        let mut symtab_count = 0usize;

        for lc in &load_commands {
            if let LoadCommand::Symtab {
                stroff,
                strsize,
                symoff,
                nsyms,
            } = lc
            {
                let str_start = offset.saturating_add(*stroff as usize);
                let str_end = str_start.saturating_add(*strsize as usize);
                if str_end <= data.len() && str_end > str_start {
                    strtab = &data[str_start..str_end];
                }
                symtab_offset = offset.saturating_add(*symoff as usize);
                symtab_count = *nsyms as usize;
            }
        }

        // Build a flat list of sections for symbol kind detection
        // Sections are numbered 1-based across all segments
        let all_sections: Vec<&MachSection> = segments
            .iter()
            .flat_map(|seg| seg.sections.iter())
            .collect();

        // Parse symbols
        let mut symbols = if symtab_count > 0 && symtab_offset > 0 {
            Self::parse_symbols(
                data,
                symtab_offset,
                symtab_count,
                is_64,
                strtab,
                &all_sections,
            )?
        } else {
            Vec::new()
        };

        // Parse stub symbols (map stub addresses to import symbol names)
        let stub_symbols = Self::parse_stub_symbols(
            data,
            offset,
            &load_commands,
            &segments,
            strtab,
            symtab_offset,
            symtab_count,
            is_64,
        );
        symbols.extend(stub_symbols);

        // Estimate symbol sizes based on neighboring symbols
        Self::estimate_symbol_sizes(&mut symbols, &segments);

        Ok(Self {
            data,
            offset,
            header,
            load_commands,
            segments,
            symbols,
            strtab,
        })
    }

    /// Parse a fat (universal) binary and select the best architecture.
    fn parse_fat(data: &'a [u8]) -> Result<Self, ParseError> {
        let fat_header = header::FatHeader::parse(data)?;

        // Prefer x86_64, then arm64, then first available
        let arch = fat_header
            .architectures
            .iter()
            .find(|a| a.cputype == header::CPU_TYPE_X86_64)
            .or_else(|| {
                fat_header
                    .architectures
                    .iter()
                    .find(|a| a.cputype == header::CPU_TYPE_ARM64)
            })
            .or_else(|| fat_header.architectures.first())
            .ok_or_else(|| {
                ParseError::invalid_structure("fat header", 0, "no architectures in fat binary")
            })?;

        // Don't allow nested fat binaries (prevent infinite recursion)
        Self::parse_at_internal(data, arch.offset as usize, false)
    }

    fn parse_load_commands(
        data: &[u8],
        ncmds: usize,
        total_size: usize,
        is_64: bool,
    ) -> Result<Vec<LoadCommand>, ParseError> {
        let mut commands = Vec::with_capacity(ncmds.min(1000));
        let mut offset: usize = 0;

        for _ in 0..ncmds {
            if offset.saturating_add(8) > data.len() || offset >= total_size {
                break;
            }

            let cmd = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            let cmdsize = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]) as usize;

            if cmdsize < 8 || offset.saturating_add(cmdsize) > data.len() {
                break;
            }

            let cmd_data = &data[offset..offset + cmdsize];
            if let Some(lc) = LoadCommand::parse(cmd, cmd_data, is_64)? {
                commands.push(lc);
            }

            offset += cmdsize;
        }

        Ok(commands)
    }

    /// Parse stub symbols from the __stubs section.
    /// This maps stub addresses to their corresponding import symbol names.
    #[allow(clippy::too_many_arguments)]
    fn parse_stub_symbols(
        data: &[u8],
        file_offset: usize,
        load_commands: &[LoadCommand],
        segments: &[Segment],
        strtab: &[u8],
        symtab_offset: usize,
        symtab_count: usize,
        is_64: bool,
    ) -> Vec<Symbol> {
        let mut stub_symbols = Vec::new();

        // Find indirect symbol table info from LC_DYSYMTAB
        let (indirect_symoff, _nindirect) = load_commands
            .iter()
            .find_map(|lc| {
                if let LoadCommand::Dysymtab {
                    indirectsymoff,
                    nindirectsyms,
                    ..
                } = lc
                {
                    Some((*indirectsymoff, *nindirectsyms))
                } else {
                    None
                }
            })
            .unwrap_or((0, 0));

        if indirect_symoff == 0 || symtab_offset == 0 {
            return stub_symbols;
        }

        // Find the __stubs section
        let stubs_section = segments
            .iter()
            .flat_map(|seg| seg.sections.iter())
            .find(|sect| sect.sectname == "__stubs");

        let Some(stubs) = stubs_section else {
            return stub_symbols;
        };

        // reserved1 contains the index into the indirect symbol table
        let indirect_start_index = stubs.reserved1 as usize;
        // reserved2 contains the stub size (on ARM64 it's 12 bytes typically)
        let stub_size = if stubs.reserved2 > 0 {
            stubs.reserved2 as usize
        } else {
            // Default stub sizes by architecture
            if is_64 {
                12
            } else {
                6
            }
        };

        if stub_size == 0 {
            return stub_symbols;
        }

        let num_stubs = stubs.size as usize / stub_size;
        let entry_size = if is_64 { 16 } else { 12 };

        for i in 0..num_stubs {
            // Read the indirect symbol table entry (4 bytes each)
            let indirect_offset = file_offset
                .saturating_add(indirect_symoff as usize)
                .saturating_add((indirect_start_index + i).saturating_mul(4));
            if indirect_offset.saturating_add(4) > data.len() {
                break;
            }

            let sym_index = u32::from_le_bytes([
                data[indirect_offset],
                data[indirect_offset + 1],
                data[indirect_offset + 2],
                data[indirect_offset + 3],
            ]) as usize;

            // Skip special indirect symbol values
            const INDIRECT_SYMBOL_LOCAL: u32 = 0x80000000;
            const INDIRECT_SYMBOL_ABS: u32 = 0x40000000;
            if sym_index as u32 == INDIRECT_SYMBOL_LOCAL || sym_index as u32 == INDIRECT_SYMBOL_ABS
            {
                continue;
            }

            // Look up the symbol in the main symbol table
            if sym_index >= symtab_count {
                continue;
            }

            let sym_offset = symtab_offset.saturating_add(sym_index.saturating_mul(entry_size));
            if sym_offset.saturating_add(entry_size) > data.len() {
                continue;
            }

            // Parse the nlist to get the name
            if let Ok(nlist) = Nlist::parse(&data[sym_offset..], is_64) {
                let name = if (nlist.n_strx as usize) < strtab.len() {
                    let name_bytes = &strtab[nlist.n_strx as usize..];
                    let end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    String::from_utf8_lossy(&name_bytes[..end]).to_string()
                } else {
                    continue;
                };

                if name.is_empty() {
                    continue;
                }

                // Create a symbol at the stub address
                let stub_addr = stubs.addr + (i * stub_size) as u64;
                stub_symbols.push(Symbol {
                    name,
                    address: stub_addr,
                    size: stub_size as u64,
                    kind: SymbolKind::Function,
                    binding: hexray_core::SymbolBinding::Global,
                    section_index: None,
                });
            }
        }

        stub_symbols
    }

    fn parse_symbols(
        data: &[u8],
        offset: usize,
        count: usize,
        is_64: bool,
        strtab: &[u8],
        sections: &[&MachSection],
    ) -> Result<Vec<Symbol>, ParseError> {
        let entry_size = if is_64 { 16 } else { 12 };
        let mut symbols = Vec::with_capacity(count.min(100_000));

        for i in 0..count {
            let entry_offset = offset.saturating_add(i.saturating_mul(entry_size));
            if entry_offset.saturating_add(entry_size) > data.len() {
                break;
            }

            let nlist = Nlist::parse(&data[entry_offset..], is_64)?;

            // Get symbol name from string table
            let name = if (nlist.n_strx as usize) < strtab.len() {
                let name_bytes = &strtab[nlist.n_strx as usize..];
                let end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                String::from_utf8_lossy(&name_bytes[..end]).to_string()
            } else {
                String::new()
            };

            // Determine symbol kind based on section properties
            let kind = if nlist.is_stab() {
                SymbolKind::Other(nlist.n_type)
            } else if !nlist.is_defined() {
                SymbolKind::None
            } else if nlist.n_sect > 0 {
                // n_sect is 1-based, convert to 0-based index
                let sect_idx = (nlist.n_sect - 1) as usize;
                if sect_idx < sections.len() {
                    use crate::Section as SectionTrait;
                    if sections[sect_idx].is_executable() {
                        SymbolKind::Function
                    } else {
                        SymbolKind::Object
                    }
                } else {
                    SymbolKind::None
                }
            } else {
                SymbolKind::None
            };

            let mut symbol = nlist.to_symbol(name);
            symbol.kind = kind;
            symbols.push(symbol);
        }

        Ok(symbols)
    }

    /// Estimate symbol sizes based on the distance to the next symbol.
    ///
    /// Mach-O nlist entries don't contain size information, so we estimate
    /// the size of each symbol by looking at the address of the next symbol
    /// in the same section.
    fn estimate_symbol_sizes(symbols: &mut [Symbol], segments: &[Segment]) {
        if symbols.is_empty() {
            return;
        }

        // Build a map of section ranges for bounds checking
        let section_bounds: Vec<(u64, u64)> = segments
            .iter()
            .flat_map(|seg| seg.sections.iter())
            .map(|sect| (sect.addr, sect.addr.saturating_add(sect.size)))
            .collect();

        // Sort symbols by address for efficient neighbor lookup
        // We work on indices to avoid ownership issues
        let mut sorted_indices: Vec<usize> = (0..symbols.len()).collect();
        sorted_indices.sort_by_key(|&i| symbols[i].address);

        // For each symbol, find the next symbol in the same section
        for i in 0..sorted_indices.len() {
            let idx = sorted_indices[i];
            let sym = &symbols[idx];

            // Skip symbols that already have a size or are undefined
            if sym.size > 0 || sym.address == 0 {
                continue;
            }

            // Find which section this symbol belongs to
            let sym_section = section_bounds
                .iter()
                .position(|(start, end)| sym.address >= *start && sym.address < *end);

            let Some(sect_idx) = sym_section else {
                continue;
            };

            let (sect_start, sect_end) = section_bounds[sect_idx];

            // Look for the next symbol in the same section
            let mut estimated_size = None;
            for &next_idx in &sorted_indices[(i + 1)..] {
                let next_sym = &symbols[next_idx];

                // Check if next symbol is in the same section
                if next_sym.address >= sect_start && next_sym.address < sect_end {
                    // Found the next symbol in the same section
                    estimated_size = Some(next_sym.address - sym.address);
                    break;
                }

                // If next symbol is beyond our section, stop looking
                if next_sym.address >= sect_end {
                    break;
                }
            }

            // If no next symbol found, use distance to section end (with reasonable cap)
            let size = estimated_size.unwrap_or_else(|| {
                let to_end = sect_end.saturating_sub(sym.address);
                to_end.min(4096) // Cap at 4KB for safety
            });

            // Apply the estimated size (cap at reasonable maximum)
            symbols[idx].size = size.min(65536); // Cap at 64KB
        }
    }

    /// Returns the data for this Mach-O (accounting for fat binary offset).
    fn macho_data(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    /// Get a segment by name.
    pub fn segment_by_name(&self, name: &str) -> Option<&Segment> {
        self.segments.iter().find(|s| s.segname == name)
    }

    /// Get __TEXT segment.
    pub fn text_segment(&self) -> Option<&Segment> {
        self.segment_by_name("__TEXT")
    }
}

impl BinaryFormat for MachO<'_> {
    fn architecture(&self) -> Architecture {
        self.header.architecture()
    }

    fn endianness(&self) -> Endianness {
        // Mach-O on x86/ARM is always little-endian in practice
        Endianness::Little
    }

    fn bitness(&self) -> Bitness {
        if self.header.is_64bit() {
            Bitness::Bits64
        } else {
            Bitness::Bits32
        }
    }

    fn entry_point(&self) -> Option<u64> {
        // Look for LC_MAIN or LC_UNIXTHREAD
        for lc in &self.load_commands {
            match lc {
                LoadCommand::Main { entryoff, .. } => {
                    // entryoff is relative to __TEXT segment
                    if let Some(text) = self.text_segment() {
                        return Some(text.vmaddr.saturating_add(*entryoff));
                    }
                }
                LoadCommand::UnixThread { entry_point, .. } => {
                    return Some(*entry_point);
                }
                _ => {}
            }
        }
        None
    }

    fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
        Box::new(
            self.segments
                .iter()
                .flat_map(|seg| seg.sections.iter())
                .filter(|s| s.is_executable())
                .map(|s| s as &dyn Section),
        )
    }

    fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
        Box::new(
            self.segments
                .iter()
                .flat_map(|seg| seg.sections.iter())
                .map(|s| s as &dyn Section),
        )
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
            if addr >= segment.vmaddr && addr < segment.vmaddr.saturating_add(segment.vmsize) {
                let offset_in_seg = (addr - segment.vmaddr) as usize;
                if offset_in_seg < segment.filesize as usize {
                    let file_offset = self
                        .offset
                        .saturating_add(segment.fileoff as usize)
                        .saturating_add(offset_in_seg);
                    let available = (segment.filesize as usize).saturating_sub(offset_in_seg);
                    let to_read = len.min(available);
                    let end = file_offset.saturating_add(to_read);
                    if end <= self.data.len() && end > file_offset {
                        return Some(&self.data[file_offset..end]);
                    }
                }
            }
        }
        None
    }

    fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
        for segment in &self.segments {
            for section in &segment.sections {
                if addr >= section.addr && addr < section.addr + section.size {
                    return Some(section as &dyn Section);
                }
            }
        }
        None
    }
}
