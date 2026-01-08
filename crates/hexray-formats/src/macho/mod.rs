//! Mach-O (macOS/iOS) binary format parser.
//!
//! This module provides a complete Mach-O parser built from scratch,
//! supporting:
//! - 32-bit and 64-bit Mach-O files
//! - Universal (fat) binaries
//! - Common load commands
//! - Symbol tables

mod header;
mod load_command;
mod segment;
mod symbol;

pub use header::{CpuType, FileType, MachHeader, FatArch};
pub use load_command::LoadCommand;
pub use segment::{Segment, Section as MachSection};
pub use symbol::Nlist;

use crate::{BinaryFormat, ParseError, Section};
use hexray_core::{Architecture, Bitness, Endianness, Symbol, SymbolBinding, SymbolKind};

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
        if data.len() < offset + 4 {
            return Err(ParseError::too_short(4, data.len() - offset));
        }

        let magic = u32::from_ne_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Check for fat binary
        if magic == header::FAT_MAGIC || magic == header::FAT_CIGAM {
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
        for segment in &mut segments {
            for section in &mut segment.sections {
                section.populate_data(data);
            }
        }

        // Find string table and symbol table
        let mut strtab: &[u8] = &[];
        let mut symtab_offset = 0usize;
        let mut symtab_count = 0usize;

        for lc in &load_commands {
            if let LoadCommand::Symtab { stroff, strsize, symoff, nsyms } = lc {
                let str_start = offset + *stroff as usize;
                let str_end = str_start + *strsize as usize;
                if str_end <= data.len() {
                    strtab = &data[str_start..str_end];
                }
                symtab_offset = offset + *symoff as usize;
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
        let symbols = if symtab_count > 0 && symtab_offset > 0 {
            Self::parse_symbols(data, symtab_offset, symtab_count, is_64, strtab, &all_sections)?
        } else {
            Vec::new()
        };

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
        let arch = fat_header.architectures.iter()
            .find(|a| a.cputype == header::CPU_TYPE_X86_64)
            .or_else(|| fat_header.architectures.iter()
                .find(|a| a.cputype == header::CPU_TYPE_ARM64))
            .or_else(|| fat_header.architectures.first())
            .ok_or_else(|| ParseError::invalid_structure(
                "fat header",
                0,
                "no architectures in fat binary",
            ))?;

        Self::parse_at(data, arch.offset as usize)
    }

    fn parse_load_commands(
        data: &[u8],
        ncmds: usize,
        total_size: usize,
        is_64: bool,
    ) -> Result<Vec<LoadCommand>, ParseError> {
        let mut commands = Vec::with_capacity(ncmds);
        let mut offset = 0;

        for _ in 0..ncmds {
            if offset + 8 > data.len() || offset >= total_size {
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

            if cmdsize < 8 || offset + cmdsize > data.len() {
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

    fn parse_symbols(
        data: &[u8],
        offset: usize,
        count: usize,
        is_64: bool,
        strtab: &[u8],
        sections: &[&MachSection],
    ) -> Result<Vec<Symbol>, ParseError> {
        let entry_size = if is_64 { 16 } else { 12 };
        let mut symbols = Vec::with_capacity(count);

        for i in 0..count {
            let entry_offset = offset + i * entry_size;
            if entry_offset + entry_size > data.len() {
                break;
            }

            let nlist = Nlist::parse(&data[entry_offset..], is_64)?;

            // Get symbol name from string table
            let name = if (nlist.n_strx as usize) < strtab.len() {
                let name_bytes = &strtab[nlist.n_strx as usize..];
                let end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
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
                        return Some(text.vmaddr + *entryoff);
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
            if addr >= segment.vmaddr && addr < segment.vmaddr + segment.vmsize {
                let offset_in_seg = (addr - segment.vmaddr) as usize;
                if offset_in_seg < segment.filesize as usize {
                    let file_offset = self.offset + segment.fileoff as usize + offset_in_seg;
                    let available = (segment.filesize as usize).saturating_sub(offset_in_seg);
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
