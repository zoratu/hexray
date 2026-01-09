//! hexray - A multi-architecture disassembler
//!
//! Usage:
//!   hexray <binary>              Disassemble the entry point
//!   hexray <binary> -s <symbol>  Disassemble a specific symbol/function
//!   hexray <binary> --sections   List sections
//!   hexray <binary> --symbols    List symbols

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hexray_analysis::{CfgBuilder, Decompiler, StringTable, SymbolTable, RelocationTable};
use hexray_core::Architecture;
use hexray_demangle::demangle_or_original;
use hexray_disasm::{Disassembler, X86_64Disassembler, Arm64Disassembler, RiscVDisassembler};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hexray")]
#[command(about = "A multi-architecture disassembler", long_about = None)]
struct Cli {
    /// Path to the binary file
    binary: PathBuf,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Disassemble a specific symbol/function
    #[arg(short, long)]
    symbol: Option<String>,

    /// Disassemble at a specific address
    #[arg(short, long, value_parser = parse_hex)]
    address: Option<u64>,

    /// Number of bytes/instructions to disassemble
    #[arg(short, long, default_value = "100")]
    count: usize,
}

#[derive(Subcommand)]
enum Commands {
    /// List sections in the binary
    Sections,
    /// List symbols in the binary
    Symbols {
        /// Filter to function symbols only
        #[arg(short, long)]
        functions: bool,
    },
    /// Show binary header information
    Info,
    /// Disassemble a function and show its CFG
    Cfg {
        /// Symbol name or address
        target: String,
    },
    /// Decompile a function to pseudo-code
    Decompile {
        /// Symbol name or address
        target: String,
        /// Show basic block address comments
        #[arg(long)]
        show_addresses: bool,
    },
}

fn parse_hex(s: &str) -> Result<u64, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| e.to_string())
}

/// Wrapper enum to hold either format
enum Binary<'a> {
    Elf(Elf<'a>),
    MachO(MachO<'a>),
    Pe(Pe<'a>),
}

impl<'a> Binary<'a> {
    fn as_format(&self) -> &dyn BinaryFormat {
        match self {
            Self::Elf(elf) => elf,
            Self::MachO(macho) => macho,
            Self::Pe(pe) => pe,
        }
    }

    fn format_name(&self) -> &'static str {
        match self {
            Self::Elf(_) => "ELF",
            Self::MachO(_) => "Mach-O",
            Self::Pe(_) => "PE",
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Read the binary file
    let data = fs::read(&cli.binary)
        .with_context(|| format!("Failed to read binary: {}", cli.binary.display()))?;

    // Detect and parse the binary format
    let binary = match detect_format(&data) {
        BinaryType::Elf => {
            let elf = Elf::parse(&data).context("Failed to parse ELF file")?;
            Binary::Elf(elf)
        }
        BinaryType::MachO => {
            let macho = MachO::parse(&data).context("Failed to parse Mach-O file")?;
            Binary::MachO(macho)
        }
        BinaryType::Pe => {
            let pe = Pe::parse(&data).context("Failed to parse PE file")?;
            Binary::Pe(pe)
        }
        BinaryType::Unknown => {
            bail!("Unknown binary format. Supported formats: ELF, Mach-O, PE");
        }
    };

    let fmt = binary.as_format();

    match cli.command {
        Some(Commands::Sections) => {
            print_sections(&binary);
        }
        Some(Commands::Symbols { functions }) => {
            print_symbols(fmt, functions);
        }
        Some(Commands::Info) => {
            print_info(&binary);
        }
        Some(Commands::Cfg { target }) => {
            disassemble_cfg(fmt, &target)?;
        }
        Some(Commands::Decompile { target, show_addresses }) => {
            decompile_function(&binary, &target, show_addresses)?;
        }
        None => {
            // Default: disassemble
            if let Some(symbol_name) = cli.symbol {
                disassemble_symbol(fmt, &symbol_name, cli.count)?;
            } else if let Some(addr) = cli.address {
                disassemble_at(fmt, addr, cli.count)?;
            } else if let Some(entry) = fmt.entry_point() {
                println!("Disassembling entry point at {:#x}\n", entry);
                disassemble_at(fmt, entry, cli.count)?;
            } else {
                println!("No entry point found. Use -s <symbol> or -a <address>");
            }
        }
    }

    Ok(())
}

fn print_info(binary: &Binary) {
    let fmt = binary.as_format();

    println!("Binary Information");
    println!("==================");
    println!("Format:        {}", binary.format_name());
    println!("Architecture:  {:?}", fmt.architecture());
    println!("Endianness:    {:?}", fmt.endianness());
    println!("Bitness:       {:?}", fmt.bitness());

    match binary {
        Binary::Elf(elf) => {
            println!("Type:          {:?}", elf.header.file_type);
            println!("Machine:       {:?}", elf.header.machine);
            if let Some(entry) = fmt.entry_point() {
                println!("Entry Point:   {:#x}", entry);
            }
            println!("\nSections:      {}", elf.sections.len());
            println!("Segments:      {}", elf.segments.len());

            // Display kernel module info if present
            if let Some(modinfo) = &elf.modinfo {
                println!("\nKernel Module Information");
                println!("-------------------------");
                if let Some(name) = &modinfo.name {
                    println!("Name:          {}", name);
                }
                if let Some(version) = &modinfo.version {
                    println!("Version:       {}", version);
                }
                if let Some(author) = &modinfo.author {
                    println!("Author:        {}", author);
                }
                if let Some(description) = &modinfo.description {
                    println!("Description:   {}", description);
                }
                if let Some(license) = &modinfo.license {
                    println!("License:       {}", license);
                }
                if let Some(srcversion) = &modinfo.srcversion {
                    println!("Srcversion:    {}", srcversion);
                }
                if let Some(vermagic) = &modinfo.vermagic {
                    println!("Vermagic:      {}", vermagic);
                }
                if !modinfo.depends.is_empty() {
                    println!("Dependencies:  {}", modinfo.depends.join(", "));
                }
                if modinfo.retpoline {
                    println!("Retpoline:     Yes");
                }

                // Print relocation count
                println!("\nRelocations:   {}", elf.relocations.len());
            }
        }
        Binary::MachO(macho) => {
            println!("Type:          {:?}", macho.header.filetype);
            println!("CPU Type:      {:?}", macho.header.cputype);
            if let Some(entry) = fmt.entry_point() {
                println!("Entry Point:   {:#x}", entry);
            }
            println!("\nSegments:      {}", macho.segments.len());
            println!("Load Commands: {}", macho.load_commands.len());

            // Print segments
            println!("\nSegments:");
            for seg in &macho.segments {
                println!("  {:<16} {:#016x} - {:#016x} ({} sections)",
                         seg.segname, seg.vmaddr, seg.vmaddr + seg.vmsize, seg.sections.len());
            }
        }
        Binary::Pe(pe) => {
            let pe_type = if pe.is_dll() { "DLL" } else { "Executable" };
            println!("Type:          {}", pe_type);
            println!("Machine:       {:#06x}", pe.coff_header.machine);
            println!("Image Base:    {:#x}", pe.image_base());
            if let Some(entry) = fmt.entry_point() {
                println!("Entry Point:   {:#x}", entry);
            }
            println!("\nSections:      {}", pe.sections.len());
            println!("Imports:       {}", pe.imports.len());
            println!("Exports:       {}", pe.exports.len());
        }
    }

    let sym_count: usize = fmt.symbols().count();
    println!("\nSymbols:       {}", sym_count);
}

fn print_sections(binary: &Binary) {
    println!("{:<4} {:<24} {:<16} {:<16} {:<8}",
             "Idx", "Name", "Address", "Size", "Flags");
    println!("{}", "-".repeat(75));

    match binary {
        Binary::Elf(elf) => {
            for (idx, section) in elf.sections.iter().enumerate() {
                let name = elf.section_name(section).unwrap_or("");
                let flags = format!("{}{}{}",
                    if section.is_allocated() { "A" } else { "-" },
                    if section.is_writable() { "W" } else { "-" },
                    if section.is_executable() { "X" } else { "-" },
                );

                println!("{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                         idx, name, section.sh_addr, section.sh_size, flags);
            }
        }
        Binary::MachO(macho) => {
            let mut idx = 0;
            for seg in &macho.segments {
                for section in &seg.sections {
                    let flags = format!("{}{}",
                        if section.is_allocated() { "A" } else { "-" },
                        if section.is_executable() { "X" } else { "-" },
                    );
                    let full_name = format!("{},{}", seg.segname, section.sectname);

                    println!("{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                             idx, full_name, section.addr, section.size, flags);
                    idx += 1;
                }
            }
        }
        Binary::Pe(pe) => {
            for (idx, section) in pe.sections.iter().enumerate() {
                let flags = section.flags_string();
                println!("{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                         idx, section.name,
                         pe.image_base() + section.virtual_address as u64,
                         section.virtual_size,
                         flags);
            }
        }
    }
}

fn print_symbols(fmt: &dyn BinaryFormat, functions_only: bool) {
    println!("{:<16} {:<8} {:<8} {:<8} {}",
             "Address", "Size", "Type", "Bind", "Name");
    println!("{}", "-".repeat(70));

    let mut symbols: Vec<_> = fmt.symbols().collect();
    symbols.sort_by_key(|s| s.address);

    for symbol in symbols {
        if functions_only && !symbol.is_function() {
            continue;
        }
        if symbol.name.is_empty() {
            continue;
        }

        let type_str = match symbol.kind {
            hexray_core::SymbolKind::Function => "FUNC",
            hexray_core::SymbolKind::Object => "OBJ",
            hexray_core::SymbolKind::Section => "SECT",
            hexray_core::SymbolKind::File => "FILE",
            _ => "OTHER",
        };

        let bind_str = match symbol.binding {
            hexray_core::SymbolBinding::Local => "LOCAL",
            hexray_core::SymbolBinding::Global => "GLOBAL",
            hexray_core::SymbolBinding::Weak => "WEAK",
            _ => "OTHER",
        };

        let demangled = demangle_or_original(&symbol.name);

        println!("{:#016x} {:<8} {:<8} {:<8} {}",
                 symbol.address, symbol.size, type_str, bind_str, demangled);
    }
}

/// Find a symbol by name, preferring exact matches over partial matches.
/// For function decompilation, we want the most specific match.
fn find_symbol(fmt: &dyn BinaryFormat, name: &str) -> Option<hexray_core::Symbol> {
    // Collect symbols into owned values
    let symbols: Vec<hexray_core::Symbol> = fmt.symbols().cloned().collect();

    // 1. Try exact match first (highest priority)
    if let Some(sym) = symbols.iter().find(|s| s.name == name) {
        return Some(sym.clone());
    }

    // 2. Try exact match on demangled name
    if let Some(sym) = symbols.iter().find(|s| demangle_or_original(&s.name) == name) {
        return Some(sym.clone());
    }

    // 3. Try prefix match (e.g., "nfsd_open" matches "nfsd_open.cold")
    //    Prefer function symbols and shorter names
    let mut prefix_matches: Vec<hexray_core::Symbol> = symbols.iter()
        .filter(|s| s.name.starts_with(name) || demangle_or_original(&s.name).starts_with(name))
        .cloned()
        .collect();
    prefix_matches.sort_by(|a, b| {
        // Prefer functions over non-functions
        let a_is_func = a.is_function() as u8;
        let b_is_func = b.is_function() as u8;
        b_is_func.cmp(&a_is_func)
            .then_with(|| a.name.len().cmp(&b.name.len())) // Shorter names preferred
    });
    if !prefix_matches.is_empty() {
        return Some(prefix_matches.remove(0));
    }

    // 4. Try contains match as last resort (lowest priority)
    //    Only match function symbols, and prefer shorter names
    let mut contains_matches: Vec<hexray_core::Symbol> = symbols.iter()
        .filter(|s| s.is_function() && (s.name.contains(name) || demangle_or_original(&s.name).contains(name)))
        .cloned()
        .collect();
    contains_matches.sort_by(|a, b| a.name.len().cmp(&b.name.len()));
    if !contains_matches.is_empty() {
        return Some(contains_matches.remove(0));
    }

    None
}

fn disassemble_symbol(fmt: &dyn BinaryFormat, name: &str, max_count: usize) -> Result<()> {
    // Find the symbol - prefer exact matches, then prefix matches, then contains
    let symbol = find_symbol(fmt, name)
        .with_context(|| format!("Symbol '{}' not found", name))?;

    println!("Disassembling {} at {:#x} (size: {} bytes)\n",
             demangle_or_original(&symbol.name), symbol.address, symbol.size);

    let size = if symbol.size > 0 {
        symbol.size as usize
    } else {
        max_count * 15 // Estimate: max x86 instruction is 15 bytes
    };

    disassemble_at(fmt, symbol.address, size.min(max_count * 15))
}

fn disassemble_at(fmt: &dyn BinaryFormat, address: u64, max_bytes: usize) -> Result<()> {
    let bytes = fmt
        .bytes_at(address, max_bytes)
        .with_context(|| format!("Cannot read bytes at {:#x}", address))?;

    let arch = fmt.architecture();
    let mut offset = 0;
    let mut count = 0;

    // Use the appropriate disassembler based on architecture
    match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_with(&disasm, fmt, bytes, address, &mut offset, &mut count)?;
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_with(&disasm, fmt, bytes, address, &mut offset, &mut count)?;
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_with(&disasm, fmt, bytes, address, &mut offset, &mut count)?;
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_with(&disasm, fmt, bytes, address, &mut offset, &mut count)?;
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    }

    Ok(())
}

fn disassemble_with<D: Disassembler>(
    disasm: &D,
    fmt: &dyn BinaryFormat,
    bytes: &[u8],
    address: u64,
    offset: &mut usize,
    count: &mut usize,
) -> Result<()> {
    while *offset < bytes.len() && *count < 100 {
        let remaining = &bytes[*offset..];
        let addr = address + *offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                // Check for symbol at this address
                if let Some(sym) = fmt.symbol_at(addr) {
                    if !sym.name.is_empty() {
                        println!("\n<{}>:", demangle_or_original(&sym.name));
                    }
                }

                println!("{}", decoded.instruction);
                *offset += decoded.size;
                *count += 1;

                // Stop at return
                if decoded.instruction.is_return() {
                    break;
                }
            }
            Err(e) => {
                println!("{:#010x}:  {:02x}                      <decode error: {}>",
                         addr, remaining[0], e);
                *offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    Ok(())
}

fn disassemble_cfg(fmt: &dyn BinaryFormat, target: &str) -> Result<()> {
    // Try to parse as address first
    let address = if let Some(stripped) = target.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        u64::from_str_radix(target, 16).ok()
    };

    let (start_addr, name) = if let Some(addr) = address {
        (addr, format!("sub_{:x}", addr))
    } else {
        // Find symbol using improved search
        let symbol = find_symbol(fmt, target)
            .with_context(|| format!("Symbol '{}' not found", target))?;
        (symbol.address, demangle_or_original(&symbol.name))
    };

    println!("Building CFG for {} at {:#x}\n", name, start_addr);

    // Disassemble instructions
    let bytes = fmt
        .bytes_at(start_addr, 4096)
        .context("Cannot read bytes")?;

    let arch = fmt.architecture();
    let instructions = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    };

    // Build CFG
    let cfg = CfgBuilder::build(&instructions, start_addr);

    println!("CFG has {} basic blocks\n", cfg.num_blocks());

    // Print each block
    for block_id in cfg.reverse_post_order() {
        let block = cfg.block(block_id).unwrap();
        println!("{}:  ; [{:#x} - {:#x})", block_id, block.start, block.end);

        for inst in &block.instructions {
            println!("    {}", inst);
        }

        // Print successors
        let succs = cfg.successors(block_id);
        if !succs.is_empty() {
            let succ_strs: Vec<_> = succs.iter().map(|s| format!("{}", s)).collect();
            println!("    ; -> {}", succ_strs.join(", "));
        }
        println!();
    }

    Ok(())
}

fn disassemble_for_cfg<D: Disassembler>(
    disasm: &D,
    bytes: &[u8],
    start_addr: u64,
) -> Vec<hexray_core::Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;

                if is_ret {
                    break;
                }
            }
            Err(_) => {
                offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    instructions
}

fn decompile_function(binary: &Binary, target: &str, show_addresses: bool) -> Result<()> {
    let fmt = binary.as_format();

    // Try to parse as address first
    let address = if let Some(stripped) = target.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        u64::from_str_radix(target, 16).ok()
    };

    let (start_addr, name) = if let Some(addr) = address {
        (addr, format!("sub_{:x}", addr))
    } else {
        // Find symbol using improved search
        let symbol = find_symbol(fmt, target)
            .with_context(|| format!("Symbol '{}' not found", target))?;
        (symbol.address, demangle_or_original(&symbol.name))
    };

    println!("Decompiling {} at {:#x}\n", name, start_addr);

    // Disassemble instructions
    let bytes = fmt
        .bytes_at(start_addr, 4096)
        .context("Cannot read bytes")?;

    let arch = fmt.architecture();
    let instructions = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_for_cfg(&disasm, bytes, start_addr)
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    };

    // Build CFG
    let cfg = CfgBuilder::build(&instructions, start_addr);

    // Build string table from data sections
    let string_table = build_string_table(fmt);

    // Build symbol table for function names
    let symbol_table = build_symbol_table(fmt);

    // Build relocation table for kernel modules
    let relocation_table = build_relocation_table(binary);

    // Decompile
    let decompiler = Decompiler::new()
        .with_addresses(show_addresses)
        .with_string_table(string_table)
        .with_symbol_table(symbol_table)
        .with_relocation_table(relocation_table);
    let pseudocode = decompiler.decompile(&cfg, &name);

    println!("{}", pseudocode);

    Ok(())
}

/// Builds a string table from readable data sections in the binary.
fn build_string_table(fmt: &dyn BinaryFormat) -> StringTable {
    let mut table = StringTable::new();

    // Look for common data section names
    for section in fmt.sections() {
        let name = section.name().to_lowercase();
        // Include read-only data sections, string sections, and const sections
        if name.contains("rodata") || name.contains("cstring") ||
           name.contains("__const") || name.contains("data") ||
           name.contains("rdata") {
            // Get section data directly
            let data = section.data();
            let addr = section.virtual_address();
            if !data.is_empty() {
                // Extract strings from this section
                let section_strings = StringTable::from_binary_data(data, addr);
                table.merge(&section_strings);
            }
        }
    }

    table
}

/// Builds a symbol table from the binary's symbols.
fn build_symbol_table(fmt: &dyn BinaryFormat) -> SymbolTable {
    let mut table = SymbolTable::new();

    // Add all function symbols
    for symbol in fmt.symbols() {
        if symbol.is_function() && symbol.address != 0 {
            table.insert(symbol.address, symbol.name.clone());
        }
    }

    table
}

/// Builds a relocation table from ELF relocations.
///
/// For kernel modules and other relocatable files, call instructions have
/// unresolved targets. This table maps call instruction addresses to the
/// actual target symbol names based on relocation entries.
///
/// For dynamically linked binaries, this also populates GOT/PLT symbol mappings
/// to resolve indirect calls through the GOT.
fn build_relocation_table(binary: &Binary) -> RelocationTable {
    use hexray_formats::RelocationType;

    let mut table = RelocationTable::new();

    // Only ELF files have relocations we need to process
    let elf = match binary {
        Binary::Elf(elf) => elf,
        _ => return table,
    };

    // Collect symbols for lookup by index
    let symbols: Vec<_> = elf.symbols().collect();

    // Process relocations - each relocation has a section_index telling us which section it applies to
    for reloc in &elf.relocations {
        if let Some(symbol) = symbols.get(reloc.symbol_index as usize) {
            if symbol.name.is_empty() {
                continue;
            }

            match reloc.r_type {
                // GOT entry relocations - map GOT address to symbol name
                // These are used for indirect calls: call [rip + offset] -> call through GOT
                RelocationType::GlobDat | RelocationType::JumpSlot => {
                    // The relocation offset is the virtual address of the GOT entry
                    table.insert_got(reloc.offset, symbol.name.clone());
                }
                // PC-relative relocations (for calls/jumps in relocatable objects)
                RelocationType::Pc32 | RelocationType::Plt32 => {
                    if let Some(section) = elf.sections.get(reloc.section_index) {
                        // For x86_64 call E8 xx xx xx xx, the relocation points to the displacement
                        // The call opcode (E8) is at offset-1 from the relocation
                        let call_addr = section.sh_offset + reloc.offset - 1;
                        table.insert(call_addr, symbol.name.clone());
                    }
                }
                // 32-bit signed immediate relocations (for mov reg, imm32)
                // mov rdi, 0x0 = 48 C7 C7 xx xx xx xx (7 bytes)
                // relocation points to offset+3 (the immediate)
                RelocationType::R32S => {
                    if let Some(section) = elf.sections.get(reloc.section_index) {
                        // Instruction starts 3 bytes before the relocation offset
                        // for "mov reg, imm32" with REX prefix
                        let inst_addr = section.sh_offset + reloc.offset - 3;
                        table.insert_data(inst_addr, symbol.name.clone());
                    }
                }
                // 64-bit absolute relocations
                RelocationType::R64 => {
                    if let Some(section) = elf.sections.get(reloc.section_index) {
                        // For movabs, the relocation points to the immediate
                        let inst_addr = section.sh_offset + reloc.offset - 2;
                        table.insert_data(inst_addr, symbol.name.clone());
                    }
                }
                _ => {}
            }
        }
    }

    table
}
