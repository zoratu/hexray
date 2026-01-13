//! hexray - A multi-architecture disassembler
//!
//! Usage:
//!   hexray <binary>              Disassemble the entry point
//!   hexray <binary> -s <symbol>  Disassemble a specific symbol/function
//!   hexray <binary> --sections   List sections
//!   hexray <binary> --symbols    List symbols

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hexray_analysis::{
    CallGraphBuilder, CallGraphDotExporter, CallGraphHtmlExporter, CallGraphJsonExporter,
    CfgBuilder, CfgDotExporter, CfgHtmlExporter, CfgJsonExporter,
    Decompiler, FunctionInfo, ParallelCallGraphBuilder, StringTable, SymbolTable, RelocationTable,
    StringDetector, StringConfig, XrefBuilder, XrefType,
};
use hexray_core::Architecture;
use hexray_demangle::demangle_or_original;
use hexray_disasm::{Disassembler, X86_64Disassembler, Arm64Disassembler, RiscVDisassembler};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use hexray_formats::dwarf::{parse_debug_info, DebugInfo};
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
        /// Output in Graphviz DOT format
        #[arg(long)]
        dot: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Output in interactive HTML format
        #[arg(long)]
        html: bool,
    },
    /// Decompile a function to pseudo-code
    Decompile {
        /// Symbol name or address (defaults to entry point or main)
        target: Option<String>,
        /// Show basic block address comments
        #[arg(long)]
        show_addresses: bool,
        /// Follow and decompile internal called functions
        #[arg(long, short = 'f')]
        follow: bool,
        /// Maximum depth for --follow (default: 3)
        #[arg(long, default_value = "3")]
        depth: usize,
    },
    /// Build and display call graph
    Callgraph {
        /// Symbol name, address, or "all" for full binary
        #[arg(default_value = "all")]
        target: String,
        /// Output in Graphviz DOT format
        #[arg(long)]
        dot: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Output in interactive HTML format
        #[arg(long)]
        html: bool,
    },
    /// Extract strings from the binary
    Strings {
        /// Minimum string length
        #[arg(short, long, default_value = "4")]
        min_length: usize,
        /// Search for strings matching a pattern
        #[arg(short, long)]
        search: Option<String>,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
    },
    /// Build cross-reference database
    Xrefs {
        /// Target address to find references to
        target: Option<String>,
        /// Show only calls
        #[arg(long)]
        calls_only: bool,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
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
        Some(Commands::Cfg { target, dot, json, html }) => {
            disassemble_cfg(fmt, &target, dot, json, html)?;
        }
        Some(Commands::Decompile { target, show_addresses, follow, depth }) => {
            let target = resolve_decompile_target(&binary, target)?;
            if follow {
                decompile_with_follow(&binary, &target, show_addresses, depth)?;
            } else {
                decompile_function(&binary, &target, show_addresses)?;
            }
        }
        Some(Commands::Callgraph { target, dot, json, html }) => {
            build_callgraph(fmt, &target, dot, json, html)?;
        }
        Some(Commands::Strings { min_length, search, json }) => {
            extract_strings(fmt, min_length, search.as_deref(), json)?;
        }
        Some(Commands::Xrefs { target, calls_only, json }) => {
            build_xrefs(fmt, target.as_deref(), calls_only, json)?;
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

/// Resolve the target for decompilation.
/// If target is provided, use it. Otherwise, try to find main, then fall back to entry point.
fn resolve_decompile_target(binary: &Binary, target: Option<String>) -> Result<String> {
    // If user provided a target, use it
    if let Some(t) = target {
        return Ok(t);
    }

    let fmt = binary.as_format();

    // Try to find "main" symbol first
    if let Some(sym) = find_symbol(fmt, "main") {
        println!("(auto-selected 'main' at {:#x})\n", sym.address);
        return Ok("main".to_string());
    }

    // Fall back to entry point
    if let Some(entry) = fmt.entry_point() {
        if entry != 0 {
            println!("(auto-selected entry point at {:#x})\n", entry);
            return Ok(format!("{:#x}", entry));
        }
    }

    bail!("No target specified and could not find 'main' or entry point")
}

/// Find a symbol by name, preferring exact matches over partial matches.
/// For function decompilation, we want the most specific match.
fn find_symbol(fmt: &dyn BinaryFormat, name: &str) -> Option<hexray_core::Symbol> {
    // Collect symbols into owned values, filtering out undefined/external symbols
    let symbols: Vec<hexray_core::Symbol> = fmt.symbols()
        .filter(|s| s.is_defined() && s.address != 0)
        .cloned()
        .collect();

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

fn disassemble_cfg(fmt: &dyn BinaryFormat, target: &str, dot: bool, json: bool, html: bool) -> Result<()> {
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

    if html {
        // Output in interactive HTML format
        let exporter = CfgHtmlExporter::new();
        exporter.export_to_stdout(&cfg, &name)?;
    } else if json {
        // Output in JSON format using the exporter
        let exporter = CfgJsonExporter::pretty();
        exporter.export_to_stdout(&cfg, &name)?;
    } else if dot {
        // Output in Graphviz DOT format using the exporter
        let exporter = CfgDotExporter::new();
        exporter.export_to_stdout(&cfg, &name)?;
    } else {
        // Text output
        println!("Building CFG for {} at {:#x}\n", name, start_addr);
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
            .with_context(|| format!("Symbol '{}' not found. It may be an external/undefined symbol (e.g., from a shared library).", target))?;
        (symbol.address, demangle_or_original(&symbol.name))
    };

    // Validate the address is reasonable
    if start_addr == 0 {
        bail!("Invalid address 0x0 - symbol may be undefined or external");
    }

    // Check if address is in an executable section
    let in_executable = fmt.sections().any(|s| {
        let section_start = s.virtual_address();
        let section_end = section_start.saturating_add(s.size());
        start_addr >= section_start && start_addr < section_end && s.is_executable()
    });
    if !in_executable {
        bail!("Address {:#x} is not in an executable section - cannot decompile data", start_addr);
    }

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

    // Try to load DWARF debug info for variable names
    let dwarf_names = if let Some(debug_info) = load_dwarf_info(binary) {
        let names = get_dwarf_variable_names(&debug_info, start_addr);
        if !names.is_empty() {
            println!("(using DWARF debug info for variable names)\n");
        }
        names
    } else {
        std::collections::HashMap::new()
    };

    // Decompile
    let decompiler = Decompiler::new()
        .with_addresses(show_addresses)
        .with_string_table(string_table)
        .with_symbol_table(symbol_table)
        .with_relocation_table(relocation_table)
        .with_dwarf_names(dwarf_names);
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
/// Reads a null-terminated C string from ELF data at the given offset.
/// Returns None if the offset is out of bounds or the string is too long/invalid.
fn read_cstring_from_elf(data: &[u8], offset: usize) -> Option<String> {
    if offset >= data.len() {
        return None;
    }

    // Find the null terminator, with a reasonable max length
    let max_len = 256;
    let end = data[offset..]
        .iter()
        .take(max_len)
        .position(|&b| b == 0)?;

    // Try to convert to UTF-8 string
    let bytes = &data[offset..offset + end];
    let s = std::str::from_utf8(bytes).ok()?;

    // Skip if empty or contains non-printable characters
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }

    // Format as a C string literal, escaping if needed
    Some(format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
}

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

                        // Try to read actual string content from .rodata.str* sections
                        // These sections (e.g., .rodata.str1.1, .rodata.str1.8) contain string literals
                        let sym_name = if symbol.name.starts_with(".rodata.str") {
                            // Find the target section and read the string
                            if let Some(rodata_section) = elf.sections.iter()
                                .find(|s| elf.section_name(s).map(|n| n == symbol.name).unwrap_or(false))
                            {
                                let string_offset = rodata_section.sh_offset as usize + reloc.addend as usize;
                                read_cstring_from_elf(elf.data(), string_offset)
                                    .unwrap_or_else(|| format!("{}+{:#x}", symbol.name, reloc.addend))
                            } else {
                                format!("{}+{:#x}", symbol.name, reloc.addend)
                            }
                        } else if reloc.addend != 0 {
                            format!("{}+{:#x}", symbol.name, reloc.addend)
                        } else {
                            symbol.name.clone()
                        };
                        table.insert_data(inst_addr, sym_name);
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
                // GOT-relative relocations (for mov reg, [rip+X] accessing global variables)
                // The relocation points to the displacement (4 bytes), instruction starts 3 bytes before
                // Format: REX.W MOV ModRM disp32 = 48 8b XX 00 00 00 00
                RelocationType::GotPcRel
                | RelocationType::GotPcRelX
                | RelocationType::RexGotPcRelX => {
                    if let Some(section) = elf.sections.get(reloc.section_index) {
                        // Instruction starts 3 bytes before the displacement
                        let inst_addr = section.sh_offset + reloc.offset - 3;
                        table.insert_got(inst_addr, symbol.name.clone());
                    }
                }
                _ => {}
            }
        }
    }

    table
}

/// Attempts to load DWARF debug info from a binary.
/// Returns None if DWARF sections are not present.
fn load_dwarf_info(binary: &Binary) -> Option<DebugInfo> {
    let fmt = binary.as_format();

    // Get DWARF sections
    let debug_info = fmt.sections()
        .find(|s| s.name() == ".debug_info" || s.name() == "__debug_info")?
        .data();
    let debug_abbrev = fmt.sections()
        .find(|s| s.name() == ".debug_abbrev" || s.name() == "__debug_abbrev")?
        .data();
    let debug_str = fmt.sections()
        .find(|s| s.name() == ".debug_str" || s.name() == "__debug_str")
        .map(|s| s.data());
    let debug_line = fmt.sections()
        .find(|s| s.name() == ".debug_line" || s.name() == "__debug_line")
        .map(|s| s.data());

    // Determine address size based on architecture
    let address_size = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 4,
        _ => 8,
    };

    // Parse DWARF info
    parse_debug_info(debug_info, debug_abbrev, debug_str, debug_line, address_size).ok()
}

/// Gets DWARF variable names for a function at the given address.
fn get_dwarf_variable_names(debug_info: &DebugInfo, func_addr: u64) -> std::collections::HashMap<i128, String> {
    if let Some(func) = debug_info.find_function(func_addr) {
        func.variable_names()
    } else {
        std::collections::HashMap::new()
    }
}

fn build_callgraph(fmt: &dyn BinaryFormat, target: &str, dot: bool, json: bool, html: bool) -> Result<()> {
    let symbols: Vec<_> = fmt.symbols().cloned().collect();
    let arch = fmt.architecture();

    // Determine which functions to analyze (address, name, size)
    // Note: Mach-O symbols don't have size info (nlist doesn't store it),
    // so we use a default size for symbols with size == 0
    let functions_to_analyze: Vec<(u64, String, u64)> = if target == "all" {
        symbols
            .iter()
            .filter(|s| s.is_function() && s.address != 0)
            .map(|s| {
                let size = if s.size > 0 { s.size } else { 256 }; // Default for Mach-O
                (s.address, demangle_or_original(&s.name), size)
            })
            .collect()
    } else {
        // Parse as address or find symbol by name
        let address = if let Some(stripped) = target.strip_prefix("0x") {
            u64::from_str_radix(stripped, 16).ok()
        } else {
            u64::from_str_radix(target, 16).ok()
        };

        let (addr, name, size) = if let Some(a) = address {
            // For raw addresses, use a default size
            (a, format!("sub_{:x}", a), 4096u64)
        } else {
            let symbol = find_symbol(fmt, target)
                .with_context(|| format!("Symbol '{}' not found", target))?;
            let size = if symbol.size > 0 { symbol.size } else { 4096 };
            (symbol.address, demangle_or_original(&symbol.name), size)
        };

        vec![(addr, name, size)]
    };

    // Collect function info for parallel disassembly
    let function_infos: Vec<FunctionInfo> = functions_to_analyze
        .iter()
        .filter_map(|(func_addr, _, func_size)| {
            let size = (*func_size).max(64) as usize;
            fmt.bytes_at(*func_addr, size).map(|bytes| FunctionInfo {
                address: *func_addr,
                size,
                bytes: bytes.to_vec(),
            })
        })
        .collect();

    // Build call graph using parallel disassembly
    let callgraph = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            ParallelCallGraphBuilder::build(&function_infos, &disasm, &symbols)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            ParallelCallGraphBuilder::build(&function_infos, &disasm, &symbols)
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            ParallelCallGraphBuilder::build(&function_infos, &disasm, &symbols)
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            ParallelCallGraphBuilder::build(&function_infos, &disasm, &symbols)
        }
        _ => {
            // Fallback to sequential for unsupported architectures
            let mut builder = CallGraphBuilder::new();
            builder.add_symbols(&symbols);
            builder.build()
        }
    };

    if html {
        // Output in interactive HTML format
        let exporter = CallGraphHtmlExporter::new();
        exporter.export_to_stdout(&callgraph)?;
    } else if json {
        // Output in JSON format using the exporter
        let exporter = CallGraphJsonExporter::pretty();
        exporter.export_to_stdout(&callgraph)?;
    } else if dot {
        // Output in Graphviz DOT format using the exporter
        let exporter = CallGraphDotExporter::new();
        exporter.export_to_stdout(&callgraph)?;
    } else {
        // Text output
        println!("Call Graph Analysis");
        println!("===================");
        println!("Functions: {}", callgraph.node_count());
        println!("Call edges: {}", callgraph.edge_count());
        println!();

        for node in callgraph.nodes() {
            let node_name = node.name.clone().unwrap_or_else(|| format!("sub_{:x}", node.address));
            let callees: Vec<_> = callgraph
                .callees(node.address)
                .filter_map(|(addr, _)| callgraph.get_node(addr))
                .collect();

            if !callees.is_empty() {
                println!("{} ({:#x}):", node_name, node.address);
                for callee in callees {
                    let callee_name = callee.name.clone().unwrap_or_else(|| format!("sub_{:x}", callee.address));
                    println!("  -> {} ({:#x})", callee_name, callee.address);
                }
                println!();
            }
        }
    }

    Ok(())
}

fn extract_strings(
    fmt: &dyn BinaryFormat,
    min_length: usize,
    search: Option<&str>,
    json: bool,
) -> Result<()> {
    let config = StringConfig {
        min_length,
        ..Default::default()
    };
    let detector = StringDetector::with_config(config);

    let mut all_strings = Vec::new();

    // Extract strings from all sections
    for section in fmt.sections() {
        let data = section.data();
        if !data.is_empty() {
            let strings = detector.detect(data, section.virtual_address());
            all_strings.extend(strings);
        }
    }

    // Sort by address
    all_strings.sort_by_key(|s| s.address);

    // Filter by search pattern if provided
    if let Some(pattern) = search {
        let pattern_lower = pattern.to_lowercase();
        all_strings.retain(|s| s.content.to_lowercase().contains(&pattern_lower));
    }

    if json {
        // JSON output
        println!("{{");
        println!("  \"strings\": [");
        for (i, s) in all_strings.iter().enumerate() {
            let escaped_content = s.content
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");

            let comma = if i < all_strings.len() - 1 { "," } else { "" };
            println!("    {{");
            println!("      \"address\": \"{:#x}\",", s.address);
            println!("      \"length\": {},", s.length);
            println!("      \"encoding\": \"{:?}\",", s.encoding);
            println!("      \"content\": \"{}\"", escaped_content);
            println!("    }}{}", comma);
        }
        println!("  ],");
        println!("  \"total\": {}", all_strings.len());
        println!("}}");
    } else {
        // Text output
        println!("Strings ({} found)", all_strings.len());
        println!("{}", "=".repeat(50));
        println!();

        for s in &all_strings {
            let type_marker = match s.encoding {
                hexray_analysis::StringEncoding::Ascii => "",
                hexray_analysis::StringEncoding::Utf8 => " (UTF-8)",
                hexray_analysis::StringEncoding::Utf16Le => " (UTF-16 LE)",
                hexray_analysis::StringEncoding::Utf16Be => " (UTF-16 BE)",
            };

            // Truncate very long strings
            let display_content = if s.content.len() > 80 {
                format!("{}...", &s.content[..77])
            } else {
                s.content.clone()
            };

            // Add indicators for special string types
            let mut indicators = Vec::new();
            if s.is_path() {
                indicators.push("PATH");
            }
            if s.is_url() {
                indicators.push("URL");
            }
            if s.is_error_message() {
                indicators.push("ERROR");
            }

            let indicator_str = if indicators.is_empty() {
                String::new()
            } else {
                format!(" [{}]", indicators.join(", "))
            };

            println!("{:#016x}{}: \"{}\"{}",
                     s.address, type_marker, display_content, indicator_str);
        }
    }

    Ok(())
}

/// Decompile a function and follow internal calls recursively.
fn decompile_with_follow(binary: &Binary, target: &str, show_addresses: bool, max_depth: usize) -> Result<()> {
    use std::collections::HashSet;

    let fmt = binary.as_format();
    let arch = fmt.architecture();

    // Track which functions we've already decompiled to avoid duplicates
    let mut decompiled: HashSet<u64> = HashSet::new();

    // Queue of (address, name, depth) to decompile
    let mut queue: Vec<(u64, String, usize)> = Vec::new();

    // Resolve the initial target
    let address = if let Some(stripped) = target.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        u64::from_str_radix(target, 16).ok()
    };

    let (start_addr, name) = if let Some(addr) = address {
        (addr, format!("sub_{:x}", addr))
    } else {
        let symbol = find_symbol(fmt, target)
            .with_context(|| format!("Symbol '{}' not found", target))?;
        (symbol.address, demangle_or_original(&symbol.name))
    };

    queue.push((start_addr, name, 0));

    // Build tables once for all decompilations
    let string_table = build_string_table(fmt);
    let symbol_table = build_symbol_table(fmt);
    let relocation_table = build_relocation_table(binary);

    // Try to load DWARF debug info once
    let debug_info = load_dwarf_info(binary);

    while let Some((func_addr, func_name, depth)) = queue.pop() {
        if decompiled.contains(&func_addr) {
            continue;
        }

        // Validate address
        if func_addr == 0 {
            continue;
        }

        // Check if in executable section
        let in_executable = fmt.sections().any(|s| {
            let section_start = s.virtual_address();
            let section_end = section_start.saturating_add(s.size());
            func_addr >= section_start && func_addr < section_end && s.is_executable()
        });
        if !in_executable {
            continue;
        }

        decompiled.insert(func_addr);

        // Print separator between functions
        if decompiled.len() > 1 {
            println!("\n{}\n", "─".repeat(60));
        }

        println!("// Decompiling {} at {:#x} (depth {})\n", func_name, func_addr, depth);

        // Disassemble
        let bytes = match fmt.bytes_at(func_addr, 4096) {
            Some(b) => b,
            None => continue,
        };

        let instructions = match arch {
            Architecture::X86_64 | Architecture::X86 => {
                let disasm = X86_64Disassembler::new();
                disassemble_for_cfg(&disasm, bytes, func_addr)
            }
            Architecture::Arm64 => {
                let disasm = Arm64Disassembler::new();
                disassemble_for_cfg(&disasm, bytes, func_addr)
            }
            Architecture::RiscV64 => {
                let disasm = RiscVDisassembler::new();
                disassemble_for_cfg(&disasm, bytes, func_addr)
            }
            Architecture::RiscV32 => {
                let disasm = RiscVDisassembler::new_rv32();
                disassemble_for_cfg(&disasm, bytes, func_addr)
            }
            _ => continue,
        };

        // Build CFG
        let cfg = CfgBuilder::build(&instructions, func_addr);

        // Get DWARF variable names for this function
        let dwarf_names = if let Some(ref di) = debug_info {
            get_dwarf_variable_names(di, func_addr)
        } else {
            std::collections::HashMap::new()
        };

        // Decompile
        let decompiler = Decompiler::new()
            .with_addresses(show_addresses)
            .with_string_table(string_table.clone())
            .with_symbol_table(symbol_table.clone())
            .with_relocation_table(relocation_table.clone())
            .with_dwarf_names(dwarf_names);
        let pseudocode = decompiler.decompile(&cfg, &func_name);

        println!("{}", pseudocode);

        // If we haven't reached max depth, find internal calls to follow
        if depth < max_depth {
            let call_targets = extract_internal_call_targets(&instructions, fmt);
            for (target_addr, target_name) in call_targets {
                if !decompiled.contains(&target_addr) {
                    // Check for special patterns like __libc_start_main
                    // which passes main as first argument
                    let actual_name = if func_name == "__libc_start_main" || func_name.contains("libc_start_main") {
                        // The first argument to __libc_start_main is typically main
                        if target_name.starts_with("sub_") {
                            "main".to_string()
                        } else {
                            target_name
                        }
                    } else {
                        target_name
                    };
                    queue.push((target_addr, actual_name, depth + 1));
                }
            }
        }
    }

    println!("\n// Decompiled {} function(s)", decompiled.len());

    Ok(())
}

/// Extract internal call targets from instructions.
/// Returns addresses of functions that are called within this function.
/// Also detects function pointers passed as arguments (e.g., main passed to __libc_start_main).
fn extract_internal_call_targets(instructions: &[hexray_core::Instruction], fmt: &dyn BinaryFormat) -> Vec<(u64, String)> {
    use hexray_core::{ControlFlow, Operand};

    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper to check if an address is in an internal executable section
    let is_internal_addr = |addr: u64| -> bool {
        if addr == 0 {
            return false;
        }
        fmt.sections().any(|s| {
            let section_start = s.virtual_address();
            let section_end = section_start.saturating_add(s.size());
            let section_name = s.name().to_lowercase();
            // Exclude PLT sections (ELF) and __stubs/__stub_helper (Mach-O)
            if section_name.contains("plt") || section_name.contains("stub") {
                return false;
            }
            addr >= section_start && addr < section_end && s.is_executable()
        })
    };

    // Helper to add a target if it's valid
    let add_target = |target_addr: u64, seen: &mut std::collections::HashSet<u64>, targets: &mut Vec<(u64, String)>| {
        if target_addr == 0 || seen.contains(&target_addr) {
            return;
        }
        if is_internal_addr(target_addr) {
            seen.insert(target_addr);
            let name = if let Some(sym) = fmt.symbol_at(target_addr) {
                if !sym.name.is_empty() {
                    demangle_or_original(&sym.name)
                } else {
                    format!("sub_{:x}", target_addr)
                }
            } else {
                format!("sub_{:x}", target_addr)
            };
            targets.push((target_addr, name));
        }
    };

    for inst in instructions {
        // Look for direct call instructions
        if let ControlFlow::Call { target, .. } = inst.control_flow {
            add_target(target, &mut seen, &mut targets);
        }

        // Also look for function addresses in operands (e.g., LEA for function pointers)
        // This catches cases like: lea rdi, [rip + main] ; call __libc_start_main
        for operand in &inst.operands {
            match operand {
                Operand::PcRelative { target, .. } => {
                    // Check if this looks like a function pointer (in .text, has symbol)
                    if is_internal_addr(*target) {
                        // Only add if there's a symbol or it looks like a function start
                        if fmt.symbol_at(*target).is_some() {
                            add_target(*target, &mut seen, &mut targets);
                        }
                    }
                }
                Operand::Immediate(imm) => {
                    // Check if immediate value is a function address
                    let addr = imm.value as u64;
                    if is_internal_addr(addr) && fmt.symbol_at(addr).is_some() {
                        add_target(addr, &mut seen, &mut targets);
                    }
                }
                _ => {}
            }
        }
    }

    targets
}

fn build_xrefs(
    fmt: &dyn BinaryFormat,
    target: Option<&str>,
    calls_only: bool,
    json: bool,
) -> Result<()> {
    let arch = fmt.architecture();
    let symbols: Vec<_> = fmt.symbols().cloned().collect();

    // Build xref database by disassembling all functions
    let mut xref_builder = XrefBuilder::new();

    // Gather function addresses and disassemble
    let functions: Vec<_> = symbols
        .iter()
        .filter(|s| s.is_function() && s.address != 0)
        .collect();

    for func in &functions {
        let size = if func.size > 0 { func.size as usize } else { 256 };
        if let Some(bytes) = fmt.bytes_at(func.address, size) {
            let instructions = match arch {
                Architecture::X86_64 | Architecture::X86 => {
                    let disasm = X86_64Disassembler::new();
                    disassemble_for_cfg(&disasm, bytes, func.address)
                }
                Architecture::Arm64 => {
                    let disasm = Arm64Disassembler::new();
                    disassemble_for_cfg(&disasm, bytes, func.address)
                }
                Architecture::RiscV64 => {
                    let disasm = RiscVDisassembler::new();
                    disassemble_for_cfg(&disasm, bytes, func.address)
                }
                Architecture::RiscV32 => {
                    let disasm = RiscVDisassembler::new_rv32();
                    disassemble_for_cfg(&disasm, bytes, func.address)
                }
                _ => Vec::new(),
            };
            xref_builder.analyze_instructions(&instructions);
        }
    }

    let db = xref_builder.build();

    // If a target is specified, show refs to that target
    if let Some(target_str) = target {
        let target_addr = if let Some(stripped) = target_str.strip_prefix("0x") {
            u64::from_str_radix(stripped, 16)
                .with_context(|| format!("Invalid address: {}", target_str))?
        } else if let Ok(addr) = u64::from_str_radix(target_str, 16) {
            addr
        } else {
            // Try to find symbol
            let symbol = find_symbol(fmt, target_str)
                .with_context(|| format!("Symbol '{}' not found", target_str))?;
            symbol.address
        };

        let refs = if calls_only {
            db.call_refs_to(target_addr)
        } else {
            db.refs_to(target_addr).iter().collect()
        };

        let target_name = fmt
            .symbol_at(target_addr)
            .map(|s| demangle_or_original(&s.name))
            .unwrap_or_else(|| format!("sub_{:x}", target_addr));

        if json {
            println!("{{");
            println!("  \"target\": \"{:#x}\",", target_addr);
            println!("  \"target_name\": \"{}\",", target_name);
            println!("  \"references\": [");
            for (i, xref) in refs.iter().enumerate() {
                let from_name = fmt
                    .symbol_at(xref.from)
                    .map(|s| demangle_or_original(&s.name))
                    .unwrap_or_else(|| format!("sub_{:x}", xref.from));
                let comma = if i < refs.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"from\": \"{:#x}\",", xref.from);
                println!("      \"from_name\": \"{}\",", from_name);
                println!("      \"type\": \"{:?}\"", xref.xref_type);
                println!("    }}{}", comma);
            }
            println!("  ],");
            println!("  \"count\": {}", refs.len());
            println!("}}");
        } else {
            println!("Cross-references to {} ({:#x})", target_name, target_addr);
            println!("{}", "=".repeat(50));
            println!();

            if refs.is_empty() {
                println!("No references found.");
            } else {
                for xref in &refs {
                    let from_name = fmt
                        .symbol_at(xref.from)
                        .map(|s| demangle_or_original(&s.name))
                        .unwrap_or_else(|| format!("sub_{:x}", xref.from));
                    let type_str = match xref.xref_type {
                        XrefType::Call => "CALL",
                        XrefType::Jump => "JUMP",
                        XrefType::DataRead => "READ",
                        XrefType::DataWrite => "WRITE",
                        XrefType::Unknown => "???",
                    };
                    println!("{:#016x} {} from {}", xref.from, type_str, from_name);
                }
                println!();
                println!("Total: {} references", refs.len());
            }
        }
    } else {
        // No target - show summary
        if json {
            println!("{{");
            println!("  \"total_xrefs\": {},", db.total_xrefs());
            println!("  \"referenced_addresses\": {}", db.all_referenced().count());
            println!("}}");
        } else {
            println!("Cross-reference Database Summary");
            println!("{}", "=".repeat(50));
            println!();
            println!("Total cross-references: {}", db.total_xrefs());
            println!("Referenced addresses: {}", db.all_referenced().count());
            println!();
            println!("Use 'xrefs <address>' or 'xrefs <symbol>' to see references to a specific target.");
        }
    }

    Ok(())
}
