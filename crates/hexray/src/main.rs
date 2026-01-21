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
    AnalysisProject, CallGraphBuilder, CallGraphDotExporter, CallGraphHtmlExporter,
    CallGraphJsonExporter, CfgBuilder, CfgDotExporter, CfgHtmlExporter, CfgJsonExporter,
    Decompiler, FunctionInfo, ParallelCallGraphBuilder, RelocationTable, StringConfig,
    StringDetector, StringTable, SymbolTable, XrefBuilder, XrefType,
};
use hexray_core::Architecture;
use hexray_demangle::demangle_or_original;
use hexray_disasm::{Arm64Disassembler, Disassembler, RiscVDisassembler, X86_64Disassembler};
use hexray_formats::dwarf::{parse_debug_info, DebugInfo};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use hexray_types::TypeDatabase;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod commands;
mod session;

use commands::emulate::EmulateAction;
use commands::signatures::SignaturesAction;
use commands::trace::TraceAction;
use commands::types::TypesAction;
use session::{list_sessions, AnnotationKind, Repl, Session};

#[derive(Parser)]
#[command(name = "hexray")]
#[command(about = "A multi-architecture disassembler", long_about = None)]
struct Cli {
    /// Path to the binary file (not required for 'types' command)
    binary: Option<PathBuf>,

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

    /// Project file for annotations
    #[arg(short, long)]
    project: Option<PathBuf>,
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
        /// Project file for function names and comments
        #[arg(long)]
        project: Option<PathBuf>,
        /// Load type library for struct field resolution (posix, linux, macos, libc, all, or auto)
        #[arg(long, short = 't')]
        types: Option<String>,
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
    /// Manage analysis project (annotations, bookmarks, etc.)
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },
    /// Manage C type libraries for decompilation
    Types {
        #[command(subcommand)]
        action: TypesAction,
    },
    /// Identify library functions using signatures (FLIRT-like)
    Signatures {
        #[command(subcommand)]
        action: SignaturesAction,
    },
    /// Trace data flow (where values come from/go to)
    Trace {
        #[command(subcommand)]
        action: TraceAction,
    },
    /// Static emulation for resolving indirect branches and tracing execution
    Emulate {
        #[command(subcommand)]
        action: EmulateAction,
    },
    /// Interactive analysis session with persistent history
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },
}

/// Project management actions
#[derive(Subcommand)]
enum ProjectAction {
    /// Create a new project for a binary
    Create {
        /// Output project file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Load and show project information
    Info {
        /// Project file path
        project: PathBuf,
    },
    /// Add a comment at an address
    Comment {
        /// Project file path
        project: PathBuf,
        /// Address to comment (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Comment text
        comment: String,
    },
    /// Set a custom function name
    Name {
        /// Project file path
        project: PathBuf,
        /// Function address (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Custom function name
        name: String,
    },
    /// Add a label at an address
    Label {
        /// Project file path
        project: PathBuf,
        /// Address to label (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Label text
        label: String,
    },
    /// Add a bookmark
    Bookmark {
        /// Project file path
        project: PathBuf,
        /// Address to bookmark (hex)
        #[arg(value_parser = parse_hex)]
        address: u64,
        /// Optional label for the bookmark
        #[arg(short, long)]
        label: Option<String>,
    },
    /// List all annotations in a project
    List {
        /// Project file path
        project: PathBuf,
        /// Show only comments
        #[arg(long)]
        comments: bool,
        /// Show only function names
        #[arg(long)]
        functions: bool,
        /// Show only bookmarks
        #[arg(long)]
        bookmarks: bool,
    },
    /// Undo the last action
    Undo {
        /// Project file path
        project: PathBuf,
    },
    /// Redo the last undone action
    Redo {
        /// Project file path
        project: PathBuf,
    },
}

/// Interactive session actions
#[derive(Subcommand)]
enum SessionAction {
    /// Start a new analysis session
    New {
        /// Output session file path (.hrp)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Resume an existing session
    Resume {
        /// Session file path (.hrp)
        session: PathBuf,
    },
    /// List available sessions in a directory
    List {
        /// Directory to search (defaults to current directory)
        #[arg(default_value = ".")]
        directory: PathBuf,
    },
    /// Show session information
    Info {
        /// Session file path (.hrp)
        session: PathBuf,
    },
    /// Export session history to a file
    Export {
        /// Session file path (.hrp)
        session: PathBuf,
        /// Output file (stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Export format: text, json
        #[arg(short, long, default_value = "text")]
        format: String,
    },
}

/// Parse a hex string (with optional 0x prefix) into u64.
pub fn parse_hex(s: &str) -> Result<u64, String> {
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

    // Handle commands that don't require a binary file
    if let Some(Commands::Types { action }) = cli.command {
        return commands::handle_types_command(action);
    }

    // Handle signature subcommands that don't require a binary
    if let Some(Commands::Signatures { ref action }) = cli.command {
        match action {
            SignaturesAction::Builtin
            | SignaturesAction::Stats { .. }
            | SignaturesAction::List { .. }
            | SignaturesAction::Show { .. } => {
                return commands::handle_signatures_command_no_binary(action);
            }
            SignaturesAction::Scan { .. } => {
                // Scan requires a binary, handled below
            }
        }
    }

    // Handle session subcommands that don't require a binary on command line
    if let Some(Commands::Session { ref action }) = cli.command {
        match action {
            SessionAction::List { directory } => {
                return handle_session_list(directory);
            }
            SessionAction::Info { session } => {
                return handle_session_info(session);
            }
            SessionAction::Resume { session } => {
                return handle_session_resume(session);
            }
            SessionAction::Export {
                session,
                output,
                format,
            } => {
                return handle_session_export(session, output.as_ref(), format);
            }
            SessionAction::New { .. } => {
                // New requires a binary, handled below
            }
        }
    }

    // Get binary path (required for all other commands)
    let binary_path = cli.binary.as_ref().ok_or_else(|| {
        anyhow::anyhow!("Binary file path is required. Usage: hexray <BINARY> [COMMAND]")
    })?;

    // Read the binary file
    let data = fs::read(binary_path)
        .with_context(|| format!("Failed to read binary: {}", binary_path.display()))?;

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
        Some(Commands::Cfg {
            target,
            dot,
            json,
            html,
        }) => {
            disassemble_cfg(fmt, &target, dot, json, html)?;
        }
        Some(Commands::Decompile {
            target,
            show_addresses,
            follow,
            depth,
            project,
            types,
        }) => {
            let target = resolve_decompile_target(&binary, target)?;
            let project = match project {
                Some(path) => Some(
                    AnalysisProject::load(&path)
                        .with_context(|| format!("Failed to load project: {}", path.display()))?,
                ),
                None => None,
            };
            let type_db = load_type_database(&binary, types.as_deref())?;
            if follow {
                decompile_with_follow(
                    &binary,
                    &target,
                    show_addresses,
                    depth,
                    project.as_ref(),
                    type_db.as_ref(),
                )?;
            } else {
                decompile_function(
                    &binary,
                    &target,
                    show_addresses,
                    project.as_ref(),
                    type_db.as_ref(),
                )?;
            }
        }
        Some(Commands::Callgraph {
            target,
            dot,
            json,
            html,
        }) => {
            build_callgraph(fmt, &target, dot, json, html)?;
        }
        Some(Commands::Strings {
            min_length,
            search,
            json,
        }) => {
            extract_strings(fmt, min_length, search.as_deref(), json)?;
        }
        Some(Commands::Xrefs {
            target,
            calls_only,
            json,
        }) => {
            build_xrefs(fmt, target.as_deref(), calls_only, json)?;
        }
        Some(Commands::Project { action }) => {
            handle_project_command(binary_path, action)?;
        }
        Some(Commands::Types { .. }) => {
            // Already handled before binary loading
            unreachable!("Types command should have been handled earlier");
        }
        Some(Commands::Signatures { action }) => {
            commands::handle_signatures_command(binary.as_format(), action)?;
        }
        Some(Commands::Trace { action }) => {
            commands::handle_trace_command(binary.as_format(), action)?;
        }
        Some(Commands::Emulate { action }) => {
            commands::handle_emulate_command(binary.as_format(), action)?;
        }
        Some(Commands::Session { action }) => {
            match action {
                SessionAction::New { output } => {
                    handle_session_new(binary_path, output.as_ref())?;
                }
                _ => {
                    // Already handled before binary loading
                    unreachable!("Session command should have been handled earlier");
                }
            }
        }
        None => {
            // Default: disassemble
            // cli.count is instruction count, convert to bytes (max 15 bytes per x86 instruction)
            let max_bytes = cli.count * 15;
            if let Some(symbol_name) = cli.symbol {
                disassemble_symbol(fmt, &symbol_name, cli.count)?;
            } else if let Some(addr) = cli.address {
                disassemble_at(fmt, addr, max_bytes)?;
            } else if let Some(entry) = fmt.entry_point() {
                println!("Disassembling entry point at {:#x}\n", entry);
                disassemble_at(fmt, entry, max_bytes)?;
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
                println!(
                    "  {:<16} {:#016x} - {:#016x} ({} sections)",
                    seg.segname,
                    seg.vmaddr,
                    seg.vmaddr + seg.vmsize,
                    seg.sections.len()
                );
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
    println!(
        "{:<4} {:<24} {:<16} {:<16} {:<8}",
        "Idx", "Name", "Address", "Size", "Flags"
    );
    println!("{}", "-".repeat(75));

    match binary {
        Binary::Elf(elf) => {
            for (idx, section) in elf.sections.iter().enumerate() {
                let name = elf.section_name(section).unwrap_or("");
                let flags = format!(
                    "{}{}{}",
                    if section.is_allocated() { "A" } else { "-" },
                    if section.is_writable() { "W" } else { "-" },
                    if section.is_executable() { "X" } else { "-" },
                );

                println!(
                    "{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                    idx, name, section.sh_addr, section.sh_size, flags
                );
            }
        }
        Binary::MachO(macho) => {
            let mut idx = 0;
            for seg in &macho.segments {
                for section in &seg.sections {
                    let flags = format!(
                        "{}{}",
                        if section.is_allocated() { "A" } else { "-" },
                        if section.is_executable() { "X" } else { "-" },
                    );
                    let full_name = format!("{},{}", seg.segname, section.sectname);

                    println!(
                        "{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                        idx, full_name, section.addr, section.size, flags
                    );
                    idx += 1;
                }
            }
        }
        Binary::Pe(pe) => {
            use hexray_formats::Section;
            for (idx, section) in pe.sections.iter().enumerate() {
                let flags = section.flags_string();
                println!(
                    "{:<4} {:<24} {:#016x} {:#016x} {:<8}",
                    idx,
                    section.name,
                    section.virtual_address(), // Now returns absolute address including image_base
                    section.virtual_size,
                    flags
                );
            }
        }
    }
}

fn print_symbols(fmt: &dyn BinaryFormat, functions_only: bool) {
    println!(
        "{:<16} {:<8} {:<8} {:<8} Name",
        "Address", "Size", "Type", "Bind"
    );
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

        println!(
            "{:#016x} {:<8} {:<8} {:<8} {}",
            symbol.address, symbol.size, type_str, bind_str, demangled
        );
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
    let symbols: Vec<hexray_core::Symbol> = fmt
        .symbols()
        .filter(|s| s.is_defined() && s.address != 0)
        .cloned()
        .collect();

    // 1. Try exact match first (highest priority)
    if let Some(sym) = symbols.iter().find(|s| s.name == name) {
        return Some(sym.clone());
    }

    // 2. Try exact match on demangled name
    if let Some(sym) = symbols
        .iter()
        .find(|s| demangle_or_original(&s.name) == name)
    {
        return Some(sym.clone());
    }

    // 3. Try prefix match (e.g., "nfsd_open" matches "nfsd_open.cold")
    //    Prefer function symbols and shorter names
    let mut prefix_matches: Vec<hexray_core::Symbol> = symbols
        .iter()
        .filter(|s| s.name.starts_with(name) || demangle_or_original(&s.name).starts_with(name))
        .cloned()
        .collect();
    prefix_matches.sort_by(|a, b| {
        // Prefer functions over non-functions
        let a_is_func = a.is_function() as u8;
        let b_is_func = b.is_function() as u8;
        b_is_func
            .cmp(&a_is_func)
            .then_with(|| a.name.len().cmp(&b.name.len())) // Shorter names preferred
    });
    if !prefix_matches.is_empty() {
        return Some(prefix_matches.remove(0));
    }

    // 4. Try contains match as last resort (lowest priority)
    //    Only match function symbols, and prefer shorter names
    let mut contains_matches: Vec<hexray_core::Symbol> = symbols
        .iter()
        .filter(|s| {
            s.is_function()
                && (s.name.contains(name) || demangle_or_original(&s.name).contains(name))
        })
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
    let symbol = find_symbol(fmt, name).with_context(|| format!("Symbol '{}' not found", name))?;

    println!(
        "Disassembling {} at {:#x} (size: {} bytes)\n",
        demangle_or_original(&symbol.name),
        symbol.address,
        symbol.size
    );

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
                println!(
                    "{:#010x}:  {:02x}                      <decode error: {}>",
                    addr, remaining[0], e
                );
                *offset += disasm.min_instruction_size().max(1);
            }
        }
    }

    Ok(())
}

fn disassemble_cfg(
    fmt: &dyn BinaryFormat,
    target: &str,
    dot: bool,
    json: bool,
    html: bool,
) -> Result<()> {
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
        let symbol =
            find_symbol(fmt, target).with_context(|| format!("Symbol '{}' not found", target))?;
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

fn decompile_function(
    binary: &Binary,
    target: &str,
    show_addresses: bool,
    project: Option<&AnalysisProject>,
    type_db: Option<&std::sync::Arc<TypeDatabase>>,
) -> Result<()> {
    let fmt = binary.as_format();

    // Try to parse as address first
    let address = if let Some(stripped) = target.strip_prefix("0x") {
        u64::from_str_radix(stripped, 16).ok()
    } else {
        u64::from_str_radix(target, 16).ok()
    };

    let (start_addr, name) = if let Some(addr) = address {
        // Check if project has a custom name for this address
        let name = project
            .and_then(|p| p.get_function_name(addr))
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("sub_{:x}", addr));
        (addr, name)
    } else {
        // Find symbol using improved search
        let symbol = find_symbol(fmt, target)
            .with_context(|| format!("Symbol '{}' not found. It may be an external/undefined symbol (e.g., from a shared library).", target))?;
        // Check if project has a custom name for this address
        let name = project
            .and_then(|p| p.get_function_name(symbol.address))
            .map(|n| n.to_string())
            .unwrap_or_else(|| demangle_or_original(&symbol.name));
        (symbol.address, name)
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
        bail!(
            "Address {:#x} is not in an executable section - cannot decompile data",
            start_addr
        );
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

    // Build symbol table for function names, merging with project overrides
    let mut symbol_table = build_symbol_table(fmt);
    if let Some(proj) = project {
        for addr in proj.overridden_functions() {
            if let Some(name) = proj.get_function_name(addr) {
                symbol_table.insert(addr, name.to_string());
            }
        }
    }

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
    // Create constant database for magic number recognition
    let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());

    let mut decompiler = Decompiler::new()
        .with_addresses(show_addresses)
        .with_string_table(string_table)
        .with_symbol_table(symbol_table)
        .with_relocation_table(relocation_table)
        .with_dwarf_names(dwarf_names)
        .with_constant_database(const_db);
    if let Some(db) = type_db {
        decompiler = decompiler.with_type_database(db.clone());
    }
    let pseudocode = decompiler.decompile(&cfg, &name);

    println!("{}", pseudocode);

    Ok(())
}

/// Builds a string table from readable data sections in the binary.
fn build_string_table(fmt: &dyn BinaryFormat) -> StringTable {
    let mut table = StringTable::new();

    // Look for string-specific section names
    // Be conservative to avoid false positives from data sections that contain
    // integers that happen to look like short strings (e.g., value 80 = 'P')
    for section in fmt.sections() {
        let name = section.name().to_lowercase();
        // Only extract strings from sections specifically meant for strings:
        // - .rodata, .rodata.str1.1 (ELF read-only data with strings)
        // - __cstring (Mach-O C strings)
        // - .rdata (Windows read-only data)
        // Avoid __data, __const, etc. which may contain mixed data
        if name.contains("rodata")
            || name.contains("cstring")
            || name == ".rdata"
            || name == "rdata"
        {
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

    // Add all symbols (both functions and data) for proper resolution
    for symbol in fmt.symbols() {
        if symbol.address != 0 && !symbol.name.is_empty() {
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
    let end = data[offset..].iter().take(max_len).position(|&b| b == 0)?;

    // Try to convert to UTF-8 string
    let bytes = &data[offset..offset + end];
    let s = std::str::from_utf8(bytes).ok()?;

    // Skip if empty or contains non-printable characters
    if s.is_empty() || !s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return None;
    }

    // Format as a C string literal, escaping if needed
    Some(format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"")
    ))
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
                            if let Some(rodata_section) = elf.sections.iter().find(|s| {
                                elf.section_name(s)
                                    .map(|n| n == symbol.name)
                                    .unwrap_or(false)
                            }) {
                                let string_offset =
                                    rodata_section.sh_offset as usize + reloc.addend as usize;
                                read_cstring_from_elf(elf.data(), string_offset).unwrap_or_else(
                                    || format!("{}+{:#x}", symbol.name, reloc.addend),
                                )
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

/// Loads a type database based on the specified type library option.
/// If no option is given, returns None.
/// If "auto" is specified, selects based on binary format (linux/macos).
fn load_type_database(
    binary: &Binary,
    types_opt: Option<&str>,
) -> Result<Option<std::sync::Arc<TypeDatabase>>> {
    use hexray_types::builtin::{libc, linux, macos, posix};

    let types_str = match types_opt {
        Some(s) => s,
        None => return Ok(None),
    };

    let mut db = TypeDatabase::new();

    match types_str.to_lowercase().as_str() {
        "posix" => {
            posix::load_posix_types(&mut db);
        }
        "linux" => {
            posix::load_posix_types(&mut db);
            linux::load_linux_types(&mut db);
            libc::load_libc_functions(&mut db);
        }
        "macos" | "darwin" => {
            posix::load_posix_types(&mut db);
            macos::load_macos_types(&mut db);
            libc::load_libc_functions(&mut db);
        }
        "libc" => {
            posix::load_posix_types(&mut db);
            libc::load_libc_functions(&mut db);
        }
        "all" => {
            posix::load_posix_types(&mut db);
            linux::load_linux_types(&mut db);
            macos::load_macos_types(&mut db);
            libc::load_libc_functions(&mut db);
        }
        "auto" => {
            // Detect based on binary format
            posix::load_posix_types(&mut db);
            libc::load_libc_functions(&mut db);
            match binary {
                Binary::Elf(_) => linux::load_linux_types(&mut db),
                Binary::MachO(_) => macos::load_macos_types(&mut db),
                Binary::Pe(_) => {} // TODO: Windows types
            }
        }
        _ => bail!(
            "Unknown type library '{}'. Use: posix, linux, macos, libc, all, or auto",
            types_str
        ),
    }

    Ok(Some(std::sync::Arc::new(db)))
}

/// Attempts to load DWARF debug info from a binary.
/// Returns None if DWARF sections are not present.
fn load_dwarf_info(binary: &Binary) -> Option<DebugInfo> {
    let fmt = binary.as_format();

    // Get DWARF sections
    let debug_info = fmt
        .sections()
        .find(|s| s.name() == ".debug_info" || s.name() == "__debug_info")?
        .data();
    let debug_abbrev = fmt
        .sections()
        .find(|s| s.name() == ".debug_abbrev" || s.name() == "__debug_abbrev")?
        .data();
    let debug_str = fmt
        .sections()
        .find(|s| s.name() == ".debug_str" || s.name() == "__debug_str")
        .map(|s| s.data());
    let debug_line = fmt
        .sections()
        .find(|s| s.name() == ".debug_line" || s.name() == "__debug_line")
        .map(|s| s.data());

    // Determine address size based on architecture
    let address_size = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 4,
        _ => 8,
    };

    // Parse DWARF info
    parse_debug_info(
        debug_info,
        debug_abbrev,
        debug_str,
        debug_line,
        address_size,
    )
    .ok()
}

/// Gets DWARF variable names for a function at the given address.
fn get_dwarf_variable_names(
    debug_info: &DebugInfo,
    func_addr: u64,
) -> std::collections::HashMap<i128, String> {
    if let Some(func) = debug_info.find_function(func_addr) {
        func.variable_names()
    } else {
        std::collections::HashMap::new()
    }
}

/// Disassemble bytes to extract call instructions (for function discovery).
fn disassemble_for_calls<D: hexray_disasm::Disassembler>(
    disasm: &D,
    bytes: &[u8],
    start_addr: u64,
) -> Vec<hexray_core::Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;

    // Limit to 2000 instructions to prevent runaway disassembly
    while offset < bytes.len() && instructions.len() < 2000 {
        let remaining = &bytes[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                instructions.push(decoded.instruction);
                offset += decoded.size;

                // Don't stop at return - we want to find all calls in the function
                // including those after conditional returns
                if is_ret && offset >= bytes.len() / 2 {
                    // Only stop if we're past the midpoint
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

fn build_callgraph(
    fmt: &dyn BinaryFormat,
    target: &str,
    dot: bool,
    json: bool,
    html: bool,
) -> Result<()> {
    let symbols: Vec<_> = fmt.symbols().cloned().collect();
    let arch = fmt.architecture();

    // Determine which functions to analyze (address, name, size)
    // Note: Mach-O symbols don't have size info (nlist doesn't store it),
    // so we use a default size for symbols with size == 0
    let functions_to_analyze: Vec<(u64, String, u64)> = if target == "all" {
        // Start with defined internal function symbols
        let mut funcs: Vec<_> = symbols
            .iter()
            .filter(|s| {
                s.is_function() && s.address != 0 && s.is_defined() && s.section_index.is_some()
            })
            .map(|s| {
                let size = if s.size > 0 { s.size } else { 4096 }; // Larger default for actual code
                (s.address, demangle_or_original(&s.name), size)
            })
            .collect();

        // Also add the entry point if present (important for stripped binaries)
        if let Some(entry) = fmt.entry_point() {
            let entry_name = symbols
                .iter()
                .find(|s| s.address == entry)
                .map(|s| demangle_or_original(&s.name))
                .unwrap_or_else(|| format!("_start_{:x}", entry));
            if !funcs.iter().any(|(addr, _, _)| *addr == entry) {
                funcs.push((entry, entry_name, 8192)); // Entry functions are often large
            }
        }

        funcs
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

    // Helper to check if an address is in executable code (not a stub/import)
    let is_internal_code = |addr: u64| -> bool {
        fmt.executable_sections().any(|sec| {
            let sec_start = sec.virtual_address();
            let sec_end = sec_start + sec.size();
            let sec_name = sec.name();
            // Exclude stub sections
            addr >= sec_start && addr < sec_end && !sec_name.contains("stub")
        })
    };

    // Iteratively discover functions by following calls
    let mut known_functions: std::collections::HashSet<u64> =
        functions_to_analyze.iter().map(|(a, _, _)| *a).collect();
    let mut pending_functions: Vec<(u64, String, u64)> = functions_to_analyze.clone();
    let mut all_function_infos: Vec<FunctionInfo> = Vec::new();

    // Create disassembler once based on architecture
    let disasm_x86 = X86_64Disassembler::new();
    let disasm_arm64 = Arm64Disassembler::new();
    let disasm_riscv = RiscVDisassembler::new();
    let disasm_riscv32 = RiscVDisassembler::new_rv32();

    // Iteratively discover functions (up to 3 iterations to avoid infinite loops)
    for _iteration in 0..3 {
        if pending_functions.is_empty() {
            break;
        }

        // Collect function info for current batch
        let function_infos: Vec<FunctionInfo> = pending_functions
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

        // Disassemble and find call targets
        let mut new_call_targets: Vec<(u64, String, u64)> = Vec::new();
        for func_info in &function_infos {
            let instructions: Vec<hexray_core::Instruction> = match arch {
                Architecture::X86_64 | Architecture::X86 => {
                    disassemble_for_calls(&disasm_x86, &func_info.bytes, func_info.address)
                }
                Architecture::Arm64 => {
                    disassemble_for_calls(&disasm_arm64, &func_info.bytes, func_info.address)
                }
                Architecture::RiscV64 => {
                    disassemble_for_calls(&disasm_riscv, &func_info.bytes, func_info.address)
                }
                Architecture::RiscV32 => {
                    disassemble_for_calls(&disasm_riscv32, &func_info.bytes, func_info.address)
                }
                _ => Vec::new(),
            };

            // Extract call targets
            for instr in instructions {
                if let hexray_core::ControlFlow::Call { target, .. } = instr.control_flow {
                    if !known_functions.contains(&target) && is_internal_code(target) {
                        known_functions.insert(target);
                        let name = symbols
                            .iter()
                            .find(|s| s.address == target)
                            .map(|s| demangle_or_original(&s.name))
                            .unwrap_or_else(|| format!("sub_{:x}", target));
                        new_call_targets.push((target, name, 4096));
                    }
                }
            }
        }

        all_function_infos.extend(function_infos);
        pending_functions = new_call_targets;
    }

    // Build call graph using all discovered functions
    let callgraph = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            ParallelCallGraphBuilder::build(&all_function_infos, &disasm_x86, &symbols)
        }
        Architecture::Arm64 => {
            ParallelCallGraphBuilder::build(&all_function_infos, &disasm_arm64, &symbols)
        }
        Architecture::RiscV64 => {
            ParallelCallGraphBuilder::build(&all_function_infos, &disasm_riscv, &symbols)
        }
        Architecture::RiscV32 => {
            ParallelCallGraphBuilder::build(&all_function_infos, &disasm_riscv32, &symbols)
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
            let node_name = node
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", node.address));
            let callees: Vec<_> = callgraph
                .callees(node.address)
                .filter_map(|(addr, _)| callgraph.get_node(addr))
                .collect();

            if !callees.is_empty() {
                println!("{} ({:#x}):", node_name, node.address);
                for callee in callees {
                    let callee_name = callee
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("sub_{:x}", callee.address));
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
            let escaped_content = s
                .content
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

            println!(
                "{:#016x}{}: \"{}\"{}",
                s.address, type_marker, display_content, indicator_str
            );
        }
    }

    Ok(())
}

/// Decompile a function and follow internal calls recursively.
fn decompile_with_follow(
    binary: &Binary,
    target: &str,
    show_addresses: bool,
    max_depth: usize,
    project: Option<&AnalysisProject>,
    type_db: Option<&std::sync::Arc<TypeDatabase>>,
) -> Result<()> {
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
        // Check if project has a custom name for this address
        let name = project
            .and_then(|p| p.get_function_name(addr))
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("sub_{:x}", addr));
        (addr, name)
    } else {
        let symbol =
            find_symbol(fmt, target).with_context(|| format!("Symbol '{}' not found", target))?;
        // Check if project has a custom name for this address
        let name = project
            .and_then(|p| p.get_function_name(symbol.address))
            .map(|n| n.to_string())
            .unwrap_or_else(|| demangle_or_original(&symbol.name));
        (symbol.address, name)
    };

    queue.push((start_addr, name, 0));

    // Build tables once for all decompilations
    let string_table = build_string_table(fmt);
    let mut symbol_table = build_symbol_table(fmt);
    // Merge project function names into symbol table
    if let Some(proj) = project {
        for addr in proj.overridden_functions() {
            if let Some(name) = proj.get_function_name(addr) {
                symbol_table.insert(addr, name.to_string());
            }
        }
    }
    let relocation_table = build_relocation_table(binary);

    // Create constant database for magic number recognition
    let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());

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

        println!(
            "// Decompiling {} at {:#x} (depth {})\n",
            func_name, func_addr, depth
        );

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
        let mut decompiler = Decompiler::new()
            .with_addresses(show_addresses)
            .with_string_table(string_table.clone())
            .with_symbol_table(symbol_table.clone())
            .with_relocation_table(relocation_table.clone())
            .with_dwarf_names(dwarf_names)
            .with_constant_database(const_db.clone());
        if let Some(db) = type_db {
            decompiler = decompiler.with_type_database(db.clone());
        }
        let pseudocode = decompiler.decompile(&cfg, &func_name);

        println!("{}", pseudocode);

        // If we haven't reached max depth, find internal calls to follow
        if depth < max_depth {
            let call_targets = extract_internal_call_targets(&instructions, fmt);
            for (target_addr, target_name) in call_targets {
                if !decompiled.contains(&target_addr) {
                    // Check for special patterns like __libc_start_main
                    // which passes main as first argument
                    let actual_name = if func_name == "__libc_start_main"
                        || func_name.contains("libc_start_main")
                    {
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
fn extract_internal_call_targets(
    instructions: &[hexray_core::Instruction],
    fmt: &dyn BinaryFormat,
) -> Vec<(u64, String)> {
    use hexray_core::{register::x86, ControlFlow, Operand};

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
    let add_target = |target_addr: u64,
                      seen: &mut std::collections::HashSet<u64>,
                      targets: &mut Vec<(u64, String)>| {
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
                Operand::Memory(mem) => {
                    // Check for RIP-relative addressing: lea reg, [rip + offset]
                    // This is common for loading function pointers on x86_64
                    if let Some(base) = &mem.base {
                        // Check for RIP by ID (more reliable than name comparison)
                        let is_rip = base.id == x86::RIP;
                        if is_rip && mem.index.is_none() {
                            // Calculate effective address: inst_addr + inst_size + displacement
                            // For RIP-relative, displacement is relative to the next instruction
                            let effective_addr = (inst.address as i64)
                                .wrapping_add(inst.size as i64)
                                .wrapping_add(mem.displacement)
                                as u64;
                            // For RIP-relative LEA, we trust it's a valid function pointer
                            // even without a symbol (common in stripped PIE binaries)
                            if is_internal_addr(effective_addr) {
                                add_target(effective_addr, &mut seen, &mut targets);
                            }
                        }
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
        let size = if func.size > 0 {
            func.size as usize
        } else {
            256
        };
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
            println!(
                "  \"referenced_addresses\": {}",
                db.all_referenced().count()
            );
            println!("}}");
        } else {
            println!("Cross-reference Database Summary");
            println!("{}", "=".repeat(50));
            println!();
            println!("Total cross-references: {}", db.total_xrefs());
            println!("Referenced addresses: {}", db.all_referenced().count());
            println!();
            println!(
                "Use 'xrefs <address>' or 'xrefs <symbol>' to see references to a specific target."
            );
        }
    }

    Ok(())
}

/// Handle project management commands
fn handle_project_command(binary_path: &PathBuf, action: ProjectAction) -> Result<()> {
    match action {
        ProjectAction::Create { output } => {
            let project = AnalysisProject::new(binary_path).with_context(|| {
                format!("Failed to create project for {}", binary_path.display())
            })?;

            let mut project = project;
            project
                .save(&output)
                .with_context(|| format!("Failed to save project to {}", output.display()))?;

            println!("Created project: {}", output.display());
            println!("Binary: {}", binary_path.display());
        }

        ProjectAction::Info {
            project: project_path,
        } => {
            let project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            let stats = project.stats();

            println!("Project Information");
            println!("{}", "=".repeat(40));
            println!("Binary:              {}", project.binary_path.display());
            println!("Annotations:         {}", stats.annotation_count);
            println!("  Comments:          {}", stats.comment_count);
            println!("  Labels:            {}", stats.label_count);
            println!("Function overrides:  {}", stats.function_override_count);
            println!("Type overrides:      {}", stats.type_override_count);
            println!("Bookmarks:           {}", stats.bookmark_count);
        }

        ProjectAction::Comment {
            project: project_path,
            address,
            comment,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            project.set_comment(address, &comment);
            project.save(&project_path)?;

            println!("Added comment at {:#x}: {}", address, comment);
        }

        ProjectAction::Name {
            project: project_path,
            address,
            name,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            project.set_function_name(address, &name);
            project.save(&project_path)?;

            println!("Set function name at {:#x}: {}", address, name);
        }

        ProjectAction::Label {
            project: project_path,
            address,
            label,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            project.set_label(address, &label);
            project.save(&project_path)?;

            println!("Added label at {:#x}: {}", address, label);
        }

        ProjectAction::Bookmark {
            project: project_path,
            address,
            label,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            project.add_bookmark(address, label.clone());
            project.save(&project_path)?;

            if let Some(lbl) = label {
                println!("Added bookmark at {:#x}: {}", address, lbl);
            } else {
                println!("Added bookmark at {:#x}", address);
            }
        }

        ProjectAction::List {
            project: project_path,
            comments,
            functions,
            bookmarks,
        } => {
            let project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            let show_all = !comments && !functions && !bookmarks;

            if show_all || comments {
                println!("Comments");
                println!("{}", "-".repeat(40));
                let mut count = 0;
                for addr in project.annotated_addresses() {
                    if let Some(comment) = project.get_comment(addr) {
                        println!("{:#016x}: {}", addr, comment);
                        count += 1;
                    }
                }
                if count == 0 {
                    println!("(none)");
                }
                println!();
            }

            if show_all || functions {
                println!("Function Names");
                println!("{}", "-".repeat(40));
                let mut count = 0;
                for addr in project.overridden_functions() {
                    if let Some(name) = project.get_function_name(addr) {
                        println!("{:#016x}: {}", addr, name);
                        count += 1;
                    }
                }
                if count == 0 {
                    println!("(none)");
                }
                println!();
            }

            if show_all || bookmarks {
                println!("Bookmarks");
                println!("{}", "-".repeat(40));
                let bm = project.get_bookmarks();
                if bm.is_empty() {
                    println!("(none)");
                } else {
                    for b in bm {
                        if let Some(label) = &b.label {
                            println!("{:#016x}: {}", b.address, label);
                        } else {
                            println!("{:#016x}", b.address);
                        }
                    }
                }
                println!();
            }
        }

        ProjectAction::Undo {
            project: project_path,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            match project.undo() {
                Ok(msg) => {
                    project.save(&project_path)?;
                    println!("{}", msg);
                }
                Err(e) => {
                    println!("Cannot undo: {}", e);
                }
            }
        }

        ProjectAction::Redo {
            project: project_path,
        } => {
            let mut project = AnalysisProject::load(&project_path)
                .with_context(|| format!("Failed to load project: {}", project_path.display()))?;

            match project.redo() {
                Ok(msg) => {
                    project.save(&project_path)?;
                    println!("{}", msg);
                }
                Err(e) => {
                    println!("Cannot redo: {}", e);
                }
            }
        }
    }

    Ok(())
}

// =============================================================================
// Session Command Handlers
// =============================================================================

fn handle_session_list(directory: &Path) -> Result<()> {
    println!("Sessions in {}:", directory.display());
    println!("{}", "-".repeat(80));

    let sessions = list_sessions(directory)?;

    if sessions.is_empty() {
        println!("No session files (.hrp) found.");
        return Ok(());
    }

    println!("{:<40} {:<20} {:<20}", "File", "Binary", "Last Accessed");
    println!("{}", "-".repeat(80));

    for (path, meta) in sessions {
        let filename = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "???".to_string());
        let binary_name = PathBuf::from(&meta.binary_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "???".to_string());
        let last_accessed = meta.last_accessed.format("%Y-%m-%d %H:%M");

        println!("{:<40} {:<20} {:<20}", filename, binary_name, last_accessed);
    }

    Ok(())
}

fn handle_session_info(session_path: &Path) -> Result<()> {
    let session = Session::resume(session_path)?;
    let stats = session.stats()?;

    println!("Session Information");
    println!("===================");
    println!("Session ID:    {}", session.meta.id);
    println!("Name:          {}", session.meta.name);
    println!("Binary:        {}", session.meta.binary_path);
    println!("Binary Hash:   {}", &session.meta.binary_hash[..16]);
    println!(
        "Created:       {}",
        session.meta.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!(
        "Last Accessed: {}",
        session.meta.last_accessed.format("%Y-%m-%d %H:%M:%S UTC")
    );
    println!();
    println!("Statistics");
    println!("----------");
    println!("History entries: {}", stats.history_entries);
    println!("Annotations:     {}", stats.annotations);
    println!("  Renames:       {}", stats.renames);
    println!("  Comments:      {}", stats.comments);
    println!("  Bookmarks:     {}", stats.bookmarks);

    // Verify binary
    match session.verify_binary() {
        Ok(true) => println!("\nBinary verification: OK"),
        Ok(false) => println!("\nWARNING: Binary has changed since session creation!"),
        Err(e) => println!("\nWARNING: Could not verify binary: {}", e),
    }

    Ok(())
}

fn handle_session_resume(session_path: &Path) -> Result<()> {
    let session = Session::resume(session_path)?;
    let binary_path = PathBuf::from(&session.meta.binary_path);

    // Load the binary
    let data = fs::read(&binary_path)
        .with_context(|| format!("Failed to read binary: {}", binary_path.display()))?;

    let binary = match detect_format(&data) {
        BinaryType::Elf => Binary::Elf(Elf::parse(&data)?),
        BinaryType::MachO => Binary::MachO(MachO::parse(&data)?),
        BinaryType::Pe => Binary::Pe(Pe::parse(&data)?),
        BinaryType::Unknown => bail!("Unknown binary format"),
    };

    run_session_repl(session, binary)?;
    Ok(())
}

fn handle_session_new(binary_path: &Path, output: Option<&PathBuf>) -> Result<()> {
    // Determine session file path
    let session_path = match output {
        Some(p) => p.clone(),
        None => {
            let stem = binary_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "session".to_string());
            PathBuf::from(format!("{}.hrp", stem))
        }
    };

    // Create session
    let session = Session::create(binary_path, &session_path)?;
    println!("Created session: {}", session_path.display());

    // Load binary and start REPL
    let data = fs::read(binary_path)?;
    let binary = match detect_format(&data) {
        BinaryType::Elf => Binary::Elf(Elf::parse(&data)?),
        BinaryType::MachO => Binary::MachO(MachO::parse(&data)?),
        BinaryType::Pe => Binary::Pe(Pe::parse(&data)?),
        BinaryType::Unknown => bail!("Unknown binary format"),
    };

    run_session_repl(session, binary)?;
    Ok(())
}

fn handle_session_export(
    session_path: &Path,
    output: Option<&PathBuf>,
    format: &str,
) -> Result<()> {
    let session = Session::resume(session_path)?;
    let history = session.get_history(None)?;

    let content = match format {
        "json" => serde_json::to_string_pretty(&history)?,
        _ => {
            let mut s = String::new();
            s.push_str(&format!("# Session: {}\n", session.meta.name));
            s.push_str(&format!("# Binary: {}\n", session.meta.binary_path));
            s.push_str(&format!("# Created: {}\n", session.meta.created_at));
            s.push_str(&format!("# Exported: {}\n\n", chrono::Utc::now()));

            for entry in &history {
                s.push_str(&format!("--- [{}] {} ---\n", entry.index, entry.timestamp));
                s.push_str(&format!("> {}\n", entry.command));
                if !entry.output.is_empty() {
                    s.push_str(&entry.output);
                    if !entry.output.ends_with('\n') {
                        s.push('\n');
                    }
                }
                s.push('\n');
            }
            s
        }
    };

    match output {
        Some(path) => {
            fs::write(path, &content)?;
            println!(
                "Exported {} history entries to {}",
                history.len(),
                path.display()
            );
        }
        None => {
            println!("{}", content);
        }
    }

    Ok(())
}

// ============================================================================
// REPL JSON Output Types
// ============================================================================

/// Check if --json or -j flag is present in command parts
fn is_json_mode(parts: &[&str]) -> bool {
    parts.iter().any(|&p| p == "--json" || p == "-j")
}

/// Binary information for JSON output
#[derive(Serialize)]
struct JsonBinaryInfo {
    format: String,
    architecture: String,
    endianness: String,
    entry_point: Option<String>,
    symbol_count: usize,
}

/// Symbol information for JSON output
#[derive(Serialize)]
struct JsonSymbol {
    address: String,
    size: u64,
    #[serde(rename = "type")]
    symbol_type: String,
    binding: String,
    name: String,
    demangled: Option<String>,
}

/// Instruction for JSON output
#[derive(Serialize)]
struct JsonInstruction {
    address: String,
    bytes: String,
    mnemonic: String,
    operands: String,
    comment: Option<String>,
}

/// Disassembly result for JSON output
#[derive(Serialize)]
struct JsonDisasm {
    target: String,
    start_address: String,
    instructions: Vec<JsonInstruction>,
}

/// Decompilation result for JSON output
#[derive(Serialize)]
struct JsonDecompile {
    target: String,
    address: String,
    code: String,
}

/// Cross-reference for JSON output
#[derive(Serialize)]
struct JsonXref {
    from: String,
    #[serde(rename = "type")]
    xref_type: String,
}

/// Xrefs result for JSON output
#[derive(Serialize)]
struct JsonXrefs {
    target: String,
    refs: Vec<JsonXref>,
}

/// CFG block for JSON output
#[derive(Serialize)]
struct JsonCfgBlock {
    id: u32,
    start_address: String,
    instruction_count: usize,
    successors: Vec<u32>,
}

/// CFG result for JSON output
#[derive(Serialize)]
struct JsonCfg {
    target: String,
    entry_block: u32,
    blocks: Vec<JsonCfgBlock>,
}

/// Run the interactive REPL with a session
fn run_session_repl(session: Session, binary: Binary<'_>) -> Result<()> {
    let mut repl = Repl::new(session)?;

    repl.run(|session, line| {
        // Parse the REPL command and execute it
        execute_repl_command(session, &binary, line)
    })?;

    Ok(())
}

/// Execute a command within the REPL context
fn execute_repl_command(session: &mut Session, binary: &Binary<'_>, line: &str) -> Result<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(String::new());
    }

    let fmt = binary.as_format();

    match parts[0] {
        "info" => {
            let sym_count: usize = fmt.symbols().count();

            if is_json_mode(&parts) {
                let info = JsonBinaryInfo {
                    format: binary.format_name().to_string(),
                    architecture: format!("{:?}", fmt.architecture()),
                    endianness: format!("{:?}", fmt.endianness()),
                    entry_point: fmt.entry_point().map(|e| format!("{:#x}", e)),
                    symbol_count: sym_count,
                };
                Ok(serde_json::to_string_pretty(&info)?)
            } else {
                let mut output = String::new();
                output.push_str("Binary Information\n");
                output.push_str("==================\n");
                output.push_str(&format!("Format:        {}\n", binary.format_name()));
                output.push_str(&format!("Architecture:  {:?}\n", fmt.architecture()));
                output.push_str(&format!("Endianness:    {:?}\n", fmt.endianness()));
                if let Some(entry) = fmt.entry_point() {
                    output.push_str(&format!("Entry Point:   {:#x}\n", entry));
                }
                output.push_str(&format!("Symbols:       {}\n", sym_count));
                Ok(output)
            }
        }

        "symbols" | "syms" => {
            let functions_only = parts.iter().any(|&p| p == "-f" || p == "--functions");
            let json_mode = is_json_mode(&parts);

            let mut symbols: Vec<_> = fmt.symbols().collect();
            symbols.sort_by_key(|s| s.address);

            if json_mode {
                let json_symbols: Vec<JsonSymbol> = symbols
                    .iter()
                    .filter(|s| !s.name.is_empty())
                    .filter(|s| !functions_only || s.is_function())
                    .map(|symbol| {
                        let demangled = demangle_or_original(&symbol.name);
                        let display_name = session
                            .get_rename(symbol.address)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| demangled.clone());
                        JsonSymbol {
                            address: format!("{:#x}", symbol.address),
                            size: symbol.size,
                            symbol_type: if symbol.is_function() {
                                "function".to_string()
                            } else {
                                "other".to_string()
                            },
                            binding: match symbol.binding {
                                hexray_core::SymbolBinding::Local => "local".to_string(),
                                hexray_core::SymbolBinding::Global => "global".to_string(),
                                hexray_core::SymbolBinding::Weak => "weak".to_string(),
                                _ => "other".to_string(),
                            },
                            name: display_name,
                            demangled: if demangled != symbol.name {
                                Some(demangled)
                            } else {
                                None
                            },
                        }
                    })
                    .collect();
                Ok(serde_json::to_string_pretty(&json_symbols)?)
            } else {
                let mut output = String::new();
                output.push_str(&format!(
                    "{:<16} {:<8} {:<8} {:<8} {}\n",
                    "Address", "Size", "Type", "Bind", "Name"
                ));
                output.push_str(&format!("{}\n", "-".repeat(70)));

                for symbol in symbols {
                    if functions_only && !symbol.is_function() {
                        continue;
                    }
                    if symbol.name.is_empty() {
                        continue;
                    }

                    let type_str = if symbol.is_function() {
                        "FUNC"
                    } else {
                        "OTHER"
                    };
                    let bind_str = match symbol.binding {
                        hexray_core::SymbolBinding::Local => "LOCAL",
                        hexray_core::SymbolBinding::Global => "GLOBAL",
                        hexray_core::SymbolBinding::Weak => "WEAK",
                        _ => "OTHER",
                    };

                    let name = session
                        .get_rename(symbol.address)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| demangle_or_original(&symbol.name));

                    output.push_str(&format!(
                        "{:#016x} {:<8} {:<8} {:<8} {}\n",
                        symbol.address, symbol.size, type_str, bind_str, name
                    ));
                }
                Ok(output)
            }
        }

        "sections" => {
            let mut output = String::new();
            output.push_str(&format!(
                "{:<4} {:<24} {:<16} {:<16} {:<8}\n",
                "Idx", "Name", "Address", "Size", "Flags"
            ));
            output.push_str(&format!("{}\n", "-".repeat(75)));

            for (idx, section) in fmt.sections().enumerate() {
                output.push_str(&format!(
                    "{:<4} {:<24} {:#016x} {:#016x} {:<8}\n",
                    idx,
                    section.name(),
                    section.virtual_address(),
                    section.size(),
                    ""
                ));
            }
            Ok(output)
        }

        "strings" => {
            let min_len = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(4);
            let mut output = String::new();
            let mut all_strings = Vec::new();

            // Detect strings in all sections
            let config = StringConfig {
                min_length: min_len,
                ..Default::default()
            };
            let detector = StringDetector::with_config(config);

            for section in fmt.sections() {
                let bytes = section.data();
                let base_addr = section.virtual_address();
                all_strings.extend(detector.detect(bytes, base_addr));
            }

            output.push_str(&format!("{:<16} {:<6} {}\n", "Address", "Length", "String"));
            output.push_str(&format!("{}\n", "-".repeat(60)));

            for s in all_strings.iter().take(100) {
                let display = if s.content.len() > 60 {
                    format!("{}...", &s.content[..57])
                } else {
                    s.content.clone()
                };
                output.push_str(&format!(
                    "{:#016x} {:<6} {}\n",
                    s.address, s.length, display
                ));
            }

            if all_strings.len() > 100 {
                output.push_str(&format!("... ({} more)\n", all_strings.len() - 100));
            }

            Ok(output)
        }

        "functions" | "funcs" => {
            let mut output = String::new();
            output.push_str(&format!("{:<16} {:<8} {}\n", "Address", "Size", "Name"));
            output.push_str(&format!("{}\n", "-".repeat(60)));

            let mut functions: Vec<_> = fmt
                .symbols()
                .filter(|s| s.is_function() && !s.name.is_empty())
                .collect();
            functions.sort_by_key(|s| s.address);

            for sym in functions {
                let name = session
                    .get_rename(sym.address)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| demangle_or_original(&sym.name));
                output.push_str(&format!("{:#016x} {:<8} {}\n", sym.address, sym.size, name));
            }
            Ok(output)
        }

        "hexdump" | "hex" | "x" => {
            if parts.len() < 2 {
                return Ok("Usage: hexdump <address> [length]".to_string());
            }

            let addr = match parse_address_str(parts[1]) {
                Ok(a) => a,
                Err(_) => {
                    // Try to find symbol
                    if let Some(sym) = fmt.symbols().find(|s| s.name == parts[1]) {
                        sym.address
                    } else {
                        return Ok(format!("Invalid address or symbol: {}", parts[1]));
                    }
                }
            };

            let len = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(256);

            if let Some(bytes) = fmt.bytes_at(addr, len) {
                let mut output = String::new();
                for (i, chunk) in bytes.chunks(16).enumerate() {
                    let offset = addr + (i * 16) as u64;
                    output.push_str(&format!("{:#010x}  ", offset));

                    // Hex bytes
                    for (j, byte) in chunk.iter().enumerate() {
                        output.push_str(&format!("{:02x} ", byte));
                        if j == 7 {
                            output.push(' ');
                        }
                    }

                    // Padding for incomplete lines
                    for j in chunk.len()..16 {
                        output.push_str("   ");
                        if j == 7 {
                            output.push(' ');
                        }
                    }

                    output.push_str(" |");

                    // ASCII representation
                    for byte in chunk {
                        if *byte >= 0x20 && *byte < 0x7f {
                            output.push(*byte as char);
                        } else {
                            output.push('.');
                        }
                    }

                    output.push_str("|\n");
                }
                Ok(output)
            } else {
                Ok(format!("No data at address {:#x}", addr))
            }
        }

        "cfg" => {
            let json_mode = is_json_mode(&parts);
            let parts: Vec<&str> = parts
                .iter()
                .filter(|&&p| p != "--json" && p != "-j")
                .copied()
                .collect();

            if parts.len() < 2 {
                return Ok("Usage: cfg <symbol|address> [--json]".to_string());
            }

            let target = parts[1];

            // Find function
            let (addr, size) = if let Ok(a) = parse_address_str(target) {
                if let Some(sym) = fmt.symbols().find(|s| s.address == a && s.is_function()) {
                    (a, sym.size as usize)
                } else {
                    (a, 1000)
                }
            } else if let Some(sym) = fmt
                .symbols()
                .find(|s| s.name == target || demangle_or_original(&s.name) == target)
            {
                let size = if sym.size > 0 {
                    sym.size as usize
                } else {
                    1000
                };
                (sym.address, size)
            } else {
                return Ok(format!("Symbol not found: {}", target));
            };

            if let Some(bytes) = fmt.bytes_at(addr, size.max(1000)) {
                let results = disassemble_block_for_arch(fmt.architecture(), bytes, addr);
                let instructions: Vec<_> = results
                    .into_iter()
                    .filter_map(|r| r.ok())
                    .take(500)
                    .collect();

                if instructions.is_empty() {
                    return Ok("No instructions decoded".to_string());
                }

                let cfg = CfgBuilder::build(&instructions, addr);

                let mut block_ids: Vec<_> = cfg.block_ids().collect();
                block_ids.sort_by_key(|id| id.0);

                if json_mode {
                    let blocks: Vec<JsonCfgBlock> = block_ids
                        .iter()
                        .filter_map(|&block_id| {
                            cfg.block(block_id).map(|block| {
                                let succs = cfg.successors(block_id);
                                JsonCfgBlock {
                                    id: block_id.0,
                                    start_address: format!("{:#x}", block.start),
                                    instruction_count: block.instructions.len(),
                                    successors: succs.iter().map(|id| id.0).collect(),
                                }
                            })
                        })
                        .collect();

                    let entry_id = cfg.entry.0;
                    let result = JsonCfg {
                        target: target.to_string(),
                        entry_block: entry_id,
                        blocks,
                    };
                    Ok(serde_json::to_string_pretty(&result)?)
                } else {
                    // Generate ASCII CFG
                    let mut output = String::new();
                    output.push_str(&format!("Control Flow Graph for {}\n", target));
                    output.push_str(&format!("{}\n\n", "=".repeat(40)));

                    for block_id in block_ids {
                        if let Some(block) = cfg.block(block_id) {
                            output
                                .push_str(&format!("Block {} @ {:#x}:\n", block_id.0, block.start));

                            // Show first few instructions
                            for inst in block.instructions.iter().take(5) {
                                output.push_str(&format!("  {:#x}: {}\n", inst.address, inst));
                            }
                            if block.instructions.len() > 5 {
                                output.push_str(&format!(
                                    "  ... ({} more)\n",
                                    block.instructions.len() - 5
                                ));
                            }

                            // Show successors
                            let succs = cfg.successors(block_id);
                            if !succs.is_empty() {
                                let succ_ids: Vec<_> = succs.iter().map(|id| id.0).collect();
                                output.push_str(&format!("  -> {:?}\n", succ_ids));
                            }
                            output.push('\n');
                        }
                    }

                    Ok(output)
                }
            } else {
                Ok(format!("No data at address {:#x}", addr))
            }
        }

        "imports" => {
            let mut output = String::new();
            output.push_str(&format!("{:<16} {}\n", "Address", "Name"));
            output.push_str(&format!("{}\n", "-".repeat(50)));

            // For PE, imports are in the symbol table with specific characteristics
            // For ELF, undefined symbols are imports
            // For Mach-O, look for undefined external symbols
            for sym in fmt.symbols() {
                let is_import =
                    sym.address == 0 || sym.name.starts_with("__imp_") || sym.name.contains("@");
                if is_import && !sym.name.is_empty() {
                    output.push_str(&format!(
                        "{:#016x} {}\n",
                        sym.address,
                        demangle_or_original(&sym.name)
                    ));
                }
            }
            Ok(output)
        }

        "exports" => {
            let mut output = String::new();
            output.push_str(&format!("{:<16} {}\n", "Address", "Name"));
            output.push_str(&format!("{}\n", "-".repeat(50)));

            // Exported symbols typically have addresses and are global
            for sym in fmt.symbols() {
                if sym.address != 0 && sym.is_global() && !sym.name.is_empty() {
                    output.push_str(&format!(
                        "{:#016x} {}\n",
                        sym.address,
                        demangle_or_original(&sym.name)
                    ));
                }
            }
            Ok(output)
        }

        "disasm" | "d" => {
            if parts.len() < 2 {
                return Ok("Usage: disasm <symbol|address> [count] [--json]".to_string());
            }

            let target = parts[1];
            let json_mode = is_json_mode(&parts);
            let count = parts
                .iter()
                .filter(|&&p| p != "--json" && p != "-j")
                .nth(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(50);

            // Try to parse as address
            let (addr, size) = if let Ok(a) = parse_address_str(target) {
                (a, count * 10) // Estimate bytes
            } else {
                // Try to find symbol
                if let Some(sym) = fmt
                    .symbols()
                    .find(|s| s.name == target || demangle_or_original(&s.name) == target)
                {
                    let size = if sym.size > 0 {
                        sym.size as usize
                    } else {
                        count * 10
                    };
                    (sym.address, size)
                } else {
                    return Ok(format!("Symbol not found: {}", target));
                }
            };

            if let Some(bytes) = fmt.bytes_at(addr, size) {
                let results = disassemble_block_for_arch(fmt.architecture(), bytes, addr);

                if json_mode {
                    let mut json_instructions = Vec::new();
                    let mut offset = 0usize;

                    for result in results.into_iter().take(count) {
                        match result {
                            Ok(inst) => {
                                let inst_bytes = &bytes[offset..offset + inst.size];
                                let bytes_hex = inst_bytes
                                    .iter()
                                    .map(|b| format!("{:02x}", b))
                                    .collect::<String>();

                                json_instructions.push(JsonInstruction {
                                    address: format!("{:#x}", inst.address),
                                    bytes: bytes_hex,
                                    mnemonic: inst.mnemonic.clone(),
                                    operands: inst
                                        .operands
                                        .iter()
                                        .map(|o| o.to_string())
                                        .collect::<Vec<_>>()
                                        .join(", "),
                                    comment: session
                                        .get_comment(inst.address)
                                        .map(|s| s.to_string()),
                                });
                                offset += inst.size;
                            }
                            Err(_) => {
                                offset += 1;
                            }
                        }
                    }

                    let result = JsonDisasm {
                        target: target.to_string(),
                        start_address: format!("{:#x}", addr),
                        instructions: json_instructions,
                    };
                    Ok(serde_json::to_string_pretty(&result)?)
                } else {
                    let mut output = String::new();

                    for (i, result) in results.into_iter().enumerate().take(count) {
                        match result {
                            Ok(inst) => {
                                let comment = session
                                    .get_comment(inst.address)
                                    .map(|c| format!("  ; {}", c))
                                    .unwrap_or_default();
                                output.push_str(&format!(
                                    "{:#010x}  {:<32}{}\n",
                                    inst.address,
                                    inst.to_string(),
                                    comment
                                ));
                            }
                            Err(_) => {
                                let estimated_addr = addr + i as u64;
                                output.push_str(&format!("{:#010x}  <invalid>\n", estimated_addr));
                            }
                        }
                    }
                    Ok(output)
                }
            } else {
                Ok(format!("No data at address {:#x}", addr))
            }
        }

        "decompile" | "dec" => {
            if parts.len() < 2 {
                return Ok("Usage: decompile <symbol|address> [--json]".to_string());
            }

            let target = parts[1];
            let json_mode = is_json_mode(&parts);

            // Find function
            let (addr, size) = if let Ok(a) = parse_address_str(target) {
                // Find symbol at address for size
                if let Some(sym) = fmt.symbols().find(|s| s.address == a && s.is_function()) {
                    (a, sym.size as usize)
                } else {
                    (a, 1000) // Default size
                }
            } else if let Some(sym) = fmt
                .symbols()
                .find(|s| s.name == target || demangle_or_original(&s.name) == target)
            {
                let size = if sym.size > 0 {
                    sym.size as usize
                } else {
                    1000
                };
                (sym.address, size)
            } else {
                return Ok(format!("Symbol not found: {}", target));
            };

            if let Some(bytes) = fmt.bytes_at(addr, size.max(1000)) {
                // Disassemble the function
                let results = disassemble_block_for_arch(fmt.architecture(), bytes, addr);
                let instructions: Vec<_> = results
                    .into_iter()
                    .filter_map(|r| r.ok())
                    .take(500)
                    .take_while(|inst| !inst.is_return())
                    .chain(
                        // Include one return instruction if we stopped at one
                        disassemble_block_for_arch(fmt.architecture(), bytes, addr)
                            .into_iter()
                            .filter_map(|r| r.ok())
                            .take(500)
                            .find(|inst| inst.is_return()),
                    )
                    .collect();

                if instructions.is_empty() {
                    return Ok("No instructions decoded".to_string());
                }

                let cfg = CfgBuilder::build(&instructions, addr);

                // Build symbol table from session renames
                let mut symbols = SymbolTable::new();
                for (rename_addr, name) in session.get_all_annotations(AnnotationKind::Rename) {
                    symbols.insert(rename_addr, name);
                }
                // Add original symbols
                for sym in fmt.symbols() {
                    symbols.insert(sym.address, demangle_or_original(&sym.name));
                }

                // Get function name
                let func_name = session
                    .get_rename(addr)
                    .map(|s| s.to_string())
                    .or_else(|| {
                        fmt.symbols()
                            .find(|s| s.address == addr)
                            .map(|s| demangle_or_original(&s.name))
                    })
                    .unwrap_or_else(|| format!("sub_{:x}", addr));

                let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());
                let decompiler = Decompiler::new()
                    .with_addresses(false)
                    .with_symbol_table(symbols)
                    .with_constant_database(const_db);

                let pseudo_code = decompiler.decompile(&cfg, &func_name);

                if json_mode {
                    let result = JsonDecompile {
                        target: target.to_string(),
                        address: format!("{:#x}", addr),
                        code: pseudo_code,
                    };
                    Ok(serde_json::to_string_pretty(&result)?)
                } else {
                    Ok(pseudo_code)
                }
            } else {
                Ok(format!("No data at address {:#x}", addr))
            }
        }

        "xrefs" => {
            let json_mode = is_json_mode(&parts);
            let parts: Vec<&str> = parts
                .iter()
                .filter(|&&p| p != "--json" && p != "-j")
                .copied()
                .collect();

            if parts.len() < 2 {
                return Ok("Usage: xrefs <address> [--json]".to_string());
            }

            let addr = match parse_address_str(parts[1]) {
                Ok(a) => a,
                Err(_) => {
                    // Try to find symbol
                    if let Some(sym) = fmt.symbols().find(|s| s.name == parts[1]) {
                        sym.address
                    } else {
                        return Ok(format!("Invalid address or symbol: {}", parts[1]));
                    }
                }
            };

            // Build xref database (this is expensive, could be cached in session)
            let mut builder = XrefBuilder::new();

            for section in fmt.sections() {
                if section.is_executable() {
                    let bytes = section.data();
                    let section_addr = section.virtual_address();
                    let results =
                        disassemble_block_for_arch(fmt.architecture(), bytes, section_addr);
                    for inst in results.into_iter().flatten() {
                        builder.analyze_instruction(&inst);
                    }
                }
            }

            let xref_db = builder.build();
            let refs = xref_db.refs_to(addr);

            if refs.is_empty() {
                if json_mode {
                    let result = JsonXrefs {
                        target: format!("{:#x}", addr),
                        refs: vec![],
                    };
                    return Ok(serde_json::to_string_pretty(&result)?);
                }
                return Ok(format!("No references to {:#x}", addr));
            }

            if json_mode {
                let json_refs: Vec<JsonXref> = refs
                    .iter()
                    .map(|xref| {
                        let type_str = match xref.xref_type {
                            XrefType::Call => "call",
                            XrefType::Jump => "jump",
                            XrefType::DataRead => "read",
                            XrefType::DataWrite => "write",
                            XrefType::Unknown => "unknown",
                        };
                        JsonXref {
                            from: format!("{:#x}", xref.from),
                            xref_type: type_str.to_string(),
                        }
                    })
                    .collect();

                let result = JsonXrefs {
                    target: format!("{:#x}", addr),
                    refs: json_refs,
                };
                Ok(serde_json::to_string_pretty(&result)?)
            } else {
                let mut output = String::new();
                output.push_str(&format!("Cross-references to {:#x}:\n", addr));
                output.push_str(&format!("{}\n", "-".repeat(50)));

                for xref in refs {
                    let type_str = match xref.xref_type {
                        XrefType::Call => "CALL",
                        XrefType::Jump => "JUMP",
                        XrefType::DataRead => "READ",
                        XrefType::DataWrite => "WRITE",
                        XrefType::Unknown => "UNKNOWN",
                    };
                    output.push_str(&format!("{:#016x}  {}\n", xref.from, type_str));
                }

                Ok(output)
            }
        }

        _ => Ok(format!(
            "Unknown command: {}. Type 'help' for available commands.",
            parts[0]
        )),
    }
}

fn parse_address_str(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).context("Invalid address")
}

/// Helper function to disassemble a block of bytes using the appropriate architecture
fn disassemble_block_for_arch(
    arch: Architecture,
    bytes: &[u8],
    start_addr: u64,
) -> Vec<Result<hexray_core::Instruction, hexray_disasm::DecodeError>> {
    match arch {
        Architecture::X86_64 | Architecture::X86 => {
            X86_64Disassembler::new().disassemble_block(bytes, start_addr)
        }
        Architecture::Arm64 => Arm64Disassembler::new().disassemble_block(bytes, start_addr),
        Architecture::RiscV64 => RiscVDisassembler::new().disassemble_block(bytes, start_addr),
        Architecture::RiscV32 => RiscVDisassembler::new_rv32().disassemble_block(bytes, start_addr),
        _ => X86_64Disassembler::new().disassemble_block(bytes, start_addr),
    }
}
