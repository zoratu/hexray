//! hexray - A multi-architecture disassembler
//!
//! # Usage
//!
//! ```text
//! hexray <binary>              Disassemble the entry point
//! hexray <binary> -s <symbol>  Disassemble a specific symbol/function
//! hexray <binary> --sections   List sections
//! hexray <binary> --symbols    List symbols
//! ```

#![forbid(unsafe_code)]
// rust 1.95 collapsible-match style lint; matches the policy in
// hexray-analysis (see its `lib.rs`).
#![allow(clippy::collapsible_match, clippy::collapsible_if)]

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use hexray_analysis::cfg_builder::resolve_computed_dispatch_targets;
use hexray_analysis::{
    add_exception_section_xrefs, is_noreturn_function_name, is_ubsan_handler_function_name,
    AnalysisProject, BinaryDataContext, BinaryDiff, CallGraph, CallGraphBuilder,
    CallGraphDotExporter, CallGraphHtmlExporter, CallGraphJsonExporter, CallSite, CallType,
    CfgBuilder, CfgDotExporter, CfgHtmlExporter, CfgJsonExporter, Decompiler, DecompilerConfig,
    ExceptionExtractor, ExceptionInfo, FunctionInfo, OptimizationLevel, OptimizationPass,
    ParallelCallGraphBuilder, Patch, PatchType, RelocationTable, RttiParser, StringConfig,
    StringDetector, StringTable, SymbolTable, XrefBuilder, XrefType,
};
use hexray_core::{Architecture, Endianness};
use hexray_demangle::demangle_or_original;
use hexray_disasm::{Arm64Disassembler, Disassembler, RiscVDisassembler, X86_64Disassembler};
use hexray_formats::dwarf::{
    decode_uleb128, parse_debug_info, AttributeValue, DebugInfo, Die, DwAt, DwTag,
};
use hexray_formats::{detect_format, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use hexray_signatures::{builtin as sig_builtin, SignatureMatcher};
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

    /// For universal (fat) Mach-O input, select an architecture slice
    /// (e.g. x86_64, arm64, arm64e). Defaults to x86_64 then arm64.
    #[arg(long)]
    arch: Option<String>,
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
    /// Compare two GPU binaries kernel-by-kernel (cross-vendor capable)
    Cmp {
        /// Path to the second binary
        other: PathBuf,
    },
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
        /// Optimization level: none (0), basic (1), standard (2), aggressive (3)
        #[arg(long, short = 'O', default_value = "2")]
        opt_level: String,
        /// Enable specific optimization passes (can be repeated)
        #[arg(long = "enable-pass")]
        enable_passes: Vec<String>,
        /// Disable specific optimization passes (can be repeated)
        #[arg(long = "disable-pass")]
        disable_passes: Vec<String>,
        /// List available optimization passes and exit
        #[arg(long)]
        list_passes: bool,
        /// Show signature-recovery diagnostics (including function-pointer provenance)
        #[arg(long)]
        diagnostics: bool,
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
    /// Compare two binary versions and show affected functions
    Diff {
        /// Path to the original binary
        original: PathBuf,
        /// Path to the modified binary
        modified: PathBuf,
        /// Output in JSON format
        #[arg(long)]
        json: bool,
        /// Show detailed patch information
        #[arg(long, short)]
        verbose: bool,
    },
}

/// Project management actions
#[derive(Subcommand, Clone)]
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

fn normalize_hex_address_target(s: &str) -> &str {
    let s = s.strip_prefix("sub_").unwrap_or(s);
    s.strip_prefix("0x").unwrap_or(s)
}

/// Parse a hex string (with optional `sub_`/`0x` prefix) into u64.
pub fn parse_hex(s: &str) -> Result<u64, String> {
    let s = normalize_hex_address_target(s);
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

    fn exception_info_for_function(&self, func_start: u64, func_end: u64) -> Option<ExceptionInfo> {
        let extractor = match self {
            Self::Elf(elf) => ExceptionExtractor::from_elf(elf).ok()?,
            Self::MachO(macho) => ExceptionExtractor::from_elf(macho).ok()?,
            Self::Pe(pe) => ExceptionExtractor::from_elf(pe).ok()?,
        };
        let mut info = extractor.get_exception_info(func_start, func_end)?;
        resolve_exception_type_names(self.as_format(), &mut info);
        Some(info)
    }

    fn exception_metadata_summary(&self) -> Option<ExceptionMetadataSummary> {
        let extractor = match self {
            Self::Elf(elf) => ExceptionExtractor::from_elf(elf).ok()?,
            Self::MachO(macho) => ExceptionExtractor::from_elf(macho).ok()?,
            Self::Pe(pe) => ExceptionExtractor::from_elf(pe).ok()?,
        };

        Some(ExceptionMetadataSummary {
            fde_count: extractor.fde_count(),
            personalities: extractor.personality_functions(),
            lsda_section_name: exception_lsda_section_name(self.as_format()),
        })
    }
}

fn resolve_exception_type_names(fmt: &dyn BinaryFormat, info: &mut ExceptionInfo) {
    for try_block in &mut info.try_blocks {
        for handler in &mut try_block.handlers {
            let Some(typeinfo_addr) =
                parse_exception_type_placeholder(handler.catch_type.as_deref())
            else {
                continue;
            };

            if let Some(name) = resolve_exception_type_name(fmt, typeinfo_addr) {
                handler.catch_type = Some(name);
            }
        }
    }
}

fn parse_exception_type_placeholder(value: Option<&str>) -> Option<u64> {
    let raw = value?.strip_prefix("type@0x")?;
    u64::from_str_radix(raw, 16).ok()
}

fn resolve_exception_type_name(fmt: &dyn BinaryFormat, addr: u64) -> Option<String> {
    let symbol = fmt.symbol_at(addr)?;
    demangle_exception_typeinfo_symbol_name(&symbol.name).or_else(|| {
        demangle_or_original(&symbol.name)
            .strip_prefix("typeinfo for ")
            .map(str::to_string)
    })
}

fn demangle_exception_typeinfo_symbol_name(raw_name: &str) -> Option<String> {
    let unversioned = hexray_core::unversioned_symbol_name(raw_name);
    let mangled = &unversioned[unversioned.find("_ZTI")? + 4..];
    if mangled.is_empty() {
        return None;
    }

    let parser = RttiParser::new(8, Endianness::Little);
    let demangled = parser.demangle_type_name(mangled);
    if demangled != mangled {
        return Some(demangled);
    }

    None
}

#[derive(Debug, Clone, Default)]
struct ExceptionMetadataSummary {
    fde_count: usize,
    personalities: Vec<u64>,
    lsda_section_name: Option<String>,
}

fn exception_lsda_section_name(fmt: &dyn BinaryFormat) -> Option<String> {
    fmt.sections().find_map(|section| {
        let name = section.name();
        if matches!(name, ".gcc_except_table" | "__gcc_except_tab")
            || name.ends_with(".gcc_except_table")
            || name.ends_with("__gcc_except_tab")
        {
            Some(section.name().to_string())
        } else {
            None
        }
    })
}

fn format_exception_personality(binary: &Binary<'_>, addr: u64) -> String {
    match binary.as_format().symbol_at(addr) {
        Some(symbol) if !symbol.name.is_empty() => {
            format!("{} ({:#x})", demangle_or_original(&symbol.name), addr)
        }
        _ => format!("{:#x}", addr),
    }
}

fn append_exception_metadata(output: &mut String, binary: &Binary<'_>) {
    let Some(summary) = binary.exception_metadata_summary() else {
        return;
    };

    let personality = if summary.personalities.is_empty() {
        "none".to_string()
    } else {
        summary
            .personalities
            .iter()
            .map(|addr| format_exception_personality(binary, *addr))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let lsda = match summary.lsda_section_name {
        Some(name) => format!("{} (present)", name),
        None => "absent".to_string(),
    };

    output.push_str("\nException Handling\n");
    output.push_str("------------------\n");
    output.push_str(&format!(".eh_frame FDEs: {}\n", summary.fde_count));
    output.push_str(&format!("Personality:   {}\n", personality));
    output.push_str(&format!("LSDA Section:  {}\n", lsda));
}

fn default_calling_convention(
    binary_type: BinaryType,
    arch: Architecture,
) -> hexray_analysis::CallingConvention {
    match arch {
        Architecture::Arm64 => hexray_analysis::CallingConvention::Aarch64,
        Architecture::RiscV64 | Architecture::RiscV32 => hexray_analysis::CallingConvention::RiscV,
        Architecture::X86_64 if matches!(binary_type, BinaryType::Pe) => {
            hexray_analysis::CallingConvention::Win64
        }
        _ => hexray_analysis::CallingConvention::SystemV,
    }
}

#[derive(Clone, Copy)]
enum ProjectAddressRule {
    AnySection,
    Executable,
    ExecutableOrData,
}

fn validate_project_address(
    binary_path: &Path,
    address: u64,
    rule: ProjectAddressRule,
) -> Result<()> {
    let data = fs::read(binary_path)
        .with_context(|| format!("Failed to read binary: {}", binary_path.display()))?;
    let binary = match detect_format(&data) {
        BinaryType::Elf => Binary::Elf(Elf::parse(&data).context("Failed to parse ELF file")?),
        BinaryType::MachO => Binary::MachO(
            MachO::parse_with_arch(&data, None).context("Failed to parse Mach-O file")?,
        ),
        BinaryType::Pe => Binary::Pe(Pe::parse(&data).context("Failed to parse PE file")?),
        BinaryType::Unknown => {
            bail!("Unknown binary format. Supported formats: ELF, Mach-O, PE");
        }
    };

    let Some(section) = binary.as_format().section_containing(address) else {
        bail!("address {:#x} not in any section", address);
    };

    match rule {
        ProjectAddressRule::AnySection => Ok(()),
        ProjectAddressRule::Executable if section.is_executable() => Ok(()),
        ProjectAddressRule::Executable => {
            bail!("address {:#x} is not in an executable section", address)
        }
        ProjectAddressRule::ExecutableOrData
            if section.is_executable() || section.is_allocated() =>
        {
            Ok(())
        }
        ProjectAddressRule::ExecutableOrData => {
            bail!(
                "address {:#x} is not in an executable or data section",
                address
            )
        }
    }
}

fn validate_project_function_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("function name must not be empty");
    }
    if name.len() > 256 {
        bail!("function name must be at most 256 characters");
    }

    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        bail!("function name must not be empty");
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        bail!("function name must be a valid C identifier");
    }
    if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        bail!("function name must be a valid C identifier");
    }

    Ok(())
}

fn load_analysis_project(path: &Path) -> Result<AnalysisProject> {
    if !path.exists() {
        bail!("Project file not found: {}", path.display());
    }

    AnalysisProject::load(path)
        .with_context(|| format!("Failed to load project: {}", path.display()))
}

fn load_requested_project(
    explicit: Option<&Path>,
    global: Option<&Path>,
    binary_path: &Path,
) -> Result<Option<AnalysisProject>> {
    let Some(project_path) = explicit.or(global) else {
        return Ok(None);
    };

    let project = load_analysis_project(project_path)?;
    ensure_project_matches_binary(project_path, &project, binary_path)?;
    Ok(Some(project))
}

fn ensure_project_matches_binary(
    project_path: &Path,
    project: &AnalysisProject,
    binary_path: &Path,
) -> Result<()> {
    let project_binary =
        fs::canonicalize(&project.binary_path).unwrap_or_else(|_| project.binary_path.clone());
    let requested_binary =
        fs::canonicalize(binary_path).unwrap_or_else(|_| binary_path.to_path_buf());

    if project_binary != requested_binary {
        bail!(
            "project {} was created for binary {}, but you specified {}",
            project_path.display(),
            project.binary_path.display(),
            binary_path.display()
        );
    }

    Ok(())
}

fn main() -> Result<()> {
    // Restore the Unix default so piped output exits quietly on EPIPE.
    sigpipe::reset();

    let cli = Cli::parse();
    let global_project_path = cli.project.clone();

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

    // Handle project subcommands that don't require a binary on the command line
    if let Some(Commands::Project { ref action }) = cli.command {
        match action {
            ProjectAction::Create { .. } => {
                // Create requires a binary, handled below
            }
            _ => {
                return handle_project_command(None, action.clone());
            }
        }
    }

    // Handle diff command (doesn't use the main binary argument)
    if let Some(Commands::Diff {
        original,
        modified,
        json,
        verbose,
    }) = cli.command
    {
        return handle_diff_command(&original, &modified, json, verbose);
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
            let macho = MachO::parse_with_arch(&data, cli.arch.as_deref())
                .context("Failed to parse Mach-O file")?;
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
            let project =
                load_requested_project(None, global_project_path.as_deref(), binary_path)?;
            print_symbols(&binary, functions, project.as_ref());
        }
        Some(Commands::Info) => {
            print_info(&binary);
        }
        Some(Commands::Cmp { other }) => {
            cmp_kernels(&binary, &other)?;
        }
        Some(Commands::Cfg {
            target,
            dot,
            json,
            html,
        }) => {
            let project =
                load_requested_project(None, global_project_path.as_deref(), binary_path)?;
            disassemble_cfg(&binary, &target, dot, json, html, project.as_ref())?;
        }
        Some(Commands::Decompile {
            target,
            show_addresses,
            follow,
            depth,
            project,
            types,
            opt_level,
            enable_passes,
            disable_passes,
            list_passes,
            diagnostics,
        }) => {
            // Handle --list-passes
            if list_passes {
                print_optimization_passes();
                return Ok(());
            }

            let project = load_requested_project(
                project.as_deref(),
                global_project_path.as_deref(),
                binary_path,
            )?;
            let target = resolve_decompile_target(&binary, target)?;
            let type_db = load_type_database(&binary, types.as_deref())?;

            // Build decompiler config
            let config = build_decompiler_config(&opt_level, &enable_passes, &disable_passes)?;

            if follow {
                decompile_with_follow(
                    binary_path,
                    &binary,
                    &target,
                    show_addresses,
                    depth,
                    diagnostics,
                    project.as_ref(),
                    type_db.as_ref(),
                    Some(&config),
                )?;
            } else {
                decompile_function(
                    binary_path,
                    &binary,
                    &target,
                    show_addresses,
                    diagnostics,
                    project.as_ref(),
                    type_db.as_ref(),
                    Some(&config),
                )?;
            }
        }
        Some(Commands::Callgraph {
            target,
            dot,
            json,
            html,
        }) => {
            let project =
                load_requested_project(None, global_project_path.as_deref(), binary_path)?;
            build_callgraph(&binary, &target, dot, json, html, project.as_ref())?;
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
            let project =
                load_requested_project(None, global_project_path.as_deref(), binary_path)?;
            build_xrefs(
                &binary,
                target.as_deref(),
                calls_only,
                json,
                project.as_ref(),
            )?;
        }
        Some(Commands::Project { action }) => {
            handle_project_command(Some(binary_path.as_path()), action)?;
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
        Some(Commands::Diff { .. }) => {
            // Already handled before binary loading
            unreachable!("Diff command should have been handled earlier");
        }
        None => {
            // Default: disassemble
            // cli.count is instruction count, convert to bytes (max 15 bytes per x86 instruction)
            let max_bytes = cli.count * 15;
            if let Some(symbol_name) = cli.symbol {
                disassemble_symbol(&binary, &symbol_name, cli.count)?;
            } else if let Some(addr) = cli.address {
                disassemble_at(&binary, addr, max_bytes)?;
            } else if let Some(entry) = fmt.entry_point() {
                println!("Disassembling entry point at {:#x}\n", entry);
                disassemble_at(&binary, entry, max_bytes)?;
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
    println!(
        "Architecture:  {}",
        format_arch_for_info(fmt.architecture())
    );
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

            // Display CUDA CUBIN info if this is an EM_CUDA ELF.
            if let Ok(view) = elf.cubin_view() {
                print_cubin_info(&view);
            }

            // Display AMDGPU code-object info if this is an EM_AMDGPU ELF.
            if let Ok(view) = elf.code_object_view() {
                print_amdgpu_info(&view);
            }

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
            if macho.is_fat_slice() {
                println!(
                    "Slice:         {} (selected from universal binary)",
                    macho.slice_label()
                );
            }
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
    let mut exception_output = String::new();
    append_exception_metadata(&mut exception_output, binary);
    if !exception_output.is_empty() {
        print!("{}", exception_output);
    }
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

fn print_symbols(binary: &Binary, functions_only: bool, project: Option<&AnalysisProject>) {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);
    println!(
        "{:<16} {:<8} {:<8} {:<8} Name",
        "Address", "Size", "Type", "Bind"
    );
    println!("{}", "-".repeat(70));

    let mut symbols = collect_analysis_symbols(binary, &relocation_table);
    if matches!(binary, Binary::Elf(elf) if elf.is_relocatable()) {
        let undefined_names: std::collections::HashSet<_> = fmt
            .symbols()
            .filter(|symbol| !symbol.is_defined() && symbol.address == 0)
            .map(|symbol| symbol.name.as_str())
            .collect();
        for symbol in &mut symbols {
            if symbol.address != 0
                && symbol.section_index.is_none()
                && undefined_names.contains(symbol.name.as_str())
            {
                symbol.address = 0;
            }
        }

        let mut deduped = std::collections::HashMap::new();
        for symbol in symbols {
            let key = (symbol.address, symbol.name.clone());
            match deduped.entry(key) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    let current = entry.get();
                    let replace = symbol_display_priority(&symbol)
                        .cmp(&symbol_display_priority(current))
                        .then_with(|| current.name.len().cmp(&symbol.name.len()))
                        .is_gt();
                    if replace {
                        entry.insert(symbol);
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(symbol);
                }
            }
        }
        symbols = deduped.into_values().collect();
    }
    symbols.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| compare_symbol_display_priority(left, right))
    });

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

        let demangled = display_symbol_name(fmt, project, &symbol);

        println!(
            "{:#016x} {:<8} {:<8} {:<8} {}",
            symbol.address, symbol.size, type_str, bind_str, demangled
        );
    }
}

fn compare_symbol_display_priority(
    left: &hexray_core::Symbol,
    right: &hexray_core::Symbol,
) -> std::cmp::Ordering {
    symbol_display_priority(right)
        .cmp(&symbol_display_priority(left))
        .then_with(|| left.name.len().cmp(&right.name.len()))
}

fn symbol_display_priority(symbol: &hexray_core::Symbol) -> (u8, u8, u8, u8, u8, u64) {
    let defined_rank = u8::from(symbol.is_defined());
    let kind_rank = match symbol.kind {
        hexray_core::SymbolKind::Function => 3u8,
        hexray_core::SymbolKind::Tls => 2u8,
        hexray_core::SymbolKind::Object => 2u8,
        hexray_core::SymbolKind::Section => 0u8,
        _ => 1u8,
    };
    let version_rank = match symbol.version() {
        Some(version) if version.is_default => 2u8,
        Some(_) => 1u8,
        None => 0u8,
    };
    let binding_rank = match symbol.binding {
        hexray_core::SymbolBinding::Global => 2u8,
        hexray_core::SymbolBinding::Weak => 1u8,
        _ => 0u8,
    };
    let name_rank = u8::from(!symbol.name.is_empty());

    (
        defined_rank,
        kind_rank,
        version_rank,
        binding_rank,
        name_rank,
        symbol.size,
    )
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
    if let Some(sym) = find_exact_symbol(fmt, "main") {
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
    find_symbol_with_mode(fmt, name, SymbolLookupMode::Fuzzy)
}

fn find_exact_symbol(fmt: &dyn BinaryFormat, name: &str) -> Option<hexray_core::Symbol> {
    find_symbol_with_mode(fmt, name, SymbolLookupMode::ExactOnly)
}

fn find_exact_symbol_for_project(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    name: &str,
) -> Option<hexray_core::Symbol> {
    find_symbol_for_project_with_mode(fmt, project, name, SymbolLookupMode::ExactOnly)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymbolLookupMode {
    ExactOnly,
    Fuzzy,
}

fn find_symbol_with_mode(
    fmt: &dyn BinaryFormat,
    name: &str,
    mode: SymbolLookupMode,
) -> Option<hexray_core::Symbol> {
    // CUDA CUBIN kernels have section-relative addresses (the driver
    // relocates them at module-load time), so address==0 is normal —
    // filter only on `is_defined()`.
    let symbols: Vec<hexray_core::Symbol> =
        fmt.symbols().filter(|s| s.is_defined()).cloned().collect();
    find_symbol_in_candidates(&symbols, name, mode)
}

fn find_symbol_for_project(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    name: &str,
) -> Option<hexray_core::Symbol> {
    find_symbol_for_project_with_mode(fmt, project, name, SymbolLookupMode::Fuzzy)
}

fn find_symbol_for_project_with_mode(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    name: &str,
    mode: SymbolLookupMode,
) -> Option<hexray_core::Symbol> {
    let mut symbols: Vec<hexray_core::Symbol> =
        fmt.symbols().filter(|s| s.is_defined()).cloned().collect();

    if let Some(project) = project {
        for addr in project.overridden_functions() {
            let Some(project_name) = project.get_function_name(addr) else {
                continue;
            };

            let mut symbol = fmt.symbol_at(addr).cloned().unwrap_or(hexray_core::Symbol {
                name: project_name.to_string(),
                address: addr,
                size: 0,
                kind: hexray_core::SymbolKind::Function,
                binding: hexray_core::SymbolBinding::Local,
                section_index: fmt.section_containing(addr).map(|_| 0),
            });
            symbol.name = project_name.to_string();
            symbol.kind = hexray_core::SymbolKind::Function;
            if symbol.section_index.is_none() && fmt.section_containing(addr).is_some() {
                symbol.section_index = Some(0);
            }
            symbols.push(symbol);
        }
    }

    find_symbol_in_candidates(&symbols, name, mode)
}

enum ResolvedAnalysisTarget {
    Address(u64),
    Symbol(hexray_core::Symbol),
}

fn resolve_analysis_target(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    target: &str,
) -> Result<ResolvedAnalysisTarget> {
    if let Some(symbol) = find_exact_symbol_for_project(fmt, project, target) {
        return Ok(ResolvedAnalysisTarget::Symbol(symbol));
    }

    if let Ok(address) = parse_address_str(target) {
        return Ok(ResolvedAnalysisTarget::Address(address));
    }

    if let Some(symbol) = find_symbol_for_project(fmt, project, target) {
        return Ok(ResolvedAnalysisTarget::Symbol(symbol));
    }

    bail!("Symbol '{}' not found", target)
}

fn resolve_analysis_target_with_entry_main(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    target: &str,
    relocation_table: &RelocationTable,
) -> Result<ResolvedAnalysisTarget> {
    match resolve_analysis_target(fmt, project, target) {
        Ok(resolved) => Ok(resolved),
        Err(err) if target == "main" => infer_main_symbol_from_entry(fmt, relocation_table)
            .map(ResolvedAnalysisTarget::Symbol)
            .ok_or(err),
        Err(err) => Err(err),
    }
}

fn resolve_analysis_target_with_symbols(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    target: &str,
    symbols: &[hexray_core::Symbol],
) -> Result<ResolvedAnalysisTarget> {
    if let Some(symbol) = find_symbol_in_candidates(symbols, target, SymbolLookupMode::ExactOnly) {
        return Ok(ResolvedAnalysisTarget::Symbol(symbol));
    }

    match resolve_analysis_target(fmt, project, target) {
        Ok(ResolvedAnalysisTarget::Symbol(symbol)) => {
            if let Some(candidate) =
                find_symbol_in_candidates(symbols, &symbol.name, SymbolLookupMode::ExactOnly)
            {
                Ok(ResolvedAnalysisTarget::Symbol(candidate))
            } else {
                Ok(ResolvedAnalysisTarget::Symbol(symbol))
            }
        }
        Ok(resolved) => Ok(resolved),
        Err(_) => {
            if let Some(symbol) =
                find_symbol_in_candidates(symbols, target, SymbolLookupMode::ExactOnly)
            {
                return Ok(ResolvedAnalysisTarget::Symbol(symbol));
            }
            if let Some(symbol) =
                find_symbol_in_candidates(symbols, target, SymbolLookupMode::Fuzzy)
            {
                return Ok(ResolvedAnalysisTarget::Symbol(symbol));
            }

            bail!("Symbol '{}' not found", target)
        }
    }
}

fn display_function_name(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    address: u64,
) -> String {
    project
        .and_then(|p| p.get_function_name(address))
        .map(|name| name.to_string())
        .or_else(|| {
            fmt.symbol_at(address)
                .map(|s| demangle_or_original(&s.name))
        })
        .unwrap_or_else(|| format!("sub_{:x}", address))
}

fn tls_image_base(fmt: &dyn BinaryFormat) -> Option<u64> {
    fmt.sections()
        .filter(|section| section.is_allocated() && matches!(section.name(), ".tdata" | ".tbss"))
        .map(|section| section.virtual_address())
        .min()
}

fn find_tls_symbol_by_image_address<'a>(
    fmt: &dyn BinaryFormat,
    symbols: &'a [hexray_core::Symbol],
    address: u64,
) -> Option<(&'a hexray_core::Symbol, u64)> {
    let base = tls_image_base(fmt)?;

    for symbol in symbols {
        if symbol.kind != hexray_core::SymbolKind::Tls {
            continue;
        }
        let start = base.checked_add(symbol.address)?;
        let span = symbol.size.max(1);
        let end = start.checked_add(span)?;
        if address >= start && address < end {
            return Some((symbol, address - start));
        }
    }

    None
}

fn tls_symbol_query_address(
    fmt: &dyn BinaryFormat,
    symbols: &[hexray_core::Symbol],
    address: u64,
) -> Option<u64> {
    let base = tls_image_base(fmt)?;

    for symbol in symbols {
        if symbol.kind != hexray_core::SymbolKind::Tls {
            continue;
        }
        let span = symbol.size.max(1);
        let end = symbol.address.checked_add(span)?;
        if address >= symbol.address && address < end {
            return base.checked_add(address);
        }
    }

    None
}

fn display_symbol_or_label_name_with_symbols(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    symbols: &[hexray_core::Symbol],
    address: u64,
) -> String {
    project
        .and_then(|p| {
            p.get_function_name(address)
                .or_else(|| p.get_label(address))
                .map(|name| name.to_string())
        })
        .or_else(|| {
            find_preferred_symbol_at(symbols, address)
                .map(|s| demangle_or_original(&s.name))
                .or_else(|| {
                    fmt.symbol_at(address)
                        .map(|symbol| demangle_or_original(&symbol.name))
                })
                .or_else(|| {
                    find_tls_symbol_by_image_address(fmt, symbols, address).map(
                        |(symbol, offset)| {
                            let name = demangle_or_original(&symbol.name);
                            if offset == 0 {
                                name
                            } else {
                                format!("{name} + 0x{offset:x}")
                            }
                        },
                    )
                })
        })
        .unwrap_or_else(|| format!("sub_{:x}", address))
}

fn resolve_xref_source_label(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    function_starts: &[(u64, Option<String>, u64)],
    from: u64,
) -> (String, Option<u64>) {
    let mut data_section = None;
    for section in fmt.sections() {
        let section_start = section.virtual_address();
        let section_end = section_start.saturating_add(section.size());
        if from < section_start
            || from >= section_end
            || section.is_executable()
            || !section.is_allocated()
        {
            continue;
        }
        if matches!(section.name(), ".init_array" | ".fini_array") {
            return (
                section.name().to_string(),
                Some(from.saturating_sub(section_start)),
            );
        }
        data_section.get_or_insert((section.name().to_string(), section_start));
    }
    if let Some((section_name, section_start)) = data_section {
        return (section_name, Some(from.saturating_sub(section_start)));
    }
    if let Some(s) = fmt.symbol_at(from).filter(|s| !s.name.starts_with("__mh_")) {
        return (display_function_name(fmt, project, s.address), Some(0));
    }
    let idx = function_starts.partition_point(|(addr, _, _)| *addr <= from);
    if idx == 0 {
        return (format!("sub_{:x}", from), None);
    }
    let (start, name, size) = &function_starts[idx - 1];
    let offset = from - start;
    let limit = if *size > 0 { *size } else { 0x2000 };
    if offset < limit {
        let display = name.clone().unwrap_or_else(|| format!("sub_{:x}", start));
        (display, Some(offset))
    } else {
        (format!("sub_{:x}", from), None)
    }
}

fn display_symbol_name(
    _fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    symbol: &hexray_core::Symbol,
) -> String {
    if symbol.is_function() {
        return project
            .and_then(|p| p.get_function_name(symbol.address))
            .map(|name| name.to_string())
            .unwrap_or_else(|| demangle_or_original(&symbol.name));
    }

    project
        .and_then(|p| p.get_label(symbol.address))
        .map(|name| name.to_string())
        .unwrap_or_else(|| demangle_or_original(&symbol.name))
}

fn find_preferred_symbol_at(
    symbols: &[hexray_core::Symbol],
    address: u64,
) -> Option<&hexray_core::Symbol> {
    symbols
        .iter()
        .filter(|symbol| symbol.address == address)
        .max_by(|left, right| {
            symbol_display_priority(left)
                .cmp(&symbol_display_priority(right))
                .then_with(|| right.name.len().cmp(&left.name.len()))
        })
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum CompilerGeneratedAliasRank {
    SplitVariant,
    OptimizedClone,
    PrivateClone,
}

fn compiler_generated_alias_rank(
    candidate: &str,
    query: &str,
) -> Option<CompilerGeneratedAliasRank> {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SuffixKind {
        SplitVariant,
        OptimizedClone,
        PrivateClone,
    }

    fn strip_one_suffix(name: &str) -> Option<(&str, SuffixKind)> {
        let (prefix, suffix) = name.rsplit_once('.')?;
        match suffix {
            "cold" | "hot" | "unlikely" => return Some((prefix, SuffixKind::SplitVariant)),
            _ => {}
        }

        if !suffix.chars().all(|ch| ch.is_ascii_digit()) {
            return None;
        }

        let (prefix, class) = prefix.rsplit_once('.')?;
        let kind = match class {
            "cold" | "hot" | "unlikely" => SuffixKind::SplitVariant,
            "lto_priv" | "lto_partition" => SuffixKind::PrivateClone,
            "constprop" | "isra" | "part" | "clone" | "prop" | "llvm" => SuffixKind::OptimizedClone,
            _ => return None,
        };

        Some((prefix, kind))
    }

    let mut current = candidate;
    let mut best_rank: Option<CompilerGeneratedAliasRank> = None;
    let mut saw_split_variant = false;

    while let Some((stripped, kind)) = strip_one_suffix(current) {
        current = stripped;
        saw_split_variant |= kind == SuffixKind::SplitVariant;

        if current != query {
            continue;
        }

        let rank = if saw_split_variant {
            CompilerGeneratedAliasRank::SplitVariant
        } else {
            match kind {
                SuffixKind::SplitVariant => CompilerGeneratedAliasRank::SplitVariant,
                SuffixKind::OptimizedClone => CompilerGeneratedAliasRank::OptimizedClone,
                SuffixKind::PrivateClone => CompilerGeneratedAliasRank::PrivateClone,
            }
        };
        best_rank = Some(match best_rank {
            Some(current_best) => current_best.max(rank),
            None => rank,
        });
    }

    best_rank
}

fn find_symbol_in_candidates(
    symbols: &[hexray_core::Symbol],
    name: &str,
    mode: SymbolLookupMode,
) -> Option<hexray_core::Symbol> {
    let is_exact_alias_match = |candidate: &str| {
        candidate
            .strip_prefix('_')
            .is_some_and(|stripped| stripped == name)
    };
    let symbol_priority = |s: &hexray_core::Symbol| {
        let is_func = if s.is_function() { 1u8 } else { 0u8 };
        let is_defined = u8::from(s.is_defined());
        let version_rank = match s.version() {
            Some(version) if version.is_default => 2u8,
            Some(_) => 1u8,
            None => 0u8,
        };
        let binding_rank = match s.binding {
            hexray_core::SymbolBinding::Global => 2u8,
            hexray_core::SymbolBinding::Weak => 1u8,
            _ => 0u8,
        };
        (is_func, is_defined, version_rank, binding_rank, s.size)
    };
    let pick_best = |mut candidates: Vec<hexray_core::Symbol>| {
        candidates.sort_by(|a, b| {
            symbol_priority(b)
                .cmp(&symbol_priority(a))
                .then_with(|| a.name.len().cmp(&b.name.len()))
        });
        candidates.into_iter().next()
    };

    // 1. Try exact match first (highest priority)
    let exact_matches: Vec<_> = symbols.iter().filter(|s| s.name == name).cloned().collect();
    if !exact_matches.is_empty() {
        return pick_best(exact_matches);
    }

    // 2. Try exact match on demangled name
    let demangled_exact_matches: Vec<_> = symbols
        .iter()
        .filter(|s| demangle_or_original(&s.name) == name)
        .cloned()
        .collect();
    if !demangled_exact_matches.is_empty() {
        return pick_best(demangled_exact_matches);
    }

    let exact_alias_matches: Vec<_> = symbols
        .iter()
        .filter(|s| {
            is_exact_alias_match(&s.name) || is_exact_alias_match(&demangle_or_original(&s.name))
        })
        .cloned()
        .collect();
    if !exact_alias_matches.is_empty() {
        return pick_best(exact_alias_matches);
    }

    let version_base_matches: Vec<_> = symbols
        .iter()
        .filter(|s| {
            if s.unversioned_name() == name {
                return true;
            }
            let demangled = demangle_or_original(&s.name);
            hexray_core::unversioned_symbol_name(&demangled) == name
        })
        .cloned()
        .collect();
    if !version_base_matches.is_empty() {
        return pick_best(version_base_matches);
    }

    if mode == SymbolLookupMode::ExactOnly {
        return None;
    }

    let compiler_generated_rank = |symbol: &hexray_core::Symbol| {
        [
            compiler_generated_alias_rank(&symbol.name, name),
            compiler_generated_alias_rank(symbol.name_without_plt(), name),
            compiler_generated_alias_rank(symbol.unversioned_name(), name),
            {
                let demangled = demangle_or_original(&symbol.name);
                compiler_generated_alias_rank(&demangled, name)
            },
            {
                let demangled = demangle_or_original(&symbol.name);
                compiler_generated_alias_rank(hexray_core::strip_plt_suffix(&demangled), name)
            },
            {
                let demangled = demangle_or_original(&symbol.name);
                compiler_generated_alias_rank(
                    hexray_core::unversioned_symbol_name(&demangled),
                    name,
                )
            },
        ]
        .into_iter()
        .flatten()
        .max()
    };

    let compiler_generated_matches: Vec<_> = symbols
        .iter()
        .filter_map(|symbol| compiler_generated_rank(symbol).map(|rank| (rank, symbol.clone())))
        .collect();
    if let Some(best_rank) = compiler_generated_matches
        .iter()
        .map(|(rank, _)| *rank)
        .max()
    {
        return pick_best(
            compiler_generated_matches
                .into_iter()
                .filter_map(|(rank, symbol)| (rank == best_rank).then_some(symbol))
                .collect(),
        );
    }

    // 3. Try prefix match (e.g., "nfsd_open" matches "nfsd_open.cold")
    //    Prefer function symbols and shorter names
    let mut prefix_matches: Vec<hexray_core::Symbol> = symbols
        .iter()
        .filter(|s| {
            if s.name.starts_with(name)
                || s.name_without_plt().starts_with(name)
                || s.unversioned_name().starts_with(name)
            {
                return true;
            }

            let demangled = demangle_or_original(&s.name);
            demangled.starts_with(name)
                || hexray_core::strip_plt_suffix(&demangled).starts_with(name)
                || hexray_core::unversioned_symbol_name(&demangled).starts_with(name)
        })
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

    None
}

fn infer_main_bootstrap_from_entry(
    fmt: &dyn BinaryFormat,
    relocation_table: &RelocationTable,
) -> Option<(u64, Option<u64>)> {
    use hexray_core::{register::x86, ControlFlow, Operand, Operation};

    if fmt.architecture() != Architecture::X86_64 {
        return None;
    }

    let entry = fmt.entry_point()?;
    let section = fmt.section_containing(entry)?;
    if !section.is_executable() {
        return None;
    }

    let max_bytes = section
        .virtual_address()
        .saturating_add(section.size())
        .saturating_sub(entry)
        .min(0x100) as usize;
    let bytes = fmt.bytes_at(entry, max_bytes)?;
    let disasm = X86_64Disassembler::new();

    let is_internal_exec_addr = |addr: u64| {
        if addr == 0 {
            return false;
        }
        fmt.sections().any(|section| {
            let start = section.virtual_address();
            let end = start.saturating_add(section.size());
            let name = section.name().to_ascii_lowercase();
            addr >= start
                && addr < end
                && section.is_executable()
                && !name.contains("plt")
                && !name.contains("stub")
        })
    };

    let mut register_values: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    let mut offset = 0usize;
    let mut decoded_count = 0usize;

    while offset < bytes.len() && decoded_count < 64 {
        let addr = entry + offset as u64;
        let remaining = &bytes[offset..];
        let Ok(decoded) = disasm.decode_instruction(remaining, addr) else {
            break;
        };
        let instruction = &decoded.instruction;

        let tracked_assignment = if matches!(
            instruction.operation,
            Operation::Move | Operation::LoadEffectiveAddress
        ) {
            match instruction.operands.first() {
                Some(Operand::Register(dest)) => {
                    let source = instruction.operands.get(1);
                    let value = match source {
                        Some(Operand::Immediate(imm)) => Some(imm.value as u64),
                        Some(Operand::PcRelative { target, .. }) => Some(*target),
                        Some(Operand::Register(reg)) => register_values.get(&reg.id).copied(),
                        Some(Operand::Memory(mem))
                            if matches!(instruction.operation, Operation::LoadEffectiveAddress)
                                && mem.base.as_ref().map(|reg| reg.id) == Some(x86::RIP)
                                && mem.index.is_none() =>
                        {
                            Some(
                                (instruction.address + instruction.size as u64)
                                    .wrapping_add(mem.displacement as u64),
                            )
                        }
                        _ => None,
                    };

                    value
                        .filter(|target| is_internal_exec_addr(*target))
                        .map(|value| (dest.id, value))
                }
                _ => None,
            }
        } else {
            None
        };

        if let Some((dest_reg, value)) = tracked_assignment {
            register_values.insert(dest_reg, value);
        } else if let Some(Operand::Register(dest)) = instruction.operands.first() {
            register_values.remove(&dest.id);
        }

        let main_addr = register_values
            .get(&x86::RDI)
            .copied()
            .filter(|addr| is_internal_exec_addr(*addr));
        let bootstrap_target = match instruction.control_flow {
            ControlFlow::Call { target, .. } => {
                let named_target = relocation_table
                    .get_call(instruction.address)
                    .map(|reloc| reloc.symbol.contains("libc_start_main"))
                    .unwrap_or_else(|| {
                        fmt.symbol_at(target)
                            .is_some_and(|symbol| symbol.name.contains("libc_start_main"))
                    });
                if named_target || (main_addr.is_some() && is_internal_exec_addr(target)) {
                    Some(target)
                } else {
                    None
                }
            }
            ControlFlow::IndirectCall { .. } => match instruction.operands.first() {
                Some(Operand::Memory(mem)) => rip_relative_memory_target(mem, instruction)
                    .and_then(|slot| relocation_table.get_got(slot))
                    .filter(|symbol| symbol.contains("libc_start_main"))
                    .filter(|_| main_addr.is_some())
                    .map(|_| 0),
                _ => None,
            },
            _ => None,
        };
        if let (Some(address), Some(target)) = (main_addr, bootstrap_target) {
            let internal_target = is_internal_exec_addr(target).then_some(target);
            return Some((address, internal_target));
        }

        offset += decoded.size;
        decoded_count += 1;

        if matches!(
            instruction.control_flow,
            ControlFlow::Return | ControlFlow::Halt
        ) {
            break;
        }
    }

    None
}

fn infer_main_symbol_from_entry(
    fmt: &dyn BinaryFormat,
    relocation_table: &RelocationTable,
) -> Option<hexray_core::Symbol> {
    use hexray_core::{SymbolBinding, SymbolKind};

    let (address, _) = infer_main_bootstrap_from_entry(fmt, relocation_table)?;
    Some(hexray_core::Symbol {
        name: "main".to_string(),
        address,
        size: 0,
        kind: SymbolKind::Function,
        binding: SymbolBinding::Local,
        section_index: fmt.section_containing(address).map(|_| 0),
    })
}

fn synthesize_startup_function_symbols(
    fmt: &dyn BinaryFormat,
    relocation_table: &RelocationTable,
    symbols: &mut Vec<hexray_core::Symbol>,
) {
    use hexray_core::{SymbolBinding, SymbolKind};

    let mut seen: std::collections::HashSet<(u64, String)> = symbols
        .iter()
        .map(|symbol| (symbol.address, symbol.name.clone()))
        .collect();

    let has_named_symbol_at = |addr: u64, symbols: &[hexray_core::Symbol]| {
        symbols
            .iter()
            .any(|symbol| symbol.address == addr && !symbol.name.is_empty())
    };

    if let Some(entry) = fmt.entry_point() {
        if !has_named_symbol_at(entry, symbols) && seen.insert((entry, "_start".to_string())) {
            symbols.push(hexray_core::Symbol {
                name: "_start".to_string(),
                address: entry,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Local,
                section_index: fmt.section_containing(entry).map(|_| 0),
            });
        }
    }

    if let Some((main_addr, bootstrap_target)) =
        infer_main_bootstrap_from_entry(fmt, relocation_table)
    {
        let main_symbol = hexray_core::Symbol {
            name: "main".to_string(),
            address: main_addr,
            size: 0,
            kind: SymbolKind::Function,
            binding: SymbolBinding::Local,
            section_index: fmt.section_containing(main_addr).map(|_| 0),
        };
        if !has_named_symbol_at(main_symbol.address, symbols)
            && seen.insert((main_symbol.address, main_symbol.name.clone()))
        {
            symbols.push(main_symbol);
        }

        if let Some(target) = bootstrap_target {
            if !has_named_symbol_at(target, symbols)
                && seen.insert((target, "__libc_start_main".to_string()))
            {
                symbols.push(hexray_core::Symbol {
                    name: "__libc_start_main".to_string(),
                    address: target,
                    size: 0,
                    kind: SymbolKind::Function,
                    binding: SymbolBinding::Local,
                    section_index: fmt.section_containing(target).map(|_| 0),
                });
            }
        }
    }
}

fn signature_architecture_name(arch: Architecture) -> Option<&'static str> {
    match arch {
        Architecture::X86_64 | Architecture::X86 => Some("x86_64"),
        Architecture::Arm64 => Some("aarch64"),
        _ => None,
    }
}

fn function_start_bytes(
    fmt: &dyn BinaryFormat,
    address: u64,
    size: u64,
    heuristic_bounds: bool,
) -> Option<&[u8]> {
    let requested = if heuristic_bounds {
        size.clamp(64, 4096)
    } else {
        size.clamp(1, 4096)
    };
    let len = usize::try_from(requested).ok()?;
    fmt.bytes_at(address, len)
}

fn synthesize_signature_function_symbols(
    fmt: &dyn BinaryFormat,
    symbols: &mut Vec<hexray_core::Symbol>,
) {
    use hexray_core::{SymbolBinding, SymbolKind};

    let Some(arch_name) = signature_architecture_name(fmt.architecture()) else {
        return;
    };
    let db = sig_builtin::load_for_architecture(arch_name);
    if db.is_empty() {
        return;
    }
    let matcher = SignatureMatcher::new(&db).with_min_confidence(0.75);

    let mut seen: std::collections::HashSet<(u64, String)> = symbols
        .iter()
        .map(|symbol| (symbol.address, symbol.name.clone()))
        .collect();
    let has_named_symbol_at = |addr: u64, symbols: &[hexray_core::Symbol]| {
        symbols
            .iter()
            .any(|symbol| symbol.address == addr && !symbol.name.is_empty())
    };

    for (address, size, heuristic_bounds) in
        discover_function_starts(fmt, fmt.architecture(), symbols)
    {
        if has_named_symbol_at(address, symbols) {
            continue;
        }
        let Some(bytes) = function_start_bytes(fmt, address, size, heuristic_bounds) else {
            continue;
        };
        let Some(matched) = matcher.match_bytes(bytes) else {
            continue;
        };
        let name = matched.signature.preferred_name().to_string();
        if !seen.insert((address, name.clone())) {
            continue;
        }
        symbols.push(hexray_core::Symbol {
            name,
            address,
            size: if heuristic_bounds { 0 } else { size },
            kind: SymbolKind::Function,
            binding: SymbolBinding::Local,
            section_index: fmt.section_containing(address).map(|_| 0),
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum XrefSymbolMatchRank {
    Prefix,
    Unversioned,
    Exact,
}

fn exact_symbol_alias_match(candidate: &str, query: &str) -> bool {
    candidate
        .strip_prefix('_')
        .is_some_and(|stripped| stripped == query)
}

fn xref_symbol_match_rank(
    symbol: &hexray_core::Symbol,
    query: &str,
) -> Option<XrefSymbolMatchRank> {
    let demangled = demangle_or_original(&symbol.name);
    let demangled_no_plt = hexray_core::strip_plt_suffix(&demangled);

    if symbol.name == query
        || demangled == query
        || exact_symbol_alias_match(&symbol.name, query)
        || exact_symbol_alias_match(&demangled, query)
    {
        return Some(XrefSymbolMatchRank::Exact);
    }

    if symbol.name_without_plt() == query
        || demangled_no_plt == query
        || exact_symbol_alias_match(symbol.name_without_plt(), query)
        || exact_symbol_alias_match(demangled_no_plt, query)
    {
        return Some(XrefSymbolMatchRank::Exact);
    }

    if symbol.unversioned_name() == query
        || hexray_core::unversioned_symbol_name(&demangled) == query
    {
        return Some(XrefSymbolMatchRank::Unversioned);
    }

    if symbol.name.starts_with(query)
        || symbol.name_without_plt().starts_with(query)
        || symbol.unversioned_name().starts_with(query)
        || demangled.starts_with(query)
        || demangled_no_plt.starts_with(query)
        || hexray_core::unversioned_symbol_name(&demangled).starts_with(query)
    {
        return Some(XrefSymbolMatchRank::Prefix);
    }

    None
}

fn collect_xref_symbol_matches(
    symbols: &[hexray_core::Symbol],
    query: &str,
) -> Vec<hexray_core::Symbol> {
    let mut best_rank = None;
    let mut matches = Vec::new();

    for symbol in symbols {
        let Some(rank) = xref_symbol_match_rank(symbol, query) else {
            continue;
        };

        match best_rank {
            None => {
                best_rank = Some(rank);
                matches.push(symbol.clone());
            }
            Some(current) if rank > current => {
                best_rank = Some(rank);
                matches.clear();
                matches.push(symbol.clone());
            }
            Some(current) if rank == current => matches.push(symbol.clone()),
            Some(_) => {}
        }
    }

    matches
}

fn resolve_xref_target_addresses(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    target: &str,
    symbols: &[hexray_core::Symbol],
    relocation_table: &RelocationTable,
    db: &hexray_analysis::XrefDatabase,
    calls_only: bool,
) -> Result<Vec<u64>> {
    if let Ok(address) = parse_address_str(target) {
        return Ok(vec![address]);
    }

    let has_refs = |addr: u64| {
        xref_query_target_addresses(fmt, symbols, relocation_table, addr)
            .into_iter()
            .any(|query_addr| {
                if calls_only {
                    !db.call_refs_to(query_addr).is_empty()
                } else {
                    !db.refs_to(query_addr).is_empty()
                }
            })
    };
    let matching_symbols = collect_xref_symbol_matches(symbols, target);

    let mut referenced_targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for symbol in &matching_symbols {
        if (symbol.address == 0 && symbol.kind != hexray_core::SymbolKind::Tls)
            || !has_refs(symbol.address)
            || !seen.insert(symbol.address)
        {
            continue;
        }
        referenced_targets.push(symbol.address);
    }
    if !referenced_targets.is_empty() {
        referenced_targets.sort_unstable();
        return Ok(referenced_targets);
    }

    let mut resolved_matches = Vec::new();
    for symbol in matching_symbols {
        if (symbol.address == 0 && symbol.kind != hexray_core::SymbolKind::Tls)
            || !seen.insert(symbol.address)
        {
            continue;
        }
        resolved_matches.push(symbol.address);
    }
    if !resolved_matches.is_empty() {
        resolved_matches.sort_unstable();
        return Ok(resolved_matches);
    }

    let resolved = resolve_analysis_target_with_symbols(fmt, project, target, symbols)?;
    Ok(vec![match resolved {
        ResolvedAnalysisTarget::Address(address) => address,
        ResolvedAnalysisTarget::Symbol(symbol) => symbol.address,
    }])
}

fn xref_query_target_addresses(
    fmt: &dyn BinaryFormat,
    symbols: &[hexray_core::Symbol],
    relocation_table: &RelocationTable,
    addr: u64,
) -> Vec<u64> {
    let mut addresses = vec![addr];
    if let Some(address_point) = maybe_itanium_vtable_address_point(fmt, symbols, addr) {
        if !addresses.contains(&address_point) {
            addresses.push(address_point);
        }
    }
    if let Some(tls_image_addr) = tls_symbol_query_address(fmt, symbols, addr) {
        if !addresses.contains(&tls_image_addr) {
            addresses.push(tls_image_addr);
        }
    }
    if let Some((symbol, _)) = find_tls_symbol_by_image_address(fmt, symbols, addr) {
        for descriptor_addr in relocation_table.tls_descriptor_addresses(&symbol.name) {
            if !addresses.contains(&descriptor_addr) {
                addresses.push(descriptor_addr);
            }
        }
    } else if let Some(symbol) = symbols
        .iter()
        .find(|symbol| symbol.address == addr && symbol.kind == hexray_core::SymbolKind::Tls)
    {
        for descriptor_addr in relocation_table.tls_descriptor_addresses(&symbol.name) {
            if !addresses.contains(&descriptor_addr) {
                addresses.push(descriptor_addr);
            }
        }
    }
    addresses
}

fn maybe_itanium_vtable_address_point(
    fmt: &dyn BinaryFormat,
    symbols: &[hexray_core::Symbol],
    addr: u64,
) -> Option<u64> {
    let is_vtable_base = fmt
        .symbol_at(addr)
        .into_iter()
        .chain(symbols.iter().filter(|symbol| symbol.address == addr))
        .any(|symbol| symbol.name.starts_with("_ZTV"));
    if !is_vtable_base {
        return None;
    }

    let address_point_offset = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 8,
        Architecture::X86_64 | Architecture::Arm64 | Architecture::RiscV64 => 16,
        _ => return None,
    };
    addr.checked_add(address_point_offset)
}

fn format_disassembly_operand(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    symbols: &[hexray_core::Symbol],
    relocations: &RelocationTable,
    instruction: &hexray_core::Instruction,
    operand: &hexray_core::Operand,
) -> String {
    match operand {
        hexray_core::Operand::PcRelative { target, .. } => {
            if let Some(relocation) = relocations.get_call(instruction.address) {
                demangle_or_original(&relocation.symbol)
            } else if let Some(symbol) = find_preferred_symbol_at(symbols, *target) {
                display_symbol_name(fmt, project, symbol)
            } else {
                format!("{:#x}", target)
            }
        }
        hexray_core::Operand::Immediate(_)
            if relocations.get_data(instruction.address).is_some() =>
        {
            relocations
                .get_data(instruction.address)
                .map(demangle_or_original)
                .unwrap_or_else(|| format!("{}", operand))
        }
        hexray_core::Operand::Memory(mem)
            if mem.base.as_ref().is_some_and(|reg| reg.name() == "rip")
                && mem.index.is_none()
                && relocations.data_is_pc_relative(instruction.address) =>
        {
            relocations
                .get_data(instruction.address)
                .map(|name| format!("[{}]", demangle_or_original(name)))
                .unwrap_or_else(|| format!("{}", operand))
        }
        _ => format!("{}", operand),
    }
}

fn format_instruction_for_output(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    symbols: &[hexray_core::Symbol],
    relocations: &RelocationTable,
    instruction: &hexray_core::Instruction,
) -> String {
    let mut rendered = format!("{:#010x}:  ", instruction.address);
    for byte in &instruction.bytes {
        rendered.push_str(&format!("{:02x} ", byte));
    }
    for _ in instruction.bytes.len()..8 {
        rendered.push_str("   ");
    }
    rendered.push(' ');
    rendered.push_str(&instruction.mnemonic);
    if !instruction.operands.is_empty() {
        rendered.push(' ');
        let operands: Vec<_> = instruction
            .operands
            .iter()
            .map(|operand| {
                format_disassembly_operand(fmt, project, symbols, relocations, instruction, operand)
            })
            .collect();
        rendered.push_str(&operands.join(", "));
    }
    rendered
}

fn disassemble_symbol(binary: &Binary, name: &str, max_count: usize) -> Result<()> {
    let fmt = binary.as_format();
    // Find the symbol - prefer exact or alias matches, then prefix matches.
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

    disassemble_at(binary, symbol.address, size.min(max_count * 15))
}

fn disassemble_at(binary: &Binary, address: u64, max_bytes: usize) -> Result<()> {
    let fmt = binary.as_format();
    let bytes = fmt
        .bytes_at(address, max_bytes)
        .with_context(|| format!("Cannot read bytes at {:#x}", address))?;
    let relocation_table = build_relocation_table(binary);
    let symbols = collect_analysis_symbols(binary, &relocation_table);

    let arch = fmt.architecture();
    let mut offset = 0;
    let mut count = 0;

    // Use the appropriate disassembler based on architecture
    match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => {
            let disasm = hexray_disasm::cuda::SassDisassembler::for_sm(sm);
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        Architecture::Amdgpu(target) => {
            let disasm = hexray_disasm::amdgpu::AmdgpuDisassembler::for_target(target);
            disassemble_with(
                &disasm,
                fmt,
                bytes,
                address,
                &mut offset,
                &mut count,
                None,
                &symbols,
                &relocation_table,
            )?;
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn disassemble_with<D: Disassembler>(
    disasm: &D,
    fmt: &dyn BinaryFormat,
    bytes: &[u8],
    address: u64,
    offset: &mut usize,
    count: &mut usize,
    project: Option<&AnalysisProject>,
    symbols: &[hexray_core::Symbol],
    relocations: &RelocationTable,
) -> Result<()> {
    while *offset < bytes.len() && *count < 100 {
        let remaining = &bytes[*offset..];
        let addr = address + *offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let mut instruction = decoded.instruction;
                apply_instruction_relocations(std::slice::from_mut(&mut instruction), relocations);

                // Check for symbol at this address
                if let Some(sym) = fmt.symbol_at(addr) {
                    if !sym.name.is_empty() {
                        println!("\n<{}>:", demangle_or_original(&sym.name));
                    }
                }

                println!(
                    "{}",
                    format_instruction_for_output(fmt, project, symbols, relocations, &instruction)
                );
                *offset += decoded.size;
                *count += 1;

                // Stop at return
                if instruction.is_return() {
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
    binary: &Binary,
    target: &str,
    dot: bool,
    json: bool,
    html: bool,
    project: Option<&AnalysisProject>,
) -> Result<()> {
    let fmt = binary.as_format();
    let (start_addr, name, max_bytes, stop_after_first_return) =
        match resolve_analysis_target(fmt, project, target)? {
            ResolvedAnalysisTarget::Address(addr) => {
                let name = project
                    .and_then(|p| p.get_function_name(addr))
                    .map(|n| n.to_string())
                    .or_else(|| fmt.symbol_at(addr).map(|s| demangle_or_original(&s.name)))
                    .unwrap_or_else(|| format!("sub_{:x}", addr));
                (addr, name, 4096usize, true)
            }
            ResolvedAnalysisTarget::Symbol(symbol) => {
                let max_bytes = if symbol.size > 0 {
                    symbol.size as usize
                } else {
                    4096usize
                };
                let name = project
                    .and_then(|p| p.get_function_name(symbol.address))
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| demangle_or_original(&symbol.name));
                (symbol.address, name, max_bytes, symbol.size == 0)
            }
        };

    // Disassemble instructions
    let bytes = fmt
        .bytes_at(start_addr, max_bytes)
        .context("Cannot read bytes")?;
    let relocation_table = build_relocation_table(binary);
    let symbols = collect_analysis_symbols(binary, &relocation_table);

    let arch = fmt.architecture();
    let mut instructions = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    };
    apply_instruction_relocations(&mut instructions, &relocation_table);
    // Build CFG
    let binary_data_ctx = build_binary_data_context(fmt);
    let cfg = CfgBuilder::build_with_binary_context(&instructions, start_addr, &binary_data_ctx);

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
                println!(
                    "    {}",
                    format_instruction_for_output(fmt, project, &symbols, &relocation_table, inst)
                );
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
    fmt: &dyn BinaryFormat,
    bytes: &[u8],
    start_addr: u64,
    stop_after_first_return: bool,
) -> Vec<hexray_core::Instruction> {
    let binary_data_ctx = build_binary_data_context(fmt);
    let scan_limit = start_addr.saturating_add(bytes.len() as u64);
    let mut instructions = Vec::new();
    let mut offset = 0;
    let mut min_scan_end = start_addr;

    while offset < bytes.len() && instructions.len() < 500 {
        let remaining = &bytes[offset..];
        let addr = start_addr + offset as u64;

        match disasm.decode_instruction(remaining, addr) {
            Ok(decoded) => {
                let is_ret = decoded.instruction.is_return();
                let is_halt = matches!(
                    decoded.instruction.control_flow,
                    hexray_core::ControlFlow::Halt
                );
                let next_offset = offset + decoded.size;
                let next_addr = addr + decoded.size as u64;
                let is_heuristic_tail_jump = stop_after_first_return
                    && heuristic_tail_jump_stops_scan(
                        disasm,
                        bytes,
                        next_offset,
                        next_addr,
                        &decoded.instruction,
                        fmt.symbol_at(next_addr)
                            .is_some_and(|symbol| symbol.is_function()),
                    );
                let is_noreturn_call = matches!(
                    decoded.instruction.control_flow,
                    hexray_core::ControlFlow::Call { target, .. }
                        if is_known_noreturn_call_target(fmt, target)
                );
                instructions.push(decoded.instruction);
                offset += decoded.size;

                let branch_index = instructions.len() - 1;
                if !binary_data_ctx.is_empty() {
                    let targets = resolve_computed_dispatch_targets(
                        &instructions,
                        branch_index,
                        &binary_data_ctx,
                        start_addr,
                        scan_limit,
                    );
                    if !targets.is_empty() {
                        if let hexray_core::ControlFlow::IndirectBranch { possible_targets } =
                            &mut instructions[branch_index].control_flow
                        {
                            *possible_targets = targets.clone();
                        }
                        if let Some(max_target) = targets.into_iter().max() {
                            min_scan_end = min_scan_end.max(max_target);
                        }
                    }
                }

                // If we only have a fallback byte window (unknown function size),
                // stop at the first return/noreturn call to avoid spilling into neighbors.
                let must_keep_scanning = next_addr < min_scan_end;
                if stop_after_first_return
                    && !must_keep_scanning
                    && (is_ret || is_halt || is_noreturn_call || is_heuristic_tail_jump)
                {
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

fn is_known_noreturn_call_target(fmt: &dyn BinaryFormat, target: u64) -> bool {
    fmt.symbol_at(target)
        .is_some_and(|symbol| is_noreturn_function_name(&symbol.name))
        || looks_like_x86_ud2_trap_stub(fmt, target)
}

fn looks_like_x86_ud2_trap_stub(fmt: &dyn BinaryFormat, target: u64) -> bool {
    if !matches!(fmt.architecture(), Architecture::X86_64 | Architecture::X86) {
        return false;
    }

    let Some(bytes) = fmt.bytes_at(target, 6) else {
        return false;
    };
    let bytes = if bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfa])
        || bytes.starts_with(&[0xf3, 0x0f, 0x1e, 0xfb])
    {
        &bytes[4..]
    } else {
        bytes
    };

    bytes.starts_with(&[0x0f, 0x0b])
}

struct DecompileTargetInfo {
    start_addr: u64,
    name: String,
    max_bytes: usize,
    stop_after_first_return: bool,
}

fn decompile_target_info_for_address(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    addr: u64,
) -> DecompileTargetInfo {
    let exact_symbol = fmt.symbol_at(addr).filter(|symbol| symbol.is_function());
    let name = project
        .and_then(|p| p.get_function_name(addr))
        .map(|n| n.to_string())
        .or_else(|| exact_symbol.map(|symbol| demangle_or_original(&symbol.name)))
        .unwrap_or_else(|| format!("sub_{:x}", addr));
    let max_bytes = exact_symbol
        .map(|symbol| {
            if symbol.size > 0 {
                symbol.size as usize
            } else {
                4096
            }
        })
        .unwrap_or(4096);
    let stop_after_first_return = exact_symbol.map_or(true, |symbol| symbol.size == 0);

    DecompileTargetInfo {
        start_addr: addr,
        name,
        max_bytes,
        stop_after_first_return,
    }
}

fn resolve_decompile_target_info(
    fmt: &dyn BinaryFormat,
    project: Option<&AnalysisProject>,
    target: &str,
    relocation_table: &RelocationTable,
) -> Result<DecompileTargetInfo> {
    match resolve_analysis_target_with_entry_main(fmt, project, target, relocation_table)? {
        ResolvedAnalysisTarget::Address(addr) => {
            Ok(decompile_target_info_for_address(fmt, project, addr))
        }
        ResolvedAnalysisTarget::Symbol(symbol) => {
            let max_bytes = if symbol.size > 0 {
                symbol.size as usize
            } else {
                4096usize
            };
            let name = project
                .and_then(|p| p.get_function_name(symbol.address))
                .map(|n| n.to_string())
                .unwrap_or_else(|| demangle_or_original(&symbol.name));
            Ok(DecompileTargetInfo {
                start_addr: symbol.address,
                name,
                max_bytes,
                stop_after_first_return: symbol.size == 0,
            })
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn decompile_function(
    binary_path: &Path,
    binary: &Binary,
    target: &str,
    show_addresses: bool,
    diagnostics: bool,
    project: Option<&AnalysisProject>,
    type_db: Option<&std::sync::Arc<TypeDatabase>>,
    config: Option<&DecompilerConfig>,
) -> Result<()> {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);

    let DecompileTargetInfo {
        start_addr,
        name,
        max_bytes,
        stop_after_first_return,
    } = resolve_decompile_target_info(fmt, project, target, &relocation_table).map_err(|_| {
        anyhow::anyhow!(
            "Symbol '{}' not found. It may be an external/undefined symbol (e.g., from a shared library).",
            target
        )
    })?;

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
        .bytes_at(start_addr, max_bytes)
        .context("Cannot read bytes")?;

    let arch = fmt.architecture();
    let mut instructions = match arch {
        Architecture::X86_64 | Architecture::X86 => {
            let disasm = X86_64Disassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::Arm64 => {
            let disasm = Arm64Disassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::RiscV64 => {
            let disasm = RiscVDisassembler::new();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        Architecture::RiscV32 => {
            let disasm = RiscVDisassembler::new_rv32();
            disassemble_for_cfg(&disasm, fmt, bytes, start_addr, stop_after_first_return)
        }
        _ => {
            bail!("Unsupported architecture: {:?}", arch);
        }
    };
    apply_instruction_relocations(&mut instructions, &relocation_table);
    let tls_access_targets = build_tls_access_targets(binary);
    let tls_slot_map = build_tls_slot_map(binary);
    rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);

    // Build CFG
    let binary_data_ctx = build_binary_data_context(fmt);
    let cfg = CfgBuilder::build_with_binary_context(&instructions, start_addr, &binary_data_ctx);

    // Build string table from data sections
    let string_table = build_string_table(fmt);

    // Build symbol table for function names, merging with project overrides
    let mut symbol_table = build_symbol_table(binary);
    if let Some(proj) = project {
        for addr in proj.overridden_functions() {
            if let Some(name) = proj.get_function_name(addr) {
                symbol_table.insert(addr, name.to_string());
            }
        }
    }
    let throw_thunks = collect_throw_thunks(binary, &symbol_table, &relocation_table);
    let binary_data_ctx = build_binary_data_context(fmt);

    // Build relocation table for kernel modules
    // Reuse the binary data context for jump table reconstruction.

    // Try to load DWARF debug info for function-scoped variable and parameter names.
    let dwarf_names = if let Some(debug_info) = load_dwarf_info(binary_path, binary) {
        get_dwarf_function_names(&debug_info, start_addr, binary)
    } else {
        DwarfFunctionNames::default()
    };

    // Decompile
    // Create constant database for magic number recognition
    let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());

    // Determine calling convention from architecture
    let calling_convention = default_calling_convention(
        match binary {
            Binary::Elf(_) => BinaryType::Elf,
            Binary::MachO(_) => BinaryType::MachO,
            Binary::Pe(_) => BinaryType::Pe,
        },
        arch,
    );

    let mut decompiler = Decompiler::new()
        .with_addresses(show_addresses)
        .with_string_table(string_table)
        .with_symbol_table(symbol_table)
        .with_relocation_table(relocation_table)
        .with_throw_thunks(throw_thunks)
        .with_binary_data(binary_data_ctx)
        .with_dwarf_names(dwarf_names.stack_names)
        .with_dwarf_param_names(dwarf_names.parameter_names)
        .with_dwarf_scope_ranges(dwarf_names.local_scope_ranges)
        .with_constant_database(const_db)
        .with_struct_inference(true)
        .with_calling_convention(calling_convention);
    decompiler = decompiler.analyze_cpp_special(&cfg, &instructions, Some(&name));
    if let Some(info) = binary.exception_info_for_function(start_addr, start_addr) {
        decompiler = decompiler.with_exception_info(info);
    }
    if let Some(db) = type_db {
        decompiler = decompiler.with_type_database(db.clone());
    }
    if let Some(cfg_opts) = config {
        decompiler = decompiler.with_config(cfg_opts.clone());
    }
    if diagnostics {
        let signature = decompiler.recover_signature(&cfg);
        print_signature_diagnostics(&name, &signature);
    }
    let pseudocode = annotate_pseudocode_with_project_comments(
        decompiler.decompile(&cfg, &name),
        project,
        show_addresses,
    );

    println!("{}", pseudocode);

    Ok(())
}

fn annotate_pseudocode_with_project_comments(
    pseudocode: String,
    project: Option<&AnalysisProject>,
    show_addresses: bool,
) -> String {
    if !show_addresses {
        return pseudocode;
    }
    let Some(project) = project else {
        return pseudocode;
    };

    let mut comments: Vec<(u64, String)> = project
        .annotated_addresses()
        .filter_map(|addr| {
            project
                .get_comment(addr)
                .map(|comment| (addr, comment.to_string()))
        })
        .collect();
    comments.sort_by_key(|(addr, _)| *addr);
    if comments.is_empty() {
        return pseudocode;
    }

    let trailing_newline = pseudocode.ends_with('\n');
    let mut rendered = String::new();
    let mut next_comment = 0usize;

    for line in pseudocode.lines() {
        rendered.push_str(line);
        rendered.push('\n');

        let Some((start, end, indent)) = parse_basic_block_address_line(line) else {
            continue;
        };

        while next_comment < comments.len() && comments[next_comment].0 < start {
            next_comment += 1;
        }
        while next_comment < comments.len() && comments[next_comment].0 <= end {
            rendered.push_str(&indent);
            rendered.push_str("// ");
            rendered.push_str(&comments[next_comment].1);
            rendered.push('\n');
            next_comment += 1;
        }
    }

    if trailing_newline {
        rendered
    } else {
        rendered.trim_end_matches('\n').to_string()
    }
}

fn parse_basic_block_address_line(line: &str) -> Option<(u64, u64, String)> {
    let indent_len = line.len() - line.trim_start().len();
    let indent = line[..indent_len].to_string();
    let trimmed = &line[indent_len..];
    if !trimmed.starts_with("// bb") {
        return None;
    }

    let open = trimmed.find('[')?;
    let close = trimmed[open + 1..].find(']')? + open + 1;
    let range = &trimmed[open + 1..close];
    let (start_str, end_str) = range.split_once("..")?;
    let start = u64::from_str_radix(start_str.strip_prefix("0x")?, 16).ok()?;
    let end = u64::from_str_radix(end_str.strip_prefix("0x")?, 16).ok()?;

    Some((start, end, indent))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ElfTlsLayout {
    vaddr: u64,
    memsz: u64,
    align: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TlsAccessTarget {
    tpoff: i64,
    address: u64,
    size: u64,
}

fn elf_tls_layout(binary: &Binary) -> Option<ElfTlsLayout> {
    const PT_TLS: u32 = 7;

    match binary {
        Binary::Elf(elf) => elf
            .segments
            .iter()
            .find(|segment| segment.p_type == PT_TLS && segment.p_memsz > 0)
            .map(|segment| ElfTlsLayout {
                vaddr: segment.p_vaddr,
                memsz: segment.p_memsz,
                align: segment.p_align,
            }),
        _ => None,
    }
}

fn normalize_symbol_address(symbol: &hexray_core::Symbol, tls_layout: Option<ElfTlsLayout>) -> u64 {
    if symbol.kind == hexray_core::SymbolKind::Tls {
        if let Some(layout) = tls_layout {
            return layout.vaddr.saturating_add(symbol.address);
        }
    }

    symbol.address
}

fn align_up_u64(value: u64, align: u64) -> Option<u64> {
    if align <= 1 {
        return Some(value);
    }

    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
    }
}

fn tls_static_block_size(layout: ElfTlsLayout) -> Option<i64> {
    let aligned = align_up_u64(layout.memsz, layout.align.max(1))?;
    i64::try_from(aligned).ok()
}

fn build_tls_access_targets(binary: &Binary) -> Vec<TlsAccessTarget> {
    let Some(layout) = elf_tls_layout(binary) else {
        return Vec::new();
    };
    let Some(static_block_size) = tls_static_block_size(layout) else {
        return Vec::new();
    };

    let mut targets = Vec::new();
    for symbol in binary.as_format().symbols() {
        if symbol.kind != hexray_core::SymbolKind::Tls || !symbol.is_defined() {
            continue;
        }
        let Ok(raw_offset) = i64::try_from(symbol.address) else {
            continue;
        };
        targets.push(TlsAccessTarget {
            tpoff: raw_offset - static_block_size,
            address: layout.vaddr.saturating_add(symbol.address),
            size: symbol.size,
        });
    }

    targets.sort_by_key(|target| target.tpoff);
    targets
}

fn build_tls_slot_map(binary: &Binary) -> std::collections::HashMap<u64, u64> {
    let Binary::Elf(elf) = binary else {
        return std::collections::HashMap::new();
    };

    let Some(layout) = elf_tls_layout(binary) else {
        return std::collections::HashMap::new();
    };

    let mut map = std::collections::HashMap::new();
    for reloc in &elf.relocations {
        if !matches!(reloc.r_type, hexray_formats::RelocationType::Tpoff64) {
            continue;
        }
        let Ok(raw_offset) = u64::try_from(reloc.addend) else {
            continue;
        };
        map.insert(reloc.offset, layout.vaddr.saturating_add(raw_offset));
    }

    map
}

fn rip_relative_memory_target(
    mem: &hexray_core::MemoryRef,
    inst: &hexray_core::Instruction,
) -> Option<u64> {
    let base = mem.base.as_ref()?;
    if base.name() != "rip" || mem.index.is_some() {
        return None;
    }

    let inst_size = i128::try_from(inst.size).ok()?;
    let target = i128::from(inst.address) + inst_size + i128::from(mem.displacement);
    u64::try_from(target).ok()
}

fn add_signed_offset(base: u64, displacement: i64) -> Option<i64> {
    let target = i128::from(base) + i128::from(displacement);
    i64::try_from(target).ok()
}

fn resolve_tls_access_target(
    targets: &[TlsAccessTarget],
    displacement: i64,
    access_size: u8,
) -> Option<i64> {
    for target in targets {
        if displacement == target.tpoff {
            if let Ok(address) = i64::try_from(target.address) {
                return Some(address);
            }
        }
    }

    let access_size = i64::from(access_size);
    for target in targets {
        let Ok(size) = i64::try_from(target.size) else {
            continue;
        };
        if size <= 0 {
            continue;
        }
        let Some(offset) = displacement.checked_sub(target.tpoff) else {
            continue;
        };
        if offset < 0 {
            continue;
        }
        let Some(end) = offset.checked_add(access_size) else {
            continue;
        };
        if end > size {
            continue;
        }
        let absolute = i128::from(target.address) + i128::from(offset);
        if let Ok(address) = i64::try_from(absolute) {
            return Some(address);
        }
    }

    None
}

fn rewrite_tls_memory_operands(
    instructions: &mut [hexray_core::Instruction],
    tls_access_targets: &[TlsAccessTarget],
    tls_slot_map: &std::collections::HashMap<u64, u64>,
) {
    if tls_access_targets.is_empty() && tls_slot_map.is_empty() {
        return;
    }

    let mut tls_regs: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();

    for instruction in instructions {
        let tls_reg_load = if instruction.operation == hexray_core::Operation::Move {
            match instruction.operands.as_slice() {
                [hexray_core::Operand::Register(dest), hexray_core::Operand::Memory(mem), ..]
                    if dest.class == hexray_core::RegisterClass::General =>
                {
                    rip_relative_memory_target(mem, instruction)
                        .and_then(|slot| tls_slot_map.get(&slot).copied())
                        .map(|target| (dest.id, target))
                }
                _ => None,
            }
        } else {
            None
        };

        for operand in &mut instruction.operands {
            let hexray_core::Operand::Memory(mem) = operand else {
                continue;
            };
            let Some(segment) = mem.segment.as_ref() else {
                continue;
            };
            if !matches!(
                segment.id,
                hexray_core::register::x86::FS | hexray_core::register::x86::GS
            ) {
                continue;
            }
            if mem.index.is_none() {
                if let Some(base) = mem.base.as_ref() {
                    if let Some(&target) = tls_regs.get(&base.id) {
                        let Some(target_addr) = add_signed_offset(target, mem.displacement) else {
                            continue;
                        };
                        *mem = hexray_core::MemoryRef::absolute(target_addr, mem.size);
                        continue;
                    }
                }
            }
            if mem.base.is_some() || mem.index.is_some() {
                continue;
            }
            let Some(target_addr) =
                resolve_tls_access_target(tls_access_targets, mem.displacement, mem.size)
            else {
                continue;
            };
            *mem = hexray_core::MemoryRef::absolute(target_addr, mem.size);
        }

        for reg in &instruction.writes {
            if matches!(reg.arch, Architecture::X86_64 | Architecture::X86)
                && reg.class == hexray_core::RegisterClass::General
            {
                tls_regs.remove(&reg.id);
            }
        }

        if let Some((reg_id, target)) = tls_reg_load {
            tls_regs.insert(reg_id, target);
        }
    }
}

/// Builds a symbol table from the binary's symbols.
fn build_symbol_table(binary: &Binary) -> SymbolTable {
    let fmt = binary.as_format();
    let tls_layout = elf_tls_layout(binary);
    let mut table = SymbolTable::new();
    let mut best_symbols: std::collections::HashMap<u64, hexray_core::Symbol> =
        std::collections::HashMap::new();
    let mut symbols: Vec<_> = fmt.symbols().cloned().collect();
    add_ifunc_plt_aliases(binary, &mut symbols);

    // Add all symbols (both functions and data) for proper resolution.
    // TLS symbols are inserted both at their canonical TLS offset and at a
    // synthetic image address so rewritten fs:/gs: references can still
    // resolve to names while symbol queries keep the canonical offset.
    for symbol in &symbols {
        if symbol.name.is_empty() {
            continue;
        }

        if symbol.address == 0 && symbol.kind != hexray_core::SymbolKind::Tls {
            continue;
        }

        table.insert_symbol(symbol, demangle_or_original(&symbol.name));

        let mut candidate = symbol.clone();
        candidate.address = normalize_symbol_address(symbol, tls_layout);
        if candidate.address != symbol.address {
            table.insert_symbol(&candidate, demangle_or_original(&symbol.name));
        }
        if candidate.address == 0 {
            continue;
        }

        match best_symbols.entry(candidate.address) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                if compare_symbol_display_priority(&candidate, entry.get()).is_lt() {
                    entry.insert(candidate);
                }
            }
        }
    }

    for (address, symbol) in best_symbols {
        let mut symbol = symbol;
        symbol.address = address;
        table.insert_symbol(&symbol, demangle_or_original(&symbol.name));
    }

    table
}

fn collect_throw_thunks(
    binary: &Binary,
    symbol_table: &SymbolTable,
    relocation_table: &RelocationTable,
) -> std::collections::HashMap<u64, String> {
    let fmt = binary.as_format();
    let arch = fmt.architecture();
    let mut throw_thunks = std::collections::HashMap::new();

    for symbol in fmt.symbols() {
        if !symbol.is_function() || symbol.address == 0 {
            continue;
        }

        let display_name = symbol_table
            .get(symbol.address)
            .map(str::to_string)
            .unwrap_or_else(|| demangle_or_original(&symbol.name));
        if !looks_like_cold_split_symbol(&symbol.name, &display_name) {
            continue;
        }

        let max_bytes = if symbol.size > 0 {
            symbol.size as usize
        } else {
            256usize
        };
        let Some(bytes) = fmt.bytes_at(symbol.address, max_bytes) else {
            continue;
        };

        let mut instructions = match arch {
            Architecture::X86_64 | Architecture::X86 => {
                let disasm = X86_64Disassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, symbol.address, symbol.size == 0)
            }
            Architecture::Arm64 => {
                let disasm = Arm64Disassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, symbol.address, symbol.size == 0)
            }
            Architecture::RiscV64 => {
                let disasm = RiscVDisassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, symbol.address, symbol.size == 0)
            }
            Architecture::RiscV32 => {
                let disasm = RiscVDisassembler::new_rv32();
                disassemble_for_cfg(&disasm, fmt, bytes, symbol.address, symbol.size == 0)
            }
            _ => Vec::new(),
        };
        apply_call_relocations(&mut instructions, relocation_table);

        if instructions.iter().any(|instruction| {
            instruction_calls_cxx_throw(instruction, fmt, symbol_table, relocation_table)
        }) {
            throw_thunks.insert(symbol.address, display_name);
        }
    }

    throw_thunks
}

fn looks_like_cold_split_symbol(raw_name: &str, display_name: &str) -> bool {
    raw_name.contains(".cold") || display_name.contains(".cold")
}

fn instruction_calls_cxx_throw(
    instruction: &hexray_core::Instruction,
    fmt: &dyn BinaryFormat,
    symbol_table: &SymbolTable,
    relocation_table: &RelocationTable,
) -> bool {
    let hexray_core::ControlFlow::Call { target, .. } = instruction.control_flow else {
        return false;
    };

    if relocation_table
        .get_call(instruction.address)
        .is_some_and(|relocation| is_cxx_throw_symbol_name(&relocation.symbol))
    {
        return true;
    }

    symbol_table
        .get(target)
        .or_else(|| fmt.symbol_at(target).map(|symbol| symbol.name.as_str()))
        .is_some_and(is_cxx_throw_symbol_name)
}

fn is_cxx_throw_symbol_name(name: &str) -> bool {
    name.contains("__cxa_throw") || name.contains("__cxa_rethrow")
}

/// Builds a binary data context from read-only data sections for jump table reconstruction.
fn build_binary_data_context(fmt: &dyn BinaryFormat) -> BinaryDataContext {
    let mut ctx = BinaryDataContext::new();

    for section in fmt.sections() {
        let name = section.name().to_lowercase();
        // Include sections that may contain jump tables:
        // - .rodata (ELF read-only data)
        // - __const (Mach-O constants)
        // - .rdata (Windows read-only data)
        // - __DATA_CONST (Mach-O data constants)
        // - __text, .text (code sections - compilers often embed small jump tables here)
        if !section.data().is_empty()
            && (name.contains("rodata")
                || name.contains("const")
                || name == ".rdata"
                || name == "rdata"
                || name == "__text"
                || name == ".text")
        {
            ctx.add_section(section.virtual_address(), section.data().to_vec());
        }
    }

    ctx
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

fn synthetic_external_symbol_address(name: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET;
    for byte in name.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }

    0xff00_0000_0000_0000 | (hash & 0x00ff_ffff_ffff_ffff)
}

fn relocation_defined_target_addr(
    symbol: &hexray_core::Symbol,
    reloc_type: hexray_formats::RelocationType,
    addend: i64,
) -> u64 {
    match reloc_type {
        hexray_formats::RelocationType::Pc32 | hexray_formats::RelocationType::Plt32 => symbol
            .address
            .checked_add_signed(addend.saturating_add(4))
            .unwrap_or(symbol.address),
        hexray_formats::RelocationType::R32S => symbol
            .address
            .checked_add_signed(addend)
            .unwrap_or(symbol.address),
        _ => symbol.address,
    }
}

fn relocation_display_name(
    symbols: &[hexray_core::Symbol],
    symbol: &hexray_core::Symbol,
    target_addr: u64,
) -> String {
    if let Some(preferred) = find_preferred_symbol_at(symbols, target_addr) {
        let symbol_is_sectionish =
            matches!(symbol.kind, hexray_core::SymbolKind::Section) || symbol.name.starts_with('.');
        let preferred_is_concrete = !matches!(preferred.kind, hexray_core::SymbolKind::Section)
            && !preferred.name.starts_with('.');
        if symbol_is_sectionish && preferred_is_concrete {
            return preferred.name.clone();
        }
    }

    if target_addr != symbol.address {
        if let Some(offset) = target_addr.checked_sub(symbol.address) {
            if offset > 0 {
                return format!("{}+{:#x}", symbol.name, offset);
            }
        }
    }

    symbol.name.clone()
}

fn resolve_relocation_symbol(
    symbols: &[hexray_core::Symbol],
    symbol: &hexray_core::Symbol,
    reloc_type: hexray_formats::RelocationType,
    addend: i64,
) -> (String, u64, bool) {
    if symbol.section_index.is_some() {
        let target_addr = relocation_defined_target_addr(symbol, reloc_type, addend);
        (
            relocation_display_name(symbols, symbol, target_addr),
            target_addr,
            false,
        )
    } else {
        (
            symbol.name.clone(),
            synthetic_external_symbol_address(&symbol.name),
            true,
        )
    }
}

fn instruction_can_host_x86_64_relocation(instruction: &hexray_core::Instruction) -> bool {
    matches!(
        instruction.control_flow,
        hexray_core::ControlFlow::Call { .. }
            | hexray_core::ControlFlow::UnconditionalBranch { .. }
            | hexray_core::ControlFlow::ConditionalBranch { .. }
    ) || instruction.operands.iter().any(|operand| match operand {
        hexray_core::Operand::Immediate(_) => true,
        hexray_core::Operand::Memory(mem) => {
            mem.base.as_ref().is_some_and(|reg| reg.name() == "rip") && mem.index.is_none()
        }
        hexray_core::Operand::PcRelative { .. } => true,
        _ => false,
    })
}

fn x86_64_relocation_candidate_rank(
    instruction: &hexray_core::Instruction,
    reloc_type: hexray_formats::RelocationType,
) -> u8 {
    let is_control_flow = matches!(
        instruction.control_flow,
        hexray_core::ControlFlow::Call { .. }
            | hexray_core::ControlFlow::UnconditionalBranch { .. }
            | hexray_core::ControlFlow::ConditionalBranch { .. }
    );
    let has_pc_relative_operand = instruction
        .operands
        .iter()
        .any(|operand| matches!(operand, hexray_core::Operand::PcRelative { .. }));
    let has_rip_relative_memory = instruction.operands.iter().any(|operand| {
        matches!(
            operand,
            hexray_core::Operand::Memory(mem)
                if mem.base.as_ref().is_some_and(|reg| reg.name() == "rip")
                    && mem.index.is_none()
        )
    });
    let has_immediate = instruction
        .operands
        .iter()
        .any(|operand| matches!(operand, hexray_core::Operand::Immediate(_)));

    match reloc_type {
        hexray_formats::RelocationType::Pc32 | hexray_formats::RelocationType::Plt32 => {
            if is_control_flow && has_pc_relative_operand {
                3
            } else if has_rip_relative_memory {
                2
            } else if has_immediate {
                1
            } else {
                0
            }
        }
        hexray_formats::RelocationType::R32S | hexray_formats::RelocationType::R64 => {
            if has_immediate {
                3
            } else if has_rip_relative_memory {
                2
            } else if is_control_flow && has_pc_relative_operand {
                1
            } else {
                0
            }
        }
        _ => {
            if is_control_flow {
                2
            } else if has_rip_relative_memory || has_immediate {
                1
            } else {
                0
            }
        }
    }
}

fn find_x86_64_relocation_instruction(
    section: &hexray_formats::elf::SectionHeader,
    section_data: &[u8],
    reloc_type: hexray_formats::RelocationType,
    reloc_offset: u64,
) -> Option<hexray_core::Instruction> {
    let field_start = usize::try_from(reloc_offset).ok()?;
    let field_end = field_start.checked_add(4)?;
    if field_end > section_data.len() {
        return None;
    }

    let disasm = X86_64Disassembler::new();
    let scan_start = field_start.saturating_sub(15);
    let mut best: Option<(u8, usize, hexray_core::Instruction)> = None;

    for candidate in scan_start..=field_start {
        let remaining = section_data.get(candidate..)?;
        let addr = section.sh_offset.saturating_add(candidate as u64);
        let Ok(decoded) = disasm.decode_instruction(remaining, addr) else {
            continue;
        };
        if candidate.saturating_add(decoded.size) != field_end {
            continue;
        }
        if !instruction_can_host_x86_64_relocation(&decoded.instruction) {
            continue;
        }
        let rank = x86_64_relocation_candidate_rank(&decoded.instruction, reloc_type);
        if rank == 0 {
            continue;
        }
        let should_replace = best
            .as_ref()
            .map(|(best_rank, best_size, _)| {
                rank > *best_rank || (rank == *best_rank && decoded.size > *best_size)
            })
            .unwrap_or(true);
        if should_replace {
            best = Some((rank, decoded.size, decoded.instruction));
        }
    }

    best.map(|(_, _, instruction)| instruction)
}

const R_X86_64_IRELATIVE: u32 = 37;

fn ifunc_symbol_alias(
    symbols: &[hexray_core::Symbol],
    resolver_addr: u64,
) -> Option<hexray_core::Symbol> {
    symbols
        .iter()
        .find(|symbol| {
            symbol.address == resolver_addr
                && matches!(symbol.kind, hexray_core::SymbolKind::Other(10))
                && !symbol.name.is_empty()
        })
        .cloned()
}

fn add_ifunc_plt_aliases(binary: &Binary, symbols: &mut Vec<hexray_core::Symbol>) {
    let Binary::Elf(elf) = binary else {
        return;
    };

    let mut plt_sec = None;
    let mut plt = None;
    for section in &elf.sections {
        match elf.section_name(section) {
            Some(".plt.sec") => plt_sec = Some(section),
            Some(".plt") => plt = Some(section),
            _ => {}
        }
    }

    let (stub_base, stub_size, stub_count, has_header) = match (plt_sec, plt) {
        (Some(section), _) => (
            section.sh_addr,
            section.sh_entsize.max(16),
            section.sh_size / section.sh_entsize.max(16),
            false,
        ),
        (None, Some(section)) => (
            section.sh_addr,
            section.sh_entsize.max(16),
            section.sh_size / section.sh_entsize.max(16),
            true,
        ),
        _ => return,
    };

    let mut seen: std::collections::HashSet<(u64, String)> = symbols
        .iter()
        .map(|symbol| (symbol.address, symbol.name.clone()))
        .collect();

    for rel_section in &elf.sections {
        let rel_name = elf.section_name(rel_section).unwrap_or("");
        if rel_name != ".rela.plt" && rel_name != ".rel.plt" {
            continue;
        }

        let rel_start = rel_section.sh_offset as usize;
        let rel_end = rel_start.saturating_add(rel_section.sh_size as usize);
        let rel_entsize = rel_section.sh_entsize as usize;
        if rel_end > elf.data().len() || rel_end <= rel_start || rel_entsize == 0 {
            continue;
        }

        let mut reloc_entries = Vec::new();
        let mut rel_offset = rel_start;
        while let Some(rel_next) = rel_offset.checked_add(rel_entsize) {
            if rel_next > rel_end {
                break;
            }

            let entry_bytes = elf.data().get(rel_offset..rel_next).unwrap_or(&[]);
            let (offset, sym_index, reloc_type, addend) = match elf.header.class {
                hexray_formats::elf::ElfClass::Elf64 => {
                    if entry_bytes.len() < 16 {
                        break;
                    }
                    let offset_bytes: [u8; 8] = entry_bytes
                        .get(0..8)
                        .unwrap_or(&[0; 8])
                        .try_into()
                        .unwrap_or([0; 8]);
                    let offset = match elf.header.endianness {
                        hexray_core::Endianness::Little => u64::from_le_bytes(offset_bytes),
                        hexray_core::Endianness::Big => u64::from_be_bytes(offset_bytes),
                    };
                    let info_bytes: [u8; 8] = entry_bytes
                        .get(8..16)
                        .unwrap_or(&[0; 8])
                        .try_into()
                        .unwrap_or([0; 8]);
                    let r_info = match elf.header.endianness {
                        hexray_core::Endianness::Little => u64::from_le_bytes(info_bytes),
                        hexray_core::Endianness::Big => u64::from_be_bytes(info_bytes),
                    };
                    let addend = if rel_name == ".rela.plt" && entry_bytes.len() >= 24 {
                        let addend_bytes: [u8; 8] = entry_bytes
                            .get(16..24)
                            .unwrap_or(&[0; 8])
                            .try_into()
                            .unwrap_or([0; 8]);
                        match elf.header.endianness {
                            hexray_core::Endianness::Little => i64::from_le_bytes(addend_bytes),
                            hexray_core::Endianness::Big => i64::from_be_bytes(addend_bytes),
                        }
                    } else {
                        0
                    };
                    (offset, (r_info >> 32) as u32, r_info as u32, addend)
                }
                hexray_formats::elf::ElfClass::Elf32 => {
                    if entry_bytes.len() < 8 {
                        break;
                    }
                    let offset_bytes: [u8; 4] = entry_bytes
                        .get(0..4)
                        .unwrap_or(&[0; 4])
                        .try_into()
                        .unwrap_or([0; 4]);
                    let offset = match elf.header.endianness {
                        hexray_core::Endianness::Little => u32::from_le_bytes(offset_bytes) as u64,
                        hexray_core::Endianness::Big => u32::from_be_bytes(offset_bytes) as u64,
                    };
                    let info_bytes: [u8; 4] = entry_bytes
                        .get(4..8)
                        .unwrap_or(&[0; 4])
                        .try_into()
                        .unwrap_or([0; 4]);
                    let r_info = match elf.header.endianness {
                        hexray_core::Endianness::Little => u32::from_le_bytes(info_bytes),
                        hexray_core::Endianness::Big => u32::from_be_bytes(info_bytes),
                    };
                    let addend = if rel_name == ".rela.plt" && entry_bytes.len() >= 12 {
                        let addend_bytes: [u8; 4] = entry_bytes
                            .get(8..12)
                            .unwrap_or(&[0; 4])
                            .try_into()
                            .unwrap_or([0; 4]);
                        let raw = match elf.header.endianness {
                            hexray_core::Endianness::Little => i32::from_le_bytes(addend_bytes),
                            hexray_core::Endianness::Big => i32::from_be_bytes(addend_bytes),
                        };
                        i64::from(raw)
                    } else {
                        0
                    };
                    (offset, r_info >> 8, r_info & 0xff, addend)
                }
            };

            reloc_entries.push((offset, sym_index, reloc_type, addend));
            rel_offset = rel_next;
        }

        reloc_entries.sort_by_key(|(offset, _, _, _)| *offset);
        let header_shift = u64::from(has_header && (reloc_entries.len() as u64) < stub_count);

        for (stub_index, (_, sym_index, reloc_type, addend)) in
            reloc_entries.into_iter().enumerate()
        {
            if sym_index == 0 && reloc_type == R_X86_64_IRELATIVE {
                if let Ok(resolver_addr) = u64::try_from(addend) {
                    if let Some(mut alias) = ifunc_symbol_alias(symbols, resolver_addr) {
                        let stub_idx = (stub_index as u64).saturating_add(header_shift);
                        alias.address =
                            stub_base.saturating_add(stub_size.saturating_mul(stub_idx));
                        alias.size = stub_size;
                        alias.kind = hexray_core::SymbolKind::Function;
                        alias.section_index = None;
                        if seen.insert((alias.address, alias.name.clone())) {
                            symbols.push(alias);
                        }
                    }
                }
            }
        }
    }
}

fn collect_analysis_symbols(
    binary: &Binary,
    relocations: &RelocationTable,
) -> Vec<hexray_core::Symbol> {
    let fmt = binary.as_format();
    let mut symbols: Vec<_> = fmt.symbols().cloned().collect();
    add_ifunc_plt_aliases(binary, &mut symbols);
    let mut seen = std::collections::HashSet::new();
    for symbol in &symbols {
        seen.insert((symbol.address, symbol.name.clone()));
    }

    for (_, relocation) in relocations.call_relocations() {
        if !relocation.is_external {
            continue;
        }
        if !seen.insert((relocation.target_addr, relocation.symbol.clone())) {
            continue;
        }
        symbols.push(hexray_core::Symbol {
            name: relocation.symbol.clone(),
            address: relocation.target_addr,
            size: 0,
            kind: hexray_core::SymbolKind::Function,
            binding: hexray_core::SymbolBinding::Global,
            section_index: None,
        });
    }

    synthesize_startup_function_symbols(fmt, relocations, &mut symbols);
    synthesize_signature_function_symbols(fmt, &mut symbols);

    symbols
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

    // Collect symbols for lookup by index and section-relative target resolution.
    let symbols: Vec<_> = elf.symbols().cloned().collect();

    // Process relocations - each relocation has a section_index telling us which section it applies to
    for reloc in &elf.relocations {
        let Some(symbol) = symbols.get(reloc.symbol_index as usize) else {
            continue;
        };
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
            RelocationType::DtpMod64 => {
                table.insert_tls_descriptor(reloc.offset, symbol.name.clone());
            }
            RelocationType::DtpOff64 => {
                table.insert_tls_descriptor(reloc.offset.saturating_sub(8), symbol.name.clone());
            }
            // PC-relative relocations (for calls/jumps in relocatable objects)
            RelocationType::Pc32 | RelocationType::Plt32 => {
                let Some(section) = elf.sections.get(reloc.section_index) else {
                    continue;
                };
                let (resolved_name, target_addr, is_external) =
                    resolve_relocation_symbol(&symbols, symbol, reloc.r_type, reloc.addend);
                let instruction = elf.section_data(section).and_then(|section_data| {
                    find_x86_64_relocation_instruction(
                        section,
                        section_data,
                        reloc.r_type,
                        reloc.offset,
                    )
                });
                if let Some(instruction) = instruction {
                    match instruction.control_flow {
                        hexray_core::ControlFlow::Call { .. }
                        | hexray_core::ControlFlow::UnconditionalBranch { .. }
                        | hexray_core::ControlFlow::ConditionalBranch { .. } => {
                            table.insert_call(
                                instruction.address,
                                resolved_name,
                                target_addr,
                                is_external,
                            );
                        }
                        _ => {
                            table.insert_data(
                                instruction.address,
                                resolved_name,
                                target_addr,
                                true,
                            );
                        }
                    }
                } else {
                    let call_addr = section
                        .sh_offset
                        .saturating_add(reloc.offset)
                        .saturating_sub(1);
                    table.insert_call(call_addr, resolved_name, target_addr, is_external);
                }
            }
            // 32-bit signed immediate relocations (for mov reg, imm32)
            RelocationType::R32S => {
                let Some(section) = elf.sections.get(reloc.section_index) else {
                    continue;
                };
                let (resolved_name, target_addr, _) =
                    resolve_relocation_symbol(&symbols, symbol, reloc.r_type, reloc.addend);
                let sym_name = if symbol.name.starts_with(".rodata.str") {
                    usize::try_from(target_addr)
                        .ok()
                        .and_then(|offset| read_cstring_from_elf(elf.data(), offset))
                        .unwrap_or(resolved_name)
                } else {
                    resolved_name
                };
                let inst_addr = elf
                    .section_data(section)
                    .and_then(|section_data| {
                        find_x86_64_relocation_instruction(
                            section,
                            section_data,
                            reloc.r_type,
                            reloc.offset,
                        )
                    })
                    .map(|instruction| instruction.address)
                    .unwrap_or_else(|| {
                        section
                            .sh_offset
                            .saturating_add(reloc.offset)
                            .saturating_sub(3)
                    });
                table.insert_data(inst_addr, sym_name, target_addr, false);
            }
            // 64-bit absolute relocations
            RelocationType::R64 => {
                if let Some(section) = elf.sections.get(reloc.section_index) {
                    let (resolved_name, target_addr, _) =
                        resolve_relocation_symbol(&symbols, symbol, reloc.r_type, reloc.addend);
                    let inst_addr = section.sh_offset + reloc.offset - 2;
                    table.insert_data(inst_addr, resolved_name, target_addr, false);
                }
            }
            // GOT-relative relocations (for mov reg, [rip+X] accessing global variables)
            // The relocation points to the displacement (4 bytes), instruction starts 3 bytes before
            // Format: REX.W MOV ModRM disp32 = 48 8b XX 00 00 00 00
            RelocationType::GotPcRel | RelocationType::GotPcRelX | RelocationType::RexGotPcRelX => {
                if let Some(section) = elf.sections.get(reloc.section_index) {
                    // Instruction starts 3 bytes before the displacement
                    let inst_addr = section.sh_offset + reloc.offset - 3;
                    table.insert_got(inst_addr, symbol.name.clone());
                }
            }
            _ => {}
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
            match binary {
                Binary::Elf(_) => {
                    posix::load_posix_types(&mut db);
                    linux::load_linux_types(&mut db);
                    libc::load_libc_functions(&mut db);
                }
                Binary::MachO(_) => {
                    posix::load_posix_types(&mut db);
                    macos::load_macos_types(&mut db);
                    libc::load_libc_functions(&mut db);
                }
                // Keep empty until Win32/NT type libraries are added.
                Binary::Pe(_) => {}
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
fn load_dwarf_info(binary_path: &Path, binary: &Binary) -> Option<DebugInfo> {
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
    let debug_loc = fmt
        .sections()
        .find(|s| s.name() == ".debug_loc" || s.name() == "__debug_loc")
        .map(|s| s.data());
    let debug_loclists = fmt
        .sections()
        .find(|s| s.name() == ".debug_loclists" || s.name() == "__debug_loclists")
        .map(|s| s.data());
    let debug_str_offsets = fmt
        .sections()
        .find(|s| s.name() == ".debug_str_offsets" || s.name() == "__debug_str_offsets")
        .map(|s| s.data());
    let debug_addr = fmt
        .sections()
        .find(|s| s.name() == ".debug_addr" || s.name() == "__debug_addr")
        .map(|s| s.data());

    // Determine address size based on architecture
    let address_size = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 4,
        _ => 8,
    };

    // Parse DWARF info
    let parsed = parse_debug_info(
        debug_info,
        debug_abbrev,
        debug_str,
        debug_line,
        debug_loc,
        debug_loclists,
        debug_str_offsets,
        debug_addr,
        address_size,
    )
    .ok()?;

    load_split_dwarf_info(binary_path, fmt, &parsed, address_size).or(Some(parsed))
}

#[derive(Default)]
struct DwarfFunctionNames {
    stack_names: std::collections::HashMap<i128, String>,
    parameter_names: Vec<String>,
    local_scope_ranges: std::collections::HashMap<String, (u64, u64)>,
}

/// Gets DWARF variable and parameter names for a function at the given address.
fn get_dwarf_function_names(
    debug_info: &DebugInfo,
    func_addr: u64,
    binary: &Binary,
) -> DwarfFunctionNames {
    if let Some(func) = debug_info.find_function(func_addr) {
        let declared_names: Vec<String> = func
            .parameters()
            .map(|param| {
                func.resolved_name(param)
                    .map(str::to_string)
                    .unwrap_or_default()
            })
            .collect();
        let mut bound_names = std::collections::HashMap::new();
        for param in func.parameters() {
            let Some(name) = func.resolved_name(param).map(str::to_string) else {
                continue;
            };
            let Some(expr) = func.entry_location_expression(param) else {
                continue;
            };
            let Some(reg) = dwarf_entry_register(&expr) else {
                continue;
            };
            let Some(arg_index) = dwarf_register_arg_index(binary, reg) else {
                continue;
            };
            bound_names.entry(arg_index).or_insert(name);
        }

        let parameter_names = if bound_names.is_empty() {
            declared_names
        } else {
            let mut names = vec![
                String::new();
                declared_names.len().max(
                    bound_names
                        .keys()
                        .copied()
                        .max()
                        .unwrap_or(0)
                        .saturating_add(1)
                )
            ];
            for (idx, name) in bound_names {
                if let Some(slot) = names.get_mut(idx) {
                    *slot = name;
                }
            }
            for name in declared_names {
                if name.is_empty() {
                    continue;
                }
                if let Some(slot) = names.iter_mut().find(|slot| slot.is_empty()) {
                    *slot = name;
                }
            }
            names
        };
        DwarfFunctionNames {
            stack_names: func.variable_names(),
            parameter_names,
            local_scope_ranges: dwarf_lexical_scope_ranges(&func),
        }
    } else {
        DwarfFunctionNames::default()
    }
}

fn dwarf_lexical_scope_ranges(
    func: &hexray_formats::dwarf::FunctionInfo<'_>,
) -> std::collections::HashMap<String, (u64, u64)> {
    fn collect(
        func: &hexray_formats::dwarf::FunctionInfo<'_>,
        die: &Die,
        out: &mut std::collections::HashMap<String, (u64, u64)>,
    ) {
        if matches!(die.tag, DwTag::LexicalBlock) {
            if let (Some(low_pc), Some(high_pc_attr)) = (die.low_pc(), die.attr(DwAt::HighPc)) {
                let high_pc = match high_pc_attr {
                    AttributeValue::Address(addr) => *addr,
                    AttributeValue::Unsigned(size) => low_pc.saturating_add(*size),
                    _ => low_pc,
                };
                for child in &die.children {
                    if matches!(child.tag, DwTag::Variable) {
                        if let Some(name) = func.resolved_name(child) {
                            out.insert(name.to_string(), (low_pc, high_pc));
                        }
                    }
                }
            }
        }

        for child in &die.children {
            collect(func, child, out);
        }
    }

    let mut ranges = std::collections::HashMap::new();
    collect(func, func.die, &mut ranges);
    ranges
}

fn load_split_dwarf_info(
    binary_path: &Path,
    fmt: &dyn BinaryFormat,
    main_debug_info: &DebugInfo,
    address_size: u8,
) -> Option<DebugInfo> {
    let (dwo_name, comp_dir) = main_debug_info
        .compilation_units
        .iter()
        .find_map(|cu| match cu.root_die.attr(DwAt::DwoName) {
            Some(AttributeValue::String(name)) => {
                Some((name.clone(), cu.comp_dir().map(str::to_string)))
            }
            _ => None,
        })?;

    let sidecar_path = resolve_dwo_path(binary_path, comp_dir.as_deref(), &dwo_name)?;
    let bytes = fs::read(sidecar_path).ok()?;
    if detect_format(&bytes) != BinaryType::Elf {
        return None;
    }
    let elf = Elf::parse(&bytes).ok()?;

    let debug_info = elf
        .sections()
        .find(|s| s.name() == ".debug_info.dwo")?
        .data();
    let debug_abbrev = elf
        .sections()
        .find(|s| s.name() == ".debug_abbrev.dwo")?
        .data();
    let debug_str = elf
        .sections()
        .find(|s| s.name() == ".debug_str.dwo")
        .map(|s| s.data());
    let debug_line = elf
        .sections()
        .find(|s| s.name() == ".debug_line.dwo")
        .map(|s| s.data());
    let debug_loclists = elf
        .sections()
        .find(|s| s.name() == ".debug_loclists.dwo")
        .map(|s| s.data());
    let debug_str_offsets = elf
        .sections()
        .find(|s| s.name() == ".debug_str_offsets.dwo")
        .map(|s| s.data());
    let debug_addr = fmt
        .sections()
        .find(|s| s.name() == ".debug_addr" || s.name() == "__debug_addr")
        .map(|s| s.data());

    parse_debug_info(
        debug_info,
        debug_abbrev,
        debug_str,
        debug_line,
        None,
        debug_loclists,
        debug_str_offsets,
        debug_addr,
        address_size,
    )
    .ok()
}

fn resolve_dwo_path(binary_path: &Path, comp_dir: Option<&str>, dwo_name: &str) -> Option<PathBuf> {
    let dwo_path = Path::new(dwo_name);
    if dwo_path.is_absolute() && dwo_path.exists() {
        return Some(dwo_path.to_path_buf());
    }

    let mut candidates = Vec::new();
    if let Some(parent) = binary_path.parent() {
        candidates.push(parent.join(dwo_name));
    }
    if let Some(dir) = comp_dir {
        candidates.push(Path::new(dir).join(dwo_name));
    }

    candidates.into_iter().find(|path| path.exists())
}

fn dwarf_entry_register(expr: &[u8]) -> Option<u64> {
    let op = *expr.first()?;
    match op {
        0x50..=0x6f => Some((op - 0x50) as u64),
        0x90 => decode_uleb128(expr.get(1..)?).ok().map(|(reg, _)| reg),
        0xa3 | 0xf3 => {
            let (len, consumed) = decode_uleb128(expr.get(1..)?).ok()?;
            let start = 1usize.checked_add(consumed)?;
            let end = start.checked_add(len as usize)?;
            dwarf_entry_register(expr.get(start..end)?)
        }
        _ => None,
    }
}

fn dwarf_register_arg_index(binary: &Binary, reg: u64) -> Option<usize> {
    const X86_64_SYSV: &[u64] = &[5, 4, 1, 2, 8, 9];
    const X86_64_WIN64: &[u64] = &[2, 1, 8, 9];
    const ARM64_AAPCS: &[u64] = &[0, 1, 2, 3, 4, 5, 6, 7];
    const RISCV: &[u64] = &[10, 11, 12, 13, 14, 15, 16, 17];

    let order = match (binary, binary.as_format().architecture()) {
        (Binary::Pe(_), Architecture::X86_64) => X86_64_WIN64,
        (_, Architecture::X86_64) => X86_64_SYSV,
        (_, Architecture::Arm64) => ARM64_AAPCS,
        (_, Architecture::RiscV64 | Architecture::RiscV32) => RISCV,
        _ => &[],
    };

    order.iter().position(|candidate| *candidate == reg)
}

/// Disassemble bytes to extract call instructions (for function discovery).
fn disassemble_for_calls<D: hexray_disasm::Disassembler>(
    disasm: &D,
    bytes: &[u8],
    start_addr: u64,
    heuristic_bounds: bool,
    noreturn_targets: &std::collections::HashSet<u64>,
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
                let is_halt = matches!(
                    decoded.instruction.control_flow,
                    hexray_core::ControlFlow::Halt
                );
                let next_offset = offset + decoded.size;
                let next_addr = addr + decoded.size as u64;
                let is_heuristic_tail_jump = heuristic_bounds
                    && heuristic_tail_jump_stops_scan(
                        disasm,
                        bytes,
                        next_offset,
                        next_addr,
                        &decoded.instruction,
                        false,
                    );
                let is_noreturn_call = heuristic_bounds
                    && matches!(
                        decoded.instruction.control_flow,
                        hexray_core::ControlFlow::Call { target, .. }
                            if noreturn_targets.contains(&target)
                    );
                instructions.push(decoded.instruction);
                offset += decoded.size;

                if is_halt || is_noreturn_call || is_heuristic_tail_jump {
                    break;
                }
                // With exact symbol bounds we can keep scanning across early returns
                // to pick up later cold/error blocks that still belong to the same
                // function body. The midpoint cutoff is only for heuristic windows.
                if heuristic_bounds && is_ret && offset >= bytes.len() / 2 {
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

fn heuristic_tail_jump_stops_scan<D: Disassembler>(
    disasm: &D,
    bytes: &[u8],
    next_offset: usize,
    next_addr: u64,
    instruction: &hexray_core::Instruction,
    next_addr_is_function_start: bool,
) -> bool {
    match instruction.control_flow {
        hexray_core::ControlFlow::UnconditionalBranch { .. } => true,
        hexray_core::ControlFlow::IndirectBranch { .. } => {
            next_addr_is_function_start
                || next_decoded_instruction_looks_like_padding_or_entry(
                    disasm,
                    bytes.get(next_offset..).unwrap_or(&[]),
                    next_addr,
                )
        }
        _ => false,
    }
}

fn next_decoded_instruction_looks_like_padding_or_entry<D: Disassembler>(
    disasm: &D,
    remaining: &[u8],
    addr: u64,
) -> bool {
    let Ok(decoded) = disasm.decode_instruction(remaining, addr) else {
        return false;
    };

    matches!(decoded.instruction.operation, hexray_core::Operation::Nop)
        || decoded.instruction.mnemonic == "endbr64"
}

fn apply_call_relocations(
    instructions: &mut [hexray_core::Instruction],
    relocations: &RelocationTable,
) {
    for instruction in instructions {
        let Some(relocation) = relocations.get_call(instruction.address) else {
            continue;
        };
        let is_return_thunk = relocation.symbol == "__x86_return_thunk";

        match &mut instruction.control_flow {
            hexray_core::ControlFlow::Call { target, .. } => {
                *target = relocation.target_addr;
            }
            hexray_core::ControlFlow::UnconditionalBranch { target } => {
                if is_return_thunk {
                    instruction.control_flow = hexray_core::ControlFlow::Return;
                } else {
                    *target = relocation.target_addr;
                }
            }
            hexray_core::ControlFlow::ConditionalBranch { target, .. } => {
                *target = relocation.target_addr;
            }
            _ => {}
        }

        if !is_return_thunk {
            for operand in &mut instruction.operands {
                if let hexray_core::Operand::PcRelative { target, .. } = operand {
                    *target = relocation.target_addr;
                }
            }
        }
    }
}

fn apply_data_relocations(
    instructions: &mut [hexray_core::Instruction],
    relocations: &RelocationTable,
) {
    for instruction in instructions {
        let Some(target_addr) = relocations.get_data_target(instruction.address) else {
            continue;
        };
        if !relocations.data_is_pc_relative(instruction.address) {
            for operand in &mut instruction.operands {
                if let hexray_core::Operand::Immediate(imm) = operand {
                    imm.value = i128::from(target_addr);
                    break;
                }
            }
            continue;
        }
        let Some(inst_end) = instruction.address.checked_add(instruction.size as u64) else {
            continue;
        };
        let Ok(inst_end_i64) = i64::try_from(inst_end) else {
            continue;
        };
        let Ok(target_i64) = i64::try_from(target_addr) else {
            continue;
        };
        let Some(displacement) = target_i64.checked_sub(inst_end_i64) else {
            continue;
        };

        for operand in &mut instruction.operands {
            if let hexray_core::Operand::Memory(mem) = operand {
                if mem.base.as_ref().is_some_and(|reg| reg.name() == "rip") && mem.index.is_none() {
                    mem.displacement = displacement;
                    break;
                }
            }
        }
    }
}

fn apply_instruction_relocations(
    instructions: &mut [hexray_core::Instruction],
    relocations: &RelocationTable,
) {
    apply_call_relocations(instructions, relocations);
    apply_data_relocations(instructions, relocations);
}

// Shared function-start recovery for analyses that need whole-function
// coverage, including partially symbolized CET/IBT binaries. Callers
// can still layer additional discoveries on top (for example
// round-6.5's xref call-target seeding).
fn discover_function_starts(
    fmt: &dyn BinaryFormat,
    arch: Architecture,
    symbols: &[hexray_core::Symbol],
) -> Vec<(u64, u64, bool)> {
    let mut starts: Vec<_> = symbols
        .iter()
        .filter(|s| {
            s.is_function() && s.address != 0 && s.is_defined() && s.section_index.is_some()
        })
        .map(|s| {
            (
                s.address,
                if s.size > 0 { s.size } else { 4096 },
                s.size == 0,
            )
        })
        .collect();

    // CET/IBT binaries often expose only partial function-symbol coverage
    // (for example dynsym plus a handful of local labels). Always fold in
    // ENDBR-derived starts on x86 so xref/callgraph scans still reach the
    // unsymbolized bodies that make direct calls into PLT stubs.
    starts.extend(discover_stripped_x86_function_seeds(fmt, arch));

    starts.extend(
        discover_lifecycle_array_entries(fmt)
            .into_iter()
            .map(|(_, target)| {
                find_preferred_symbol_at(symbols, target)
                    .map(|symbol| {
                        (
                            target,
                            if symbol.size > 0 { symbol.size } else { 4096 },
                            symbol.size == 0,
                        )
                    })
                    .unwrap_or((target, 4096, true))
            }),
    );

    if let Some(entry) = fmt.entry_point() {
        if !starts.iter().any(|(addr, _, _)| *addr == entry) {
            starts.push((entry, 8192, true));
        }
    }

    starts.sort_by_key(|(addr, _, _)| *addr);
    starts.dedup_by_key(|(addr, _, _)| *addr);
    starts
}

fn discover_stripped_x86_function_seeds(
    fmt: &dyn BinaryFormat,
    arch: Architecture,
) -> Vec<(u64, u64, bool)> {
    let pattern: &[u8] = match arch {
        Architecture::X86_64 => &[0xf3, 0x0f, 0x1e, 0xfa],
        Architecture::X86 => &[0xf3, 0x0f, 0x1e, 0xfb],
        _ => return Vec::new(),
    };

    let mut seeds = Vec::new();
    for section in fmt.executable_sections() {
        let starts =
            discover_endbr_function_starts(section.virtual_address(), section.data(), pattern);
        for (idx, start) in starts.iter().enumerate() {
            let end = starts
                .get(idx + 1)
                .copied()
                .unwrap_or_else(|| section.virtual_address().saturating_add(section.size()));
            let size = end.saturating_sub(*start).max(pattern.len() as u64);
            seeds.push((*start, size, false));
        }
    }

    seeds.sort_by_key(|(addr, _, _)| *addr);
    seeds.dedup_by_key(|(addr, _, _)| *addr);
    seeds
}

fn discover_endbr_function_starts(section_addr: u64, bytes: &[u8], pattern: &[u8]) -> Vec<u64> {
    if bytes.len() < pattern.len() {
        return Vec::new();
    }

    bytes
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(offset, window)| {
            if window == pattern {
                Some(section_addr.saturating_add(offset as u64))
            } else {
                None
            }
        })
        .collect()
}

fn discover_materialized_internal_targets(
    instructions: &[hexray_core::Instruction],
    fmt: &dyn BinaryFormat,
) -> Vec<u64> {
    use hexray_core::{register::x86, Operand, Operation};

    let is_internal_addr = |addr: u64| -> bool {
        if addr == 0 {
            return false;
        }
        fmt.sections().any(|s| {
            let section_start = s.virtual_address();
            let section_end = section_start.saturating_add(s.size());
            let section_name = s.name().to_ascii_lowercase();
            if section_name.contains("plt") || section_name.contains("stub") {
                return false;
            }
            addr >= section_start && addr < section_end && s.is_executable()
        })
    };

    let mut seen = std::collections::HashSet::new();
    let mut targets = Vec::new();
    for instr in instructions {
        if !matches!(instr.operands.first(), Some(Operand::Register(_))) {
            continue;
        }

        let Some(source) = (match instr.operation {
            Operation::Move | Operation::LoadEffectiveAddress => instr.operands.get(1),
            _ => None,
        }) else {
            continue;
        };

        let target = match source {
            Operand::Immediate(imm) => Some(imm.value as u64),
            Operand::PcRelative { target, .. } => Some(*target),
            Operand::Memory(mem)
                if matches!(instr.operation, Operation::LoadEffectiveAddress)
                    && mem.base.as_ref().map(|reg| reg.id) == Some(x86::RIP)
                    && mem.index.is_none() =>
            {
                Some((instr.address + instr.size as u64).wrapping_add(mem.displacement as u64))
            }
            _ => None,
        };

        if let Some(addr) = target.filter(|addr| is_internal_addr(*addr)) {
            if seen.insert(addr) {
                targets.push(addr);
            }
        }
    }

    targets
}

fn is_executable_callback_target(fmt: &dyn BinaryFormat, addr: u64) -> bool {
    if addr == 0 {
        return false;
    }

    fmt.sections().any(|section| {
        let section_start = section.virtual_address();
        let section_end = section_start.saturating_add(section.size());
        let section_name = section.name().to_ascii_lowercase();
        addr >= section_start
            && addr < section_end
            && section.is_executable()
            && !section_name.contains("plt")
            && !section_name.contains("stub")
    })
}

fn read_pointer_at(fmt: &dyn BinaryFormat, addr: u64) -> Option<u64> {
    let ptr_size = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 4usize,
        hexray_core::Bitness::Bits64 => 8usize,
    };
    let bytes = fmt.bytes_at(addr, ptr_size)?;

    match (fmt.endianness(), ptr_size) {
        (hexray_core::Endianness::Little, 4) => {
            let value = u32::from_le_bytes(bytes.try_into().ok()?);
            Some(value as u64)
        }
        (hexray_core::Endianness::Big, 4) => {
            let value = u32::from_be_bytes(bytes.try_into().ok()?);
            Some(value as u64)
        }
        (hexray_core::Endianness::Little, 8) => Some(u64::from_le_bytes(bytes.try_into().ok()?)),
        (hexray_core::Endianness::Big, 8) => Some(u64::from_be_bytes(bytes.try_into().ok()?)),
        _ => None,
    }
}

fn discover_lifecycle_array_entries(fmt: &dyn BinaryFormat) -> Vec<(u64, u64)> {
    let ptr_size = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 4u64,
        hexray_core::Bitness::Bits64 => 8u64,
    };
    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();

    for section in fmt.sections() {
        if !matches!(section.name(), ".init_array" | ".fini_array") {
            continue;
        }

        let section_start = section.virtual_address();
        let slot_count = section.size() / ptr_size;
        for index in 0..slot_count {
            let slot_addr = section_start + index * ptr_size;
            let Some(target) = read_pointer_at(fmt, slot_addr) else {
                continue;
            };
            if !is_executable_callback_target(fmt, target) {
                continue;
            }
            if seen.insert((slot_addr, target)) {
                entries.push((slot_addr, target));
            }
        }
    }

    entries
}

fn append_lifecycle_array_relative_relocations(
    fmt: &dyn BinaryFormat,
    lifecycle_ranges: &[(u64, u64)],
    relocations: &[(u64, hexray_formats::RelocationType, i64)],
    seen: &mut std::collections::HashSet<(u64, u64)>,
    entries: &mut Vec<(u64, u64)>,
) {
    for (slot_addr, reloc_type, addend) in relocations {
        if *reloc_type != hexray_formats::RelocationType::Relative {
            continue;
        }
        if !lifecycle_ranges
            .iter()
            .any(|(start, end)| *slot_addr >= *start && *slot_addr < *end)
        {
            continue;
        }

        let Ok(target) = u64::try_from(*addend) else {
            continue;
        };
        if !is_executable_callback_target(fmt, target) {
            continue;
        }
        if seen.insert((*slot_addr, target)) {
            entries.push((*slot_addr, target));
        }
    }
}

fn discover_lifecycle_array_entries_for_binary(binary: &Binary) -> Vec<(u64, u64)> {
    let fmt = binary.as_format();
    let mut entries = discover_lifecycle_array_entries(fmt);
    let lifecycle_ranges: Vec<_> = fmt
        .sections()
        .filter(|section| matches!(section.name(), ".init_array" | ".fini_array"))
        .map(|section| {
            (
                section.virtual_address(),
                section.virtual_address().saturating_add(section.size()),
            )
        })
        .collect();
    if lifecycle_ranges.is_empty() {
        return entries;
    }

    if let Binary::Elf(elf) = binary {
        let relocations: Vec<_> = elf
            .relocations
            .iter()
            .map(|reloc| (reloc.offset, reloc.r_type, reloc.addend))
            .collect();
        let mut seen: std::collections::HashSet<_> = entries.iter().copied().collect();
        append_lifecycle_array_relative_relocations(
            fmt,
            &lifecycle_ranges,
            &relocations,
            &mut seen,
            &mut entries,
        );
        entries.sort_unstable_by_key(|(slot_addr, _)| *slot_addr);
    }

    entries
}

fn resolve_materialized_callback_targets(
    fmt: &dyn BinaryFormat,
    call: &hexray_analysis::callgraph::MaterializedIndirectCall,
) -> Vec<u64> {
    const MAX_SCAN_SLOTS: usize = 32;
    const MAX_STRIDE_SLOTS: usize = 8;

    let Some(section) = fmt.section_containing(call.table_base) else {
        return Vec::new();
    };
    if section.is_executable() || !section.is_allocated() {
        return Vec::new();
    }

    let ptr_size = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 4u64,
        hexray_core::Bitness::Bits64 => 8u64,
    };
    if call.deref_offset % ptr_size != 0 {
        return Vec::new();
    }

    let Some(scan_start) = call.table_base.checked_add(call.deref_offset) else {
        return Vec::new();
    };
    if scan_start % ptr_size != 0 {
        return Vec::new();
    }

    let section_start = section.virtual_address();
    let section_end = section_start.saturating_add(section.size());
    if scan_start < section_start || scan_start.saturating_add(ptr_size) > section_end {
        return Vec::new();
    }

    let remaining_slots = ((section_end - scan_start) / ptr_size) as usize;
    let slot_count = remaining_slots.min(MAX_SCAN_SLOTS);
    if slot_count < 2 {
        return Vec::new();
    }

    let mut slots = Vec::with_capacity(slot_count);
    for index in 0..slot_count {
        let slot_addr = scan_start + index as u64 * ptr_size;
        let Some(value) = read_pointer_at(fmt, slot_addr) else {
            break;
        };
        slots.push(value);
    }
    if slots.len() < 2 || !is_executable_callback_target(fmt, slots[0]) {
        return Vec::new();
    }

    let mut best_run = Vec::new();
    let max_stride = slots.len().min(MAX_STRIDE_SLOTS + 1);
    for stride in 1..max_stride {
        if !is_executable_callback_target(fmt, slots[stride]) {
            continue;
        }
        if (1..stride).any(|index| is_executable_callback_target(fmt, slots[index])) {
            continue;
        }

        let mut run = vec![slots[0]];
        let mut index = stride;
        while index < slots.len() {
            if stride > 1
                && slots[index - stride + 1..index]
                    .iter()
                    .any(|value| *value == 0 || is_executable_callback_target(fmt, *value))
            {
                break;
            }

            let value = slots[index];
            if !is_executable_callback_target(fmt, value) {
                break;
            }
            run.push(value);
            index += stride;
        }

        if run.len() >= 2 && run.len() > best_run.len() {
            best_run = run;
        }
    }

    best_run
}

struct MaterializedCallbackEdgeContext<'a> {
    fmt: &'a dyn BinaryFormat,
    arch: Architecture,
    function_infos: &'a [FunctionInfo],
    has_call_relocations: bool,
    relocation_table: &'a RelocationTable,
    symbols: &'a [hexray_core::Symbol],
    noreturn_targets: &'a std::collections::HashSet<u64>,
}

#[cfg_attr(not(test), allow(dead_code))]
fn add_lifecycle_array_edges(
    callgraph: &mut CallGraph,
    fmt: &dyn BinaryFormat,
    symbols: &[hexray_core::Symbol],
) {
    let Some(entry) = fmt.entry_point() else {
        return;
    };

    let mut seen_edges = std::collections::HashSet::new();
    for (slot_addr, target) in discover_lifecycle_array_entries(fmt) {
        if !seen_edges.insert((entry, slot_addr, target)) {
            continue;
        }
        if let Some(symbol) = find_preferred_symbol_at(symbols, target) {
            callgraph.add_node(target, Some(symbol.name.clone()), false);
        } else {
            callgraph.add_node(target, None, false);
        }
        callgraph.add_call(
            entry,
            target,
            CallSite {
                call_address: slot_addr,
                call_type: CallType::Indirect,
            },
        );
    }
}

fn add_lifecycle_array_edges_for_binary(
    callgraph: &mut CallGraph,
    binary: &Binary,
    symbols: &[hexray_core::Symbol],
) {
    let fmt = binary.as_format();
    let Some(entry) = fmt.entry_point() else {
        return;
    };

    let mut seen_edges = std::collections::HashSet::new();
    for (slot_addr, target) in discover_lifecycle_array_entries_for_binary(binary) {
        if !seen_edges.insert((entry, slot_addr, target)) {
            continue;
        }
        if let Some(symbol) = find_preferred_symbol_at(symbols, target) {
            callgraph.add_node(target, Some(symbol.name.clone()), false);
        } else {
            callgraph.add_node(target, None, false);
        }
        callgraph.add_call(
            entry,
            target,
            CallSite {
                call_address: slot_addr,
                call_type: CallType::Indirect,
            },
        );
    }
}

fn add_materialized_callback_edges(
    callgraph: &mut CallGraph,
    ctx: MaterializedCallbackEdgeContext<'_>,
) {
    let disasm_x86 = X86_64Disassembler::new();
    let disasm_arm64 = Arm64Disassembler::new();
    let disasm_riscv = RiscVDisassembler::new();
    let disasm_riscv32 = RiscVDisassembler::new_rv32();
    let mut seen_edges = std::collections::HashSet::new();

    for func_info in ctx.function_infos {
        let mut instructions: Vec<hexray_core::Instruction> = match ctx.arch {
            Architecture::X86_64 | Architecture::X86 => disassemble_for_calls(
                &disasm_x86,
                &func_info.bytes,
                func_info.address,
                func_info.heuristic_bounds,
                ctx.noreturn_targets,
            ),
            Architecture::Arm64 => disassemble_for_calls(
                &disasm_arm64,
                &func_info.bytes,
                func_info.address,
                func_info.heuristic_bounds,
                ctx.noreturn_targets,
            ),
            Architecture::RiscV64 => disassemble_for_calls(
                &disasm_riscv,
                &func_info.bytes,
                func_info.address,
                func_info.heuristic_bounds,
                ctx.noreturn_targets,
            ),
            Architecture::RiscV32 => disassemble_for_calls(
                &disasm_riscv32,
                &func_info.bytes,
                func_info.address,
                func_info.heuristic_bounds,
                ctx.noreturn_targets,
            ),
            _ => Vec::new(),
        };
        if ctx.has_call_relocations {
            apply_call_relocations(&mut instructions, ctx.relocation_table);
        }

        for call in hexray_analysis::callgraph::discover_materialized_indirect_calls(&instructions)
        {
            for target in resolve_materialized_callback_targets(ctx.fmt, &call) {
                if !seen_edges.insert((func_info.address, call.call_address, target)) {
                    continue;
                }
                if let Some(symbol) = find_preferred_symbol_at(ctx.symbols, target) {
                    callgraph.add_node(target, Some(symbol.name.clone()), false);
                } else {
                    callgraph.add_node(target, None, false);
                }
                callgraph.add_call(
                    func_info.address,
                    target,
                    CallSite {
                        call_address: call.call_address,
                        call_type: CallType::Indirect,
                    },
                );
            }
        }
    }
}

fn build_callgraph(
    binary: &Binary,
    target: &str,
    dot: bool,
    json: bool,
    html: bool,
    project: Option<&AnalysisProject>,
) -> Result<()> {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);
    let has_call_relocations = relocation_table.call_relocations().len() > 0;
    let symbols = collect_analysis_symbols(binary, &relocation_table);
    let arch = fmt.architecture();
    let noreturn_targets: std::collections::HashSet<u64> = symbols
        .iter()
        .filter(|symbol| is_noreturn_function_name(&symbol.name))
        .map(|symbol| symbol.address)
        .collect();

    // Determine which functions to analyze (address, name, size, heuristic_bounds)
    // Note: Mach-O symbols don't have size info (nlist doesn't store it),
    // so we use a default size for symbols with size == 0
    let functions_to_analyze: Vec<(u64, String, u64, bool)> = if target == "all" {
        discover_function_starts(fmt, arch, &symbols)
            .into_iter()
            .map(|(addr, size, heuristic_bounds)| {
                let name = find_preferred_symbol_at(&symbols, addr)
                    .map(|s| demangle_or_original(&s.name))
                    .unwrap_or_else(|| {
                        if Some(addr) == fmt.entry_point() {
                            format!("_start_{addr:x}")
                        } else {
                            format!("sub_{addr:x}")
                        }
                    });
                (addr, name, size, heuristic_bounds)
            })
            .collect()
    } else {
        let (addr, name, size, heuristic_bounds) =
            match resolve_analysis_target_with_symbols(fmt, project, target, &symbols)? {
                ResolvedAnalysisTarget::Address(address) => (
                    address,
                    display_symbol_or_label_name_with_symbols(fmt, project, &symbols, address),
                    4096u64,
                    true,
                ),
                ResolvedAnalysisTarget::Symbol(symbol) => {
                    let size = if symbol.size > 0 { symbol.size } else { 4096 };
                    (
                        symbol.address,
                        display_symbol_or_label_name_with_symbols(
                            fmt,
                            project,
                            &symbols,
                            symbol.address,
                        ),
                        size,
                        symbol.size == 0,
                    )
                }
            };

        vec![(addr, name, size, heuristic_bounds)]
    };
    let target_root = if target == "all" {
        None
    } else {
        functions_to_analyze.first().map(|(addr, _, _, _)| *addr)
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
        functions_to_analyze.iter().map(|(a, _, _, _)| *a).collect();
    let mut pending_functions: Vec<(u64, String, u64, bool)> = functions_to_analyze.clone();
    let mut all_function_infos: Vec<FunctionInfo> = Vec::new();

    // Create disassembler once based on architecture
    let disasm_x86 = X86_64Disassembler::new();
    let disasm_arm64 = Arm64Disassembler::new();
    let disasm_riscv = RiscVDisassembler::new();
    let disasm_riscv32 = RiscVDisassembler::new_rv32();

    // Discover all reachable callees for targeted graphs; keep the bounded
    // best-effort discovery behavior for `all`.
    let mut iteration = 0usize;
    while !pending_functions.is_empty() {
        if target == "all" && iteration >= 3 {
            break;
        }
        iteration += 1;

        // Collect function info for current batch
        let function_infos: Vec<FunctionInfo> = pending_functions
            .iter()
            .filter_map(|(func_addr, _, func_size, heuristic_bounds)| {
                let size = if *heuristic_bounds {
                    (*func_size).max(64) as usize
                } else {
                    (*func_size).max(1) as usize
                };
                fmt.bytes_at(*func_addr, size).map(|bytes| FunctionInfo {
                    address: *func_addr,
                    size,
                    bytes: bytes.to_vec(),
                    heuristic_bounds: *heuristic_bounds,
                })
            })
            .collect();

        // Disassemble and find call targets
        let mut new_call_targets: Vec<(u64, String, u64, bool)> = Vec::new();
        for func_info in &function_infos {
            let mut instructions: Vec<hexray_core::Instruction> = match arch {
                Architecture::X86_64 | Architecture::X86 => disassemble_for_calls(
                    &disasm_x86,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::Arm64 => disassemble_for_calls(
                    &disasm_arm64,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::RiscV64 => disassemble_for_calls(
                    &disasm_riscv,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::RiscV32 => disassemble_for_calls(
                    &disasm_riscv32,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                _ => Vec::new(),
            };
            if has_call_relocations {
                apply_call_relocations(&mut instructions, &relocation_table);
            }

            // Extract call targets
            for instr in &instructions {
                if let hexray_core::ControlFlow::Call { target, .. } = &instr.control_flow {
                    if !known_functions.contains(target) && is_internal_code(*target) {
                        known_functions.insert(*target);
                        let (name, size, heuristic_bounds) =
                            find_preferred_symbol_at(&symbols, *target)
                                .map(|s| {
                                    let size = if s.size > 0 { s.size } else { 4096 };
                                    (demangle_or_original(&s.name), size, s.size == 0)
                                })
                                .unwrap_or_else(|| (format!("sub_{:x}", target), 4096, true));
                        new_call_targets.push((*target, name, size, heuristic_bounds));
                    }
                }
            }

            for target in discover_materialized_internal_targets(&instructions, fmt) {
                if !known_functions.contains(&target) && is_internal_code(target) {
                    known_functions.insert(target);
                    let (name, size, heuristic_bounds) = find_preferred_symbol_at(&symbols, target)
                        .map(|s| {
                            let size = if s.size > 0 { s.size } else { 4096 };
                            (demangle_or_original(&s.name), size, s.size == 0)
                        })
                        .unwrap_or_else(|| (format!("sub_{:x}", target), 4096, true));
                    new_call_targets.push((target, name, size, heuristic_bounds));
                }
            }
        }

        all_function_infos.extend(function_infos);
        pending_functions = new_call_targets;
    }

    // Build call graph using all discovered functions
    let mut callgraph = if has_call_relocations {
        let mut callgraph = CallGraph::new();
        for symbol in &symbols {
            if symbol.is_function() {
                callgraph.add_node(
                    symbol.address,
                    Some(symbol.name.clone()),
                    callgraph_symbol_is_external(symbol),
                );
            }
        }
        for func_info in &all_function_infos {
            let mut instructions: Vec<hexray_core::Instruction> = match arch {
                Architecture::X86_64 | Architecture::X86 => disassemble_for_calls(
                    &disasm_x86,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::Arm64 => disassemble_for_calls(
                    &disasm_arm64,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::RiscV64 => disassemble_for_calls(
                    &disasm_riscv,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                Architecture::RiscV32 => disassemble_for_calls(
                    &disasm_riscv32,
                    &func_info.bytes,
                    func_info.address,
                    func_info.heuristic_bounds,
                    &noreturn_targets,
                ),
                _ => Vec::new(),
            };
            apply_call_relocations(&mut instructions, &relocation_table);
            if find_preferred_symbol_at(&symbols, func_info.address).is_none() {
                callgraph.add_node(func_info.address, None, false);
            }
            for instruction in instructions {
                if let hexray_core::ControlFlow::Call { target, .. } = instruction.control_flow {
                    if let Some(symbol) = find_preferred_symbol_at(&symbols, target) {
                        if suppress_callgraph_edge_to_name(&symbol.name) {
                            continue;
                        }
                        callgraph.add_node(
                            target,
                            Some(symbol.name.clone()),
                            callgraph_symbol_is_external(symbol),
                        );
                    } else {
                        callgraph.add_node(target, None, false);
                    }
                    callgraph.add_call(
                        func_info.address,
                        target,
                        CallSite {
                            call_address: instruction.address,
                            call_type: CallType::Direct,
                        },
                    );
                }
            }
        }
        callgraph
    } else {
        match arch {
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
                let mut builder = CallGraphBuilder::new();
                builder.add_symbols(&symbols);
                builder.build()
            }
        }
    };
    add_materialized_callback_edges(
        &mut callgraph,
        MaterializedCallbackEdgeContext {
            fmt,
            arch,
            function_infos: &all_function_infos,
            has_call_relocations,
            relocation_table: &relocation_table,
            symbols: &symbols,
            noreturn_targets: &noreturn_targets,
        },
    );
    add_lifecycle_array_edges_for_binary(&mut callgraph, binary, &symbols);
    mark_callgraph_stub_nodes_external(&mut callgraph, fmt);
    let callgraph = if let Some(root) = target_root {
        callgraph.subgraph_from(root)
    } else {
        callgraph
    };
    let callgraph = apply_project_names_to_callgraph(callgraph, project);

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
        print!("{}", format_callgraph_text(&callgraph));
    }

    Ok(())
}

fn callgraph_node_display_name(node: &hexray_analysis::CallGraphNode) -> String {
    node.name
        .clone()
        .unwrap_or_else(|| format!("sub_{:x}", node.address))
}

fn callgraph_symbol_is_external(symbol: &hexray_core::Symbol) -> bool {
    !symbol.is_defined() || symbol.is_plt()
}

fn suppress_callgraph_edge_to_name(name: &str) -> bool {
    is_ubsan_handler_function_name(name)
}

fn mark_callgraph_stub_nodes_external(
    callgraph: &mut hexray_analysis::CallGraph,
    fmt: &dyn BinaryFormat,
) {
    let stub_ranges: Vec<_> = fmt
        .sections()
        .filter_map(|section| {
            if !section.is_executable() {
                return None;
            }

            let name = section.name().to_ascii_lowercase();
            if !(name.contains("plt") || name.contains("stub")) {
                return None;
            }

            Some((
                section.virtual_address(),
                section.virtual_address().saturating_add(section.size()),
            ))
        })
        .collect();

    let external_nodes: Vec<_> = callgraph
        .nodes()
        .filter(|node| {
            node.name
                .as_deref()
                .is_some_and(|name| name.ends_with("@plt"))
                || stub_ranges
                    .iter()
                    .any(|(start, end)| node.address >= *start && node.address < *end)
        })
        .map(|node| node.address)
        .collect();

    for address in external_nodes {
        callgraph.mark_node_external(address);
    }
}

fn apply_project_names_to_callgraph(
    callgraph: hexray_analysis::CallGraph,
    project: Option<&AnalysisProject>,
) -> hexray_analysis::CallGraph {
    let Some(project) = project else {
        return callgraph;
    };

    let mut renamed = hexray_analysis::CallGraph::new();
    for node in callgraph.nodes() {
        let name = project
            .get_function_name(node.address)
            .map(|name| name.to_string())
            .or_else(|| node.name.clone());
        renamed.add_node(node.address, name, node.is_external);
    }

    for node in callgraph.nodes() {
        for (callee, site) in callgraph.callees(node.address) {
            renamed.add_call(node.address, callee, site.clone());
        }
    }

    for &(caller, call_address) in callgraph.unresolved_calls() {
        renamed.add_unresolved_call(caller, call_address);
    }

    renamed
}

fn format_callgraph_text(callgraph: &hexray_analysis::CallGraph) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    writeln!(output, "Call Graph Analysis").unwrap();
    writeln!(output, "===================").unwrap();
    writeln!(output, "Functions: {}", callgraph.node_count()).unwrap();
    writeln!(output, "Call edges: {}", callgraph.edge_count()).unwrap();
    writeln!(output).unwrap();

    let mut nodes: Vec<_> = callgraph.nodes().collect();
    nodes.sort_by_key(|node| node.address);

    for node in nodes {
        let mut callees: std::collections::BTreeMap<u64, (String, usize)> =
            std::collections::BTreeMap::new();
        for (addr, _) in callgraph.callees(node.address) {
            let Some(callee) = callgraph.get_node(addr) else {
                continue;
            };
            let entry = callees
                .entry(callee.address)
                .or_insert_with(|| (callgraph_node_display_name(callee), 0));
            entry.1 += 1;
        }

        if !callees.is_empty() {
            writeln!(
                output,
                "{} ({:#x}):",
                callgraph_node_display_name(node),
                node.address
            )
            .unwrap();
            for (addr, (name, count)) in callees {
                if count > 1 {
                    writeln!(output, "  -> {} ({:#x}) [{}x]", name, addr, count).unwrap();
                } else {
                    writeln!(output, "  -> {} ({:#x})", name, addr).unwrap();
                }
            }
            writeln!(output).unwrap();
        }
    }

    output
}

fn truncate_for_display(content: &str, max_chars: usize) -> String {
    let char_count = content.chars().count();
    if char_count <= max_chars {
        return content.to_string();
    }

    if max_chars <= 3 {
        return ".".repeat(max_chars);
    }

    let prefix: String = content.chars().take(max_chars - 3).collect();
    format!("{prefix}...")
}

fn string_tags(s: &hexray_analysis::DetectedString) -> Vec<&'static str> {
    let mut tags = Vec::new();
    if s.is_path() {
        tags.push("PATH");
    }
    if s.is_url() {
        tags.push("URL");
    }
    if s.is_error_message() {
        tags.push("ERROR");
    }
    tags
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
            let tags = string_tags(s);
            let tags_json = tags
                .iter()
                .map(|tag| format!("\"{tag}\""))
                .collect::<Vec<_>>()
                .join(", ");

            let comma = if i < all_strings.len() - 1 { "," } else { "" };
            println!("    {{");
            println!("      \"address\": \"{:#x}\",", s.address);
            println!("      \"length\": {},", s.length);
            println!("      \"encoding\": \"{:?}\",", s.encoding);
            println!("      \"content\": \"{}\",", escaped_content);
            println!("      \"tags\": [{}]", tags_json);
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

            // Truncate very long strings without slicing through a UTF-8 codepoint.
            let display_content = truncate_for_display(&s.content, 80);
            let indicators = string_tags(s);

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
#[allow(clippy::too_many_arguments)]
fn decompile_with_follow(
    binary_path: &Path,
    binary: &Binary,
    target: &str,
    show_addresses: bool,
    max_depth: usize,
    diagnostics: bool,
    project: Option<&AnalysisProject>,
    type_db: Option<&std::sync::Arc<TypeDatabase>>,
    config: Option<&DecompilerConfig>,
) -> Result<()> {
    use std::collections::HashSet;

    let fmt = binary.as_format();
    let arch = fmt.architecture();
    let relocation_table = build_relocation_table(binary);

    // Track which functions we've already decompiled to avoid duplicates
    let mut decompiled: HashSet<u64> = HashSet::new();

    // Queue of (address, name, depth) to decompile
    let mut queue: Vec<(u64, String, usize)> = Vec::new();

    let DecompileTargetInfo {
        start_addr, name, ..
    } = resolve_decompile_target_info(fmt, project, target, &relocation_table)?;

    queue.push((start_addr, name, 0));

    // Build tables once for all decompilations
    let string_table = build_string_table(fmt);
    let mut symbol_table = build_symbol_table(binary);
    // Merge project function names into symbol table
    if let Some(proj) = project {
        for addr in proj.overridden_functions() {
            if let Some(name) = proj.get_function_name(addr) {
                symbol_table.insert(addr, name.to_string());
            }
        }
    }
    let throw_thunks = collect_throw_thunks(binary, &symbol_table, &relocation_table);
    let binary_data_ctx = build_binary_data_context(fmt);
    let tls_access_targets = build_tls_access_targets(binary);
    let tls_slot_map = build_tls_slot_map(binary);

    // Create constant database for magic number recognition
    let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());

    // Try to load DWARF debug info once
    let debug_info = load_dwarf_info(binary_path, binary);

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
        let DecompileTargetInfo {
            max_bytes,
            stop_after_first_return,
            ..
        } = decompile_target_info_for_address(fmt, project, func_addr);

        let bytes = match fmt.bytes_at(func_addr, max_bytes) {
            Some(b) => b,
            None => continue,
        };

        let mut instructions = match arch {
            Architecture::X86_64 | Architecture::X86 => {
                let disasm = X86_64Disassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, func_addr, stop_after_first_return)
            }
            Architecture::Arm64 => {
                let disasm = Arm64Disassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, func_addr, stop_after_first_return)
            }
            Architecture::RiscV64 => {
                let disasm = RiscVDisassembler::new();
                disassemble_for_cfg(&disasm, fmt, bytes, func_addr, stop_after_first_return)
            }
            Architecture::RiscV32 => {
                let disasm = RiscVDisassembler::new_rv32();
                disassemble_for_cfg(&disasm, fmt, bytes, func_addr, stop_after_first_return)
            }
            _ => continue,
        };
        apply_instruction_relocations(&mut instructions, &relocation_table);
        crate::rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);

        // Build CFG
        let cfg = CfgBuilder::build_with_binary_context(&instructions, func_addr, &binary_data_ctx);

        // Get DWARF variable and parameter names for this function.
        let dwarf_names = if let Some(ref di) = debug_info {
            get_dwarf_function_names(di, func_addr, binary)
        } else {
            DwarfFunctionNames::default()
        };

        // Decompile
        let calling_convention = default_calling_convention(
            match binary {
                Binary::Elf(_) => BinaryType::Elf,
                Binary::MachO(_) => BinaryType::MachO,
                Binary::Pe(_) => BinaryType::Pe,
            },
            arch,
        );
        let mut decompiler = Decompiler::new()
            .with_addresses(show_addresses)
            .with_string_table(string_table.clone())
            .with_symbol_table(symbol_table.clone())
            .with_relocation_table(relocation_table.clone())
            .with_throw_thunks(throw_thunks.clone())
            .with_dwarf_names(dwarf_names.stack_names)
            .with_dwarf_param_names(dwarf_names.parameter_names)
            .with_dwarf_scope_ranges(dwarf_names.local_scope_ranges)
            .with_constant_database(const_db.clone())
            .with_struct_inference(true)
            .with_calling_convention(calling_convention);
        decompiler = decompiler.analyze_cpp_special(&cfg, &instructions, Some(&func_name));
        if let Some(info) = binary.exception_info_for_function(func_addr, func_addr) {
            decompiler = decompiler.with_exception_info(info);
        }
        if let Some(db) = type_db {
            decompiler = decompiler.with_type_database(db.clone());
        }
        if let Some(cfg_opts) = config {
            decompiler = decompiler.with_config(cfg_opts.clone());
        }
        if diagnostics {
            let signature = decompiler.recover_signature(&cfg);
            print_signature_diagnostics(&func_name, &signature);
        }
        let pseudocode = annotate_pseudocode_with_project_comments(
            decompiler.decompile(&cfg, &func_name),
            project,
            show_addresses,
        );

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

fn print_signature_diagnostics(name: &str, signature: &hexray_analysis::FunctionSignature) {
    let mut printed_any = false;
    for (idx, param) in signature.parameters.iter().enumerate() {
        if !matches!(
            param.param_type,
            hexray_analysis::ParamType::FunctionPointer { .. }
        ) {
            continue;
        }
        printed_any = true;
        println!(
            "// [diag] {} param {} '{}' inferred as {}",
            name,
            idx,
            param.name,
            param.param_type.to_c_string()
        );
        if let Some(reasons) = signature.parameter_provenance.get(&idx) {
            for reason in reasons {
                println!("// [diag]   - {}", reason);
            }
        } else {
            println!("// [diag]   - no explicit provenance recorded");
        }
    }
    if !printed_any {
        println!(
            "// [diag] {}: no function-pointer parameters inferred",
            name
        );
    }
    if signature.has_return {
        println!(
            "// [diag] {} return inferred as {} (confidence {})",
            name,
            signature.return_type.to_c_string(),
            signature.return_confidence
        );
        if signature.return_provenance.is_empty() {
            println!("// [diag]   - no explicit return provenance recorded");
        } else {
            for reason in &signature.return_provenance {
                println!("// [diag]   - {}", reason);
            }
        }
    } else {
        println!("// [diag] {} return inferred as void", name);
    }
    println!();
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

/// Build a DecompilerConfig from CLI options.
fn build_decompiler_config(
    opt_level: &str,
    enable_passes: &[String],
    disable_passes: &[String],
) -> Result<DecompilerConfig> {
    // Parse optimization level
    let level = match opt_level {
        "0" | "none" => OptimizationLevel::None,
        "1" | "basic" => OptimizationLevel::Basic,
        "2" | "standard" => OptimizationLevel::Standard,
        "3" | "aggressive" => OptimizationLevel::Aggressive,
        other => bail!(
            "Invalid optimization level '{}'. Use: 0/none, 1/basic, 2/standard, 3/aggressive",
            other
        ),
    };

    let mut config = DecompilerConfig::new(level);

    // Apply enabled passes
    for pass_name in enable_passes {
        let pass = parse_pass_name(pass_name)?;
        config = config.enable_pass(pass);
    }

    // Apply disabled passes
    for pass_name in disable_passes {
        let pass = parse_pass_name(pass_name)?;
        config = config.disable_pass(pass);
    }

    Ok(config)
}

/// Parse a pass name string into an OptimizationPass.
fn parse_pass_name(name: &str) -> Result<OptimizationPass> {
    match name.to_lowercase().as_str() {
        "call-arg-propagation" | "call_arg_propagation" => Ok(OptimizationPass::CallArgPropagation),
        "return-value-merge" | "return_value_merge" => Ok(OptimizationPass::ReturnValueMerge),
        "temp-simplification" | "temp_simplification" => Ok(OptimizationPass::TempSimplification),
        "for-loop-detection" | "for_loop_detection" => Ok(OptimizationPass::ForLoopDetection),
        "loop-invariant-hoisting" | "loop_invariant_hoisting" => {
            Ok(OptimizationPass::LoopInvariantHoisting)
        }
        "loop-pattern-detection" | "loop_pattern_detection" => {
            Ok(OptimizationPass::LoopPatternDetection)
        }
        "switch-detection" | "switch_detection" => Ok(OptimizationPass::SwitchDetection),
        "short-circuit-detection" | "short_circuit_detection" => {
            Ok(OptimizationPass::ShortCircuitDetection)
        }
        "goto-conversion" | "goto_conversion" => Ok(OptimizationPass::GotoConversion),
        "guard-clause-flattening" | "guard_clause_flattening" => {
            Ok(OptimizationPass::GuardClauseFlattening)
        }
        "expression-simplification" | "expression_simplification" => {
            Ok(OptimizationPass::ExpressionSimplification)
        }
        "string-pattern-detection" | "string_pattern_detection" => {
            Ok(OptimizationPass::StringPatternDetection)
        }
        "arch-pattern-simplification" | "arch_pattern_simplification" => {
            Ok(OptimizationPass::ArchPatternSimplification)
        }
        "dead-store-elimination" | "dead_store_elimination" => {
            Ok(OptimizationPass::DeadStoreElimination)
        }
        "linked-list-detection" | "linked_list_detection" => {
            Ok(OptimizationPass::LinkedListDetection)
        }
        "variable-naming" | "variable_naming" => Ok(OptimizationPass::VariableNaming),
        "loop-canonicalization" | "loop_canonicalization" => {
            Ok(OptimizationPass::LoopCanonicalization)
        }
        "memset-idiom-detection" | "memset_idiom_detection" => {
            Ok(OptimizationPass::MemsetIdiomDetection)
        }
        "constant-propagation" | "constant_propagation" => {
            Ok(OptimizationPass::ConstantPropagation)
        }
        "type-inference" | "type_inference" => Ok(OptimizationPass::TypeInference),
        "switch-recovery" | "switch_recovery" => Ok(OptimizationPass::SwitchRecovery),
        other => bail!(
            "Unknown optimization pass '{}'. Use --list-passes to see available passes.",
            other
        ),
    }
}

/// Print available optimization passes.
fn print_optimization_passes() {
    println!("Available optimization passes:\n");
    println!("  Control Flow:");
    println!("    for-loop-detection          - Detect for loop patterns");
    println!("    loop-invariant-hoisting     - Hoist invariant expressions out of loops");
    println!("    loop-pattern-detection      - Detect common loop patterns");
    println!("    loop-canonicalization       - Convert do-while to while loops");
    println!("    switch-detection            - Detect switch statement patterns");
    println!("    switch-recovery             - Recover switch tables");
    println!("    short-circuit-detection     - Detect && and || expressions");
    println!("    goto-conversion             - Convert gotos to structured control flow");
    println!("    guard-clause-flattening     - Flatten guard clause patterns");
    println!();
    println!("  Expression:");
    println!("    expression-simplification   - Simplify complex expressions");
    println!("    constant-propagation        - Propagate and fold constants");
    println!("    call-arg-propagation        - Propagate arguments to call sites");
    println!("    return-value-merge          - Merge return value assignments");
    println!("    temp-simplification         - Simplify temporary variables");
    println!();
    println!("  Pattern Recognition:");
    println!("    string-pattern-detection    - Detect string operations (strlen, strcmp, etc.)");
    println!("    arch-pattern-simplification - Simplify architecture-specific patterns");
    println!("    memset-idiom-detection      - Detect memset/array initialization loops");
    println!("    linked-list-detection       - Detect linked list traversal patterns");
    println!();
    println!("  Analysis:");
    println!("    dead-store-elimination      - Remove dead stores");
    println!("    variable-naming             - Improve variable names from usage");
    println!("    type-inference              - Infer variable types");
    println!();
    println!("Optimization levels:");
    println!("    0/none       - No optimizations");
    println!("    1/basic      - Basic simplifications only");
    println!("    2/standard   - Default: all standard passes (recommended)");
    println!("    3/aggressive - Include experimental passes");
    println!();
    println!("Examples:");
    println!("    hexray decompile main -O0                    # No optimizations");
    println!("    hexray decompile main -O3                    # Aggressive optimizations");
    println!("    hexray decompile main --disable-pass goto-conversion");
    println!("    hexray decompile main -O1 --enable-pass constant-propagation");
}

fn build_xrefs(
    binary: &Binary,
    target: Option<&str>,
    calls_only: bool,
    json: bool,
    project: Option<&AnalysisProject>,
) -> Result<()> {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);
    let arch = fmt.architecture();
    let symbols = collect_analysis_symbols(binary, &relocation_table);
    let noreturn_targets: std::collections::HashSet<u64> = symbols
        .iter()
        .filter(|s| is_noreturn_function_name(&s.name))
        .map(|s| s.address)
        .collect();
    let tls_access_targets = build_tls_access_targets(binary);
    let tls_slot_map = build_tls_slot_map(binary);

    // Build xref database by disassembling all functions
    let mut xref_builder = XrefBuilder::new();

    // Start from the same function-start seeds used by `callgraph all`, then
    // also walk discovered internal callees so stripped callers still
    // contribute xrefs.
    let functions_to_analyze = discover_function_starts(fmt, arch, &symbols);

    let is_internal_code = |addr: u64| -> bool {
        fmt.executable_sections().any(|sec| {
            let sec_start = sec.virtual_address();
            let sec_end = sec_start + sec.size();
            let sec_name = sec.name();
            addr >= sec_start && addr < sec_end && !sec_name.contains("stub")
        })
    };

    let mut known_functions: std::collections::HashSet<u64> = functions_to_analyze
        .iter()
        .map(|(addr, _, _)| *addr)
        .collect();

    let disasm_x86 = X86_64Disassembler::new();
    let disasm_arm64 = Arm64Disassembler::new();
    let disasm_riscv = RiscVDisassembler::new();
    let disasm_riscv32 = RiscVDisassembler::new_rv32();

    let mut pending_functions = functions_to_analyze;
    for _iteration in 0..3 {
        if pending_functions.is_empty() {
            break;
        }

        let mut new_call_targets = Vec::new();
        for (address, size, heuristic_bounds) in &pending_functions {
            let size = if *heuristic_bounds {
                (*size).max(64) as usize
            } else {
                (*size).max(1) as usize
            };
            if let Some(bytes) = fmt.bytes_at(*address, size) {
                let mut instructions = match arch {
                    Architecture::X86_64 | Architecture::X86 => disassemble_for_calls(
                        &disasm_x86,
                        bytes,
                        *address,
                        *heuristic_bounds,
                        &noreturn_targets,
                    ),
                    Architecture::Arm64 => disassemble_for_calls(
                        &disasm_arm64,
                        bytes,
                        *address,
                        *heuristic_bounds,
                        &noreturn_targets,
                    ),
                    Architecture::RiscV64 => disassemble_for_calls(
                        &disasm_riscv,
                        bytes,
                        *address,
                        *heuristic_bounds,
                        &noreturn_targets,
                    ),
                    Architecture::RiscV32 => disassemble_for_calls(
                        &disasm_riscv32,
                        bytes,
                        *address,
                        *heuristic_bounds,
                        &noreturn_targets,
                    ),
                    _ => Vec::new(),
                };
                apply_call_relocations(&mut instructions, &relocation_table);
                rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);
                xref_builder.analyze_instructions(&instructions);

                for instr in instructions {
                    if let hexray_core::ControlFlow::Call { target, .. } = instr.control_flow {
                        if known_functions.insert(target) && is_internal_code(target) {
                            let (size, heuristic_bounds) =
                                find_preferred_symbol_at(&symbols, target)
                                    .map(|s| (if s.size > 0 { s.size } else { 4096 }, s.size == 0))
                                    .unwrap_or((4096, true));
                            new_call_targets.push((target, size, heuristic_bounds));
                        }
                    }
                }
            }
        }

        pending_functions = new_call_targets;
    }

    let mut db = xref_builder.build();
    add_exception_section_xrefs(fmt, &mut db);
    for (slot_addr, target) in discover_lifecycle_array_entries_for_binary(binary) {
        db.add_xref(slot_addr, target, XrefType::DataRead);
    }

    // If a target is specified, show refs to that target
    if let Some(target_str) = target {
        let target_addrs = resolve_xref_target_addresses(
            fmt,
            project,
            target_str,
            &symbols,
            &relocation_table,
            &db,
            calls_only,
        )?;
        let resolved_targets: Vec<_> = target_addrs
            .iter()
            .map(|addr| {
                (
                    *addr,
                    display_symbol_or_label_name_with_symbols(fmt, project, &symbols, *addr),
                )
            })
            .collect();
        let target_name = if resolved_targets.len() == 1 {
            resolved_targets[0].1.clone()
        } else {
            target_str.to_string()
        };
        let mut refs = Vec::new();
        let mut seen_refs = std::collections::HashSet::new();
        for target_addr in &target_addrs {
            for query_addr in
                xref_query_target_addresses(fmt, &symbols, &relocation_table, *target_addr)
            {
                let target_refs: Vec<_> = if calls_only {
                    db.call_refs_to(query_addr).into_iter().cloned().collect()
                } else {
                    db.refs_to(query_addr).to_vec()
                };
                for xref in target_refs {
                    if seen_refs.insert((xref.from, xref.to, xref.xref_type)) {
                        refs.push(xref);
                    }
                }
            }
        }
        refs.sort_by(|left, right| {
            left.from
                .cmp(&right.from)
                .then_with(|| left.to.cmp(&right.to))
                .then_with(|| {
                    let left_rank = match left.xref_type {
                        XrefType::Call => 0u8,
                        XrefType::Jump => 1u8,
                        XrefType::DataRead => 2u8,
                        XrefType::DataWrite => 3u8,
                        XrefType::DataAddress => 4u8,
                        XrefType::Unknown => 5u8,
                    };
                    let right_rank = match right.xref_type {
                        XrefType::Call => 0u8,
                        XrefType::Jump => 1u8,
                        XrefType::DataRead => 2u8,
                        XrefType::DataWrite => 3u8,
                        XrefType::DataAddress => 4u8,
                        XrefType::Unknown => 5u8,
                    };
                    left_rank.cmp(&right_rank)
                })
        });

        // Function-start lookup table: sorted by address. For any call-site
        // address we use partition_point to find the nearest preceding
        // function start so xrefs report "<caller> + 0xN" instead of
        // sub_<call-site-addr>. Start with the same recovered seeds as
        // `callgraph all`, then add xref-discovered call targets so Mach-O
        // callers without symbols still get a stable function label.
        // Mach-O image-anchor symbols (__mh_execute_header etc.) are not
        // real functions and would otherwise dominate the lookup, so we
        // exclude anything starting with __mh_.
        let mut function_starts: Vec<(u64, Option<String>, u64)> =
            discover_function_starts(fmt, arch, &symbols)
                .into_iter()
                .filter_map(|(addr, size, _)| {
                    let symbol = fmt.symbol_at(addr);
                    if symbol.is_some_and(|s| s.name.starts_with("__mh_")) {
                        None
                    } else {
                        let lookup_size = symbol.map(|s| s.size).unwrap_or(size);
                        Some((
                            addr,
                            Some(display_symbol_or_label_name_with_symbols(
                                fmt, project, &symbols, addr,
                            )),
                            lookup_size,
                        ))
                    }
                })
                .collect();
        let mut seen: std::collections::HashSet<u64> =
            function_starts.iter().map(|(a, _, _)| *a).collect();
        for target in db.all_referenced() {
            // Only call targets are function starts. Jump and data refs
            // would otherwise pollute the lookup table with basic-block
            // heads and global symbols.
            if db.call_refs_to(target).is_empty() {
                continue;
            }
            if seen.insert(target) {
                let name = if fmt
                    .symbol_at(target)
                    .is_some_and(|s| s.name.starts_with("__mh_"))
                {
                    None
                } else {
                    Some(display_symbol_or_label_name_with_symbols(
                        fmt, project, &symbols, target,
                    ))
                };
                function_starts.push((target, name, 0));
            }
        }
        if let Some(entry) = fmt.entry_point() {
            if seen.insert(entry) {
                function_starts.push((
                    entry,
                    Some(display_symbol_or_label_name_with_symbols(
                        fmt, project, &symbols, entry,
                    )),
                    0,
                ));
            }
        }
        function_starts.sort_by_key(|(addr, _, _)| *addr);

        let resolve_caller = |from: u64| -> (String, Option<u64>) {
            resolve_xref_source_label(fmt, project, &function_starts, from)
        };

        if json {
            println!("{{");
            println!("  \"target_query\": \"{}\",", target_str);
            if resolved_targets.len() == 1 {
                println!("  \"target\": \"{:#x}\",", resolved_targets[0].0);
                println!("  \"target_name\": \"{}\",", target_name);
            } else {
                println!("  \"targets\": [");
                for (index, (addr, name)) in resolved_targets.iter().enumerate() {
                    let comma = if index + 1 < resolved_targets.len() {
                        ","
                    } else {
                        ""
                    };
                    println!(
                        "    {{ \"address\": \"{:#x}\", \"name\": \"{}\" }}{}",
                        addr, name, comma
                    );
                }
                println!("  ],");
            }
            println!("  \"references\": [");
            for (i, xref) in refs.iter().enumerate() {
                let (from_name, from_offset) = resolve_caller(xref.from);
                let comma = if i < refs.len() - 1 { "," } else { "" };
                println!("    {{");
                println!("      \"from\": \"{:#x}\",", xref.from);
                println!("      \"from_name\": \"{}\",", from_name);
                if let Some(off) = from_offset {
                    println!("      \"from_offset\": \"{:#x}\",", off);
                }
                println!("      \"type\": \"{:?}\"", xref.xref_type);
                println!("    }}{}", comma);
            }
            println!("  ],");
            println!("  \"count\": {}", refs.len());
            println!("}}");
        } else {
            if resolved_targets.len() == 1 {
                println!(
                    "Cross-references to {} ({:#x})",
                    target_name, resolved_targets[0].0
                );
            } else {
                println!(
                    "Cross-references to {} ({} targets)",
                    target_name,
                    resolved_targets.len()
                );
            }
            println!("{}", "=".repeat(50));
            println!();
            if resolved_targets.len() > 1 {
                println!("Resolved targets:");
                for (addr, name) in &resolved_targets {
                    println!("{:#016x} {}", addr, name);
                }
                println!();
            }

            if refs.is_empty() {
                println!("No references found.");
            } else {
                for xref in &refs {
                    let (from_name, from_offset) = resolve_caller(xref.from);
                    let type_str = match xref.xref_type {
                        XrefType::Call => "CALL",
                        XrefType::Jump => "JUMP",
                        XrefType::DataRead => "READ",
                        XrefType::DataWrite => "WRITE",
                        XrefType::DataAddress => "ADDR",
                        XrefType::Unknown => "???",
                    };
                    let caller_label = match from_offset {
                        Some(0) => from_name,
                        Some(off) => format!("{} + {:#x}", from_name, off),
                        None => from_name,
                    };
                    println!("{:#016x} {} from {}", xref.from, type_str, caller_label);
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
fn handle_project_command(binary_path: Option<&Path>, action: ProjectAction) -> Result<()> {
    match action {
        ProjectAction::Create { output } => {
            let binary_path = binary_path.ok_or_else(|| {
                anyhow::anyhow!(
                    "Binary file path is required for project create. Usage: hexray <BINARY> project create --output <PROJECT>"
                )
            })?;

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

            validate_project_address(
                &project.binary_path,
                address,
                ProjectAddressRule::ExecutableOrData,
            )?;
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

            validate_project_address(
                &project.binary_path,
                address,
                ProjectAddressRule::Executable,
            )?;
            validate_project_function_name(&name)?;
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

            validate_project_address(
                &project.binary_path,
                address,
                ProjectAddressRule::AnySection,
            )?;
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

            validate_project_address(
                &project.binary_path,
                address,
                ProjectAddressRule::ExecutableOrData,
            )?;
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

            if show_all {
                println!("Labels");
                println!("{}", "-".repeat(40));
                let mut count = 0;
                for addr in project.annotated_addresses() {
                    if let Some(label) = project.get_label(addr) {
                        println!("{:#016x}: {}", addr, label);
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
    }

    Ok(())
}

// =============================================================================
// Diff Command Handler
// =============================================================================

/// JSON output for diff command
#[derive(Serialize)]
struct JsonDiffOutput {
    original: String,
    modified: String,
    stats: JsonDiffStats,
    patches: Vec<JsonPatch>,
    affected_functions: Vec<JsonAffectedFunction>,
}

#[derive(Serialize)]
struct JsonDiffStats {
    changed_regions: usize,
    bytes_changed: usize,
    bytes_inserted: usize,
    bytes_deleted: usize,
    similarity_ratio: f64,
}

#[derive(Serialize)]
struct JsonPatch {
    address: String,
    old_size: usize,
    new_size: usize,
    patch_type: String,
}

#[derive(Serialize)]
struct JsonAffectedFunction {
    address: String,
    name: String,
    size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileAddressRange {
    file_start: u64,
    file_end: u64,
    va_start: u64,
}

enum DiffPatchAddressSpace {
    FileOffsets(Vec<FileAddressRange>),
    VirtualAddresses,
}

fn build_diff_patch_address_space(binary: &Binary<'_>) -> DiffPatchAddressSpace {
    const ELF_PT_LOAD: u32 = 1;

    match binary {
        Binary::Elf(elf) => {
            let mut ranges = Vec::new();

            ranges.extend(
                elf.segments
                    .iter()
                    .filter(|segment| segment.p_type == ELF_PT_LOAD && segment.p_filesz > 0)
                    .map(|segment| FileAddressRange {
                        file_start: segment.p_offset,
                        file_end: segment.p_offset.saturating_add(segment.p_filesz),
                        va_start: segment.p_vaddr,
                    }),
            );

            ranges.extend(
                elf.sections
                    .iter()
                    .filter(|section| section.sh_size > 0)
                    .map(|section| FileAddressRange {
                        file_start: section.sh_offset,
                        file_end: section.sh_offset.saturating_add(section.sh_size),
                        va_start: section.virtual_address(),
                    }),
            );

            if ranges.is_empty() {
                DiffPatchAddressSpace::VirtualAddresses
            } else {
                DiffPatchAddressSpace::FileOffsets(ranges)
            }
        }
        Binary::MachO(macho) if !macho.is_fat_slice() => {
            let mut ranges: Vec<FileAddressRange> = macho
                .segments
                .iter()
                .filter(|segment| segment.filesize > 0)
                .map(|segment| FileAddressRange {
                    file_start: segment.fileoff,
                    file_end: segment.fileoff.saturating_add(segment.filesize),
                    va_start: segment.vmaddr,
                })
                .collect();

            ranges.extend(
                macho
                    .segments
                    .iter()
                    .flat_map(|segment| segment.sections.iter())
                    .filter(|section| section.size > 0)
                    .map(|section| FileAddressRange {
                        file_start: section.offset as u64,
                        file_end: (section.offset as u64).saturating_add(section.size),
                        va_start: section.addr,
                    }),
            );

            if ranges.is_empty() {
                DiffPatchAddressSpace::VirtualAddresses
            } else {
                DiffPatchAddressSpace::FileOffsets(ranges)
            }
        }
        Binary::Pe(pe) => {
            let ranges: Vec<FileAddressRange> = pe
                .sections
                .iter()
                .filter(|section| section.size_of_raw_data > 0)
                .map(|section| FileAddressRange {
                    file_start: section.pointer_to_raw_data as u64,
                    file_end: (section.pointer_to_raw_data as u64)
                        .saturating_add(section.size_of_raw_data as u64),
                    va_start: section.virtual_address(),
                })
                .collect();
            if ranges.is_empty() {
                DiffPatchAddressSpace::VirtualAddresses
            } else {
                DiffPatchAddressSpace::FileOffsets(ranges)
            }
        }
        Binary::MachO(_) => DiffPatchAddressSpace::VirtualAddresses,
    }
}

fn translate_patch_offset(ranges: &[FileAddressRange], offset: u64) -> Option<u64> {
    ranges.iter().find_map(|range| {
        if offset < range.file_start || offset >= range.file_end {
            return None;
        }
        Some(
            range
                .va_start
                .saturating_add(offset.saturating_sub(range.file_start)),
        )
    })
}

fn translated_patch_overlaps_function(
    ranges: &[FileAddressRange],
    patch: &Patch,
    func_start: u64,
    func_end: u64,
) -> bool {
    if patch.old_bytes.is_empty() {
        return translate_patch_offset(ranges, patch.address)
            .is_some_and(|va| va >= func_start && va < func_end);
    }

    let patch_end = patch.address.saturating_add(patch.old_bytes.len() as u64);
    ranges.iter().any(|range| {
        let overlap_start = patch.address.max(range.file_start);
        let overlap_end = patch_end.min(range.file_end);
        if overlap_start >= overlap_end {
            return false;
        }

        let va_start = range
            .va_start
            .saturating_add(overlap_start.saturating_sub(range.file_start));
        let va_end = va_start.saturating_add(overlap_end.saturating_sub(overlap_start));
        va_start < func_end && va_end > func_start
    })
}

fn patch_affects_function(
    address_space: &DiffPatchAddressSpace,
    patch: &Patch,
    func_start: u64,
    func_end: u64,
) -> bool {
    match address_space {
        DiffPatchAddressSpace::FileOffsets(ranges) => {
            translated_patch_overlaps_function(ranges, patch, func_start, func_end)
        }
        DiffPatchAddressSpace::VirtualAddresses => patch.affects_range(func_start, func_end),
    }
}

fn handle_diff_command(
    original_path: &Path,
    modified_path: &Path,
    json: bool,
    verbose: bool,
) -> Result<()> {
    // Read both binaries
    let original_data = fs::read(original_path).with_context(|| {
        format!(
            "Failed to read original binary: {}",
            original_path.display()
        )
    })?;
    let modified_data = fs::read(modified_path).with_context(|| {
        format!(
            "Failed to read modified binary: {}",
            modified_path.display()
        )
    })?;

    // Compute the diff
    let diff = BinaryDiff::compute(&original_data, &modified_data);

    // Parse the original binary to find function symbols
    let original_binary = match detect_format(&original_data) {
        BinaryType::Elf => {
            let elf = Elf::parse(&original_data).context("Failed to parse original as ELF")?;
            Binary::Elf(elf)
        }
        BinaryType::MachO => {
            let macho =
                MachO::parse(&original_data).context("Failed to parse original as Mach-O")?;
            Binary::MachO(macho)
        }
        BinaryType::Pe => {
            let pe = Pe::parse(&original_data).context("Failed to parse original as PE")?;
            Binary::Pe(pe)
        }
        BinaryType::Unknown => {
            bail!("Unknown binary format for original file");
        }
    };

    let fmt = original_binary.as_format();
    let patch_address_space = build_diff_patch_address_space(&original_binary);

    // Find functions affected by the patches
    let mut affected_functions: Vec<(u64, String, u64)> = Vec::new();
    for sym in fmt.symbols() {
        if !sym.is_function() || sym.address == 0 || sym.size == 0 {
            continue;
        }
        let func_start = sym.address;
        let func_end = sym.address + sym.size;

        // Check if any patch overlaps with this function
        if diff
            .patches
            .patches
            .iter()
            .any(|patch| patch_affects_function(&patch_address_space, patch, func_start, func_end))
        {
            let name = demangle_or_original(&sym.name);
            affected_functions.push((sym.address, name, sym.size));
        }
    }

    // Sort by address
    affected_functions.sort_by_key(|(addr, _, _)| *addr);

    if json {
        let output = JsonDiffOutput {
            original: original_path.display().to_string(),
            modified: modified_path.display().to_string(),
            stats: JsonDiffStats {
                changed_regions: diff.stats.changed_regions,
                bytes_changed: diff.stats.bytes_changed,
                bytes_inserted: diff.stats.bytes_inserted,
                bytes_deleted: diff.stats.bytes_deleted,
                similarity_ratio: diff.stats.similarity,
            },
            patches: diff
                .patches
                .patches
                .iter()
                .map(|p| JsonPatch {
                    address: format!("{:#x}", p.address),
                    old_size: p.old_bytes.len(),
                    new_size: p.new_bytes.len(),
                    patch_type: match p.patch_type {
                        PatchType::Insertion => "insertion".to_string(),
                        PatchType::Deletion => "deletion".to_string(),
                        PatchType::Replacement => "replacement".to_string(),
                        PatchType::SizeChange => "size_change".to_string(),
                    },
                })
                .collect(),
            affected_functions: affected_functions
                .iter()
                .map(|(addr, name, size)| JsonAffectedFunction {
                    address: format!("{:#x}", addr),
                    name: name.clone(),
                    size: *size as usize,
                })
                .collect(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("Binary Diff Analysis");
        println!("====================");
        println!("Original: {}", original_path.display());
        println!("Modified: {}", modified_path.display());
        println!();
        println!("Statistics:");
        println!("  Changed regions:  {}", diff.stats.changed_regions);
        println!("  Bytes changed:    {}", diff.stats.bytes_changed);
        println!("  Bytes inserted:   {}", diff.stats.bytes_inserted);
        println!("  Bytes deleted:    {}", diff.stats.bytes_deleted);
        println!("  Similarity:       {:.1}%", diff.stats.similarity * 100.0);
        println!();

        if verbose && !diff.patches.is_empty() {
            println!("Patches ({}):", diff.patches.len());
            println!("{}", "-".repeat(60));
            for patch in &diff.patches.patches {
                let type_str = match patch.patch_type {
                    PatchType::Insertion => "INSERT",
                    PatchType::Deletion => "DELETE",
                    PatchType::Replacement => "REPLACE",
                    PatchType::SizeChange => "RESIZE",
                };
                println!(
                    "  {:#010x}: {} ({} -> {} bytes)",
                    patch.address,
                    type_str,
                    patch.old_bytes.len(),
                    patch.new_bytes.len()
                );
            }
            println!();
        }

        if affected_functions.is_empty() {
            println!("No function symbols affected by the changes.");
            println!(
                "(Note: changes may affect code not covered by symbols, or the binary may be stripped)"
            );
        } else {
            println!("Affected Functions ({}):", affected_functions.len());
            println!("{}", "-".repeat(60));
            println!("{:<18} {:<8} Name", "Address", "Size");
            for (addr, name, size) in &affected_functions {
                println!("{:#018x} {:<8} {}", addr, size, name);
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

const SESSION_EXPORT_FORMATS: &[&str] = &["text", "json"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionExportFormat {
    Text,
    Json,
}

impl SessionExportFormat {
    fn parse(format: &str) -> Result<Self> {
        match format {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            _ => bail!(
                "format '{}' not supported; valid: {}",
                format,
                SESSION_EXPORT_FORMATS.join(", ")
            ),
        }
    }
}

fn canonicalize_output_path(path: &Path) -> Result<PathBuf> {
    match path.canonicalize() {
        Ok(path) => Ok(path),
        Err(_) if !path.exists() => {
            let parent = path.parent().unwrap_or(Path::new("."));
            let parent = parent.canonicalize().with_context(|| {
                format!("Failed to resolve output directory: {}", parent.display())
            })?;
            let Some(file_name) = path.file_name() else {
                bail!("Output path must include a filename: {}", path.display());
            };
            Ok(parent.join(file_name))
        }
        Err(err) => {
            Err(err).with_context(|| format!("Failed to resolve output path: {}", path.display()))
        }
    }
}

fn ensure_distinct_export_paths(session_path: &Path, output_path: &Path) -> Result<()> {
    let session_path = session_path
        .canonicalize()
        .with_context(|| format!("Failed to resolve session path: {}", session_path.display()))?;
    let output_path = canonicalize_output_path(output_path)?;

    if session_path == output_path {
        bail!("input and output paths are the same");
    }

    Ok(())
}

fn handle_session_export(
    session_path: &Path,
    output: Option<&PathBuf>,
    format: &str,
) -> Result<()> {
    let format = SessionExportFormat::parse(format)?;

    if let Some(path) = output {
        ensure_distinct_export_paths(session_path, path)?;
    }

    let session = Session::resume(session_path)?;
    let history = session.get_history(None)?;

    let content = match format {
        SessionExportFormat::Json => serde_json::to_string_pretty(&history)?,
        SessionExportFormat::Text => {
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
    #[serde(skip_serializing_if = "Option::is_none")]
    eh_frame_fde_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    personality_function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lsda_section: Option<String>,
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
                let exception_summary = binary.exception_metadata_summary();
                let info = JsonBinaryInfo {
                    format: binary.format_name().to_string(),
                    architecture: format!("{:?}", fmt.architecture()),
                    endianness: format!("{:?}", fmt.endianness()),
                    entry_point: fmt.entry_point().map(|e| format!("{:#x}", e)),
                    symbol_count: sym_count,
                    eh_frame_fde_count: exception_summary.as_ref().map(|summary| summary.fde_count),
                    personality_function: exception_summary.as_ref().and_then(|summary| {
                        if summary.personalities.is_empty() {
                            None
                        } else {
                            Some(
                                summary
                                    .personalities
                                    .iter()
                                    .map(|addr| format_exception_personality(binary, *addr))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                            )
                        }
                    }),
                    lsda_section: exception_summary.and_then(|summary| summary.lsda_section_name),
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
                append_exception_metadata(&mut output, binary);
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

                let binary_data_ctx = build_binary_data_context(fmt);
                let cfg =
                    CfgBuilder::build_with_binary_context(&instructions, addr, &binary_data_ctx);

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

                let binary_data_ctx = build_binary_data_context(fmt);
                let cfg =
                    CfgBuilder::build_with_binary_context(&instructions, addr, &binary_data_ctx);

                // Build symbol table from session renames
                let mut symbols = SymbolTable::new();
                for (rename_addr, name) in session.get_all_annotations(AnnotationKind::Rename) {
                    symbols.insert(rename_addr, name);
                }
                // Add original symbols
                for sym in fmt.symbols() {
                    symbols.insert_symbol(sym, demangle_or_original(&sym.name));
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

                let relocations = build_relocation_table(binary);
                let throw_thunks = collect_throw_thunks(binary, &symbols, &relocations);
                let const_db = Arc::new(hexray_types::ConstantDatabase::with_builtins());
                let calling_convention = default_calling_convention(
                    match binary {
                        Binary::Elf(_) => BinaryType::Elf,
                        Binary::MachO(_) => BinaryType::MachO,
                        Binary::Pe(_) => BinaryType::Pe,
                    },
                    fmt.architecture(),
                );
                let mut decompiler = Decompiler::new()
                    .with_addresses(false)
                    .with_symbol_table(symbols)
                    .with_relocation_table(relocations)
                    .with_throw_thunks(throw_thunks)
                    .with_constant_database(const_db)
                    .with_struct_inference(true)
                    .with_calling_convention(calling_convention);
                if let Some(info) = binary.exception_info_for_function(addr, addr) {
                    decompiler = decompiler.with_exception_info(info);
                }

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

            let mut xref_db = builder.build();
            add_exception_section_xrefs(fmt, &mut xref_db);
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
                            XrefType::DataAddress => "addr",
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
                        XrefType::DataAddress => "ADDR",
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
    let s = normalize_hex_address_target(s);
    u64::from_str_radix(s, 16).context("Invalid address")
}

/// Helper function to disassemble a block of bytes using the appropriate architecture.
///
/// Returns an empty vector for architectures we do not have a decoder for
/// (notably CUDA SASS until M3 lands). The previous behaviour silently
/// delegated to `X86_64Disassembler`, which would happily emit plausible-but-
/// wrong instructions from a CUBIN's `.text.*` bytes.
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
        Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => {
            hexray_disasm::cuda::SassDisassembler::for_sm(sm).disassemble_block(bytes, start_addr)
        }
        Architecture::Amdgpu(target) => {
            hexray_disasm::amdgpu::AmdgpuDisassembler::for_target(target)
                .disassemble_block(bytes, start_addr)
        }
        Architecture::Cuda(hexray_core::CudaArchitecture::Ptx(_))
        | Architecture::Arm
        | Architecture::Unknown(_) => Vec::new(),
    }
}

/// Print the CUDA-specific summary block for a CUBIN: kernels, memory
/// regions, module-level .nv.info, and any parsing diagnostics.
fn print_cubin_info(view: &hexray_formats::CubinView<'_>) {
    println!("\nCUDA CUBIN View");
    println!("---------------");
    let strong = view.entry_kernels().count();
    println!(
        "Kernels:       {} ({} entry, {} candidate)",
        view.kernels().len(),
        strong,
        view.kernels().len() - strong,
    );
    for k in view.kernels() {
        let info_note = if k.nv_info.is_some() {
            " (+nv_info)"
        } else {
            ""
        };
        let conf = match k.confidence {
            hexray_formats::KernelConfidence::EntryMarker => "entry",
            hexray_formats::KernelConfidence::SiblingInfoOnly => "candidate",
        };
        println!(
            "  [{conf}] {name}  size={size}  section=#{idx}{info}",
            conf = conf,
            name = k.name,
            size = k.size,
            idx = k.section_index,
            info = info_note,
        );
        if let Some(usage) = k.resource_usage() {
            if let Some(rc) = usage.max_reg_count {
                print!("      regs={}", rc);
            }
            if let Some(cb) = usage.param_cbank {
                print!("  params@c[{}][{:#x}] size={}", cb.bank, cb.offset, cb.size);
            }
            if let Some(ntid) = usage.req_ntid {
                print!("  req_ntid=({},{},{})", ntid.0, ntid.1, ntid.2);
            }
            if !usage.exit_offsets.is_empty() {
                print!("  exits={}", usage.exit_offsets.len());
            }
            if usage.ctaidz_used {
                print!("  ctaidz");
            }
            if !usage.params.is_empty() {
                print!("  args=[");
                for (i, p) in usage.params.iter().enumerate() {
                    if i > 0 {
                        print!(",");
                    }
                    print!("#{}:{}B", p.ordinal, p.size_bytes());
                }
                print!("]");
            }
            println!();
        }
    }
    if !view.memory_regions().is_empty() {
        println!("Memory Regions: {}", view.memory_regions().len());
        for r in view.memory_regions() {
            let space = match r.space {
                hexray_formats::MemorySpace::Constant { bank } => format!("constant[{}]", bank),
                hexray_formats::MemorySpace::Shared => "shared".to_string(),
                hexray_formats::MemorySpace::Local => "local".to_string(),
            };
            let owner = r
                .owner_kernel
                .map(|n| format!(" ({})", n))
                .unwrap_or_default();
            println!(
                "  - {space}{owner}  {name}  size={size}",
                space = space,
                owner = owner,
                name = r.name,
                size = r.size,
            );
        }
    }
    if let Some(module) = view.module_info() {
        println!(
            "Module .nv.info: {} entries{}",
            module.entries.len(),
            if module.truncated { " (truncated)" } else { "" }
        );
    }
    if !view.diagnostics().is_empty() {
        println!("Diagnostics:    {}", view.diagnostics().len());
        for d in view.diagnostics() {
            let kind = match d.kind {
                hexray_formats::CubinDiagnosticKind::AmbiguousTextSection => {
                    "ambiguous .text.<name> section"
                }
                hexray_formats::CubinDiagnosticKind::OrphanNvInfoSection => {
                    "orphan .nv.info.<name> with no matching .text"
                }
                hexray_formats::CubinDiagnosticKind::DuplicateKernelName => "duplicate kernel name",
                hexray_formats::CubinDiagnosticKind::MalformedNvInfo => {
                    "malformed .nv.info TLV framing"
                }
            };
            match d.section_index {
                Some(idx) => println!("  - section #{}: {}", idx, kind),
                None => println!("  - {}", kind),
            }
        }
    }
}

/// A vendor-agnostic kernel summary used by the `hexray cmp`
/// subcommand. Different vendors expose different resource axes
/// (NVIDIA reports a single `regs`; AMDGPU splits into vgpr / sgpr),
/// so we collapse to the union and let the comparator report the
/// per-axis values.
#[derive(Debug, Clone, Default)]
struct KernelSummary {
    name: String,
    /// CUDA: total registers. AMDGPU: vgprs only.
    primary_regs: Option<u32>,
    /// AMDGPU: sgprs. CUDA: None.
    scalar_regs: Option<u32>,
    /// CUDA: param-cbank size. AMDGPU: kernarg_size.
    kernarg_or_param_size: Option<u32>,
    /// LDS / shared memory bytes (AMDGPU group_segment / CUDA shared
    /// region size).
    shared_lds_bytes: Option<u32>,
    /// CUDA: exit count. AMDGPU: not modelled (yet).
    exits: Option<usize>,
    /// Per-argument records, by ordinal. CUDA fills these from the
    /// `.nv.info` `KPARAM_INFO` records; AMDGPU from
    /// `NT_AMDGPU_METADATA`. Vendor-agnostic shape: just size
    /// in bytes per arg, since that's the only field both sides
    /// expose meaningfully.
    args: Vec<KernelArg>,
}

#[derive(Debug, Clone, Default)]
struct KernelArg {
    /// Argument size in bytes.
    size_bytes: Option<u32>,
}

fn collect_summaries(binary: &Binary) -> (Vec<KernelSummary>, String) {
    let mut summaries = Vec::new();
    let arch_label = format_arch_for_info(binary.as_format().architecture());

    if let Binary::Elf(elf) = binary {
        if let Ok(view) = elf.cubin_view() {
            for k in view.kernels() {
                let resource = k.resource_usage();
                let mut args: Vec<KernelArg> = resource
                    .as_ref()
                    .map(|r| {
                        let mut params = r.params.clone();
                        params.sort_by_key(|p| p.ordinal);
                        params
                            .iter()
                            .map(|p| KernelArg {
                                size_bytes: Some(p.size_bytes()),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                args.sort_by_key(|_| 0); // stable
                summaries.push(KernelSummary {
                    name: k.name.to_string(),
                    primary_regs: resource
                        .as_ref()
                        .and_then(|r| r.max_reg_count.map(u32::from)),
                    scalar_regs: None,
                    kernarg_or_param_size: resource
                        .as_ref()
                        .and_then(|r| r.cbank_param_size.map(u32::from)),
                    shared_lds_bytes: None,
                    exits: resource.as_ref().map(|r| r.exit_offsets.len()),
                    args,
                });
            }
        }
        if let Ok(view) = elf.code_object_view() {
            for k in &view.kernels {
                let r = &k.resource_usage;
                // Prefer metadata-supplied vgpr/sgpr counts when
                // present (the descriptor block reports
                // *granulated* allocation while metadata reports the
                // signed compiler view — equal in practice but
                // metadata is the canonical source).
                let metadata = k.metadata.as_ref();
                let primary = metadata
                    .and_then(|m| m.vgpr_count)
                    .unwrap_or(u32::from(r.vgpr_count));
                let scalar = metadata
                    .and_then(|m| m.sgpr_count)
                    .unwrap_or(u32::from(r.sgpr_count));
                let kernarg = metadata
                    .and_then(|m| m.kernarg_segment_size.map(|n| n as u32))
                    .unwrap_or(r.kernarg_size);
                let lds = metadata
                    .and_then(|m| m.group_segment_fixed_size.map(|n| n as u32))
                    .unwrap_or(r.lds_bytes);
                let args: Vec<KernelArg> = metadata
                    .map(|m| {
                        m.args
                            .iter()
                            .map(|a| KernelArg { size_bytes: a.size })
                            .collect()
                    })
                    .unwrap_or_default();
                summaries.push(KernelSummary {
                    name: k.name.to_string(),
                    primary_regs: Some(primary),
                    scalar_regs: Some(scalar),
                    kernarg_or_param_size: Some(kernarg),
                    shared_lds_bytes: Some(lds),
                    exits: None,
                    args,
                });
            }
        }
    }

    (summaries, arch_label)
}

fn cmp_input_kind(binary: &Binary, arch_label: &str) -> String {
    format!("{}/{}", binary.format_name(), arch_label)
}

/// `cmp` accepts recognized GPU binary formats even when they contain
/// zero kernels (for example, metadata-only AMDGPU code objects or
/// CUDA stubs). Kernel presence only affects the comparison output,
/// not whether the binary is GPU-shaped in the first place.
fn cmp_recognizes_gpu_binary(binary: &Binary) -> bool {
    match binary {
        Binary::Elf(elf) => elf.cubin_view().is_ok() || elf.code_object_view().is_ok(),
        Binary::MachO(_) | Binary::Pe(_) => false,
    }
}

/// Compare two GPU binaries kernel-by-kernel.
///
/// Matches kernels by mangled name (the same name appears on both
/// sides for SCALE-emitted CUDA-compiled-for-AMDGPU). Reports a
/// per-kernel resource diff. Cross-vendor comparison is at the
/// signature level, not instruction-by-instruction — different ISAs
/// can't be compared word-for-word.
///
/// Exit code:
/// - 0 if every matched kernel agrees on parameter / kernarg size
///   (informational `differ` lines for register-pressure / LDS deltas
///   don't count).
/// - 1 if any signature-level MISMATCH was detected.
fn cmp_kernels(a: &Binary, b_path: &Path) -> Result<()> {
    let b_data = fs::read(b_path).with_context(|| format!("reading {}", b_path.display()))?;
    let b = match detect_format(&b_data) {
        BinaryType::Elf => Binary::Elf(Elf::parse(&b_data).context("Failed to parse ELF (b)")?),
        BinaryType::MachO => {
            Binary::MachO(MachO::parse(&b_data).context("Failed to parse Mach-O (b)")?)
        }
        BinaryType::Pe => Binary::Pe(Pe::parse(&b_data).context("Failed to parse PE (b)")?),
        BinaryType::Unknown => {
            bail!("Unknown binary format for {}", b_path.display());
        }
    };

    let (a_kernels, a_arch) = collect_summaries(a);
    let (b_kernels, b_arch) = collect_summaries(&b);

    let a_kind = cmp_input_kind(a, &a_arch);
    let b_kind = cmp_input_kind(&b, &b_arch);

    match (cmp_recognizes_gpu_binary(a), cmp_recognizes_gpu_binary(&b)) {
        (true, true) => {}
        (false, false) => {
            bail!("cmp expects GPU binaries; got {a_kind} for 'a' and {b_kind} for 'b'");
        }
        (false, true) => {
            bail!("cmp expects a GPU binary for 'a'; got {a_kind}");
        }
        (true, false) => {
            bail!("cmp expects a GPU binary for 'b'; got {b_kind}");
        }
    }

    println!("hexray cmp");
    println!("==========");
    println!("a: {a_arch}");
    println!("b: {b_arch}");
    println!();

    let mut hard_mismatch = false;
    let mut matched = 0usize;
    for ka in &a_kernels {
        let Some(kb) = b_kernels.iter().find(|k| k.name == ka.name) else {
            println!("Kernel {}: present in a only", ka.name);
            continue;
        };
        matched += 1;
        println!("Kernel: {}", ka.name);
        cmp_field(
            "primary regs",
            ka.primary_regs.map(|r| r.to_string()),
            kb.primary_regs.map(|r| r.to_string()),
            FieldKind::Informational,
        );
        cmp_field(
            "scalar regs",
            ka.scalar_regs.map(|r| r.to_string()),
            kb.scalar_regs.map(|r| r.to_string()),
            FieldKind::Informational,
        );
        if cmp_field(
            "kernarg/param",
            ka.kernarg_or_param_size.map(|s| format!("{s}B")),
            kb.kernarg_or_param_size.map(|s| format!("{s}B")),
            FieldKind::Structural,
        ) {
            hard_mismatch = true;
        }
        cmp_field(
            "shared/LDS",
            ka.shared_lds_bytes.map(|s| format!("{s}B")),
            kb.shared_lds_bytes.map(|s| format!("{s}B")),
            FieldKind::Informational,
        );
        cmp_field(
            "exit count",
            ka.exits.map(|n| n.to_string()),
            kb.exits.map(|n| n.to_string()),
            FieldKind::Informational,
        );
        // Argument layout: count + per-ordinal size. The arg count
        // is structural (a missing arg means the kernel signatures
        // diverge); per-arg size is structural too (different sizes
        // mean a real ABI break).
        if !ka.args.is_empty() || !kb.args.is_empty() {
            if cmp_field(
                "arg count",
                Some(ka.args.len().to_string()),
                Some(kb.args.len().to_string()),
                FieldKind::Structural,
            ) {
                hard_mismatch = true;
            }
            for i in 0..ka.args.len().max(kb.args.len()) {
                let a = ka.args.get(i).and_then(|a| a.size_bytes);
                let b = kb.args.get(i).and_then(|a| a.size_bytes);
                if cmp_field(
                    &format!("arg [{i}] size"),
                    a.map(|s| format!("{s}B")),
                    b.map(|s| format!("{s}B")),
                    FieldKind::Structural,
                ) {
                    hard_mismatch = true;
                }
            }
        }
        println!();
    }
    for kb in &b_kernels {
        if !a_kernels.iter().any(|k| k.name == kb.name) {
            println!("Kernel {}: present in b only", kb.name);
        }
    }
    println!("Matched {matched} kernel(s).");

    if hard_mismatch {
        std::process::exit(1);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum FieldKind {
    /// Mismatch is real: parameter count, kernarg size — same source
    /// must produce the same signature on both sides.
    Structural,
    /// Mismatch is expected codegen difference: vgpr vs nvidia-reg
    /// counts, scheduling, etc.
    Informational,
}

/// Print one comparison row. Returns `true` if a structural mismatch
/// was detected (callers track this for the exit code).
fn cmp_field(name: &str, a: Option<String>, b: Option<String>, kind: FieldKind) -> bool {
    let (a_str, b_str) = (
        a.unwrap_or_else(|| "—".to_string()),
        b.unwrap_or_else(|| "—".to_string()),
    );
    let status = if a_str == b_str {
        "✓"
    } else if a_str == "—" || b_str == "—" {
        "n/a"
    } else {
        match kind {
            FieldKind::Structural => "MISMATCH",
            FieldKind::Informational => "differ",
        }
    };
    println!("  {name:<14}  a={a_str:<12} b={b_str:<12} {status}");
    status == "MISMATCH"
}

/// Print the AMDGPU-specific summary block for a code object:
/// kernels, decoded resource usage, and any soft diagnostics.
fn print_amdgpu_info(view: &hexray_formats::CodeObjectView<'_>) {
    println!("\nAMDGPU Code Object View");
    println!("-----------------------");
    println!("Target:        {}", view.target.target_id());
    println!("Kernels:       {}", view.kernels.len());
    for k in &view.kernels {
        let r = &k.resource_usage;
        let wave = if r.wave32 { "wave32" } else { "wave64" };
        println!("  {}", k.name);
        println!(
            "    entry=0x{:x}  kd=0x{:x}  {}  vgprs={}  sgprs={}",
            k.entry_addr, k.descriptor_addr, wave, r.vgpr_count, r.sgpr_count,
        );
        println!(
            "    kernarg={}B  lds={}B  scratch={}B  user_sgprs={}",
            r.kernarg_size, r.lds_bytes, r.scratch_bytes, r.user_sgpr_count,
        );
    }
    if !view.diagnostics.is_empty() {
        println!("\n  Diagnostics:");
        for d in &view.diagnostics {
            println!("    [{:?}] {}", d.kind, d.detail);
        }
    }
}

/// Pretty-print an Architecture for `hexray info`. CUDA targets expand to
/// canonical SM names (`sm_80`, `sm_90a`); AMDGPU targets render as full
/// target IDs (`gfx906`, `gfx90a:xnack+`); other architectures fall back
/// to their short name plus any ABI-specific detail we'd otherwise lose.
fn format_arch_for_info(arch: Architecture) -> String {
    match arch {
        Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => {
            format!(
                "cuda-sass ({}, family={:?})",
                sm.canonical_name(),
                sm.family
            )
        }
        Architecture::Cuda(hexray_core::CudaArchitecture::Ptx(ptx)) => {
            let target = ptx
                .target
                .map(|t| format!(", target={}", t.canonical_name()))
                .unwrap_or_default();
            format!(
                "cuda-ptx (v{}.{}, address_size={}{})",
                ptx.major, ptx.minor, ptx.address_size, target
            )
        }
        Architecture::Amdgpu(g) => format!("amdgpu ({}, family={:?})", g.target_id(), g.family),
        Architecture::Unknown(m) => format!("unknown (machine={})", m),
        other => other.name().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_instruction_relocations, default_calling_convention,
        demangle_exception_typeinfo_symbol_name, discover_function_starts,
        discover_materialized_internal_targets, discover_stripped_x86_function_seeds,
        ensure_distinct_export_paths, find_symbol_in_candidates, format_callgraph_text,
        infer_main_symbol_from_entry, parse_address_str, patch_affects_function,
        resolve_analysis_target, resolve_analysis_target_with_entry_main,
        resolve_materialized_callback_targets, resolve_xref_source_label,
        resolve_xref_target_addresses, string_tags, truncate_for_display, DiffPatchAddressSpace,
        FileAddressRange, ResolvedAnalysisTarget, SessionExportFormat, SymbolLookupMode,
    };
    use hexray_analysis::{
        CallGraph, CallSite, CallType, DetectedString, Patch, RelocationTable, StringEncoding,
        XrefType,
    };
    use hexray_core::{
        register::x86, Architecture, Bitness, ControlFlow, Endianness, Immediate, Instruction,
        MemoryRef, Operand, Operation, Register, RegisterClass, Symbol, SymbolBinding, SymbolKind,
    };
    use hexray_disasm::X86_64Disassembler;
    use hexray_formats::{BinaryFormat, BinaryType, RelocationType, Section};
    use std::fs;

    struct TestBinary {
        sections: Vec<TestSection>,
        symbols: Vec<Symbol>,
        entry_point: Option<u64>,
    }

    struct TestSection {
        name: &'static str,
        address: u64,
        data: Vec<u8>,
        executable: bool,
        allocated: bool,
    }

    impl BinaryFormat for TestBinary {
        fn architecture(&self) -> Architecture {
            Architecture::X86_64
        }

        fn endianness(&self) -> Endianness {
            Endianness::Little
        }

        fn bitness(&self) -> Bitness {
            Bitness::Bits64
        }

        fn entry_point(&self) -> Option<u64> {
            self.entry_point
        }

        fn executable_sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(
                self.sections
                    .iter()
                    .filter(|section| section.executable)
                    .map(|section| section as &dyn Section),
            )
        }

        fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section> + '_> {
            Box::new(self.sections.iter().map(|section| section as &dyn Section))
        }

        fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol> + '_> {
            Box::new(self.symbols.iter())
        }

        fn symbol_at(&self, addr: u64) -> Option<&Symbol> {
            self.symbols.iter().find(|symbol| symbol.address == addr)
        }

        fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]> {
            let section = self.section_containing(addr)?;
            let start = usize::try_from(addr.checked_sub(section.virtual_address())?).ok()?;
            section.data().get(start..start.checked_add(len)?)
        }

        fn section_containing(&self, addr: u64) -> Option<&dyn Section> {
            self.sections
                .iter()
                .find(|section| {
                    let start = section.address;
                    let end = start.saturating_add(section.data.len() as u64);
                    addr >= start && addr < end
                })
                .map(|section| section as &dyn Section)
        }
    }

    impl Section for TestSection {
        fn name(&self) -> &str {
            self.name
        }

        fn virtual_address(&self) -> u64 {
            self.address
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }

        fn data(&self) -> &[u8] {
            &self.data
        }

        fn is_executable(&self) -> bool {
            self.executable
        }

        fn is_writable(&self) -> bool {
            false
        }

        fn is_allocated(&self) -> bool {
            self.allocated
        }
    }

    fn unique_temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hexray-{}-{}", std::process::id(), name))
    }

    fn test_symbol(name: &str, address: u64) -> Symbol {
        Symbol {
            name: name.to_string(),
            address,
            size: 16,
            kind: SymbolKind::Function,
            binding: SymbolBinding::Global,
            section_index: Some(1),
        }
    }

    #[test]
    fn exact_match_beats_contains_match() {
        let symbols = vec![
            test_symbol("textdomain@plt", 0x4860),
            test_symbol("main", 0x6000),
        ];

        let resolved =
            find_symbol_in_candidates(&symbols, "main", SymbolLookupMode::Fuzzy).unwrap();

        assert_eq!(resolved.name, "main");
        assert_eq!(resolved.address, 0x6000);
    }

    #[test]
    fn exact_only_lookup_rejects_substring_matches() {
        let symbols = vec![test_symbol("textdomain@plt", 0x4860)];

        let resolved = find_symbol_in_candidates(&symbols, "main", SymbolLookupMode::ExactOnly);

        assert!(resolved.is_none());
    }

    #[test]
    fn fuzzy_lookup_rejects_substring_matches() {
        let symbols = vec![test_symbol("textdomain@plt", 0x4860)];

        let resolved = find_symbol_in_candidates(&symbols, "main", SymbolLookupMode::Fuzzy);

        assert!(resolved.is_none());
    }

    #[test]
    fn parse_address_str_accepts_sub_prefix() {
        assert_eq!(parse_address_str("sub_4860").unwrap(), 0x4860);
    }

    #[test]
    fn callgraph_symbol_helper_marks_plt_symbols_external() {
        assert!(crate::callgraph_symbol_is_external(&test_symbol(
            "textdomain@plt",
            0x4860,
        )));
        assert!(!crate::callgraph_symbol_is_external(&test_symbol(
            "main", 0x6000
        )));
    }

    #[test]
    fn suppress_callgraph_edge_helper_filters_ubsan_targets() {
        assert!(crate::suppress_callgraph_edge_to_name(
            "__ubsan_handle_add_overflow@plt"
        ));
        assert!(!crate::suppress_callgraph_edge_to_name("main"));
    }

    #[test]
    fn demangled_exact_match_is_preserved() {
        let symbols = vec![test_symbol("_ZN3foo4mainEv", 0x7000)];

        let resolved =
            find_symbol_in_candidates(&symbols, "foo::main()", SymbolLookupMode::Fuzzy).unwrap();

        assert_eq!(resolved.name, "_ZN3foo4mainEv");
    }

    #[test]
    fn exact_only_lookup_accepts_leading_underscore_alias() {
        let symbols = vec![test_symbol("_main", 0x7080)];

        let resolved =
            find_symbol_in_candidates(&symbols, "main", SymbolLookupMode::ExactOnly).unwrap();

        assert_eq!(resolved.name, "_main");
    }

    #[test]
    fn prefix_fallback_still_works() {
        let symbols = vec![test_symbol("nfsd_open.cold", 0x7100)];

        let resolved =
            find_symbol_in_candidates(&symbols, "nfsd_open", SymbolLookupMode::Fuzzy).unwrap();

        assert_eq!(resolved.name, "nfsd_open.cold");
    }

    #[test]
    fn compiler_generated_aliases_prefer_primary_clone_over_cold_split() {
        let symbols = vec![
            test_symbol("compute.cold", 0x401070),
            test_symbol("compute.lto_priv.1234", 0x4010f0),
        ];

        let resolved =
            find_symbol_in_candidates(&symbols, "compute", SymbolLookupMode::Fuzzy).unwrap();

        assert_eq!(resolved.name, "compute.lto_priv.1234");
        assert_eq!(resolved.address, 0x4010f0);
    }

    #[test]
    fn unversioned_lookup_prefers_default_gnu_export() {
        let symbols = vec![
            test_symbol("foo@VER_1", 0x10f9),
            test_symbol("foo@@VER_2", 0x110c),
        ];

        let resolved = find_symbol_in_candidates(&symbols, "foo", SymbolLookupMode::ExactOnly)
            .expect("default version should resolve");

        assert_eq!(resolved.name, "foo@@VER_2");
        assert_eq!(resolved.address, 0x110c);
    }

    #[test]
    fn exact_lookup_accepts_unversioned_demangled_cpp_export() {
        let symbols = vec![test_symbol(
            "_ZSt21ios_base_library_initv@GLIBCXX_3.4.32",
            0x401140,
        )];

        let resolved = find_symbol_in_candidates(
            &symbols,
            "std::ios_base_library_init()",
            SymbolLookupMode::ExactOnly,
        )
        .expect("versioned C++ export should resolve by demangled base name");

        assert_eq!(resolved.name, "_ZSt21ios_base_library_initv@GLIBCXX_3.4.32");
        assert_eq!(resolved.address, 0x401140);
    }

    #[test]
    fn xrefs_resolve_unversioned_imports_to_all_referenced_plt_targets() {
        let binary = TestBinary {
            sections: Vec::new(),
            symbols: Vec::new(),
            entry_point: None,
        };
        let symbols = vec![
            Symbol {
                name: "foo@VER_1".to_string(),
                address: 0,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: None,
            },
            Symbol {
                name: "foo@VER_1@plt".to_string(),
                address: 0x1060,
                size: 16,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
            Symbol {
                name: "foo@VER_2".to_string(),
                address: 0,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: None,
            },
            Symbol {
                name: "foo@VER_2@plt".to_string(),
                address: 0x1070,
                size: 16,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
        ];
        let mut db = hexray_analysis::XrefDatabase::new();
        db.add_xref(0x117b, 0x1060, XrefType::Call);
        db.add_xref(0x1187, 0x1070, XrefType::Call);
        let relocation_table = RelocationTable::new();

        let resolved = resolve_xref_target_addresses(
            &binary,
            None,
            "foo",
            &symbols,
            &relocation_table,
            &db,
            true,
        )
        .expect("versioned PLT targets should resolve");

        assert_eq!(resolved, vec![0x1060, 0x1070]);
    }

    #[test]
    fn xrefs_resolve_explicit_version_to_matching_plt_target() {
        let binary = TestBinary {
            sections: Vec::new(),
            symbols: Vec::new(),
            entry_point: None,
        };
        let symbols = vec![
            Symbol {
                name: "foo@VER_1".to_string(),
                address: 0,
                size: 0,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: None,
            },
            Symbol {
                name: "foo@VER_1@plt".to_string(),
                address: 0x1060,
                size: 16,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            },
        ];
        let mut db = hexray_analysis::XrefDatabase::new();
        db.add_xref(0x117b, 0x1060, XrefType::Call);
        let relocation_table = RelocationTable::new();

        let resolved = resolve_xref_target_addresses(
            &binary,
            None,
            "foo@VER_1",
            &symbols,
            &relocation_table,
            &db,
            true,
        )
        .expect("versioned PLT target should resolve");

        assert_eq!(resolved, vec![0x1060]);
    }

    #[test]
    fn xrefs_ignore_unallocated_debug_sections_when_labeling_callers() {
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".debug_str",
                    address: 0x0,
                    data: vec![0; 0x2000],
                    executable: false,
                    allocated: false,
                },
                TestSection {
                    name: ".text",
                    address: 0x1060,
                    data: vec![0; 0x40],
                    executable: true,
                    allocated: true,
                },
            ],
            symbols: Vec::new(),
            entry_point: None,
        };
        let function_starts = vec![(0x1060, Some("sub_1060".to_string()), 0x40)];

        let (name, offset) = resolve_xref_source_label(&binary, None, &function_starts, 0x106c);

        assert_eq!(name, "sub_1060");
        assert_eq!(offset, Some(0xc));
    }

    #[test]
    fn xrefs_consider_itanium_vtable_address_point_for_symbol_queries() {
        let binary = TestBinary {
            sections: Vec::new(),
            symbols: vec![Symbol {
                name: "_ZTV6Circle".to_string(),
                address: 0x402060,
                size: 0x30,
                kind: SymbolKind::Object,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };
        let mut db = hexray_analysis::XrefDatabase::new();
        db.add_xref(0x401500, 0x402070, XrefType::DataWrite);

        let resolved = resolve_xref_target_addresses(
            &binary,
            None,
            "_ZTV6Circle",
            &binary.symbols,
            &RelocationTable::new(),
            &db,
            false,
        )
        .expect("vtable base query should resolve");

        assert_eq!(resolved, vec![0x402060]);
        assert_eq!(
            super::xref_query_target_addresses(
                &binary,
                &binary.symbols,
                &RelocationTable::new(),
                resolved[0],
            ),
            vec![0x402060, 0x402070]
        );
    }

    #[test]
    fn xrefs_consider_itanium_vtable_address_point_for_address_queries() {
        let binary = TestBinary {
            sections: Vec::new(),
            symbols: vec![Symbol {
                name: "_ZTV6Circle".to_string(),
                address: 0x402060,
                size: 0x30,
                kind: SymbolKind::Object,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };

        assert_eq!(
            super::xref_query_target_addresses(
                &binary,
                &binary.symbols,
                &RelocationTable::new(),
                0x402060,
            ),
            vec![0x402060, 0x402070]
        );
    }

    #[test]
    fn xrefs_query_tls_symbols_by_canonical_offset() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".tdata",
                address: 0x403de0,
                data: vec![0; 0x20],
                executable: false,
                allocated: true,
            }],
            symbols: vec![Symbol {
                name: "g_thread_counter".to_string(),
                address: 0x14,
                size: 4,
                kind: SymbolKind::Tls,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };
        let mut db = hexray_analysis::XrefDatabase::new();
        db.add_xref(0x401274, 0x403df4, XrefType::DataRead);
        let relocation_table = RelocationTable::new();

        let resolved = resolve_xref_target_addresses(
            &binary,
            None,
            "g_thread_counter",
            &binary.symbols,
            &relocation_table,
            &db,
            false,
        )
        .expect("TLS query should resolve by canonical offset");

        assert_eq!(resolved, vec![0x14]);
        assert_eq!(
            super::xref_query_target_addresses(&binary, &binary.symbols, &relocation_table, 0x14,),
            vec![0x14, 0x403df4]
        );
    }

    #[test]
    fn xrefs_query_tls_symbols_through_gd_descriptors() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".tdata",
                address: 0x3de8,
                data: vec![0; 4],
                executable: false,
                allocated: true,
            }],
            symbols: vec![Symbol {
                name: "lib_counter".to_string(),
                address: 0,
                size: 4,
                kind: SymbolKind::Tls,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };
        let mut db = hexray_analysis::XrefDatabase::new();
        db.add_xref(0x1128, 0x3fb8, XrefType::DataAddress);
        let mut relocation_table = RelocationTable::new();
        relocation_table.insert_tls_descriptor(0x3fb8, "lib_counter".to_string());

        let resolved = resolve_xref_target_addresses(
            &binary,
            None,
            "lib_counter",
            &binary.symbols,
            &relocation_table,
            &db,
            false,
        )
        .expect("GD TLS descriptor should resolve to the TLS symbol");

        assert_eq!(resolved, vec![0]);
        assert_eq!(
            super::xref_query_target_addresses(&binary, &binary.symbols, &relocation_table, 0,),
            vec![0, 0x3de8, 0x3fb8]
        );
    }

    #[test]
    fn exact_lookup_prefers_callable_alias_over_ifunc_symbol() {
        let symbols = vec![
            Symbol {
                name: "strlen".to_string(),
                address: 0x4115f0,
                size: 112,
                kind: SymbolKind::Other(10),
                binding: SymbolBinding::Global,
                section_index: Some(7),
            },
            test_symbol("strlen", 0x401160),
        ];

        let resolved =
            find_symbol_in_candidates(&symbols, "strlen", SymbolLookupMode::ExactOnly).unwrap();

        assert_eq!(resolved.address, 0x401160);
        assert!(resolved.is_function());
    }

    #[test]
    fn resolve_analysis_target_prefers_exact_symbol_over_hex_parse() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401000,
                data: vec![0; 0x1000],
                executable: true,
                allocated: true,
            }],
            symbols: vec![test_symbol("add", 0x401106)],
            entry_point: None,
        };

        let resolved = resolve_analysis_target(&binary, None, "add").unwrap();

        match resolved {
            ResolvedAnalysisTarget::Symbol(symbol) => assert_eq!(symbol.address, 0x401106),
            ResolvedAnalysisTarget::Address(address) => {
                panic!("resolved {address:#x} instead of the exact symbol")
            }
        }
    }

    #[test]
    fn resolve_analysis_target_uses_hex_before_fuzzy_fallback_for_hex_looking_queries() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x0,
                data: vec![0; 0x2000],
                executable: true,
                allocated: true,
            }],
            symbols: vec![test_symbol("adder", 0x401106)],
            entry_point: None,
        };

        let resolved = resolve_analysis_target(&binary, None, "add").unwrap();

        match resolved {
            ResolvedAnalysisTarget::Address(address) => assert_eq!(address, 0xadd),
            ResolvedAnalysisTarget::Symbol(symbol) => {
                panic!("resolved {} instead of the hex address", symbol.name)
            }
        }
    }

    #[test]
    fn infer_main_symbol_from_entry_tracks_mov_rdi_before_libc_start_main() {
        let mut text = vec![0x90; 0x500];
        let start = 0x3a0usize;
        text[start..start + 38].copy_from_slice(&[
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x31, 0xed, // xor ebp, ebp
            0x49, 0x89, 0xd1, // mov r9, rdx
            0x5e, // pop rsi
            0x48, 0x89, 0xe2, // mov rdx, rsp
            0x48, 0x83, 0xe4, 0xf0, // and rsp, -16
            0x50, // push rax
            0x54, // push rsp
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0x31, 0xc9, // xor ecx, ecx
            0x48, 0xc7, 0xc7, 0xc0, 0x12, 0x40, 0x00, // mov rdi, 0x4012c0
            0xff, 0x15, 0x13, 0x2c, 0x00, 0x00, // call [rip + 0x2c13]
            0xf4, // hlt
        ]);
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401000,
                    data: text,
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".got.plt",
                    address: 0x403fd8,
                    data: vec![0; 8],
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: Some(0x4013a0),
        };
        let relocation_table = {
            let mut table = RelocationTable::new();
            table.insert_got(0x403fd8, "__libc_start_main@GLIBC_2.34".to_string());
            table
        };

        let main = infer_main_symbol_from_entry(&binary, &relocation_table)
            .expect("entry sequence should recover main");

        assert_eq!(main.name, "main");
        assert_eq!(main.address, 0x4012c0);
        assert!(main.is_function());
    }

    #[test]
    fn infer_main_symbol_from_entry_accepts_internal_bootstrap_call_target() {
        let mut text = vec![0x90; 0x4000];
        let start = 0x790usize;
        text[start..start + 38].copy_from_slice(&[
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x31, 0xed, // xor ebp, ebp
            0x49, 0x89, 0xd1, // mov r9, rdx
            0x5e, // pop rsi
            0x48, 0x89, 0xe2, // mov rdx, rsp
            0x48, 0x83, 0xe4, 0xf0, // and rsp, -16
            0x50, // push rax
            0x54, // push rsp
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0x31, 0xc9, // xor ecx, ecx
            0x48, 0xc7, 0xc7, 0x40, 0x17, 0x40, 0x00, // mov rdi, 0x401740
            0x67, 0xe8, 0x2b, 0x26, 0x00, 0x00, // addr32 call 0x403de0
            0xf4, // hlt
        ]);
        text[0x2de0..0x2de0 + 4].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfa]);

        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401000,
                data: text,
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: Some(0x401790),
        };

        let main = infer_main_symbol_from_entry(&binary, &RelocationTable::new())
            .expect("direct internal bootstrap call should recover main");

        assert_eq!(main.name, "main");
        assert_eq!(main.address, 0x401740);
        assert!(main.is_function());
    }

    #[test]
    fn resolve_analysis_target_with_entry_main_falls_back_when_symbol_is_missing() {
        let mut text = vec![0x90; 0x500];
        let start = 0x3a0usize;
        text[start..start + 38].copy_from_slice(&[
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x31, 0xed, // xor ebp, ebp
            0x49, 0x89, 0xd1, // mov r9, rdx
            0x5e, // pop rsi
            0x48, 0x89, 0xe2, // mov rdx, rsp
            0x48, 0x83, 0xe4, 0xf0, // and rsp, -16
            0x50, // push rax
            0x54, // push rsp
            0x45, 0x31, 0xc0, // xor r8d, r8d
            0x31, 0xc9, // xor ecx, ecx
            0x48, 0xc7, 0xc7, 0xc0, 0x12, 0x40, 0x00, // mov rdi, 0x4012c0
            0xff, 0x15, 0x13, 0x2c, 0x00, 0x00, // call [rip + 0x2c13]
            0xf4, // hlt
        ]);
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401000,
                    data: text,
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".got.plt",
                    address: 0x403fd8,
                    data: vec![0; 8],
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: Some(0x4013a0),
        };
        let relocation_table = {
            let mut table = RelocationTable::new();
            table.insert_got(0x403fd8, "__libc_start_main@GLIBC_2.34".to_string());
            table
        };

        let resolved =
            resolve_analysis_target_with_entry_main(&binary, None, "main", &relocation_table)
                .expect("stripped entry fallback should resolve main");

        match resolved {
            ResolvedAnalysisTarget::Symbol(symbol) => {
                assert_eq!(symbol.name, "main");
                assert_eq!(symbol.address, 0x4012c0);
            }
            ResolvedAnalysisTarget::Address(address) => {
                panic!("resolved {address:#x} instead of synthesized main symbol")
            }
        }
    }

    #[test]
    fn resolve_analysis_target_with_symbols_prefers_canonical_tls_exact_match() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".tdata",
                address: 0x403de4,
                data: vec![0; 4],
                executable: false,
                allocated: true,
            }],
            symbols: vec![Symbol {
                name: "seeded".to_string(),
                address: 0,
                size: 4,
                kind: SymbolKind::Tls,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };
        let symbols = vec![Symbol {
            name: "seeded".to_string(),
            address: 0,
            size: 4,
            kind: SymbolKind::Tls,
            binding: SymbolBinding::Global,
            section_index: Some(1),
        }];

        let resolved =
            crate::resolve_analysis_target_with_symbols(&binary, None, "seeded", &symbols).unwrap();

        match resolved {
            ResolvedAnalysisTarget::Symbol(symbol) => assert_eq!(symbol.address, 0),
            ResolvedAnalysisTarget::Address(address) => {
                panic!("resolved {address:#x} instead of the canonical TLS symbol")
            }
        }
    }

    #[test]
    fn display_symbol_name_prefers_defined_tls_over_undefined_import_at_zero() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".tdata",
                address: 0x403de4,
                data: vec![0; 4],
                executable: false,
                allocated: true,
            }],
            symbols: vec![
                Symbol {
                    name: "__tls_get_addr@GLIBC_2.3".to_string(),
                    address: 0,
                    size: 0,
                    kind: SymbolKind::Function,
                    binding: SymbolBinding::Global,
                    section_index: None,
                },
                Symbol {
                    name: "lib_counter".to_string(),
                    address: 0,
                    size: 4,
                    kind: SymbolKind::Tls,
                    binding: SymbolBinding::Global,
                    section_index: Some(1),
                },
            ],
            entry_point: None,
        };

        let display =
            crate::display_symbol_or_label_name_with_symbols(&binary, None, &binary.symbols, 0);

        assert_eq!(display, "lib_counter");
    }

    #[test]
    fn decompile_address_queries_reuse_exact_function_symbol_bounds() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401000,
                data: vec![0; 0x100],
                executable: true,
                allocated: true,
            }],
            symbols: vec![Symbol {
                name: "_Z10total_areaPP5Shapei".to_string(),
                address: 0x401040,
                size: 0x49,
                kind: SymbolKind::Function,
                binding: SymbolBinding::Global,
                section_index: Some(1),
            }],
            entry_point: None,
        };

        let info = super::decompile_target_info_for_address(&binary, None, 0x401040);

        assert_eq!(info.start_addr, 0x401040);
        assert_eq!(info.name, "total_area(Shape**, int)");
        assert_eq!(info.max_bytes, 0x49);
        assert!(!info.stop_after_first_return);
    }

    #[test]
    fn stripped_x86_function_seeds_use_endbr_boundaries() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401020,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0xc3, 0x90, 0x90, 0xf3, 0x0f, 0x1e, 0xfa, 0x55,
                    0xc3,
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };

        let seeds = discover_stripped_x86_function_seeds(&binary, Architecture::X86_64);

        assert_eq!(seeds, vec![(0x401020, 8, false), (0x401028, 6, false)]);
    }

    #[test]
    fn shared_function_starts_add_entry_and_stripped_seeds() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401020,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0xc3, 0x90, 0x90, 0xf3, 0x0f, 0x1e, 0xfa, 0x55,
                    0xc3,
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: Some(0x401000),
        };

        let starts = discover_function_starts(&binary, Architecture::X86_64, &binary.symbols);

        assert_eq!(
            starts,
            vec![
                (0x401000, 8192, true),
                (0x401020, 8, false),
                (0x401028, 6, false),
            ]
        );
    }

    #[test]
    fn lifecycle_arrays_seed_function_discovery() {
        let mut init_array = vec![0u8; 16];
        init_array[..8].copy_from_slice(&0x401156u64.to_le_bytes());
        init_array[8..].copy_from_slice(&0x401193u64.to_le_bytes());

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401100,
                    data: vec![0x90; 0x200],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".init_array",
                    address: 0x403de0,
                    data: init_array,
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };

        let starts = discover_function_starts(&binary, Architecture::X86_64, &binary.symbols);

        assert!(starts.iter().any(|(addr, _, _)| *addr == 0x401156));
        assert!(starts.iter().any(|(addr, _, _)| *addr == 0x401193));
    }

    #[test]
    fn lifecycle_array_entries_capture_slot_addresses() {
        let mut init_array = vec![0u8; 16];
        init_array[..8].copy_from_slice(&0x401156u64.to_le_bytes());
        init_array[8..].copy_from_slice(&0x401193u64.to_le_bytes());
        let mut fini_array = vec![0u8; 8];
        fini_array[..8].copy_from_slice(&0x4011b7u64.to_le_bytes());

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401100,
                    data: vec![0x90; 0x200],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".init_array",
                    address: 0x403de0,
                    data: init_array,
                    executable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".fini_array",
                    address: 0x403df0,
                    data: fini_array,
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };

        let entries = crate::discover_lifecycle_array_entries(&binary);

        assert_eq!(
            entries,
            vec![
                (0x403de0, 0x401156),
                (0x403de8, 0x401193),
                (0x403df0, 0x4011b7)
            ]
        );
    }

    #[test]
    fn lifecycle_array_relative_relocations_add_missing_entries() {
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401100,
                    data: vec![0x90; 0x200],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".init_array",
                    address: 0x403de0,
                    data: vec![0u8; 16],
                    executable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".fini_array",
                    address: 0x403df0,
                    data: vec![0u8; 8],
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };

        let mut entries = Vec::new();
        let mut seen = std::collections::HashSet::new();
        crate::append_lifecycle_array_relative_relocations(
            &binary,
            &[(0x403de0, 0x403df0), (0x403df0, 0x403df8)],
            &[
                (0x403de0, RelocationType::Relative, 0x401156),
                (0x403de8, RelocationType::Relative, 0x401193),
                (0x403df0, RelocationType::Relative, 0x4011b7),
                (0x500000, RelocationType::Relative, 0x401156),
                (0x403df8, RelocationType::Relative, 0x500000),
            ],
            &mut seen,
            &mut entries,
        );

        assert_eq!(
            entries,
            vec![
                (0x403de0, 0x401156),
                (0x403de8, 0x401193),
                (0x403df0, 0x4011b7)
            ]
        );
    }

    #[test]
    fn lifecycle_arrays_add_entry_edges_to_callgraph() {
        let mut init_array = vec![0u8; 8];
        init_array[..8].copy_from_slice(&0x401156u64.to_le_bytes());

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401000,
                    data: vec![0x90; 0x200],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".init_array",
                    address: 0x403de0,
                    data: init_array,
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![
                test_symbol("_start", 0x401000),
                test_symbol("init_runtime", 0x401156),
            ],
            entry_point: Some(0x401000),
        };
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x401000, Some("_start".to_string()), false);

        crate::add_lifecycle_array_edges(&mut callgraph, &binary, &binary.symbols);

        let callees: Vec<_> = callgraph.callees(0x401000).map(|(addr, _)| addr).collect();
        assert_eq!(callees, vec![0x401156]);
    }

    #[test]
    fn mark_callgraph_stub_nodes_external_uses_section_ranges_and_plt_names() {
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".plt",
                    address: 0x401000,
                    data: vec![0x90; 0x20],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".text",
                    address: 0x402000,
                    data: vec![0x90; 0x20],
                    executable: true,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };

        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x401010, None, false);
        callgraph.add_node(0x402000, Some("puts@GLIBC_2.2.5@plt".to_string()), false);
        callgraph.add_node(0x402010, Some("main".to_string()), false);

        crate::mark_callgraph_stub_nodes_external(&mut callgraph, &binary);

        assert!(callgraph.get_node(0x401010).unwrap().is_external);
        assert!(callgraph.get_node(0x402000).unwrap().is_external);
        assert!(!callgraph.get_node(0x402010).unwrap().is_external);
    }

    #[test]
    fn materialized_internal_targets_include_mov_immediates_in_text() {
        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x401000,
                    data: vec![0x90; 0x200],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".plt",
                    address: 0x402000,
                    data: vec![0x90; 0x40],
                    executable: true,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };
        let instructions = vec![
            Instruction {
                address: 0x401020,
                size: 7,
                operation: Operation::Move,
                mnemonic: "mov".to_string(),
                operands: vec![
                    Operand::Register(Register::new(
                        Architecture::X86_64,
                        RegisterClass::General,
                        x86::RDI,
                        64,
                    )),
                    Operand::Immediate(Immediate {
                        value: 0x401080,
                        size: 64,
                        signed: false,
                    }),
                ],
                control_flow: ControlFlow::Sequential,
                bytes: vec![0x48, 0xc7, 0xc7, 0x80, 0x10, 0x40, 0x00],
                reads: vec![],
                writes: vec![],
                guard: None,
            },
            Instruction {
                address: 0x401027,
                size: 7,
                operation: Operation::Move,
                mnemonic: "mov".to_string(),
                operands: vec![
                    Operand::Register(Register::new(
                        Architecture::X86_64,
                        RegisterClass::General,
                        x86::RAX,
                        64,
                    )),
                    Operand::Immediate(Immediate {
                        value: 0x402010,
                        size: 64,
                        signed: false,
                    }),
                ],
                control_flow: ControlFlow::Sequential,
                bytes: vec![0x48, 0xc7, 0xc0, 0x10, 0x20, 0x40, 0x00],
                reads: vec![],
                writes: vec![],
                guard: None,
            },
        ];

        let targets = discover_materialized_internal_targets(&instructions, &binary);

        assert_eq!(targets, vec![0x401080]);
    }

    #[test]
    fn materialized_internal_targets_ignore_memory_stores() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401000,
                data: vec![0x90; 0x200],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };
        let instructions = vec![Instruction {
            address: 0x401020,
            size: 8,
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef {
                    base: Some(Register::new(
                        Architecture::X86_64,
                        RegisterClass::General,
                        x86::RBP,
                        64,
                    )),
                    index: None,
                    scale: 1,
                    displacement: 0x10,
                    size: 8,
                    segment: None,
                    broadcast: false,
                    index_mode: hexray_core::IndexMode::None,
                    space: hexray_core::MemorySpace::Generic,
                }),
                Operand::Immediate(Immediate {
                    value: 0x401080,
                    size: 64,
                    signed: false,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            bytes: vec![0; 8],
            reads: vec![],
            writes: vec![],
            guard: None,
        }];

        let targets = discover_materialized_internal_targets(&instructions, &binary);

        assert!(targets.is_empty());
    }

    #[test]
    fn materialized_callback_targets_follow_fixed_stride_exec_entries() {
        let mut table = vec![0u8; 0x60];
        let mut write_ptr = |offset: usize, value: u64| {
            table[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        };

        write_ptr(0x00, 0x1228d3);
        write_ptr(0x08, 0x0ee4f0);
        write_ptr(0x10, 0x122ba1);
        write_ptr(0x18, 0x0eb850);
        write_ptr(0x20, 0x11f780);
        write_ptr(0x28, 0x0eb7e0);
        write_ptr(0x30, 0x122ba7);
        write_ptr(0x38, 0x0f5a80);
        write_ptr(0x40, 0x0);
        write_ptr(0x48, 0x0ef000);

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x0eb000,
                    data: vec![0x90; 0x10000],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".rodata",
                    address: 0x122000,
                    data: vec![0; 0x2000],
                    executable: false,
                    allocated: true,
                },
                TestSection {
                    name: ".data.rel.ro",
                    address: 0x1554c0,
                    data: table,
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };

        let targets = resolve_materialized_callback_targets(
            &binary,
            &hexray_analysis::callgraph::MaterializedIndirectCall {
                call_address: 0x0f5357,
                table_base: 0x1554c0,
                deref_offset: 8,
            },
        );

        assert_eq!(targets, vec![0x0ee4f0, 0x0eb850, 0x0eb7e0, 0x0f5a80]);
    }

    #[test]
    fn heuristic_disassembly_stops_at_unconditional_tail_jump() {
        let bytes = vec![
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xeb, 0xfa, // jmp 0x401150
            0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
            0xc3, // ret
        ];
        let disasm = X86_64Disassembler::new();

        let instructions =
            crate::disassemble_for_calls(&disasm, &bytes, 0x401150, true, &Default::default());

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "jmp");
    }

    #[test]
    fn heuristic_disassembly_stops_at_indirect_tail_jump_before_padding() {
        let bytes = vec![
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0x48, 0x8b, 0x07, // mov rax, [rdi]
            0xff, 0x60, 0x10, // jmp [rax + 0x10]
            0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, // nopw [rax + rax]
            0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
            0xc3, // ret
        ];
        let disasm = X86_64Disassembler::new();

        let instructions =
            crate::disassemble_for_calls(&disasm, &bytes, 0x401490, true, &Default::default());

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[2].mnemonic, "jmp");
        assert!(matches!(
            instructions[2].control_flow,
            ControlFlow::IndirectBranch { .. }
        ));
    }

    #[test]
    fn exact_sized_disassembly_keeps_scanning_past_mid_function_return() {
        let bytes = vec![
            0xf3, 0x0f, 0x1e, 0xfa, // endbr64
            0xc3, // ret
            0xe8, 0x00, 0x00, 0x00, 0x00, // call 0x40115a
            0xc3, // ret
        ];
        let disasm = X86_64Disassembler::new();

        let instructions =
            crate::disassemble_for_calls(&disasm, &bytes, 0x401150, false, &Default::default());

        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "ret");
        assert_eq!(instructions[2].mnemonic, "call");
        assert_eq!(instructions[3].mnemonic, "ret");
        assert!(matches!(
            instructions[2].control_flow,
            ControlFlow::Call {
                target: 0x40115a,
                ..
            }
        ));
    }

    #[test]
    fn heuristic_cfg_disassembly_stops_at_unconditional_tail_jump() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401150,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0xeb, 0xfa, // jmp 0x401150
                    0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
                    0xc3, // ret
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };
        let bytes = binary.bytes_at(0x401150, 11).unwrap();
        let disasm = X86_64Disassembler::new();

        let instructions = crate::disassemble_for_cfg(&disasm, &binary, bytes, 0x401150, true);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "jmp");
    }

    #[test]
    fn heuristic_cfg_disassembly_stops_at_ud2_leaf() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401520,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0x0f, 0x0b, // ud2
                    0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
                    0xc3, // ret
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };
        let bytes = binary.bytes_at(0x401520, 11).unwrap();
        let disasm = X86_64Disassembler::new();

        let instructions = crate::disassemble_for_cfg(&disasm, &binary, bytes, 0x401520, true);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "ud2");
    }

    #[test]
    fn heuristic_cfg_disassembly_treats_symbolless_ud2_leaf_call_as_noreturn() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401550,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0xe8, 0x03, 0x00, 0x00, 0x00, // call 0x40155c
                    0x0f, 0x1f, 0x00, // nopl [rax]
                    0x0f, 0x0b, // ud2 trap stub
                    0x66, 0x90, // padding
                    0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
                    0xc3, // ret
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };
        let bytes = binary.bytes_at(0x401550, 21).unwrap();
        let disasm = X86_64Disassembler::new();

        let instructions = crate::disassemble_for_cfg(&disasm, &binary, bytes, 0x401550, true);

        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "call");
    }

    #[test]
    fn heuristic_cfg_disassembly_stops_at_indirect_tail_jump_before_padding() {
        let binary = TestBinary {
            sections: vec![TestSection {
                name: ".text",
                address: 0x401490,
                data: vec![
                    0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                    0x48, 0x8b, 0x07, // mov rax, [rdi]
                    0xff, 0x60, 0x10, // jmp [rax + 0x10]
                    0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, // nopw [rax + rax]
                    0xf3, 0x0f, 0x1e, 0xfa, // adjacent function
                    0xc3, // ret
                ],
                executable: true,
                allocated: true,
            }],
            symbols: vec![],
            entry_point: None,
        };
        let bytes = binary.bytes_at(0x401490, 18).unwrap();
        let disasm = X86_64Disassembler::new();

        let instructions = crate::disassemble_for_cfg(&disasm, &binary, bytes, 0x401490, true);

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[0].mnemonic, "endbr64");
        assert_eq!(instructions[1].mnemonic, "mov");
        assert_eq!(instructions[2].mnemonic, "jmp");
        assert!(matches!(
            instructions[2].control_flow,
            ControlFlow::IndirectBranch { .. }
        ));
    }

    #[test]
    fn heuristic_cfg_disassembly_keeps_scanning_through_local_dispatch_table() {
        let mut table = vec![0u8; 0x30];
        for (index, value) in [0x4011f0u64, 0x401270, 0x401260, 0x401230, 0x401220]
            .into_iter()
            .enumerate()
        {
            let start = index * 8;
            table[start..start + 8].copy_from_slice(&value.to_le_bytes());
        }

        let binary = TestBinary {
            sections: vec![
                TestSection {
                    name: ".text",
                    address: 0x4011d0,
                    data: vec![
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x48, 0x89, 0xf9, // mov rcx, rdi
                        0x31, 0xd2, // xor edx, edx
                        0x85, 0xf6, // test esi, esi
                        0x74, 0x47, // je 0x401224
                        0x48, 0x8d, 0x47, 0x04, // lea rax, [rdi + 4]
                        0x48, 0x63, 0x3f, // movsxd rdi, [rdi]
                        0xff, 0x24, 0xfd, 0x20, 0x20, 0x40, 0x00, // jmp [rdi*8 + 0x402020]
                        0x0f, 0x1f, 0x44, 0x00, 0x00, // nopl [rax + rax]
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x03, 0x10, // add edx, [rax]
                        0x48, 0x8d, 0x78, 0x04, // lea rdi, [rax + 4]
                        0x4c, 0x63, 0xc6, // movsxd r8, esi
                        0x48, 0x29, 0xcf, // sub rdi, rcx
                        0x48, 0xc1, 0xff, 0x02, // sar rdi, 2
                        0x4c, 0x39, 0xc7, // cmp rdi, r8
                        0x7d, 0x1b, // jge 0x401224
                        0x48, 0x63, 0x78, 0x04, // movsxd rdi, [rax + 4]
                        0x48, 0x83, 0xc0, 0x08, // add rax, 8
                        0x48, 0x8b, 0x3c, 0xfd, 0x20, 0x20, 0x40,
                        0x00, // mov rdi, [rdi*8 + 0x402020]
                        0xff, 0xe7, // jmp rdi
                        0x0f, 0x1f, 0x44, 0x00, 0x00, // nopl [rax + rax]
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x89, 0xd0, // mov eax, edx
                        0xc3, // ret
                        0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00,
                        0x00, // nopw [rax + rax]
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x48, 0x89, 0xc7, // mov rdi, rax
                        0x4c, 0x63, 0xc6, // movsxd r8, esi
                        0xf7, 0xda, // neg edx
                        0x48, 0x29, 0xcf, // sub rdi, rcx
                        0x48, 0xc1, 0xff, 0x02, // sar rdi, 2
                        0x4c, 0x39, 0xc7, // cmp rdi, r8
                        0x7d, 0xdc, // jge 0x401224
                        0x48, 0x63, 0x38, // movsxd rdi, [rax]
                        0x48, 0x83, 0xc0, 0x04, // add rax, 4
                        0x48, 0x8b, 0x3c, 0xfd, 0x20, 0x20, 0x40,
                        0x00, // mov rdi, [rdi*8 + 0x402020]
                        0xff, 0xe7, // jmp rdi
                        0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // nopl [rax]
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x0f, 0xaf, 0x10, // imul edx, [rax]
                        0xeb, 0x8d, // jmp 0x4011f6
                        0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00, // nopl [rax]
                        0xf3, 0x0f, 0x1e, 0xfa, // endbr64
                        0x2b, 0x10, // sub edx, [rax]
                        0xe9, 0x7b, 0xff, 0xff, 0xff, // jmp 0x4011f6
                    ],
                    executable: true,
                    allocated: true,
                },
                TestSection {
                    name: ".rodata",
                    address: 0x402020,
                    data: table,
                    executable: false,
                    allocated: true,
                },
            ],
            symbols: vec![],
            entry_point: None,
        };
        let bytes = binary.bytes_at(0x4011d0, 0xab).unwrap();
        let disasm = X86_64Disassembler::new();

        let instructions = crate::disassemble_for_cfg(&disasm, &binary, bytes, 0x4011d0, true);

        assert!(instructions.iter().any(|inst| inst.address == 0x401270));
        assert!(instructions.iter().any(|inst| inst.address == 0x401276));
        let first_dispatch = instructions
            .iter()
            .find(|inst| inst.address == 0x4011e4)
            .expect("dispatch branch");
        match &first_dispatch.control_flow {
            ControlFlow::IndirectBranch { possible_targets } => {
                assert_eq!(possible_targets.len(), 5);
            }
            other => panic!("expected indirect branch, got {other:?}"),
        }
    }

    #[test]
    fn tls_memory_operands_rewrite_to_absolute_symbol_addresses() {
        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let mut instructions = vec![Instruction {
            address: 0x4011bf,
            size: 8,
            bytes: vec![],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    x86::RAX,
                    64,
                )),
                Operand::Memory(MemoryRef::absolute(-0x50, 4).with_segment(fs)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        }];
        let tls_access_targets = vec![crate::TlsAccessTarget {
            tpoff: -0x50,
            address: 0x403de0,
            size: 4,
        }];
        let tls_slot_map = std::collections::HashMap::new();
        crate::rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);

        let Operand::Memory(mem) = &instructions[0].operands[1] else {
            panic!("expected rewritten TLS memory operand");
        };
        assert_eq!(mem.displacement, 0x403de0);
        assert!(mem.segment.is_none());
    }

    #[test]
    fn tls_memory_operands_rewrite_interior_tls_offsets() {
        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let mut instructions = vec![Instruction {
            address: 0x4012c4,
            size: 9,
            bytes: vec![],
            operation: Operation::Move,
            mnemonic: "mov".to_string(),
            operands: vec![
                Operand::Register(Register::new(
                    Architecture::X86_64,
                    RegisterClass::General,
                    x86::RAX,
                    64,
                )),
                Operand::Memory(MemoryRef::absolute(-0x10, 8).with_segment(fs)),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        }];
        let tls_access_targets = vec![crate::TlsAccessTarget {
            tpoff: -0x18,
            address: 0x403de0,
            size: 16,
        }];

        crate::rewrite_tls_memory_operands(
            &mut instructions,
            &tls_access_targets,
            &std::collections::HashMap::new(),
        );

        let Operand::Memory(mem) = &instructions[0].operands[1] else {
            panic!("expected rewritten interior TLS memory operand");
        };
        assert_eq!(mem.displacement, 0x403de8);
        assert!(mem.segment.is_none());
    }

    #[test]
    fn tls_slot_loaded_register_rewrites_segmented_store() {
        let fs = Register::new(Architecture::X86_64, RegisterClass::Segment, x86::FS, 16);
        let rax = Register::new(Architecture::X86_64, RegisterClass::General, x86::RAX, 64);
        let rip = Register::new(Architecture::X86_64, RegisterClass::General, x86::RIP, 64);
        let mut instructions = vec![
            Instruction {
                address: 0x1000,
                size: 7,
                bytes: vec![],
                operation: Operation::Move,
                mnemonic: "mov".to_string(),
                operands: vec![
                    Operand::Register(rax),
                    Operand::Memory(MemoryRef::base_disp(rip, 0x100, 8)),
                ],
                control_flow: ControlFlow::Sequential,
                reads: vec![],
                writes: vec![rax],
                guard: None,
            },
            Instruction {
                address: 0x1007,
                size: 7,
                bytes: vec![],
                operation: Operation::Move,
                mnemonic: "mov".to_string(),
                operands: vec![
                    Operand::Memory(MemoryRef::base_disp(rax, 0, 4).with_segment(fs)),
                    Operand::Immediate(Immediate {
                        value: 0x26,
                        size: 4,
                        signed: false,
                    }),
                ],
                control_flow: ControlFlow::Sequential,
                reads: vec![],
                writes: vec![],
                guard: None,
            },
        ];
        let tls_access_targets = Vec::new();
        let tls_slot_map = std::collections::HashMap::from([(0x1107, 0x403de0)]);

        crate::rewrite_tls_memory_operands(&mut instructions, &tls_access_targets, &tls_slot_map);

        let Operand::Memory(mem) = &instructions[1].operands[0] else {
            panic!("expected rewritten TLS store operand");
        };
        assert_eq!(mem.displacement, 0x403de0);
        assert!(mem.base.is_none());
        assert!(mem.segment.is_none());
    }

    #[test]
    fn string_tags_match_text_classifier() {
        let path = DetectedString {
            address: 0,
            length: 9,
            content: "/tmp/file".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };
        let url = DetectedString {
            address: 0,
            length: 19,
            content: "https://hexray.dev".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };
        let error = DetectedString {
            address: 0,
            length: 18,
            content: "operation failed".to_string(),
            encoding: StringEncoding::Ascii,
            null_terminated: true,
        };

        assert_eq!(string_tags(&path), vec!["PATH"]);
        assert_eq!(string_tags(&url), vec!["URL"]);
        assert_eq!(string_tags(&error), vec!["ERROR"]);
    }

    #[test]
    fn truncate_for_display_preserves_utf8_boundaries() {
        let content = format!("{}Æ{}", "A".repeat(76), "B".repeat(10));

        let truncated = truncate_for_display(&content, 80);

        assert_eq!(truncated, format!("{}Æ...", "A".repeat(76)));
    }

    #[test]
    fn callgraph_text_output_is_sorted_by_address() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x2000, Some("callee_b".to_string()), false);
        callgraph.add_node(0x1000, Some("caller".to_string()), false);
        callgraph.add_node(0x1500, Some("callee_a".to_string()), false);
        callgraph.add_node(0x800, Some("root".to_string()), false);

        callgraph.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1010,
                call_type: CallType::Direct,
            },
        );
        callgraph.add_call(
            0x1000,
            0x1500,
            CallSite {
                call_address: 0x1020,
                call_type: CallType::Direct,
            },
        );
        callgraph.add_call(
            0x1000,
            0x2000,
            CallSite {
                call_address: 0x1030,
                call_type: CallType::Direct,
            },
        );
        callgraph.add_call(
            0x800,
            0x1000,
            CallSite {
                call_address: 0x810,
                call_type: CallType::Direct,
            },
        );

        let output = format_callgraph_text(&callgraph);

        assert_eq!(
            output,
            concat!(
                "Call Graph Analysis\n",
                "===================\n",
                "Functions: 4\n",
                "Call edges: 4\n",
                "\n",
                "root (0x800):\n",
                "  -> caller (0x1000)\n",
                "\n",
                "caller (0x1000):\n",
                "  -> callee_a (0x1500)\n",
                "  -> callee_b (0x2000) [2x]\n",
                "\n",
            )
        );
    }

    #[test]
    fn export_rejects_same_input_and_output_path() {
        let session_path = unique_temp_path("session-export-same-path.hrp");
        fs::write(&session_path, b"session").unwrap();

        let err = ensure_distinct_export_paths(&session_path, &session_path).unwrap_err();
        assert!(err
            .to_string()
            .contains("input and output paths are the same"));

        fs::remove_file(&session_path).unwrap();
    }

    #[test]
    fn export_rejects_unknown_format() {
        let err = SessionExportFormat::parse("asciinema").unwrap_err();

        assert!(err
            .to_string()
            .contains("format 'asciinema' not supported; valid: text, json"));
    }

    #[test]
    fn default_calling_convention_uses_win64_for_pe_x86_64() {
        assert_eq!(
            default_calling_convention(BinaryType::Pe, Architecture::X86_64),
            hexray_analysis::CallingConvention::Win64
        );
    }

    #[test]
    fn default_calling_convention_keeps_sysv_for_non_pe_x86_64() {
        assert_eq!(
            default_calling_convention(BinaryType::Elf, Architecture::X86_64),
            hexray_analysis::CallingConvention::SystemV
        );
        assert_eq!(
            default_calling_convention(BinaryType::MachO, Architecture::X86_64),
            hexray_analysis::CallingConvention::SystemV
        );
    }

    #[test]
    fn diff_attribution_translates_et_exec_file_offsets_to_virtual_addresses() {
        let address_space = DiffPatchAddressSpace::FileOffsets(vec![FileAddressRange {
            file_start: 0x1000,
            file_end: 0x2000,
            va_start: 0x401000,
        }]);
        let add_start = 0x401106;
        let add_end = 0x40111e;
        let factorial_start = 0x40111e;
        let factorial_end = 0x401150;

        let mid_add = Patch::new(0x111a, vec![0x01], vec![0x29]);
        assert!(patch_affects_function(
            &address_space,
            &mid_add,
            add_start,
            add_end
        ));
        assert!(!patch_affects_function(
            &address_space,
            &mid_add,
            factorial_start,
            factorial_end
        ));

        let last_add_byte = Patch::new(0x111d, vec![0x02], vec![0x2a]);
        assert!(patch_affects_function(
            &address_space,
            &last_add_byte,
            add_start,
            add_end
        ));
        assert!(!patch_affects_function(
            &address_space,
            &last_add_byte,
            factorial_start,
            factorial_end
        ));

        let first_factorial_byte = Patch::new(0x111e, vec![0x03], vec![0x2b]);
        assert!(!patch_affects_function(
            &address_space,
            &first_factorial_byte,
            add_start,
            add_end
        ));
        assert!(patch_affects_function(
            &address_space,
            &first_factorial_byte,
            factorial_start,
            factorial_end
        ));
    }

    #[test]
    fn diff_attribution_ignores_unmapped_eof_insertions() {
        let address_space = DiffPatchAddressSpace::FileOffsets(vec![FileAddressRange {
            file_start: 0x1000,
            file_end: 0x2000,
            va_start: 0x401000,
        }]);
        let eof_append = Patch::new(0xab80, vec![], vec![0x00]);

        assert!(!patch_affects_function(
            &address_space,
            &eof_append,
            0x401106,
            0x40111e
        ));
        assert!(!patch_affects_function(
            &address_space,
            &eof_append,
            0x4011f0,
            0x401260
        ));
    }

    #[test]
    fn demangle_exception_typeinfo_symbol_name_handles_direct_typeinfo() {
        assert_eq!(
            demangle_exception_typeinfo_symbol_name("_ZTI7MyError"),
            Some("MyError".to_string())
        );
    }

    #[test]
    fn demangle_exception_typeinfo_symbol_name_handles_dw_ref_aliases() {
        assert_eq!(
            demangle_exception_typeinfo_symbol_name("DW.ref._ZTI7MyError"),
            Some("MyError".to_string())
        );
    }

    #[test]
    fn apply_instruction_relocations_rewrites_rip_relative_data_targets() {
        let rip = Register::new(Architecture::X86_64, RegisterClass::General, x86::RIP, 64);
        let rdx = Register::new(Architecture::X86_64, RegisterClass::General, x86::RDX, 32);
        let mut instructions =
            vec![
                Instruction::new(0x4d, 6, vec![0x8b, 0x15, 0x00, 0x00, 0x00, 0x00], "mov")
                    .with_operation(Operation::Move)
                    .with_operand(Operand::reg(rdx))
                    .with_operand(Operand::Memory(MemoryRef::base_disp(rip, 0, 4))),
            ];

        let mut relocations = RelocationTable::new();
        relocations.insert_data(0x4d, "counter".to_string(), 0x2000, true);

        apply_instruction_relocations(&mut instructions, &relocations);

        let Operand::Memory(mem) = &instructions[0].operands[1] else {
            panic!("expected RIP-relative memory operand");
        };
        assert_eq!(mem.displacement, 0x2000_i64 - 0x53_i64);
    }

    #[test]
    fn apply_instruction_relocations_rewrites_absolute_immediates() {
        let rdi = Register::new(Architecture::X86_64, RegisterClass::General, x86::RDI, 64);
        let mut instructions = vec![Instruction::new(
            0x1a66,
            7,
            vec![0x48, 0xc7, 0xc7, 0x00, 0x00, 0x00, 0x00],
            "mov",
        )
        .with_operation(Operation::Move)
        .with_operand(Operand::reg(rdi))
        .with_operand(Operand::Immediate(Immediate {
            value: 0,
            size: 4,
            signed: true,
        }))];

        let mut relocations = RelocationTable::new();
        relocations.insert_data(0x1a66, "msdos_fs_type".to_string(), 0x3020, false);

        apply_instruction_relocations(&mut instructions, &relocations);

        let Operand::Immediate(imm) = &instructions[0].operands[1] else {
            panic!("expected immediate operand");
        };
        assert_eq!(imm.value, 0x3020);
    }
}
