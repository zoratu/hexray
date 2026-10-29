//! `hexray db` — the persistent analysis project front end.
//!
//! This module owns everything that needs a parser or the CLI:
//! - turning an input file into a validated image layout (`mappings`,
//!   `sections`, layout fingerprint) and the effective patched bytes;
//! - running the analysis passes and publishing them into `hexray-db`;
//! - the query/edit/REPL surface.
//!
//! It never re-implements analysis: decoding, CFG construction, xref recovery
//! and pseudo-C rendering all go through [`crate::analysis_pipeline`], the same
//! entry point the plain `hexray <binary> decompile` command uses.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser as _, Subcommand};
use hexray_core::{Architecture, ControlFlow, Instruction, Operand};
use hexray_db::store::{PayloadBytes, MAX_PAYLOAD_BYTES};
use hexray_db::{
    Address, AnalysisBatch, AnalysisPayload, AnalysisScope, AnalysisState, AnnotationKind,
    BlockPayload, BoundsOrigin, ContainerKind, CreateInput, Database, DbError, Dependency,
    DependencyKind, Diagnostic, EdgeKind, Edit, EditOutcome, FileOffset, FunctionCfgPayload,
    FunctionOrigin, FunctionOverrideRow, FunctionRow, ImageIndexPayload, ImageInfo, ItemKind,
    ItemRow, MappingInfo, MappingPermissions, OpenMode, OverallState, PatchRow, RenderConfig,
    RenderPayload, Revision, ScopeRange, SectionInfo, Severity, StringEncoding, StringRow,
    SymbolInfo, SymbolOrigin, TypeKind, TypeRow, UnitKey, UnitPublish, VariableLocator, XrefKind,
    XrefOrigin, XrefRow,
};
use hexray_formats::{detect_format, ArArchive, BinaryFormat, BinaryType, Elf, MachO, Pe, Section};
use hexray_types::TypeDatabase;
use rayon::prelude::*;
use std::sync::Arc;

use crate::analysis_pipeline::{
    self, analyze_replay, build_decompiler_config, render_function, AnalysisInputs,
    CommentOverlay, DecodeKey, DecodeSession, DecodedFunction, RenderOptions, ReplayInput,
    SharedAnalysisContext, SharedTables,
};
use crate::analysis_scope::{ScopeMap, SectionHint, SECTION_HINTS_WARNING};
use crate::Binary;
use serde_json::json;

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

/// How one command may spend CPU and extra working memory.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct AnalysisExecutionOptions {
    /// Worker threads: 0 = one per available core, 1 = serial, up to 256;
    /// a value above the core count is clamped to it
    #[arg(
        short = 'j',
        long,
        default_value_t = 0,
        value_parser = clap::value_parser!(u32).range(0..=256)
    )]
    pub jobs: u32,
    /// Extra working-set budget for concurrent function analysis, in MiB.
    ///
    /// This bounds the scheduler's own in-flight scratch and payload estimates,
    /// not the process RSS: parser and SSA allocations inside one function are
    /// covered by the per-function change limits, not by this number.
    #[arg(
        long,
        default_value_t = 512,
        value_parser = clap::value_parser!(u64).range(64..=65536)
    )]
    pub analysis_memory_mib: u64,
    /// Print per-stage wall times to stderr (also a `timings` object with --json)
    #[arg(long)]
    pub timings: bool,
}

impl Default for AnalysisExecutionOptions {
    fn default() -> Self {
        Self {
            jobs: 0,
            analysis_memory_mib: 512,
            timings: false,
        }
    }
}

/// Largest accepted explicit worker count.
const MAX_JOBS: usize = 256;
/// Virtual stack reserved per worker. The analysis pipeline is recursive in the
/// source it accepts, so workers get the same generous stack the CLI main thread
/// already uses instead of the 2 MiB default.
const WORKER_STACK_BYTES: usize = 32 * 1024 * 1024;
/// Floor for one function's estimated scratch, in bytes.
const MIN_FUNCTION_SCRATCH_BYTES: u64 = 8 * 1024 * 1024;
/// Most functions one publish batch may contain.
const MAX_BATCH_FUNCTIONS: usize = 128;

impl AnalysisExecutionOptions {
    /// 0 means "one per available core".
    pub(crate) fn requested_jobs(&self) -> usize {
        let cores = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        if self.jobs == 0 {
            cores
        } else {
            // The work is CPU-bound: workers past the core count only reserve a
            // 32 MiB stack each and contend the allocator, so an explicit value
            // above the machine is clamped to it.
            (self.jobs as usize).clamp(1, MAX_JOBS).min(cores)
        }
    }

    pub(crate) fn budget_bytes(&self) -> u64 {
        self.analysis_memory_mib.saturating_mul(1024 * 1024)
    }

    /// Effective workers for one batch: never more than the batch can use, and
    /// never more than the budget can cover at the per-worker floor.
    fn effective_jobs(&self, batch_len: usize) -> usize {
        let by_budget = (self.budget_bytes() / MIN_FUNCTION_SCRATCH_BYTES).max(1) as usize;
        self.requested_jobs()
            .min(batch_len.max(1))
            .min(by_budget)
            .max(1)
    }
}

/// The global form of [`AnalysisExecutionOptions`] for `db query`, whose flags
/// may appear after the subcommand (`db query db.hxdb decompile main --jobs 4`).
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct GlobalAnalysisOptions {
    /// Worker threads: 0 = one per available core, 1 = serial, up to 256;
    /// a value above the core count is clamped to it
    #[arg(
        short = 'j',
        long,
        global = true,
        default_value_t = 0,
        value_parser = clap::value_parser!(u32).range(0..=256)
    )]
    pub jobs: u32,
    /// Extra working-set budget for concurrent function analysis, in MiB
    #[arg(
        long,
        global = true,
        default_value_t = 512,
        value_parser = clap::value_parser!(u64).range(64..=65536)
    )]
    pub analysis_memory_mib: u64,
    /// Print per-stage wall times to stderr
    #[arg(long, global = true)]
    pub timings: bool,
}

impl Default for GlobalAnalysisOptions {
    fn default() -> Self {
        Self {
            jobs: 0,
            analysis_memory_mib: 512,
            timings: false,
        }
    }
}

impl From<&GlobalAnalysisOptions> for AnalysisExecutionOptions {
    fn from(value: &GlobalAnalysisOptions) -> Self {
        Self {
            jobs: value.jobs,
            analysis_memory_mib: value.analysis_memory_mib,
            timings: value.timings,
        }
    }
}

/// One analysis-scope edit: section names and explicit address ranges.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct ScopeFlags {
    /// Exclude one executable section by exact name (repeatable)
    #[arg(long = "skip-section")]
    pub skip_sections: Vec<String>,
    /// Exclude one half-open address range `start:end` in hex (repeatable)
    #[arg(long = "skip-range")]
    pub skip_ranges: Vec<String>,
}

impl ScopeFlags {
    pub(crate) fn is_empty(&self) -> bool {
        self.skip_sections.is_empty() && self.skip_ranges.is_empty()
    }
}

/// Flags that bound how much input an operation may touch.
#[derive(Debug, Clone, clap::Args)]
pub(crate) struct InputLimits {
    /// Maximum accepted size of the original input file.
    #[arg(long, default_value_t = 8 * 1024 * 1024 * 1024u64)]
    pub max_source_bytes: u64,
    /// Maximum accepted size of the analyzed image.
    #[arg(long, default_value_t = 256 * 1024 * 1024u64)]
    pub max_analysis_bytes: u64,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: 8 * 1024 * 1024 * 1024,
            max_analysis_bytes: 256 * 1024 * 1024,
        }
    }
}

/// How to pick one image out of a container.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct Selection {
    /// Mach-O architecture to select from a fat binary.
    #[arg(long)]
    pub arch: Option<String>,
    /// `ar` member name to analyze.
    #[arg(long)]
    pub member: Option<String>,
    /// Zero-based `ar` member index, required when names collide.
    #[arg(long)]
    pub member_index: Option<u64>,
    /// Authorized split-DWARF sidecar; repeatable.
    #[arg(long = "debug-file")]
    pub debug_files: Vec<PathBuf>,
}

/// Pseudo-C rendering options, mirroring the standalone `decompile` command.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct RenderFlags {
    /// Emit basic-block address comments.
    #[arg(long)]
    pub show_addresses: bool,
    /// Optimization level: none, basic, standard, aggressive.
    #[arg(long, default_value = "standard")]
    pub opt_level: String,
    /// Enable an optimization pass (repeatable).
    #[arg(long = "enable-pass")]
    pub enable_passes: Vec<String>,
    /// Disable an optimization pass (repeatable).
    #[arg(long = "disable-pass")]
    pub disable_passes: Vec<String>,
}

#[derive(Subcommand, Clone)]
pub(crate) enum DbAction {
    /// Describe the selectable images inside an input file
    InputInfo {
        binary: PathBuf,
        #[command(flatten)]
        selection: Selection,
        /// Also list per-section packing hints (read-only; never skips anything)
        #[arg(long)]
        section_hints: bool,
        #[arg(long)]
        json: bool,
    },
    /// Create a new analysis project
    Create {
        binary: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        selection: Selection,
        #[command(flatten)]
        limits: InputLimits,
        /// Initial analysis scope: exclude one executable section by name
        #[command(flatten)]
        scope: ScopeFlags,
        #[command(flatten)]
        exec: AnalysisExecutionOptions,
        #[arg(long)]
        json: bool,
    },
    /// Show project metadata and analysis state
    Info {
        database: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run or repair analysis
    Analyze {
        database: PathBuf,
        #[command(flatten)]
        flags: AnalyzeFlags,
        #[command(flatten)]
        limits: InputLimits,
        #[arg(long)]
        json: bool,
    },
    /// Interactive project shell
    Open {
        database: PathBuf,
        #[arg(long)]
        read_only: bool,
        #[command(flatten)]
        exec: AnalysisExecutionOptions,
    },
    /// Read analysis results
    Query {
        database: PathBuf,
        #[command(subcommand)]
        command: QueryAction,
        #[arg(long, global = true)]
        json: bool,
        /// Show historical results even when they are not current
        #[arg(long, global = true)]
        allow_stale: bool,
        /// Rebuild missing or stale results (writes to the project)
        #[arg(long, global = true)]
        update: bool,
        #[command(flatten)]
        exec: GlobalAnalysisOptions,
        #[command(flatten)]
        limits: InputLimits,
    },
    /// Apply one user edit
    Edit {
        database: PathBuf,
        #[command(subcommand)]
        command: EditAction,
        /// Required revision; the write fails if the project moved on
        #[arg(long, global = true)]
        expect_revision: Option<u64>,
    },
    /// Undo the most recent edit
    Undo {
        database: PathBuf,
        #[arg(long)]
        expect_revision: Option<u64>,
    },
    /// Redo the most recently undone edit
    Redo {
        database: PathBuf,
        #[arg(long)]
        expect_revision: Option<u64>,
    },
    /// Copy the project to a new file
    Backup {
        database: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Write a binary with the recorded byte patches applied
    ExportBinary {
        database: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify database integrity
    Check {
        database: PathBuf,
        /// Re-hash the embedded source and validate patch ranges
        #[arg(long)]
        deep: bool,
        #[arg(long)]
        json: bool,
    },
    /// Import user state from a legacy project or session
    ImportLegacy {
        legacy: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        selection: Selection,
        #[command(flatten)]
        limits: InputLimits,
        /// Initial analysis scope: exclude one executable section by name
        #[command(flatten)]
        scope: ScopeFlags,
        #[command(flatten)]
        exec: AnalysisExecutionOptions,
        /// Accept a legacy file whose weak digest does not match
        #[arg(long)]
        accept_unverified_legacy: bool,
        #[arg(long)]
        json: bool,
    },
}

/// What one `analyze` run should do. Shared by the one-shot command, the
/// `db query ... --update` path and the shell so all three accept exactly the
/// same grammar.
#[derive(Debug, Clone, clap::Args, Default)]
pub(crate) struct AnalyzeFlags {
    /// Restrict to one function (address or name)
    #[arg(long)]
    pub function: Option<String>,
    /// Recompute even when the stored result is current
    #[arg(long)]
    pub force: bool,
    /// Also generate pseudo-C
    #[arg(long)]
    pub render: bool,
    #[command(flatten)]
    pub render_flags: RenderFlags,
    #[command(flatten)]
    pub exec: AnalysisExecutionOptions,
}

/// Read-only queries. Every variant is answered from the database, never by
/// re-parsing the source.
#[derive(Subcommand, Clone)]
pub(crate) enum QueryAction {
    /// Sections and loaded mappings
    Info {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Sections {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Symbols {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Functions {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Disasm {
        function: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Cfg {
        function: String,
        #[arg(long)]
        dot: bool,
        #[arg(long)]
        html: bool,
    },
    Xrefs {
        address: String,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Callgraph {
        function: Option<String>,
        #[arg(long)]
        dot: bool,
        #[arg(long)]
        html: bool,
    },
    Strings {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Bytes {
        address: String,
        length: u64,
    },
    Decompile {
        function: String,
        #[command(flatten)]
        render_flags: RenderFlags,
    },
    Variables {
        function: String,
    },
    Types {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    History {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    Changes {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        offset: Option<usize>,
    },
    /// Emulate a function (temporary computation, never persisted)
    Emulate {
        #[command(subcommand)]
        action: crate::commands::emulate::EmulateAction,
    },
    /// Trace a function (temporary computation, never persisted)
    Trace {
        #[command(subcommand)]
        action: crate::commands::trace::TraceAction,
    },
    /// Signature scans (read-only)
    Signatures {
        #[command(subcommand)]
        action: crate::commands::signatures::SignaturesAction,
    },
    /// Automatic-analysis scope, optionally with per-section packing hints
    Scope {
        /// Also list per-section packing hints (read-only; never skips anything)
        #[arg(long)]
        section_hints: bool,
    },
}

/// User edits. Each maps 1:1 onto a [`hexray_db::Edit`].
#[derive(Subcommand, Clone)]
pub(crate) enum EditAction {
    /// Overwrite bytes at a source file offset or image address
    Patch {
        address: String,
        /// Hex bytes, e.g. `554889e5`
        hex_bytes: String,
    },
    MakeCode {
        address: String,
        length: u64,
    },
    MakeData {
        address: String,
        length: u64,
        #[arg(long = "type")]
        type_name: Option<String>,
    },
    Undefine {
        address: String,
        length: u64,
    },
    FunctionCreate {
        start: String,
        end: String,
    },
    FunctionBounds {
        start: String,
        end: String,
    },
    FunctionRemove {
        start: String,
    },
    FunctionExclude {
        start: String,
        /// `true` or `false`
        excluded: String,
    },
    Name {
        address: String,
        name: String,
    },
    Comment {
        address: String,
        text: String,
    },
    Tag {
        address: String,
        text: String,
    },
    Bookmark {
        address: String,
        label: Option<String>,
    },
    Signature {
        function: String,
        /// One C function prototype
        prototype: String,
    },
    CallingConvention {
        function: String,
        convention: String,
    },
    TypeImport {
        /// UTF-8 header file
        header: PathBuf,
    },
    TypeRemove {
        name: String,
    },
    ApplyType {
        address: String,
        #[arg(long = "type")]
        type_name: String,
        #[arg(long)]
        length: Option<u64>,
    },
    Variable {
        function: String,
        /// Locator JSON, as printed by `query variables`
        locator: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long = "type")]
        type_name: Option<String>,
    },
    Clear {
        /// One of name, comment, tag, bookmark, signature, calling-convention,
        /// type, variable
        target: String,
        address: String,
        #[arg(long)]
        locator: Option<String>,
    },
    /// Replace the automatic-analysis scope (no flags clears it)
    Scope {
        #[command(flatten)]
        flags: ScopeFlags,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub(crate) fn handle(action: DbAction) -> Result<()> {
    match action {
        DbAction::InputInfo {
            binary,
            selection,
            section_hints,
            json,
        } => input_info(&binary, &selection, section_hints, json),
        DbAction::Create {
            binary,
            output,
            selection,
            limits,
            scope,
            exec,
            json,
        } => create(&binary, &output, &selection, &limits, &scope, &exec, json),
        DbAction::Info { database, json } => info(&database, json),
        DbAction::Analyze {
            database,
            flags,
            limits,
            json,
        } => analyze(
            &database,
            flags.function,
            flags.force,
            flags.render,
            &flags.render_flags,
            &limits,
            &flags.exec,
            json,
        ),
        DbAction::Open {
            database,
            read_only,
            exec,
        } => run_repl(&database, read_only, &exec),
        DbAction::Query {
            database,
            command,
            json,
            allow_stale,
            update,
            exec,
            limits,
        } => query(
            &database,
            command,
            json,
            allow_stale,
            update,
            &limits,
            &AnalysisExecutionOptions::from(&exec),
        ),
        DbAction::Edit {
            database,
            command,
            expect_revision,
        } => edit(&database, command, expect_revision),
        DbAction::Undo {
            database,
            expect_revision,
        } => undo(&database, expect_revision),
        DbAction::Redo {
            database,
            expect_revision,
        } => redo(&database, expect_revision),
        DbAction::Backup { database, output } => backup(&database, &output),
        DbAction::ExportBinary { database, output } => export_binary(&database, &output),
        DbAction::Check {
            database,
            deep,
            json,
        } => check(&database, deep, json),
        DbAction::ImportLegacy {
            legacy,
            binary,
            output,
            selection,
            limits,
            scope,
            exec,
            accept_unverified_legacy,
            json,
        } => import_legacy(
            &legacy,
            &binary,
            &output,
            &selection,
            &limits,
            &scope,
            &exec,
            accept_unverified_legacy,
            json,
        ),
    }
}

/// Keep the store error's concrete type so `main` can map it to the documented
/// exit class (3 for revision conflicts, 4 for lock/resource limits).
fn db<T>(result: Result<T, DbError>) -> Result<T> {
    result.map_err(anyhow::Error::new)
}

/// Publish one analysis batch, retrying while SQLite is busy.
///
/// A busy `publish` has already rolled back, so retrying the same batch with
/// the same base revision is safe: another process's *analysis* would instead
/// surface as a generation conflict.
fn publish_batch(database: &mut Database, revision: Revision, batch: &AnalysisBatch) -> Result<()> {
    const RETRIES: usize = 30;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(200);
    for attempt in 0..=RETRIES {
        match database.publish(revision, batch) {
            Ok(()) => return Ok(()),
            Err(DbError::Busy(error)) if attempt < RETRIES => {
                if attempt == 0 {
                    eprintln!("waiting for a concurrent reader to release {error}");
                }
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("the retry loop returns on the last attempt")
}

// ---------------------------------------------------------------------------
// Engine fingerprint
// ---------------------------------------------------------------------------

/// Identifier of the analysis engine.
///
/// Any change that can alter output for the same input must bump
/// [`hexray_db::ANALYSIS_FORMAT_REVISION`]; the schema version moves separately.
fn engine_fingerprint() -> [u8; 32] {
    let mut canonical = String::new();
    canonical.push_str("hexray-analysis\n");
    canonical.push_str(&format!(
        "analysis-format-revision={}\n",
        hexray_db::ANALYSIS_FORMAT_REVISION
    ));
    canonical.push_str(&format!("crate-version={}\n", env!("CARGO_PKG_VERSION")));
    // The decoder set is fixed by the CLI's `hexray-disasm` feature selection;
    // it is part of the fingerprint because it decides what can be decoded.
    let mut arches: Vec<&str> = vec![
        "x86",
        "x86_64",
        "arm64",
        "riscv32",
        "riscv64",
        "cuda-sass",
        "amdgpu",
    ];
    arches.sort_unstable();
    canonical.push_str(&format!("architectures={}\n", arches.join(",")));
    hexray_db::sha256(canonical.as_bytes())
}

// ---------------------------------------------------------------------------
// Input loading: container -> image selection -> validated layout
// ---------------------------------------------------------------------------

/// One selectable image inside an input container.
#[derive(Debug, Clone)]
struct ImageSelection {
    container_kind: ContainerKind,
    container_offset: u64,
    container_length: u64,
    member_name: Option<String>,
    member_index: Option<u64>,
    slice_label: Option<String>,
    selector_json: String,
}

/// An input file split into the full source and the selected image.
struct LoadedInput {
    source: Vec<u8>,
    selection: ImageSelection,
}

fn describe_images(path: &Path, selection: &Selection) -> Result<Vec<String>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    match detect_format(&bytes) {
        BinaryType::Ar => {
            let archive = ArArchive::parse(&bytes).context("failed to parse ar archive")?;
            let mut out = Vec::new();
            for (index, member) in archive.regular_members().enumerate() {
                out.push(format!(
                    "member_index={index} name={} size={}",
                    member.name(),
                    member.data().len()
                ));
            }
            Ok(out)
        }
        BinaryType::MachO => {
            let labels = MachO::list_slices(&bytes);
            if labels.is_empty() {
                Ok(vec!["thin mach-o".to_string()])
            } else {
                Ok(labels)
            }
        }
        BinaryType::Elf => Ok(vec!["elf".to_string()]),
        BinaryType::Pe => Ok(vec!["pe".to_string()]),
        BinaryType::Unknown => {
            let _ = selection;
            Ok(Vec::new())
        }
    }
}

fn select_input(path: &Path, selection: &Selection, limits: &InputLimits) -> Result<LoadedInput> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.len() > limits.max_source_bytes {
        bail!(
            "input is {} bytes, above the {} byte limit (raise --max-source-bytes)",
            metadata.len(),
            limits.max_source_bytes
        );
    }
    let source =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let container = detect_format(&source);

    let selection = match container {
        BinaryType::Ar => {
            let archive = ArArchive::parse(&source).context("failed to parse ar archive")?;
            let members: Vec<_> = archive.regular_members().collect();
            let index = match (&selection.member, selection.member_index) {
                (_, Some(index)) => {
                    let index = usize::try_from(index)
                        .map_err(|_| anyhow::anyhow!("member index is out of range"))?;
                    if index >= members.len() {
                        bail!(
                            "member index {index} is out of range; the archive holds {} members",
                            members.len()
                        );
                    }
                    index
                }
                (Some(name), None) => {
                    let matches: Vec<usize> = members
                        .iter()
                        .enumerate()
                        .filter(|(_, member)| member.name() == name)
                        .map(|(index, _)| index)
                        .collect();
                    match matches.len() {
                        0 => bail!("no ar member named '{name}'"),
                        1 => matches[0],
                        _ => bail!(
                            "ar member name '{name}' is ambiguous ({} matches); pass --member-index",
                            matches.len()
                        ),
                    }
                }
                (None, None) => bail!(
                    "this input is an ar archive; select a member with --member <name> \
                     or --member-index <n> (see `db input-info`)"
                ),
            };
            let member = &members[index];
            let data = member.data();
            let offset = member.data_offset() as u64;
            ImageSelection {
                container_kind: ContainerKind::Ar,
                container_offset: offset,
                container_length: data.len() as u64,
                member_name: Some(member.name().to_string()),
                member_index: Some(index as u64),
                slice_label: None,
                selector_json: json!({
                    "member_index": index,
                    "member_name": member.name(),
                })
                .to_string(),
            }
        }
        BinaryType::MachO => {
            let parsed = MachO::parse_with_arch(&source, selection.arch.as_deref())
                .context("failed to parse Mach-O")?;
            let offset = parsed.file_offset() as u64;
            let length = parsed
                .slice_size()
                .map(|size| size as u64)
                .unwrap_or_else(|| source.len() as u64 - offset.min(source.len() as u64));
            let label = parsed.slice_label();
            ImageSelection {
                container_kind: ContainerKind::MachO,
                container_offset: offset,
                container_length: length,
                member_name: None,
                member_index: None,
                slice_label: Some(label.clone()),
                selector_json: json!({ "slice": label }).to_string(),
            }
        }
        BinaryType::Elf => ImageSelection {
            container_kind: ContainerKind::Elf,
            container_offset: 0,
            container_length: source.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: json!({ "image": "elf" }).to_string(),
        },
        BinaryType::Pe => ImageSelection {
            container_kind: ContainerKind::Pe,
            container_offset: 0,
            container_length: source.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: json!({ "image": "pe" }).to_string(),
        },
        BinaryType::Unknown => bail!(
            "{} is not a supported input (ELF, Mach-O, PE or ar). CUDA fatbin, HIP wrappers \
             and PTX must be extracted to a supported object first.",
            path.display()
        ),
    };

    if selection.container_kind == ContainerKind::Ar {
        // An ar member may itself be a Mach-O slice: allow one more level.
        let start = usize::try_from(selection.container_offset)
            .map_err(|_| anyhow::anyhow!("member offset is out of range"))?;
        let end = start
            .checked_add(usize::try_from(selection.container_length)?)
            .ok_or_else(|| anyhow::anyhow!("member range overflows"))?;
        if end > source.len() {
            bail!("selected member extends past the end of the archive");
        }
    }

    if selection.container_length > limits.max_analysis_bytes {
        bail!(
            "selected image is {} bytes, above the {} byte analysis limit \
             (raise --max-analysis-bytes)",
            selection.container_length,
            limits.max_analysis_bytes
        );
    }

    Ok(LoadedInput { source, selection })
}

/// Build the persisted image description from the selected slice.
struct ParsedImage<'a> {
    binary: Binary<'a>,
    info: ImageInfo,
}

fn parse_image<'a>(image_bytes: &'a [u8], selection: &ImageSelection) -> Result<ParsedImage<'a>> {
    #[cfg(test)]
    cache_counters::IMAGE_PARSES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let format = detect_format(image_bytes);
    let binary = match format {
        BinaryType::Elf => Binary::Elf(Elf::parse(image_bytes).context("failed to parse ELF")?),
        BinaryType::MachO => {
            Binary::MachO(MachO::parse(image_bytes).context("failed to parse Mach-O slice")?)
        }
        BinaryType::Pe => Binary::Pe(Pe::parse(image_bytes).context("failed to parse PE")?),
        other => bail!("selected image is {other:?}, not a supported object"),
    };
    let info = build_image_info(&binary, selection)?;
    Ok(ParsedImage { binary, info })
}

fn build_image_info(binary: &Binary<'_>, selection: &ImageSelection) -> Result<ImageInfo> {
    let fmt = binary.as_format();
    let arch = fmt.architecture();
    let bitness = match fmt.bitness() {
        hexray_core::Bitness::Bits32 => 32u8,
        hexray_core::Bitness::Bits64 => 64u8,
    };
    let endianness = match fmt.endianness() {
        hexray_core::Endianness::Little => "little",
        hexray_core::Endianness::Big => "big",
    }
    .to_string();
    let abi = match binary {
        Binary::Pe(_) => {
            if bitness == 64 {
                hexray_db::AbiInfo::llp64()
            } else {
                hexray_db::AbiInfo::ilp32()
            }
        }
        _ => {
            if bitness == 64 {
                hexray_db::AbiInfo::lp64()
            } else {
                hexray_db::AbiInfo::ilp32()
            }
        }
    };
    let mut abi = abi;
    abi.big_endian = endianness == "big";

    let mappings = build_mappings(binary)?;
    let sections = build_sections(fmt);
    let mut info = ImageInfo {
        format: binary.format_name().to_ascii_lowercase(),
        architecture: format_architecture(arch),
        bitness,
        endianness,
        abi,
        entry_address: fmt.entry_point().map(Address),
        selector_json: selection.selector_json.clone(),
        container_offset: FileOffset(selection.container_offset),
        container_length: selection.container_length,
        member_name: selection.member_name.clone(),
        member_index: selection.member_index,
        slice_label: selection.slice_label.clone(),
        layout_fingerprint: [0u8; 32],
        mappings,
        sections,
    };
    info.layout_fingerprint = compute_layout_fingerprint(&info);
    Ok(info)
}

/// Architectures this project can structure and render as pseudo-C.
///
/// GPU code objects (CUDA SASS, AMDGPU) are decodable and stored, but they
/// have no pseudo-C path: rendering publishes an `unsupported` unit instead.
fn supports_pseudo_c(arch: Architecture) -> bool {
    matches!(
        arch,
        Architecture::X86
            | Architecture::X86_64
            | Architecture::Arm64
            | Architecture::RiscV32
            | Architecture::RiscV64
    )
}

/// Short architecture label stored in the database. The detailed
/// (ABI-specific) form is only used in messages.
fn format_architecture(arch: Architecture) -> String {
    match arch {
        Architecture::X86 => "x86".to_string(),
        Architecture::X86_64 => "x86_64".to_string(),
        Architecture::Arm64 => "arm64".to_string(),
        Architecture::RiscV32 => "riscv32".to_string(),
        Architecture::RiscV64 => "riscv64".to_string(),
        other => crate::format_arch_for_info(other),
    }
}

fn build_mappings(binary: &Binary<'_>) -> Result<Vec<MappingInfo>> {
    let mut mappings = Vec::new();
    match binary {
        Binary::Elf(elf) => {
            for (index, segment) in elf.segments.iter().enumerate() {
                if !segment.is_load() {
                    continue;
                }
                mappings.push(MappingInfo {
                    name: format!("PT_LOAD[{index}]"),
                    va: Address(segment.p_vaddr),
                    memory_size: segment.p_memsz,
                    file_offset: if segment.p_filesz > 0 {
                        Some(FileOffset(segment.p_offset))
                    } else {
                        None
                    },
                    file_size: segment.p_filesz,
                    permissions: MappingPermissions {
                        read: segment.is_readable(),
                        write: segment.is_writable(),
                        execute: segment.is_executable(),
                    },
                    origin: "program_header".to_string(),
                });
            }
        }
        Binary::MachO(macho) => {
            for segment in &macho.segments {
                if segment.filesize == 0 && segment.vmsize == 0 {
                    continue;
                }
                mappings.push(MappingInfo {
                    name: segment.segname.clone(),
                    va: Address(segment.vmaddr),
                    memory_size: segment.vmsize,
                    file_offset: if segment.filesize > 0 {
                        Some(FileOffset(segment.fileoff))
                    } else {
                        None
                    },
                    file_size: segment.filesize,
                    permissions: MappingPermissions {
                        read: segment.is_readable(),
                        write: segment.is_writable(),
                        execute: segment.is_executable(),
                    },
                    origin: "segment".to_string(),
                });
            }
        }
        Binary::Pe(pe) => {
            let base = pe.image_base();
            let mut mappings: Vec<MappingInfo> = Vec::new();
            for section in &pe.sections {
                let start = base + u64::from(section.virtual_address);
                let memory_size = u64::from(section.virtual_size.max(section.size_of_raw_data));
                mappings.push(MappingInfo {
                    name: section.name.clone(),
                    va: Address(start),
                    memory_size,
                    file_offset: if section.size_of_raw_data > 0 {
                        Some(FileOffset(u64::from(section.pointer_to_raw_data)))
                    } else {
                        None
                    },
                    file_size: u64::from(section.size_of_raw_data),
                    permissions: MappingPermissions {
                        read: section.is_readable(),
                        write: section.is_writable(),
                        execute: section.is_executable(),
                    },
                    origin: "section".to_string(),
                });
            }
            // Consecutive sections with identical permissions form one mapping;
            // keeping them separate preserves the header/body distinction the
            // patch guard needs.
            mappings.sort_by_key(|mapping| mapping.va.0);
        }
    }

    if mappings.is_empty() {
        // Sections are a strictly worse fallback, but a stripped container
        // with no program headers still has to be readable. GPU code objects
        // are the reason this cannot require SHF_ALLOC: a CUBIN's `.text.sm_*`
        // is executable without being allocated, and dropping it would leave
        // the image with no mappings at all.
        for section in binary.as_format().sections() {
            if section.size() == 0 || !(section.is_allocated() || section.is_executable()) {
                continue;
            }
            mappings.push(MappingInfo {
                name: section.name().to_string(),
                va: Address(section.virtual_address()),
                memory_size: section.size(),
                file_offset: Some(FileOffset(section.file_offset())),
                file_size: section.size(),
                permissions: MappingPermissions {
                    read: true,
                    write: section.is_writable(),
                    execute: section.is_executable(),
                },
                origin: "section_fallback".to_string(),
            });
        }
    }

    mappings.sort_by_key(|mapping| mapping.va.0);
    if mappings.is_empty() {
        bail!("the selected image exposes no loadable mappings");
    }
    Ok(mappings)
}

fn build_sections(fmt: &dyn BinaryFormat) -> Vec<SectionInfo> {
    let mut sections: Vec<SectionInfo> = fmt
        .sections()
        .map(|section| SectionInfo {
            name: section.name().to_string(),
            va: Address(section.virtual_address()),
            memory_size: section.size(),
            file_offset: Some(FileOffset(section.file_offset())),
            file_size: section.size(),
            flags: format!(
                "{}{}{}",
                if section.is_allocated() { "A" } else { "-" },
                if section.is_writable() { "W" } else { "-" },
                if section.is_executable() { "X" } else { "-" },
            ),
        })
        .collect();
    sections.sort_by_key(|section| (section.va.0, section.name.clone()));
    sections
}

/// SHA-256 over the canonical layout description. Any change here invalidates
/// stored mappings, so patching cannot silently reshape the image.
fn compute_layout_fingerprint(info: &ImageInfo) -> [u8; 32] {
    let mut canonical = String::new();
    canonical.push_str(&format!(
        "layout-fingerprint-version={}\n",
        hexray_db::LAYOUT_FINGERPRINT_VERSION
    ));
    canonical.push_str(&format!("format={}\n", info.format));
    canonical.push_str(&format!("architecture={}\n", info.architecture));
    canonical.push_str(&format!("bitness={}\n", info.bitness));
    canonical.push_str(&format!("endianness={}\n", info.endianness));
    canonical.push_str(&format!(
        "entry={}\n",
        info.entry_address
            .map(|address| address.to_hex())
            .unwrap_or_default()
    ));
    canonical.push_str(&format!("selector={}\n", info.selector_json));
    let mut mappings = info.mappings.clone();
    mappings.sort_by_key(|mapping| mapping.va.0);
    for mapping in &mappings {
        canonical.push_str(&format!(
            "map {} {} {} {} {} {} {}\n",
            mapping.name,
            mapping.va.to_hex(),
            mapping.memory_size,
            mapping
                .file_offset
                .map(|offset| offset.to_hex())
                .unwrap_or_default(),
            mapping.file_size,
            mapping.permissions.as_str(),
            mapping.origin
        ));
    }
    let mut sections = info.sections.clone();
    sections.sort_by_key(|section| (section.va.0, section.name.clone()));
    for section in &sections {
        canonical.push_str(&format!(
            "sec {} {} {} {} {} {}\n",
            section.name,
            section.va.to_hex(),
            section.memory_size,
            section
                .file_offset
                .map(|offset| offset.to_hex())
                .unwrap_or_default(),
            section.file_size,
            section.flags
        ));
    }
    hexray_db::sha256(canonical.as_bytes())
}

/// Apply recorded patches to a copy of the source.
fn effective_source(source: &[u8], patches: &[PatchRow]) -> Result<Vec<u8>> {
    let mut bytes = source.to_vec();
    for patch in patches {
        let start = usize::try_from(patch.offset.0)
            .map_err(|_| anyhow::anyhow!("patch offset is out of range"))?;
        let end = start
            .checked_add(patch.bytes.len())
            .ok_or_else(|| anyhow::anyhow!("patch range overflows"))?;
        if end > bytes.len() {
            bail!("patch at {} extends past the input", patch.offset.to_hex());
        }
        bytes[start..end].copy_from_slice(&patch.bytes);
    }
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// Consistent materialization
// ---------------------------------------------------------------------------

/// One command's view of the project's *metadata*.
///
/// Capturing the picture up front is what makes the later write safe:
/// computation never observes a partially updated database, and the publish
/// step can compare the revision it planned against. Stored analysis artifacts
/// — instructions, CFGs, xrefs, strings, rendered text — are deliberately *not*
/// part of it: they are read per batch, only for the owners a command actually
/// touches. A list query therefore no longer pays for the whole project's
/// artifacts.
struct AnalysisSnapshot {
    revision: Revision,
    engine: [u8; 32],
    /// SHA-256 of the stored original input, for the index unit's fingerprint.
    /// Read from the source metadata instead of re-hashing the bytes.
    source_sha256: [u8; 32],
    image: ImageInfo,
    scope: AnalysisScope,
    /// Execution view of [`Self::scope`] (merged, sorted intervals).
    scope_map: ScopeMap,
    /// Effective bytes of the whole original input (patches applied).
    effective: Vec<u8>,
    image_start: usize,
    image_len: usize,
    /// Every function row, including absent/suppressed ones, by address.
    functions: Vec<FunctionRow>,
    function_index: BTreeMap<Address, usize>,
    /// Only `ItemKind::Data` rows, ordered by address.
    data_items: Vec<ItemRow>,
    /// Every symbol alias, ordered by `(address, name)` like the store reader.
    symbols: Vec<SymbolInfo>,
    /// First symbol at each address: the store's display preference.
    preferred_symbols: BTreeMap<Address, SymbolInfo>,
    names: BTreeMap<Address, String>,
    annotations: Vec<(Address, AnnotationKind, String)>,
    function_overrides: BTreeMap<Address, FunctionOverrideRow>,
    variable_overrides: Vec<hexray_db::VariableOverrideRow>,
    types: Vec<TypeRow>,
    /// Every analysis unit, keyed by owner. The full row is kept because the
    /// reuse decision needs the engine fingerprint and dependency completeness,
    /// not just the state.
    units: BTreeMap<UnitKey, hexray_db::AnalysisUnitRow>,
    builtin_types_json: Option<String>,
    /// Stored split-DWARF sidecars, in import order.
    dwarf_sidecars: Vec<Vec<u8>>,
}

impl AnalysisSnapshot {
    /// Bytes of the selected image inside the effective source.
    fn image_bytes(&self) -> &[u8] {
        &self.effective[self.image_start..self.image_start + self.image_len]
    }

    fn function(&self, address: Address) -> Option<&FunctionRow> {
        self.function_index
            .get(&address)
            .map(|index| &self.functions[*index])
    }

    fn name_at(&self, address: Address) -> Option<&str> {
        self.names.get(&address).map(String::as_str)
    }

    fn unit_state(&self, key: &UnitKey) -> Option<AnalysisState> {
        self.units.get(key).map(|unit| unit.state)
    }

    fn unit_generation(&self, key: &UnitKey) -> Option<u64> {
        self.units.get(key).map(|unit| unit.generation)
    }

    fn comment_overlay(&self) -> CommentOverlay {
        CommentOverlay::from_pairs(
            self.annotations
                .iter()
                .filter(|(_, kind, _)| *kind == AnnotationKind::Comment)
                .map(|(address, _, text)| (address.0, text.clone()))
                .collect(),
        )
    }

    /// Range of a user data item covering `address`.
    ///
    /// Only *data* items are indexed, and user data items are a small,
    /// hand-authored set, so this stays a scan over that set rather than an
    /// interval tree the project does not need.
    fn data_item_at(&self, address: u64) -> Option<&ItemRow> {
        self.data_items.iter().find(|item| {
            address >= item.address.0 && address < item.address.0.saturating_add(item.length)
        })
    }

    /// Resolve a user-supplied function reference (address or unique name).
    fn resolve(&self, text: &str) -> Result<Address> {
        if let Ok(address) = parse_address(text) {
            if self.function_index.contains_key(&address) {
                return Ok(address);
            }
            bail!("no function at {}", address.to_hex());
        }

        let mut unique: BTreeSet<u64> = BTreeSet::new();
        for (address, name) in &self.names {
            if name == text {
                unique.insert(address.0);
            }
        }
        for symbol in &self.symbols {
            if symbol.name == text {
                unique.insert(symbol.address.0);
            }
        }
        if unique.len() > 1 {
            let listed: Vec<String> = unique
                .iter()
                .map(|address| Address(*address).to_hex())
                .collect();
            bail!(
                "name '{text}' matches several addresses: {}; use an address",
                listed.join(", ")
            );
        }
        match unique.pop_first() {
            Some(address) => Ok(Address(address)),
            None => bail!("no function named '{text}'"),
        }
    }

    fn display_name(&self, function: &FunctionRow) -> String {
        if let Some(name) = self.name_at(function.address) {
            return name.to_string();
        }
        if let Some(symbol) = self.preferred_symbols.get(&function.address) {
            return hexray_demangle::demangle_or_original(&symbol.name).to_string();
        }
        format!("sub_{:x}", function.address.0)
    }
}

fn load_snapshot(database: &mut Database) -> Result<AnalysisSnapshot> {
    #[cfg(test)]
    cache_counters::SNAPSHOT_BUILDS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let snapshot = database.snapshot()?;
    let revision = snapshot.data_revision();
    let engine = snapshot.engine_fingerprint();
    let source_sha256 = db(snapshot.source_sha256())?;
    let patches = db(snapshot.patches())?;
    let image = db(snapshot.image())?;
    let scope = db(snapshot.scope())?;
    let functions = db(snapshot.functions_with_state(true))?;
    let items = db(snapshot.items())?;
    let symbols = db(snapshot.symbols())?;
    let names = db(snapshot.names())?;
    let annotations = db(snapshot.annotations())?;
    let function_overrides = db(snapshot.function_overrides())?;
    let variable_overrides = db(snapshot.variable_overrides())?;
    let types = db(snapshot.types())?;
    let type_snapshot = db(snapshot.resource("type_snapshot", "builtin"))?;
    let builtin_types_json = type_snapshot
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .map(str::to_string);
    let mut dwarf_sidecars = Vec::new();
    for name in db(snapshot.resource_names("dwarf_sidecar"))? {
        if let Some(bytes) = db(snapshot.resource("dwarf_sidecar", &name))? {
            dwarf_sidecars.push(bytes);
        }
    }
    let unit_rows = db(snapshot.all_units())?;

    let mut units = BTreeMap::new();
    for unit in unit_rows {
        units.insert(unit.key, unit);
    }

    let mut function_index = BTreeMap::new();
    for (index, function) in functions.iter().enumerate() {
        function_index.insert(function.address, index);
    }
    let data_items: Vec<ItemRow> = items
        .iter()
        .filter(|item| item.kind == ItemKind::Data)
        .cloned()
        .collect();
    let mut preferred_symbols: BTreeMap<Address, SymbolInfo> = BTreeMap::new();
    for symbol in &symbols {
        preferred_symbols
            .entry(symbol.address)
            .or_insert_with(|| symbol.clone());
    }
    let names: BTreeMap<Address, String> = names.into_iter().collect();
    let function_overrides: BTreeMap<Address, FunctionOverrideRow> =
        function_overrides.into_iter().collect();

    let effective = effective_source(&db(snapshot.source_bytes())?, &patches)?;
    let image_start = usize::try_from(image.container_offset.0)
        .map_err(|_| anyhow::anyhow!("image offset is out of range"))?;
    let image_len = usize::try_from(image.container_length)?;
    let image_end = image_start
        .checked_add(image_len)
        .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
    if image_end > effective.len() {
        bail!("stored image range exceeds the stored input");
    }

    Ok(AnalysisSnapshot {
        revision,
        engine,
        source_sha256,
        scope_map: ScopeMap::from_scope(&scope),
        scope,
        image,
        effective,
        image_start,
        image_len,
        functions,
        function_index,
        data_items,
        symbols,
        preferred_symbols,
        names,
        annotations,
        function_overrides,
        variable_overrides,
        types,
        units,
        builtin_types_json,
        dwarf_sidecars,
    })
}

fn selection_from_image(image: &ImageInfo) -> ImageSelection {
    ImageSelection {
        container_kind: hexray_db::ContainerKind::Elf,
        container_offset: image.container_offset.0,
        container_length: image.container_length,
        member_name: image.member_name.clone(),
        member_index: image.member_index,
        slice_label: image.slice_label.clone(),
        selector_json: image.selector_json.clone(),
    }
}

// ---------------------------------------------------------------------------
// Address and function resolution
// ---------------------------------------------------------------------------

fn parse_address(text: &str) -> Result<Address> {
    let trimmed = text.trim();
    let stripped = trimmed.strip_prefix("sub_").unwrap_or(trimmed);
    let stripped = stripped
        .strip_prefix("0x")
        .or_else(|| stripped.strip_prefix("0X"))
        .unwrap_or(stripped);
    u64::from_str_radix(stripped, 16)
        .map(Address)
        .map_err(|_| anyhow::anyhow!("'{text}' is neither an address nor a numeric symbol"))
}

/// Resolve a user-supplied function reference against the database only.
///
/// The pure read path uses this instead of materializing every name and symbol
/// row: two bound lookups answer the question, and the ambiguity check still
/// spans user names *and* symbol aliases.
fn resolve_function_reads(snapshot: &hexray_db::ReadSnapshot<'_>, text: &str) -> Result<Address> {
    if let Ok(address) = parse_address(text) {
        if db(snapshot.function_at(address))?.is_some() {
            return Ok(address);
        }
        bail!("no function at {}", address.to_hex());
    }

    let mut unique: BTreeSet<u64> = BTreeSet::new();
    for address in db(snapshot.addresses_for_name(text))? {
        unique.insert(address.0);
    }
    for address in db(snapshot.addresses_for_symbol(text))? {
        unique.insert(address.0);
    }
    if unique.len() > 1 {
        let listed: Vec<String> = unique
            .iter()
            .map(|address| Address(*address).to_hex())
            .collect();
        bail!(
            "name '{text}' matches several addresses: {}; use an address",
            listed.join(", ")
        );
    }
    match unique.pop_first() {
        Some(address) => Ok(Address(address)),
        None => bail!("no function named '{text}'"),
    }
}

/// Display name for a row, resolved from the batched name/symbol maps.
fn display_name_from_maps(
    names: &BTreeMap<Address, String>,
    symbols: &BTreeMap<Address, SymbolInfo>,
    function: &FunctionRow,
) -> String {
    if let Some(name) = names.get(&function.address) {
        return name.clone();
    }
    if let Some(symbol) = symbols.get(&function.address) {
        return hexray_demangle::demangle_or_original(&symbol.name).to_string();
    }
    format!("sub_{:x}", function.address.0)
}

fn function_limit(function: &FunctionRow) -> (usize, bool) {
    match function.declared_end {
        Some(end) if end.0 > function.address.0 => (
            usize::try_from(end.0 - function.address.0).unwrap_or(4096),
            function.bounds_origin == BoundsOrigin::Heuristic,
        ),
        _ => (4096, true),
    }
}

// ---------------------------------------------------------------------------
// `db input-info`
// ---------------------------------------------------------------------------

fn input_info(
    binary: &Path,
    selection: &Selection,
    section_hints: bool,
    json_output: bool,
) -> Result<()> {
    let images = describe_images(binary, selection)?;
    if !section_hints {
        if json_output {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "path": binary.to_string_lossy(),
                    "images": images,
                }))?
            );
            return Ok(());
        }
        println!("Selectable images in {}", binary.display());
        if images.is_empty() {
            println!("  none (unsupported input)");
        }
        for image in &images {
            println!("  {image}");
        }
        return Ok(());
    }

    // Hints are per *image*: an archive without a selected member and a fat
    // container without a selected slice have no sections to measure. The
    // selection step reports exactly what to pass, so listing the candidates
    // is the whole answer there.
    let loaded = match select_input(binary, selection, &InputLimits::default()) {
        Ok(loaded) => loaded,
        Err(error) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "path": binary.to_string_lossy(),
                        "images": images,
                        "error": format!("{error}"),
                    }))?
                );
            } else {
                println!("Selectable images in {}", binary.display());
                for image in &images {
                    println!("  {image}");
                }
                println!("note: {error}");
            }
            return Ok(());
        }
    };
    let image_bytes = {
        let start = usize::try_from(loaded.selection.container_offset)?;
        let end = start
            .checked_add(usize::try_from(loaded.selection.container_length)?)
            .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
        loaded
            .source
            .get(start..end)
            .ok_or_else(|| anyhow::anyhow!("selected image extends past the input"))?
    };
    let parsed = parse_image(image_bytes, &loaded.selection)?;
    let hints = section_hints_for(&parsed.binary, &parsed.info);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": binary.to_string_lossy(),
                "format": parsed.info.format,
                "architecture": parsed.info.architecture,
                "sections": hints,
                "warning": SECTION_HINTS_WARNING,
            }))?
        );
        return Ok(());
    }
    println!("Input: {}", binary.display());
    print_section_hints(&parsed.info, &hints);
    Ok(())
}

// ---------------------------------------------------------------------------
// `db create`
// ---------------------------------------------------------------------------

/// True when a stored section carries executable code.
fn is_executable_section(section: &SectionInfo) -> bool {
    section.flags.contains('X')
}

/// Resolve `--skip-section`/`--skip-range` flags against one image.
///
/// Section names match exactly, and *every* section with that name is excluded.
/// A section with no file-backed bytes carries no code, so it is rejected
/// rather than turned into an empty range with an invented file offset. An
/// explicit range must be non-empty, must not overflow, and must intersect a
/// loaded mapping.
fn resolve_scope(image: &ImageInfo, flags: &ScopeFlags) -> Result<AnalysisScope> {
    if flags.is_empty() {
        return Ok(AnalysisScope::empty());
    }
    let mut ranges: Vec<ScopeRange> = Vec::new();
    for name in &flags.skip_sections {
        let matches: Vec<&SectionInfo> = image
            .sections
            .iter()
            .filter(|section| section.name == *name)
            .collect();
        if matches.is_empty() {
            let mut available: Vec<&str> = image
                .sections
                .iter()
                .filter(|section| is_executable_section(section) && section.memory_size > 0)
                .map(|section| section.name.as_str())
                .collect();
            available.sort_unstable();
            available.dedup();
            let listed = if available.is_empty() {
                "(none)".to_string()
            } else {
                available.join(", ")
            };
            bail!("no section named '{name}' in this image; executable sections are: {listed}");
        }
        for section in matches {
            if !is_executable_section(section) {
                bail!(
                    "section '{}' at {} is not executable; only executable sections can be skipped",
                    section.name,
                    section.va.to_hex()
                );
            }
            if section.file_size == 0 || section.memory_size == 0 {
                bail!(
                    "section '{}' at {} has no file-backed bytes, so there is no code to exclude",
                    section.name,
                    section.va.to_hex()
                );
            }
            let end = section.va.0.checked_add(section.memory_size).ok_or_else(|| {
                anyhow::anyhow!(
                    "section '{}' range overflows the address space",
                    section.name
                )
            })?;
            ranges.push(ScopeRange {
                start: section.va,
                end: Address(end),
                section_name: Some(section.name.clone()),
            });
        }
    }
    for text in &flags.skip_ranges {
        let (start, end) = crate::analysis_scope::parse_skip_range(text)?;
        ranges.push(ScopeRange {
            start: Address(start),
            end: Address(end),
            section_name: None,
        });
    }
    for range in &ranges {
        let mapped = image.mappings.iter().any(|mapping| {
            mapping.va.0 < range.end.0
                && range.start.0 < mapping.va.0.saturating_add(mapping.memory_size)
        });
        if !mapped {
            bail!(
                "analysis scope range {}..{} is not mapped in this image",
                range.start.to_hex(),
                range.end.to_hex()
            );
        }
    }
    ranges.sort_by_key(|range| (range.start.0, range.end.0, range.section_name.clone()));
    let scope = AnalysisScope {
        payload_version: AnalysisScope::CURRENT_PAYLOAD_VERSION,
        excluded_ranges: ranges,
    };
    scope.validate()?;
    Ok(scope)
}

fn create(
    binary: &Path,
    output: &Path,
    selection: &Selection,
    limits: &InputLimits,
    scope_flags: &ScopeFlags,
    exec: &AnalysisExecutionOptions,
    json_output: bool,
) -> Result<()> {
    let loaded = select_input(binary, selection, limits)?;
    let staged = {
        let parent = output
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        std::fs::create_dir_all(&parent).ok();
        let image_bytes = {
            let start = usize::try_from(loaded.selection.container_offset)?;
            let end = start
                .checked_add(usize::try_from(loaded.selection.container_length)?)
                .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
            loaded.source[start..end].to_vec()
        };
        let parsed = parse_image(&image_bytes, &loaded.selection)?;
        let scope = resolve_scope(&parsed.info, scope_flags)?;
        let mut input = build_create_input(binary, &loaded, &parsed, &scope)?;
        let engine = engine_fingerprint();
        input.engine_fingerprint = engine;
        let mut staged = db(hexray_db::store::StagedProject::create(&parent, &input))?;
        drop(parsed);
        store_debug_sidecars(staged.database(), selection)?;

        // First analysis pass: whole-image discovery, no pseudo-C yet.
        let report = run_analysis(
            staged.database(),
            &AnalyzeRequest {
                function: None,
                force: true,
                render: None,
                limits: limits.clone(),
                exec: exec.clone(),
            },
        )?;
        if report.partial > 0 {
            eprintln!(
                "note: {} function(s) were only partially analyzed; re-run `db analyze` to continue",
                report.partial
            );
        }
        staged
    };

    let database = db(staged.publish(output))?;
    let revision = db(database.revision())?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "database": output.to_string_lossy(),
                "revision": revision.0,
                "stored_input": binary.to_string_lossy(),
            }))?
        );
    } else {
        println!(
            "Created {} (revision {}, input {})",
            output.display(),
            revision.0,
            binary.display()
        );
    }
    Ok(())
}

/// Capture authorized split-DWARF sidecars into the project so a reopened
/// database never searches the filesystem.
fn store_debug_sidecars(database: &mut Database, selection: &Selection) -> Result<usize> {
    let mut stored = 0usize;
    for path in &selection.debug_files {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("failed to stat --debug-file {}", path.display()))?;
        if metadata.len() > MAX_PAYLOAD_BYTES as u64 {
            bail!(
                "--debug-file {} is larger than the {MAX_PAYLOAD_BYTES} byte payload limit",
                path.display()
            );
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read --debug-file {}", path.display()))?;
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| format!("sidecar-{stored}"));
        db(database.put_resource("dwarf_sidecar", &name, &bytes))?;
        stored += 1;
    }
    Ok(stored)
}

fn build_create_input(
    original_path: &Path,
    loaded: &LoadedInput,
    parsed: &ParsedImage<'_>,
    scope: &AnalysisScope,
) -> Result<CreateInput> {
    let fmt = parsed.binary.as_format();
    let relocation_table = crate::build_relocation_table(&parsed.binary);
    let symbols: Vec<SymbolInfo> =
        crate::collect_analysis_symbols(&parsed.binary, &relocation_table)
            .into_iter()
            .map(|symbol| SymbolInfo {
                address: Address(symbol.address),
                name: symbol.name.clone(),
                kind: format!("{:?}", symbol.kind).to_ascii_lowercase(),
                size: symbol.size,
                origin: SymbolOrigin::Loader,
            })
            .collect();

    let functions = discover_functions(&parsed.binary);
    let strings = detect_strings(fmt);
    let builtin = builtin_type_database(&parsed.binary, parsed.info.abi)?;

    Ok(CreateInput {
        original_path: original_path.to_path_buf(),
        source_bytes: loaded.source.clone(),
        container_kind: loaded.selection.container_kind,
        image: parsed.info.clone(),
        engine_fingerprint: [0u8; 32],
        symbols,
        functions,
        strings,
        xrefs: Vec::new(),
        builtin_types_json: serde_json::to_string(&builtin).ok(),
        analysis_scope: scope.clone(),
        diagnostics: Vec::new(),
    })
}

/// Decode one GPU kernel with its architecture decoder.
///
/// GPU objects have no CPU analysis path: there is no CFG builder, callgraph
/// walk or parameter recovery here, so the caller stores the decoded stream
/// as a single straight-line block. An empty result is not an error; the
/// caller publishes an `unsupported` unit with a diagnostic instead.
fn decode_gpu_function(
    binary: &Binary<'_>,
    start: u64,
    max_bytes: usize,
) -> Result<Vec<Instruction>> {
    let fmt = binary.as_format();
    let Some(bytes) = fmt.bytes_at(start, max_bytes) else {
        return Ok(Vec::new());
    };
    let mut instructions: Vec<Instruction> =
        crate::disassemble_block_for_arch(fmt.architecture(), bytes, start)
            .into_iter()
            .filter_map(|decoded| decoded.ok())
            .collect();
    instructions.sort_by_key(|instruction| instruction.address);
    Ok(instructions)
}

/// Seed set for GPU code objects: the entry point, every defined symbol that
/// lands in an executable section, and — for CUBINs — the marked entry
/// kernels.
///
/// The symbol kind is deliberately not filtered: CUDA `.text.*` kernels and
/// HSA kernel symbols (`STT_AMDGPU_HSA_KERNEL`, reported as `Other`) are the
/// metadata this discovery set exists for. There is no call-target walk on
/// this path.
fn gpu_function_starts(binary: &Binary<'_>) -> Vec<(u64, u64)> {
    let fmt = binary.as_format();
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts: Vec<(u64, u64)> = Vec::new();
    if let Some(entry) = fmt.entry_point() {
        if entry != 0 {
            starts.push((entry, 0));
        }
    }
    for symbol in &symbols {
        if !symbol.is_defined() || symbol.address == 0 {
            continue;
        }
        if !is_executable(fmt, symbol.address) {
            continue;
        }
        starts.push((symbol.address, symbol.size));
    }
    if let Binary::Elf(elf) = binary {
        if let Ok(view) = elf.cubin_view() {
            for kernel in view.entry_kernels() {
                let address = kernel
                    .symbol
                    .map(|symbol| symbol.address)
                    .filter(|address| *address != 0)
                    .unwrap_or_else(|| kernel.section.virtual_address());
                if address != 0 {
                    starts.push((address, kernel.size));
                }
            }
        }
    }
    starts.sort_by_key(|(address, _)| *address);
    starts.dedup_by_key(|(address, _)| *address);
    starts
}

/// Row for a GPU function. Unlike [`function_row_for`] there is no symbol-kind
/// filter, so an unknown-size kernel keeps `declared_end: None` rather than
/// pretending a size.
fn gpu_function_row(
    binary: &Binary<'_>,
    existing: Option<&FunctionRow>,
    address: u64,
    size: u64,
) -> FunctionRow {
    if let Some(existing) = existing {
        if existing.origin == FunctionOrigin::User {
            return existing.clone();
        }
    }
    FunctionRow {
        address: Address(address),
        declared_end: (size > 0).then(|| Address(address.saturating_add(size))),
        bounds_origin: if size > 0 {
            BoundsOrigin::Symbol
        } else if Some(address) == binary.as_format().entry_point() {
            BoundsOrigin::Entry
        } else {
            BoundsOrigin::Heuristic
        },
        origin: FunctionOrigin::Auto,
        excluded: false,
        user_removed: false,
        present: true,
    }
}

/// Initial discovery, using the same start set the callgraph analysis uses.
fn discover_functions(binary: &Binary<'_>) -> Vec<FunctionRow> {
    let fmt = binary.as_format();
    if !supports_pseudo_c(fmt.architecture()) {
        return gpu_function_starts(binary)
            .into_iter()
            .map(|(address, size)| gpu_function_row(binary, None, address, size))
            .collect();
    }
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts = crate::discover_function_starts(fmt, fmt.architecture(), &symbols, None);
    starts.sort_by_key(|(address, _, _)| *address);
    starts.dedup_by_key(|(address, _, _)| *address);

    starts
        .into_iter()
        .map(|(address, size, heuristic)| {
            let _ = size;
            let symbol = symbols
                .iter()
                .find(|symbol| symbol.address == address && symbol.is_function());
            FunctionRow {
                address: Address(address),
                declared_end: symbol
                    .filter(|symbol| symbol.size > 0)
                    .map(|symbol| Address(address.saturating_add(symbol.size))),
                bounds_origin: if symbol.is_some_and(|symbol| symbol.size > 0) {
                    BoundsOrigin::Symbol
                } else if Some(address) == fmt.entry_point() {
                    BoundsOrigin::Entry
                } else {
                    let _ = heuristic;
                    BoundsOrigin::Heuristic
                },
                origin: FunctionOrigin::Auto,
                excluded: false,
                user_removed: false,
                present: true,
            }
        })
        .collect()
}

/// Snapshot of the built-in type library, pinned into the project so a later
/// tool upgrade cannot change what an existing project means.
fn builtin_type_database(binary: &Binary<'_>, abi: hexray_db::AbiInfo) -> Result<TypeDatabase> {
    let mut database = match crate::load_type_database(binary, Some("auto"))? {
        Some(database) => (*database).clone(),
        None => TypeDatabase::new(),
    };
    database.set_arch(abi.to_arch_info());
    Ok(database)
}

fn detect_strings(fmt: &dyn BinaryFormat) -> Vec<StringRow> {
    let detector = hexray_analysis::StringDetector::with_config(hexray_analysis::StringConfig {
        min_length: 4,
        ..Default::default()
    });
    let mut out = Vec::new();
    for section in fmt.sections() {
        let data = section.data();
        if data.is_empty() {
            continue;
        }
        for detected in detector.detect(data, section.virtual_address()) {
            let encoding = match detected.encoding {
                hexray_analysis::StringEncoding::Ascii => StringEncoding::Ascii,
                hexray_analysis::StringEncoding::Utf8 => StringEncoding::Utf8,
                hexray_analysis::StringEncoding::Utf16Le => StringEncoding::Utf16Le,
                hexray_analysis::StringEncoding::Utf16Be => StringEncoding::Utf16Be,
            };
            out.push(StringRow {
                address: Address(detected.address),
                encoding,
                bytes: detected.content.as_bytes().to_vec(),
                text: Some(detected.content.clone()),
            });
        }
    }
    out.sort_by_key(|row| (row.address.0, row.encoding.as_str()));
    out
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// What to analyze.
struct AnalyzeRequest {
    /// Restrict to one function; `None` means every stale or missing function.
    function: Option<String>,
    /// Recompute even when stored results are current.
    force: bool,
    /// Also generate pseudo-C with this configuration.
    render: Option<RenderConfig>,
    limits: InputLimits,
    exec: AnalysisExecutionOptions,
}

impl AnalyzeRequest {
    fn new() -> Self {
        Self {
            function: None,
            force: false,
            render: None,
            limits: InputLimits::default(),
            exec: AnalysisExecutionOptions::default(),
        }
    }
}

/// What one analysis run did.
#[derive(Debug, Default)]
struct AnalyzeReport {
    discovered: usize,
    analyzed: usize,
    reused: usize,
    partial: usize,
    unsupported: usize,
    failed: usize,
    rendered: usize,
    reused_render: usize,
    stale_skipped: usize,
    /// Live functions whose entry the analysis scope excludes.
    skipped_scope: usize,
    timings: Option<StageTimings>,
}

/// Wall time per stage, plus the concurrency the run actually used.
///
/// Written to stderr by `--timings` and into `--json` output. Never stored in
/// the database, never part of a fingerprint: timings must not change what the
/// engine computes.
#[derive(Debug, Default, Clone)]
struct StageTimings {
    load_ms: u128,
    context_ms: u128,
    discovery_ms: u128,
    cfg_ms: u128,
    render_ms: u128,
    publish_ms: u128,
    total_ms: u128,
    requested_jobs: usize,
    effective_jobs: usize,
    worker_stack_mib: u64,
    analyzed: usize,
    reused: usize,
    failed: usize,
    max_in_flight: usize,
    decodes: usize,
    decode_hits: usize,
    skipped_scope: usize,
    /// Excluded address ranges the automatic chain did not decode.
    skipped_bytes: u64,
}

impl StageTimings {
    fn to_json(&self) -> serde_json::Value {
        json!({
            "load_ms": self.load_ms,
            "context_ms": self.context_ms,
            "discovery_ms": self.discovery_ms,
            "cfg_ms": self.cfg_ms,
            "render_ms": self.render_ms,
            "publish_ms": self.publish_ms,
            "total_ms": self.total_ms,
            "requested_jobs": self.requested_jobs,
            "effective_jobs": self.effective_jobs,
            "worker_stack_mib": self.worker_stack_mib,
            "analyzed": self.analyzed,
            "reused": self.reused,
            "failed": self.failed,
            "max_in_flight": self.max_in_flight,
            "decodes": self.decodes,
            "decode_hits": self.decode_hits,
            "skipped_scope": self.skipped_scope,
            "skipped_bytes": self.skipped_bytes,
        })
    }

    fn print(&self) {
        // stderr: `--timings` is a diagnostic channel and must never change
        // stdout, which callers may be piping into another tool.
        eprintln!(
            "timings: load={}ms context={}ms discovery={}ms cfg={}ms render={}ms publish={}ms total={}ms",
            self.load_ms,
            self.context_ms,
            self.discovery_ms,
            self.cfg_ms,
            self.render_ms,
            self.publish_ms,
            self.total_ms
        );
        eprintln!(
            "timings: jobs requested={} effective={} worker_stack={}MiB max_in_flight={} decodes={} hits={}",
            self.requested_jobs,
            self.effective_jobs,
            self.worker_stack_mib,
            self.max_in_flight,
            self.decodes,
            self.decode_hits
        );
        eprintln!(
            "timings: analyzed={} reused={} failed={} skipped_scope={} skipped_bytes={}",
            self.analyzed, self.reused, self.failed, self.skipped_scope, self.skipped_bytes
        );
    }
}

fn project_type_database(
    snapshot: &AnalysisSnapshot,
    binary: &Binary<'_>,
) -> Result<Arc<TypeDatabase>> {
    let _ = binary;
    Ok(Arc::new(build_type_database(
        snapshot.builtin_types_json.as_deref(),
        &snapshot.types,
        &snapshot.image,
    )?))
}

/// Build the effective type database from the stored builtin snapshot plus the
/// user's imported types. ABI facts come from the stored image, so neither the
/// input file nor the image bytes are needed.
fn build_type_database(
    builtin_types_json: Option<&str>,
    types: &[TypeRow],
    image: &ImageInfo,
) -> Result<TypeDatabase> {
    let mut database = match builtin_types_json {
        Some(json) => TypeDatabase::from_json(json)
            .map_err(|error| anyhow::anyhow!("stored type snapshot is unreadable: {error}"))?,
        None => TypeDatabase::new(),
    };
    database.set_arch(image.abi.to_arch_info());

    for row in types {
        let parsed = serde_json::from_str::<hexray_types::CType>(&row.payload_json);
        match (row.kind, parsed) {
            (TypeKind::Prototype, _) => {
                if let Ok(prototype) =
                    serde_json::from_str::<hexray_types::FunctionPrototype>(&row.payload_json)
                {
                    database.add_function(prototype);
                }
            }
            (TypeKind::Typedef, Ok(ty)) => database.add_typedef(row.name.clone(), ty),
            (_, Ok(ty)) => database.add_type(row.name.clone(), ty),
            (_, Err(_)) => {}
        }
    }
    Ok(database)
}

/// Canonical digest of a type database, independent of hash iteration order.
fn type_snapshot_digest(database: &TypeDatabase) -> [u8; 32] {
    let mut canonical = String::new();
    let mut type_names: Vec<&str> = database.type_names().collect();
    type_names.sort_unstable();
    for name in type_names {
        if let Ok(json) = serde_json::to_string(&database.get_type(name)) {
            canonical.push_str(&format!("type {name} {json}\n"));
        }
    }
    let mut typedef_names: Vec<&str> = database.typedef_names().collect();
    typedef_names.sort_unstable();
    for name in typedef_names {
        if let Ok(json) = serde_json::to_string(&database.get_type(name)) {
            canonical.push_str(&format!("typedef {name} {json}\n"));
        }
    }
    let mut function_names: Vec<&str> = database.function_names().collect();
    function_names.sort_unstable();
    for name in function_names {
        if let Ok(json) = serde_json::to_string(&database.get_function(name)) {
            canonical.push_str(&format!("prototype {name} {json}\n"));
        }
    }
    hexray_db::sha256(canonical.as_bytes())
}

fn run_analysis(database: &mut Database, request: &AnalyzeRequest) -> Result<AnalyzeReport> {
    let started = std::time::Instant::now();
    let mut stage = StageTimings::default();
    let load_started = std::time::Instant::now();
    let snapshot = load_snapshot(database)?;
    stage.load_ms = load_started.elapsed().as_millis();
    let revision = snapshot.revision;
    let parsed = parse_image(
        snapshot.image_bytes(),
        &selection_from_image(&snapshot.image),
    )?;
    let binary = &parsed.binary;
    let fmt = binary.as_format();
    let mut report = AnalyzeReport::default();

    // One decode cache for the whole command: discovery, CFG analysis and
    // callee seeding all share it, so the same bytes are decoded once. It is
    // bounded by the analysis memory budget and evicts oldest-first, so holding
    // decodes across batches costs throughput far less than re-decoding callees.
    let mut decode = DecodeSession::with_budget(
        snapshot.scope_map.clone(),
        fmt.architecture(),
        request.exec.budget_bytes() as usize,
    );

    let context_started = std::time::Instant::now();
    let type_database = project_type_database(&snapshot, binary)?;
    let debug_info = load_project_dwarf(&snapshot, fmt)?;
    let name_pairs: Vec<(u64, String)> = snapshot
        .names
        .iter()
        .map(|(address, name)| (address.0, name.clone()))
        .collect();
    let shared = SharedAnalysisContext::build(
        binary,
        SharedTables {
            // The database already carries the user names; the `.hxproj`
            // overlay is a bare-file CLI feature.
            project: None,
            type_db: Some(&type_database),
            debug_info,
            names: &name_pairs,
            scope: Some(&snapshot.scope_map),
        },
    );
    stage.context_ms = context_started.elapsed().as_millis();

    let index_key = UnitKey::image_index();
    let index_current = snapshot.unit_state(&index_key) == Some(AnalysisState::Current);
    let need_discovery =
        request.force || !index_current || !snapshot.functions.iter().any(|f| f.is_live());

    let discovery_started = std::time::Instant::now();
    let mut discovery_truncated = false;
    let mut discovered: Vec<FunctionRow> = if need_discovery {
        let (functions, truncated) =
            discovery_pass(binary, &snapshot, &mut decode, MAX_DISCOVERED_FUNCTIONS)?;
        discovery_truncated = truncated;
        functions
    } else {
        snapshot.functions.clone()
    };
    discovered.sort_by_key(|row| row.address.0);
    report.discovered = discovered.iter().filter(|row| row.is_live()).count();
    stage.discovery_ms = discovery_started.elapsed().as_millis();

    let in_scope = |address: u64| snapshot.scope_map.contains(address);
    report.skipped_scope = discovered
        .iter()
        .filter(|row| row.is_live() && in_scope(row.address.0))
        .count();

    // Audit fingerprint: the source digest, plus the scope's canonical digest
    // when a scope is in force. An empty scope keeps the historical value, so a
    // project without exclusions stays byte-identical to the serial baseline.
    let index_fingerprint = if snapshot.scope.is_empty() {
        snapshot.source_sha256
    } else {
        let mut canonical = Vec::with_capacity(64);
        canonical.extend_from_slice(&snapshot.source_sha256);
        canonical.extend_from_slice(&snapshot.scope_map.fingerprint());
        hexray_db::sha256(&canonical)
    };

    if need_discovery {
        let symbols: Vec<SymbolInfo> =
            crate::collect_analysis_symbols(binary, &crate::build_relocation_table(binary))
                .into_iter()
                .map(|symbol| SymbolInfo {
                    address: Address(symbol.address),
                    name: symbol.name.clone(),
                    kind: format!("{:?}", symbol.kind).to_ascii_lowercase(),
                    size: symbol.size,
                    origin: SymbolOrigin::Loader,
                })
                .collect();
        let strings = detect_strings(fmt);
        let payload = ImageIndexPayload {
            functions: discovered.clone(),
            symbols,
            strings,
            xrefs: Vec::new(),
        };
        let function_count = discovered.iter().filter(|row| row.is_live()).count();
        // A GPU project can never reach `ready`: pseudo-C is unsupported, so
        // the index unit stays partial and `db info` never claims completion.
        // A scope-filtered project is partial for the same honest reason: the
        // excluded ranges were deliberately not analyzed.
        let gpu = !supports_pseudo_c(fmt.architecture());
        let scope_active = !snapshot.scope.is_empty();
        let mut diagnostics = Vec::new();
        if gpu {
            diagnostics.push(Diagnostic::new(
                "gpu-pseudo-c-unsupported",
                Severity::Info,
                "pseudo-C is unsupported for GPU code objects",
            ));
        }
        if scope_active {
            diagnostics.push(Diagnostic::new(
                "analysis-scope-filtered",
                Severity::Info,
                format!(
                    "analysis scope excludes {} known function(s); discovery covers the \
                     remaining ranges only",
                    report.skipped_scope
                ),
            ));
        }
        if discovery_truncated {
            diagnostics.push(Diagnostic::new(
                "discovery-truncated",
                Severity::Warning,
                format!(
                    "function discovery stopped at {MAX_DISCOVERED_FUNCTIONS}; the project is \
                     only partially discovered"
                ),
            ));
        }
        let unit = UnitPublish {
            key: index_key,
            expected_generation: snapshot.unit_generation(&index_key),
            // No discovered function is not a complete analysis either: report
            // it as partial so `db info` never claims a finished project.
            state: if gpu || function_count == 0 || scope_active || discovery_truncated {
                AnalysisState::Partial
            } else {
                AnalysisState::Current
            },
            input_fingerprint: index_fingerprint,
            dependencies_complete: true,
            diagnostics,
            dependencies: Vec::new(),
            payload: AnalysisPayload::ImageIndex(Box::new(payload)),
        };
        let publish_started = std::time::Instant::now();
        publish_batch(database, revision, &AnalysisBatch { units: vec![unit] })?;
        stage.publish_ms += publish_started.elapsed().as_millis();
    }

    // Which functions still need a decoded CFG?
    let in_scope = |address: u64| snapshot.scope_map.contains(address);
    report.skipped_scope = discovered
        .iter()
        .filter(|row| row.is_live() && in_scope(row.address.0))
        .count();
    let targets: Vec<Address> = match &request.function {
        Some(reference) => {
            let address = snapshot.resolve(reference)?;
            if in_scope(address.0) {
                bail!(
                    "function {} is excluded by analysis scope; change the scope first with `db edit <db> scope`",
                    address.to_hex()
                );
            }
            vec![address]
        }
        None => discovered
            .iter()
            .filter(|row| row.is_live() && !row.excluded && !in_scope(row.address.0))
            .map(|row| row.address)
            .collect(),
    };

    // One batched read answers "does this function still have instructions?"
    // instead of loading every function's payload.
    let with_instructions = {
        let read = db(database.snapshot())?;
        db(read.functions_with_instructions(&targets))?
    };
    let recorded_dependencies = {
        let read = db(database.snapshot())?;
        let keys: Vec<UnitKey> = targets
            .iter()
            .map(|address| UnitKey::function_cfg(*address))
            .collect();
        db(read.dependencies_for_units(&keys))?
    };

    let mut pending_cfg: Vec<Address> = Vec::new();
    for address in &targets {
        let Some(function) = snapshot.function(*address) else {
            continue;
        };
        let key = UnitKey::function_cfg(*address);
        if !request.force
            && reusable_unit(
                &snapshot,
                &key,
                &recorded_dependencies,
                with_instructions.contains(address),
            )
        {
            report.reused += 1;
            continue;
        }
        if snapshot.data_item_at(address.0).is_some()
            && function.origin == FunctionOrigin::Auto
        {
            // A user data definition is a hard barrier for automatic analysis.
            report.stale_skipped += 1;
            continue;
        }
        pending_cfg.push(*address);
        if pending_cfg.len() >= 10_000 {
            break;
        }
    }

    let signature_overrides = build_signature_overrides(&snapshot, fmt.architecture())?;
    let variable_overrides = build_variable_overrides(&snapshot, &discovered);

    // Plan batches: bounded by function count and by the caller's working-set
    // budget. A function whose own estimate exceeds the whole budget runs
    // alone, serially, instead of being skipped.
    let payloads = {
        let read = db(database.snapshot())?;
        db(read.payload_bytes_for_functions(&pending_cfg))?
    };
    let budget = request.exec.budget_bytes();
    let mut solo: BTreeSet<Address> = BTreeSet::new();
    let batches = plan_batches(&pending_cfg, &snapshot, &payloads, budget, &mut solo);
    let requested_jobs = request.exec.requested_jobs();
    // The pool is sized by what the batches can actually use: never more
    // workers than a batch has functions, and never more than the working-set
    // budget covers at the per-function floor.
    let analysis_jobs = batches
        .iter()
        .map(|batch| request.exec.effective_jobs(batch.len()))
        .max()
        .unwrap_or(1)
        .min(requested_jobs);
    let effective_jobs = if request.render.is_some() {
        // The render stage reuses this pool, and its pending set is empty in the
        // common "analyze, then --render" flow: size it from the render targets
        // too, or all decompilation runs on the CLI thread.
        analysis_jobs.max(request.exec.effective_jobs(targets.len().max(1)))
    } else {
        analysis_jobs
    };
    let pool = if effective_jobs > 1 {
        Some(build_worker_pool(effective_jobs)?)
    } else {
        None
    };
    let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let batched: BTreeSet<Address> = batches.iter().flatten().copied().collect();
    // Owners already republished by an earlier batch: their generation is one
    // ahead of the command-start snapshot.
    let mut republished_targets: BTreeSet<Address> = BTreeSet::new();
    let cfg_started = std::time::Instant::now();
    for batch in &batches {
        // A batch reads the generations it will compare against from the same
        // snapshot, after every earlier batch has committed.
        let (generations, content_moved) = {
            let read = db(database.snapshot())?;
            let mut generations = BTreeMap::new();
            for address in batch {
                generations.insert(
                    *address,
                    db(read.analysis_generation(&UnitKey::function_cfg(*address)))?,
                );
            }
            (generations, read.data_revision() != revision)
        };
        if content_moved {
            bail!(
                "the project changed while analysis was running; re-run the command (revision {} is no longer head)",
                revision.0
            );
        }

        let single = batch.len() == 1;
        let original = *batch
            .iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("empty analysis batch"))?;
        let run_alone = single && solo.contains(&original);

        // Serial pre-decode: exactly one decode per distinct window, and the
        // callees of these functions are decoded before any worker runs so no
        // two workers can decode the same callee. A decode failure is not fatal:
        // it becomes this owner's `failed` unit, exactly like the serial
        // baseline, so one unreadable function cannot abort the whole project.
        let mut prepared: Vec<(Address, PreparedDecode)> = Vec::with_capacity(batch.len());
        let gpu = !supports_pseudo_c(fmt.architecture());
        if !gpu {
            for address in batch {
                let Some(function) = snapshot.function(*address) else {
                    continue;
                };
                let (max_bytes, stop_after_first_return) = function_limit(function);
                match decode.decode(binary, address.0, max_bytes, stop_after_first_return) {
                    Ok(decoded) => prepared.push((*address, PreparedDecode::Decoded(decoded))),
                    Err(error) => {
                        prepared.push((*address, PreparedDecode::Unavailable(format!("{error}"))))
                    }
                }
            }
            let mut callees: BTreeSet<u64> = BTreeSet::new();
            for (_, prepared) in &prepared {
                let PreparedDecode::Decoded(decoded) = prepared else {
                    continue;
                };
                // Scan the same instructions the workers analyze. The raw
                // decode still carries the PLT stub for a PLT32-relocated
                // internal call; applying the relocations here resolves it to
                // the real callee, which the stub filter would otherwise drop
                // and every worker would then decode locally.
                let mut relocated = decoded.instructions.to_vec();
                crate::apply_call_relocations(&mut relocated, &shared.relocation_table);
                for (target, _) in crate::extract_internal_call_targets(&relocated, fmt) {
                    if !callees.insert(target) || in_scope(target) {
                        continue;
                    }
                    let info = crate::decompile_target_info_for_address(fmt, None, target);
                    // A failing callee is not fatal here: the seed pass retries
                    // and skips it exactly like the baseline did.
                    let _ = decode.decode_callee(
                        binary,
                        target,
                        info.max_bytes,
                        info.stop_after_first_return,
                    );
                }
            }
        } else {
            for address in batch {
                prepared.push((*address, PreparedDecode::Gpu));
            }
        }

        let compute_one = |(address, prepared): &(Address, PreparedDecode)| -> Result<ComputedFunction> {
            let current = active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            max_active.fetch_max(current, std::sync::atomic::Ordering::SeqCst);
            let result = compute_function(
                binary,
                &snapshot,
                &shared,
                &signature_overrides,
                &variable_overrides,
                decode.table(),
                &snapshot.scope_map,
                *address,
                prepared,
            );
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            result
        };

        let results: Vec<Result<ComputedFunction>> = match &pool {
            Some(pool) if !run_alone && prepared.len() > 1 => {
                pool.install(|| prepared.par_iter().map(compute_one).collect::<Vec<_>>())
            }
            _ => prepared.iter().map(compute_one).collect(),
        };
        // Errors are surfaced on the main thread, in address order, so a
        // failing worker cannot interleave diagnostics with another one.
        let mut computed: Vec<ComputedFunction> = Vec::with_capacity(results.len());
        for result in results {
            computed.push(result?);
        }
        if run_alone {
            eprintln!(
                "warning: function {} exceeds analysis scratch estimate; running alone",
                original.to_hex()
            );
        }
        computed.sort_by_key(|unit| unit.address.0);

        let mut units: Vec<UnitPublish> = Vec::with_capacity(computed.len());
        // Signature dependencies must record the generation the target will have
        // *after this batch commits*: an earlier batch of the same command may
        // already have republished the callee, and a callee in this batch is
        // republished exactly once. Recording the command-start generation would
        // make the next `db analyze` consider the caller stale.
        let dependency_generations = {
            let mut targets: BTreeSet<u64> = BTreeSet::new();
            for unit in &computed {
                for dependency in &unit.dependencies {
                    if let Some(target) = signature_dependency_target(dependency) {
                        targets.insert(target);
                    }
                }
            }
            let mut generations_now: BTreeMap<u64, u64> = BTreeMap::new();
            if !targets.is_empty() {
                let read = db(database.snapshot())?;
                if read.data_revision() != revision {
                    return Err(anyhow::Error::new(DbError::RevisionConflict {
                        expected: revision.0,
                        actual: read.data_revision().0,
                    }));
                }
                for target in targets {
                    let current = db(read.analysis_generation(&UnitKey::function_cfg(Address(
                        target,
                    ))))?
                    .unwrap_or(0);
                    let target_address = Address(target);
                    // A target that this command will (re)publish — now or in a
                    // later batch — ends the command at current + 1. Using the
                    // snapshot value would make the next run recompute this
                    // caller.
                    let bumps = generations.contains_key(&target_address)
                        || (batched.contains(&target_address)
                            && !republished_targets.contains(&target_address));
                    generations_now.insert(target, if bumps { current + 1 } else { current });
                }
            }
            generations_now
        };
        for mut unit in computed {
            for dependency in &mut unit.dependencies {
                if let Some(target) = signature_dependency_target(dependency) {
                    if let Some(generation) = dependency_generations.get(&target) {
                        dependency.target_generation = *generation;
                    }
                }
            }
            if unit.state == AnalysisState::Current {
                report.analyzed += 1;
            } else if unit.state == AnalysisState::Unsupported {
                report.unsupported += 1;
            } else {
                report.failed += 1;
            }
            units.push(UnitPublish {
                key: UnitKey::function_cfg(unit.address),
                expected_generation: generations.get(&unit.address).copied().flatten(),
                state: unit.state,
                input_fingerprint: unit.hash,
                dependencies_complete: unit.dependencies_complete,
                diagnostics: unit.diagnostics,
                dependencies: unit.dependencies,
                payload: AnalysisPayload::FunctionCfg(Box::new(FunctionCfgPayload {
                    function: unit.function,
                    instructions: unit.instructions,
                    blocks: unit.blocks,
                    block_instructions: unit.block_instructions,
                    edges: unit.edges,
                    xrefs: unit.xrefs,
                })),
            });
        }
        if !units.is_empty() {
            let publish_started = std::time::Instant::now();
            // What this batch republishes decides the +1 bump for callees in
            // later batches, so take the addresses before the batch is moved.
            let published_now: Vec<Address> = units.iter().map(|unit| unit.key.key).collect();
            // A whole batch in one transaction: the orphan-instruction sweep
            // then runs once per batch, after every owner in it was replaced.
            publish_batch(database, revision, &AnalysisBatch { units })?;
            republished_targets.extend(published_now);
            stage.publish_ms += publish_started.elapsed().as_millis();
        }
    }
    stage.cfg_ms = cfg_started.elapsed().as_millis();

    if let Some(config) = &request.render {
        // The batches above replaced instructions and CFGs, so the rendering
        // pass must observe the state it will store into. It must also be the
        // *same* project revision: the shared context (names, types, DWARF) came
        // from the command's snapshot, so rendering against newer content would
        // store text that mixes two revisions.
        let refreshed = load_snapshot(database)?;
        if refreshed.revision != revision {
            return Err(anyhow::Error::new(DbError::RevisionConflict {
                expected: revision.0,
                actual: refreshed.revision.0,
            }));
        }
        let report_render = render_functions(
            database,
            &refreshed,
            &shared,
            &targets,
            config,
            request.force,
            request.exec.budget_bytes(),
            pool.as_ref(),
            &mut stage,
            &active,
            &max_active,
        )?;
        report.rendered = report_render.rendered;
        report.reused_render = report_render.reused;
        report.partial += report_render.partial;
        report.unsupported += report_render.unsupported;
    }

    stage.requested_jobs = requested_jobs;
    stage.effective_jobs = if pool.is_some() { effective_jobs } else { 1 };
    stage.worker_stack_mib = if pool.is_some() {
        (WORKER_STACK_BYTES / (1024 * 1024)) as u64
    } else {
        0
    };
    stage.max_in_flight = max_active.load(std::sync::atomic::Ordering::SeqCst);
    stage.analyzed = report.analyzed;
    stage.reused = report.reused;
    stage.failed = report.failed;
    stage.decodes = decode.decodes();
    stage.decode_hits = decode.hits();
    stage.skipped_scope = report.skipped_scope;
    stage.skipped_bytes = snapshot
        .scope_map
        .spans()
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum();
    stage.total_ms = started.elapsed().as_millis();
    if request.exec.timings {
        stage.print();
        report.timings = Some(stage);
    }

    Ok(report)
}

/// One function's computed artifacts, before publish bookkeeping.
///
/// Generations, engine fingerprints and transactions stay on the main thread:
/// a worker returns data only, never a publish decision.
struct ComputedFunction {
    address: Address,
    function: FunctionRow,
    state: AnalysisState,
    instructions: Vec<Instruction>,
    blocks: Vec<BlockPayload>,
    block_instructions: Vec<(u32, Vec<Address>)>,
    edges: Vec<(u32, u32, EdgeKind)>,
    xrefs: Vec<XrefRow>,
    diagnostics: Vec<Diagnostic>,
    dependencies: Vec<Dependency>,
    hash: [u8; 32],
    dependencies_complete: bool,
}

/// Function a `Signature` dependency refers to, from its `function:<hex>` key.
fn signature_dependency_target(dependency: &Dependency) -> Option<u64> {
    if dependency.kind != DependencyKind::Signature {
        return None;
    }
    dependency
        .key
        .strip_prefix("function:")
        .and_then(|text| u64::from_str_radix(text, 16).ok())
}

/// True when a stored CFG unit may be reused without recomputation.
///
/// A `Current` row alone is not enough: the unit must have been produced by
/// this engine, must have a complete dependency record, and every recorded
/// signature dependency must still point at the generation it was built from.
fn reusable_unit(
    snapshot: &AnalysisSnapshot,
    key: &UnitKey,
    recorded_dependencies: &BTreeMap<UnitKey, Vec<Dependency>>,
    has_instructions: bool,
) -> bool {
    let Some(unit) = snapshot.units.get(key) else {
        return false;
    };
    if unit.state != AnalysisState::Current
        || unit.engine_fingerprint != snapshot.engine
        || !unit.dependencies_complete
        || !has_instructions
    {
        return false;
    }
    let Some(dependencies) = recorded_dependencies.get(key) else {
        // No recorded dependency rows means nothing to verify; the unit was
        // published by this engine with complete bookkeeping.
        return true;
    };
    dependencies.iter().all(|dependency| {
        let Some(target) = signature_dependency_target(dependency) else {
            return true;
        };
        snapshot
            .unit_generation(&UnitKey::function_cfg(Address(target)))
            .unwrap_or(0)
            == dependency.target_generation
    })
}

/// Split the pending functions into publish batches.
///
/// Cost per function is its estimated in-flight scratch plus its expected
/// output payload. An unknown payload (never analyzed) is estimated at the
/// single-payload limit, which is the only defensible upper bound before the
/// first decode. A function that alone exceeds the budget is added as a
/// single-function batch and reported through `solo`.
fn plan_batches(
    pending: &[Address],
    snapshot: &AnalysisSnapshot,
    payloads: &BTreeMap<Address, hexray_db::store::PayloadBytes>,
    budget: u64,
    solo: &mut BTreeSet<Address>,
) -> Vec<Vec<Address>> {
    let mut batches: Vec<Vec<Address>> = Vec::new();
    let mut current: Vec<Address> = Vec::new();
    let mut current_cost = 0u64;
    for address in pending {
        let estimate = estimate_function_cost(snapshot.function(*address), payloads.get(address));
        if estimate > budget {
            if !current.is_empty() {
                batches.push(std::mem::take(&mut current));
                current_cost = 0;
            }
            solo.insert(*address);
            batches.push(vec![*address]);
            continue;
        }
        if !current.is_empty()
            && (current.len() >= MAX_BATCH_FUNCTIONS
                || current_cost.saturating_add(estimate) > budget)
        {
            batches.push(std::mem::take(&mut current));
            current_cost = 0;
        }
        current.push(*address);
        current_cost = current_cost.saturating_add(estimate);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Estimated working set of analyzing one function, in bytes.
///
/// The estimate covers this scheduler's own bookkeeping — decoded instructions,
/// the CFG payload and the produced text — never the parser or SSA peak inside
/// one function, which is bounded by the existing instruction/function limits.
fn estimate_function_cost(
    function: Option<&FunctionRow>,
    payload: Option<&PayloadBytes>,
) -> u64 {
    let decode_bound = function
        .map(|row| function_limit(row).0 as u64)
        .unwrap_or(4096)
        .saturating_mul(16);
    let (encoded, cfg, render) = match payload {
        Some(bytes) => (bytes.instructions, bytes.cfg, bytes.render),
        None => (0, 0, 0),
    };
    let encoded = encoded.max(decode_bound);
    let scratch = encoded
        .saturating_mul(8)
        .saturating_add(cfg.saturating_mul(4))
        .max(MIN_FUNCTION_SCRATCH_BYTES);
    let unknown = MAX_PAYLOAD_BYTES as u64;
    let output = encoded
        .saturating_add(cfg)
        .saturating_add(if render == 0 { unknown } else { render });
    scratch.saturating_add(output)
}

/// Build the worker pool for one command.
///
/// No process-global pool: `--jobs 1` must stay serial even if another command
/// already configured a pool, and the stack size is part of this command's
/// behaviour.
fn build_worker_pool(jobs: usize) -> Result<rayon::ThreadPool> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(jobs)
        .stack_size(WORKER_STACK_BYTES)
        .thread_name(|index| format!("hexray-analysis-{index}"))
        .build()
        .map_err(|error| anyhow::anyhow!("failed to start the analysis workers: {error}"))
}

/// One batch member's decode state, prepared on the main thread.
enum PreparedDecode {
    /// Raw instructions, already decoded (and cached) by the serial pass.
    Decoded(Arc<DecodedFunction>),
    /// The decode failed; the owner still gets a `failed` unit and a diagnostic.
    Unavailable(String),
    /// GPU object: no CPU decode is possible, the worker decodes it itself.
    Gpu,
}

/// Analyze one function on a worker thread.
#[allow(clippy::too_many_arguments)]
fn compute_function(
    binary: &Binary<'_>,
    snapshot: &AnalysisSnapshot,
    shared: &SharedAnalysisContext,
    signature_overrides: &BTreeMap<u64, hexray_analysis::FunctionSignature>,
    variable_overrides: &BTreeMap<u64, Vec<hexray_analysis::VariableOverride>>,
    decoded_table: &HashMap<DecodeKey, Arc<DecodedFunction>>,
    scope_map: &ScopeMap,
    address: Address,
    prepared: &PreparedDecode,
) -> Result<ComputedFunction> {
    let fmt = binary.as_format();
    let Some(function) = snapshot.function(address) else {
        bail!("no function row for {}", address.to_hex());
    };
    let (max_bytes, stop_after_first_return) = function_limit(function);

    if !supports_pseudo_c(fmt.architecture()) {
        // GPU objects: decode with the architecture decoder and store one
        // straight-line block. There is no CFG, xref or callgraph recovery on
        // this path, and an empty decode is an explicit unsupported unit
        // rather than a silent empty CFG. A kernel inside an excluded range is
        // never decoded at all.
        let excluded = scope_map.barrier_end(address.0).is_some();
        let allowed = if excluded {
            0
        } else {
            scope_map.clamp_window(address.0, max_bytes).0
        };
        let decoded = if allowed == 0 {
            Vec::new()
        } else {
            decode_gpu_function(binary, address.0, allowed)?
        };
        let (blocks, block_instructions) = match decoded.split_first() {
            Some((first, _)) => {
                let last = decoded.last().unwrap_or(first);
                let end = last.address.saturating_add(last.size as u64);
                (
                    vec![BlockPayload {
                        id: 0,
                        start: Address(first.address),
                        end: Address(end),
                        terminator: hexray_core::BlockTerminator::Unknown,
                    }],
                    vec![(
                        0u32,
                        decoded
                            .iter()
                            .map(|instruction| Address(instruction.address))
                            .collect(),
                    )],
                )
            }
            None => (Vec::new(), Vec::new()),
        };
        let mut diagnostics = Vec::new();
        let state = if decoded.is_empty() {
            diagnostics.push(Diagnostic::new(
                "no-instructions",
                Severity::Warning,
                format!(
                    "the {} decoder produced no instructions for {}",
                    format_architecture(fmt.architecture()),
                    address.to_hex()
                ),
            ));
            AnalysisState::Unsupported
        } else {
            AnalysisState::Current
        };
        let dependencies = match (decoded.first(), decoded.last()) {
            (Some(first), Some(last)) => {
                let start = first.address;
                let length = last
                    .address
                    .saturating_add(last.size as u64)
                    .saturating_sub(start);
                vec![Dependency {
                    kind: DependencyKind::Range,
                    key: "bytes".to_string(),
                    range: hexray_db::AddressRange::new(Address(start), length).ok(),
                    target_generation: 0,
                }]
            }
            _ => Vec::new(),
        };
        return Ok(ComputedFunction {
            address,
            function: function.clone(),
            state,
            hash: hash_instructions(&decoded),
            dependencies_complete: !decoded.is_empty(),
            diagnostics,
            dependencies,
            instructions: decoded,
            blocks,
            block_instructions,
            edges: Vec::new(),
            xrefs: Vec::new(),
        });
    }

    let decoded = match prepared {
        PreparedDecode::Decoded(decoded) => decoded,
        PreparedDecode::Unavailable(error) => {
            // The same shape a failed re-analysis produces: the owner keeps a
            // diagnostic explaining what went wrong and is not `current`.
            return Ok(ComputedFunction {
                address,
                function: function.clone(),
                state: AnalysisState::Failed,
                hash: [0u8; 32],
                dependencies_complete: false,
                diagnostics: vec![Diagnostic::new(
                    "analysis-failed",
                    Severity::Error,
                    error.clone(),
                )],
                dependencies: Vec::new(),
                instructions: Vec::new(),
                blocks: Vec::new(),
                block_instructions: Vec::new(),
                edges: Vec::new(),
                xrefs: Vec::new(),
            });
        }
        PreparedDecode::Gpu => bail!(
            "function {} was routed to the CPU path without a decode",
            address.to_hex()
        ),
    };
    let name = snapshot.display_name(function);
    let inputs = AnalysisInputs {
        shared,
        config: None,
        diagnostics: false,
        signature_override: signature_overrides.get(&address.0),
        variable_overrides: variable_overrides
            .get(&address.0)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        decoded: Some(decoded_table),
        scope_map: Some(scope_map),
    };
    match analysis_pipeline::analyze_decoded(
        binary,
        address.0,
        name,
        None,
        max_bytes,
        stop_after_first_return,
        decoded,
        &inputs,
    ) {
        Ok(analyzed) => {
            let payload = cfg_payload(&analyzed);
            let mut diagnostics: Vec<Diagnostic> = analyzed
                .diagnostics
                .iter()
                .map(|diagnostic| diagnostic.to_stored())
                .collect();
            if decoded.stop_reason == analysis_pipeline::DecodeStopReason::AnalysisScope {
                // The function is partially analyzed because the user excluded
                // the bytes after `decoded_end`; say so instead of presenting a
                // short CFG as if it were the whole function.
                let boundary = scope_map
                    .next_start(decoded.decoded_end)
                    .unwrap_or(decoded.decoded_end);
                diagnostics.push(Diagnostic::new(
                    "analysis-scope-filtered",
                    Severity::Info,
                    format!(
                        "decoding stopped at the analysis-scope boundary {} ({}); the excluded bytes were not analyzed",
                        Address(boundary).to_hex(),
                        decoded.stop_reason.as_str()
                    ),
                ));
            }
            Ok(ComputedFunction {
                address,
                function: function.clone(),
                state: AnalysisState::Current,
                hash: hash_instructions(&analyzed.instructions),
                dependencies_complete: true,
                diagnostics,
                dependencies: cfg_dependencies(address, &analyzed),
                instructions: payload.instructions,
                blocks: payload.blocks,
                block_instructions: payload.block_instructions,
                edges: payload.edges,
                xrefs: payload.xrefs,
            })
        }
        Err(error) => Ok(ComputedFunction {
            address,
            function: function.clone(),
            state: AnalysisState::Failed,
            hash: [0u8; 32],
            dependencies_complete: false,
            diagnostics: vec![Diagnostic::new(
                "analysis-failed",
                Severity::Error,
                format!("{error}"),
            )],
            dependencies: Vec::new(),
            instructions: Vec::new(),
            blocks: Vec::new(),
            block_instructions: Vec::new(),
            edges: Vec::new(),
            xrefs: Vec::new(),
        }),
    }
}

fn hash_instructions(instructions: &[Instruction]) -> [u8; 32] {
    let mut canonical = Vec::new();
    for instruction in instructions {
        canonical.extend_from_slice(&instruction.address.to_be_bytes());
        canonical.extend_from_slice(&(instruction.size as u64).to_be_bytes());
        canonical.extend_from_slice(&instruction.bytes);
        canonical.extend_from_slice(instruction.mnemonic.as_bytes());
        canonical.push(0);
    }
    hexray_db::sha256(&canonical)
}

fn cfg_payload(analyzed: &crate::analysis_pipeline::AnalyzedFunction) -> FunctionCfgPayload {
    let mut blocks = Vec::new();
    let mut block_instructions = Vec::new();
    let mut edges = Vec::new();
    // A CFG may legitimately hold the same normal edge twice: a conditional
    // branch whose target block is also its fallthrough (e.g. `je` to the very
    // next instruction) adds `from -> to` twice, because `add_edge` records
    // every transfer. The store keys edges by (function, from, to, kind), so a
    // duplicate row is a hard UNIQUE failure for the whole publish batch — and
    // with it the whole project's analysis. Deduplicate here, keeping first
    // occurrence order so the stored payload stays deterministic.
    let mut seen_edges: BTreeSet<(u32, u32, &'static str)> = BTreeSet::new();
    for block_id in analyzed.cfg.block_ids() {
        let Some(block) = analyzed.cfg.block(block_id) else {
            continue;
        };
        blocks.push(hexray_db::BlockPayload {
            id: block_id.0,
            start: Address(block.start),
            end: Address(block.end),
            terminator: block.terminator.clone(),
        });
        block_instructions.push((
            block_id.0,
            block
                .instructions
                .iter()
                .map(|instruction| Address(instruction.address))
                .collect(),
        ));
        for successor in analyzed.cfg.successors(block_id) {
            if seen_edges.insert((block_id.0, successor.0, EdgeKind::Normal.as_str())) {
                edges.push((block_id.0, successor.0, EdgeKind::Normal));
            }
        }
        for successor in analyzed.cfg.eh_successors(block_id) {
            if seen_edges.insert((block_id.0, successor.0, EdgeKind::Unwind.as_str())) {
                edges.push((block_id.0, successor.0, EdgeKind::Unwind));
            }
        }
    }
    let xrefs = xrefs_for_function(analyzed.start, &analyzed.instructions, &analyzed.cfg);
    FunctionCfgPayload {
        function: FunctionRow {
            address: Address(analyzed.start),
            declared_end: analyzed.instructions.last().map(|instruction| {
                Address(instruction.address.saturating_add(instruction.size as u64))
            }),
            bounds_origin: BoundsOrigin::Heuristic,
            origin: FunctionOrigin::Auto,
            excluded: false,
            user_removed: false,
            present: true,
        },
        instructions: analyzed.instructions.clone(),
        blocks,
        block_instructions,
        edges,
        xrefs,
    }
}

fn xrefs_for_function(
    function: u64,
    instructions: &[Instruction],
    cfg: &hexray_core::ControlFlowGraph,
) -> Vec<XrefRow> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<(u64, u64, &'static str)> = BTreeSet::new();
    for instruction in instructions {
        let mut push = |to: u64, kind: XrefKind| {
            if seen.insert((instruction.address, to, kind.as_str())) {
                out.push(XrefRow {
                    from: Address(instruction.address),
                    to: Address(to),
                    kind,
                    owner: Some(Address(function)),
                    origin: XrefOrigin::Auto,
                });
            }
        };
        match &instruction.control_flow {
            ControlFlow::Call { target, .. } => push(*target, XrefKind::Call),
            ControlFlow::UnconditionalBranch { target } => push(*target, XrefKind::Jump),
            ControlFlow::ConditionalBranch {
                target,
                fallthrough,
                ..
            } => {
                push(*target, XrefKind::Jump);
                push(*fallthrough, XrefKind::Jump);
            }
            ControlFlow::IndirectBranch { possible_targets } => {
                for target in possible_targets {
                    push(*target, XrefKind::Jump);
                }
            }
            _ => {}
        }
        for operand in &instruction.operands {
            if let Operand::Memory(memory) = operand {
                if let Some(target) = crate::rip_relative_memory_target(memory, instruction) {
                    push(target, XrefKind::Data);
                }
            }
        }
    }
    let _ = cfg;
    out.sort_by_key(|row| (row.from.0, row.to.0, row.kind.as_str()));
    out
}

fn cfg_dependencies(
    function: Address,
    analyzed: &crate::analysis_pipeline::AnalyzedFunction,
) -> Vec<Dependency> {
    let mut dependencies = Vec::new();
    let end = analyzed
        .instructions
        .last()
        .map(|instruction| instruction.address.saturating_add(instruction.size as u64))
        .unwrap_or(function.0);
    dependencies.push(Dependency {
        kind: DependencyKind::Range,
        key: "bytes".to_string(),
        range: hexray_db::AddressRange::new(function, end.saturating_sub(function.0)).ok(),
        target_generation: 0,
    });
    for instruction in &analyzed.instructions {
        if let ControlFlow::Call { target, .. } = &instruction.control_flow {
            // The generation is filled by the scheduler from the batch snapshot:
            // only it knows what an earlier batch of this command published.
            dependencies.push(Dependency {
                kind: DependencyKind::Signature,
                key: format!("function:{target:x}"),
                range: None,
                target_generation: 0,
            });
        }
    }
    dependencies
}

// ---------------------------------------------------------------------------
// Discovery, overrides, DWARF
// ---------------------------------------------------------------------------

const MAX_DISCOVERED_FUNCTIONS: usize = 10_000;

/// Whole-image function discovery.
///
/// Seed set: loader symbols, the entry point, CET/lifecycle arrays and
/// already-published functions. The queue then grows by following direct calls
/// and materialized internal targets, exactly like the standalone callgraph
/// walk. User data definitions and user-suppressed functions are hard
/// barriers, so re-running discovery never resurrects them.
fn discovery_pass(
    binary: &Binary<'_>,
    snapshot: &AnalysisSnapshot,
    decode: &mut DecodeSession,
    max_functions: usize,
) -> Result<(Vec<FunctionRow>, bool)> {
    let fmt = binary.as_format();
    let in_scope = |address: u64| snapshot.scope_map.contains(address);
    if !supports_pseudo_c(fmt.architecture()) {
        // GPU objects are discovered from metadata only: no call-target walk
        // and no decode gate, because the caller stores whatever the decoder
        // produces (an empty decode becomes an unsupported unit).
        let suppressed: BTreeSet<u64> = snapshot
            .functions
            .iter()
            .filter(|row| row.user_removed)
            .map(|row| row.address.0)
            .collect();
        let mut found: BTreeMap<u64, FunctionRow> = BTreeMap::new();
        let mut truncated = false;
        for (address, size) in gpu_function_starts(binary) {
            if found.len() >= max_functions {
                truncated = true;
                break;
            }
            if address == 0 || suppressed.contains(&address) || in_scope(address) {
                continue;
            }
            if !is_executable(fmt, address) || snapshot.data_item_at(address).is_some() {
                continue;
            }
            found.insert(
                address,
                gpu_function_row(
                    binary,
                    snapshot.function(Address(address)),
                    address,
                    size,
                ),
            );
        }
        // Existing rows whose entry is excluded are kept, not dropped (see the
        // CPU branch); the scope filters display and target selection instead.
        for function in snapshot
            .functions
            .iter()
            .filter(|row| row.is_live() && in_scope(row.address.0))
        {
            found
                .entry(function.address.0)
                .or_insert_with(|| function.clone());
        }
        // User-defined functions survive a rebuild.
        for function in snapshot
            .functions
            .iter()
            .filter(|row| row.origin == FunctionOrigin::User)
        {
            found
                .entry(function.address.0)
                .or_insert_with(|| function.clone());
        }
        return Ok((found.into_values().collect(), truncated));
    }
    let relocation_table = crate::build_relocation_table(binary);
    let symbols = crate::collect_analysis_symbols(binary, &relocation_table);
    let mut starts: Vec<(u64, u64, bool)> =
        crate::discover_function_starts(fmt, fmt.architecture(), &symbols, Some(&snapshot.scope_map));
    for function in snapshot.functions.iter().filter(|row| row.is_live()) {
        let (max_bytes, heuristic) = function_limit(function);
        starts.push((function.address.0, max_bytes as u64, heuristic));
    }
    starts.sort_by_key(|(address, _, _)| *address);
    starts.dedup_by_key(|(address, _, _)| *address);

    let suppressed: BTreeSet<u64> = snapshot
        .functions
        .iter()
        .filter(|row| row.user_removed)
        .map(|row| row.address.0)
        .collect();

    let mut found: BTreeMap<u64, FunctionRow> = BTreeMap::new();
    let mut truncated = false;
    let mut queue: VecDeque<(u64, u64, bool)> = starts.iter().copied().collect();
    let mut visited: BTreeSet<u64> = BTreeSet::new();

    while let Some((address, size, heuristic)) = queue.pop_front() {
        if found.len() >= max_functions {
            truncated = true;
            break;
        }
        if address == 0 || !visited.insert(address) {
            continue;
        }
        if suppressed.contains(&address) || in_scope(address) {
            continue;
        }
        if !is_executable(fmt, address) || snapshot.data_item_at(address).is_some() {
            continue;
        }
        // The serial decode is cached: the CFG pass below reuses this exact
        // decode instead of decoding the same function a second time.
        let Ok(decoded) = decode.decode(binary, address, size.max(64) as usize, heuristic) else {
            continue;
        };
        found.insert(
            address,
            function_row_for(binary, snapshot, address, &symbols),
        );
        for (target, _) in crate::extract_internal_call_targets(&decoded.instructions, fmt) {
            if !visited.contains(&target) {
                queue.push_back((target, 4096, true));
            }
        }
        for target in crate::discover_materialized_internal_targets(&decoded.instructions, fmt) {
            if !visited.contains(&target) {
                queue.push_back((target, 4096, true));
            }
        }
    }

    // Existing automatic rows whose entry is now excluded are *kept*, not
    // dropped: excluding a range is a policy change, not a discovery result,
    // and clearing the scope must be able to bring the same functions back
    // without a re-discovery guess. The display and target selection filter
    // them instead.
    for function in snapshot
        .functions
        .iter()
        .filter(|row| row.is_live() && in_scope(row.address.0))
    {
        found
            .entry(function.address.0)
            .or_insert_with(|| function.clone());
    }

    // User-defined functions survive a rebuild.
    for function in snapshot
        .functions
        .iter()
        .filter(|row| row.origin == FunctionOrigin::User)
    {
        found
            .entry(function.address.0)
            .or_insert_with(|| function.clone());
    }

    Ok((found.into_values().collect(), truncated))
}

fn function_row_for(
    binary: &Binary<'_>,
    snapshot: &AnalysisSnapshot,
    address: u64,
    symbols: &[hexray_core::Symbol],
) -> FunctionRow {
    if let Some(existing) = snapshot.function(Address(address)) {
        if existing.origin == FunctionOrigin::User {
            return existing.clone();
        }
    }
    let symbol = crate::find_preferred_symbol_at(symbols, address)
        .filter(|symbol| symbol.is_function() && symbol.size > 0 && symbol.address == address);
    FunctionRow {
        address: Address(address),
        declared_end: symbol.map(|symbol| Address(address.saturating_add(symbol.size))),
        bounds_origin: if symbol.is_some() {
            BoundsOrigin::Symbol
        } else if Some(address) == binary.as_format().entry_point() {
            BoundsOrigin::Entry
        } else {
            BoundsOrigin::Heuristic
        },
        origin: FunctionOrigin::Auto,
        excluded: false,
        user_removed: false,
        present: true,
    }
}

fn is_executable(fmt: &dyn BinaryFormat, address: u64) -> bool {
    fmt.executable_sections().any(|section| {
        let start = section.virtual_address();
        let end = start.saturating_add(section.size());
        address >= start && address < end
    })
}

/// Convert persisted `function_overrides` into decoder-ready signatures.
fn build_signature_overrides(
    snapshot: &AnalysisSnapshot,
    arch: Architecture,
) -> Result<BTreeMap<u64, hexray_analysis::FunctionSignature>> {
    let mut out = BTreeMap::new();
    let fallback_convention = match arch {
        Architecture::Arm64 => hexray_analysis::CallingConvention::Aarch64,
        Architecture::RiscV64 | Architecture::RiscV32 => hexray_analysis::CallingConvention::RiscV,
        _ => {
            if snapshot.image.format == "pe" {
                hexray_analysis::CallingConvention::Win64
            } else {
                hexray_analysis::CallingConvention::SystemV
            }
        }
    };

    for (address, row) in &snapshot.function_overrides {
        if row.signature.is_none() && row.calling_convention.is_none() {
            continue;
        }
        let mut signature = match &row.signature {
            Some(prototype) => prototype_to_signature(prototype, fallback_convention)
                .with_context(|| format!("signature override for {}", address.to_hex()))?,
            None => hexray_analysis::FunctionSignature::new(fallback_convention),
        };
        if let Some(name) = &row.calling_convention {
            signature.convention = calling_convention_from_name(name).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown calling convention '{name}' for {} (use systemv, win64, aarch64 or riscv)",
                    address.to_hex()
                )
            })?;
        }
        out.insert(address.0, signature);
    }
    Ok(out)
}

fn calling_convention_from_name(name: &str) -> Option<hexray_analysis::CallingConvention> {
    Some(match name.trim().to_ascii_lowercase().as_str() {
        "systemv" | "sysv" | "cdecl" => hexray_analysis::CallingConvention::SystemV,
        "win64" | "msx64" | "microsoft" => hexray_analysis::CallingConvention::Win64,
        "aarch64" | "aapcs64" | "aapcs" => hexray_analysis::CallingConvention::Aarch64,
        "riscv" | "riscv64" => hexray_analysis::CallingConvention::RiscV,
        _ => return None,
    })
}

fn prototype_to_signature(
    prototype: &str,
    convention: hexray_analysis::CallingConvention,
) -> Result<hexray_analysis::FunctionSignature> {
    let header = format!("{};", prototype.trim().trim_end_matches(';'));
    let database = hexray_types::parser::parse_header(&header)
        .map_err(|error| anyhow::anyhow!("'{prototype}' is not a C function prototype: {error}"))?;
    let Some(name) = database.function_names().next().map(str::to_string) else {
        bail!("'{prototype}' does not declare a function");
    };
    let Some(declared) = database.get_function(&name) else {
        bail!("'{prototype}' does not declare a function");
    };

    let return_type = param_type_from_ctype(&declared.return_type);
    let mut parameters = Vec::new();
    let registers = convention.integer_arg_registers();
    for (index, parameter) in declared.parameters.iter().enumerate() {
        let location = match registers.get(index) {
            Some(register) => hexray_analysis::ParameterLocation::IntegerRegister {
                name: (*register).to_string(),
                index,
            },
            None => hexray_analysis::ParameterLocation::Stack {
                offset: 16 + 8 * (index as i64 - registers.len() as i64),
            },
        };
        parameters.push(hexray_analysis::Parameter {
            name: parameter.0.clone(),
            param_type: param_type_from_ctype(&parameter.1),
            location,
            type_confidence: u8::MAX,
        });
    }

    let mut signature = hexray_analysis::FunctionSignature::new(convention);
    signature.return_type = return_type.clone();
    signature.has_return = return_type != hexray_analysis::ParamType::Void;
    signature.is_variadic = declared.variadic;
    signature.parameters = parameters;
    signature.return_confidence = u8::MAX;
    Ok(signature)
}

fn param_type_from_ctype(ty: &hexray_types::CType) -> hexray_analysis::ParamType {
    use hexray_analysis::ParamType;
    use hexray_types::CType;
    match ty {
        CType::Void => ParamType::Void,
        CType::Int(int) => {
            let bits = u8::try_from(int.size.saturating_mul(8)).unwrap_or(64);
            if int.signed {
                ParamType::SignedInt(bits)
            } else {
                ParamType::UnsignedInt(bits)
            }
        }
        CType::Float(float) => {
            ParamType::Float(u8::try_from(float.size.saturating_mul(8)).unwrap_or(64))
        }
        CType::Pointer(inner) => match param_type_from_ctype(inner) {
            ParamType::Void => ParamType::Pointer,
            other => ParamType::TypedPointer(Box::new(other)),
        },
        CType::Array(array) => {
            ParamType::TypedPointer(Box::new(param_type_from_ctype(&array.element)))
        }
        other => ParamType::Named(ctype_display(other)),
    }
}

fn ctype_display(ty: &hexray_types::CType) -> String {
    use hexray_types::CType;
    match ty {
        CType::Void => "void".to_string(),
        CType::Int(int) => format!(
            "{}{}",
            if int.signed { "int" } else { "uint" },
            int.size * 8
        ),
        CType::Float(float) => format!("float{}", float.size * 8),
        CType::Pointer(inner) => format!("{}*", ctype_display(inner)),
        CType::Array(array) => format!("{}[]", ctype_display(&array.element)),
        CType::Struct(structure) => format!(
            "struct {}",
            structure.name.as_deref().unwrap_or("<anonymous>")
        ),
        CType::Union(union) => format!("union {}", union.name.as_deref().unwrap_or("<anonymous>")),
        CType::Enum(enumeration) => {
            format!(
                "enum {}",
                enumeration.name.as_deref().unwrap_or("<anonymous>")
            )
        }
        CType::Function(function) => format!("{} (*)()", ctype_display(&function.return_type)),
        CType::Typedef(alias) => alias.name.clone(),
        CType::Named(name) => name.clone(),
    }
}

fn build_variable_overrides(
    snapshot: &AnalysisSnapshot,
    _functions: &[FunctionRow],
) -> BTreeMap<u64, Vec<hexray_analysis::VariableOverride>> {
    use hexray_analysis::VariableOverrideLocator;

    let mut out: BTreeMap<u64, Vec<hexray_analysis::VariableOverride>> = BTreeMap::new();
    for row in &snapshot.variable_overrides {
        let locator = match &row.locator {
            VariableLocator::Parameter { index } => VariableOverrideLocator::Parameter(*index),
            VariableLocator::Stack { offset } => {
                let Ok(parsed) = offset.parse::<i64>() else {
                    continue;
                };
                VariableOverrideLocator::Stack(parsed)
            }
            VariableLocator::Expression { generation: _, key } => {
                let Some((kind, rest)) = key.split_once(':') else {
                    continue;
                };
                let mut parts = rest.split(':');
                let Ok(index) = parts.next().unwrap_or_default().parse::<u32>() else {
                    continue;
                };
                let Ok(size) = parts.next().unwrap_or_default().parse::<u8>() else {
                    continue;
                };
                match kind {
                    "register" => VariableOverrideLocator::Register {
                        index: u16::try_from(index).unwrap_or(u16::MAX),
                        size,
                    },
                    "temp" => VariableOverrideLocator::Temp { index, size },
                    _ => continue,
                }
            }
        };
        out.entry(row.function.0)
            .or_default()
            .push(hexray_analysis::VariableOverride {
                locator,
                name: row.name.clone(),
                type_name: row.type_name.clone(),
            });
    }
    out
}

/// Load DWARF for a project without touching the filesystem: sections come
/// from the effective image, and split-DWARF sidecars come from stored
/// resources only.
fn load_project_dwarf(
    snapshot: &AnalysisSnapshot,
    fmt: &dyn BinaryFormat,
) -> Result<Option<hexray_formats::dwarf::DebugInfo>> {
    let main = crate::parse_dwarf_from_sections(fmt);
    let address_size = match fmt.architecture() {
        Architecture::X86 | Architecture::RiscV32 => 4u8,
        _ => 8u8,
    };
    if let Some(sidecar) = snapshot
        .dwarf_sidecars
        .first()
        .and_then(|bytes| crate::parse_split_dwarf_bytes(bytes, fmt, address_size))
    {
        return Ok(Some(sidecar));
    }
    Ok(main)
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn cfg_from_records(
    data: &hexray_db::store::CfgData,
    instructions: &[Instruction],
) -> Result<hexray_core::ControlFlowGraph> {
    use hexray_core::{BasicBlock, BasicBlockId, ControlFlowGraph};
    let mut decoded: BTreeMap<u64, &Instruction> = BTreeMap::new();
    for instruction in instructions {
        decoded.insert(instruction.address, instruction);
    }
    let entry = data
        .blocks
        .first()
        .map(|block| BasicBlockId(block.id))
        .unwrap_or(BasicBlockId::ENTRY);
    let mut cfg = ControlFlowGraph::new(entry);
    for payload in &data.blocks {
        let mut block = BasicBlock::new(BasicBlockId(payload.id), payload.start.0);
        block.end = payload.end.0;
        for address in data.block_instructions(payload.id) {
            if let Some(instruction) = decoded.get(&address.0) {
                block.push_instruction((*instruction).clone());
            }
        }
        block.terminator = payload.terminator.clone();
        cfg.add_block(block);
    }
    for (from, to, kind) in &data.edges {
        match kind {
            EdgeKind::Normal => cfg.add_edge(BasicBlockId(*from), BasicBlockId(*to)),
            EdgeKind::Unwind => cfg.add_eh_edge(BasicBlockId(*from), BasicBlockId(*to)),
        }
    }
    Ok(cfg)
}

#[derive(Debug, Default)]
struct RenderReport {
    rendered: usize,
    reused: usize,
    partial: usize,
    unsupported: usize,
}

#[allow(clippy::too_many_arguments)]
fn render_functions(
    database: &mut Database,
    snapshot: &AnalysisSnapshot,
    shared: &Arc<SharedAnalysisContext>,
    targets: &[Address],
    config: &RenderConfig,
    force: bool,
    budget: u64,
    pool: Option<&rayon::ThreadPool>,
    stage: &mut StageTimings,
    active: &std::sync::atomic::AtomicUsize,
    max_active: &std::sync::atomic::AtomicUsize,
) -> Result<RenderReport> {
    let started = std::time::Instant::now();
    let mut report = RenderReport::default();
    let selection = selection_from_image(&snapshot.image);
    let parsed = parse_image(snapshot.image_bytes(), &selection)?;
    let binary = &parsed.binary;
    let fingerprint = config.fingerprint();
    if !supports_pseudo_c(binary.as_format().architecture()) {
        // GPU code objects have no pseudo-C path. Mark every target's render
        // unit unsupported so the reason is stored, `db info` stays partial,
        // and `db query decompile` can report the same reason instead of
        // asking for a rebuild that can never succeed.
        let mut batch = AnalysisBatch::default();
        for address in targets {
            let Some(function) = snapshot.function(*address) else {
                continue;
            };
            if !function.is_live() {
                continue;
            }
            let key = UnitKey::function_render(*address, fingerprint);
            batch.units.push(UnitPublish {
                key,
                expected_generation: snapshot.unit_generation(&key),
                state: AnalysisState::Unsupported,
                input_fingerprint: fingerprint,
                dependencies_complete: true,
                diagnostics: vec![Diagnostic::new(
                    "gpu-pseudo-c-unsupported",
                    Severity::Info,
                    "pseudo-C is unsupported for GPU code objects",
                )],
                dependencies: Vec::new(),
                payload: AnalysisPayload::FunctionRender(Box::new(RenderPayload {
                    function: *address,
                    config_fingerprint: fingerprint,
                    text: String::new(),
                })),
            });
        }
        if !batch.units.is_empty() {
            publish_batch(database, snapshot.revision, &batch)?;
        }
        stage.render_ms += started.elapsed().as_millis();
        return Ok(RenderReport {
            unsupported: targets.len(),
            ..Default::default()
        });
    }
    // The render context (types, DWARF, symbols, constants) was built once for
    // this command; rendering reuses it instead of rebuilding the image.
    let decompiler_config = build_decompiler_config(
        &config.optimization_level,
        &config.enable_passes,
        &config.disable_passes,
    )?;
    let signature_overrides = build_signature_overrides(snapshot, binary.as_format().architecture())?;
    let variable_overrides = build_variable_overrides(snapshot, &snapshot.functions);
    let overlay = snapshot.comment_overlay();

    // A stored render is reusable only when its unit is current for this engine.
    let pending = {
        let read = db(database.snapshot())?;
        let mut pending: Vec<Address> = Vec::new();
        let mut units: BTreeMap<Address, hexray_db::AnalysisUnitRow> = BTreeMap::new();
        let mut addresses: Vec<Address> = Vec::new();
        for address in targets {
            let Some(function) = snapshot.function(*address) else {
                continue;
            };
            if !function.is_live() {
                continue;
            }
            addresses.push(*address);
            if let Some(unit) = db(read.unit(&UnitKey::function_render(*address, fingerprint)))? {
                units.insert(*address, unit);
            }
        }
        let rendered = db(read.rendered_for(&fingerprint, &addresses))?;
        for address in &addresses {
            let current = units.get(address).is_some_and(|unit| {
                unit.state == AnalysisState::Current
                    && unit.engine_fingerprint == snapshot.engine
                    && unit.dependencies_complete
            });
            if !force && current && rendered.contains(address) {
                report.reused += 1;
                continue;
            }
            pending.push(*address);
        }
        pending
    };

    // Batches keep the publish transaction and the reload of owner artifacts
    // small; the estimated payload cost reuses the same budget as analysis.
    let payloads = {
        let read = db(database.snapshot())?;
        db(read.payload_bytes_for_functions(&pending))?
    };
    let mut solo: BTreeSet<Address> = BTreeSet::new();
    let batches = plan_batches(&pending, snapshot, &payloads, budget, &mut solo);

    for batch in batches {
        let (instructions, cfgs, generations) = {
            let read = db(database.snapshot())?;
            if read.data_revision() != snapshot.revision {
                bail!(
                    "the project changed while rendering was running; re-run the command \
                     (revision {} is no longer head)",
                    snapshot.revision.0
                );
            }
            // Artifacts and their render generation come from one snapshot, so a
            // batch always replays the CFG it read. The CFG's own generation is
            // deliberately not part of the render key: re-analysis of unchanged
            // bytes produces the same CFG, and a concurrent publish of the same
            // owner is rejected by the per-unit generation CAS below.
            let mut generations = BTreeMap::new();
            for address in &batch {
                generations.insert(
                    *address,
                    db(read.analysis_generation(&UnitKey::function_render(*address, fingerprint)))?,
                );
            }
            let instructions = db(read.instructions_for_functions(&batch))?;
            let cfgs = db(read.cfgs_for_functions(&batch))?;
            (instructions, cfgs, generations)
        };

        let compute = |address: &Address| -> (Address, Option<UnitPublish>, Vec<String>) {
            active.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let current = active.load(std::sync::atomic::Ordering::SeqCst);
            max_active.fetch_max(current, std::sync::atomic::Ordering::SeqCst);
            let result = compute_render_unit(
                binary,
                snapshot,
                shared,
                &decompiler_config,
                &signature_overrides,
                &variable_overrides,
                &overlay,
                config,
                &fingerprint,
                &instructions,
                &cfgs,
                &generations,
                address,
            );
            active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            result
        };

        let mut results: Vec<(Address, Option<UnitPublish>, Vec<String>)> = match pool {
            Some(pool) if batch.len() > 1 => {
                pool.install(|| batch.par_iter().map(compute).collect::<Vec<_>>())
            }
            _ => batch.iter().map(compute).collect(),
        };
        // Warnings are printed on the main thread in address order: a worker
        // never writes to the terminal, so two failures cannot interleave.
        results.sort_by_key(|(address, _, _)| address.0);
        let mut units: Vec<UnitPublish> = Vec::with_capacity(results.len());
        let mut partial = 0usize;
        for (_, unit, warnings) in results {
            for warning in warnings {
                eprintln!("{warning}");
            }
            match unit {
                Some(unit) => units.push(unit),
                None => partial += 1,
            }
        }
        units.sort_by_key(|unit| unit.key.key.0);
        report.rendered += units.len();
        report.partial += partial;
        if !units.is_empty() {
            let publish_started = std::time::Instant::now();
            publish_batch(database, snapshot.revision, &AnalysisBatch { units })?;
            stage.publish_ms += publish_started.elapsed().as_millis();
        }
    }
    stage.render_ms += started.elapsed().as_millis();
    Ok(report)
}

// ---------------------------------------------------------------------------
// `db info`, `db analyze`, `db check`, `db backup`, `db export-binary`
// ---------------------------------------------------------------------------

fn info(path: &Path, json_output: bool) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadOnly))?;
    let snapshot = db(database.snapshot())?;
    let info = db(snapshot.info())?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }
    println!("Project:        {}", path.display());
    println!("UUID:           {}", info.uuid);
    println!("Revision:       {}", info.revision.0);
    println!("Created:        {}", info.created_at);
    println!("Schema version: {}", info.schema_version);
    println!(
        "State:          {}",
        match info.overall_state {
            OverallState::Ready => "ready",
            OverallState::Partial => "partial (some analysis is pending or stale)",
            OverallState::Pending => "pending (no analysis yet)",
        }
    );
    println!(
        "Input:          {} bytes sha256 {}",
        info.source_size,
        hexray_db::hex_encode(&info.source_sha256[..8])
    );
    println!(
        "Image:          {} {}",
        info.image.format, info.image.architecture
    );
    println!("Selector:       {}", info.image.selector_json.trim());
    println!(
        "Entry:          {}",
        info.image
            .entry_address
            .map(|address| address.to_hex())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("Mappings:       {}", info.image.mappings.len());
    println!("Sections:       {}", info.image.sections.len());
    println!("Functions:      {}", info.function_count);
    println!("Instructions:   {}", info.instruction_count);
    println!("Strings:        {}", info.string_count);
    println!("Xrefs:          {}", info.xref_count);
    println!("Patches:        {}", info.patch_count);
    println!("Debug sidecars: {}", info.debug_sidecars);
    println!("Undo depth:     {}", info.undo_depth);
    println!("Redo depth:     {}", info.redo_depth);
    println!(
        "Coverage:       {} ({} known function(s) excluded by scope)",
        info.coverage, info.skipped_functions
    );
    if !info.analysis_scope.is_empty() {
        for &(start, end) in ScopeMap::from_scope(&info.analysis_scope).spans() {
            println!(
                "  scope        {}..{}",
                Address(start).to_hex(),
                Address(end).to_hex()
            );
        }
    }
    if info.engine_fingerprint != info.stored_engine_fingerprint {
        println!(
            "Engine:         changed since creation ({} -> {}); stored results are stale",
            hexray_db::hex_encode(&info.stored_engine_fingerprint[..8]),
            hexray_db::hex_encode(&info.engine_fingerprint[..8])
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn analyze(
    path: &Path,
    function: Option<String>,
    force: bool,
    render: bool,
    render_flags: &RenderFlags,
    limits: &InputLimits,
    exec: &AnalysisExecutionOptions,
    json_output: bool,
) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let mut request = AnalyzeRequest::new();
    request.function = function;
    request.force = force;
    request.limits = limits.clone();
    request.exec = exec.clone();
    if render {
        // The render key is a database fact: ABI, type snapshot and user types
        // are enough, so the image is not parsed here.
        let (image, config) = {
            let read = db(database.snapshot())?;
            let image = db(read.image())?;
            let config = render_config_from_reads(&read, &image, render_flags)?;
            (image, config)
        };
        let _ = image;
        request.render = Some(config);
    }
    let report = run_analysis(&mut database, &request)?;
    let revision = db(database.revision())?;

    if json_output {
        let mut payload = json!({
            "revision": revision.0,
            "discovered": report.discovered,
            "analyzed": report.analyzed,
            "reused": report.reused,
            "rendered": report.rendered,
            "reused_render": report.reused_render,
            "partial": report.partial,
            "unsupported": report.unsupported,
            "failed": report.failed,
            "skipped": report.stale_skipped,
            "skipped_scope": report.skipped_scope,
        });
        if let Some(timings) = &report.timings {
            payload["timings"] = timings.to_json();
        }
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    println!(
        "Analyzed {} function(s), reused {}, rendered {} (reused {}). Revision {}.",
        report.analyzed, report.reused, report.rendered, report.reused_render, revision.0
    );
    if report.skipped_scope > 0 {
        println!(
            "Analysis scope excluded {} known function(s); `db query <db> scope` shows the ranges.",
            report.skipped_scope
        );
    }
    if report.partial + report.unsupported + report.failed > 0 {
        println!(
            "Incomplete: {} partial, {} unsupported, {} failed",
            report.partial, report.unsupported, report.failed
        );
    }
    Ok(())
}

fn check(path: &Path, deep: bool, json_output: bool) -> Result<()> {
    let database = db(Database::open(path, OpenMode::ReadOnly))?;
    let report = db(database.check(deep))?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("quick_check:        {}", report.quick_check);
        println!(
            "foreign_key_check:  {}",
            report.foreign_key_violations.len()
        );
        for violation in &report.foreign_key_violations {
            println!("  {violation}");
        }
        if deep {
            println!("source digest:      {}", report.source_digest_matches);
            println!("patch ranges:       {}", report.patch_ranges_valid);
        }
        for problem in &report.problems {
            println!("problem:            {problem}");
        }
    }
    if !report.passed() {
        bail!("database check failed");
    }
    Ok(())
}

fn backup(path: &Path, output: &Path) -> Result<()> {
    let database = db(Database::open(path, OpenMode::ReadOnly))?;
    db(database.backup(output))?;
    println!("Backed up {} to {}", path.display(), output.display());
    Ok(())
}

/// Write a binary with every recorded patch applied.
///
/// The output keeps the original length. No checksum or signature is
/// recomputed: the file may not load if it was signed.
fn export_binary(path: &Path, output: &Path) -> Result<()> {
    if same_file(path, output)? {
        bail!("refusing to write the export over the project file");
    }
    let mut database = db(Database::open(path, OpenMode::ReadOnly))?;
    let (source, patches, original_path) = {
        let snapshot = db(database.snapshot())?;
        (
            db(snapshot.source_bytes())?,
            db(snapshot.patches())?,
            db(snapshot.original_path())?,
        )
    };
    if let Ok(original) = std::fs::canonicalize(&original_path) {
        if let Ok(target) = std::fs::canonicalize(output) {
            if original == target {
                bail!("refusing to overwrite the original input");
            }
        }
    }
    let exported = effective_source(&source, &patches)?;
    if exported.len() != source.len() {
        bail!("patched export changed the input length");
    }
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let staging = tempfile::Builder::new()
        .prefix(".hexray-export-")
        .tempdir_in(&parent)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let staged = staging.path().join("export.bin");
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&staged)
            .with_context(|| format!("failed to create {}", staged.display()))?;
        file.write_all(&exported)?;
        file.sync_all()?;
    }
    std::fs::hard_link(&staged, output)
        .map_err(|error| anyhow::anyhow!("failed to publish {}: {error}", output.display()))?;
    println!(
        "Wrote {} ({} bytes, {} patch region(s)). Signatures and checksums were not repaired.",
        output.display(),
        exported.len(),
        patches.len()
    );
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> Result<bool> {
    let left = std::fs::canonicalize(left).unwrap_or_else(|_| left.to_path_buf());
    let right = std::fs::canonicalize(right).unwrap_or_else(|_| right.to_path_buf());
    Ok(left == right)
}

// ---------------------------------------------------------------------------
// Patchable regions
// ---------------------------------------------------------------------------

/// Section names that hold metadata a byte patch must never touch: rewriting
/// them would invalidate the layout the project validated at creation.
fn is_metadata_section(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        ".debug",
        ".zdebug",
        ".symtab",
        ".strtab",
        ".dynsym",
        ".dynstr",
        ".gnu",
        ".hash",
        ".rela",
        ".rel",
        ".relocs",
        ".dynamic",
        ".interp",
        ".note",
        ".comment",
        ".eh_frame",
        ".gcc_except_table",
        ".ARM.exidx",
        ".ARM.extab",
        ".llvm",
        ".nv_debug",
        "__debug",
        "__symbol",
        "__reloc",
        "__linkedit",
        "__dysymtab",
        ".idata",
        ".edata",
        ".rsrc",
        ".reloc",
        ".tls",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        || name.contains("reloc")
        || name.contains("import")
        || name.contains("export")
}

/// File ranges (relative to the analyzed image) that may be patched.
fn patchable_ranges(snapshot: &AnalysisSnapshot, fmt: &dyn BinaryFormat) -> Vec<(FileOffset, u64)> {
    let header_ranges = header_file_ranges(fmt, snapshot);
    let mut candidates: Vec<(FileOffset, u64)> = Vec::new();

    let mut any_section = false;
    for section in fmt.sections() {
        if !section.is_allocated() || section.size() == 0 {
            continue;
        }
        any_section = true;
        let name = section.name();
        if is_metadata_section(name) {
            continue;
        }
        if !fmt
            .executable_sections()
            .any(|executable| std::ptr::eq(executable, section))
        {
            // Non-executable data sections are still patchable; only skip
            // sections with no file payload.
        }
        candidates.push((FileOffset(section.file_offset()), section.size()));
    }

    if !any_section {
        // Sectionless images: program headers are the only layout truth.
        for mapping in &snapshot.image.mappings {
            let Some(offset) = mapping.file_offset else {
                continue;
            };
            if mapping.file_size == 0 {
                continue;
            }
            candidates.push((offset, mapping.file_size));
        }
    }

    // Never allow a patch to reach into container structure.
    let mut allowed = Vec::new();
    for (start, length) in candidates {
        let end = start.0.saturating_add(length);
        let mut cursor = start.0;
        let mut blocked: Vec<(u64, u64)> = header_ranges
            .iter()
            .filter(|(header_start, header_len)| {
                let header_end = header_start.saturating_add(*header_len);
                *header_start < end && cursor < header_end
            })
            .map(|(header_start, header_len)| (*header_start, header_start + header_len))
            .collect();
        blocked.sort_unstable();
        for (block_start, block_end) in blocked {
            if block_start > cursor {
                allowed.push((FileOffset(cursor), block_start - cursor));
            }
            cursor = cursor.max(block_end);
        }
        if cursor < end {
            allowed.push((FileOffset(cursor), end - cursor));
        }
    }
    allowed
}

/// Container structure that a patch must not modify.
fn header_file_ranges(fmt: &dyn BinaryFormat, _snapshot: &AnalysisSnapshot) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let sections: Vec<_> = fmt.sections().collect();
    let first_section_offset = sections
        .iter()
        .map(|section| section.file_offset())
        .min()
        .unwrap_or(u64::MAX);
    if first_section_offset != u64::MAX && first_section_offset > 0 {
        ranges.push((0u64, first_section_offset));
    }
    ranges
}

/// Translate a user-supplied patch target into a source file offset.
fn resolve_patch_offset(
    snapshot: &AnalysisSnapshot,
    fmt: &dyn BinaryFormat,
    text: &str,
) -> Result<FileOffset> {
    let address = parse_address(text)?;
    let image_offset = if let Some(mapping) = snapshot
        .image
        .mappings
        .iter()
        .filter(|mapping| {
            address.0 >= mapping.va.0
                && address.0 < mapping.va.0.saturating_add(mapping.memory_size)
        })
        .collect::<Vec<_>>()
        .first()
    {
        let delta = address.0 - mapping.va.0;
        let Some(file_offset) = mapping.file_offset else {
            bail!(
                "{} is inside zero-fill memory with no file backing; it cannot be patched",
                address.to_hex()
            );
        };
        if delta >= mapping.file_size {
            bail!(
                "{} is beyond the file-backed part of mapping {}",
                address.to_hex(),
                mapping.name
            );
        }
        file_offset
            .0
            .checked_add(delta)
            .ok_or_else(|| anyhow::anyhow!("mapping offset overflows for {}", address.to_hex()))?
    } else {
        // A bare file offset is accepted too; it is validated below.
        address.0
    };

    let _ = fmt;
    let source_offset = snapshot
        .image
        .container_offset
        .0
        .checked_add(image_offset)
        .ok_or_else(|| anyhow::anyhow!("source offset overflows"))?;
    Ok(FileOffset(source_offset))
}

/// Which image-relative file offset a source offset maps to.
fn image_file_offset(snapshot: &AnalysisSnapshot, source_offset: FileOffset) -> Result<FileOffset> {
    source_offset
        .0
        .checked_sub(snapshot.image.container_offset.0)
        .map(FileOffset)
        .ok_or_else(|| anyhow::anyhow!("patch lies before the selected image"))
}

fn require_patchable(
    snapshot: &AnalysisSnapshot,
    fmt: &dyn BinaryFormat,
    source_offset: FileOffset,
    length: u64,
) -> Result<()> {
    let image_offset = image_file_offset(snapshot, source_offset)?;
    let end = image_offset
        .0
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("patch range overflows at {}", image_offset.to_hex()))?;
    for (start, size) in patchable_ranges(snapshot, fmt) {
        let range_end = start.0.saturating_add(size);
        if image_offset.0 >= start.0 && end <= range_end {
            return Ok(());
        }
    }
    bail!(
        "patch {}..{:#x} is not inside a patchable code or data region \
         (headers, tables, symbols and debug metadata are protected)",
        image_offset.to_hex(),
        end
    )
}

// ---------------------------------------------------------------------------
// `db query`
// ---------------------------------------------------------------------------

const LIST_LIMIT_DEFAULT: usize = 1000;
const LIST_LIMIT_MAX: usize = 10_000;
const BYTES_LIMIT: usize = 1024 * 1024;

fn list_window(limit: Option<usize>, offset: Option<usize>) -> (usize, usize) {
    let limit = limit.unwrap_or(LIST_LIMIT_DEFAULT).min(LIST_LIMIT_MAX);
    (limit, offset.unwrap_or(0))
}

fn page<T>(items: Vec<T>, limit: usize, offset: usize) -> Vec<T> {
    items.into_iter().skip(offset).take(limit).collect()
}

fn query(
    path: &Path,
    action: QueryAction,
    json_output: bool,
    allow_stale: bool,
    update: bool,
    limits: &InputLimits,
    exec: &AnalysisExecutionOptions,
) -> Result<()> {
    if allow_stale && update {
        bail!("--allow-stale and --update are mutually exclusive");
    }

    let mut database = db(Database::open(
        path,
        if update {
            OpenMode::ReadWrite
        } else {
            OpenMode::ReadOnly
        },
    ))?;

    // Temporary computations (`trace`, `emulate`, `signatures`) are never
    // persisted and keep their original full-image semantics; when a scope is
    // in force they say so instead of silently pretending the exclusion applies.
    match &action {
        QueryAction::Trace { action } => {
            let (image, scope, image_bytes) = effective_image(&mut database)?;
            warn_scope_ignored(&scope);
            let parsed = parse_image(&image_bytes, &selection_from_image(&image))?;
            return crate::commands::handle_trace_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        QueryAction::Emulate { action } => {
            let (image, scope, image_bytes) = effective_image(&mut database)?;
            warn_scope_ignored(&scope);
            let parsed = parse_image(&image_bytes, &selection_from_image(&image))?;
            return crate::commands::handle_emulate_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        QueryAction::Signatures { action } => {
            let (image, scope, image_bytes) = effective_image(&mut database)?;
            warn_scope_ignored(&scope);
            let parsed = parse_image(&image_bytes, &selection_from_image(&image))?;
            return crate::commands::handle_signatures_command(
                parsed.binary.as_format(),
                action.clone(),
            );
        }
        _ => {}
    }

    if let QueryAction::Decompile {
        function,
        render_flags,
    } = &action
    {
        return query_decompile(
            &mut database,
            function,
            render_flags,
            json_output,
            allow_stale,
            update,
            limits,
            exec,
        );
    }

    // Everything below is a pure database read: no image is parsed, and no
    // stored artifact outside the rows the query names is loaded. Function
    // display names come from two batched lookups per page, never from a full
    // symbol/name table.
    let (image, scope) = {
        let read = db(database.snapshot())?;
        let image = db(read.image())?;
        let scope = db(read.scope())?;
        (image, scope)
    };
    let scope_map = ScopeMap::from_scope(&scope);
    match action {
        QueryAction::Info { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let info = {
                let read = db(database.snapshot())?;
                db(read.info())?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&info)?);
            } else {
                println!("format      {}", info.image.format);
                println!("arch        {}", info.image.architecture);
                println!("bitness     {}", info.image.bitness);
                println!("endianness  {}", info.image.endianness);
                println!(
                    "abi         pointer={} long={}",
                    info.image.abi.pointer_size, info.image.abi.long_size
                );
                println!(
                    "entry       {}",
                    info.image
                        .entry_address
                        .map(|a| a.to_hex())
                        .unwrap_or_else(|| "-".into())
                );
                println!("mappings    {}", info.image.mappings.len());
                for mapping in page(info.image.mappings.clone(), limit, offset) {
                    println!(
                        "  {:<16} {} size {:#x} file {}",
                        mapping.name,
                        mapping.va.to_hex(),
                        mapping.memory_size,
                        mapping
                            .file_offset
                            .map(|offset| offset.to_hex())
                            .unwrap_or_else(|| "-".to_string())
                    );
                }
                println!(
                    "coverage    {} ({} known function(s) excluded by scope)",
                    info.coverage, info.skipped_functions
                );
                for &(start, end) in ScopeMap::from_scope(&info.analysis_scope).spans() {
                    println!(
                        "  scope     {}..{}",
                        Address(start).to_hex(),
                        Address(end).to_hex()
                    );
                }
            }
        }
        QueryAction::Sections { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = page(image.sections.clone(), limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for section in rows {
                    println!(
                        "{:<28} {} size {:#x} file {} {}",
                        section.name,
                        section.va.to_hex(),
                        section.memory_size,
                        section
                            .file_offset
                            .map(|offset| offset.to_hex())
                            .unwrap_or_else(|| "-".to_string()),
                        section.flags
                    );
                }
            }
        }
        QueryAction::Symbols { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = {
                let read = db(database.snapshot())?;
                db(read.symbols_page(limit, offset))?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for symbol in rows {
                    println!(
                        "{} {:<8} {:<6} {}",
                        symbol.address.to_hex(),
                        symbol.kind,
                        symbol.size,
                        symbol.name
                    );
                }
            }
        }
        QueryAction::Functions { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let (rows, names, symbols) = {
                let read = db(database.snapshot())?;
                let rows = db(read.functions_page(limit, offset))?;
                let addresses: Vec<Address> =
                    rows.iter().map(|row| row.function.address).collect();
                let names = db(read.names_for(&addresses))?;
                let symbols = db(read.symbols_for(&addresses))?;
                (rows, names, symbols)
            };
            if json_output {
                let payload: Vec<_> = rows
                    .iter()
                    .map(|row| {
                        json!({
                            "address": row.function.address.to_hex(),
                            "name": display_name_from_maps(&names, &symbols, &row.function),
                            "end": row.function.declared_end.map(|end| end.to_hex()),
                            "bounds": row.function.bounds_origin.as_str(),
                            "origin": row.function.origin.as_str(),
                            "excluded": row.function.excluded,
                            "skipped_by_scope": scope_map.contains(row.function.address.0),
                            "state": row.state.map(|state| state.as_str()).unwrap_or("missing"),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                for row in rows {
                    println!(
                        "{} {:<12} {:<9} {}{}",
                        row.function.address.to_hex(),
                        row.state.map(|state| state.as_str()).unwrap_or("missing"),
                        row.function.bounds_origin.as_str(),
                        display_name_from_maps(&names, &symbols, &row.function),
                        if scope_map.contains(row.function.address.0) {
                            "  (skipped by scope)"
                        } else {
                            ""
                        }
                    );
                }
            }
        }
        QueryAction::Disasm {
            function,
            limit,
            offset,
        } => {
            let (address, instructions) = {
                let read = db(database.snapshot())?;
                let address = resolve_function_reads(&read, &function)?;
                let mut decoded = db(read.instructions_for_functions(&[address]))?;
                (address, decoded.remove(&address).unwrap_or_default())
            };
            let _ = address;
            let (limit, offset) = list_window(limit, offset);
            let rows = page(instructions, limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for instruction in rows {
                    println!(
                        "{}  {:<8} {:<24} {}",
                        Address(instruction.address).to_hex(),
                        instruction
                            .bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>(),
                        instruction.mnemonic,
                        instruction
                            .operands
                            .iter()
                            .map(|operand| format!("{operand}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
            }
        }
        QueryAction::Cfg {
            function,
            dot,
            html,
        } => {
            let (address, instructions, data, name) = {
                let read = db(database.snapshot())?;
                let address = resolve_function_reads(&read, &function)?;
                let addresses = [address];
                let mut instructions = db(read.instructions_for_functions(&addresses))?;
                let mut cfgs = db(read.cfgs_for_functions(&addresses))?;
                let Some(data) = cfgs.remove(&address) else {
                    bail!("no CFG for {}; run `db analyze`", address.to_hex());
                };
                let Some(instructions) = instructions.remove(&address) else {
                    bail!(
                        "no decoded instructions for {}; run `db analyze`",
                        address.to_hex()
                    );
                };
                let name = match db(read.function_at(address))? {
                    Some(row) => {
                        let names = db(read.names_for(&addresses))?;
                        let symbols = db(read.symbols_for(&addresses))?;
                        display_name_from_maps(&names, &symbols, &row)
                    }
                    None => format!("sub_{:x}", address.0),
                };
                (address, instructions, data, name)
            };
            let _ = address;
            let cfg = cfg_from_records(&data, &instructions)?;
            if dot {
                println!(
                    "{}",
                    hexray_analysis::CfgDotExporter::new().export_to_string(&cfg, &name)
                );
            } else if html {
                println!(
                    "{}",
                    hexray_analysis::CfgHtmlExporter::new().export_to_string(&cfg, &name)
                );
            } else if json_output {
                println!("{}", serde_json::to_string_pretty(&data)?);
            } else {
                println!("CFG {} ({} blocks)", name, data.blocks.len());
                for block in &data.blocks {
                    println!(
                        "  bb{:<4} {}..{} {:?}",
                        block.id,
                        block.start.to_hex(),
                        block.end.to_hex(),
                        block.terminator
                    );
                    for address in data.block_instructions(block.id) {
                        println!("      {}", address.to_hex());
                    }
                }
                for (from, to, kind) in &data.edges {
                    println!("  edge bb{from} -> bb{to} ({})", kind.as_str());
                }
            }
        }
        QueryAction::Xrefs {
            address,
            limit,
            offset,
        } => {
            let address = parse_address(&address)?;
            let (limit, offset) = list_window(limit, offset);
            let mut rows = {
                let read = db(database.snapshot())?;
                db(read.xrefs_for_addresses(&[address]))?
            };
            rows.sort_by_key(|row| (row.from.0, row.to.0));
            let rows = page(rows, limit, offset);
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{} -> {} {} ({})",
                        row.from.to_hex(),
                        row.to.to_hex(),
                        row.kind.as_str(),
                        row.owner
                            .map(|owner| owner.to_hex())
                            .unwrap_or_else(|| "image".into())
                    );
                }
            }
        }
        QueryAction::Callgraph {
            function,
            dot,
            html,
        } => {
            // A call graph is inherently whole-image: it needs every live
            // function and every call xref. Nothing else is loaded.
            let (root, live, calls, names, symbols) = {
                let read = db(database.snapshot())?;
                let root = match &function {
                    Some(reference) => Some(resolve_function_reads(&read, reference)?),
                    None => None,
                };
                let live = db(read.functions_page(10_000_000, 0))?;
                let addresses: Vec<Address> =
                    live.iter().map(|row| row.function.address).collect();
                let names = db(read.names_for(&addresses))?;
                let symbols = db(read.symbols_for(&addresses))?;
                let calls = db(read.call_xrefs(root))?;
                (root, live, calls, names, symbols)
            };
            let mut graph = hexray_analysis::CallGraph::new();
            for row in &live {
                graph.add_node(
                    row.function.address.0,
                    Some(display_name_from_maps(&names, &symbols, &row.function)),
                    false,
                );
            }
            for row in &calls {
                graph.add_call(
                    row.from.0,
                    row.to.0,
                    hexray_analysis::CallSite {
                        call_address: row.from.0,
                        call_type: hexray_analysis::CallType::Direct,
                    },
                );
            }
            if dot {
                println!(
                    "{}",
                    hexray_analysis::CallGraphDotExporter::new().export_to_string(&graph)
                );
            } else if html {
                println!(
                    "{}",
                    hexray_analysis::CallGraphHtmlExporter::new().export_to_string(&graph)
                );
            } else if json_output {
                println!(
                    "{}",
                    hexray_analysis::CallGraphJsonExporter::new().export_to_string(&graph)
                );
            } else {
                for row in &calls {
                    if let Some(root) = root {
                        if row.from != root {
                            continue;
                        }
                    }
                    let target = names
                        .get(&row.to)
                        .cloned()
                        .or_else(|| {
                            symbols
                                .get(&row.to)
                                .map(|symbol| {
                                    hexray_demangle::demangle_or_original(&symbol.name).to_string()
                                })
                        })
                        .unwrap_or_else(|| format!("sub_{:x}", row.to.0));
                    println!("{} -> {target}", Address(row.from.0).to_hex());
                }
            }
        }
        QueryAction::Strings { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = {
                let read = db(database.snapshot())?;
                db(read.strings_page(limit, offset))?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!(
                        "{} {:<6} {}",
                        row.address.to_hex(),
                        row.encoding.as_str(),
                        row.text
                            .unwrap_or_else(|| String::from_utf8_lossy(&row.bytes).into_owned())
                    );
                }
            }
        }
        QueryAction::Bytes { address, length } => {
            let address = parse_address(&address)?;
            if length as usize > BYTES_LIMIT {
                bail!("byte requests are limited to {BYTES_LIMIT} bytes");
            }
            let bytes = {
                let (image, _, image_bytes) = effective_image(&mut database)?;
                read_image_bytes(&image, &image_bytes, address, length)?
            };
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "address": address.to_hex(),
                        "length": bytes.len(),
                        "hex": bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                    }))?
                );
            } else {
                for (index, chunk) in bytes.chunks(16).enumerate() {
                    let offset = address.0 as usize + index * 16;
                    let hex: Vec<String> = chunk.iter().map(|byte| format!("{byte:02x}")).collect();
                    println!("{:016x}  {}", offset, hex.join(" "));
                }
            }
        }
        QueryAction::Variables { function } => {
            let (address, rows) = {
                let read = db(database.snapshot())?;
                let address = resolve_function_reads(&read, &function)?;
                let rows: Vec<hexray_db::VariableOverrideRow> = db(read.variable_overrides())?
                    .into_iter()
                    .filter(|row| row.function == address)
                    .collect();
                (address, rows)
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                println!("Editable variable locators for {}", address.to_hex());
                for row in &rows {
                    println!(
                        "  {} name={} type={}",
                        row.locator.to_key(),
                        row.name.clone().unwrap_or_else(|| "-".into()),
                        row.type_name.clone().unwrap_or_else(|| "-".into())
                    );
                }
                // Doubled braces because these are `println!` literals, not
                // format placeholders.
                println!(r#"  {{"kind":"parameter","index":0}}"#);
                println!(r#"  {{"kind":"stack","offset":"-16"}}"#);
                println!(r#"  {{"kind":"expression","generation":1,"key":"register:0:4"}}"#);
            }
        }
        QueryAction::Types { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let rows = {
                let read = db(database.snapshot())?;
                db(read.types_page(limit, offset))?
            };
            if json_output {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                for row in rows {
                    println!("{:<20} {:<10} {}", row.name, row.kind.as_str(), row.origin);
                }
            }
        }
        QueryAction::History { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let read = db(database.snapshot())?;
            let events = db(read.history_events(limit, offset))?;
            let commands = db(read.command_history(limit, offset))?;
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "events": events,
                        "commands": commands.iter().map(|row| json!({
                            "id": row.id,
                            "actor": row.actor,
                            "command": row.command,
                            "success": row.success,
                            "timestamp": row.timestamp,
                            "truncated": row.truncated,
                        })).collect::<Vec<_>>(),
                    }))?
                );
            } else {
                for event in events {
                    println!(
                        "#{:<6} {:<12} rev {:<6} {} {}",
                        event.id,
                        event.action,
                        event.revision.0,
                        event.kind.unwrap_or_default(),
                        event.timestamp
                    );
                }
            }
        }
        QueryAction::Changes { limit, offset } => {
            let (limit, offset) = list_window(limit, offset);
            let read = db(database.snapshot())?;
            let events = db(read.history_events(limit, offset))?;
            if json_output {
                println!("{}", serde_json::to_string_pretty(&events)?);
            } else {
                for event in events {
                    println!(
                        "#{:<6} {:<12} rev {:<6} {}",
                        event.id,
                        event.action,
                        event.revision.0,
                        event.kind.unwrap_or_default()
                    );
                }
            }
        }
        QueryAction::Scope { section_hints } => {
            let (image, scope, image_bytes) = effective_image(&mut database)?;
            let hints = if section_hints {
                let parsed = parse_image(&image_bytes, &selection_from_image(&image))?;
                Some(section_hints_for(&parsed.binary, &parsed.info))
            } else {
                None
            };
            if json_output {
                let mut payload = json!({
                    "analysis_scope": scope,
                    "coverage": if scope.is_empty() { "full" } else { "filtered" },
                });
                if let Some(hints) = &hints {
                    payload["section_hints"] = serde_json::to_value(hints)?;
                    payload["warning"] = json!(SECTION_HINTS_WARNING);
                }
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                print_scope(&scope);
                if let Some(hints) = &hints {
                    print_section_hints(&image, hints);
                }
            }
        }
        QueryAction::Decompile { .. }
        | QueryAction::Trace { .. }
        | QueryAction::Emulate { .. }
        | QueryAction::Signatures { .. } => unreachable!("handled before the read path"),
    }
    Ok(())
}

/// Stored pseudo-C for one function and one render configuration.
///
/// The cached path reads only the function's own rows: its location, the stored
/// text, and the metadata the render key needs (image ABI, type snapshot, user
/// types). It never materializes the image, the instructions or a CFG.
#[allow(clippy::too_many_arguments)]
fn query_decompile(
    database: &mut Database,
    function: &str,
    render_flags: &RenderFlags,
    json_output: bool,
    allow_stale: bool,
    update: bool,
    limits: &InputLimits,
    exec: &AnalysisExecutionOptions,
) -> Result<()> {
    let (address, image, scope, config) = {
        let read = db(database.snapshot())?;
        let address = resolve_function_reads(&read, function)?;
        let image = db(read.image())?;
        let scope = db(read.scope())?;
        let config = render_config_from_reads(&read, &image, render_flags)?;
        (address, image, scope, config)
    };
    // A GPU code object has no pseudo-C path at all, so refuse before touching
    // stored artifacts or rebuilding anything.
    if !image_supports_pseudo_c(&image) {
        bail!("pseudo-C is unsupported for GPU code objects");
    }
    let scope_map = ScopeMap::from_scope(&scope);
    let excluded = scope_map.contains(address.0);
    let fingerprint = config.fingerprint();
    let key = UnitKey::function_render(address, fingerprint);

    if update {
        // Rebuild whatever is stale or missing — CFG first, then the rendered
        // text — through the same path `db analyze` uses.
        run_analysis(
            database,
            &AnalyzeRequest {
                function: Some(address.to_hex()),
                force: false,
                render: Some(config.clone()),
                limits: limits.clone(),
                exec: exec.clone(),
            },
        )?;
    } else if excluded && !allow_stale {
        bail!(
            "function {} is excluded by analysis scope; pass --allow-stale to read the \
             historical pseudo-C, or change the scope with `db edit <db> scope`",
            address.to_hex()
        );
    }

    let (state, stored) = {
        let read = db(database.snapshot())?;
        let state = db(read.unit(&key))?.map(|unit| unit.state);
        let stored = db(read.decompiled(address, &fingerprint))?;
        (state, stored)
    };
    if state == Some(AnalysisState::Unsupported) {
        bail!("pseudo-C is unsupported for GPU code objects");
    }
    let excluded_label = if excluded { "scope-excluded" } else { "" };
    let text = stored.map(|(_, text)| text);
    match (text, state) {
        (Some(text), Some(AnalysisState::Current)) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "function": address.to_hex(),
                        "state": "current",
                        "config": hexray_db::hex_encode(&fingerprint),
                        "text": text,
                    }))?
                );
            } else {
                println!("{text}");
            }
            Ok(())
        }
        (Some(text), state) if allow_stale => {
            let state_label = state.map(|state| state.as_str()).unwrap_or("missing");
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "function": address.to_hex(),
                        "state": state_label,
                        "stale": true,
                        "scope_excluded": excluded,
                        "text": text,
                    }))?
                );
            } else {
                if excluded {
                    println!("// {excluded_label}: the analysis scope now excludes this function");
                }
                println!(
                    "// stale: state is {state_label}; \
                     run `db query ... decompile ... --update`"
                );
                println!("{text}");
            }
            Ok(())
        }
        (Some(_), state) => bail!(
            "pseudo-C for this configuration is {}; pass --allow-stale to view it \
             or --update to rebuild it",
            state.map(|state| state.as_str()).unwrap_or("missing")
        ),
        (None, _) => {
            if update {
                bail!("no pseudo-C was produced for this function");
            }
            bail!(
                "no current pseudo-C for this configuration; \
                 re-run with `--update` (or `db analyze --render`)"
            );
        }
    }
}

/// Render one function from its persisted artifacts.
///
/// Returns the unit to publish, or `None` for "nothing to render" (missing
/// artifacts), plus warnings for the main thread to print in address order.
#[allow(clippy::too_many_arguments)]
fn compute_render_unit(
    binary: &Binary<'_>,
    snapshot: &AnalysisSnapshot,
    shared: &SharedAnalysisContext,
    decompiler_config: &hexray_analysis::DecompilerConfig,
    signature_overrides: &BTreeMap<u64, hexray_analysis::FunctionSignature>,
    variable_overrides: &BTreeMap<u64, Vec<hexray_analysis::VariableOverride>>,
    overlay: &CommentOverlay,
    config: &RenderConfig,
    fingerprint: &[u8; 32],
    instructions: &BTreeMap<Address, Vec<Instruction>>,
    cfgs: &BTreeMap<Address, hexray_db::store::CfgData>,
    generations: &BTreeMap<Address, Option<u64>>,
    address: &Address,
) -> (Address, Option<UnitPublish>, Vec<String>) {
    let mut warnings = Vec::new();
    let Some(function) = snapshot.function(*address) else {
        return (*address, None, warnings);
    };
    if !function.is_live() {
        return (*address, None, warnings);
    }
    let key = UnitKey::function_render(*address, *fingerprint);
    let (Some(instructions), Some(cfg_data)) = (instructions.get(address), cfgs.get(address)) else {
        return (*address, None, warnings);
    };
    let cfg = match cfg_from_records(cfg_data, instructions) {
        Ok(cfg) => cfg,
        Err(error) => {
            warnings.push(format!(
                "warning: {} CFG is unreadable: {error}",
                address.to_hex()
            ));
            return (*address, None, warnings);
        }
    };
    let name = snapshot.display_name(function);
    let (max_bytes, stop_after_first_return) = function_limit(function);
    let inputs = AnalysisInputs {
        shared,
        config: Some(decompiler_config),
        diagnostics: false,
        signature_override: signature_overrides.get(&address.0),
        variable_overrides: variable_overrides
            .get(&address.0)
            .map(Vec::as_slice)
            .unwrap_or(&[]),
        decoded: None,
        scope_map: None,
    };
    let analyzed = match analyze_replay(
        binary,
        ReplayInput {
            start: address.0,
            name,
            symbol_kind: None,
            instructions: instructions.clone(),
            cfg,
            max_bytes,
            stop_after_first_return,
        },
        &inputs,
    ) {
        Ok(analyzed) => analyzed,
        Err(error) => {
            warnings.push(format!(
                "warning: {} replay failed: {error}",
                address.to_hex()
            ));
            return (*address, None, warnings);
        }
    };
    let rendered = match render_function(
        analyzed,
        &RenderOptions {
            show_addresses: config.show_addresses,
            comments: Some(overlay.clone()),
        },
    ) {
        Ok(rendered) => rendered,
        Err(error) => {
            warnings.push(format!(
                "warning: {} render failed: {error}",
                address.to_hex()
            ));
            return (*address, None, warnings);
        }
    };
    (
        *address,
        Some(UnitPublish {
            key,
            expected_generation: generations.get(address).copied().flatten(),
            state: AnalysisState::Current,
            input_fingerprint: *fingerprint,
            dependencies_complete: true,
            diagnostics: Vec::new(),
            dependencies: vec![
                Dependency {
                    kind: DependencyKind::Range,
                    key: "bytes".to_string(),
                    range: hexray_db::AddressRange::new(*address, 1).ok(),
                    target_generation: 0,
                },
                Dependency {
                    kind: DependencyKind::Name,
                    key: format!("address:{:x}", address.0),
                    range: None,
                    target_generation: 0,
                },
            ],
            payload: AnalysisPayload::FunctionRender(Box::new(RenderPayload {
                function: *address,
                config_fingerprint: *fingerprint,
                text: rendered.text,
            })),
        }),
        warnings,
    )
}

/// Canonical render configuration computed from the database alone.
fn render_config_from_reads(
    read: &hexray_db::ReadSnapshot<'_>,
    image: &ImageInfo,
    flags: &RenderFlags,
) -> Result<RenderConfig> {
    let types = db(read.types())?;
    let type_snapshot = db(read.resource("type_snapshot", "builtin"))?;
    let builtin_types_json = type_snapshot
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok());
    let database = build_type_database(builtin_types_json, &types, image)?;
    Ok(RenderConfig {
        optimization_level: flags.opt_level.clone(),
        enable_passes: flags.enable_passes.clone(),
        disable_passes: flags.disable_passes.clone(),
        show_addresses: flags.show_addresses,
        indent: "    ".to_string(),
        type_snapshot_sha256: type_snapshot_digest(&database),
        engine_fingerprint: read.engine_fingerprint(),
    })
}

/// True when the stored architecture has a pseudo-C path.
///
/// The GPU variants carry a specific architecture that the label alone cannot
/// reconstruct, so this checks the recorded family label instead of guessing.
fn image_supports_pseudo_c(image: &ImageInfo) -> bool {
    matches!(
        image.architecture.as_str(),
        "x86" | "x86_64" | "arm64" | "riscv32" | "riscv64"
    )
}

/// Effective bytes of the whole source plus the selected image slice.
fn effective_image(database: &mut Database) -> Result<(ImageInfo, AnalysisScope, Vec<u8>)> {
    let (image, scope, source, patches) = {
        let read = db(database.snapshot())?;
        (
            db(read.image())?,
            db(read.scope())?,
            db(read.source_bytes())?,
            db(read.patches())?,
        )
    };
    let effective = effective_source(&source, &patches)?;
    let start = usize::try_from(image.container_offset.0)
        .map_err(|_| anyhow::anyhow!("image offset is out of range"))?;
    let end = start
        .checked_add(usize::try_from(image.container_length)?)
        .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
    let bytes = effective
        .get(start..end)
        .ok_or_else(|| anyhow::anyhow!("stored image range exceeds the stored input"))?
        .to_vec();
    Ok((image, scope, bytes))
}

/// Say plainly that a temporary computation ignores the automatic scope.
fn warn_scope_ignored(scope: &AnalysisScope) {
    if !scope.is_empty() {
        eprintln!("warning: temporary query ignores automatic analysis scope");
    }
}

fn print_scope(scope: &AnalysisScope) {
    if scope.is_empty() {
        println!("analysis scope: full image (nothing excluded)");
        println!("coverage:       full");
        return;
    }
    println!("analysis scope: filtered");
    println!("coverage:       filtered");
    for &(start, end) in ScopeMap::from_scope(scope).spans() {
        println!(
            "  {}-{} ({} bytes)",
            Address(start).to_hex(),
            Address(end).to_hex(),
            end.saturating_sub(start)
        );
    }
    for range in &scope.excluded_ranges {
        if let Some(name) = &range.section_name {
            println!(
                "  section {name}: {}..{}",
                range.start.to_hex(),
                range.end.to_hex()
            );
        }
    }
}

/// Per-section packing hints for one parsed image.
fn section_hints_for(binary: &Binary<'_>, image: &ImageInfo) -> Vec<SectionHint> {
    let mut hints: Vec<SectionHint> = Vec::new();
    for section in binary.as_format().sections() {
        if !section.is_executable() || section.size() == 0 || section.data().is_empty() {
            continue;
        }
        let start = section.virtual_address();
        let end = start.saturating_add(section.size());
        // Mach-O sections report `is_writable() == false` unconditionally, so
        // the W+X evidence comes from the segment mapping, never the section.
        let mapping = image.mappings.iter().find(|mapping| {
            mapping.va.0 <= start && start < mapping.va.0.saturating_add(mapping.memory_size)
        });
        let writable = mapping
            .map(|mapping| mapping.permissions.write)
            .unwrap_or_else(|| section.is_writable());
        let executable = mapping
            .map(|mapping| mapping.permissions.execute)
            .unwrap_or_else(|| section.is_executable());
        hints.push(crate::analysis_scope::section_hint(
            section.name(),
            start,
            end,
            section.data(),
            writable,
            executable,
        ));
    }
    hints.sort_by_key(|hint| (hint.start, hint.name.clone()));
    hints
}

fn print_section_hints(image: &ImageInfo, hints: &[SectionHint]) {
    println!("Section hints for {} {}", image.format, image.architecture);
    for hint in hints {
        println!(
            "  {:<24} {}-{}  {} file bytes  entropy {}  {}",
            hint.name,
            Address(hint.start).to_hex(),
            Address(hint.end).to_hex(),
            hint.file_bytes,
            hint.entropy_bits_per_byte
                .map(|value| format!("{value:.2}"))
                .unwrap_or_else(|| "n/a".into()),
            if hint.reasons.is_empty() {
                "-".to_string()
            } else {
                hint.reasons.join(",")
            }
        );
        if hint.suggest_skip {
            println!(
                "      possible: db edit <db> scope {}",
                shell_quote_arg(&format!("--skip-section={}", hint.name))
            );
        }
    }
    println!("warning: {SECTION_HINTS_WARNING}");
}

/// Quote one shell argument only when it needs it.
fn shell_quote_arg(value: &str) -> String {
    let simple = !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='));
    if simple {
        value.to_string()
    } else {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

fn read_image_bytes(
    image: &ImageInfo,
    image_bytes: &[u8],
    address: Address,
    length: u64,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut remaining = length;
    let mut cursor = address.0;
    while remaining > 0 {
        let Some(mapping) = image.mappings.iter().find(|mapping| {
            cursor >= mapping.va.0 && cursor < mapping.va.0.saturating_add(mapping.memory_size)
        }) else {
            bail!("{} is not mapped", Address(cursor).to_hex());
        };
        let delta = cursor - mapping.va.0;
        let available_memory = mapping.memory_size - delta;
        let (chunk_len, zero_fill) = if delta < mapping.file_size {
            let file_backed = (mapping.file_size - delta).min(available_memory);
            (file_backed.min(remaining), false)
        } else {
            (available_memory.min(remaining), true)
        };
        if chunk_len == 0 {
            break;
        }
        if zero_fill {
            out.resize(out.len() + chunk_len as usize, 0);
        } else {
            let Some(file_offset) = mapping.file_offset else {
                out.resize(out.len() + chunk_len as usize, 0);
                remaining -= chunk_len;
                cursor += chunk_len;
                continue;
            };
            let start = usize::try_from(file_offset.0 + delta)?;
            let end = start
                .checked_add(usize::try_from(chunk_len)?)
                .ok_or_else(|| anyhow::anyhow!("byte range overflows"))?;
            let bytes = image_bytes
                .get(start..end)
                .ok_or_else(|| anyhow::anyhow!("byte range is outside the stored image"))?;
            out.extend_from_slice(bytes);
        }
        remaining -= chunk_len;
        cursor += chunk_len;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `db edit`, `db undo`, `db redo`
// ---------------------------------------------------------------------------

fn edit(path: &Path, action: EditAction, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let snapshot = load_snapshot(&mut database)?;
    let edits = build_edits(&snapshot, &action)?;

    let mut revision = expect_revision.map(Revision).unwrap_or(snapshot.revision);
    let mut applied = 0usize;
    for edit in edits {
        let result = db(database.apply(revision, &edit))?;
        match result {
            EditOutcome::Applied(next) => {
                applied += 1;
                revision = next;
            }
            EditOutcome::Unchanged(current) => {
                revision = current;
            }
        }
    }

    if applied == 0 {
        println!("No change; revision stays {}.", revision.0);
    } else {
        println!("Applied {applied} edit(s); revision {}.", revision.0);
    }
    Ok(())
}

fn build_edits(snapshot: &AnalysisSnapshot, action: &EditAction) -> Result<Vec<Edit>> {
    let selection = selection_from_image(&snapshot.image);
    let parsed = parse_image(snapshot.image_bytes(), &selection)?;
    let fmt = parsed.binary.as_format();

    let mut edits = Vec::new();
    match action {
        EditAction::Patch { address, hex_bytes } => {
            let bytes = parse_hex_bytes(hex_bytes)?;
            let offset = resolve_patch_offset(snapshot, fmt, address)?;
            require_patchable(snapshot, fmt, offset, bytes.len() as u64)?;
            edits.push(Edit::PatchBytes {
                file_offset: offset,
                bytes,
            });
        }
        EditAction::MakeCode { address, length } => edits.push(Edit::SetItem {
            address: parse_address(address)?,
            length: *length,
            kind: ItemKind::Code,
            type_name: None,
        }),
        EditAction::MakeData {
            address,
            length,
            type_name,
        } => edits.push(Edit::SetItem {
            address: parse_address(address)?,
            length: *length,
            kind: ItemKind::Data,
            type_name: type_name.clone(),
        }),
        EditAction::Undefine { address, length } => edits.push(Edit::ClearItem {
            address: parse_address(address)?,
            length: *length,
        }),
        EditAction::FunctionCreate { start, end } => edits.push(Edit::CreateFunction {
            start: parse_address(start)?,
            end: parse_address(end)?,
        }),
        EditAction::FunctionBounds { start, end } => edits.push(Edit::SetFunctionBounds {
            start: parse_address(start)?,
            end: parse_address(end)?,
        }),
        EditAction::FunctionRemove { start } => edits.push(Edit::RemoveFunction {
            start: parse_address(start)?,
        }),
        EditAction::FunctionExclude { start, excluded } => {
            let excluded = match excluded.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => true,
                "false" | "0" | "no" => false,
                other => bail!("'{other}' is not a boolean"),
            };
            edits.push(Edit::SetFunctionExcluded {
                start: parse_address(start)?,
                excluded,
            });
        }
        EditAction::Name { address, name } => edits.push(Edit::SetName {
            address: parse_address(address)?,
            name: Some(name.clone()),
        }),
        EditAction::Comment { address, text } => edits.push(Edit::SetComment {
            address: parse_address(address)?,
            text: Some(text.clone()),
        }),
        EditAction::Tag { address, text } => edits.push(Edit::SetTag {
            address: parse_address(address)?,
            text: Some(text.clone()),
        }),
        EditAction::Bookmark { address, label } => edits.push(Edit::SetBookmark {
            address: parse_address(address)?,
            label: label.clone(),
        }),
        EditAction::Signature {
            function,
            prototype,
        } => {
            // Validate here: the store cannot tell a C prototype from prose.
            prototype_to_signature(prototype, hexray_analysis::CallingConvention::SystemV)
                .context("signature")?;
            edits.push(Edit::SetFunctionSignature {
                start: parse_address(function)?,
                prototype: Some(prototype.clone()),
            });
        }
        EditAction::CallingConvention {
            function,
            convention,
        } => {
            if calling_convention_from_name(convention).is_none() {
                bail!(
                    "unknown calling convention '{convention}' (use systemv, win64, aarch64 or riscv)"
                );
            }
            edits.push(Edit::SetCallingConvention {
                start: parse_address(function)?,
                convention: Some(convention.clone()),
            });
        }
        EditAction::TypeImport { header } => {
            let metadata = std::fs::metadata(header)
                .with_context(|| format!("failed to stat {}", header.display()))?;
            if metadata.len() > 16 * 1024 * 1024 {
                bail!("header is larger than the 16 MiB limit");
            }
            let text = std::fs::read_to_string(header)
                .with_context(|| format!("failed to read {}", header.display()))?;
            let database = hexray_types::parser::parse_header(&text).map_err(|error| {
                anyhow::anyhow!("failed to parse {}: {error}", header.display())
            })?;
            let mut type_names: Vec<&str> = database.type_names().collect();
            type_names.sort_unstable();
            for name in type_names {
                if let Some(ty) = database.get_type(name) {
                    let kind = match ty {
                        hexray_types::CType::Struct(_) => TypeKind::Struct,
                        hexray_types::CType::Union(_) => TypeKind::Union,
                        hexray_types::CType::Enum(_) => TypeKind::Enum,
                        _ => TypeKind::Typedef,
                    };
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind,
                        payload_json: serde_json::to_string(ty)?,
                    });
                }
            }
            let mut typedefs: Vec<&str> = database.typedef_names().collect();
            typedefs.sort_unstable();
            for name in typedefs {
                if let Some(ty) = database.get_type(name) {
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind: TypeKind::Typedef,
                        payload_json: serde_json::to_string(ty)?,
                    });
                }
            }
            let mut functions: Vec<&str> = database.function_names().collect();
            functions.sort_unstable();
            for name in functions {
                if let Some(prototype) = database.get_function(name) {
                    edits.push(Edit::PutType {
                        name: name.to_string(),
                        kind: TypeKind::Prototype,
                        payload_json: serde_json::to_string(prototype)?,
                    });
                }
            }
            if edits.is_empty() {
                bail!("{} declares no types", header.display());
            }
        }
        EditAction::TypeRemove { name } => edits.push(Edit::RemoveType { name: name.clone() }),
        EditAction::ApplyType {
            address,
            type_name,
            length,
        } => edits.push(Edit::ApplyType {
            address: parse_address(address)?,
            type_name: Some(type_name.clone()),
            length: *length,
        }),
        EditAction::Variable {
            function,
            locator,
            name,
            type_name,
        } => edits.push(Edit::SetVariableOverride {
            function: parse_address(function)?,
            locator: VariableLocator::from_json(locator)
                .map_err(|error| anyhow::anyhow!("{error}"))?,
            name: name.clone(),
            type_name: type_name.clone(),
        }),
        EditAction::Clear {
            target,
            address,
            locator,
        } => {
            let target_kind = hexray_db::edit::OverrideTarget::parse(target).ok_or_else(|| {
                anyhow::anyhow!(
                    "unknown clear target '{target}' \
                     (use name, comment, tag, bookmark, signature, calling-convention, type, variable)"
                )
            })?;
            edits.push(Edit::RemoveOverride {
                target: target_kind,
                address: parse_address(address)?,
                locator: match locator {
                    Some(locator) => Some(
                        VariableLocator::from_json(locator)
                            .map_err(|error| anyhow::anyhow!("{error}"))?,
                    ),
                    None => None,
                },
            });
        }
        EditAction::Scope { flags } => {
            // The whole policy is replaced: no flags means "clear". Unknown or
            // non-executable section names are rejected by `resolve_scope`
            // instead of silently becoming a no-op.
            edits.push(Edit::SetAnalysisScope {
                scope: resolve_scope(&snapshot.image, flags)?,
            });
        }
    }
    Ok(edits)
}

fn parse_hex_bytes(text: &str) -> Result<Vec<u8>> {
    let cleaned: String = text
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '_')
        .collect();
    let cleaned = cleaned
        .strip_prefix("0x")
        .or_else(|| cleaned.strip_prefix("0X"))
        .unwrap_or(&cleaned);
    if cleaned.is_empty() {
        bail!("patch bytes must not be empty");
    }
    if !cleaned.len().is_multiple_of(2) {
        bail!("patch bytes must have an even number of hex digits");
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for chunk in cleaned.as_bytes().chunks(2) {
        let pair = std::str::from_utf8(chunk).map_err(|_| anyhow::anyhow!("patch is not ASCII"))?;
        out.push(
            u8::from_str_radix(pair, 16)
                .map_err(|_| anyhow::anyhow!("'{pair}' is not a hex byte"))?,
        );
    }
    Ok(out)
}

fn undo(path: &Path, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let expected = match expect_revision {
        Some(revision) => Revision(revision),
        None => db(database.revision())?,
    };
    match db(database.undo(expected))? {
        EditOutcome::Applied(revision) => println!("Undone; revision {}.", revision.0),
        EditOutcome::Unchanged(revision) => println!("Nothing to undo; revision {}.", revision.0),
    }
    Ok(())
}

fn redo(path: &Path, expect_revision: Option<u64>) -> Result<()> {
    let mut database = db(Database::open(path, OpenMode::ReadWrite))?;
    let expected = match expect_revision {
        Some(revision) => Revision(revision),
        None => db(database.revision())?,
    };
    match db(database.redo(expected))? {
        EditOutcome::Applied(revision) => println!("Redone; revision {}.", revision.0),
        EditOutcome::Unchanged(revision) => println!("Nothing to redo; revision {}.", revision.0),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `db import-legacy`
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn import_legacy(
    legacy: &Path,
    binary: &Path,
    output: &Path,
    selection: &Selection,
    limits: &InputLimits,
    scope_flags: &ScopeFlags,
    exec: &AnalysisExecutionOptions,
    accept_unverified: bool,
    json_output: bool,
) -> Result<()> {
    if !legacy.exists() {
        bail!("legacy file not found: {}", legacy.display());
    }
    if output.exists() {
        bail!("destination already exists: {}", output.display());
    }
    let loaded = select_input(binary, selection, limits)?;
    let image_bytes = {
        let start = usize::try_from(loaded.selection.container_offset)?;
        let end = start
            .checked_add(usize::try_from(loaded.selection.container_length)?)
            .ok_or_else(|| anyhow::anyhow!("image range overflows"))?;
        loaded.source[start..end].to_vec()
    };
    let parsed = parse_image(&image_bytes, &loaded.selection)?;
    let scope = resolve_scope(&parsed.info, scope_flags)?;
    let source_digest = hexray_db::sha256(&loaded.source);
    let legacy_source = db(hexray_db::legacy::read_legacy_source(
        legacy,
        &source_digest,
        &loaded.source,
        accept_unverified,
    ))?;

    let mut input = build_create_input(binary, &loaded, &parsed, &scope)?;
    input.engine_fingerprint = engine_fingerprint();
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).ok();
    let mut staged = db(hexray_db::store::StagedProject::create(&parent, &input))?;
    drop(parsed);
    store_debug_sidecars(staged.database(), selection)?;
    let summary = db(staged.database().import_legacy(&legacy_source))?;
    let _ = run_analysis(
        staged.database(),
        &AnalyzeRequest {
            function: None,
            force: true,
            render: None,
            limits: limits.clone(),
            exec: exec.clone(),
        },
    )?;
    let database = db(staged.publish(output))?;
    let revision = db(database.revision())?;

    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "database": output.to_string_lossy(),
                "revision": revision.0,
                "legacy": legacy.to_string_lossy(),
                "kind": legacy_source.kind.as_str(),
                "identity": legacy_source.identity_status.as_str(),
                "imported_records": summary.imported_records,
                "applied": summary.applied,
                "unresolved": summary.unresolved,
                "by_kind": summary.by_kind.iter().map(|row| json!({
                    "kind": row.kind,
                    "applied": row.applied,
                    "unresolved": row.unresolved,
                })).collect::<Vec<_>>(),
            }))?
        );
    } else {
        println!(
            "Imported {} ({}, identity {}) into {} (revision {}).",
            legacy.display(),
            legacy_source.kind.as_str(),
            legacy_source.identity_status.as_str(),
            output.display(),
            revision.0
        );
        print!("{}", summary.render());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `db open` — interactive project shell
// ---------------------------------------------------------------------------

/// One REPL command.
enum ReplOutcome {
    Continue,
    Quit,
}

/// Parsers used to reuse the exact one-shot command grammar inside the shell.
#[derive(clap::Parser)]
struct QueryParser {
    #[command(flatten)]
    exec: GlobalAnalysisOptions,
    #[command(subcommand)]
    command: QueryAction,
}

#[derive(clap::Parser)]
struct EditParser {
    #[command(subcommand)]
    command: EditAction,
}

#[derive(clap::Parser)]
struct AnalyzeParser {
    #[command(flatten)]
    flags: AnalyzeFlags,
}

/// `scope` / `scope-set` reuse the one-shot flag grammar.
#[derive(clap::Parser)]
struct ScopeFlagsParser {
    #[command(flatten)]
    flags: ScopeFlags,
}

/// One shell session's fixed configuration.
struct ReplSession<'a> {
    path: &'a Path,
    read_only: bool,
    /// Options `db open` was started with. Each `analyze` may override them.
    exec: AnalysisExecutionOptions,
}

fn run_repl(path: &Path, read_only: bool, exec: &AnalysisExecutionOptions) -> Result<()> {
    // Validate once up front so the shell refuses to open a broken project.
    {
        let database = db(Database::open(
            path,
            if read_only {
                OpenMode::ReadOnly
            } else {
                OpenMode::ReadWrite
            },
        ))?;
        println!(
            "hexray db {} — {} mode, revision {}",
            path.display(),
            if read_only { "read-only" } else { "read-write" },
            db(database.revision())?.0
        );
        println!(
            "Analysis: {} worker(s), {} MiB working-set budget",
            exec.requested_jobs(),
            exec.analysis_memory_mib
        );
        println!("Commands: info sections symbols functions disasm cfg xrefs callgraph strings");
        println!("          bytes decompile variables types trace emulate signatures scope");
        println!("          analyze scope-set name comment tag bookmark patch make-code");
        println!("          make-data undefine function-create function-bounds function-remove");
        println!("          function-exclude signature calling-convention type-import");
        println!("          type-remove apply-type variable clear undo redo refresh check");
        println!("          backup export-binary quit");
    }

    let session = ReplSession {
        path,
        read_only,
        exec: exec.clone(),
    };

    // Without a terminal (pipes, CI) there is no line editor to drive; read
    // one command per line instead of failing outright.
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        return run_repl_batch(&session);
    }

    let mut editor = rustyline::DefaultEditor::new()
        .map_err(|error| anyhow::anyhow!("failed to start the shell: {error}"))?;
    loop {
        match editor.readline("hxdb> ") {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                let _ = editor.add_history_entry(line.trim());
                match handle_repl_line(&session, &line) {
                    Ok(ReplOutcome::Continue) => {}
                    Ok(ReplOutcome::Quit) => return Ok(()),
                    Err(error) => eprintln!("error: {error}"),
                }
            }
            Err(rustyline::error::ReadlineError::Interrupted) => continue,
            Err(rustyline::error::ReadlineError::Eof) => return Ok(()),
            Err(error) => return Err(anyhow::anyhow!("shell error: {error}")),
        }
    }
}

fn run_repl_batch(session: &ReplSession<'_>) -> Result<()> {
    use std::io::BufRead as _;
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.context("failed to read a command")?;
        if line.trim().is_empty() {
            continue;
        }
        println!("hxdb> {line}");
        match handle_repl_line(session, &line) {
            Ok(ReplOutcome::Continue) => {}
            Ok(ReplOutcome::Quit) => return Ok(()),
            Err(error) => {
                eprintln!("error: {error}");
                // A batch script stops at the first failure so a broken step
                // cannot silently be followed by successful ones.
                return Err(error);
            }
        }
    }
    Ok(())
}

fn handle_repl_line(session: &ReplSession<'_>, line: &str) -> Result<ReplOutcome> {
    let Some(args) = shlex::split(line) else {
        bail!("unbalanced quote in command");
    };
    if args.is_empty() {
        return Ok(ReplOutcome::Continue);
    }
    run_repl_command(session, &args)
}

fn run_repl_command(session: &ReplSession<'_>, args: &[String]) -> Result<ReplOutcome> {
    let path = session.path;
    let read_only = session.read_only;
    let command = args[0].as_str();
    let rest: Vec<String> = args[1..].to_vec();
    let mut json_output = false;
    let mut update = false;
    let mut bare = Vec::new();
    for argument in &rest {
        match argument.as_str() {
            "--json" => json_output = true,
            "--update" => update = true,
            _ => bare.push(argument.clone()),
        }
    }
    if update && read_only {
        bail!("'--update' needs a writable project (reopen without --read-only)");
    }

    let writable_edit = |name: &str| -> Result<()> {
        if read_only {
            bail!("'{name}' needs a writable project (reopen without --read-only)");
        }
        Ok(())
    };

    match command {
        "quit" | "exit" => return Ok(ReplOutcome::Quit),
        "info" => {
            query(
                path,
                QueryAction::Info {
                    limit: None,
                    offset: None,
                },
                json_output,
                false,
                false,
                &InputLimits::default(),
                &session.exec,
            )?;
        }
        "scope" => {
            let section_hints = bare.iter().any(|argument| argument == "--section-hints");
            let unexpected: Vec<&String> = bare
                .iter()
                .filter(|argument| *argument != "--section-hints")
                .collect();
            if !unexpected.is_empty() {
                bail!("scope takes only --section-hints (got {:?})", unexpected);
            }
            query(
                path,
                QueryAction::Scope { section_hints },
                json_output,
                false,
                false,
                &InputLimits::default(),
                &session.exec,
            )?;
        }
        "scope-set" => {
            writable_edit("scope-set")?;
            let parsed = ScopeFlagsParser::try_parse_from(
                std::iter::once("scope-set".to_string()).chain(bare.iter().cloned()),
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            edit(
                path,
                EditAction::Scope {
                    flags: parsed.flags,
                },
                None,
            )?;
        }
        "analyze" => {
            writable_edit("analyze")?;
            // `--jobs`/`--analysis-memory-mib` on this line override the
            // session defaults; omitted flags inherit what `open` was given.
            let mut argv = vec!["analyze".to_string()];
            argv.extend(bare.iter().cloned());
            let parsed =
                AnalyzeParser::try_parse_from(argv).map_err(|error| anyhow::anyhow!("{error}"))?;
            let mut exec = parsed.flags.exec.clone();
            if exec.jobs == 0 && session.exec.jobs != 0 {
                exec.jobs = session.exec.jobs;
            }
            if exec.analysis_memory_mib == AnalysisExecutionOptions::default().analysis_memory_mib
                && session.exec.analysis_memory_mib
                    != AnalysisExecutionOptions::default().analysis_memory_mib
            {
                exec.analysis_memory_mib = session.exec.analysis_memory_mib;
            }
            analyze(
                path,
                parsed.flags.function.clone(),
                parsed.flags.force,
                parsed.flags.render,
                &parsed.flags.render_flags,
                &InputLimits::default(),
                &exec,
                json_output,
            )?;
        }
        "sections" | "symbols" | "functions" | "strings" | "types" | "history" | "changes" => {
            run_query_repl(session, command, &bare, json_output, update)?;
        }
        "disasm" | "cfg" | "xrefs" | "callgraph" | "bytes" | "decompile" | "variables"
        | "trace" | "emulate" | "signatures" => {
            run_query_repl(session, command, &bare, json_output, update)?;
        }
        "undo" => {
            writable_edit("undo")?;
            undo(path, None)?;
        }
        "redo" => {
            writable_edit("redo")?;
            redo(path, None)?;
        }
        "refresh" => {
            let database = db(Database::open(path, OpenMode::ReadOnly))?;
            println!("Re-read project; revision {}.", db(database.revision())?.0);
        }
        "check" => {
            let deep = bare.iter().any(|argument| argument == "--deep");
            let unexpected: Vec<&String> = bare.iter().filter(|arg| *arg != "--deep").collect();
            if !unexpected.is_empty() {
                bail!("check takes no arguments (got {:?})", unexpected);
            }
            check(path, deep, json_output)?;
        }
        "backup" => {
            let target = bare
                .first()
                .ok_or_else(|| anyhow::anyhow!("backup <file>"))?;
            backup(path, Path::new(target))?;
        }
        "export-binary" => {
            let target = bare
                .first()
                .ok_or_else(|| anyhow::anyhow!("export-binary <file>"))?;
            export_binary(path, Path::new(target))?;
        }
        other => {
            writable_edit(other)?;
            let parsed = EditParser::try_parse_from(
                std::iter::once("edit".to_string())
                    .chain(std::iter::once(command.to_string()))
                    .chain(bare.iter().cloned()),
            )
            .map_err(|error| anyhow::anyhow!("{error}"))?;
            edit(path, parsed.command, None)?;
        }
    }
    Ok(ReplOutcome::Continue)
}

/// Parse one shell query line with the one-shot grammar.
fn parse_query_action(
    command: &str,
    args: Vec<String>,
) -> Result<(QueryAction, AnalysisExecutionOptions)> {
    // clap treats argv[0] as the program name, so the shell command word is the
    // subcommand of a synthetic `query` parser.
    let parsed = QueryParser::try_parse_from(
        std::iter::once("query".to_string())
            .chain(std::iter::once(command.to_string()))
            .chain(args),
    )
    .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok((parsed.command, AnalysisExecutionOptions::from(&parsed.exec)))
}

fn run_query_repl(
    session: &ReplSession<'_>,
    command: &str,
    args: &[String],
    json_output: bool,
    update: bool,
) -> Result<()> {
    let (action, overrides) = parse_query_action(command, args.to_vec())?;
    // Explicit `--jobs` on this line wins; otherwise the session default holds.
    let exec = if overrides.jobs != 0 {
        overrides
    } else {
        AnalysisExecutionOptions {
            jobs: session.exec.jobs.max(overrides.jobs),
            analysis_memory_mib: if overrides.analysis_memory_mib
                == AnalysisExecutionOptions::default().analysis_memory_mib
            {
                session.exec.analysis_memory_mib
            } else {
                overrides.analysis_memory_mib
            },
            timings: overrides.timings || session.exec.timings,
        }
    };
    query(
        session.path,
        action,
        json_output,
        false,
        update,
        &InputLimits::default(),
        &exec,
    )
}

/// Test-only witnesses for "the cached read path touches nothing expensive".
///
/// Compiled out of release builds: no production code reads these, and no
/// hidden environment variable gates behaviour.
#[cfg(test)]
mod cache_counters {
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(super) static SNAPSHOT_BUILDS: AtomicUsize = AtomicUsize::new(0);
    pub(super) static IMAGE_PARSES: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn reset() {
        SNAPSHOT_BUILDS.store(0, Ordering::SeqCst);
        IMAGE_PARSES.store(0, Ordering::SeqCst);
    }

    pub(super) fn snapshot_builds() -> usize {
        SNAPSHOT_BUILDS.load(Ordering::SeqCst)
    }

    pub(super) fn image_parses() -> usize {
        IMAGE_PARSES.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    use super::*;

    use crate::analysis_pipeline::AnalyzedFunction;
    use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlowGraph};

    #[path = "../../../tests/common/analysis_fixture.rs"]
    mod fixture;

    /// Build a project from a generated fixture and return (database, layout).
    fn build_project(directory: &Path, functions_per_section: usize) -> (PathBuf, fixture::FixtureLayout) {
        let source = directory.join("fixture.bin");
        let layout =
            fixture::write_analysis_fixture(&source, functions_per_section).expect("write fixture");
        let database = directory.join("project.hxdb");
        create(
            &source,
            &database,
            &Selection::default(),
            &InputLimits::default(),
            &ScopeFlags::default(),
            &AnalysisExecutionOptions::default(),
            true,
        )
        .expect("create project");
        (database, layout)
    }

    /// Render flags with the clap defaults (the derived `Default` has an empty
    /// optimization level, which is not a valid choice).
    fn render_flags() -> RenderFlags {
        RenderFlags {
            opt_level: "standard".to_string(),
            ..RenderFlags::default()
        }
    }

    #[test]
    fn cached_pseudo_c_reads_only_the_owner_rows() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (database, layout) = build_project(directory.path(), 8);
        let helper = format!("{:#x}", layout.helper);
        {
            let mut database = db(Database::open(&database, OpenMode::ReadWrite)).expect("open");
            let config = {
                let read = db(database.snapshot()).expect("snapshot");
                let image = db(read.image()).expect("image");
                render_config_from_reads(&read, &image, &render_flags()).expect("render config")
            };
            run_analysis(
                &mut database,
                &AnalyzeRequest {
                    function: Some(helper.clone()),
                    force: false,
                    render: Some(config),
                    limits: InputLimits::default(),
                    exec: AnalysisExecutionOptions::default(),
                },
            )
            .expect("render one function");
        }

        cache_counters::reset();
        query(
            &database,
            QueryAction::Decompile {
                function: helper,
                render_flags: render_flags(),
            },
            true,
            false,
            false,
            &InputLimits::default(),
            &AnalysisExecutionOptions::default(),
        )
        .expect("cached pseudo-C");
        assert_eq!(
            cache_counters::snapshot_builds(),
            0,
            "a cached render must not rebuild the project snapshot"
        );
        assert_eq!(
            cache_counters::image_parses(),
            0,
            "a cached render must not parse the image"
        );
    }

    #[test]
    fn one_decode_per_window() {
        let directory = tempfile::tempdir().expect("temp dir");
        let source = directory.path().join("fixture.bin");
        let layout = fixture::write_analysis_fixture(&source, 8).expect("write fixture");
        let bytes = std::fs::read(&source).expect("read fixture");
        let selection = ImageSelection {
            container_kind: ContainerKind::Elf,
            container_offset: 0,
            container_length: bytes.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: "{\"image\":\"elf\"}".to_string(),
        };
        let parsed = parse_image(&bytes, &selection).expect("parse fixture");
        let scope = ScopeMap::from_scope(&AnalysisScope::empty());
        let mut session = DecodeSession::new(scope, parsed.binary.as_format().architecture());
        let first = session
            .decode(&parsed.binary, layout.helper, 64, false)
            .expect("first decode");
        let second = session
            .decode(&parsed.binary, layout.helper, 64, false)
            .expect("second decode");
        assert_eq!(session.decodes(), 1, "one window decodes exactly once");
        assert_eq!(session.hits(), 1, "the repeat request is a cache hit");
        assert!(
            std::sync::Arc::ptr_eq(&first, &second),
            "the cache must hand back the same decoded function, not a copy"
        );
        // A different byte bound is a *different* decode. Serving the narrower
        // window from the wider one would be wrong: when a tail instruction is
        // cut by the bound the decoder fails and re-syncs at the next byte, so
        // the narrow decode can produce an instruction the wide one never saw.
        // This fixture has exactly such a boundary (0x40102a), which is why the
        // rule is "decode again", not "truncate the prefix".
        let narrow = session
            .decode(&parsed.binary, layout.helper, 6, false)
            .expect("narrow decode");
        assert_eq!(session.decodes(), 2, "a new bound decodes again");
        assert!(narrow.instructions.len() <= first.instructions.len());
        let mut fresh = DecodeSession::new(
            ScopeMap::from_scope(&AnalysisScope::empty()),
            parsed.binary.as_format().architecture(),
        );
        let direct = fresh
            .decode(&parsed.binary, layout.helper, 6, false)
            .expect("direct narrow decode");
        assert_eq!(
            narrow.decoded_end, direct.decoded_end,
            "the cached decode must equal a direct one for the same window"
        );
        assert_eq!(narrow.instructions.len(), direct.instructions.len());
        assert_eq!(narrow.stop_reason, direct.stop_reason);
    }

    #[test]
    fn decode_cache_is_bounded_by_its_budget() {
        let directory = tempfile::tempdir().expect("temp dir");
        let source = directory.path().join("fixture.bin");
        let layout = fixture::write_analysis_fixture(&source, 8).expect("write fixture");
        let bytes = std::fs::read(&source).expect("read fixture");
        let selection = ImageSelection {
            container_kind: ContainerKind::Elf,
            container_offset: 0,
            container_length: bytes.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: "{\"image\":\"elf\"}".to_string(),
        };
        let parsed = parse_image(&bytes, &selection).expect("parse fixture");
        let arch = parsed.binary.as_format().architecture();

        // A zero budget cannot hold anything: the decode still happens and the
        // result is still usable, it just is not retained.
        let mut starved =
            DecodeSession::with_budget(ScopeMap::from_scope(&AnalysisScope::empty()), arch, 0);
        let decoded = starved
            .decode(&parsed.binary, layout.helper, 64, false)
            .expect("zero-budget decode");
        assert_eq!(starved.decodes(), 1, "a zero budget must not skip the decode");
        assert!(
            starved.table().is_empty(),
            "a zero budget must evict the entry it just cached: {} entries",
            starved.table().len()
        );
        assert!(
            !decoded.instructions.is_empty(),
            "the returned decode must stay usable after eviction"
        );

        // An unbounded budget keeps the decode, so the repeat is a hit.
        let mut unbounded = DecodeSession::with_budget(
            ScopeMap::from_scope(&AnalysisScope::empty()),
            arch,
            usize::MAX,
        );
        unbounded
            .decode(&parsed.binary, layout.helper, 64, false)
            .expect("first unbounded decode");
        unbounded
            .decode(&parsed.binary, layout.helper, 64, false)
            .expect("second unbounded decode");
        assert_eq!(
            unbounded.table().len(),
            1,
            "an unbounded budget keeps the one window it decoded"
        );
        assert_eq!(unbounded.hits(), 1, "the repeat request is a cache hit");
    }

    #[test]
    fn scope_boundary_never_decodes_a_cut_instruction_tail() {
        let directory = tempfile::tempdir().expect("temp dir");
        let source = directory.path().join("fixture.bin");
        let layout = fixture::write_analysis_fixture(&source, 8).expect("write fixture");
        let bytes = std::fs::read(&source).expect("read fixture");
        let selection = ImageSelection {
            container_kind: ContainerKind::Elf,
            container_offset: 0,
            container_length: bytes.len() as u64,
            member_name: None,
            member_index: None,
            slice_label: None,
            selector_json: "{\"image\":\"elf\"}".to_string(),
        };
        let parsed = parse_image(&bytes, &selection).expect("parse fixture");
        let arch = parsed.binary.as_format().architecture();
        let (_, address, _) = layout.text_functions[0];
        // Function bodies are `mov eax, imm32; ret` (6 bytes). Cut the window in
        // the middle of the `mov`: the excluded bytes are the rest of it.
        let scope = ScopeMap::from_scope(&AnalysisScope {
            payload_version: AnalysisScope::CURRENT_PAYLOAD_VERSION,
            excluded_ranges: vec![ScopeRange {
                start: Address(address + 2),
                end: Address(address + 64),
                section_name: None,
            }],
        });
        let mut bounded = DecodeSession::new(scope.clone(), arch);
        let decoded = bounded
            .decode(&parsed.binary, address, 64, false)
            .expect("bounded decode");
        assert_eq!(
            decoded.stop_reason,
            analysis_pipeline::DecodeStopReason::AnalysisScope,
            "a scope-cut window must report the scope stop"
        );
        assert!(
            decoded.instructions.is_empty(),
            "a cut instruction must not be decoded, and its tail must not be \
             re-synchronised into new instructions: {:?}",
            decoded
                .instructions
                .iter()
                .map(|instruction| (instruction.address, instruction.mnemonic.clone()))
                .collect::<Vec<_>>()
        );

        // Control: the same 2-byte window with no scope re-synchronises and does
        // produce an instruction, which is exactly what must not happen across a
        // scope boundary.
        let mut plain = DecodeSession::new(ScopeMap::from_scope(&AnalysisScope::empty()), arch);
        let resynced = plain
            .decode(&parsed.binary, address, 2, false)
            .expect("plain decode");
        assert!(
            !resynced.instructions.is_empty(),
            "the control window must show the resynchronising behaviour"
        );

        // A boundary one byte later keeps the two real instructions and stops
        // before the next function's opcode byte is decoded as a NOP-ish suffix.
        let later = ScopeMap::from_scope(&AnalysisScope {
            payload_version: AnalysisScope::CURRENT_PAYLOAD_VERSION,
            excluded_ranges: vec![ScopeRange {
                start: Address(address + 7),
                end: Address(address + 64),
                section_name: None,
            }],
        });
        let mut session = DecodeSession::new(later, arch);
        let decoded = session
            .decode(&parsed.binary, address, 64, false)
            .expect("boundary decode");
        assert_eq!(
            decoded.instructions.len(),
            2,
            "only the complete instructions inside the boundary are kept"
        );
        assert_eq!(decoded.instructions[1].mnemonic, "ret");
        assert_eq!(
            decoded.stop_reason,
            analysis_pipeline::DecodeStopReason::AnalysisScope
        );
    }

    #[test]
    fn analysis_reuses_callee_decodes() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (database, layout) = build_project(directory.path(), 8);
        let mut database = db(Database::open(&database, OpenMode::ReadWrite)).expect("open");
        let live = layout.text_functions.len() + layout.packed_functions.len();
        let report = run_analysis(
            &mut database,
            &AnalyzeRequest {
                function: None,
                force: true,
                render: None,
                limits: InputLimits::default(),
                exec: AnalysisExecutionOptions {
                    timings: true,
                    ..AnalysisExecutionOptions::default()
                },
            },
        )
        .expect("analysis");
        let timings = report.timings.expect("timings requested");
        assert!(timings.decodes > 0, "the run must decode something");
        assert!(
            timings.decode_hits > 0,
            "callee signature seeding must reuse decodes the caller pass already made"
        );
        assert!(
            timings.decodes <= live * 2,
            "no window may be decoded twice: {} decodes for {} functions",
            timings.decodes,
            live
        );
    }

    #[test]
    fn discovery_reports_truncation() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (database, _layout) = build_project(directory.path(), 8);
        let mut database = db(Database::open(&database, OpenMode::ReadOnly)).expect("open");
        let snapshot = load_snapshot(&mut database).expect("snapshot");
        let parsed = parse_image(
            snapshot.image_bytes(),
            &selection_from_image(&snapshot.image),
        )
        .expect("parse fixture");
        let mut decode = DecodeSession::new(
            snapshot.scope_map.clone(),
            parsed.binary.as_format().architecture(),
        );

        let (capped, truncated) =
            discovery_pass(&parsed.binary, &snapshot, &mut decode, 3).expect("discovery");
        assert!(truncated, "a cap below the function count must be reported");
        assert!(
            capped.len() <= 3,
            "discovery must stop at the cap: {}",
            capped.len()
        );

        let (all, complete) = discovery_pass(
            &parsed.binary,
            &snapshot,
            &mut decode,
            MAX_DISCOVERED_FUNCTIONS,
        )
        .expect("discovery");
        assert!(!complete, "the fixture fits under the real cap");
        assert!(all.len() > capped.len(), "the real cap discovers more");
    }

    #[test]
    fn cfg_payload_collapses_duplicate_normal_edges() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::ENTRY);

        let mut branch = BasicBlock::new(BasicBlockId(0), 0x1000);
        branch.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId(1),
            false_target: BasicBlockId(1),
        };
        cfg.add_block(branch);

        let mut target = BasicBlock::new(BasicBlockId(1), 0x1002);
        target.terminator = BlockTerminator::Return;
        cfg.add_block(target);

        // `je +0`: the branch target is the fallthrough, so `add_edge` records
        // the same transfer twice. An unwind edge to the same block must still
        // be stored, because it is a different kind.
        cfg.add_edge(BasicBlockId(0), BasicBlockId(1));
        cfg.add_edge(BasicBlockId(0), BasicBlockId(1));
        cfg.add_eh_edge(BasicBlockId(0), BasicBlockId(1));

        let payload = cfg_payload(&AnalyzedFunction::test_stub(0x1000, Vec::new(), cfg));

        assert_eq!(
            payload.edges,
            vec![(0, 1, EdgeKind::Normal), (0, 1, EdgeKind::Unwind)],
            "the duplicate normal edge is collapsed and the unwind edge is kept"
        );
        let branch = payload
            .blocks
            .iter()
            .find(|block| block.id == 0)
            .expect("block 0 in the payload");
        assert_eq!(
            branch.terminator,
            BlockTerminator::ConditionalBranch {
                condition: Condition::Equal,
                true_target: BasicBlockId(1),
                false_target: BasicBlockId(1),
            },
            "edge deduplication must not rewrite the terminator"
        );
    }

    #[test]
    fn jobs_are_clamped_to_the_core_count() {
        let cores = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);
        let serial = AnalysisExecutionOptions {
            jobs: 1,
            ..Default::default()
        };
        assert_eq!(serial.requested_jobs(), 1, "1 stays serial");
        let oversized = AnalysisExecutionOptions {
            jobs: u32::MAX,
            ..Default::default()
        };
        assert_eq!(
            oversized.requested_jobs(),
            cores.min(MAX_JOBS),
            "an explicit count above the machine is clamped to the core count"
        );
        assert_eq!(
            AnalysisExecutionOptions::default().requested_jobs(),
            cores,
            "0 means one worker per available core"
        );
    }
}
