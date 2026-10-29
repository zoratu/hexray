//! The shared per-function analysis entry point.
//!
//! `hexray <binary> decompile` and `hexray db query decompile` must produce the
//! same pseudo-C, so neither owns the pipeline: both build an
//! [`AnalysisInputs`], call [`analyze_function`] (or [`analyze_replay`] when the
//! instructions and CFG already exist in a database) and then
//! [`render_function`].
//!
//! The split matters for persistence:
//! - analysis produces the instructions, CFG, signature and diagnostics that a
//!   database stores;
//! - rendering produces text for one canonical [`RenderConfig`], and is the
//!   only step that needs a `DecompilerConfig`.
//!
//! Nothing here prints. The CLI decides what to show, and the database decides
//! what to keep.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use anyhow::{bail, Result};
use hexray_analysis::{
    CfgBuilder, Decompiler, DecompilerConfig, FunctionSignature, OptimizationLevel,
    OptimizationPass, RelocationTable, StringTable, SymbolTable, VariableOverride,
};
use hexray_core::{ControlFlowGraph, Instruction, SymbolKind};
use hexray_formats::{BinaryFormat, BinaryType};
use hexray_types::{ConstantDatabase, TypeDatabase};

use crate::analysis_scope::ScopeMap;
use crate::{
    build_binary_data_context, build_relocation_table, build_string_table, build_symbol_table,
    build_tls_access_targets, build_tls_slot_map, build_tls_symbol_offset_map,
    collect_noreturn_call_sites, collect_throw_thunks, default_calling_convention,
    disassemble_window, get_dwarf_function_names, seed_direct_callee_signature_hints,
    seed_resolved_call_target_names, apply_instruction_relocations, rewrite_tls_memory_operands,
    disassemble_function_for_cfg, Binary, DirectCalleeSignatureSeedContext, DwarfFunctionNames,
    AnalysisProject, TlsAccessTarget,
};

/// Severity of a pipeline diagnostic, mirroring the stored model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

impl PipelineDiagnostic {
    /// Convert to the stored representation.
    pub(crate) fn to_stored(&self) -> hexray_db::Diagnostic {
        hexray_db::Diagnostic {
            code: self.code.to_string(),
            severity: match self.severity {
                DiagnosticSeverity::Info => hexray_db::Severity::Info,
                DiagnosticSeverity::Warning => hexray_db::Severity::Warning,
                DiagnosticSeverity::Error => hexray_db::Severity::Error,
            },
            message: self.message.clone(),
            address: self.address.map(hexray_db::Address),
        }
    }
}

/// One diagnostic emitted while analyzing a function.
#[derive(Debug, Clone)]
pub(crate) struct PipelineDiagnostic {
    pub code: &'static str,
    pub severity: DiagnosticSeverity,
    pub message: String,
    pub address: Option<u64>,
}

impl PipelineDiagnostic {
    fn new(code: &'static str, severity: DiagnosticSeverity, message: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            message: message.into(),
            address: None,
        }
    }

    fn info(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(code, DiagnosticSeverity::Info, message)
    }

    fn at(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// Comments to weave into the emitted pseudo-C.
#[derive(Debug, Clone, Default)]
pub(crate) struct CommentOverlay {
    entries: Vec<(u64, String)>,
}

impl CommentOverlay {
    /// Build from an `AnalysisProject` (the CLI path).
    pub(crate) fn from_project(project: Option<&AnalysisProject>) -> Self {
        let Some(project) = project else {
            return Self::default();
        };
        let mut entries: Vec<(u64, String)> = project
            .annotated_addresses()
            .filter_map(|address| {
                project
                    .get_comment(address)
                    .map(|comment| (address, comment.to_string()))
            })
            .collect();
        entries.sort_by_key(|(address, _)| *address);
        Self { entries }
    }

    /// Build from explicit pairs (the database path).
    pub(crate) fn from_pairs(mut entries: Vec<(u64, String)>) -> Self {
        entries.sort_by_key(|(address, _)| *address);
        Self { entries }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// What the caller wants analyzed.
#[derive(Debug, Clone)]
pub(crate) struct FunctionRequest {
    /// Symbol name or `0x`-prefixed address text.
    pub target: String,
    /// User name for the function, when the caller already resolved one.
    #[allow(dead_code)]
    pub name_override: Option<String>,
}

impl FunctionRequest {
    pub(crate) fn new(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            name_override: None,
        }
    }
}

/// The read-only tables every function of one command shares.
///
/// Building them is the expensive part of analysis: the relocation table, the
/// symbol/string tables, the TLS maps, the throw-thunk scan and the binary-data
/// sections only depend on the image and the user's names, never on which
/// function is being decoded. One command builds them once.
pub(crate) struct SharedTables<'a> {
    pub project: Option<&'a AnalysisProject>,
    pub type_db: Option<&'a Arc<TypeDatabase>>,
    /// DWARF resolved by the caller: a file on disk for the CLI, an embedded
    /// resource for a reopened database. Taken by value because `DebugInfo` is
    /// large and not `Clone`; the context stores it behind an `Arc`.
    pub debug_info: Option<hexray_formats::dwarf::DebugInfo>,
    /// User names by address, applied on top of the loader symbol table.
    pub names: &'a [(u64, String)],
    /// Automatic-analysis scope, so the cold-thunk scan is gated exactly like
    /// every other decode. `None` means "no exclusions".
    pub scope: Option<&'a ScopeMap>,
}

/// Immutable per-command analysis context.
///
/// Every field is either fully immutable or an `Arc` of something immutable, so
/// a worker can borrow it from several threads at once. Per-function state
/// (DWARF names, user signature overrides, variable overrides, symbol kind,
/// diagnostics) stays in [`AnalysisInputs`].
pub(crate) struct SharedAnalysisContext {
    pub(crate) relocation_table: Arc<RelocationTable>,
    /// Loader symbols merged with the user's names.
    pub(crate) symbol_table: Arc<SymbolTable>,
    pub(crate) string_table: Arc<StringTable>,
    pub(crate) tls_access_targets: Arc<Vec<TlsAccessTarget>>,
    pub(crate) tls_symbol_offsets: Arc<HashMap<i64, String>>,
    pub(crate) tls_slot_map: Arc<HashMap<u64, u64>>,
    pub(crate) throw_thunks: Arc<HashMap<u64, String>>,
    /// Immutable jump-table/constant sections plus the resolved call-target
    /// names. The per-function signature hints are added by cloning this value,
    /// which is shallow: sections are `Arc<[u8]>` and the hint maps are small.
    pub(crate) binary_data: Arc<hexray_analysis::BinaryDataContext>,
    pub(crate) calling_convention: hexray_analysis::CallingConvention,
    pub(crate) pointer_size: usize,
    pub(crate) constant_database: Arc<ConstantDatabase>,
    pub(crate) type_database: Option<Arc<TypeDatabase>>,
    pub(crate) debug_info: Option<Arc<hexray_formats::dwarf::DebugInfo>>,
    pub(crate) project: Option<Arc<AnalysisProject>>,
}

impl SharedAnalysisContext {
    /// Build every image-wide table exactly once.
    pub(crate) fn build(binary: &Binary<'_>, tables: SharedTables<'_>) -> Arc<Self> {
        let fmt = binary.as_format();
        let arch = fmt.architecture();
        let relocation_table = Arc::new(build_relocation_table(binary));

        // User names win over loader symbols, then the project overlay (the
        // bare-file CLI path) wins over both.
        let mut symbol_table = build_symbol_table(binary);
        for (address, name) in tables.names {
            symbol_table.insert(*address, name.clone());
        }
        if let Some(project) = tables.project {
            for address in project.overridden_functions() {
                if let Some(name) = project.get_function_name(address) {
                    symbol_table.insert(address, name.to_string());
                }
            }
        }
        let symbol_table = Arc::new(symbol_table);

        let mut binary_data = build_binary_data_context(fmt);
        seed_resolved_call_target_names(&mut binary_data, &symbol_table, &relocation_table);

        let calling_convention = default_calling_convention(
            match binary {
                Binary::Elf(_) => BinaryType::Elf,
                Binary::MachO(_) => BinaryType::MachO,
                Binary::Pe(_) => BinaryType::Pe,
            },
            arch,
        );
        let pointer_size = match fmt.bitness() {
            hexray_core::Bitness::Bits32 => 4usize,
            hexray_core::Bitness::Bits64 => 8usize,
        };

        Arc::new(Self {
            throw_thunks: Arc::new(collect_throw_thunks(
                binary,
                &symbol_table,
                &relocation_table,
                tables.scope,
            )),
            string_table: Arc::new(build_string_table(fmt)),
            tls_access_targets: Arc::new(build_tls_access_targets(binary)),
            tls_symbol_offsets: Arc::new(build_tls_symbol_offset_map(binary)),
            tls_slot_map: Arc::new(build_tls_slot_map(binary)),
            binary_data: Arc::new(binary_data),
            constant_database: Arc::new(ConstantDatabase::with_builtins()),
            type_database: tables.type_db.cloned(),
            debug_info: tables.debug_info.map(Arc::new),
            project: tables.project.map(|project| Arc::new(project.clone())),
            relocation_table,
            symbol_table,
            calling_convention,
            pointer_size,
        })
    }
}

/// Everything analysis reads besides the binary itself.
///
/// The image-wide tables live in the shared context; only values that genuinely
/// differ per function are carried here.
pub(crate) struct AnalysisInputs<'a> {
    pub shared: &'a SharedAnalysisContext,
    pub config: Option<&'a DecompilerConfig>,
    pub diagnostics: bool,
    /// Explicit user signature, taking priority over recovery.
    pub signature_override: Option<&'a FunctionSignature>,
    pub variable_overrides: &'a [VariableOverride],
    /// Raw decodes already produced by this command's serial decode pass.
    /// Callee signature seeding reuses them instead of decoding again; a miss
    /// still decodes on demand so output never depends on cache contents.
    pub decoded: Option<&'a HashMap<DecodeKey, Arc<DecodedFunction>>>,
    /// Active analysis scope. `None` means "no exclusions" (the bare-file path).
    pub scope_map: Option<&'a ScopeMap>,
}

/// Options for turning an analyzed function into pseudo-C.
#[derive(Debug, Clone, Default)]
pub(crate) struct RenderOptions {
    pub show_addresses: bool,
    pub comments: Option<CommentOverlay>,
}

/// The result of analysis: everything a database needs to store the function.
pub(crate) struct AnalyzedFunction {
    pub start: u64,
    pub name: String,
    pub instructions: Vec<Instruction>,
    pub cfg: ControlFlowGraph,
    pub diagnostics: Vec<PipelineDiagnostic>,
    /// Fully configured decompiler, ready to render.
    decompiler: Decompiler,
}

#[cfg(test)]
impl AnalyzedFunction {
    /// Test-only constructor: `decompiler` is private, so tests in other
    /// modules cannot build the struct with a literal.
    pub(crate) fn test_stub(
        start: u64,
        instructions: Vec<Instruction>,
        cfg: ControlFlowGraph,
    ) -> Self {
        Self {
            start,
            name: "test".to_string(),
            instructions,
            cfg,
            diagnostics: Vec::new(),
            decompiler: Decompiler::new(),
        }
    }
}

/// The result of rendering.
pub(crate) struct RenderedFunction {
    pub text: String,
}

/// Persisted analysis replayed instead of re-disassembling.
pub(crate) struct ReplayInput {
    pub start: u64,
    pub name: String,
    pub symbol_kind: Option<SymbolKind>,
    pub instructions: Vec<Instruction>,
    pub cfg: ControlFlowGraph,
    /// Address bound the original analysis used, for diagnostics only.
    pub max_bytes: usize,
    pub stop_after_first_return: bool,
}

/// Identity of one raw decode inside a single command.
///
/// The architecture, effective content revision and scope fingerprint belong to
/// the owning [`DecodeSession`] — a session never outlives one command, so
/// repeating them per key would only risk a stale hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DecodeKey {
    pub start: u64,
    pub max_bytes: usize,
    pub stop_after_first_return: bool,
    /// Address the scope cut the window at, when one did.
    pub barrier_end: Option<u64>,
}

/// Why the decoder stopped scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeStopReason {
    /// The byte window ran out.
    RangeEnd,
    /// A return (or halt) ended the scan.
    Return,
    /// A call to a known noreturn function ended the scan.
    Noreturn,
    /// A heuristic tail jump ended the scan.
    TailJump,
    /// The next instruction would cross an excluded analysis-scope boundary.
    AnalysisScope,
    /// The decoder could not decode the next byte and skipped it.
    InvalidDecode,
    /// The per-function instruction limit was hit.
    InstructionLimit,
}

impl DecodeStopReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RangeEnd => "range_end",
            Self::Return => "return",
            Self::Noreturn => "noreturn",
            Self::TailJump => "tail_jump",
            Self::AnalysisScope => "analysis_scope",
            Self::InvalidDecode => "invalid_decode",
            Self::InstructionLimit => "instruction_limit",
        }
    }
}

/// One raw decode: instructions before relocations and TLS rewriting.
pub(crate) struct DecodedFunction {
    pub instructions: Arc<[Instruction]>,
    /// Address just past the last decoded instruction (`start` when empty).
    pub decoded_end: u64,
    pub stop_reason: DecodeStopReason,
}

/// Per-command decode cache.
///
/// Discovery decodes every candidate to find call targets and then throws the
/// result away; the CFG pass decodes the same functions again; callee signature
/// seeding decodes the same callees once per caller. This session makes each
/// decode happen once, bounded by the analysis scope.
///
/// A window is identified by its start, its stop rule and its scope barrier
/// *plus its byte bound*. Reusing a decode across different bounds would be
/// wrong, not merely imprecise: when a tail instruction is cut by the bound the
/// decoder fails and advances by the minimum instruction size, so the shorter
/// window can re-sync and produce an instruction the longer window never saw.
/// Different bounds therefore decode again (discovery's `max(64)` probe does
/// not cover a narrower CFG window), and the cache only removes *identical*
/// repeats.
///
/// The cache stores *raw* instructions. Relocations and TLS rewriting are still
/// applied per consumer, and no caller's signature hints or CFG are shared, so
/// the per-caller accumulation order of the baseline is preserved.
///
/// It is also bounded by bytes: past `budget_bytes` the oldest decodes are
/// evicted (FIFO), so a long run does not pin every function it ever decoded.
pub(crate) struct DecodeSession {
    scope: ScopeMap,
    architecture: hexray_core::Architecture,
    cache: HashMap<DecodeKey, Arc<DecodedFunction>>,
    decodes: usize,
    hits: usize,
    /// Insertion order for FIFO eviction once `cached_bytes` exceeds the budget.
    order: VecDeque<DecodeKey>,
    /// Approximate bytes held by `cache`; see `estimate_decoded_bytes`.
    cached_bytes: usize,
    /// Upper bound on `cached_bytes`; exceeding it evicts the oldest decodes.
    budget_bytes: usize,
}

/// Key for one decode window under `scope`.
///
/// Shared with the callee-signature seed path so a lookup can never disagree
/// with the session about what "the same decode" means.
pub(crate) fn decode_key_for(
    scope: &ScopeMap,
    start: u64,
    max_bytes: usize,
    stop_after_first_return: bool,
) -> DecodeKey {
    let (allowed, stopped) = if scope.is_empty() {
        (max_bytes, false)
    } else {
        scope.clamp_window(start, max_bytes)
    };
    DecodeKey {
        start,
        max_bytes,
        stop_after_first_return,
        barrier_end: stopped.then(|| start.saturating_add(allowed as u64)),
    }
}

impl DecodeSession {
    /// Unbounded session, for tests that do not exercise eviction.
    #[cfg(test)]
    pub(crate) fn new(scope: ScopeMap, architecture: hexray_core::Architecture) -> Self {
        Self::with_budget(scope, architecture, usize::MAX)
    }

    /// A session that keeps at most `budget_bytes` of decoded functions, evicting
    /// the oldest decodes past that. `usize::MAX` keeps everything.
    pub(crate) fn with_budget(
        scope: ScopeMap,
        architecture: hexray_core::Architecture,
        budget_bytes: usize,
    ) -> Self {
        Self {
            scope,
            architecture,
            cache: HashMap::new(),
            decodes: 0,
            hits: 0,
            order: VecDeque::new(),
            cached_bytes: 0,
            budget_bytes,
        }
    }

    /// Number of real decodes performed (cache misses).
    pub(crate) fn decodes(&self) -> usize {
        self.decodes
    }

    /// Number of served cache hits.
    pub(crate) fn hits(&self) -> usize {
        self.hits
    }

    /// Key for the window `[start, start + max_bytes)` under this session's
    /// scope. The scope cut is part of the key: the same request with a
    /// different boundary is a different decode.
    pub(crate) fn key(
        &self,
        start: u64,
        max_bytes: usize,
        stop_after_first_return: bool,
    ) -> DecodeKey {
        decode_key_for(&self.scope, start, max_bytes, stop_after_first_return)
    }

    /// Decode `[start, start + max_bytes)` once, honouring the scope.
    pub(crate) fn decode(
        &mut self,
        binary: &Binary<'_>,
        start: u64,
        max_bytes: usize,
        stop_after_first_return: bool,
    ) -> Result<Arc<DecodedFunction>> {
        let key = self.key(start, max_bytes, stop_after_first_return);
        if let Some(cached) = self.cache.get(&key) {
            self.hits += 1;
            return Ok(cached.clone());
        }
        let fmt = binary.as_format();
        if fmt.architecture() != self.architecture {
            bail!(
                "decode session was opened for {:?} but the image is {:?}",
                self.architecture,
                fmt.architecture()
            );
        }
        let (allowed, stopped_at_scope) = if self.scope.is_empty() {
            (max_bytes, false)
        } else {
            self.scope.clamp_window(start, max_bytes)
        };
        let decoded = if allowed == 0 {
            Arc::new(DecodedFunction {
                instructions: Arc::from(Vec::<Instruction>::new()),
                decoded_end: start,
                stop_reason: DecodeStopReason::AnalysisScope,
            })
        } else {
            let (instructions, mut reason) =
                disassemble_window(fmt, start, allowed, stop_after_first_return, stopped_at_scope)?;
            if stopped_at_scope && reason == DecodeStopReason::RangeEnd {
                reason = DecodeStopReason::AnalysisScope;
            }
            let decoded_end = instructions
                .last()
                .map(|instruction| {
                    instruction
                        .address
                        .saturating_add(instruction.size as u64)
                })
                .unwrap_or(start);
            Arc::new(DecodedFunction {
                instructions: Arc::from(instructions),
                decoded_end,
                stop_reason: reason,
            })
        };
        self.decodes += 1;
        self.store(key, decoded.clone());
        Ok(decoded)
    }

    /// Decode a callee for signature seeding through the same cache and scope.
    pub(crate) fn decode_callee(
        &mut self,
        binary: &Binary<'_>,
        start: u64,
        max_bytes: usize,
        stop_after_first_return: bool,
    ) -> Result<Arc<DecodedFunction>> {
        self.decode(binary, start, max_bytes, stop_after_first_return)
    }

    /// The frozen table, for workers that run the callee-signature seed pass.
    ///
    /// Reading it concurrently is safe because the decode pass is serial and
    /// finishes before any worker starts.
    pub(crate) fn table(&self) -> &HashMap<DecodeKey, Arc<DecodedFunction>> {
        &self.cache
    }

    /// Cache one decode, evicting the oldest entries while over budget.
    ///
    /// Eviction is FIFO, not LRU: the access pattern is one serial pre-decode
    /// pass per batch, so insertion order is close enough and a touch on every
    /// hit would cost more than it saves.
    fn store(&mut self, key: DecodeKey, decoded: Arc<DecodedFunction>) {
        let bytes = estimate_decoded_bytes(&decoded);
        self.cached_bytes = self.cached_bytes.saturating_add(bytes);
        self.order.push_back(key);
        self.cache.insert(key, decoded);
        while self.cached_bytes > self.budget_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.cache.remove(&oldest) {
                self.cached_bytes = self
                    .cached_bytes
                    .saturating_sub(estimate_decoded_bytes(&entry));
            }
        }
    }
}

/// Lower-bound size of one cached decode: the struct plus the instruction
/// array. Strings and operand vectors are not counted, so the real footprint
/// can be larger; the budget is an order-of-magnitude guard, not accounting.
fn estimate_decoded_bytes(decoded: &DecodedFunction) -> usize {
    std::mem::size_of::<DecodedFunction>()
        + decoded.instructions.len() * std::mem::size_of::<Instruction>()
}

/// Analyze a function by resolving `request.target` in `binary`.
pub(crate) fn analyze_function(
    binary: &Binary<'_>,
    request: &FunctionRequest,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    let relocation_table = build_relocation_table(binary);
    let info = crate::resolve_decompile_target_info(
        fmt,
        inputs.shared.project.as_deref(),
        &request.target,
        &relocation_table,
    )
    .map_err(|_| {
        anyhow::anyhow!(
            "Symbol '{}' not found. It may be an external/undefined symbol (e.g., from a shared library).",
            request.target
        )
    })?;

    if info.start_addr == 0 {
        bail!("Invalid address 0x0 - symbol may be undefined or external");
    }
    if !is_executable_address(fmt, info.start_addr) {
        bail!(
            "Address {:#x} is not in an executable section - cannot decompile data",
            info.start_addr
        );
    }

    let name = request
        .name_override
        .clone()
        .unwrap_or_else(|| info.name.clone());
    let relocation_table = inputs.shared.relocation_table.clone();
    let mut instructions = disassemble_function_for_cfg(
        fmt,
        info.start_addr,
        info.max_bytes,
        info.stop_after_first_return,
    )?;
    apply_instruction_relocations(&mut instructions, &relocation_table);

    build_from_instructions(
        binary,
        info.start_addr,
        name,
        info.symbol_kind,
        info.max_bytes,
        info.stop_after_first_return,
        instructions,
        &relocation_table,
        inputs,
    )
}

/// Analyze a function whose raw decode is already in hand.
///
/// This is the persisted-project path: the decode happened once, in the
/// serial decode pass, and every consumer (discovery, CFG analysis, callee
/// signature seeding) reuses it instead of decoding the same bytes again.
#[allow(clippy::too_many_arguments)]
pub(crate) fn analyze_decoded(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    decoded: &DecodedFunction,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    if start == 0 {
        bail!("Invalid address 0x0 - symbol may be undefined or external");
    }
    if !is_executable_address(fmt, start) {
        bail!(
            "Address {:#x} is not in an executable section - cannot decompile data",
            start
        );
    }
    let relocation_table = inputs.shared.relocation_table.clone();
    let mut instructions = decoded.instructions.to_vec();
    apply_instruction_relocations(&mut instructions, &relocation_table);
    build_from_instructions(
        binary,
        start,
        name,
        symbol_kind,
        max_bytes,
        stop_after_first_return,
        instructions,
        &relocation_table,
        inputs,
    )
}

/// Analyze a function whose instructions and CFG were persisted earlier.
///
/// Only the context tables are rebuilt from the binary; no instruction is
/// re-decoded, so a patch that invalidated the CFG cannot silently produce a
/// half-new result.
pub(crate) fn analyze_replay(
    binary: &Binary<'_>,
    replay: ReplayInput,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let relocation_table = inputs.shared.relocation_table.clone();
    build_from_instructions_with_cfg(
        binary,
        replay.start,
        replay.name,
        replay.symbol_kind,
        replay.max_bytes,
        replay.stop_after_first_return,
        replay.instructions,
        Some(replay.cfg),
        &relocation_table,
        inputs,
    )
}

/// Render an analyzed function to pseudo-C.
pub(crate) fn render_function(
    analyzed: AnalyzedFunction,
    options: &RenderOptions,
) -> Result<RenderedFunction> {
    let analyzed = analyzed;
    let decompiler = analyzed.decompiler.with_addresses(options.show_addresses);
    let pseudocode = decompiler.decompile(&analyzed.cfg, &analyzed.name);
    let text = apply_comment_overlay(
        pseudocode,
        options.comments.as_ref(),
        options.show_addresses,
    );
    Ok(RenderedFunction {
        text: ensure_nonempty_pseudocode(text),
    })
}

fn is_executable_address(fmt: &dyn BinaryFormat, address: u64) -> bool {
    fmt.sections().any(|section| {
        let start = section.virtual_address();
        let end = start.saturating_add(section.size());
        address >= start && address < end && section.is_executable()
    })
}

#[allow(clippy::too_many_arguments)]
fn build_from_instructions(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    instructions: Vec<Instruction>,
    relocation_table: &hexray_analysis::RelocationTable,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    build_from_instructions_with_cfg(
        binary,
        start,
        name,
        symbol_kind,
        max_bytes,
        stop_after_first_return,
        instructions,
        None,
        relocation_table,
        inputs,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_from_instructions_with_cfg(
    binary: &Binary<'_>,
    start: u64,
    name: String,
    symbol_kind: Option<SymbolKind>,
    max_bytes: usize,
    stop_after_first_return: bool,
    instructions: Vec<Instruction>,
    replay_cfg: Option<ControlFlowGraph>,
    relocation_table: &hexray_analysis::RelocationTable,
    inputs: &AnalysisInputs<'_>,
) -> Result<AnalyzedFunction> {
    let fmt = binary.as_format();
    let mut diagnostics = Vec::new();
    let shared = inputs.shared;

    let instructions = match replay_cfg {
        Some(_) => instructions,
        None => {
            let mut instructions = instructions;
            rewrite_tls_memory_operands(
                &mut instructions,
                &shared.tls_access_targets,
                &shared.tls_slot_map,
            );
            instructions
        }
    };

    let dwarf_names = match shared.debug_info.as_deref() {
        Some(debug_info) => get_dwarf_function_names(debug_info, start, binary),
        None => {
            diagnostics.push(PipelineDiagnostic::info(
                "no-debug-info",
                "no DWARF information available for this function",
            ));
            DwarfFunctionNames::default()
        }
    };

    // The shared binary-data context holds the immutable sections and resolved
    // call-target names; the per-function copy only adds this caller's own
    // recovered signature hints, so it stays cheap (sections are `Arc<[u8]>`).
    let mut binary_data_ctx = (*shared.binary_data).clone();
    let seed_ctx = DirectCalleeSignatureSeedContext {
        relocation_table: &shared.relocation_table,
        symbol_table: &shared.symbol_table,
        calling_convention: shared.calling_convention,
        tls_access_targets: &shared.tls_access_targets,
        tls_slot_map: &shared.tls_slot_map,
        decoded: inputs.decoded,
        scope: inputs.scope_map,
    };
    let cfg = match replay_cfg {
        Some(cfg) => cfg,
        None => {
            seed_direct_callee_signature_hints(
                binary,
                &instructions,
                &mut binary_data_ctx,
                &seed_ctx,
            );
            let noreturn_call_sites =
                collect_noreturn_call_sites(&instructions, fmt, relocation_table);
            CfgBuilder::build_with_binary_context_and_noreturn_calls(
                &instructions,
                start,
                &binary_data_ctx,
                &noreturn_call_sites,
            )
        }
    };

    let mut decompiler = Decompiler::new()
        .with_addresses(true)
        .with_string_table_arc(shared.string_table.clone())
        .with_symbol_table_arc(shared.symbol_table.clone())
        .with_relocation_table_arc(shared.relocation_table.clone())
        .with_tls_symbol_offsets_arc(shared.tls_symbol_offsets.clone())
        .with_throw_thunks_arc(shared.throw_thunks.clone())
        .with_current_function_kind(symbol_kind)
        .with_binary_data_arc(Arc::new(binary_data_ctx))
        .with_dwarf_names(dwarf_names.stack_names)
        .with_dwarf_param_names(dwarf_names.parameter_names)
        .with_dwarf_scope_ranges(dwarf_names.local_scope_ranges)
        .with_constant_database(shared.constant_database.clone())
        .with_struct_inference(true)
        .with_calling_convention(shared.calling_convention)
        .with_pointer_size(shared.pointer_size);

    decompiler = decompiler.analyze_cpp_special(&cfg, &instructions, Some(&name));
    if let Some(info) = binary.exception_info_for_function(start, start, relocation_table) {
        decompiler = decompiler.with_exception_info(info);
    }
    if let Some(db) = &shared.type_database {
        decompiler = decompiler.with_type_database(db.clone());
    }
    if let Some(config) = inputs.config {
        decompiler = decompiler.with_config(config.clone());
    }
    if let Some(signature) = inputs.signature_override {
        decompiler = decompiler.with_signature_override(signature.clone());
    }
    if !inputs.variable_overrides.is_empty() {
        decompiler = decompiler.with_variable_overrides(inputs.variable_overrides.to_vec());
    }

    if inputs.diagnostics {
        let signature = decompiler.recover_signature(&cfg);
        crate::print_signature_diagnostics(&name, &signature);
    }
    if instructions.is_empty() {
        diagnostics.push(
            PipelineDiagnostic::new(
                "no-instructions",
                DiagnosticSeverity::Error,
                "no instruction could be decoded at this address",
            )
            .at(start),
        );
    } else if cfg.block_ids().next().is_none() {
        diagnostics.push(
            PipelineDiagnostic::new(
                "empty-cfg",
                DiagnosticSeverity::Warning,
                "decoded instructions produced no basic blocks",
            )
            .at(start),
        );
    }

    let _ = (max_bytes, stop_after_first_return);
    Ok(AnalyzedFunction {
        start,
        name,
        instructions,
        cfg,
        diagnostics,
        decompiler,
    })
}

/// Weave project/bookmark comments into the pseudo-C after each basic block
/// whose address range contains them.
pub(crate) fn apply_comment_overlay(
    pseudocode: String,
    overlay: Option<&CommentOverlay>,
    show_addresses: bool,
) -> String {
    if !show_addresses {
        return pseudocode;
    }
    let Some(overlay) = overlay else {
        return pseudocode;
    };
    if overlay.is_empty() {
        return pseudocode;
    }

    let comments = &overlay.entries;
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

pub(crate) fn ensure_nonempty_pseudocode(mut pseudocode: String) -> String {
    if pseudocode.trim().is_empty() {
        pseudocode.push_str("/* decompilation body not recoverable */");
    }
    pseudocode
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

/// Build a `DecompilerConfig` from CLI options.
pub(crate) fn build_decompiler_config(
    opt_level: &str,
    enable_passes: &[String],
    disable_passes: &[String],
) -> Result<DecompilerConfig> {
    let level = OptimizationLevel::parse(opt_level).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown optimization level '{}'. Use: none, basic, standard, aggressive",
            opt_level
        )
    })?;

    let mut config = DecompilerConfig::new(level);
    for name in enable_passes {
        if let Some(pass) = parse_optimization_pass(name) {
            config = config.enable_pass(pass);
        } else {
            bail!("Unknown optimization pass '{}'", name);
        }
    }
    for name in disable_passes {
        if let Some(pass) = parse_optimization_pass(name) {
            config = config.disable_pass(pass);
        } else {
            bail!("Unknown optimization pass '{}'", name);
        }
    }
    Ok(config)
}

fn parse_optimization_pass(name: &str) -> Option<OptimizationPass> {
    OptimizationPass::all()
        .iter()
        .copied()
        .find(|pass| pass.name().eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_is_only_applied_with_addresses() {
        let overlay = CommentOverlay::from_pairs(vec![(0x1000, "hello".to_string())]);
        let text = "// bb [0x1000..0x1010]\n  return 0;\n".to_string();
        assert_eq!(
            apply_comment_overlay(text.clone(), Some(&overlay), true),
            "// bb [0x1000..0x1010]\n// hello\n  return 0;\n"
        );
        assert_eq!(
            apply_comment_overlay(text.clone(), Some(&overlay), false),
            text
        );
        assert_eq!(apply_comment_overlay(text.clone(), None, true), text);
    }

    #[test]
    fn empty_pseudocode_is_replaced() {
        assert_eq!(
            ensure_nonempty_pseudocode("   \n".to_string()),
            "   \n/* decompilation body not recoverable */"
        );
        assert_eq!(ensure_nonempty_pseudocode("x".into()), "x");
    }

    #[test]
    fn unknown_optimization_level_is_an_error() {
        assert!(build_decompiler_config("ludicrous", &[], &[]).is_err());
        assert!(build_decompiler_config("standard", &["nope".into()], &[]).is_err());
        assert!(build_decompiler_config("standard", &[], &[]).is_ok());
    }
}
