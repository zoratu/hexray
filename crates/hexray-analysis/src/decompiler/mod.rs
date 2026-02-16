//! Pseudo-code generator / decompiler.
//!
//! This module transforms disassembled code (CFG) into high-level pseudo-code.
//!
//! The decompilation pipeline:
//! 1. **Control Flow Structuring** - Identify if/else, loops (while, do-while, for)
//! 2. **Expression Recovery** - Convert instructions to high-level expressions
//! 3. **Pseudo-code Emission** - Generate readable pseudo-code output

pub mod abi;
mod arch_patterns;
pub mod array_detection;
pub mod benchmark;
pub mod comparison;
pub mod config;
mod constant_propagation;
mod dead_store;
mod emitter;
mod expression;
pub mod float_patterns;
mod for_loop_detection;
pub mod interprocedural;
mod irreducible_cfg;
mod linked_list;
mod loop_canonicalization;
mod loop_invariant;
mod loop_pattern_detection;
mod memset_idiom;
mod naming;
pub mod quality_metrics;
pub mod riscv_vector;
mod short_circuit;
mod signature;
mod string_patterns;
mod struct_inference;
mod structurer;
mod switch_recovery;
pub mod type_propagation;
mod variable_naming;

pub use config::{DecompilerConfig, OptimizationLevel, OptimizationPass};
pub use emitter::PseudoCodeEmitter;
pub use expression::{BinOpKind, Expr, ExprKind, UnaryOpKind, Variable};
pub use interprocedural::{
    CallSiteInfo, FunctionSummary, InterproceduralAnalysis, SummaryDatabase, SummaryType,
};
pub use irreducible_cfg::{IrreducibleCfgAnalysis, IrreducibleRegion};
pub use naming::{NamingContext, TypeHint};
pub use quality_metrics::{compute_metrics, QualityMetrics};
pub use signature::{
    CallingConvention, FunctionSignature, ParamType, Parameter, ParameterLocation,
    SignatureRecovery,
};
pub use struct_inference::{InferredField, InferredStruct, InferredType, StructInference};
pub use structurer::{CatchHandler, LoopKind, StructuredCfg, StructuredNode};
pub use switch_recovery::{JumpTableInfo, SwitchInfo, SwitchKind, SwitchRecovery};
pub use type_propagation::{ExprType, ExpressionTypePropagation, KnownSignature};

use hexray_core::ControlFlowGraph;
use hexray_types::TypeDatabase;
use std::collections::HashMap;
use std::sync::Arc;

use crate::cpp_special::{CppSpecialDetector, SpecialMemberAnalysis};
use crate::rtti::RttiDatabase;

/// Exception handling information for a function.
/// Re-exported from hexray-formats for convenience.
#[derive(Debug, Clone, Default)]
pub struct ExceptionInfo {
    /// Try blocks with their catch handlers.
    pub try_blocks: Vec<TryBlockInfo>,
    /// Cleanup handlers (finally/destructors).
    pub cleanup_handlers: Vec<CleanupInfo>,
}

/// A try block with associated catch handlers.
#[derive(Debug, Clone)]
pub struct TryBlockInfo {
    /// Start address of the try block.
    pub start: u64,
    /// End address of the try block.
    pub end: u64,
    /// Catch handlers for this try block.
    pub handlers: Vec<CatchInfo>,
}

/// A catch handler.
#[derive(Debug, Clone)]
pub struct CatchInfo {
    /// Landing pad address.
    pub landing_pad: u64,
    /// Type being caught (class name if known).
    pub catch_type: Option<String>,
    /// Whether this is a catch-all (catch(...)).
    pub is_catch_all: bool,
}

/// A cleanup handler.
#[derive(Debug, Clone)]
pub struct CleanupInfo {
    /// Protected region start.
    pub start: u64,
    /// Protected region end.
    pub end: u64,
    /// Landing pad for cleanup.
    pub landing_pad: u64,
}

/// Binary data context for jump table reconstruction.
///
/// This provides access to read-only data sections needed for switch
/// statement recovery (reading jump table entries from .rodata, __const, etc.)
#[derive(Debug, Clone, Default)]
pub struct BinaryDataContext {
    /// Pairs of (base_address, data) for each data section.
    sections: Vec<(u64, Vec<u8>)>,
}

impl BinaryDataContext {
    /// Creates a new empty binary data context.
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
        }
    }

    /// Adds a data section.
    pub fn add_section(&mut self, base: u64, data: Vec<u8>) {
        self.sections.push((base, data));
    }

    /// Returns the section containing the given address.
    pub fn section_containing(&self, addr: u64) -> Option<(&[u8], u64)> {
        for (base, data) in &self.sections {
            if addr >= *base && addr < *base + data.len() as u64 {
                return Some((data, *base));
            }
        }
        None
    }

    /// Returns an iterator over all sections.
    pub fn sections(&self) -> impl Iterator<Item = &(u64, Vec<u8>)> {
        self.sections.iter()
    }

    /// Returns true if the context contains no sections.
    pub fn is_empty(&self) -> bool {
        self.sections.is_empty()
    }
}

/// String table for resolving addresses to string literals.
#[derive(Debug, Clone, Default)]
pub struct StringTable {
    /// Maps addresses to string values.
    strings: HashMap<u64, String>,
}

impl StringTable {
    /// Creates a new empty string table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a string at a given address.
    pub fn insert(&mut self, address: u64, value: String) {
        self.strings.insert(address, value);
    }

    /// Looks up a string at a given address.
    pub fn get(&self, address: u64) -> Option<&str> {
        self.strings.get(&address).map(|s| s.as_str())
    }

    /// Returns an iterator over all (address, string) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &String)> {
        self.strings.iter()
    }

    /// Merges another string table into this one.
    pub fn merge(&mut self, other: &StringTable) {
        for (addr, s) in other.strings.iter() {
            self.strings.insert(*addr, s.clone());
        }
    }

    /// Extracts strings from binary data.
    ///
    /// Scans sections for null-terminated strings at addresses.
    pub fn from_binary_data(data: &[u8], base_address: u64) -> Self {
        let mut table = Self::new();
        let mut i = 0;

        while i < data.len() {
            // Check for empty string: null byte followed by printable ASCII
            // This captures "" which is used in setlocale(LC_ALL, "")
            if data[i] == 0 && i + 1 < data.len() && is_printable_ascii(data[i + 1]) {
                table.insert(base_address + i as u64, String::new());
                i += 1;
                continue;
            }

            // Look for potential string starts (printable ASCII)
            if is_printable_ascii(data[i]) {
                let start = i;
                let mut end = i;

                // Scan forward to find null terminator or non-printable
                while end < data.len() && data[end] != 0 {
                    if !is_printable_ascii(data[end]) {
                        break;
                    }
                    end += 1;
                }

                // Check if we found a null-terminated string of reasonable length
                // Allow single-character strings (min 1 char) for locale strings like "C"
                if end < data.len() && data[end] == 0 && end - start >= 1 {
                    if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        table.insert(base_address + start as u64, s.to_string());
                    }
                }

                i = end + 1;
            } else {
                i += 1;
            }
        }

        table
    }
}

/// Checks if a byte is printable ASCII.
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Symbol table for resolving function addresses to names.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Maps addresses to symbol names.
    symbols: HashMap<u64, String>,
}

impl SymbolTable {
    /// Creates a new empty symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a symbol at a given address.
    pub fn insert(&mut self, address: u64, name: String) {
        self.symbols.insert(address, name);
    }

    /// Looks up a symbol at a given address.
    pub fn get(&self, address: u64) -> Option<&str> {
        self.symbols.get(&address).map(|s| s.as_str())
    }
}

/// Relocation table for resolving symbols in relocatable files.
///
/// In kernel modules and other relocatable files, call instructions
/// and data references have unresolved targets (offset = 0) that need
/// relocation info to determine the actual target.
#[derive(Debug, Clone, Default)]
pub struct RelocationTable {
    /// Maps instruction addresses to target symbol names (for calls).
    call_relocations: HashMap<u64, String>,
    /// Maps instruction addresses to data symbol names (for mov/lea with immediates).
    data_relocations: HashMap<u64, String>,
    /// Maps GOT/PLT entry addresses to symbol names (for indirect calls).
    got_symbols: HashMap<u64, String>,
}

impl RelocationTable {
    /// Creates a new empty relocation table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a call relocation entry.
    pub fn insert(&mut self, call_addr: u64, target_symbol: String) {
        self.call_relocations.insert(call_addr, target_symbol);
    }

    /// Adds a data relocation entry.
    pub fn insert_data(&mut self, inst_addr: u64, symbol: String) {
        self.data_relocations.insert(inst_addr, symbol);
    }

    /// Looks up a call target by call instruction address.
    pub fn get(&self, call_addr: u64) -> Option<&str> {
        self.call_relocations.get(&call_addr).map(|s| s.as_str())
    }

    /// Looks up a data symbol by instruction address.
    pub fn get_data(&self, inst_addr: u64) -> Option<&str> {
        self.data_relocations.get(&inst_addr).map(|s| s.as_str())
    }

    /// Gets all data relocations within an address range, sorted by address.
    pub fn get_data_in_range(&self, start: u64, end: u64) -> Vec<(u64, &str)> {
        let mut results: Vec<_> = self
            .data_relocations
            .iter()
            .filter(|(addr, _)| **addr >= start && **addr < end)
            .map(|(addr, name)| (*addr, name.as_str()))
            .collect();
        results.sort_by_key(|(addr, _)| *addr);
        results
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.call_relocations.is_empty()
            && self.data_relocations.is_empty()
            && self.got_symbols.is_empty()
    }

    /// Returns the number of data relocations.
    pub fn data_relocation_count(&self) -> usize {
        self.data_relocations.len()
    }

    /// Adds a GOT entry mapping.
    pub fn insert_got(&mut self, got_addr: u64, symbol: String) {
        self.got_symbols.insert(got_addr, symbol);
    }

    /// Looks up a symbol by GOT entry address.
    pub fn get_got(&self, got_addr: u64) -> Option<&str> {
        self.got_symbols.get(&got_addr).map(|s| s.as_str())
    }
}

/// Main entry point for decompilation.
///
/// Takes a CFG and produces pseudo-code output.
pub struct Decompiler {
    /// Whether to emit comments with addresses.
    pub emit_addresses: bool,
    /// Indentation string (default: 4 spaces).
    pub indent: String,
    /// String table for resolving addresses.
    pub string_table: Option<StringTable>,
    /// Symbol table for resolving function addresses.
    pub symbol_table: Option<SymbolTable>,
    /// Relocation table for resolving call targets in relocatable files.
    pub relocation_table: Option<RelocationTable>,
    /// Type information for variables (var_name -> type_string).
    /// Comes from type inference analysis.
    pub type_info: HashMap<String, String>,
    /// DWARF variable names (stack_offset -> name).
    /// Comes from DWARF debug info.
    pub dwarf_names: HashMap<i128, String>,
    /// Whether to enable struct field inference.
    pub enable_struct_inference: bool,
    /// Calling convention for function signature recovery.
    pub calling_convention: CallingConvention,
    /// Whether to enable signature recovery (default: true).
    pub enable_signature_recovery: bool,
    /// Type database for struct field access and function prototypes.
    pub type_database: Option<Arc<TypeDatabase>>,
    /// RTTI database for C++ class hierarchy information.
    pub rtti_database: Option<Arc<RttiDatabase>>,
    /// C++ special member analysis for the current function.
    pub cpp_special_member: Option<SpecialMemberAnalysis>,
    /// Exception handling information for the current function.
    pub exception_info: Option<ExceptionInfo>,
    /// Constant database for magic number recognition.
    pub constant_database: Option<Arc<hexray_types::ConstantDatabase>>,
    /// Whether to automatically run type inference on the CFG.
    /// When enabled, SSA form is built and type inference is run to
    /// automatically populate type_info.
    pub enable_auto_type_inference: bool,
    /// Configuration for decompiler optimization passes.
    pub config: Option<DecompilerConfig>,
    /// Database of inter-procedural function summaries.
    /// When set, provides type information from analyzed callees.
    pub summary_database: Option<Arc<SummaryDatabase>>,
    /// Binary data context for jump table reconstruction.
    /// When set, enables proper switch statement recovery by reading jump tables.
    pub binary_data: Option<BinaryDataContext>,
}

impl Default for Decompiler {
    fn default() -> Self {
        Self {
            emit_addresses: true,
            indent: "    ".to_string(),
            string_table: None,
            symbol_table: None,
            relocation_table: None,
            type_info: HashMap::new(),
            dwarf_names: HashMap::new(),
            enable_struct_inference: false,
            calling_convention: CallingConvention::default(),
            enable_signature_recovery: true,
            type_database: None,
            rtti_database: None,
            cpp_special_member: None,
            exception_info: None,
            constant_database: None,
            enable_auto_type_inference: false,
            config: None,
            summary_database: None,
            binary_data: None,
        }
    }
}

use crate::ssa::SsaBuilder;
use crate::types::TypeInference;

impl Decompiler {
    /// Creates a new decompiler with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables address comments.
    pub fn with_addresses(mut self, emit: bool) -> Self {
        self.emit_addresses = emit;
        self
    }

    /// Sets the indentation string.
    pub fn with_indent(mut self, indent: impl Into<String>) -> Self {
        self.indent = indent.into();
        self
    }

    /// Sets the string table for resolving addresses to strings.
    pub fn with_string_table(mut self, table: StringTable) -> Self {
        self.string_table = Some(table);
        self
    }

    /// Sets the symbol table for resolving function addresses.
    pub fn with_symbol_table(mut self, table: SymbolTable) -> Self {
        self.symbol_table = Some(table);
        self
    }

    /// Sets the relocation table for resolving call targets.
    pub fn with_relocation_table(mut self, table: RelocationTable) -> Self {
        self.relocation_table = Some(table);
        self
    }

    /// Sets the type information for variables.
    /// Keys should be variable names (e.g., "var_8", "local_10"),
    /// values should be C type strings (e.g., "int", "char*", "float").
    pub fn with_type_info(mut self, type_info: HashMap<String, String>) -> Self {
        self.type_info = type_info;
        self
    }

    /// Sets the DWARF variable names.
    /// Keys are stack offsets (frame-relative), values are variable names.
    pub fn with_dwarf_names(mut self, names: HashMap<i128, String>) -> Self {
        self.dwarf_names = names;
        self
    }

    /// Enables or disables struct field inference.
    ///
    /// When enabled, the decompiler will analyze memory access patterns
    /// to infer struct layouts and convert `*(ptr + offset)` to `ptr->field`.
    pub fn with_struct_inference(mut self, enable: bool) -> Self {
        self.enable_struct_inference = enable;
        self
    }

    /// Sets the calling convention for function signature recovery.
    ///
    /// Different calling conventions use different registers for arguments:
    /// - `SystemV`: x86_64 Linux/macOS/BSD (RDI, RSI, RDX, RCX, R8, R9)
    /// - `Win64`: Windows x64 (RCX, RDX, R8, R9)
    /// - `Aarch64`: ARM64 (X0-X7)
    /// - `RiscV`: RISC-V (a0-a7)
    pub fn with_calling_convention(mut self, convention: CallingConvention) -> Self {
        self.calling_convention = convention;
        self
    }

    /// Enables or disables signature recovery.
    ///
    /// When enabled (default), the decompiler analyzes register usage to infer
    /// function parameter count and types based on the calling convention.
    pub fn with_signature_recovery(mut self, enable: bool) -> Self {
        self.enable_signature_recovery = enable;
        self
    }

    /// Sets the type database for struct field access and function prototypes.
    ///
    /// When set, the decompiler will use the type database to:
    /// - Convert memory offsets to struct field names (e.g., `*(ptr + 8)` -> `ptr->st_size`)
    /// - Look up function prototypes for better call site rendering
    pub fn with_type_database(mut self, db: Arc<TypeDatabase>) -> Self {
        self.type_database = Some(db);
        self
    }

    /// Sets the RTTI database for C++ class hierarchy information.
    ///
    /// When set, the decompiler can resolve vtable addresses to class names
    /// and understand inheritance relationships.
    pub fn with_rtti_database(mut self, db: Arc<RttiDatabase>) -> Self {
        self.rtti_database = Some(db);
        self
    }

    /// Sets C++ special member analysis for the current function.
    ///
    /// This provides information about whether the function is a constructor,
    /// destructor, or other special member function.
    pub fn with_cpp_special_member(mut self, analysis: SpecialMemberAnalysis) -> Self {
        self.cpp_special_member = Some(analysis);
        self
    }

    /// Analyzes a function for C++ special member patterns.
    ///
    /// This is a convenience method that runs CppSpecialDetector and stores
    /// the result for use during decompilation.
    pub fn analyze_cpp_special(
        mut self,
        cfg: &ControlFlowGraph,
        instructions: &[hexray_core::Instruction],
        symbol: Option<&str>,
    ) -> Self {
        let detector = CppSpecialDetector::new();
        let analysis = detector.analyze_function(cfg, instructions, symbol);
        if analysis.kind.is_some() {
            self.cpp_special_member = Some(analysis);
        }
        self
    }

    /// Sets exception handling information for the current function.
    ///
    /// When set, the decompiler will annotate the output with try/catch blocks
    /// and cleanup handler information.
    pub fn with_exception_info(mut self, info: ExceptionInfo) -> Self {
        self.exception_info = Some(info);
        self
    }

    /// Sets the constant database for magic number recognition.
    ///
    /// When set, the decompiler will recognize and replace magic numbers with
    /// symbolic names (e.g., TIOCGWINSZ for ioctl, SIGINT for signal, O_RDONLY for open).
    pub fn with_constant_database(mut self, db: Arc<hexray_types::ConstantDatabase>) -> Self {
        self.constant_database = Some(db);
        self
    }

    /// Enables or disables automatic type inference.
    ///
    /// When enabled, the decompiler will:
    /// 1. Build SSA form from the CFG
    /// 2. Run type inference analysis
    /// 3. Automatically populate type_info with inferred types
    ///
    /// This improves variable type annotations in the output without requiring
    /// manual type specification.
    pub fn with_auto_type_inference(mut self, enable: bool) -> Self {
        self.enable_auto_type_inference = enable;
        self
    }

    /// Sets the decompiler configuration for optimization passes.
    ///
    /// When set, controls which optimization passes run during decompilation.
    /// If not set, uses the default configuration (Standard optimization level).
    pub fn with_config(mut self, config: DecompilerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Sets the inter-procedural summary database.
    ///
    /// When set, the decompiler uses function summaries from analyzed callees
    /// to improve type inference at call sites. This provides:
    /// - Return type information for function calls
    /// - Parameter type hints for callee functions
    /// - Purity and side-effect information
    pub fn with_summary_database(mut self, db: Arc<SummaryDatabase>) -> Self {
        self.summary_database = Some(db);
        self
    }

    /// Sets the binary data context for jump table reconstruction.
    ///
    /// When set, enables proper switch statement recovery by providing access
    /// to read-only data sections (.rodata, __const, .rdata) where jump
    /// tables are typically stored.
    pub fn with_binary_data(mut self, ctx: BinaryDataContext) -> Self {
        self.binary_data = Some(ctx);
        self
    }

    /// Decompiles a CFG to pseudo-code.
    pub fn decompile(&self, cfg: &ControlFlowGraph, func_name: &str) -> String {
        // Step 0: Run type inference if enabled
        let inferred_types = if self.enable_auto_type_inference {
            // Build SSA form from CFG
            let mut builder = SsaBuilder::new(cfg);
            let ssa = builder.build(func_name);

            // Run type inference with libc signatures
            let mut inference = TypeInference::with_libc();
            inference.infer(&ssa);

            // Export inferred types for the emitter
            inference.export_for_decompiler()
        } else {
            HashMap::new()
        };

        // Step 0b: Get type hints from inter-procedural analysis if available
        let ipc_types = if let Some(ref summary_db) = self.summary_database {
            self.extract_ipc_type_hints(summary_db, func_name)
        } else {
            HashMap::new()
        };

        // Merge inferred types with explicitly provided types
        // Priority: explicit > inferred > inter-procedural
        let mut merged_types = ipc_types;
        for (k, v) in inferred_types {
            merged_types.insert(k, v);
        }
        for (k, v) in &self.type_info {
            merged_types.insert(k.clone(), v.clone());
        }

        // Step 1: Structure the control flow
        let structured = if let Some(ref config) = self.config {
            StructuredCfg::from_cfg_with_config_and_binary_data(
                cfg,
                config,
                self.binary_data.as_ref(),
            )
        } else {
            StructuredCfg::from_cfg_with_config_and_binary_data(
                cfg,
                &config::DecompilerConfig::default(),
                self.binary_data.as_ref(),
            )
        };

        // Step 2: Apply struct inference if enabled
        let structured = if self.enable_struct_inference {
            let mut inference = StructInference::new();
            inference.analyze(&structured.body);
            let transformed_body: Vec<_> = structured
                .body
                .iter()
                .map(|n| inference.transform_node(n))
                .collect();
            StructuredCfg {
                body: transformed_body,
                cfg_entry: structured.cfg_entry,
            }
        } else {
            structured
        };

        // Step 2b: Run expression-level type propagation
        let mut expr_type_propagation = type_propagation::ExpressionTypePropagation::with_libc();
        expr_type_propagation.analyze(&structured.body);
        let expr_types = expr_type_propagation.export_for_decompiler();

        // Merge expression-level types into merged_types
        // Expression-level types are lower priority than SSA/IPC types
        for (k, v) in expr_types {
            if !merged_types.contains_key(&k) {
                merged_types.insert(k, v);
            }
        }

        // Step 3: Apply exception handling if available
        let structured = if let Some(ref eh_info) = self.exception_info {
            StructuredCfg {
                body: apply_exception_handling(structured.body, eh_info),
                cfg_entry: structured.cfg_entry,
            }
        } else {
            structured
        };

        // Step 4: Generate C++ header if this is a special member
        let cpp_header = self.generate_cpp_header(func_name);

        // Step 5: Format function name for C++ special members
        let display_name = self.format_cpp_function_name(func_name);

        // Step 6: Emit pseudo-code
        let mut emitter = PseudoCodeEmitter::new(&self.indent, self.emit_addresses)
            .with_string_table(self.string_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_relocation_table(self.relocation_table.clone())
            .with_type_info(merged_types)
            .with_dwarf_names(self.dwarf_names.clone())
            .with_calling_convention(self.calling_convention)
            .with_signature_recovery(self.enable_signature_recovery);
        if let Some(ref db) = self.summary_database {
            emitter = emitter.with_summary_database(db.clone());
        }
        if let Some(ref db) = self.type_database {
            emitter = emitter.with_type_database(db.clone());
        }
        if let Some(ref db) = self.constant_database {
            emitter = emitter.with_constant_database(db.clone());
        }

        let code = emitter.emit(&structured, &display_name);

        // Build final output with all headers
        let mut output = String::new();

        // Add C++ header if present
        if let Some(header) = cpp_header {
            output.push_str(&header);
            output.push('\n');
        }

        // Add exception handling header if present
        if let Some(eh_header) = self.generate_exception_header() {
            output.push_str(&eh_header);
            output.push('\n');
        }

        output.push_str(&code);
        output
    }

    /// Generates exception handling header comments.
    fn generate_exception_header(&self) -> Option<String> {
        let info = self.exception_info.as_ref()?;

        if info.try_blocks.is_empty() && info.cleanup_handlers.is_empty() {
            return None;
        }

        let mut lines = Vec::new();
        lines.push("// Exception handling:".to_string());

        for (i, try_block) in info.try_blocks.iter().enumerate() {
            lines.push(format!(
                "//   try block {}: {:#x}-{:#x}",
                i + 1,
                try_block.start,
                try_block.end
            ));
            for handler in &try_block.handlers {
                let type_str = if handler.is_catch_all {
                    "catch(...)".to_string()
                } else if let Some(ref t) = handler.catch_type {
                    format!("catch({})", t)
                } else {
                    "catch(?)".to_string()
                };
                lines.push(format!(
                    "//     {} -> landing pad {:#x}",
                    type_str, handler.landing_pad
                ));
            }
        }

        if !info.cleanup_handlers.is_empty() {
            lines.push(format!(
                "//   {} cleanup handler(s)",
                info.cleanup_handlers.len()
            ));
        }

        Some(lines.join("\n"))
    }

    /// Generates a C++ header comment for special member functions.
    fn generate_cpp_header(&self, _func_name: &str) -> Option<String> {
        let analysis = self.cpp_special_member.as_ref()?;
        let kind = analysis.kind.as_ref()?;

        let mut lines = Vec::new();

        // Add function type comment
        lines.push(format!("// C++ {}", kind.description()));

        // Add class name if known
        if let Some(ref class_name) = analysis.class_name {
            lines.push(format!("// Class: {}", class_name));
        }

        // Add vtable assignments
        if !analysis.vtable_assignments.is_empty() {
            for va in &analysis.vtable_assignments {
                let class_name = self
                    .rtti_database
                    .as_ref()
                    .and_then(|db| db.class_name_for_vtable(va.vtable_addr))
                    .unwrap_or("unknown");
                lines.push(format!(
                    "// Vtable at offset {}: {} ({:#x})",
                    va.object_offset, class_name, va.vtable_addr
                ));
            }
        }

        // Add base class calls
        if !analysis.base_calls.is_empty() {
            for bc in &analysis.base_calls {
                let kind_str = if bc.is_constructor {
                    "constructor"
                } else {
                    "destructor"
                };
                let target = bc.class_name.as_deref().unwrap_or("unknown");
                lines.push(format!("// Calls base {} of {}", kind_str, target));
            }
        }

        // Add confidence if not high
        if analysis.confidence < 0.8 {
            lines.push(format!(
                "// Confidence: {:.0}%",
                analysis.confidence * 100.0
            ));
        }

        if lines.is_empty() {
            None
        } else {
            Some(lines.join("\n"))
        }
    }

    /// Formats a function name for C++ special members.
    ///
    /// Converts mangled names or raw names to proper C++ syntax:
    /// - Constructors: `ClassName::ClassName`
    /// - Destructors: `ClassName::~ClassName`
    fn format_cpp_function_name(&self, func_name: &str) -> String {
        use crate::cpp_special::SpecialMemberKind;

        if let Some(ref analysis) = self.cpp_special_member {
            if let (Some(ref kind), Some(ref class_name)) = (&analysis.kind, &analysis.class_name) {
                // Get the simple class name (last component after ::)
                let simple_name = class_name.rsplit("::").next().unwrap_or(class_name);

                return match kind {
                    SpecialMemberKind::Constructor { .. } => {
                        if class_name.contains("::") {
                            format!("{}::{}", class_name, simple_name)
                        } else {
                            format!("{}::{}", class_name, class_name)
                        }
                    }
                    SpecialMemberKind::Destructor { .. } => {
                        if class_name.contains("::") {
                            format!("{}::~{}", class_name, simple_name)
                        } else {
                            format!("{}::~{}", class_name, class_name)
                        }
                    }
                    SpecialMemberKind::CopyConstructor => {
                        format!("{}::{}", class_name, simple_name)
                    }
                    SpecialMemberKind::MoveConstructor => {
                        format!("{}::{}", class_name, simple_name)
                    }
                    SpecialMemberKind::CopyAssignment => {
                        format!("{}::operator=", class_name)
                    }
                    SpecialMemberKind::MoveAssignment => {
                        format!("{}::operator=", class_name)
                    }
                };
            }
        }

        // Not a C++ special member, return original name
        func_name.to_string()
    }

    /// Extracts type hints from inter-procedural analysis.
    ///
    /// Uses function summaries to provide type information for:
    /// - Return values from known function calls
    /// - Parameter types for the current function
    fn extract_ipc_type_hints(
        &self,
        summary_db: &SummaryDatabase,
        func_name: &str,
    ) -> HashMap<String, String> {
        let mut hints = HashMap::new();

        // Check if we have a summary for this function by name
        if let Some(summary) = summary_db.get_summary_by_name(func_name) {
            // Add parameter type hints
            for (idx, param_type) in &summary.param_types {
                let param_name = match self.calling_convention {
                    CallingConvention::SystemV | CallingConvention::Aarch64 => {
                        format!("arg{}", idx)
                    }
                    CallingConvention::Win64 => format!("arg{}", idx),
                    CallingConvention::RiscV => format!("a{}", idx),
                };
                hints.insert(param_name, Self::summary_type_to_c(param_type));
            }
        }

        hints
    }

    /// Converts a SummaryType to a C type string.
    fn summary_type_to_c(ty: &SummaryType) -> String {
        match ty {
            SummaryType::Unknown => "int".to_string(),
            SummaryType::Void => "void".to_string(),
            SummaryType::Bool => "bool".to_string(),
            SummaryType::SignedInt(8) => "int8_t".to_string(),
            SummaryType::SignedInt(16) => "int16_t".to_string(),
            SummaryType::SignedInt(32) => "int".to_string(),
            SummaryType::SignedInt(64) => "int64_t".to_string(),
            SummaryType::SignedInt(bits) => format!("int{}_t", bits),
            SummaryType::UnsignedInt(8) => "uint8_t".to_string(),
            SummaryType::UnsignedInt(16) => "uint16_t".to_string(),
            SummaryType::UnsignedInt(32) => "uint32_t".to_string(),
            SummaryType::UnsignedInt(64) => "uint64_t".to_string(),
            SummaryType::UnsignedInt(bits) => format!("uint{}_t", bits),
            SummaryType::Float(32) => "float".to_string(),
            SummaryType::Float(64) => "double".to_string(),
            SummaryType::Float(bits) => format!("float{}", bits),
            SummaryType::Pointer(inner) => format!("{}*", Self::summary_type_to_c(inner)),
            SummaryType::Array(elem, Some(len)) => {
                format!("{}[{}]", Self::summary_type_to_c(elem), len)
            }
            SummaryType::Array(elem, None) => format!("{}[]", Self::summary_type_to_c(elem)),
            SummaryType::Struct(name) => format!("struct {}", name),
            SummaryType::FunctionPointer {
                params,
                return_type,
            } => {
                let param_str: Vec<_> = params.iter().map(Self::summary_type_to_c).collect();
                format!(
                    "{}(*)({})",
                    Self::summary_type_to_c(return_type),
                    param_str.join(", ")
                )
            }
        }
    }

    /// Recovers the function signature from a CFG.
    ///
    /// This performs signature recovery without generating decompiled code,
    /// useful for building symbol tables or function prototypes.
    pub fn recover_signature(&self, cfg: &ControlFlowGraph) -> FunctionSignature {
        let structured = StructuredCfg::from_cfg(cfg);
        let mut recovery = SignatureRecovery::new(self.calling_convention)
            .with_relocation_table(self.relocation_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_summary_database(self.summary_database.clone());
        recovery.analyze(&structured)
    }

    /// Decompiles a CFG and returns the structured representation.
    pub fn structure(&self, cfg: &ControlFlowGraph) -> StructuredCfg {
        StructuredCfg::from_cfg(cfg)
    }

    /// Analyzes a CFG for struct patterns and returns inferred struct definitions.
    ///
    /// This can be used to generate struct type definitions to prepend to the
    /// decompiled output. The returned vector contains all structs inferred
    /// from memory access patterns.
    pub fn infer_structs(&self, cfg: &ControlFlowGraph) -> Vec<InferredStruct> {
        let structured = StructuredCfg::from_cfg(cfg);
        let mut inference = StructInference::new();
        inference.analyze(&structured.body);
        inference.structs().to_vec()
    }

    /// Decompiles a CFG and returns both the code and quality metrics.
    ///
    /// This combines `decompile` with `compute_metrics` for convenience.
    /// Returns a tuple of (pseudo_code, quality_metrics).
    pub fn decompile_with_metrics(
        &self,
        cfg: &ControlFlowGraph,
        func_name: &str,
    ) -> (String, QualityMetrics) {
        // Get the structured representation
        let structured = if let Some(ref config) = self.config {
            StructuredCfg::from_cfg_with_config(cfg, config)
        } else {
            StructuredCfg::from_cfg(cfg)
        };

        // Compute metrics on the structured code
        let metrics = compute_metrics(&structured.body);

        // Get the decompiled code
        let code = self.decompile(cfg, func_name);

        (code, metrics)
    }

    /// Computes quality metrics for a CFG without generating code.
    ///
    /// This is useful for quick quality assessment or benchmarking.
    pub fn compute_quality_metrics(&self, cfg: &ControlFlowGraph) -> QualityMetrics {
        let structured = if let Some(ref config) = self.config {
            StructuredCfg::from_cfg_with_config(cfg, config)
        } else {
            StructuredCfg::from_cfg(cfg)
        };
        compute_metrics(&structured.body)
    }

    /// Decompiles a CFG and returns both the code and inferred struct definitions.
    ///
    /// This combines `infer_structs` and `decompile` for convenience.
    /// Returns a tuple of (struct_definitions, pseudo_code).
    pub fn decompile_with_structs(
        &self,
        cfg: &ControlFlowGraph,
        func_name: &str,
    ) -> (String, String) {
        let structured = StructuredCfg::from_cfg(cfg);

        // Run struct inference
        let mut inference = StructInference::new();
        inference.analyze(&structured.body);

        // Get struct definitions
        let struct_defs = inference.generate_struct_definitions();

        // Transform expressions to use field access
        let transformed_body: Vec<_> = structured
            .body
            .iter()
            .map(|n| inference.transform_node(n))
            .collect();
        let transformed = StructuredCfg {
            body: transformed_body,
            cfg_entry: structured.cfg_entry,
        };

        // Emit pseudo-code
        let mut emitter = PseudoCodeEmitter::new(&self.indent, self.emit_addresses)
            .with_string_table(self.string_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_relocation_table(self.relocation_table.clone())
            .with_type_info(self.type_info.clone())
            .with_dwarf_names(self.dwarf_names.clone())
            .with_calling_convention(self.calling_convention)
            .with_signature_recovery(self.enable_signature_recovery);
        if let Some(ref db) = self.summary_database {
            emitter = emitter.with_summary_database(db.clone());
        }
        if let Some(ref db) = self.type_database {
            emitter = emitter.with_type_database(db.clone());
        }
        if let Some(ref db) = self.constant_database {
            emitter = emitter.with_constant_database(db.clone());
        }
        let code = emitter.emit(&transformed, func_name);

        (struct_defs, code)
    }
}

/// Applies exception handling information to a structured CFG.
///
/// This function wraps code in try/catch blocks based on the exception info.
/// It identifies which nodes fall within try block address ranges and creates
/// TryCatch nodes with appropriate catch handlers. Landing pad addresses are
/// used to extract the actual handler code from the structured output.
fn apply_exception_handling(
    body: Vec<StructuredNode>,
    exception_info: &ExceptionInfo,
) -> Vec<StructuredNode> {
    if exception_info.try_blocks.is_empty() {
        return body;
    }

    // First, build an index of all landing pad addresses
    let landing_pads: std::collections::HashSet<u64> = exception_info
        .try_blocks
        .iter()
        .flat_map(|tb| tb.handlers.iter().map(|h| h.landing_pad))
        .collect();

    // Find nodes that belong to landing pads
    let mut landing_pad_nodes: std::collections::HashMap<u64, Vec<StructuredNode>> =
        std::collections::HashMap::new();
    let mut remaining_body = Vec::new();

    for node in &body {
        if let Some((node_start, _)) = get_node_address_range(node) {
            // Check if this node is a landing pad entry
            if let Some(&lp_addr) = landing_pads.iter().find(|&&lp| {
                // Node starts at or shortly after landing pad
                node_start >= lp && node_start < lp + 32
            }) {
                landing_pad_nodes
                    .entry(lp_addr)
                    .or_default()
                    .push(node.clone());
                continue;
            }
        }
        remaining_body.push(node.clone());
    }

    let mut result = Vec::new();
    let mut i = 0;

    while i < remaining_body.len() {
        let node = &remaining_body[i];

        // Get the address range of this node
        if let Some((node_start, _node_end)) = get_node_address_range(node) {
            // Check if this node starts a try block
            if let Some(try_block) = exception_info
                .try_blocks
                .iter()
                .find(|tb| node_start >= tb.start && node_start < tb.end)
            {
                // Collect all nodes that fall within this try block
                let mut try_body = vec![remaining_body[i].clone()];
                i += 1;

                while i < remaining_body.len() {
                    if let Some((next_start, _)) = get_node_address_range(&remaining_body[i]) {
                        if next_start >= try_block.start && next_start < try_block.end {
                            try_body.push(remaining_body[i].clone());
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                // Create catch handlers with extracted landing pad bodies
                let catch_handlers: Vec<structurer::CatchHandler> = try_block
                    .handlers
                    .iter()
                    .map(|h| {
                        // Get the landing pad body if we found it
                        let handler_body = landing_pad_nodes
                            .get(&h.landing_pad)
                            .cloned()
                            .unwrap_or_default();

                        structurer::CatchHandler {
                            exception_type: if h.is_catch_all {
                                None
                            } else {
                                h.catch_type.clone()
                            },
                            variable_name: Some("e".to_string()),
                            body: handler_body,
                            landing_pad: h.landing_pad,
                        }
                    })
                    .collect();

                // Create the try-catch node
                result.push(StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                });
                continue;
            }
        }

        // Not in a try block, add as-is
        result.push(remaining_body[i].clone());
        i += 1;
    }

    result
}

/// Gets the address range of a structured node.
fn get_node_address_range(node: &StructuredNode) -> Option<(u64, u64)> {
    match node {
        StructuredNode::Block { address_range, .. } => Some(*address_range),
        StructuredNode::If {
            then_body,
            else_body,
            ..
        } => {
            let start = then_body
                .first()
                .and_then(get_node_address_range)
                .map(|(s, _)| s)?;
            let end = else_body
                .as_ref()
                .and_then(|e| e.last())
                .or(then_body.last())
                .and_then(get_node_address_range)
                .map(|(_, e)| e)?;
            Some((start, end))
        }
        StructuredNode::While { body, .. }
        | StructuredNode::DoWhile { body, .. }
        | StructuredNode::Loop { body, .. }
        | StructuredNode::Sequence(body) => {
            let start = body
                .first()
                .and_then(get_node_address_range)
                .map(|(s, _)| s)?;
            let end = body
                .last()
                .and_then(get_node_address_range)
                .map(|(_, e)| e)?;
            Some((start, end))
        }
        StructuredNode::For { body, .. } => {
            let start = body
                .first()
                .and_then(get_node_address_range)
                .map(|(s, _)| s)?;
            let end = body
                .last()
                .and_then(get_node_address_range)
                .map(|(_, e)| e)?;
            Some((start, end))
        }
        StructuredNode::Switch { cases, default, .. } => {
            let mut all_nodes = Vec::new();
            for (_, body) in cases {
                all_nodes.extend(body.iter());
            }
            if let Some(d) = default {
                all_nodes.extend(d.iter());
            }
            let start = all_nodes
                .first()
                .and_then(|n| get_node_address_range(n))
                .map(|(s, _)| s)?;
            let end = all_nodes
                .last()
                .and_then(|n| get_node_address_range(n))
                .map(|(_, e)| e)?;
            Some((start, end))
        }
        StructuredNode::TryCatch { try_body, .. } => {
            let start = try_body
                .first()
                .and_then(get_node_address_range)
                .map(|(s, _)| s)?;
            let end = try_body
                .last()
                .and_then(get_node_address_range)
                .map(|(_, e)| e)?;
            Some((start, end))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        BasicBlock, BasicBlockId, BlockTerminator, Condition, ControlFlow, Instruction, Operation,
    };

    fn make_simple_cfg() -> ControlFlowGraph {
        // Simple if/else:
        //   bb0: entry
        //     cmp r0, 0
        //     beq bb2
        //   bb1: then
        //     add r1, r1, 1
        //     jmp bb3
        //   bb2: else
        //     sub r1, r1, 1
        //   bb3: join
        //     ret

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        // Entry block
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(
            Instruction::new(0x1000, 4, vec![0; 4], "cmp").with_operation(Operation::Compare),
        );
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        // Then block
        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1004);
        bb1.push_instruction(
            Instruction::new(0x1004, 4, vec![0; 4], "add").with_operation(Operation::Add),
        );
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        // Else block
        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1008);
        bb2.push_instruction(
            Instruction::new(0x1008, 4, vec![0; 4], "sub").with_operation(Operation::Sub),
        );
        bb2.terminator = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        // Join block
        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x100c);
        bb3.push_instruction(
            Instruction::new(0x100c, 4, vec![0; 4], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        // Add edges
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        cfg
    }

    #[test]
    fn test_decompile_if_else() {
        let cfg = make_simple_cfg();
        let decompiler = Decompiler::new().with_addresses(false);
        let output = decompiler.decompile(&cfg, "test_func");

        // Should contain if/else structure
        assert!(output.contains("if"));
        assert!(output.contains("else"));
    }
}
