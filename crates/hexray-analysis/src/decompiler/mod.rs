//! Pseudo-code generator / decompiler.
//!
//! This module transforms disassembled code (CFG) into high-level pseudo-code.
//!
//! The decompilation pipeline:
//! 1. **Control Flow Structuring** - Identify if/else, loops (while, do-while, for)
//! 2. **Expression Recovery** - Convert instructions to high-level expressions
//! 3. **Pseudo-code Emission** - Generate readable pseudo-code output

pub mod array_detection;
mod emitter;
mod expression;
mod naming;
mod signature;
mod struct_inference;
mod structurer;
mod switch_recovery;

pub use emitter::PseudoCodeEmitter;
pub use expression::{BinOpKind, Expr, ExprKind, UnaryOpKind, Variable};
pub use naming::{NamingContext, TypeHint};
pub use signature::{
    CallingConvention, FunctionSignature, ParamType, Parameter, ParameterLocation,
    SignatureRecovery,
};
pub use struct_inference::{InferredField, InferredStruct, InferredType, StructInference};
pub use structurer::{LoopKind, StructuredCfg, StructuredNode};
pub use switch_recovery::{JumpTableInfo, SwitchInfo, SwitchKind, SwitchRecovery};

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
                // Allow shorter strings (min 2 chars) for format strings like "%s"
                if end < data.len() && data[end] == 0 && end - start >= 2 {
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
        }
    }
}

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

    /// Decompiles a CFG to pseudo-code.
    pub fn decompile(&self, cfg: &ControlFlowGraph, func_name: &str) -> String {
        // Step 1: Structure the control flow
        let structured = StructuredCfg::from_cfg(cfg);

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

        // Step 3: Generate C++ header if this is a special member
        let cpp_header = self.generate_cpp_header(func_name);

        // Step 4: Emit pseudo-code
        let mut emitter = PseudoCodeEmitter::new(&self.indent, self.emit_addresses)
            .with_string_table(self.string_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_relocation_table(self.relocation_table.clone())
            .with_type_info(self.type_info.clone())
            .with_dwarf_names(self.dwarf_names.clone())
            .with_calling_convention(self.calling_convention)
            .with_signature_recovery(self.enable_signature_recovery);
        if let Some(ref db) = self.type_database {
            emitter = emitter.with_type_database(db.clone());
        }

        let code = emitter.emit(&structured, func_name);

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

    /// Recovers the function signature from a CFG.
    ///
    /// This performs signature recovery without generating decompiled code,
    /// useful for building symbol tables or function prototypes.
    pub fn recover_signature(&self, cfg: &ControlFlowGraph) -> FunctionSignature {
        let structured = StructuredCfg::from_cfg(cfg);
        let mut recovery = SignatureRecovery::new(self.calling_convention);
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
        if let Some(ref db) = self.type_database {
            emitter = emitter.with_type_database(db.clone());
        }
        let code = emitter.emit(&transformed, func_name);

        (struct_defs, code)
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
