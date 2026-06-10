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
mod cse;
mod dead_store;
mod emitter;
mod expression;
pub mod float_patterns;
mod for_loop_detection;
pub mod interprocedural;
mod irreducible_cfg;
mod linked_list;
mod loop_canonicalization;
mod loop_condition_analysis;
mod loop_invariant;
mod loop_pattern_detection;
mod memset_idiom;
mod naming;
pub mod quality_metrics;
pub mod riscv_vector;
mod short_circuit;
mod signature;
mod stack_struct_binding;
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

use hexray_core::{ControlFlowGraph, SymbolKind};
use hexray_types::TypeDatabase;
use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// Best-effort fixed-arity hints for direct/internal call targets keyed by name.
    call_signature_hints_by_name: HashMap<String, usize>,
    /// Best-effort fixed-arity hints for direct/internal call targets keyed by address.
    call_signature_hints_by_address: HashMap<u64, usize>,
    /// Best-effort recovered signatures for direct/internal call targets keyed by name.
    call_signatures_by_name: HashMap<String, FunctionSignature>,
    /// Best-effort recovered signatures for direct/internal call targets keyed by address.
    call_signatures_by_address: HashMap<u64, FunctionSignature>,
    /// Resolved direct-call target names keyed by target address.
    call_target_names_by_address: HashMap<u64, String>,
    /// Resolved direct-call target names keyed by call-site address.
    call_target_names_by_call_site: HashMap<u64, String>,
}

impl BinaryDataContext {
    /// Creates a new empty binary data context.
    pub fn new() -> Self {
        Self {
            sections: Vec::new(),
            call_signature_hints_by_name: HashMap::new(),
            call_signature_hints_by_address: HashMap::new(),
            call_signatures_by_name: HashMap::new(),
            call_signatures_by_address: HashMap::new(),
            call_target_names_by_address: HashMap::new(),
            call_target_names_by_call_site: HashMap::new(),
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

    /// Adds a fixed-arity hint for a call target name.
    pub fn add_call_signature_hint_by_name(
        &mut self,
        name: impl Into<String>,
        fixed_arg_count: usize,
    ) {
        self.call_signature_hints_by_name
            .insert(name.into(), fixed_arg_count);
    }

    /// Adds a fixed-arity hint for a call target address.
    pub fn add_call_signature_hint_by_address(&mut self, address: u64, fixed_arg_count: usize) {
        self.call_signature_hints_by_address
            .insert(address, fixed_arg_count);
    }

    /// Adds a recovered signature for a call target name.
    pub fn add_call_signature_by_name(
        &mut self,
        name: impl Into<String>,
        signature: FunctionSignature,
    ) {
        let name = name.into();
        self.call_signature_hints_by_name
            .insert(name.clone(), signature.parameters.len());
        self.call_signatures_by_name.insert(name, signature);
    }

    /// Adds a recovered signature for a call target address.
    pub fn add_call_signature_by_address(&mut self, address: u64, signature: FunctionSignature) {
        self.call_signature_hints_by_address
            .insert(address, signature.parameters.len());
        self.call_signatures_by_address.insert(address, signature);
    }

    /// Looks up a fixed-arity hint by call target name.
    pub fn call_signature_hint_by_name(&self, name: &str) -> Option<usize> {
        self.call_signature_hints_by_name.get(name).copied()
    }

    /// Looks up a fixed-arity hint by call target address.
    pub fn call_signature_hint_by_address(&self, address: u64) -> Option<usize> {
        self.call_signature_hints_by_address.get(&address).copied()
    }

    /// Looks up a recovered signature by call target name.
    pub fn call_signature_by_name(&self, name: &str) -> Option<&FunctionSignature> {
        self.call_signatures_by_name.get(name)
    }

    /// Looks up a recovered signature by call target address.
    pub fn call_signature_by_address(&self, address: u64) -> Option<&FunctionSignature> {
        self.call_signatures_by_address.get(&address)
    }

    /// Adds a resolved direct-call target name by target address.
    pub fn add_call_target_name_by_address(&mut self, address: u64, name: impl Into<String>) {
        self.call_target_names_by_address
            .insert(address, name.into());
    }

    /// Adds a resolved direct-call target name by call-site address.
    pub fn add_call_target_name_by_call_site(&mut self, call_site: u64, name: impl Into<String>) {
        self.call_target_names_by_call_site
            .insert(call_site, name.into());
    }

    /// Looks up a resolved direct-call target name by target address.
    pub fn call_target_name_by_address(&self, address: u64) -> Option<&str> {
        self.call_target_names_by_address
            .get(&address)
            .map(|name| name.as_str())
    }

    /// Looks up a resolved direct-call target name by call-site address.
    pub fn call_target_name_by_call_site(&self, call_site: u64) -> Option<&str> {
        self.call_target_names_by_call_site
            .get(&call_site)
            .map(|name| name.as_str())
    }

    /// Returns an iterator over resolved direct-call target names keyed by address.
    pub fn call_target_names_by_address(&self) -> impl ExactSizeIterator<Item = (u64, &str)> + '_ {
        self.call_target_names_by_address
            .iter()
            .map(|(address, name)| (*address, name.as_str()))
    }

    /// Returns an iterator over resolved direct-call target names keyed by call site.
    pub fn call_target_names_by_call_site(
        &self,
    ) -> impl ExactSizeIterator<Item = (u64, &str)> + '_ {
        self.call_target_names_by_call_site
            .iter()
            .map(|(call_site, name)| (*call_site, name.as_str()))
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
    strings: BTreeMap<u64, String>,
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
        if let Some(value) = self.strings.get(&address) {
            return Some(value.as_str());
        }

        let (&start, value) = self.strings.range(..=address).next_back()?;
        let offset = usize::try_from(address.checked_sub(start)?).ok()?;
        let bytes = value.as_bytes();
        if offset >= bytes.len() {
            return None;
        }
        std::str::from_utf8(&bytes[offset..]).ok()
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

fn collect_known_noreturn_targets(
    symbol_table: Option<&SymbolTable>,
    relocation_table: Option<&RelocationTable>,
) -> HashMap<u64, String> {
    let mut targets = HashMap::new();

    if let Some(symbol_table) = symbol_table {
        for (address, symbol) in &symbol_table.symbols {
            if crate::is_noreturn_function_name(&symbol.name) {
                targets.insert(*address, symbol.name.clone());
            }
        }
    }

    if let Some(relocation_table) = relocation_table {
        for relocation in relocation_table.call_relocations.values() {
            if relocation.target_addr != 0 && crate::is_noreturn_function_name(&relocation.symbol) {
                targets
                    .entry(relocation.target_addr)
                    .or_insert_with(|| relocation.symbol.clone());
            }
        }
    }

    targets
}

fn collect_known_ubsan_targets(
    symbol_table: Option<&SymbolTable>,
    relocation_table: Option<&RelocationTable>,
) -> HashMap<u64, String> {
    let mut targets = HashMap::new();

    if let Some(symbol_table) = symbol_table {
        for (address, symbol) in &symbol_table.symbols {
            if crate::is_ubsan_handler_function_name(&symbol.name) {
                targets.insert(*address, symbol.name.clone());
            }
        }
    }

    if let Some(relocation_table) = relocation_table {
        for relocation in relocation_table.call_relocations.values() {
            if relocation.target_addr != 0
                && crate::is_ubsan_handler_function_name(&relocation.symbol)
            {
                targets
                    .entry(relocation.target_addr)
                    .or_insert_with(|| relocation.symbol.clone());
            }
        }
    }

    targets
}

/// Symbol table for resolving function addresses to names.
#[derive(Debug, Clone)]
struct SymbolRecord {
    name: String,
    size: u64,
    is_defined: bool,
    is_data_symbol: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymbolMatch<'a> {
    pub address: u64,
    pub name: &'a str,
    pub size: u64,
    pub is_defined: bool,
    pub is_data_symbol: bool,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Maps addresses to symbol names.
    symbols: HashMap<u64, SymbolRecord>,
    /// Sorted symbol addresses for contained-range lookups.
    ordered_addresses: Vec<u64>,
}

impl SymbolTable {
    /// Creates a new empty symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a symbol at a given address.
    pub fn insert(&mut self, address: u64, name: String) {
        self.insert_with_size(address, name, 0);
    }

    /// Adds a symbol at a given address with size metadata.
    pub fn insert_with_size(&mut self, address: u64, name: String, size: u64) {
        self.insert_with_metadata(address, name, size, true, true);
    }

    /// Adds a symbol with explicit definition and kind metadata.
    pub fn insert_with_metadata(
        &mut self,
        address: u64,
        name: String,
        size: u64,
        is_defined: bool,
        is_data_symbol: bool,
    ) {
        let is_new = self
            .symbols
            .insert(
                address,
                SymbolRecord {
                    name,
                    size,
                    is_defined,
                    is_data_symbol,
                },
            )
            .is_none();
        if is_new {
            match self.ordered_addresses.binary_search(&address) {
                Ok(_) => {}
                Err(idx) => self.ordered_addresses.insert(idx, address),
            }
        }
    }

    /// Adds a symbol from a parsed symbol record.
    pub fn insert_symbol(&mut self, symbol: &hexray_core::Symbol, display_name: String) {
        let is_data_symbol = matches!(
            symbol.kind,
            hexray_core::SymbolKind::Object
                | hexray_core::SymbolKind::Common
                | hexray_core::SymbolKind::Tls
        );
        self.insert_with_metadata(
            symbol.address,
            display_name,
            symbol.size,
            symbol.is_defined(),
            is_data_symbol,
        );
    }

    /// Looks up a symbol at a given address.
    pub fn get(&self, address: u64) -> Option<&str> {
        self.symbols.get(&address).map(|s| s.name.as_str())
    }

    /// Iterates over exact symbol-address mappings.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &str)> + '_ {
        self.ordered_addresses.iter().filter_map(|address| {
            self.symbols
                .get(address)
                .map(|symbol| (*address, symbol.name.as_str()))
        })
    }

    /// Looks up the exact symbol record at an address.
    pub fn get_match(&self, address: u64) -> Option<SymbolMatch<'_>> {
        let symbol = self.symbols.get(&address)?;
        Some(SymbolMatch {
            address,
            name: symbol.name.as_str(),
            size: symbol.size,
            is_defined: symbol.is_defined,
            is_data_symbol: symbol.is_data_symbol,
        })
    }

    /// Looks up the symbol that contains a given address.
    pub fn get_containing(&self, address: u64) -> Option<&str> {
        self.get_containing_match(address).map(|symbol| symbol.name)
    }

    /// Looks up the defined data symbol that contains a given address.
    pub fn get_containing_match(&self, address: u64) -> Option<SymbolMatch<'_>> {
        let mut idx = match self.ordered_addresses.binary_search(&address) {
            Ok(idx) => idx,
            Err(0) => return None,
            Err(idx) => idx - 1,
        };
        loop {
            let start = self.ordered_addresses[idx];
            let symbol = self.symbols.get(&start)?;
            if symbol.size != 0 && symbol.is_defined && symbol.is_data_symbol {
                let end = start.checked_add(symbol.size)?;
                if address < end {
                    return Some(SymbolMatch {
                        address: start,
                        name: symbol.name.as_str(),
                        size: symbol.size,
                        is_defined: symbol.is_defined,
                        is_data_symbol: symbol.is_data_symbol,
                    });
                }
                if address >= end {
                    return None;
                }
            }

            if idx == 0 {
                return None;
            }
            idx -= 1;
        }
    }

    /// Returns true if any symbol record uses the given display name.
    pub fn contains_name(&self, name: &str) -> bool {
        self.symbols.values().any(|symbol| symbol.name == name)
    }
}

/// A resolved call-site relocation.
#[derive(Debug, Clone)]
pub struct CallRelocation {
    /// The target symbol name.
    pub symbol: String,
    /// The resolved address used by analysis.
    pub target_addr: u64,
    /// Whether the target is external to the current binary.
    pub is_external: bool,
}

/// A resolved data relocation.
#[derive(Debug, Clone)]
struct DataRelocation {
    /// The target symbol name.
    symbol: String,
    /// The resolved address used by analysis.
    target_addr: u64,
    /// Whether the relocation was PC-relative (e.g. RIP-relative x86_64 loads).
    is_pc_relative: bool,
}

/// Relocation table for resolving symbols in relocatable files.
///
/// In kernel modules and other relocatable files, call instructions
/// and data references have unresolved targets (offset = 0) that need
/// relocation info to determine the actual target.
#[derive(Debug, Clone, Default)]
pub struct RelocationTable {
    /// Maps instruction addresses to target symbol names (for calls).
    call_relocations: HashMap<u64, CallRelocation>,
    /// Maps instruction addresses to data symbol names (for mov/lea with immediates).
    data_relocations: HashMap<u64, DataRelocation>,
    /// Maps GOT/PLT entry addresses to symbol names (for indirect calls).
    got_symbols: HashMap<u64, String>,
    /// Maps TLS GD descriptor addresses to the underlying TLS symbol names.
    tls_descriptors: HashMap<u64, String>,
}

impl RelocationTable {
    /// Creates a new empty relocation table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a call relocation entry.
    pub fn insert(&mut self, call_addr: u64, target_symbol: String) {
        self.insert_call(call_addr, target_symbol, 0, false);
    }

    /// Adds a resolved call relocation entry.
    pub fn insert_call(
        &mut self,
        call_addr: u64,
        target_symbol: String,
        target_addr: u64,
        is_external: bool,
    ) {
        self.call_relocations.insert(
            call_addr,
            CallRelocation {
                symbol: target_symbol,
                target_addr,
                is_external,
            },
        );
    }

    /// Adds a data relocation entry.
    pub fn insert_data(
        &mut self,
        inst_addr: u64,
        symbol: String,
        target_addr: u64,
        is_pc_relative: bool,
    ) {
        self.data_relocations.insert(
            inst_addr,
            DataRelocation {
                symbol,
                target_addr,
                is_pc_relative,
            },
        );
    }

    /// Looks up a call target by call instruction address.
    pub fn get(&self, call_addr: u64) -> Option<&str> {
        self.call_relocations
            .get(&call_addr)
            .map(|reloc| reloc.symbol.as_str())
    }

    /// Looks up the full resolved call relocation by call instruction address.
    pub fn get_call(&self, call_addr: u64) -> Option<&CallRelocation> {
        self.call_relocations.get(&call_addr)
    }

    /// Returns all resolved call relocations.
    pub fn call_relocations(&self) -> impl ExactSizeIterator<Item = (u64, &CallRelocation)> + '_ {
        self.call_relocations
            .iter()
            .map(|(addr, reloc)| (*addr, reloc))
    }

    /// Looks up a data symbol by instruction address.
    pub fn get_data(&self, inst_addr: u64) -> Option<&str> {
        self.data_relocations
            .get(&inst_addr)
            .map(|reloc| reloc.symbol.as_str())
    }

    /// Looks up a data relocation target address by instruction address.
    pub fn get_data_target(&self, inst_addr: u64) -> Option<u64> {
        self.data_relocations
            .get(&inst_addr)
            .map(|reloc| reloc.target_addr)
    }

    /// Returns whether the data relocation at an instruction was PC-relative.
    pub fn data_is_pc_relative(&self, inst_addr: u64) -> bool {
        self.data_relocations
            .get(&inst_addr)
            .is_some_and(|reloc| reloc.is_pc_relative)
    }

    /// Gets all data relocations within an address range, sorted by address.
    pub fn get_data_in_range(&self, start: u64, end: u64) -> Vec<(u64, &str)> {
        let mut results: Vec<_> = self
            .data_relocations
            .iter()
            .filter(|(addr, _)| **addr >= start && **addr < end)
            .map(|(addr, reloc)| (*addr, reloc.symbol.as_str()))
            .collect();
        results.sort_by_key(|(addr, _)| *addr);
        results
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.call_relocations.is_empty()
            && self.data_relocations.is_empty()
            && self.got_symbols.is_empty()
            && self.tls_descriptors.is_empty()
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

    /// Adds a TLS Global Dynamic descriptor mapping.
    pub fn insert_tls_descriptor(&mut self, descriptor_addr: u64, symbol: String) {
        self.tls_descriptors.insert(descriptor_addr, symbol);
    }

    /// Looks up the underlying TLS symbol for a GD descriptor address.
    pub fn get_tls_descriptor(&self, descriptor_addr: u64) -> Option<&str> {
        self.tls_descriptors
            .get(&descriptor_addr)
            .map(|s| s.as_str())
    }

    /// Returns an iterator over all symbol names referenced by relocations.
    pub fn symbol_names(&self) -> impl Iterator<Item = &str> + '_ {
        self.call_relocations
            .values()
            .map(|reloc| reloc.symbol.as_str())
            .chain(
                self.data_relocations
                    .values()
                    .map(|reloc| reloc.symbol.as_str()),
            )
            .chain(self.got_symbols.values().map(|symbol| symbol.as_str()))
            .chain(self.tls_descriptors.values().map(|symbol| symbol.as_str()))
    }

    /// Returns descriptor addresses that resolve to the given TLS symbol.
    pub fn tls_descriptor_addresses(&self, symbol: &str) -> Vec<u64> {
        self.tls_descriptors
            .iter()
            .filter_map(|(addr, name)| {
                if name == symbol
                    || hexray_core::unversioned_symbol_name(name) == symbol
                    || hexray_core::unversioned_symbol_name(symbol) == name.as_str()
                {
                    Some(*addr)
                } else {
                    None
                }
            })
            .collect()
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
    /// DWARF parameter names in declaration order.
    pub dwarf_param_names: Vec<String>,
    /// DWARF lexical-block ranges keyed by local variable name.
    pub dwarf_scope_ranges: HashMap<String, (u64, u64)>,
    /// Whether to enable struct field inference.
    pub enable_struct_inference: bool,
    /// Calling convention for function signature recovery.
    pub calling_convention: CallingConvention,
    /// Target pointer width in bytes (4 on ILP32, 8 on LP64). Used to
    /// size class layouts whose width depends on the ABI's word size
    /// — notably C++ smart pointers, where `shared_ptr<T>` is
    /// `2 * pointer_size` bytes. Sourced from `BinaryFormat::bitness`
    /// at the CLI; defaults to 8 (the dominant target) for callers
    /// that don't set it.
    pub pointer_size: usize,
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
    /// Split cold helper targets whose bodies end in C++ throw/rethrow machinery.
    pub throw_thunks: HashMap<u64, String>,
    /// Symbol kind for the current function when known.
    pub current_function_kind: Option<SymbolKind>,
    /// Thread-pointer-relative TLS symbol names keyed by byte offset.
    pub tls_symbol_offsets: HashMap<i64, String>,
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
            dwarf_param_names: Vec::new(),
            dwarf_scope_ranges: HashMap::new(),
            enable_struct_inference: false,
            calling_convention: CallingConvention::default(),
            pointer_size: 8,
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
            throw_thunks: HashMap::new(),
            current_function_kind: None,
            tls_symbol_offsets: HashMap::new(),
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

    /// Sets known cold-split throw thunk targets.
    pub fn with_throw_thunks(mut self, throw_thunks: HashMap<u64, String>) -> Self {
        self.throw_thunks = throw_thunks;
        self
    }

    /// Sets the symbol kind for the current function when known.
    pub fn with_current_function_kind(mut self, kind: Option<SymbolKind>) -> Self {
        self.current_function_kind = kind;
        self
    }

    /// Sets thread-pointer-relative TLS symbol names keyed by byte offset.
    pub fn with_tls_symbol_offsets(mut self, offsets: HashMap<i64, String>) -> Self {
        self.tls_symbol_offsets = offsets;
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

    /// Sets DWARF parameter names in declaration order.
    pub fn with_dwarf_param_names(mut self, names: Vec<String>) -> Self {
        self.dwarf_param_names = names;
        self
    }

    /// Sets DWARF lexical-block ranges keyed by local variable name.
    pub fn with_dwarf_scope_ranges(mut self, ranges: HashMap<String, (u64, u64)>) -> Self {
        self.dwarf_scope_ranges = ranges;
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

    /// Sets the target pointer width in bytes (4 on ILP32, 8 on
    /// LP64). The CLI sources this from `BinaryFormat::bitness`; library
    /// callers that know their target can pass it directly.
    pub fn with_pointer_size(mut self, pointer_size: usize) -> Self {
        self.pointer_size = pointer_size;
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
        let structured = self.structure(cfg);

        // Step 2: Apply struct inference if enabled
        let structured = if self.enable_struct_inference {
            let mut inference = self.make_struct_inference();
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

        // Step 2a: Reconstruct stack-local structs from known-prototype call
        // sites (deferral #3). A `call(…, &<stack@K>)` whose prototype says the
        // matching parameter is `struct T *` binds the stack region as a typed
        // local; the rewrite then renders the call argument as `&<local>` and
        // exact-field-offset stores as `<local>.<field> = …`. Interior
        // union/array bytes are left untouched here — a refinement step.
        let stack_struct_bindings = stack_struct_binding::analyze_with_builtin_db(
            &structured.body,
            self.binary_data.as_ref(),
            self.pointer_size,
        );
        for binding in stack_struct_bindings.iter() {
            merged_types.insert(binding.local_name.clone(), binding.type_name.clone());
        }
        let structured = StructuredCfg {
            body: stack_struct_binding::apply_bindings(structured.body, &stack_struct_bindings),
            cfg_entry: structured.cfg_entry,
        };

        // Step 2b: Run expression-level type propagation
        let mut expr_type_propagation = type_propagation::ExpressionTypePropagation::with_libc()
            .with_binary_data(self.binary_data.as_ref());
        expr_type_propagation.analyze(&structured.body);
        let expr_types = expr_type_propagation.export_for_decompiler();

        // Merge expression-level types into merged_types
        // Expression-level types are generally lower priority than SSA/IPC types,
        // but pointer-like evidence from deref/index usage should override generic
        // scalar fallback guesses (e.g., int64_t from register width).
        let is_pointer_like = |ty: &str| {
            let ty = ty.trim();
            ty.contains("(*)") || ty.contains('*') || ty.ends_with("[]")
        };
        let is_scalar_fallback = |ty: &str| {
            matches!(
                ty.trim(),
                "int"
                    | "unsigned int"
                    | "int64_t"
                    | "uint64_t"
                    | "int32_t"
                    | "uint32_t"
                    | "int16_t"
                    | "uint16_t"
                    | "int8_t"
                    | "uint8_t"
            )
        };
        for (k, v) in expr_types {
            match merged_types.get(&k) {
                None => {
                    merged_types.insert(k, v);
                }
                Some(existing)
                    if is_pointer_like(&v)
                        && !is_pointer_like(existing)
                        && is_scalar_fallback(existing) =>
                {
                    merged_types.insert(k, v);
                }
                _ => {}
            }
        }

        self.seed_assignment_alias_type_info(&structured.body, &mut merged_types);
        self.seed_cpp_special_type_info(&structured.body, &mut merged_types);

        // Step 3: Apply exception handling if available
        let structured = if let Some(ref eh_info) = self.exception_info {
            StructuredCfg {
                body: apply_exception_handling(structured.body, eh_info),
                cfg_entry: structured.cfg_entry,
            }
        } else {
            structured
        };

        // Step 3a: Recognise the canonical Itanium C++ throw triple
        // (`__cxa_allocate_exception` + value store + `__cxa_throw`)
        // and collapse it into a single `throw VALUE` pseudo-statement.
        // Runs here (not inside `simplify_statements`) because PLT-call
        // target names live in the symbol/relocation tables, which the
        // simplify pipeline doesn't otherwise have access to.
        let structured = {
            // Mirror the emitter's call-target name resolution
            // (`emitter/mod.rs:format_call_target_name` site): the
            // relocation table is consulted FIRST by call_site (this
            // is how PLT imports keep their `@plt` names visible), and
            // the symbol table SECOND by the target address. Codex
            // review on PR #13 flagged that the original symbol-only
            // resolver missed relocation-backed `__cxa_*` calls.
            let resolve = |target_addr: u64, call_site: u64| -> Option<String> {
                if let Some(reloc) = self.relocation_table.as_ref() {
                    if let Some(name) = reloc.get(call_site) {
                        return Some(name.to_string());
                    }
                }
                self.symbol_table
                    .as_ref()
                    .and_then(|st| st.get(target_addr).map(str::to_string))
            };
            StructuredCfg {
                body: structurer::recover_cxa_throw_pattern(structured.body, &resolve),
                cfg_entry: structured.cfg_entry,
            }
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
            .with_tls_symbol_offsets(self.tls_symbol_offsets.clone())
            .with_type_info(merged_types)
            .with_dwarf_names(self.dwarf_names.clone())
            .with_dwarf_param_names(self.dwarf_param_names.clone())
            .with_dwarf_scope_ranges(self.dwarf_scope_ranges.clone())
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

        let code = if let Some(signature) = self.adjusted_cpp_special_signature(cfg, func_name) {
            emitter.emit_with_signature(&structured, &display_name, &signature)
        } else if self.enable_signature_recovery {
            let signature = SignatureRecovery::new(self.calling_convention)
                .with_binary_data(self.binary_data.as_ref())
                .with_relocation_table(self.relocation_table.clone())
                .with_symbol_table(self.symbol_table.clone())
                .with_summary_database(self.summary_database.clone())
                .with_dwarf_param_names(self.dwarf_param_names.clone())
                .with_current_function_kind(self.current_function_kind)
                .with_function_name(func_name)
                .with_float_arg_seeds(signature::scan_float_arg_registers(
                    cfg,
                    self.calling_convention,
                ))
                .with_float_return_seed(signature::scan_float_return(cfg, self.calling_convention))
                .analyze(&structured);
            emitter.emit_with_signature(&structured, &display_name, &signature)
        } else {
            emitter.emit(&structured, &display_name)
        };

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

        // Add C++20 coroutine-clone header if this function is a
        // compiler-generated `.actor` / `.destroy` / `.cleanup`
        // partition. Tells the user upfront that they're looking at a
        // state-machine body rather than the source coroutine, and
        // points at the deferral for the rest.
        if let Some(coro_header) = Self::generate_coroutine_header(&display_name) {
            output.push_str(&coro_header);
            output.push('\n');
        }

        output.push_str(&code);
        output
    }

    /// Render a per-function header for C++20 coroutine clones —
    /// `.actor` (state-machine stepper), `.destroy` (frame
    /// destructor), `.cleanup` (early-cleanup partition). When gcc /
    /// clang lower `co_await` / `co_yield` / `co_return` they split
    /// the function into these three clones; the surviving bodies
    /// shuttle suspend/resume state through a heap-allocated frame
    /// pointed to by the first parameter. Recovering the original
    /// `co_await` chain is research-grade work (deferral #7 of the
    /// post-v1.3.8 roadmap); for now the header simply makes the
    /// shape explicit and points downstream readers at the deferral
    /// so they don't mistake the state-machine body for the source.
    fn generate_coroutine_header(display_name: &str) -> Option<String> {
        let (kind, friendly) = if display_name.contains("[clone .actor]") {
            ("actor", "state-machine stepper")
        } else if display_name.contains("[clone .destroy]") {
            ("destroy", "frame destructor")
        } else if display_name.contains("[clone .cleanup]") {
            ("cleanup", "early-cleanup partition")
        } else {
            return None;
        };
        let mut lines = Vec::new();
        lines.push("// C++20 coroutine clone:".to_string());
        lines.push(format!(
            "//   This is the .{} partition ({}) emitted by the compiler",
            kind, friendly
        ));
        lines.push("//   for a coroutine source function. Suspend/resume state lives".to_string());
        lines.push(
            "//   in the heap-allocated frame pointed to by the first parameter;".to_string(),
        );
        lines.push("//   full `co_await` / `co_yield` / `co_return` reconstruction is".to_string());
        lines.push("//   deferred (deferral #7 of the v1.3.8 roadmap).".to_string());
        Some(lines.join("\n"))
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

    fn cpp_special_this_type(&self) -> Option<String> {
        let analysis = self.cpp_special_member.as_ref()?;
        let kind = analysis.kind.as_ref()?;
        if !matches!(
            kind,
            crate::cpp_special::SpecialMemberKind::Constructor { .. }
                | crate::cpp_special::SpecialMemberKind::Destructor { .. }
        ) {
            return None;
        }
        let class_name = analysis.class_name.as_deref()?.trim();
        if class_name.is_empty() {
            return None;
        }
        Some(format!("struct {}*", class_name))
    }

    fn collect_cpp_special_this_aliases(
        nodes: &[StructuredNode],
        aliases: &mut HashSet<String>,
        changed: &mut bool,
    ) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        Self::collect_cpp_special_this_aliases_from_expr(stmt, aliases, changed);
                    }
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    Self::collect_cpp_special_this_aliases_from_expr(condition, aliases, changed);
                    Self::collect_cpp_special_this_aliases(then_body, aliases, changed);
                    if let Some(nodes) = else_body {
                        Self::collect_cpp_special_this_aliases(nodes, aliases, changed);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                } => {
                    Self::collect_cpp_special_this_aliases_from_expr(condition, aliases, changed);
                    Self::collect_cpp_special_this_aliases(body, aliases, changed);
                }
                StructuredNode::DoWhile {
                    body, condition, ..
                } => {
                    Self::collect_cpp_special_this_aliases(body, aliases, changed);
                    Self::collect_cpp_special_this_aliases_from_expr(condition, aliases, changed);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(expr) = init {
                        Self::collect_cpp_special_this_aliases_from_expr(expr, aliases, changed);
                    }
                    Self::collect_cpp_special_this_aliases_from_expr(condition, aliases, changed);
                    if let Some(expr) = update {
                        Self::collect_cpp_special_this_aliases_from_expr(expr, aliases, changed);
                    }
                    Self::collect_cpp_special_this_aliases(body, aliases, changed);
                }
                StructuredNode::Loop { body, .. } => {
                    Self::collect_cpp_special_this_aliases(body, aliases, changed);
                }
                StructuredNode::Return(Some(expr)) | StructuredNode::Expr(expr) => {
                    Self::collect_cpp_special_this_aliases_from_expr(expr, aliases, changed);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    Self::collect_cpp_special_this_aliases_from_expr(value, aliases, changed);
                    for (_, body) in cases {
                        Self::collect_cpp_special_this_aliases(body, aliases, changed);
                    }
                    if let Some(nodes) = default {
                        Self::collect_cpp_special_this_aliases(nodes, aliases, changed);
                    }
                }
                StructuredNode::Sequence(nodes) => {
                    Self::collect_cpp_special_this_aliases(nodes, aliases, changed);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    Self::collect_cpp_special_this_aliases(try_body, aliases, changed);
                    for handler in catch_handlers {
                        Self::collect_cpp_special_this_aliases(&handler.body, aliases, changed);
                    }
                }
                StructuredNode::Return(None)
                | StructuredNode::Break
                | StructuredNode::Continue
                | StructuredNode::Goto(_)
                | StructuredNode::Label(_) => {}
            }
        }
    }

    fn collect_cpp_special_this_aliases_from_expr(
        expr: &Expr,
        aliases: &mut HashSet<String>,
        changed: &mut bool,
    ) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let (Some(lhs_name), Some(rhs_name)) = (
                    Self::expr_identifier_name(lhs),
                    Self::expr_identifier_name(rhs),
                ) {
                    if aliases.contains(rhs_name.as_str()) && aliases.insert(lhs_name) {
                        *changed = true;
                    }
                }
                Self::collect_cpp_special_this_aliases_from_expr(lhs, aliases, changed);
                Self::collect_cpp_special_this_aliases_from_expr(rhs, aliases, changed);
            }
            ExprKind::BinOp { left, right, .. } => {
                Self::collect_cpp_special_this_aliases_from_expr(left, aliases, changed);
                Self::collect_cpp_special_this_aliases_from_expr(right, aliases, changed);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                Self::collect_cpp_special_this_aliases_from_expr(operand, aliases, changed);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                Self::collect_cpp_special_this_aliases_from_expr(base, aliases, changed);
                Self::collect_cpp_special_this_aliases_from_expr(index, aliases, changed);
            }
            ExprKind::FieldAccess { base, .. } => {
                Self::collect_cpp_special_this_aliases_from_expr(base, aliases, changed);
            }
            ExprKind::Call { target, args } => {
                match target {
                    expression::CallTarget::Indirect(expr) => {
                        Self::collect_cpp_special_this_aliases_from_expr(expr, aliases, changed);
                    }
                    expression::CallTarget::IndirectGot { expr, .. } => {
                        Self::collect_cpp_special_this_aliases_from_expr(expr, aliases, changed);
                    }
                    expression::CallTarget::Direct { .. } | expression::CallTarget::Named(_) => {}
                }
                for arg in args {
                    Self::collect_cpp_special_this_aliases_from_expr(arg, aliases, changed);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::collect_cpp_special_this_aliases_from_expr(cond, aliases, changed);
                Self::collect_cpp_special_this_aliases_from_expr(then_expr, aliases, changed);
                Self::collect_cpp_special_this_aliases_from_expr(else_expr, aliases, changed);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    Self::collect_cpp_special_this_aliases_from_expr(value, aliases, changed);
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                Self::collect_cpp_special_this_aliases_from_expr(display_expr, aliases, changed);
            }
            ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => {}
        }
    }

    fn expr_identifier_name(expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(var) => Some(var.name.clone()),
            ExprKind::Unknown(name) => Some(name.clone()),
            ExprKind::Deref { addr, .. } => Self::stack_slot_identifier_name(addr),
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => Self::stack_slot_identifier_name_from_array(base, index, *element_size),
            ExprKind::Cast { expr, .. } => Self::expr_identifier_name(expr),
            _ => None,
        }
    }

    fn stack_slot_identifier_name(addr: &Expr) -> Option<String> {
        match &addr.kind {
            ExprKind::Var(base) if matches!(base.name.as_str(), "sp" | "rsp") => {
                Some("var_0".to_string())
            }
            ExprKind::BinOp { op, left, right } => {
                let ExprKind::Var(base) = &left.kind else {
                    return None;
                };
                let ExprKind::IntLit(offset) = &right.kind else {
                    return None;
                };
                let actual_offset = match op {
                    BinOpKind::Add => *offset,
                    BinOpKind::Sub => -*offset,
                    _ => return None,
                };
                Self::stack_slot_name_from_base_and_offset(&base.name, actual_offset)
            }
            _ => None,
        }
    }

    fn stack_slot_identifier_name_from_array(
        base: &Expr,
        index: &Expr,
        element_size: usize,
    ) -> Option<String> {
        let ExprKind::Var(base_var) = &base.kind else {
            return None;
        };
        let ExprKind::IntLit(slot_index) = &index.kind else {
            return None;
        };
        let actual_offset = *slot_index * element_size as i128;
        Self::stack_slot_name_from_base_and_offset(&base_var.name, actual_offset)
    }

    fn stack_slot_name_from_base_and_offset(
        base_name: &str,
        actual_offset: i128,
    ) -> Option<String> {
        if matches!(base_name, "rbp" | "x29") {
            if actual_offset < 0 {
                return Some(format!("local_{:x}", (-actual_offset) as u128));
            }
            if actual_offset > 0 {
                return Some(format!("arg_{:x}", actual_offset as u128));
            }
        } else if matches!(base_name, "rsp" | "sp") && actual_offset >= 0 {
            return Some(format!("var_{:x}", actual_offset as u128));
        }
        None
    }

    fn seed_cpp_special_type_info(
        &self,
        body: &[StructuredNode],
        merged_types: &mut HashMap<String, String>,
    ) {
        let Some(this_type) = self.cpp_special_this_type() else {
            return;
        };

        let mut aliases = HashSet::from([
            "arg0".to_string(),
            self.calling_convention.integer_arg_registers()[0].to_string(),
            self.calling_convention.integer_arg_registers_32()[0].to_string(),
            "this".to_string(),
            "arg_8".to_string(),
            "arg_0x8".to_string(),
            "local_8".to_string(),
            "local_0x8".to_string(),
            "stack_-8".to_string(),
        ]);

        loop {
            let mut changed = false;
            Self::collect_cpp_special_this_aliases(body, &mut aliases, &mut changed);
            if !changed {
                break;
            }
        }

        for alias in aliases {
            merged_types.insert(alias, this_type.clone());
        }
    }

    fn seed_assignment_alias_type_info(
        &self,
        body: &[StructuredNode],
        merged_types: &mut HashMap<String, String>,
    ) {
        loop {
            let mut changed = false;
            Self::collect_assignment_alias_type_info(body, merged_types, &mut changed);
            if !changed {
                break;
            }
        }
    }

    fn collect_assignment_alias_type_info(
        nodes: &[StructuredNode],
        merged_types: &mut HashMap<String, String>,
        changed: &mut bool,
    ) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        Self::collect_assignment_alias_type_info_from_expr(
                            stmt,
                            merged_types,
                            changed,
                        );
                    }
                }
                StructuredNode::Expr(expr) => {
                    Self::collect_assignment_alias_type_info_from_expr(expr, merged_types, changed);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    Self::collect_assignment_alias_type_info_from_expr(
                        condition,
                        merged_types,
                        changed,
                    );
                    Self::collect_assignment_alias_type_info(then_body, merged_types, changed);
                    if let Some(else_body) = else_body {
                        Self::collect_assignment_alias_type_info(else_body, merged_types, changed);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                }
                | StructuredNode::DoWhile {
                    condition, body, ..
                } => {
                    Self::collect_assignment_alias_type_info_from_expr(
                        condition,
                        merged_types,
                        changed,
                    );
                    Self::collect_assignment_alias_type_info(body, merged_types, changed);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(init) = init {
                        Self::collect_assignment_alias_type_info_from_expr(
                            init,
                            merged_types,
                            changed,
                        );
                    }
                    Self::collect_assignment_alias_type_info_from_expr(
                        condition,
                        merged_types,
                        changed,
                    );
                    if let Some(update) = update {
                        Self::collect_assignment_alias_type_info_from_expr(
                            update,
                            merged_types,
                            changed,
                        );
                    }
                    Self::collect_assignment_alias_type_info(body, merged_types, changed);
                }
                StructuredNode::Loop { body, .. } => {
                    Self::collect_assignment_alias_type_info(body, merged_types, changed);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    Self::collect_assignment_alias_type_info_from_expr(
                        value,
                        merged_types,
                        changed,
                    );
                    for (_, body) in cases {
                        Self::collect_assignment_alias_type_info(body, merged_types, changed);
                    }
                    if let Some(default) = default {
                        Self::collect_assignment_alias_type_info(default, merged_types, changed);
                    }
                }
                StructuredNode::Return(Some(expr)) => {
                    Self::collect_assignment_alias_type_info_from_expr(expr, merged_types, changed);
                }
                StructuredNode::Sequence(nodes) => {
                    Self::collect_assignment_alias_type_info(nodes, merged_types, changed);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    Self::collect_assignment_alias_type_info(try_body, merged_types, changed);
                    for handler in catch_handlers {
                        Self::collect_assignment_alias_type_info(
                            &handler.body,
                            merged_types,
                            changed,
                        );
                    }
                }
                StructuredNode::Return(None)
                | StructuredNode::Break
                | StructuredNode::Continue
                | StructuredNode::Goto(_)
                | StructuredNode::Label(_) => {}
            }
        }
    }

    fn collect_assignment_alias_type_info_from_expr(
        expr: &Expr,
        merged_types: &mut HashMap<String, String>,
        changed: &mut bool,
    ) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let (Some(lhs_name), Some(rhs_name)) = (
                    Self::expr_identifier_name(lhs),
                    Self::expr_identifier_name(rhs),
                ) {
                    if lhs_name != rhs_name {
                        if let Some(rhs_type) = merged_types.get(&rhs_name).cloned() {
                            if Self::is_pointer_like_type(&rhs_type) {
                                let should_update = merged_types
                                    .get(&lhs_name)
                                    .is_none_or(|existing| !Self::is_pointer_like_type(existing));
                                if should_update {
                                    merged_types.insert(lhs_name, rhs_type);
                                    *changed = true;
                                }
                            }
                        }
                    }
                }
                Self::collect_assignment_alias_type_info_from_expr(lhs, merged_types, changed);
                Self::collect_assignment_alias_type_info_from_expr(rhs, merged_types, changed);
            }
            ExprKind::BinOp { left, right, .. } => {
                Self::collect_assignment_alias_type_info_from_expr(left, merged_types, changed);
                Self::collect_assignment_alias_type_info_from_expr(right, merged_types, changed);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                Self::collect_assignment_alias_type_info_from_expr(operand, merged_types, changed);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                Self::collect_assignment_alias_type_info_from_expr(base, merged_types, changed);
                Self::collect_assignment_alias_type_info_from_expr(index, merged_types, changed);
            }
            ExprKind::FieldAccess { base, .. } => {
                Self::collect_assignment_alias_type_info_from_expr(base, merged_types, changed);
            }
            ExprKind::Call { target, args } => {
                match target {
                    expression::CallTarget::Indirect(expr) => {
                        Self::collect_assignment_alias_type_info_from_expr(
                            expr,
                            merged_types,
                            changed,
                        );
                    }
                    expression::CallTarget::IndirectGot { expr, .. } => {
                        Self::collect_assignment_alias_type_info_from_expr(
                            expr,
                            merged_types,
                            changed,
                        );
                    }
                    expression::CallTarget::Direct { .. } | expression::CallTarget::Named(_) => {}
                }
                for arg in args {
                    Self::collect_assignment_alias_type_info_from_expr(arg, merged_types, changed);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::collect_assignment_alias_type_info_from_expr(cond, merged_types, changed);
                Self::collect_assignment_alias_type_info_from_expr(
                    then_expr,
                    merged_types,
                    changed,
                );
                Self::collect_assignment_alias_type_info_from_expr(
                    else_expr,
                    merged_types,
                    changed,
                );
            }
            ExprKind::Phi(values) => {
                for value in values {
                    Self::collect_assignment_alias_type_info_from_expr(
                        value,
                        merged_types,
                        changed,
                    );
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                Self::collect_assignment_alias_type_info_from_expr(
                    display_expr,
                    merged_types,
                    changed,
                );
            }
            ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => {}
        }
    }

    fn is_pointer_like_type(ty: &str) -> bool {
        let ty = ty.trim();
        ty.contains("(*)") || ty.contains('*') || ty.ends_with("[]")
    }

    fn cpp_special_explicit_param_count(
        &self,
        func_name: &str,
        class_name: Option<&str>,
    ) -> Option<usize> {
        let class_name = class_name?.trim();
        let open_idx = func_name.find('(')?;
        let close_idx = func_name[open_idx..].find(')')? + open_idx;
        let qualified = func_name[..open_idx].trim();
        let (_, member_name) = qualified.rsplit_once("::")?;
        let simple_name = class_name.rsplit("::").next().unwrap_or(class_name);
        if member_name != simple_name && member_name != format!("~{}", simple_name) {
            return None;
        }

        let params = func_name[open_idx + 1..close_idx].trim();
        if params.is_empty() || params == "void" {
            return Some(0);
        }

        let mut count = 1usize;
        let mut angle_depth = 0usize;
        let mut paren_depth = 0usize;
        let mut bracket_depth = 0usize;
        for ch in params.chars() {
            match ch {
                '<' => angle_depth += 1,
                '>' => angle_depth = angle_depth.saturating_sub(1),
                '(' => paren_depth += 1,
                ')' => paren_depth = paren_depth.saturating_sub(1),
                '[' => bracket_depth += 1,
                ']' => bracket_depth = bracket_depth.saturating_sub(1),
                ',' if angle_depth == 0 && paren_depth == 0 && bracket_depth == 0 => count += 1,
                _ => {}
            }
        }

        Some(count)
    }

    fn adjusted_cpp_special_signature(
        &self,
        cfg: &ControlFlowGraph,
        func_name: &str,
    ) -> Option<FunctionSignature> {
        let analysis = self.cpp_special_member.as_ref()?;
        let kind = analysis.kind.as_ref()?;
        if !matches!(
            kind,
            crate::cpp_special::SpecialMemberKind::Constructor { .. }
                | crate::cpp_special::SpecialMemberKind::Destructor { .. }
        ) {
            return None;
        }

        let mut signature = self.recover_signature(cfg);
        let this_reg = self.calling_convention.integer_arg_registers()[0];
        if signature.parameters.is_empty() {
            signature.parameters.push(Parameter::from_int_register(
                0,
                this_reg,
                ParamType::Pointer,
            ));
        }
        if let Some(first_param) = signature.parameters.first_mut() {
            first_param.name = "this".to_string();
            if !matches!(
                first_param.param_type,
                ParamType::Pointer | ParamType::TypedPointer(_)
            ) {
                first_param.param_type = ParamType::Pointer;
            }
        }

        if let Some(explicit_count) =
            self.cpp_special_explicit_param_count(func_name, analysis.class_name.as_deref())
        {
            let expected_count = explicit_count + 1;
            if signature.parameters.len() > expected_count {
                signature.parameters.truncate(expected_count);
                signature
                    .parameter_provenance
                    .retain(|index, _| *index < expected_count);
            }
        }

        Some(signature)
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
        let structured = self.structure(cfg);
        let mut recovery = SignatureRecovery::new(self.calling_convention)
            .with_binary_data(self.binary_data.as_ref())
            .with_relocation_table(self.relocation_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_summary_database(self.summary_database.clone())
            .with_dwarf_param_names(self.dwarf_param_names.clone())
            .with_current_function_kind(self.current_function_kind)
            .with_float_arg_seeds(signature::scan_float_arg_registers(
                cfg,
                self.calling_convention,
            ))
            .with_float_return_seed(signature::scan_float_return(cfg, self.calling_convention));
        recovery.analyze(&structured)
    }

    /// Decompiles a CFG and returns the structured representation.
    pub fn structure(&self, cfg: &ControlFlowGraph) -> StructuredCfg {
        let noreturn_targets = collect_known_noreturn_targets(
            self.symbol_table.as_ref(),
            self.relocation_table.as_ref(),
        );
        let ubsan_targets =
            collect_known_ubsan_targets(self.symbol_table.as_ref(), self.relocation_table.as_ref());
        if let Some(ref config) = self.config {
            StructuredCfg::from_cfg_with_config_and_binary_data_and_exception_info_and_known_targets(
                cfg,
                config,
                self.binary_data.as_ref(),
                self.exception_info.as_ref(),
                &noreturn_targets,
                &ubsan_targets,
                &self.throw_thunks,
            )
        } else {
            StructuredCfg::from_cfg_with_config_and_binary_data_and_exception_info_and_known_targets(
                cfg,
                &config::DecompilerConfig::default(),
                self.binary_data.as_ref(),
                self.exception_info.as_ref(),
                &noreturn_targets,
                &ubsan_targets,
                &self.throw_thunks,
            )
        }
    }

    fn make_struct_inference(&self) -> StructInference {
        let global_identifiers = self
            .symbol_table
            .as_ref()
            .map(|table| {
                table
                    .symbols
                    .values()
                    .map(|symbol| symbol.name.clone())
                    .collect()
            })
            .unwrap_or_default();

        StructInference::new().with_global_identifiers(global_identifiers)
    }

    /// Analyzes a CFG for struct patterns and returns inferred struct definitions.
    ///
    /// This can be used to generate struct type definitions to prepend to the
    /// decompiled output. The returned vector contains all structs inferred
    /// from memory access patterns.
    pub fn infer_structs(&self, cfg: &ControlFlowGraph) -> Vec<InferredStruct> {
        let structured = self.structure(cfg);
        let mut inference = self.make_struct_inference();
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
        let structured = self.structure(cfg);

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
        let structured = self.structure(cfg);
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
        let structured = self.structure(cfg);

        // Run struct inference
        let mut inference = self.make_struct_inference();
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
            .with_dwarf_param_names(self.dwarf_param_names.clone())
            .with_dwarf_scope_ranges(self.dwarf_scope_ranges.clone())
            .with_calling_convention(self.calling_convention)
            .with_signature_recovery(self.enable_signature_recovery)
            .with_binary_data(self.binary_data.clone());
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
    if exception_info.try_blocks.is_empty() && exception_info.cleanup_handlers.is_empty() {
        return body;
    }

    // First, build an index of all landing pad addresses
    let landing_pads: std::collections::HashSet<u64> = exception_info
        .try_blocks
        .iter()
        .flat_map(|tb| tb.handlers.iter().map(|h| h.landing_pad))
        .chain(
            exception_info
                .cleanup_handlers
                .iter()
                .map(|cleanup| cleanup.landing_pad),
        )
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

    if exception_info.try_blocks.is_empty() {
        return wrap_cleanup_regions(
            remaining_body,
            &exception_info.cleanup_handlers,
            &landing_pad_nodes,
        );
    }

    let mut result = Vec::new();
    let mut i = 0;

    while i < remaining_body.len() {
        let node = &remaining_body[i];

        // Get the address range of this node
        if let Some((node_start, node_end)) = get_node_address_range(node) {
            // Check if this node starts a try block
            if let Some(try_block) = exception_info
                .try_blocks
                .iter()
                .find(|tb| node_end > tb.start && node_start < tb.end)
            {
                // Collect all nodes that fall within this try block
                let mut try_body = vec![remaining_body[i].clone()];
                i += 1;

                while i < remaining_body.len() {
                    if let Some((next_start, next_end)) = get_node_address_range(&remaining_body[i])
                    {
                        if next_end > try_block.start && next_start < try_block.end {
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

fn wrap_cleanup_regions(
    body: Vec<StructuredNode>,
    cleanup_handlers: &[CleanupInfo],
    landing_pad_nodes: &std::collections::HashMap<u64, Vec<StructuredNode>>,
) -> Vec<StructuredNode> {
    let mut result = Vec::new();
    let mut i = 0;

    while i < body.len() {
        let node = &body[i];

        if let Some((node_start, node_end)) = get_node_address_range(node) {
            if let Some(cleanup) = cleanup_handlers
                .iter()
                .find(|cleanup| node_end > cleanup.start && node_start < cleanup.end)
            {
                let mut try_body = vec![body[i].clone()];
                i += 1;

                while i < body.len() {
                    if let Some((next_start, next_end)) = get_node_address_range(&body[i]) {
                        if next_end > cleanup.start && next_start < cleanup.end {
                            try_body.push(body[i].clone());
                            i += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                result.push(StructuredNode::TryCatch {
                    try_body,
                    catch_handlers: vec![structurer::CatchHandler {
                        exception_type: None,
                        variable_name: None,
                        body: landing_pad_nodes
                            .get(&cleanup.landing_pad)
                            .cloned()
                            .unwrap_or_default(),
                        landing_pad: cleanup.landing_pad,
                    }],
                });
                continue;
            }
        }

        result.push(body[i].clone());
        i += 1;
    }

    if result
        .iter()
        .any(|node| matches!(node, StructuredNode::TryCatch { .. }))
        || cleanup_handlers.len() != 1
        || body.is_empty()
    {
        return result;
    }

    let cleanup = &cleanup_handlers[0];
    vec![StructuredNode::TryCatch {
        try_body: body,
        catch_handlers: vec![structurer::CatchHandler {
            exception_type: None,
            variable_name: None,
            body: landing_pad_nodes
                .get(&cleanup.landing_pad)
                .cloned()
                .unwrap_or_default(),
            landing_pad: cleanup.landing_pad,
        }],
    }]
}

#[cfg(test)]
fn catch_handler_body_len(catch_handlers: &[structurer::CatchHandler]) -> usize {
    catch_handlers
        .first()
        .map(|handler| handler.body.len())
        .unwrap_or(0)
}

#[cfg(test)]
fn is_catch_all_handler(catch_handlers: &[structurer::CatchHandler]) -> bool {
    catch_handlers
        .first()
        .is_some_and(|handler| handler.exception_type.is_none())
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

    #[test]
    fn test_seed_assignment_alias_type_info_propagates_pointer_types() {
        let body = vec![StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("local_8"), Expr::unknown("arg0")),
                Expr::assign(Expr::unknown("ptr_copy"), Expr::unknown("local_8")),
            ],
            address_range: (0x1000, 0x1008),
        }];

        let mut merged_types = HashMap::from([("arg0".to_string(), "int16_t*".to_string())]);
        let decompiler = Decompiler::new();
        decompiler.seed_assignment_alias_type_info(&body, &mut merged_types);

        assert_eq!(
            merged_types.get("local_8").map(String::as_str),
            Some("int16_t*")
        );
        assert_eq!(
            merged_types.get("ptr_copy").map(String::as_str),
            Some("int16_t*")
        );
    }

    #[test]
    fn test_decompile_absolute_global_increment_emits_compound_assignment() {
        use hexray_core::{Immediate, MemoryRef, Operand};

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        block.instructions.push(Instruction {
            address: 0x1000,
            size: 7,
            bytes: vec![],
            operation: Operation::Add,
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::absolute(0x403df0, 4)),
                Operand::Immediate(Immediate {
                    value: 1,
                    size: 4,
                    signed: false,
                }),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        });
        block.instructions.push(Instruction {
            address: 0x1007,
            size: 1,
            bytes: vec![],
            operation: Operation::Return,
            mnemonic: "ret".to_string(),
            operands: vec![],
            control_flow: ControlFlow::Return,
            reads: vec![],
            writes: vec![],
            guard: None,
        });
        block.terminator = BlockTerminator::Return;
        cfg.add_block(block);

        let mut symbols = SymbolTable::new();
        symbols.insert_with_metadata(0x403de0, "g_tls_struct".to_string(), 16, true, true);
        symbols.insert_with_metadata(0x403df0, "s_thread_local".to_string(), 4, true, true);

        let output = Decompiler::new()
            .with_addresses(false)
            .with_symbol_table(symbols)
            .decompile(&cfg, "incr_static");

        assert!(
            output.contains("s_thread_local += 1;"),
            "expected direct global increment, got:\n{output}"
        );
    }

    #[test]
    fn test_decompile_x86_atomic_store_from_xchg_is_preserved() {
        use crate::SymbolTable;
        use hexray_core::{Architecture, MemoryRef, Operand, Register, RegisterClass};

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        block.instructions.push(Instruction {
            address: 0x1000,
            size: 6,
            bytes: vec![0x87],
            operation: Operation::Exchange,
            mnemonic: "xchg".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::absolute(0x404028, 4)),
                Operand::Register(edi),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        });
        block.instructions.push(
            Instruction::new(0x1006, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        block.terminator = BlockTerminator::Return;
        cfg.add_block(block);

        let mut symbols = SymbolTable::new();
        symbols.insert_with_metadata(0x404028, "g_counter".to_string(), 4, true, true);

        let structured = StructuredCfg::from_cfg(&cfg);
        assert!(
            structured.body.iter().any(|node| {
                matches!(
                    node,
                    StructuredNode::Block { statements, .. }
                        if statements.iter().any(|stmt| matches!(
                            &stmt.kind,
                            super::expression::ExprKind::Call {
                                target: super::expression::CallTarget::Named(name),
                                ..
                            } if name == "atomic_store"
                        ))
                )
            }),
            "expected structured body to retain atomic_store call, got:\n{:#?}",
            structured.body
        );

        let output = Decompiler::new()
            .with_addresses(false)
            .with_symbol_table(symbols)
            .decompile(&cfg, "store_counter");

        assert!(
            output.contains("atomic_store(") && output.contains("arg0"),
            "expected atomic store pseudo-call, got:\n{output}"
        );
    }

    #[test]
    fn test_decompile_x86_seq_cst_fence_uses_enum_constant_without_declaring_local() {
        use hexray_core::{Architecture, MemoryRef, Operand, Register, RegisterClass};

        let rsp = Register::new(Architecture::X86_64, RegisterClass::General, 4, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        block.instructions.push(Instruction {
            address: 0x1000,
            size: 7,
            bytes: vec![0xf0, 0x48, 0x83, 0x44, 0x24, 0x08, 0x00],
            operation: Operation::Add,
            mnemonic: "add".to_string(),
            operands: vec![
                Operand::Memory(MemoryRef::base_disp(rsp, 8, 8)),
                Operand::imm(0, 1),
            ],
            control_flow: ControlFlow::Sequential,
            reads: vec![],
            writes: vec![],
            guard: None,
        });
        block.instructions.push(
            Instruction::new(0x1007, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        block.terminator = BlockTerminator::Return;
        cfg.add_block(block);

        let output = Decompiler::new()
            .with_addresses(false)
            .decompile(&cfg, "mem_fence");

        assert!(
            output.contains("__atomic_thread_fence(memory_order_seq_cst);"),
            "expected seq-cst fence pseudo-call, got:\n{output}"
        );
        assert!(
            output.contains("void mem_fence(void)"),
            "expected fence helper to keep a void signature, got:\n{output}"
        );
        assert!(
            !output.contains("int memory_order_seq_cst;"),
            "did not expect memory_order_seq_cst to be declared as a local:\n{output}"
        );
        assert!(
            !output.contains("atomic_fetch_add("),
            "did not expect lock-add fence idiom to survive as atomic_fetch_add:\n{output}"
        );
    }

    #[test]
    fn test_decompile_x86_hidden_rep_stos_saved_arg_tail_call_recovers_sigaction_args() {
        use crate::SymbolTable;
        use hexray_core::{Architecture, MemoryRef, Operand, Register, RegisterClass};

        let edi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 32);
        let ecx = Register::new(Architecture::X86_64, RegisterClass::General, 1, 32);
        let edx = Register::new(Architecture::X86_64, RegisterClass::General, 2, 32);
        let eax = Register::new(Architecture::X86_64, RegisterClass::General, 0, 32);
        let r8d = Register::new(Architecture::X86_64, RegisterClass::General, 8, 32);
        let rdi = Register::new(Architecture::X86_64, RegisterClass::General, 7, 64);
        let rsi = Register::new(Architecture::X86_64, RegisterClass::General, 6, 64);
        let rsp = Register::new(Architecture::X86_64, RegisterClass::General, 4, 64);

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1400);
        bb0.instructions.push(
            Instruction::new(0x1400, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(r8d), Operand::Register(edi)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1403, 5, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(ecx), Operand::imm(0x12, 4)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1408, 2, vec![], "xor")
                .with_operation(Operation::Xor)
                .with_operands(vec![Operand::Register(edx), Operand::Register(edx)]),
        );
        bb0.instructions.push(
            Instruction::new(0x140a, 2, vec![], "xor")
                .with_operation(Operation::Xor)
                .with_operands(vec![Operand::Register(eax), Operand::Register(eax)]),
        );
        bb0.instructions.push(
            Instruction::new(0x140c, 5, vec![], "lea")
                .with_operation(Operation::LoadEffectiveAddress)
                .with_operands(vec![
                    Operand::Register(rdi),
                    Operand::Memory(MemoryRef::base_disp(rsp, 0x8, 8)),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x1411, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(rsi), Operand::Register(rsp)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1414, 8, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![
                    Operand::Memory(MemoryRef::base_disp(rsp, 0, 8)),
                    Operand::imm(0x401300, 8),
                ]),
        );
        bb0.instructions.push(
            Instruction::new(0x141c, 3, vec![], "__rep_stosq")
                .with_operation(Operation::Other(0xab)),
        );
        bb0.instructions.push(
            Instruction::new(0x141f, 3, vec![], "mov")
                .with_operation(Operation::Move)
                .with_operands(vec![Operand::Register(edi), Operand::Register(r8d)]),
        );
        bb0.instructions.push(
            Instruction::new(0x1422, 5, vec![], "call")
                .with_operation(Operation::Call)
                .with_operands(vec![Operand::pc_rel(0, 0x4010c0)])
                .with_control_flow(ControlFlow::Call {
                    target: 0x4010c0,
                    return_addr: 0x1427,
                }),
        );
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1430);
        bb1.instructions.push(
            Instruction::new(0x1430, 1, vec![], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return),
        );
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let mut binary_data = BinaryDataContext::new();
        binary_data.add_call_target_name_by_address(0x4010c0, "sigaction@GLIBC_2.2.5");

        let mut symbols = SymbolTable::new();
        symbols.insert_with_metadata(0x401300, "handler".to_string(), 8, true, false);

        let decompiler = Decompiler::new()
            .with_addresses(false)
            .with_binary_data(binary_data)
            .with_symbol_table(symbols);
        let output = decompiler.decompile(&cfg, "install_handler");

        assert!(
            output.contains("return ") && output.contains("(arg0, rsp, 0);"),
            "expected saved arg restore to win over rep stos clobber:\n{output}"
        );
        assert!(
            !output.contains("(rsp + 152, arg0, rsp);")
                && !output.contains("(rsp + 0x98, arg0, rsp);"),
            "did not expect rep stos tail pointer to survive as arg0:\n{output}"
        );
    }

    #[test]
    fn test_apply_exception_handling_wraps_cleanup_only_landing_pad_in_catch_all() {
        let body = vec![
            StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![Expr::unknown("live_stmt")],
                address_range: (0x1000, 0x1008),
            },
            StructuredNode::Block {
                id: BasicBlockId::new(1),
                statements: vec![Expr::unknown("cleanup_stmt")],
                address_range: (0x1200, 0x1208),
            },
        ];
        let info = ExceptionInfo {
            try_blocks: Vec::new(),
            cleanup_handlers: vec![CleanupInfo {
                start: 0x1000,
                end: 0x1010,
                landing_pad: 0x1200,
            }],
        };

        let filtered = apply_exception_handling(body, &info);

        assert_eq!(filtered.len(), 1);
        match &filtered[0] {
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                assert_eq!(try_body.len(), 1);
                assert_eq!(catch_handlers.len(), 1);
                assert_eq!(catch_handler_body_len(catch_handlers), 1);
                assert!(is_catch_all_handler(catch_handlers));
            }
            other => panic!("expected synthetic try/catch, got {other:?}"),
        }
    }

    #[test]
    fn test_apply_exception_handling_wraps_cleanup_only_expr_body_with_single_handler() {
        let body = vec![StructuredNode::Expr(Expr::unknown("live_stmt"))];
        let info = ExceptionInfo {
            try_blocks: Vec::new(),
            cleanup_handlers: vec![CleanupInfo {
                start: 0x1000,
                end: 0x1010,
                landing_pad: 0x1200,
            }],
        };

        let wrapped = apply_exception_handling(body, &info);

        assert_eq!(wrapped.len(), 1);
        match &wrapped[0] {
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                assert_eq!(try_body.len(), 1);
                assert_eq!(catch_handlers.len(), 1);
                assert!(is_catch_all_handler(catch_handlers));
            }
            other => panic!("expected synthetic try/catch, got {other:?}"),
        }
    }

    #[test]
    fn test_apply_exception_handling_wraps_blocks_that_overlap_try_range() {
        let body = vec![
            StructuredNode::Block {
                id: BasicBlockId::new(0),
                statements: vec![Expr::unknown("call_stmt")],
                address_range: (0x1000, 0x1018),
            },
            StructuredNode::Block {
                id: BasicBlockId::new(1),
                statements: vec![Expr::unknown("handler_stmt")],
                address_range: (0x1200, 0x1208),
            },
        ];
        let info = ExceptionInfo {
            try_blocks: vec![TryBlockInfo {
                start: 0x1008,
                end: 0x1010,
                handlers: vec![CatchInfo {
                    landing_pad: 0x1200,
                    catch_type: Some("MyError".to_string()),
                    is_catch_all: false,
                }],
            }],
            cleanup_handlers: Vec::new(),
        };

        let wrapped = apply_exception_handling(body, &info);

        assert_eq!(wrapped.len(), 1);
        match &wrapped[0] {
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                assert_eq!(try_body.len(), 1);
                assert_eq!(catch_handlers.len(), 1);
                assert_eq!(catch_handlers[0].body.len(), 1);
            }
            other => panic!("expected try/catch wrapper, got {other:?}"),
        }
    }

    #[test]
    fn string_table_resolves_suffix_addresses_inside_printable_runs() {
        let bytes = b"\x01\x00@@n = %d\0";
        let table = StringTable::from_binary_data(bytes, 0x1000);

        assert_eq!(table.get(0x1002), Some("@@n = %d"));
        assert_eq!(table.get(0x1004), Some("n = %d"));
        assert_eq!(table.get(0x1009), Some("d"));
        assert_eq!(table.get(0x100a), None);
    }

    #[test]
    fn symbol_table_resolves_containing_symbol_ranges() {
        let mut table = SymbolTable::new();
        table.insert_with_size(0x4062e0, "__gcov0.classify".to_string(), 40);

        assert_eq!(table.get(0x4062e0), Some("__gcov0.classify"));
        assert_eq!(table.get_containing(0x4062f8), Some("__gcov0.classify"));
        assert_eq!(table.get_containing(0x406308), None);
    }

    #[test]
    fn symbol_table_range_lookup_ignores_undefined_or_nondata_symbols() {
        let mut table = SymbolTable::new();
        table.insert_with_metadata(0x5000, "g_struct".to_string(), 16, true, true);
        table.insert_with_metadata(0x5008, "stdin".to_string(), 32, false, false);

        let containing = table
            .get_containing_match(0x5008)
            .expect("containing symbol");
        assert_eq!(containing.address, 0x5000);
        assert_eq!(containing.name, "g_struct");
    }

    #[test]
    fn coroutine_header_fires_for_known_clone_partitions() {
        // gcc/clang lower C++20 coroutines into `.actor` / `.destroy` /
        // `.cleanup` clones; the header just tells the user which
        // partition they're looking at and that full co_await
        // reconstruction is deferral #7. Each known suffix must be
        // recognised; an unrelated function must produce no header at
        // all.
        let actor = Decompiler::generate_coroutine_header(
            "simple_coro(simple_coro(int)::_Z11simple_coroi.Frame*) [clone .actor]",
        )
        .expect("actor header");
        assert!(actor.contains(".actor partition"));
        assert!(actor.contains("state-machine stepper"));
        assert!(actor.contains("deferral #7"));

        let destroy = Decompiler::generate_coroutine_header(
            "simple_coro(simple_coro(int)::_Z11simple_coroi.Frame*) [clone .destroy]",
        )
        .expect("destroy header");
        assert!(destroy.contains(".destroy partition"));
        assert!(destroy.contains("frame destructor"));

        let cleanup = Decompiler::generate_coroutine_header("foo(foo()::Frame*) [clone .cleanup]")
            .expect("cleanup header");
        assert!(cleanup.contains(".cleanup partition"));
        assert!(cleanup.contains("early-cleanup partition"));

        assert!(
            Decompiler::generate_coroutine_header("ordinary_function(int)").is_none(),
            "non-coroutine names must not trigger the coroutine header"
        );
        // `[clone .cold]` is a gcc cold-clone partition (unrelated to
        // coroutines) — must not match.
        assert!(
            Decompiler::generate_coroutine_header("foo(int) [clone .cold]").is_none(),
            "the cold-clone partition is not a coroutine clone"
        );
    }
}
