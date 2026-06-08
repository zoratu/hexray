//! Pseudo-code emitter.
//!
//! Emits readable pseudo-code from structured control flow.

#![allow(dead_code)]

use super::abi::{get_arg_register_index, is_callee_saved_or_renamed, is_callee_saved_register};
use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind};
use super::naming::NamingContext;
use super::signature::{CallingConvention, FunctionSignature, SignatureRecovery};
use super::structurer::{StructuredCfg, StructuredNode};
use super::{RelocationTable, StringTable, SummaryDatabase, SymbolTable};
use crate::symbol_names::strip_demangled_signature as strip_demangled_symbol_signature;
use hexray_core::BasicBlockId;
use hexray_types::{
    get_argument_category, get_field_category, ConstantCategory, ConstantDatabase, TypeDatabase,
};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::Arc;

mod format;
mod predicates;
use format::{
    escape_string, format_as_char_literal, format_integer, is_likely_character_constant,
    is_printable_char_value, is_special_char_value, looks_like_char_context,
};
use predicates::{
    canonical_decl_var_name, collect_decl_identifiers_from_emitted_body, contains_identifier_token,
    exprs_equal, is_arm64_temp_register, is_arm64_temp_register_expr, is_assignable_unknown_name,
    is_declarable_variable, is_epilogue_statement, is_likely_global_identifier,
    is_loop_counter_like_name, is_prologue_statement, is_stack_canary_check_body,
    is_stack_canary_load, looks_like_parameter_name, normalize_variable_name, rename_register,
    try_extract_array_access, try_extract_rip_relative_offset,
};

/// Represents a case value or range for switch statement output.
enum CaseRange {
    /// A single case value.
    Single(i128),
    /// A range of consecutive values (inclusive).
    Range(i128, i128),
}

enum GlobalSymbolResolution {
    Exact(String),
    Interior { base_name: String, offset: u64 },
}

/// Collapses consecutive case values into ranges for cleaner output.
/// Uses GCC extension syntax `case 1 ... 5:` for ranges of 3+ consecutive values.
fn collapse_case_values(values: &[i128]) -> Vec<CaseRange> {
    if values.is_empty() {
        return Vec::new();
    }

    let mut sorted: Vec<i128> = values.to_vec();
    sorted.sort();
    sorted.dedup();

    let mut result = Vec::new();
    let mut range_start = sorted[0];
    let mut range_end = sorted[0];

    for &v in &sorted[1..] {
        if v == range_end + 1 {
            // Extend the range
            range_end = v;
        } else {
            // Emit previous range
            emit_range(&mut result, range_start, range_end);
            range_start = v;
            range_end = v;
        }
    }
    // Emit final range
    emit_range(&mut result, range_start, range_end);

    result
}

/// Helper to emit a range (as single values if small, as range if 3+ consecutive).
fn emit_range(result: &mut Vec<CaseRange>, start: i128, end: i128) {
    let count = (end - start + 1) as usize;
    if count >= 3 {
        // Emit as a range
        result.push(CaseRange::Range(start, end));
    } else {
        // Emit as individual values
        for v in start..=end {
            result.push(CaseRange::Single(v));
        }
    }
}

/// Information about a function's signature detected from analysis.
struct FunctionInfo {
    /// Detected parameter names (in order).
    parameters: Vec<String>,
    /// Whether the function has a return value.
    has_return_value: bool,
    /// Statements to skip (BasicBlockId, stmt_idx) - these are parameter/prologue/epilogue assignments.
    skip_statements: HashSet<(BasicBlockId, usize)>,
}

/// A conservative summary of an 8-byte stack slot that behaves like a packed aggregate.
#[derive(Debug, Clone, Default)]
struct PackedAggregateSlotPattern {
    /// Direct whole-slot save from an incoming register/argument source.
    param_source: Option<Expr>,
    /// Low 32-bit field store into the slot base.
    low_store: Option<Expr>,
    /// High 32-bit field store into the slot base + 4.
    high_store: Option<Expr>,
    /// Pattern is ambiguous or conflicts with non-aggregate writes.
    incompatible: bool,
}

/// Categorizes how a global address is used, enabling better fallback naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GlobalUsageHint {
    /// Used via pointer dereference (suggests ptr_ prefix)
    PointerDeref,
    /// Used in bitwise operations (suggests flags_ prefix)
    BitwiseOps,
    /// Used as a function pointer (suggests func_ prefix)
    FunctionPointer,
    /// Points to string data (suggests str_ prefix)
    StringPointer,
    /// Appears to be a counter (incremented/decremented frequently)
    Counter,
    /// Read-only global (never written to, suggests const_ prefix)
    ReadOnly,
    /// Write-heavy global (written more than read, suggests state_ prefix)
    WriteHeavy,
    /// Array base pointer (suggests arr_ prefix)
    ArrayBase,
    /// Likely stdin/stdout/stderr file pointer
    StdioStream,
    /// Default/unknown usage (uses data_ prefix)
    #[default]
    Unknown,
}

/// Size category for type-based naming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GlobalSizeHint {
    /// 1-byte (char/uint8_t)
    Byte,
    /// 2-byte (short/uint16_t)
    Word,
    /// 4-byte (int/uint32_t)
    DWord,
    /// 8-byte (long/uint64_t/pointer)
    QWord,
    /// Unknown or variable size
    Unknown,
}

impl GlobalSizeHint {
    /// Creates a size hint from byte size.
    pub fn from_size(size: u8) -> Self {
        match size {
            1 => Self::Byte,
            2 => Self::Word,
            4 => Self::DWord,
            8 => Self::QWord,
            _ => Self::Unknown,
        }
    }

    /// Returns a type prefix for the size.
    pub fn type_prefix(&self) -> &'static str {
        match self {
            Self::Byte => "b",
            Self::Word => "w",
            Self::DWord => "dw",
            Self::QWord => "qw",
            Self::Unknown => "",
        }
    }
}

/// Tracks access frequency and usage hints for global addresses.
#[derive(Debug, Clone, Default)]
pub struct GlobalAccessTracker {
    /// Maps global address to total access count.
    pub access_counts: std::collections::HashMap<u64, usize>,
    /// Maps global address to read count (rvalue usage).
    pub read_counts: std::collections::HashMap<u64, usize>,
    /// Maps global address to write count (lvalue usage).
    pub write_counts: std::collections::HashMap<u64, usize>,
    /// Maps global address to detected usage hint.
    pub usage_hints: std::collections::HashMap<u64, GlobalUsageHint>,
    /// Maps global address to observed access size (for type inference).
    pub size_hints: std::collections::HashMap<u64, GlobalSizeHint>,
    /// Tracks if a global has been incremented/decremented (counter detection).
    pub increment_counts: std::collections::HashMap<u64, usize>,
    /// Cache of resolved names for consistency within a single emission.
    resolved_names: std::collections::HashMap<u64, String>,
}

impl GlobalAccessTracker {
    /// Creates a new empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an access to a global address with optional usage hint.
    pub fn record_access(&mut self, address: u64, hint: GlobalUsageHint) {
        *self.access_counts.entry(address).or_insert(0) += 1;

        // Update usage hint if current is Unknown or matches
        self.usage_hints
            .entry(address)
            .and_modify(|h| {
                // Only upgrade from Unknown, don't override more specific hints
                if *h == GlobalUsageHint::Unknown && hint != GlobalUsageHint::Unknown {
                    *h = hint;
                }
            })
            .or_insert(hint);
    }

    /// Records a read access (global used as rvalue).
    pub fn record_read(&mut self, address: u64) {
        *self.read_counts.entry(address).or_insert(0) += 1;
    }

    /// Records a write access (global used as lvalue).
    pub fn record_write(&mut self, address: u64) {
        *self.write_counts.entry(address).or_insert(0) += 1;
    }

    /// Records an increment/decrement operation on a global.
    pub fn record_increment(&mut self, address: u64) {
        *self.increment_counts.entry(address).or_insert(0) += 1;
    }

    /// Records the access size for type inference.
    pub fn record_size(&mut self, address: u64, size: u8) {
        let hint = GlobalSizeHint::from_size(size);
        self.size_hints.entry(address).or_insert(hint);
    }

    /// Gets the access count for a global address.
    pub fn get_count(&self, address: u64) -> usize {
        self.access_counts.get(&address).copied().unwrap_or(0)
    }

    /// Gets read count for a global address.
    pub fn get_read_count(&self, address: u64) -> usize {
        self.read_counts.get(&address).copied().unwrap_or(0)
    }

    /// Gets write count for a global address.
    pub fn get_write_count(&self, address: u64) -> usize {
        self.write_counts.get(&address).copied().unwrap_or(0)
    }

    /// Gets the usage hint for a global address.
    pub fn get_hint(&self, address: u64) -> GlobalUsageHint {
        self.usage_hints
            .get(&address)
            .copied()
            .unwrap_or(GlobalUsageHint::Unknown)
    }

    /// Gets the size hint for a global address.
    pub fn get_size_hint(&self, address: u64) -> GlobalSizeHint {
        self.size_hints
            .get(&address)
            .copied()
            .unwrap_or(GlobalSizeHint::Unknown)
    }

    /// Determines if a global appears to be read-only (never written).
    pub fn is_read_only(&self, address: u64) -> bool {
        let writes = self.get_write_count(address);
        let reads = self.get_read_count(address);
        writes == 0 && reads > 0
    }

    /// Determines if a global is write-heavy (more writes than reads).
    pub fn is_write_heavy(&self, address: u64) -> bool {
        let writes = self.get_write_count(address);
        let reads = self.get_read_count(address);
        writes > reads && writes >= 2
    }

    /// Determines if a global appears to be a counter.
    pub fn is_counter(&self, address: u64) -> bool {
        self.increment_counts.get(&address).copied().unwrap_or(0) >= 1
    }

    /// Returns addresses sorted by access frequency (most accessed first).
    pub fn addresses_by_frequency(&self) -> Vec<(u64, usize)> {
        let mut addrs: Vec<_> = self.access_counts.iter().map(|(&a, &c)| (a, c)).collect();
        addrs.sort_by_key(|b| std::cmp::Reverse(b.1)); // Sort descending by count
        addrs
    }

    /// Groups globals by proximity (within 64 bytes of each other).
    /// Returns groups of (base_address, member_addresses).
    pub fn group_by_proximity(&self) -> Vec<(u64, Vec<u64>)> {
        let mut addresses: Vec<u64> = self.access_counts.keys().copied().collect();
        addresses.sort();

        if addresses.is_empty() {
            return Vec::new();
        }

        let mut groups: Vec<(u64, Vec<u64>)> = Vec::new();
        let mut current_group_base = addresses[0];
        let mut current_group = vec![addresses[0]];

        for &addr in &addresses[1..] {
            // If within 64 bytes of the last member, add to current group
            if let Some(&last) = current_group.last() {
                if addr.saturating_sub(last) <= 64 {
                    current_group.push(addr);
                    continue;
                }
            }
            // Start a new group
            if current_group.len() > 1 {
                groups.push((current_group_base, current_group));
            }
            current_group_base = addr;
            current_group = vec![addr];
        }

        // Don't forget the last group
        if current_group.len() > 1 {
            groups.push((current_group_base, current_group));
        }

        groups
    }

    /// Caches a resolved name for a global address.
    pub fn cache_name(&mut self, address: u64, name: String) {
        self.resolved_names.insert(address, name);
    }

    /// Gets a cached name if available.
    pub fn get_cached_name(&self, address: u64) -> Option<&str> {
        self.resolved_names.get(&address).map(|s| s.as_str())
    }

    /// Infers the best usage hint based on all collected data.
    pub fn infer_best_hint(&self, address: u64) -> GlobalUsageHint {
        // Check explicit hints first
        let explicit = self.get_hint(address);
        if explicit != GlobalUsageHint::Unknown {
            return explicit;
        }

        // Check for counter pattern
        if self.is_counter(address) {
            return GlobalUsageHint::Counter;
        }

        // Check for read-only pattern
        if self.is_read_only(address) {
            return GlobalUsageHint::ReadOnly;
        }

        // Check for write-heavy pattern
        if self.is_write_heavy(address) {
            return GlobalUsageHint::WriteHeavy;
        }

        GlobalUsageHint::Unknown
    }
}

/// Emits pseudo-code from structured control flow.
pub struct PseudoCodeEmitter {
    indent: String,
    emit_addresses: bool,
    string_table: Option<StringTable>,
    symbol_table: Option<SymbolTable>,
    relocation_table: Option<RelocationTable>,
    gnu_version_ambiguous_bases: RefCell<Option<HashSet<String>>>,
    tls_symbol_offsets: HashMap<i64, String>,
    /// Type information for variables (var_name -> type_string).
    type_info: std::collections::HashMap<String, String>,
    /// DWARF variable names (stack_offset -> name).
    dwarf_names: std::collections::HashMap<i128, String>,
    /// DWARF parameter names in declaration order.
    dwarf_param_names: Vec<String>,
    /// DWARF lexical-block ranges keyed by local variable name.
    dwarf_scope_ranges: std::collections::HashMap<String, (u64, u64)>,
    /// Naming context for pattern-based variable naming.
    /// Uses RefCell for interior mutability during emission.
    naming_ctx: RefCell<NamingContext>,
    /// Calling convention for signature recovery.
    calling_convention: CallingConvention,
    /// Whether to use advanced signature recovery.
    use_signature_recovery: bool,
    /// Type database for struct field access and function prototypes.
    type_database: Option<Arc<TypeDatabase>>,
    /// Constant database for magic number recognition.
    constant_database: Option<Arc<ConstantDatabase>>,
    /// Optional inter-procedural summary database for signature hints.
    summary_database: Option<Arc<SummaryDatabase>>,
    /// Tracks global access frequency and usage patterns.
    /// Uses RefCell for interior mutability during emission.
    global_tracker: RefCell<GlobalAccessTracker>,
    /// Per-function parameter display-name overrides (e.g., arg0 -> argc).
    /// Uses RefCell for interior mutability during emission.
    param_name_overrides: RefCell<HashMap<String, String>>,
    /// Fallback expression for bare returns when signature is non-void.
    /// Uses RefCell for interior mutability during emission.
    return_fallback_expr: RefCell<Option<String>>,
    /// Preserve raw machine register names while formatting selected expressions.
    preserve_register_names: Cell<bool>,
    /// Emit raw register names for low-level register snapshot helpers such as __sigsetjmp.
    register_snapshot_mode: Cell<bool>,
    /// Number of integer / floating-point argument-register *parameters* in the
    /// current function. An argument register beyond this count is a local
    /// temporary, not a parameter, so it must not be displayed as `argN`/`fargN`
    /// (which would look like a phantom parameter, e.g. `arr[arg2]`). Defaults to
    /// "no gating" until a signature is emitted.
    integer_arg_param_count: Cell<usize>,
    float_arg_param_count: Cell<usize>,
}

impl PseudoCodeEmitter {
    fn format_signature_param(p: &super::signature::Parameter, rendered_name: &str) -> String {
        // If callback typing confidence is low, keep emitted surface conservative.
        if p.type_confidence < 3
            && matches!(
                p.param_type,
                super::signature::ParamType::FunctionPointer { .. }
            )
        {
            format!("void* {}", rendered_name)
        } else {
            p.param_type.format_with_name(rendered_name)
        }
    }

    fn is_pointer_like_type_hint(type_hint: &str) -> bool {
        let ty = type_hint.trim();
        ty.contains("(*)") || ty.contains('*') || ty.ends_with("[]")
    }

    fn should_apply_signature_type_hint(
        param_type: &super::signature::ParamType,
        type_hint: &str,
    ) -> bool {
        if matches!(
            param_type,
            super::signature::ParamType::FunctionPointer { .. }
        ) {
            return false;
        }
        Self::is_pointer_like_type_hint(type_hint)
    }

    fn find_param_type_hint(
        &self,
        param_index: usize,
        source_name: &str,
        rendered_name: &str,
    ) -> Option<String> {
        let arg_fallback = format!("arg{}", param_index);
        let candidates = [source_name, rendered_name, arg_fallback.as_str()];
        for candidate in candidates {
            if let Some(ty) = self.lookup_type_info(candidate) {
                return Some(ty.to_string());
            }
        }
        None
    }

    fn lookup_type_info<'a>(&'a self, candidate: &str) -> Option<&'a str> {
        if let Some(ty) = self.type_info.get(candidate) {
            return Some(ty.as_str());
        }
        let candidate_lower = candidate.to_lowercase();
        if let Some(ty) = self.type_info.get(&candidate_lower) {
            return Some(ty.as_str());
        }
        for alias in self.argument_type_aliases(candidate) {
            if let Some(ty) = self.type_info.get(alias) {
                return Some(ty.as_str());
            }
        }
        None
    }

    fn dwarf_scope_comment(&self, candidate: &str) -> Option<String> {
        self.dwarf_scope_ranges
            .get(candidate)
            .map(|(start, end)| format!(" // DWARF scope [{start:#x}, {end:#x})"))
    }

    fn argument_type_aliases(&self, candidate: &str) -> Vec<&'static str> {
        let lower = candidate.to_lowercase();
        let (prefix, index) = if let Some(rest) = lower.strip_prefix("farg") {
            ("farg", rest.parse::<usize>().ok())
        } else if let Some(rest) = lower.strip_prefix("arg") {
            ("arg", rest.parse::<usize>().ok())
        } else {
            return Vec::new();
        };
        let Some(index) = index else {
            return Vec::new();
        };

        let mut aliases = Vec::new();
        if prefix == "arg" {
            if let Some(name) = self.calling_convention.integer_arg_registers().get(index) {
                aliases.push(*name);
            }
            if let Some(name) = self
                .calling_convention
                .integer_arg_registers_32()
                .get(index)
            {
                aliases.push(*name);
            }
        }
        if let Some(name) = self.calling_convention.float_arg_registers().get(index) {
            aliases.push(*name);
        }
        aliases
    }

    fn format_signature_param_with_type_hint(
        &self,
        p: &super::signature::Parameter,
        rendered_name: &str,
        type_hint: Option<&str>,
    ) -> String {
        if let Some(type_hint) = type_hint {
            if Self::should_apply_signature_type_hint(&p.param_type, type_hint) {
                return format!("{} {}", type_hint.trim(), rendered_name);
            }
        }
        Self::format_signature_param(p, rendered_name)
    }

    fn format_function_header(
        return_type: &super::signature::ParamType,
        func_name: &str,
        params: &[String],
        is_variadic: bool,
    ) -> String {
        let (func_name, trailing_qualifiers) =
            Self::split_embedded_signature(func_name).unwrap_or((func_name, ""));
        let params_str = if params.is_empty() {
            if is_variadic {
                "...".to_string()
            } else {
                "void".to_string()
            }
        } else {
            let joined = params.join(", ");
            if is_variadic {
                format!("{joined}, ...")
            } else {
                joined
            }
        };

        match return_type {
            super::signature::ParamType::FunctionPointer {
                return_type,
                params,
            } => {
                let callback_params = if params.is_empty() {
                    "void".to_string()
                } else {
                    params
                        .iter()
                        .map(super::signature::ParamType::to_c_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!(
                    "{} (*{}({}))({})",
                    return_type.to_c_string(),
                    func_name,
                    params_str,
                    callback_params
                )
            }
            _ => format!(
                "{} {}({}){}",
                return_type.to_c_string(),
                func_name,
                params_str,
                trailing_qualifiers
            ),
        }
    }

    fn split_embedded_signature(func_name: &str) -> Option<(&str, &str)> {
        let close_idx = func_name.rfind(')')?;
        let bytes = func_name.as_bytes();
        let mut depth = 0usize;
        let mut open_idx = None;

        for idx in (0..=close_idx).rev() {
            match bytes[idx] {
                b')' => depth += 1,
                b'(' => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        open_idx = Some(idx);
                        break;
                    }
                }
                _ => {}
            }
        }

        let open_idx = open_idx?;
        let suffix = &func_name[close_idx + 1..];
        if suffix.contains('(') || suffix.contains(')') {
            return None;
        }

        Some((func_name[..open_idx].trim_end(), suffix))
    }

    fn special_function_prelude_comment(func_name: &str) -> Option<&'static str> {
        let lower = func_name.to_ascii_lowercase();
        if lower.contains("coroutine_handle") && lower.contains("::resume") {
            return Some("/* resume coroutine via coroutine frame */");
        }
        None
    }

    /// Creates a new emitter.
    pub fn new(indent: &str, emit_addresses: bool) -> Self {
        Self {
            indent: indent.to_string(),
            emit_addresses,
            string_table: None,
            symbol_table: None,
            relocation_table: None,
            gnu_version_ambiguous_bases: RefCell::new(None),
            tls_symbol_offsets: HashMap::new(),
            type_info: std::collections::HashMap::new(),
            dwarf_names: std::collections::HashMap::new(),
            dwarf_param_names: Vec::new(),
            dwarf_scope_ranges: std::collections::HashMap::new(),
            naming_ctx: RefCell::new(NamingContext::new()),
            calling_convention: CallingConvention::default(),
            use_signature_recovery: true,
            type_database: None,
            constant_database: None,
            summary_database: None,
            global_tracker: RefCell::new(GlobalAccessTracker::new()),
            param_name_overrides: RefCell::new(HashMap::new()),
            integer_arg_param_count: Cell::new(usize::MAX),
            float_arg_param_count: Cell::new(usize::MAX),
            return_fallback_expr: RefCell::new(None),
            preserve_register_names: Cell::new(false),
            register_snapshot_mode: Cell::new(false),
        }
    }

    fn fallback_return_expr_for_type(return_type: &str) -> Option<String> {
        let ty = return_type.trim();
        if ty == "void" {
            None
        } else if ty.contains("float") || ty.contains("double") {
            Some("0.0".to_string())
        } else {
            Some("0".to_string())
        }
    }

    fn set_return_fallback_expr_for_type(&self, return_type: &str) {
        *self.return_fallback_expr.borrow_mut() = Self::fallback_return_expr_for_type(return_type);
    }

    fn clear_return_fallback_expr(&self) {
        *self.return_fallback_expr.borrow_mut() = None;
    }

    fn repair_packed_small_aggregate_output(output: String) -> String {
        fn is_simple_identifier(name: &str) -> bool {
            let mut chars = name.chars();
            let Some(first) = chars.next() else {
                return false;
            };
            (first == '_' || first.is_ascii_alphabetic())
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }

        fn looks_like_restore_temp(name: &str) -> bool {
            name == "ret"
                || name.starts_with("ret_")
                || name.starts_with("local_")
                || name.starts_with("var_")
        }

        fn line_mentions_identifier(line: &str, name: &str) -> bool {
            line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|token| token == name)
        }

        fn parse_simple_copy_assign(line: &str) -> Option<(String, String)> {
            let trimmed = line.trim().strip_suffix(';')?;
            let (lhs, rhs) = trimmed.split_once(" = ")?;
            let lhs = lhs.trim();
            let rhs = rhs.trim();
            if is_simple_identifier(lhs) && is_simple_identifier(rhs) {
                Some((lhs.to_string(), rhs.to_string()))
            } else {
                None
            }
        }

        fn parse_simple_shift_assign(line: &str) -> Option<(String, String)> {
            let trimmed = line.trim().strip_suffix(';')?;
            let (lhs, rhs) = trimmed.split_once(" <<= ")?;
            let lhs = lhs.trim();
            let rhs = rhs.trim();
            if is_simple_identifier(lhs) && rhs.chars().all(|c| c.is_ascii_digit()) {
                Some((lhs.to_string(), rhs.to_string()))
            } else {
                None
            }
        }

        fn parse_simple_decl(line: &str) -> Option<String> {
            let trimmed = line.trim().strip_suffix(';')?;
            if trimmed.contains('=') || trimmed.contains('(') || trimmed.contains(')') {
                return None;
            }
            let mut parts = trimmed.split_whitespace();
            let ty = parts.next()?;
            let name = parts.next()?;
            let starts_like_ident = name
                .chars()
                .next()
                .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic());
            if ty == "return"
                || parts.next().is_some()
                || !starts_like_ident
                || !is_simple_identifier(name)
            {
                return None;
            }
            Some(name.to_string())
        }

        fn parse_stack_guard_assign(line: &str) -> Option<String> {
            let trimmed = line.trim().strip_suffix(';')?;
            let (lhs, rhs) = trimmed.split_once(" = ")?;
            let lhs = lhs.trim();
            let rhs = rhs.trim();
            if rhs == "__stack_chk_guard" && is_simple_identifier(lhs) {
                Some(lhs.to_string())
            } else {
                None
            }
        }

        fn parse_simple_return_ident(line: &str) -> Option<String> {
            let trimmed = line.trim().strip_suffix(';')?;
            let ident = trimmed.strip_prefix("return ")?.trim();
            is_simple_identifier(ident).then(|| ident.to_string())
        }

        fn split_top_level_csv(input: &str) -> Option<Vec<String>> {
            let mut parts = Vec::new();
            let mut depth = 0i32;
            let mut start = 0usize;
            for (idx, ch) in input.char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    ',' if depth == 0 => {
                        parts.push(input[start..idx].trim().to_string());
                        start = idx + 1;
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return None;
            }
            parts.push(input[start..].trim().to_string());
            Some(parts)
        }

        fn parse_call_first_arg(line: &str) -> Option<String> {
            let trimmed = line.trim().strip_suffix(';')?;
            let open = trimmed.find('(')?;
            let close = trimmed.rfind(')')?;
            if close <= open {
                return None;
            }
            let args = split_top_level_csv(&trimmed[open + 1..close])?;
            let first = args.first()?.trim();
            is_simple_identifier(first).then(|| first.to_string())
        }

        fn parse_set_bits_call(line: &str) -> Option<(std::ops::Range<usize>, Vec<String>)> {
            let start = line.find("SET_BITS(")?;
            let args_start = start + "SET_BITS(".len();
            let mut depth = 1i32;
            let mut end = args_start;
            for (offset, ch) in line[args_start..].char_indices() {
                match ch {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            end = args_start + offset;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            if depth != 0 {
                return None;
            }
            let args = split_top_level_csv(&line[args_start..end])?;
            Some((start..end + 1, args))
        }

        let mut lines: Vec<String> = output.lines().map(str::to_string).collect();
        if lines.is_empty() {
            return output;
        }

        let has_local_4_decl = lines
            .iter()
            .any(|line| line.trim() == "int local_4;" || line.trim() == "uint32_t local_4;");

        if has_local_4_decl {
            for line in &mut lines {
                if !line.contains("printf(")
                    || !line.contains("local_4")
                    || line.contains("local_4 =")
                {
                    continue;
                }
                let Some(marker) = line.rfind(", local_4") else {
                    continue;
                };
                let prefix = &line[..marker];
                let Some(prev_comma) = prefix.rfind(',') else {
                    continue;
                };
                let source = prefix[prev_comma + 1..].trim();
                if source.is_empty() {
                    continue;
                }
                *line = line.replacen("local_4", &format!("BITS({}, 32, 32)", source), 1);
            }
        }

        let mut shifted_bitfield_sources: HashMap<String, (String, String)> = HashMap::new();
        for window in lines.windows(2) {
            let Some((temp_name, source_name)) = parse_simple_copy_assign(&window[0]) else {
                continue;
            };
            let Some((shifted_name, shift_amount)) = parse_simple_shift_assign(&window[1]) else {
                continue;
            };
            if temp_name == shifted_name {
                shifted_bitfield_sources.insert(temp_name, (source_name, shift_amount));
            }
        }

        for line in &mut lines {
            let Some((call_range, args)) = parse_set_bits_call(line) else {
                continue;
            };
            if args.len() < 4 {
                continue;
            }
            let value_arg = args[1].trim();
            let start_arg = args[2].trim();
            let Some((source_name, shift_amount)) = shifted_bitfield_sources.get(value_arg) else {
                continue;
            };
            if start_arg != shift_amount {
                continue;
            }
            let mut rewritten_args = args;
            rewritten_args[1] = source_name.clone();
            let replacement = format!("SET_BITS({})", rewritten_args.join(", "));
            line.replace_range(call_range, &replacement);
        }

        let mut idx = 0usize;
        while idx + 1 < lines.len() {
            let trimmed = lines[idx].trim();
            let Some((lhs, rhs)) = trimmed
                .strip_suffix(';')
                .and_then(|line| line.split_once(" = "))
                .map(|(lhs, rhs)| (lhs.trim(), rhs.trim()))
            else {
                idx += 1;
                continue;
            };
            if !is_simple_identifier(lhs) || !rhs.starts_with("SET_BITS(") {
                idx += 1;
                continue;
            }
            let next_trimmed = lines[idx + 1].trim();
            let Some(next_rhs) = next_trimmed
                .strip_suffix(';')
                .and_then(|line| line.split_once(" = "))
                .map(|(_, rhs)| rhs.trim())
            else {
                idx += 1;
                continue;
            };
            if rhs == next_rhs {
                lines.remove(idx);
                continue;
            }
            idx += 1;
        }

        if let Some((guard_assign_idx, guard_local)) = lines
            .iter()
            .enumerate()
            .find_map(|(idx, line)| parse_stack_guard_assign(line).map(|name| (idx, name)))
        {
            if let Some(return_idx) = lines.iter().rposition(|line| {
                parse_simple_return_ident(line).as_deref() == Some(guard_local.as_str())
            }) {
                if let Some(replacement) = lines[..return_idx]
                    .iter()
                    .rev()
                    .find_map(|line| parse_call_first_arg(line))
                {
                    let indent = lines[return_idx]
                        .chars()
                        .take_while(|c| c.is_whitespace())
                        .collect::<String>();
                    lines[return_idx] = format!("{indent}return {replacement};");

                    let guard_local_used_elsewhere = lines.iter().enumerate().any(|(idx, line)| {
                        idx != guard_assign_idx
                            && idx != return_idx
                            && line_mentions_identifier(line, &guard_local)
                    });
                    if !guard_local_used_elsewhere {
                        if let Some(decl_idx) = lines.iter().position(|line| {
                            parse_simple_decl(line).as_deref() == Some(guard_local.as_str())
                        }) {
                            lines.remove(decl_idx);
                            let adjusted_assign_idx = if decl_idx < guard_assign_idx {
                                guard_assign_idx.saturating_sub(1)
                            } else {
                                guard_assign_idx
                            };
                            lines.remove(adjusted_assign_idx);
                        } else {
                            lines.remove(guard_assign_idx);
                        }
                    }
                }
            }
        }

        let is_int64_return = lines
            .iter()
            .find(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with("//")
            })
            .is_some_and(|line| line.trim_start().starts_with("int64_t "));

        if is_int64_return {
            if let Some(return_idx) = lines.iter().position(|line| {
                let trimmed = line.trim();
                trimmed.starts_with("return ")
                    && trimmed.ends_with(';')
                    && !trimmed.contains("<< 32")
                    && !trimmed.contains("local_4")
            }) {
                let trimmed = lines[return_idx].trim();
                let return_var = trimmed
                    .strip_prefix("return ")
                    .and_then(|s| s.strip_suffix(';'))
                    .map(str::trim)
                    .filter(|name| is_simple_identifier(name));
                if let Some(name) = return_var {
                    let has_local4_assign = lines.iter().any(|line| line.contains("local_4 ="));
                    let has_return_var_assign = lines
                        .iter()
                        .any(|line| line.trim_start().starts_with(&format!("{} = ", name)));
                    if has_local4_assign && has_return_var_assign {
                        let indent = lines[return_idx]
                            .chars()
                            .take_while(|c| c.is_whitespace())
                            .collect::<String>();
                        lines[return_idx] =
                            format!("{}return {{ .lo = {}, .hi = local_4 }};", indent, name);
                    }
                }
            }

            if let Some((shift_idx, shifted_name)) =
                lines.iter().enumerate().find_map(|(idx, line)| {
                    let trimmed = line.trim();
                    let name = trimmed.strip_suffix("<<= 32;")?.trim_end();
                    if name.is_empty()
                        || !name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c.is_whitespace())
                    {
                        return None;
                    }
                    let name = name.trim_end();
                    if let Some((candidate, _)) = name.rsplit_once(' ') {
                        let last = name.split_whitespace().last().unwrap_or(name);
                        if !candidate.is_empty() && !last.is_empty() {
                            return Some((idx, last.to_string()));
                        }
                    }
                    Some((idx, name.to_string()))
                })
            {
                let redundant_suffix = format!(" | {} << 32;", shifted_name);
                for line in &mut lines {
                    let trimmed = line.trim();
                    if !trimmed.starts_with("return ") || !trimmed.ends_with(&redundant_suffix) {
                        continue;
                    }
                    let lhs =
                        trimmed["return ".len()..trimmed.len() - redundant_suffix.len()].trim();
                    if lhs.is_empty() {
                        continue;
                    }
                    let indent = line
                        .chars()
                        .take_while(|c| c.is_whitespace())
                        .collect::<String>();
                    *line = format!("{}return {} | {};", indent, lhs, shifted_name);
                }

                if let Some(return_idx) = lines.iter().position(|line| {
                    let trimmed = line.trim();
                    if !trimmed.starts_with("return ") || !trimmed.ends_with(';') {
                        return false;
                    }
                    let Some(expr) = trimmed
                        .strip_prefix("return ")
                        .and_then(|s| s.strip_suffix(';'))
                        .map(str::trim)
                    else {
                        return false;
                    };
                    let Some((lhs, rhs)) = expr.split_once('|') else {
                        return false;
                    };
                    let lhs = lhs.trim();
                    let rhs = rhs.trim();
                    (lhs == shifted_name && is_simple_identifier(rhs))
                        || (rhs == shifted_name && is_simple_identifier(lhs))
                }) {
                    let extra_statement_uses = lines
                        .iter()
                        .enumerate()
                        .filter(|(idx, line)| {
                            *idx != shift_idx
                                && *idx != return_idx
                                && line.trim().ends_with(';')
                                && line_mentions_identifier(line, &shifted_name)
                        })
                        .count();
                    if extra_statement_uses == 0 {
                        let trimmed = lines[return_idx].trim();
                        let expr = trimmed["return ".len()..trimmed.len() - 1].trim();
                        let (lhs, rhs) = expr.split_once('|').unwrap();
                        let (low, high) = if lhs.trim() == shifted_name {
                            (rhs.trim(), lhs.trim())
                        } else {
                            (lhs.trim(), rhs.trim())
                        };
                        let indent = lines[return_idx]
                            .chars()
                            .take_while(|c| c.is_whitespace())
                            .collect::<String>();
                        lines[return_idx] =
                            format!("{}return {{ .lo = {}, .hi = {} }};", indent, low, high);
                        lines.remove(shift_idx);
                    }
                }
            }
        }

        if has_local_4_decl
            && !lines
                .iter()
                .any(|line| line.contains("local_4") && !line.contains("int local_4;"))
        {
            lines
                .retain(|line| line.trim() != "int local_4;" && line.trim() != "uint32_t local_4;");
        }

        loop {
            let mut changed = false;
            for idx in 0..lines.len() {
                let Some((lhs, _rhs)) = parse_simple_copy_assign(&lines[idx]) else {
                    continue;
                };
                if !looks_like_restore_temp(&lhs) {
                    continue;
                }
                if lines[idx + 1..]
                    .iter()
                    .all(|line| !line_mentions_identifier(line, &lhs))
                {
                    lines.remove(idx);
                    changed = true;
                    break;
                }
            }
            if !changed {
                break;
            }
        }

        loop {
            let mut changed = false;
            for idx in 0..lines.len() {
                let Some(name) = parse_simple_decl(&lines[idx]) else {
                    continue;
                };
                if !looks_like_restore_temp(&name) {
                    continue;
                }
                if lines.iter().enumerate().all(|(other_idx, line)| {
                    other_idx == idx || !line_mentions_identifier(line, &name)
                }) {
                    lines.remove(idx);
                    changed = true;
                    break;
                }
            }
            if !changed {
                break;
            }
        }

        lines.join("\n")
    }

    fn rewrite_tail_call_returns_for_emission(
        nodes: &[StructuredNode],
        in_tail_return_path: bool,
    ) -> Vec<StructuredNode> {
        let mut rewritten = Vec::with_capacity(nodes.len());
        for (idx, node) in nodes.iter().cloned().enumerate() {
            let node_in_tail_return_path =
                in_tail_return_path && Self::suffix_is_tail_return_path(&nodes[idx + 1..]);
            rewritten.push(Self::rewrite_tail_call_return_node(
                node,
                node_in_tail_return_path,
            ));
        }

        Self::fold_terminal_tail_call_return(&mut rewritten, in_tail_return_path);
        rewritten
    }

    fn is_destructor_call_target(&self, target: &CallTarget) -> bool {
        match target {
            CallTarget::Named(name) => name.contains("::~"),
            CallTarget::Direct { target, .. } => self
                .symbol_table
                .as_ref()
                .and_then(|table| table.get(*target))
                .is_some_and(|name| name.contains("::~")),
            CallTarget::Indirect(_) | CallTarget::IndirectGot { .. } => false,
        }
    }

    fn expr_simple_name(expr: &Expr) -> Option<&str> {
        match &expr.kind {
            ExprKind::Var(var) => Some(&var.name),
            ExprKind::Unknown(name) => Some(name.as_str()),
            ExprKind::Cast { expr, .. } => Self::expr_simple_name(expr),
            _ => None,
        }
    }

    fn collect_expr_name_uses(expr: &Expr, counts: &mut HashMap<String, usize>) {
        match &expr.kind {
            ExprKind::Var(var) => {
                *counts.entry(var.name.clone()).or_default() += 1;
            }
            ExprKind::Unknown(name) => {
                *counts.entry(name.clone()).or_default() += 1;
            }
            ExprKind::BinOp { left, right, .. }
            | ExprKind::Assign {
                lhs: left,
                rhs: right,
            }
            | ExprKind::CompoundAssign {
                lhs: left,
                rhs: right,
                ..
            } => {
                Self::collect_expr_name_uses(left, counts);
                Self::collect_expr_name_uses(right, counts);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                Self::collect_expr_name_uses(operand, counts);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                Self::collect_expr_name_uses(base, counts);
                Self::collect_expr_name_uses(index, counts);
            }
            ExprKind::FieldAccess { base, .. } => Self::collect_expr_name_uses(base, counts),
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Indirect(expr) => Self::collect_expr_name_uses(expr, counts),
                    CallTarget::IndirectGot { expr, .. } => {
                        Self::collect_expr_name_uses(expr, counts)
                    }
                    CallTarget::Named(_) | CallTarget::Direct { .. } => {}
                }
                for arg in args {
                    Self::collect_expr_name_uses(arg, counts);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::collect_expr_name_uses(cond, counts);
                Self::collect_expr_name_uses(then_expr, counts);
                Self::collect_expr_name_uses(else_expr, counts);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    Self::collect_expr_name_uses(value, counts);
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                Self::collect_expr_name_uses(display_expr, counts);
            }
            ExprKind::IntLit(_) => {}
        }
    }

    fn prune_param_restore_statements(
        statements: &[Expr],
        param_names: &HashSet<String>,
    ) -> Vec<Expr> {
        let mut param_assign_counts: HashMap<String, usize> = HashMap::new();
        let mut name_uses: HashMap<String, usize> = HashMap::new();
        let mut assign_index_by_name: HashMap<String, usize> = HashMap::new();

        for (idx, stmt) in statements.iter().enumerate() {
            if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                if let Some(lhs_name) = Self::expr_simple_name(lhs) {
                    assign_index_by_name.insert(lhs_name.to_string(), idx);
                    if param_names.contains(lhs_name) {
                        *param_assign_counts.entry(lhs_name.to_string()).or_default() += 1;
                    }
                }
                Self::collect_expr_name_uses(rhs, &mut name_uses);
            } else {
                Self::collect_expr_name_uses(stmt, &mut name_uses);
            }
        }

        let mut remove = HashSet::new();
        for (idx, stmt) in statements.iter().enumerate() {
            let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
                continue;
            };
            let Some(lhs_name) = Self::expr_simple_name(lhs) else {
                continue;
            };
            if !param_names.contains(lhs_name) {
                continue;
            }
            if param_assign_counts
                .get(lhs_name)
                .copied()
                .unwrap_or_default()
                != 1
            {
                continue;
            }
            let Some(mut current_name) = Self::expr_simple_name(rhs).map(str::to_string) else {
                continue;
            };

            remove.insert(idx);
            let mut seen_names = HashSet::new();

            loop {
                if !seen_names.insert(current_name.clone()) {
                    break;
                }
                if name_uses.get(&current_name).copied().unwrap_or_default() != 1 {
                    break;
                }
                let Some(prev_idx) = assign_index_by_name.get(&current_name).copied() else {
                    break;
                };
                let ExprKind::Assign {
                    lhs: prev_lhs,
                    rhs: prev_rhs,
                } = &statements[prev_idx].kind
                else {
                    break;
                };
                let Some(prev_lhs_name) = Self::expr_simple_name(prev_lhs) else {
                    break;
                };
                if prev_lhs_name != current_name {
                    break;
                }
                let Some(next_name) = Self::expr_simple_name(prev_rhs).map(str::to_string) else {
                    break;
                };
                remove.insert(prev_idx);
                current_name = next_name;
            }
        }

        let mut filtered: Vec<Expr> = statements
            .iter()
            .enumerate()
            .filter(|(idx, _)| !remove.contains(idx))
            .map(|(_, stmt)| stmt.clone())
            .collect();

        if remove.is_empty() {
            return filtered;
        }

        loop {
            let mut current_uses: HashMap<String, usize> = HashMap::new();
            for stmt in &filtered {
                if let ExprKind::Assign { rhs, .. } = &stmt.kind {
                    Self::collect_expr_name_uses(rhs, &mut current_uses);
                } else {
                    Self::collect_expr_name_uses(stmt, &mut current_uses);
                }
            }

            let prior_len = filtered.len();
            let next: Vec<Expr> = filtered
                .into_iter()
                .filter(|stmt| {
                    let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
                        return true;
                    };
                    let Some(lhs_name) = Self::expr_simple_name(lhs) else {
                        return true;
                    };
                    if param_names.contains(lhs_name) {
                        return true;
                    }
                    Self::expr_simple_name(rhs).is_none()
                        || current_uses.get(lhs_name).copied().unwrap_or_default() != 0
                })
                .collect();

            if next.len() == prior_len {
                return next;
            }
            filtered = next;
        }
    }

    fn prune_param_restore_nodes(
        nodes: &[StructuredNode],
        param_names: &HashSet<String>,
    ) -> Vec<StructuredNode> {
        let mut param_assign_counts: HashMap<String, usize> = HashMap::new();
        let mut name_uses: HashMap<String, usize> = HashMap::new();
        let mut assign_index_by_name: HashMap<String, usize> = HashMap::new();

        for (idx, node) in nodes.iter().enumerate() {
            match node {
                StructuredNode::Expr(expr) => {
                    if let ExprKind::Assign { lhs, rhs } = &expr.kind {
                        if let Some(lhs_name) = Self::expr_simple_name(lhs) {
                            assign_index_by_name.insert(lhs_name.to_string(), idx);
                            if param_names.contains(lhs_name) {
                                *param_assign_counts.entry(lhs_name.to_string()).or_default() += 1;
                            }
                        }
                        Self::collect_expr_name_uses(rhs, &mut name_uses);
                    } else {
                        Self::collect_expr_name_uses(expr, &mut name_uses);
                    }
                }
                StructuredNode::Return(Some(expr)) => {
                    Self::collect_expr_name_uses(expr, &mut name_uses);
                }
                _ => {}
            }
        }

        let mut remove = HashSet::new();
        for (idx, node) in nodes.iter().enumerate() {
            let StructuredNode::Expr(expr) = node else {
                continue;
            };
            let ExprKind::Assign { lhs, rhs } = &expr.kind else {
                continue;
            };
            let Some(lhs_name) = Self::expr_simple_name(lhs) else {
                continue;
            };
            if !param_names.contains(lhs_name) {
                continue;
            }
            if param_assign_counts
                .get(lhs_name)
                .copied()
                .unwrap_or_default()
                != 1
            {
                continue;
            }
            let Some(mut current_name) = Self::expr_simple_name(rhs).map(str::to_string) else {
                continue;
            };

            remove.insert(idx);
            let mut seen_names = HashSet::new();

            loop {
                if !seen_names.insert(current_name.clone()) {
                    break;
                }
                if name_uses.get(&current_name).copied().unwrap_or_default() != 1 {
                    break;
                }
                let Some(prev_idx) = assign_index_by_name.get(&current_name).copied() else {
                    break;
                };
                let StructuredNode::Expr(prev_expr) = &nodes[prev_idx] else {
                    break;
                };
                let ExprKind::Assign {
                    lhs: prev_lhs,
                    rhs: prev_rhs,
                } = &prev_expr.kind
                else {
                    break;
                };
                let Some(prev_lhs_name) = Self::expr_simple_name(prev_lhs) else {
                    break;
                };
                if prev_lhs_name != current_name {
                    break;
                }
                let Some(next_name) = Self::expr_simple_name(prev_rhs).map(str::to_string) else {
                    break;
                };
                remove.insert(prev_idx);
                current_name = next_name;
            }
        }

        let mut filtered: Vec<StructuredNode> = nodes
            .iter()
            .enumerate()
            .filter(|(idx, _)| !remove.contains(idx))
            .map(|(_, node)| node.clone())
            .collect();

        if remove.is_empty() {
            return filtered;
        }

        loop {
            let mut current_uses: HashMap<String, usize> = HashMap::new();
            for node in &filtered {
                match node {
                    StructuredNode::Expr(expr) => {
                        if let ExprKind::Assign { rhs, .. } = &expr.kind {
                            Self::collect_expr_name_uses(rhs, &mut current_uses);
                        } else {
                            Self::collect_expr_name_uses(expr, &mut current_uses);
                        }
                    }
                    StructuredNode::Return(Some(expr)) => {
                        Self::collect_expr_name_uses(expr, &mut current_uses);
                    }
                    _ => {}
                }
            }

            let prior_len = filtered.len();
            let next: Vec<StructuredNode> = filtered
                .into_iter()
                .filter(|node| match node {
                    StructuredNode::Expr(expr) => {
                        let ExprKind::Assign { lhs, rhs } = &expr.kind else {
                            return true;
                        };
                        let Some(lhs_name) = Self::expr_simple_name(lhs) else {
                            return true;
                        };
                        if param_names.contains(lhs_name) {
                            return true;
                        }
                        Self::expr_simple_name(rhs).is_none()
                            || current_uses.get(lhs_name).copied().unwrap_or_default() != 0
                    }
                    _ => true,
                })
                .collect();

            if next.len() == prior_len {
                return next;
            }
            filtered = next;
        }
    }

    fn rewrite_param_restore_artifacts_for_emission(
        nodes: &[StructuredNode],
        signature: &FunctionSignature,
    ) -> Vec<StructuredNode> {
        let mut param_names: HashSet<String> = HashSet::new();
        for (idx, param) in signature.parameters.iter().enumerate() {
            param_names.insert(param.name.clone());
            param_names.insert(format!("arg{}", idx));
            match &param.location {
                super::signature::ParameterLocation::IntegerRegister { name, .. } => {
                    param_names.insert(name.clone());
                }
                super::signature::ParameterLocation::FloatRegister { name, index } => {
                    param_names.insert(name.clone());
                    param_names.insert(format!("farg{}", index));
                }
                super::signature::ParameterLocation::Stack { .. } => {}
            }
        }

        fn rewrite_list(
            nodes: &[StructuredNode],
            param_names: &HashSet<String>,
        ) -> Vec<StructuredNode> {
            let rewritten: Vec<_> = nodes
                .iter()
                .map(|node| match node {
                    StructuredNode::Block {
                        id,
                        statements,
                        address_range,
                    } => StructuredNode::Block {
                        id: *id,
                        statements: PseudoCodeEmitter::prune_param_restore_statements(
                            statements,
                            param_names,
                        ),
                        address_range: *address_range,
                    },
                    StructuredNode::If {
                        condition,
                        then_body,
                        else_body,
                    } => StructuredNode::If {
                        condition: condition.clone(),
                        then_body: rewrite_list(then_body, param_names),
                        else_body: else_body
                            .as_ref()
                            .map(|nodes| rewrite_list(nodes, param_names)),
                    },
                    StructuredNode::While {
                        condition,
                        body,
                        header,
                        exit_block,
                    } => StructuredNode::While {
                        condition: condition.clone(),
                        body: rewrite_list(body, param_names),
                        header: *header,
                        exit_block: *exit_block,
                    },
                    StructuredNode::DoWhile {
                        body,
                        condition,
                        header,
                        exit_block,
                    } => StructuredNode::DoWhile {
                        body: rewrite_list(body, param_names),
                        condition: condition.clone(),
                        header: *header,
                        exit_block: *exit_block,
                    },
                    StructuredNode::For {
                        init,
                        condition,
                        update,
                        body,
                        header,
                        exit_block,
                    } => StructuredNode::For {
                        init: init.clone(),
                        condition: condition.clone(),
                        update: update.clone(),
                        body: rewrite_list(body, param_names),
                        header: *header,
                        exit_block: *exit_block,
                    },
                    StructuredNode::Loop {
                        body,
                        header,
                        exit_block,
                    } => StructuredNode::Loop {
                        body: rewrite_list(body, param_names),
                        header: *header,
                        exit_block: *exit_block,
                    },
                    StructuredNode::Switch {
                        value,
                        cases,
                        default,
                    } => StructuredNode::Switch {
                        value: value.clone(),
                        cases: cases
                            .iter()
                            .map(|(vals, body)| (vals.clone(), rewrite_list(body, param_names)))
                            .collect(),
                        default: default
                            .as_ref()
                            .map(|nodes| rewrite_list(nodes, param_names)),
                    },
                    StructuredNode::Sequence(nodes) => {
                        StructuredNode::Sequence(rewrite_list(nodes, param_names))
                    }
                    StructuredNode::TryCatch {
                        try_body,
                        catch_handlers,
                    } => StructuredNode::TryCatch {
                        try_body: rewrite_list(try_body, param_names),
                        catch_handlers: catch_handlers
                            .iter()
                            .map(|handler| super::structurer::CatchHandler {
                                exception_type: handler.exception_type.clone(),
                                variable_name: handler.variable_name.clone(),
                                body: rewrite_list(&handler.body, param_names),
                                landing_pad: handler.landing_pad,
                            })
                            .collect(),
                    },
                    other => other.clone(),
                })
                .collect();

            PseudoCodeEmitter::prune_param_restore_nodes(&rewritten, param_names)
        }

        rewrite_list(nodes, &param_names)
    }

    fn rewrite_destructor_cleanup_returns_for_emission(
        &self,
        nodes: &[StructuredNode],
    ) -> Vec<StructuredNode> {
        let mut rewritten = Vec::with_capacity(nodes.len());
        let mut idx = 0usize;

        while idx < nodes.len() {
            if idx + 1 < nodes.len() {
                if let (
                    StructuredNode::Block {
                        id,
                        statements,
                        address_range,
                    },
                    StructuredNode::Return(Some(ret_expr)),
                ) = (&nodes[idx], &nodes[idx + 1])
                {
                    if let Some(ret_name) = Self::expr_simple_name(ret_expr) {
                        if let Some((cleanup_idx, saved_return_expr)) =
                            self.find_destructor_cleanup_return_rewrite(statements, ret_name)
                        {
                            let mut new_statements = statements.clone();
                            let cleanup_call = match &new_statements[cleanup_idx].kind {
                                ExprKind::Assign { rhs, .. } => rhs.as_ref().clone(),
                                _ => unreachable!(),
                            };
                            new_statements[cleanup_idx] = cleanup_call;
                            rewritten.push(StructuredNode::Block {
                                id: *id,
                                statements: new_statements,
                                address_range: *address_range,
                            });
                            rewritten.push(StructuredNode::Return(Some(saved_return_expr)));
                            idx += 2;
                            continue;
                        }
                    }
                }
            }

            let node = match &nodes[idx] {
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => StructuredNode::If {
                    condition: condition.clone(),
                    then_body: self.rewrite_destructor_cleanup_returns_for_emission(then_body),
                    else_body: else_body
                        .as_ref()
                        .map(|body| self.rewrite_destructor_cleanup_returns_for_emission(body)),
                },
                StructuredNode::While {
                    condition,
                    body,
                    header,
                    exit_block,
                } => StructuredNode::While {
                    condition: condition.clone(),
                    body: self.rewrite_destructor_cleanup_returns_for_emission(body),
                    header: *header,
                    exit_block: *exit_block,
                },
                StructuredNode::DoWhile {
                    body,
                    condition,
                    header,
                    exit_block,
                } => StructuredNode::DoWhile {
                    body: self.rewrite_destructor_cleanup_returns_for_emission(body),
                    condition: condition.clone(),
                    header: *header,
                    exit_block: *exit_block,
                },
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    header,
                    exit_block,
                } => StructuredNode::For {
                    init: init.clone(),
                    condition: condition.clone(),
                    update: update.clone(),
                    body: self.rewrite_destructor_cleanup_returns_for_emission(body),
                    header: *header,
                    exit_block: *exit_block,
                },
                StructuredNode::Loop {
                    body,
                    header,
                    exit_block,
                } => StructuredNode::Loop {
                    body: self.rewrite_destructor_cleanup_returns_for_emission(body),
                    header: *header,
                    exit_block: *exit_block,
                },
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => StructuredNode::Switch {
                    value: value.clone(),
                    cases: cases
                        .iter()
                        .map(|(values, body)| {
                            (
                                values.clone(),
                                self.rewrite_destructor_cleanup_returns_for_emission(body),
                            )
                        })
                        .collect(),
                    default: default
                        .as_ref()
                        .map(|body| self.rewrite_destructor_cleanup_returns_for_emission(body)),
                },
                StructuredNode::Sequence(inner) => StructuredNode::Sequence(
                    self.rewrite_destructor_cleanup_returns_for_emission(inner),
                ),
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => StructuredNode::TryCatch {
                    try_body: self.rewrite_destructor_cleanup_returns_for_emission(try_body),
                    catch_handlers: catch_handlers
                        .iter()
                        .map(|handler| super::structurer::CatchHandler {
                            exception_type: handler.exception_type.clone(),
                            variable_name: handler.variable_name.clone(),
                            body: self
                                .rewrite_destructor_cleanup_returns_for_emission(&handler.body),
                            landing_pad: handler.landing_pad,
                        })
                        .collect(),
                },
                other => other.clone(),
            };
            rewritten.push(node);
            idx += 1;
        }

        rewritten
    }

    fn find_destructor_cleanup_return_rewrite(
        &self,
        statements: &[Expr],
        cleanup_name: &str,
    ) -> Option<(usize, Expr)> {
        let mut cleanup_idx = None;
        let mut explicit_saved_return = None;

        for (idx, stmt) in statements.iter().enumerate().rev() {
            if let Some(saved) = Self::extract_saved_return_restore(stmt) {
                explicit_saved_return = Some(saved);
                continue;
            }

            if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                if Self::expr_simple_name(lhs).is_some_and(|name| name == cleanup_name) {
                    let ExprKind::Call { target, .. } = &rhs.kind else {
                        return None;
                    };
                    if self.is_destructor_call_target(target) {
                        cleanup_idx = Some(idx);
                        break;
                    }
                }
            }

            if self.is_cleanup_tail_noise_statement(stmt) {
                continue;
            }

            return None;
        }

        let cleanup_idx = cleanup_idx?;
        if let Some(saved) = explicit_saved_return {
            return Some((cleanup_idx, saved));
        }

        for stmt in statements[..cleanup_idx].iter().rev() {
            let ExprKind::Assign {
                lhs: saved_lhs,
                rhs: saved_rhs,
            } = &stmt.kind
            else {
                continue;
            };
            let ExprKind::Call { target, .. } = &saved_rhs.kind else {
                continue;
            };
            if self.is_destructor_call_target(target) {
                continue;
            }
            return Some((cleanup_idx, saved_lhs.as_ref().clone()));
        }

        None
    }

    fn extract_saved_return_restore(stmt: &Expr) -> Option<Expr> {
        let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
            return None;
        };
        let ExprKind::Var(var) = &lhs.kind else {
            return None;
        };
        if matches!(var.name.as_str(), "eax" | "rax" | "ret") {
            return Some(rhs.as_ref().clone());
        }
        None
    }

    fn is_cleanup_tail_noise_statement(&self, stmt: &Expr) -> bool {
        is_epilogue_statement(stmt)
            || is_stack_canary_load(stmt)
            || Self::expr_mentions_stack_canary_guard(stmt)
            || matches!(&stmt.kind, ExprKind::Unknown(name) if name.trim() == "/* nop */")
    }

    fn expr_mentions_stack_canary_guard(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => var.name.contains("stack_chk_guard"),
            ExprKind::Unknown(name) => name.contains("stack_chk_guard"),
            ExprKind::BinOp { left, right, .. }
            | ExprKind::Assign {
                lhs: left,
                rhs: right,
            }
            | ExprKind::CompoundAssign {
                lhs: left,
                rhs: right,
                ..
            } => {
                Self::expr_mentions_stack_canary_guard(left)
                    || Self::expr_mentions_stack_canary_guard(right)
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                Self::expr_mentions_stack_canary_guard(operand)
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                Self::expr_mentions_stack_canary_guard(base)
                    || Self::expr_mentions_stack_canary_guard(index)
            }
            ExprKind::FieldAccess { base, .. } => Self::expr_mentions_stack_canary_guard(base),
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => {
                args.iter().any(Self::expr_mentions_stack_canary_guard)
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::expr_mentions_stack_canary_guard(cond)
                    || Self::expr_mentions_stack_canary_guard(then_expr)
                    || Self::expr_mentions_stack_canary_guard(else_expr)
            }
            ExprKind::GotRef { display_expr, .. } => {
                Self::expr_mentions_stack_canary_guard(display_expr)
            }
            ExprKind::IntLit(_) => false,
        }
    }

    fn is_guarded_stack_canary_branch(&self, condition: &Expr, body: &[StructuredNode]) -> bool {
        Self::expr_mentions_stack_canary_guard(condition)
            && is_stack_canary_check_body(body, self.symbol_table.as_ref())
    }

    fn rewrite_small_aggregate_slots_for_emission(
        &self,
        nodes: &[StructuredNode],
    ) -> Vec<StructuredNode> {
        let mut patterns = HashMap::new();
        self.collect_packed_aggregate_slot_patterns(nodes, &mut patterns);
        if patterns.is_empty() {
            return nodes.to_vec();
        }

        nodes
            .iter()
            .cloned()
            .map(|node| self.rewrite_small_aggregate_slot_node(node, &patterns))
            .collect()
    }

    fn rewrite_small_aggregate_slot_node(
        &self,
        node: StructuredNode,
        patterns: &HashMap<i128, PackedAggregateSlotPattern>,
    ) -> StructuredNode {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => StructuredNode::Block {
                id,
                statements: statements
                    .into_iter()
                    .map(|stmt| self.rewrite_small_aggregate_slot_expr(stmt, patterns, true))
                    .collect(),
                address_range,
            },
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition: self.rewrite_small_aggregate_slot_expr(condition, patterns, true),
                then_body: then_body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                else_body: else_body.map(|nodes| {
                    nodes
                        .into_iter()
                        .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                        .collect()
                }),
            },
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition: self.rewrite_small_aggregate_slot_expr(condition, patterns, true),
                body: body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                header,
                exit_block,
            },
            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                condition: self.rewrite_small_aggregate_slot_expr(condition, patterns, true),
                header,
                exit_block,
            },
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => StructuredNode::For {
                init: init.map(|expr| self.rewrite_small_aggregate_slot_expr(expr, patterns, true)),
                condition: self.rewrite_small_aggregate_slot_expr(condition, patterns, true),
                update: update
                    .map(|expr| self.rewrite_small_aggregate_slot_expr(expr, patterns, true)),
                body: body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                header,
                exit_block,
            },
            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                header,
                exit_block,
            },
            StructuredNode::Return(expr) => StructuredNode::Return(
                expr.map(|expr| self.rewrite_small_aggregate_slot_expr(expr, patterns, true)),
            ),
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => StructuredNode::Switch {
                value: self.rewrite_small_aggregate_slot_expr(value, patterns, true),
                cases: cases
                    .into_iter()
                    .map(|(values, body)| {
                        (
                            values,
                            body.into_iter()
                                .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                                .collect(),
                        )
                    })
                    .collect(),
                default: default.map(|nodes| {
                    nodes
                        .into_iter()
                        .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                        .collect()
                }),
            },
            StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
                nodes
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
            ),
            StructuredNode::Expr(expr) => {
                StructuredNode::Expr(self.rewrite_small_aggregate_slot_expr(expr, patterns, true))
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => StructuredNode::TryCatch {
                try_body: try_body
                    .into_iter()
                    .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                    .collect(),
                catch_handlers: catch_handlers
                    .into_iter()
                    .map(|handler| super::structurer::CatchHandler {
                        exception_type: handler.exception_type,
                        variable_name: handler.variable_name,
                        body: handler
                            .body
                            .into_iter()
                            .map(|node| self.rewrite_small_aggregate_slot_node(node, patterns))
                            .collect(),
                        landing_pad: handler.landing_pad,
                    })
                    .collect(),
            },
            other => other,
        }
    }

    fn rewrite_small_aggregate_slot_expr(
        &self,
        expr: Expr,
        patterns: &HashMap<i128, PackedAggregateSlotPattern>,
        allow_stack_read_rewrite: bool,
    ) -> Expr {
        match expr.kind {
            ExprKind::Var(var) => {
                if allow_stack_read_rewrite {
                    if let Some(rewritten) =
                        Self::try_rewrite_packed_aggregate_identifier_read(&var.name, patterns)
                    {
                        return rewritten;
                    }
                }
                Expr::var(var)
            }
            ExprKind::Unknown(name) => {
                if allow_stack_read_rewrite {
                    if let Some(rewritten) =
                        Self::try_rewrite_packed_aggregate_identifier_read(&name, patterns)
                    {
                        return rewritten;
                    }
                }
                Expr::unknown(name)
            }
            ExprKind::IntLit(_) => expr,
            ExprKind::UnaryOp { op, operand } => Expr::unary(
                op,
                self.rewrite_small_aggregate_slot_expr(*operand, patterns, true),
            ),
            ExprKind::BinOp { op, left, right } => Expr::binop(
                op,
                self.rewrite_small_aggregate_slot_expr(*left, patterns, true),
                self.rewrite_small_aggregate_slot_expr(*right, patterns, true),
            ),
            ExprKind::Deref { addr, size } => {
                let addr = self.rewrite_small_aggregate_slot_expr(*addr, patterns, true);
                if allow_stack_read_rewrite {
                    if let Some(rewritten) =
                        self.try_rewrite_packed_aggregate_stack_read(&addr, size, patterns)
                    {
                        return rewritten;
                    }
                }
                Expr::deref(addr, size)
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr,
                is_deref,
            } => Expr {
                kind: ExprKind::GotRef {
                    address,
                    instruction_address,
                    size,
                    display_expr: Box::new(self.rewrite_small_aggregate_slot_expr(
                        *display_expr,
                        patterns,
                        true,
                    )),
                    is_deref,
                },
            },
            ExprKind::AddressOf(inner) => {
                Expr::address_of(self.rewrite_small_aggregate_slot_expr(*inner, patterns, true))
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => Expr::array_access(
                self.rewrite_small_aggregate_slot_expr(*base, patterns, true),
                self.rewrite_small_aggregate_slot_expr(*index, patterns, true),
                element_size,
            ),
            ExprKind::FieldAccess {
                base,
                field_name,
                offset,
            } => Expr::field_access(
                self.rewrite_small_aggregate_slot_expr(*base, patterns, true),
                field_name,
                offset,
            ),
            ExprKind::Call { target, args } => Expr::call(
                match target {
                    CallTarget::Indirect(expr) => CallTarget::Indirect(Box::new(
                        self.rewrite_small_aggregate_slot_expr(*expr, patterns, true),
                    )),
                    CallTarget::IndirectGot { got_address, expr } => CallTarget::IndirectGot {
                        got_address,
                        expr: Box::new(
                            self.rewrite_small_aggregate_slot_expr(*expr, patterns, true),
                        ),
                    },
                    other => other,
                },
                args.into_iter()
                    .map(|arg| self.rewrite_small_aggregate_slot_expr(arg, patterns, true))
                    .collect(),
            ),
            ExprKind::Assign { lhs, rhs } => Expr::assign(
                self.rewrite_small_aggregate_slot_expr(*lhs, patterns, false),
                self.rewrite_small_aggregate_slot_expr(*rhs, patterns, true),
            ),
            ExprKind::CompoundAssign { op, lhs, rhs } => Expr {
                kind: ExprKind::CompoundAssign {
                    op,
                    lhs: Box::new(self.rewrite_small_aggregate_slot_expr(*lhs, patterns, false)),
                    rhs: Box::new(self.rewrite_small_aggregate_slot_expr(*rhs, patterns, true)),
                },
            },
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => Expr {
                kind: ExprKind::Conditional {
                    cond: Box::new(self.rewrite_small_aggregate_slot_expr(*cond, patterns, true)),
                    then_expr: Box::new(
                        self.rewrite_small_aggregate_slot_expr(*then_expr, patterns, true),
                    ),
                    else_expr: Box::new(
                        self.rewrite_small_aggregate_slot_expr(*else_expr, patterns, true),
                    ),
                },
            },
            ExprKind::Cast {
                expr: inner,
                to_size,
                signed,
            } => Expr {
                kind: ExprKind::Cast {
                    expr: Box::new(self.rewrite_small_aggregate_slot_expr(*inner, patterns, true)),
                    to_size,
                    signed,
                },
            },
            ExprKind::BitField {
                expr: inner,
                start,
                width,
            } => Expr {
                kind: ExprKind::BitField {
                    expr: Box::new(self.rewrite_small_aggregate_slot_expr(*inner, patterns, true)),
                    start,
                    width,
                },
            },
            ExprKind::Phi(values) => Expr {
                kind: ExprKind::Phi(
                    values
                        .into_iter()
                        .map(|value| self.rewrite_small_aggregate_slot_expr(value, patterns, true))
                        .collect(),
                ),
            },
        }
    }

    fn collect_packed_aggregate_slot_patterns(
        &self,
        nodes: &[StructuredNode],
        patterns: &mut HashMap<i128, PackedAggregateSlotPattern>,
    ) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.collect_packed_aggregate_slot_patterns_from_expr(stmt, patterns);
                    }
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.collect_packed_aggregate_slot_patterns_from_expr(condition, patterns);
                    self.collect_packed_aggregate_slot_patterns(then_body, patterns);
                    if let Some(nodes) = else_body {
                        self.collect_packed_aggregate_slot_patterns(nodes, patterns);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                } => {
                    self.collect_packed_aggregate_slot_patterns_from_expr(condition, patterns);
                    self.collect_packed_aggregate_slot_patterns(body, patterns);
                }
                StructuredNode::DoWhile {
                    body, condition, ..
                } => {
                    self.collect_packed_aggregate_slot_patterns(body, patterns);
                    self.collect_packed_aggregate_slot_patterns_from_expr(condition, patterns);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(expr) = init {
                        self.collect_packed_aggregate_slot_patterns_from_expr(expr, patterns);
                    }
                    self.collect_packed_aggregate_slot_patterns_from_expr(condition, patterns);
                    if let Some(expr) = update {
                        self.collect_packed_aggregate_slot_patterns_from_expr(expr, patterns);
                    }
                    self.collect_packed_aggregate_slot_patterns(body, patterns);
                }
                StructuredNode::Loop { body, .. } => {
                    self.collect_packed_aggregate_slot_patterns(body, patterns);
                }
                StructuredNode::Return(Some(expr)) | StructuredNode::Expr(expr) => {
                    self.collect_packed_aggregate_slot_patterns_from_expr(expr, patterns);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    self.collect_packed_aggregate_slot_patterns_from_expr(value, patterns);
                    for (_, body) in cases {
                        self.collect_packed_aggregate_slot_patterns(body, patterns);
                    }
                    if let Some(nodes) = default {
                        self.collect_packed_aggregate_slot_patterns(nodes, patterns);
                    }
                }
                StructuredNode::Sequence(nodes) => {
                    self.collect_packed_aggregate_slot_patterns(nodes, patterns);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    self.collect_packed_aggregate_slot_patterns(try_body, patterns);
                    for handler in catch_handlers {
                        self.collect_packed_aggregate_slot_patterns(&handler.body, patterns);
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

    fn collect_packed_aggregate_slot_patterns_from_expr(
        &self,
        expr: &Expr,
        patterns: &mut HashMap<i128, PackedAggregateSlotPattern>,
    ) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let Some(name) = Self::extract_lifted_stack_identifier(lhs) {
                    self.record_packed_aggregate_identifier_write(patterns, name, rhs);
                } else if let Some((offset, size)) = Self::extract_stack_slot_access(lhs) {
                    self.record_packed_aggregate_slot_write(patterns, offset, size, rhs);
                }
                self.collect_packed_aggregate_slot_patterns_from_expr(lhs, patterns);
                self.collect_packed_aggregate_slot_patterns_from_expr(rhs, patterns);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(left, patterns);
                self.collect_packed_aggregate_slot_patterns_from_expr(right, patterns);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(operand, patterns);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(base, patterns);
                self.collect_packed_aggregate_slot_patterns_from_expr(index, patterns);
            }
            ExprKind::FieldAccess { base, .. } | ExprKind::Deref { addr: base, .. } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(base, patterns);
            }
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Indirect(expr) => {
                        self.collect_packed_aggregate_slot_patterns_from_expr(expr, patterns);
                    }
                    CallTarget::IndirectGot { expr, .. } => {
                        self.collect_packed_aggregate_slot_patterns_from_expr(expr, patterns);
                    }
                    CallTarget::Direct { .. } | CallTarget::Named(_) => {}
                }
                for arg in args {
                    self.collect_packed_aggregate_slot_patterns_from_expr(arg, patterns);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(cond, patterns);
                self.collect_packed_aggregate_slot_patterns_from_expr(then_expr, patterns);
                self.collect_packed_aggregate_slot_patterns_from_expr(else_expr, patterns);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    self.collect_packed_aggregate_slot_patterns_from_expr(value, patterns);
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                self.collect_packed_aggregate_slot_patterns_from_expr(display_expr, patterns);
            }
            ExprKind::Var(_) | ExprKind::IntLit(_) | ExprKind::Unknown(_) => {}
        }
    }

    fn record_packed_aggregate_slot_write(
        &self,
        patterns: &mut HashMap<i128, PackedAggregateSlotPattern>,
        offset: i128,
        size: u8,
        rhs: &Expr,
    ) {
        let Some((base, lane)) = Self::packed_aggregate_slot_base(offset, size) else {
            return;
        };
        let pattern = patterns.entry(base).or_default();

        match size {
            8 => {
                if lane != 0 {
                    pattern.incompatible = true;
                    return;
                }
                if self.is_packed_aggregate_param_source(rhs) {
                    Self::merge_packed_slot_expr(
                        &mut pattern.param_source,
                        rhs.clone(),
                        &mut pattern.incompatible,
                    );
                } else {
                    pattern.incompatible = true;
                }
            }
            4 => match lane {
                0 => Self::merge_packed_slot_expr(
                    &mut pattern.low_store,
                    rhs.clone(),
                    &mut pattern.incompatible,
                ),
                4 => Self::merge_packed_slot_expr(
                    &mut pattern.high_store,
                    rhs.clone(),
                    &mut pattern.incompatible,
                ),
                _ => pattern.incompatible = true,
            },
            _ => pattern.incompatible = true,
        }
    }

    fn record_packed_aggregate_identifier_write(
        &self,
        patterns: &mut HashMap<i128, PackedAggregateSlotPattern>,
        name: &str,
        rhs: &Expr,
    ) {
        let Some((offset, _)) = Self::parse_lifted_stack_offset(name) else {
            return;
        };
        let lane = offset.rem_euclid(8) as u8;
        let base = offset - i128::from(lane);
        let pattern = patterns.entry(base).or_default();

        match lane {
            4 => Self::merge_packed_slot_expr(
                &mut pattern.high_store,
                rhs.clone(),
                &mut pattern.incompatible,
            ),
            0 => {
                if self.is_packed_aggregate_param_source(rhs) {
                    Self::merge_packed_slot_expr(
                        &mut pattern.param_source,
                        rhs.clone(),
                        &mut pattern.incompatible,
                    );
                } else {
                    Self::merge_packed_slot_expr(
                        &mut pattern.low_store,
                        rhs.clone(),
                        &mut pattern.incompatible,
                    );
                }
            }
            _ => pattern.incompatible = true,
        }
    }

    fn merge_packed_slot_expr(
        existing: &mut Option<Expr>,
        candidate: Expr,
        incompatible: &mut bool,
    ) {
        if let Some(current) = existing {
            if !exprs_equal(current, &candidate) {
                *incompatible = true;
            }
        } else {
            *existing = Some(candidate);
        }
    }

    fn try_rewrite_packed_aggregate_stack_read(
        &self,
        addr: &Expr,
        size: u8,
        patterns: &HashMap<i128, PackedAggregateSlotPattern>,
    ) -> Option<Expr> {
        let offset = Self::extract_stack_slot_offset(addr)?;
        let (base, lane) = Self::packed_aggregate_slot_base(offset, size)?;
        let pattern = patterns.get(&base)?;
        if pattern.incompatible {
            return None;
        }

        match size {
            4 => {
                let source = pattern.param_source.as_ref()?;
                Some(Self::extract_packed_aggregate_half(source.clone(), lane))
            }
            8 if lane == 0 => {
                let low = pattern.low_store.clone()?;
                let high = pattern.high_store.clone()?;
                Some(Self::pack_packed_aggregate_halves(low, high))
            }
            _ => None,
        }
    }

    fn try_rewrite_packed_aggregate_identifier_read(
        name: &str,
        patterns: &HashMap<i128, PackedAggregateSlotPattern>,
    ) -> Option<Expr> {
        let (offset, _) = Self::parse_lifted_stack_offset(name)?;
        let (base, lane) = Self::packed_aggregate_slot_base(offset, 4)?;
        let pattern = patterns.get(&base)?;
        if pattern.incompatible {
            return None;
        }

        match lane {
            4 => {
                let source = pattern.param_source.as_ref()?;
                Some(Self::extract_packed_aggregate_half(source.clone(), lane))
            }
            0 if pattern.param_source.is_none() => {
                let low = pattern.low_store.clone()?;
                let high = pattern.high_store.clone()?;
                Some(Self::pack_packed_aggregate_halves(low, high))
            }
            _ => None,
        }
    }

    fn extract_packed_aggregate_half(source: Expr, lane: u8) -> Expr {
        let mask = Expr::int(0xffff_ffff);
        match lane {
            0 => Expr::binop(BinOpKind::And, source, mask).simplify(),
            4 => Expr::binop(
                BinOpKind::And,
                Expr::binop(BinOpKind::Shr, source, Expr::int(32)),
                mask,
            )
            .simplify(),
            _ => source,
        }
    }

    fn pack_packed_aggregate_halves(low: Expr, high: Expr) -> Expr {
        let mask = Expr::int(0xffff_ffff);
        let low_bits = Expr::binop(BinOpKind::And, low, mask.clone());
        let high_bits = Expr::binop(
            BinOpKind::Shl,
            Expr::binop(BinOpKind::And, high, mask),
            Expr::int(32),
        );
        Expr::binop(BinOpKind::Or, low_bits, high_bits).simplify()
    }

    fn extract_stack_slot_access(expr: &Expr) -> Option<(i128, u8)> {
        match &expr.kind {
            ExprKind::Deref { addr, size } => Some((Self::extract_stack_slot_offset(addr)?, *size)),
            ExprKind::Var(var) => {
                let (offset, _) = Self::parse_lifted_stack_offset(&var.name)?;
                Some((offset, var.size))
            }
            ExprKind::Unknown(_) => None,
            _ => None,
        }
    }

    fn extract_lifted_stack_identifier(expr: &Expr) -> Option<&str> {
        match &expr.kind {
            ExprKind::Unknown(name) if Self::is_lifted_stack_identifier(name) => Some(name),
            ExprKind::Var(var) if Self::is_lifted_stack_identifier(&var.name) => Some(&var.name),
            _ => None,
        }
    }

    fn extract_stack_slot_offset(addr: &Expr) -> Option<i128> {
        match &addr.kind {
            ExprKind::Var(var) => match &var.kind {
                super::expression::VarKind::Stack(offset) => Some(*offset as i128),
                _ => Self::parse_lifted_stack_offset(&var.name).map(|(offset, _)| offset),
            },
            ExprKind::Unknown(name) => {
                Self::parse_lifted_stack_offset(name).map(|(offset, _)| offset)
            }
            ExprKind::BinOp { op, left, right } => {
                let ExprKind::Var(base) = &left.kind else {
                    return None;
                };
                let is_frame_ptr = matches!(base.name.as_str(), "rbp" | "x29" | "fp");
                let is_stack_ptr = matches!(base.name.as_str(), "rsp" | "sp");
                if !(is_frame_ptr || is_stack_ptr) {
                    return None;
                }
                let ExprKind::IntLit(offset) = &right.kind else {
                    return None;
                };
                match op {
                    BinOpKind::Add => Some(*offset),
                    BinOpKind::Sub => Some(-*offset),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    fn packed_aggregate_slot_base(offset: i128, size: u8) -> Option<(i128, u8)> {
        let lane = offset.rem_euclid(8) as u8;
        let base = offset - i128::from(lane);
        match size {
            8 if lane == 0 => Some((base, 0)),
            4 if matches!(lane, 0 | 4) => Some((base, lane)),
            _ => None,
        }
    }

    fn is_packed_aggregate_param_source(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => {
                let name = var.name.to_lowercase();
                self.calling_convention
                    .integer_arg_registers()
                    .iter()
                    .chain(self.calling_convention.integer_arg_registers_32().iter())
                    .any(|reg| reg.eq_ignore_ascii_case(&name))
            }
            ExprKind::Unknown(name) => {
                let lower = name.to_lowercase();
                lower.starts_with("arg")
                    || get_arg_register_index(&lower).is_some()
                    || self
                        .calling_convention
                        .integer_arg_registers()
                        .iter()
                        .any(|reg| reg.eq_ignore_ascii_case(&lower))
            }
            ExprKind::Cast { expr: inner, .. } => self.is_packed_aggregate_param_source(inner),
            _ => false,
        }
    }

    fn rewrite_tail_call_return_node(
        node: StructuredNode,
        in_tail_return_path: bool,
    ) -> StructuredNode {
        match node {
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition,
                then_body: Self::rewrite_tail_call_returns_for_emission(
                    &then_body,
                    in_tail_return_path,
                ),
                else_body: else_body.map(|nodes| {
                    Self::rewrite_tail_call_returns_for_emission(&nodes, in_tail_return_path)
                }),
            },
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition,
                body: Self::rewrite_tail_call_returns_for_emission(&body, false),
                header,
                exit_block,
            },
            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: Self::rewrite_tail_call_returns_for_emission(&body, false),
                condition,
                header,
                exit_block,
            },
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                header,
                exit_block,
            } => StructuredNode::For {
                init,
                condition,
                update,
                body: Self::rewrite_tail_call_returns_for_emission(&body, false),
                header,
                exit_block,
            },
            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: Self::rewrite_tail_call_returns_for_emission(&body, false),
                header,
                exit_block,
            },
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => StructuredNode::Switch {
                value,
                cases: cases
                    .into_iter()
                    .map(|(values, body)| {
                        (
                            values,
                            Self::rewrite_tail_call_returns_for_emission(
                                &body,
                                in_tail_return_path,
                            ),
                        )
                    })
                    .collect(),
                default: default.map(|nodes| {
                    Self::rewrite_tail_call_returns_for_emission(&nodes, in_tail_return_path)
                }),
            },
            StructuredNode::Sequence(nodes) => StructuredNode::Sequence(
                Self::rewrite_tail_call_returns_for_emission(&nodes, in_tail_return_path),
            ),
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => StructuredNode::TryCatch {
                try_body: Self::rewrite_tail_call_returns_for_emission(
                    &try_body,
                    in_tail_return_path,
                ),
                catch_handlers: catch_handlers
                    .into_iter()
                    .map(|handler| super::structurer::CatchHandler {
                        exception_type: handler.exception_type,
                        variable_name: handler.variable_name,
                        body: Self::rewrite_tail_call_returns_for_emission(
                            &handler.body,
                            in_tail_return_path,
                        ),
                        landing_pad: handler.landing_pad,
                    })
                    .collect(),
            },
            other => other,
        }
    }

    fn is_tail_padding_statement(expr: &Expr) -> bool {
        matches!(&expr.kind, ExprKind::Unknown(name) if name.trim() == "/* nop */")
            || is_epilogue_statement(expr)
    }

    fn node_is_tail_padding(node: &StructuredNode) -> bool {
        match node {
            StructuredNode::Block { statements, .. } => {
                !statements.is_empty() && statements.iter().all(Self::is_tail_padding_statement)
            }
            StructuredNode::Sequence(nodes) => {
                !nodes.is_empty() && nodes.iter().all(Self::node_is_tail_padding)
            }
            _ => false,
        }
    }

    fn suffix_is_tail_return_path(nodes: &[StructuredNode]) -> bool {
        if nodes.is_empty() {
            return true;
        }

        let mut saw_bare_return = false;
        for node in nodes {
            match node {
                StructuredNode::Return(None) => {
                    saw_bare_return = true;
                }
                _ if saw_bare_return => return false,
                _ if Self::node_is_tail_padding(node) => {}
                _ => return false,
            }
        }

        true
    }

    fn fold_terminal_tail_call_return(
        nodes: &mut Vec<StructuredNode>,
        allow_fallthrough_tail_return: bool,
    ) {
        if nodes.is_empty() || !allow_fallthrough_tail_return {
            return;
        }

        let has_bare_return = matches!(nodes.last(), Some(StructuredNode::Return(None)));
        let search_end = if has_bare_return {
            nodes.len().saturating_sub(1)
        } else {
            nodes.len()
        };
        let mut call_index = search_end;
        while call_index > 0 && Self::node_is_tail_padding(&nodes[call_index - 1]) {
            call_index -= 1;
        }
        if call_index == 0 {
            return;
        }
        call_index -= 1;

        let Some(call_expr) = ({
            let StructuredNode::Block { statements, .. } = &mut nodes[call_index] else {
                return;
            };

            let call_stmt_index = statements
                .iter()
                .rposition(|stmt| !Self::is_tail_padding_statement(stmt));
            let Some(call_stmt_index) = call_stmt_index else {
                return;
            };
            let Some(Expr {
                kind: ExprKind::Call { .. },
            }) = statements.get(call_stmt_index)
            else {
                return;
            };

            let call_expr = statements.get(call_stmt_index).cloned();
            if call_expr
                .as_ref()
                .is_some_and(|expr| !Self::call_can_be_folded_into_return(expr))
            {
                return;
            }
            statements.truncate(call_stmt_index);
            call_expr
        }) else {
            return;
        };

        if call_index + 1 < search_end {
            nodes.drain(call_index + 1..search_end);
        }

        let remove_empty_block = matches!(
            nodes.get(call_index),
            Some(StructuredNode::Block { statements, .. }) if statements.is_empty()
        );
        if remove_empty_block {
            nodes.remove(call_index);
        }

        if has_bare_return {
            if let Some(last) = nodes.last_mut() {
                *last = StructuredNode::Return(Some(call_expr));
            }
        } else {
            nodes.push(StructuredNode::Return(Some(call_expr)));
        }
    }

    fn call_can_be_folded_into_return(expr: &Expr) -> bool {
        let ExprKind::Call { target, .. } = &expr.kind else {
            return false;
        };
        let CallTarget::Named(name) = target else {
            return true;
        };
        if crate::is_noreturn_function_name(name) {
            return false;
        }

        !matches!(
            name.as_str(),
            "__atomic_thread_fence"
                | "__builtin_prefetch"
                | "__builtin_trap"
                | "atomic_store"
                | "atomic_exchange"
                | "atomic_fetch_add"
                | "atomic_fetch_sub"
                | "atomic_fetch_and"
                | "atomic_fetch_or"
                | "atomic_fetch_xor"
                | "atomic_compare_exchange_strong"
        )
    }

    fn emit_return_line(&self, output: &mut String, indent: &str, expr: Option<&Expr>) {
        if let Some(e) = expr {
            writeln!(output, "{}return {};", indent, self.format_expr(e)).unwrap();
            return;
        }
        if let Some(fallback) = self.return_fallback_expr.borrow().clone() {
            writeln!(output, "{}return {};", indent, fallback).unwrap();
        } else {
            writeln!(output, "{}return;", indent).unwrap();
        }
    }

    fn output_ends_with_return_stmt(output: &str) -> bool {
        output
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .is_some_and(|line| {
                let trimmed = line.trim_start();
                trimmed == "return;" || trimmed.starts_with("return ")
            })
    }

    fn clear_param_name_overrides(&self) {
        self.param_name_overrides.borrow_mut().clear();
    }

    fn set_param_name_override(&self, from: &str, to: &str) {
        let from_lower = from.to_lowercase();
        if from_lower == to.to_lowercase() {
            return;
        }
        self.param_name_overrides
            .borrow_mut()
            .insert(from_lower, to.to_string());
    }

    fn set_lifted_param_slot_overrides(&self, index: usize, rendered_name: &str) {
        let slot = 8 * (index + 1);
        let aliases = if rendered_name == "this" {
            vec![
                format!("arg_{:x}", slot),
                format!("arg_0x{:x}", slot),
                format!("stack_-{}", slot),
            ]
        } else {
            vec![
                format!("arg_{:x}", slot),
                format!("arg_0x{:x}", slot),
                format!("local_{:x}", slot),
                format!("local_0x{:x}", slot),
                format!("stack_-{}", slot),
            ]
        };
        for alias in aliases {
            self.set_param_name_override(&alias, rendered_name);
        }
    }

    fn apply_param_name_override(&self, name: &str) -> String {
        self.param_name_overrides
            .borrow()
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| name.to_string())
    }

    fn rename_register_for_display(&self, name: &str) -> String {
        if self.preserve_register_names.get() {
            return name.to_string();
        }
        if let Some(rendered) = self.arg_register_display_name(name) {
            return rendered;
        }
        rename_register(name)
    }

    fn with_preserved_register_names<T>(&self, f: impl FnOnce() -> T) -> T {
        let previous = self.preserve_register_names.replace(true);
        let result = f();
        self.preserve_register_names.set(previous);
        result
    }

    fn format_expr_preserving_register_names(&self, expr: &Expr, table: &StringTable) -> String {
        self.with_preserved_register_names(|| self.format_expr_with_strings(expr, table))
    }

    fn format_lvalue_preserving_register_names(&self, expr: &Expr, table: &StringTable) -> String {
        self.with_preserved_register_names(|| self.format_lvalue(expr, table))
    }

    fn lhs_is_snapshot_register(&self, expr: &Expr) -> bool {
        let ExprKind::Var(var) = &expr.kind else {
            return false;
        };
        let lower = var.name.to_lowercase();
        rename_register(&lower) != lower || get_arg_register_index(&lower).is_some()
    }

    fn expr_contains_snapshot_register_source(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => {
                let lower = var.name.to_lowercase();
                is_callee_saved_register(&lower)
                    || matches!(
                        lower.as_str(),
                        "rax" | "eax" | "rdx" | "edx" | "rbp" | "ebp" | "rsp" | "esp" | "sp"
                    )
                    || get_arg_register_index(&lower).is_some()
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                Self::expr_contains_snapshot_register_source(operand)
            }
            ExprKind::BinOp { left, right, .. }
            | ExprKind::Assign {
                lhs: left,
                rhs: right,
            }
            | ExprKind::CompoundAssign {
                lhs: left,
                rhs: right,
                ..
            } => {
                Self::expr_contains_snapshot_register_source(left)
                    || Self::expr_contains_snapshot_register_source(right)
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                Self::expr_contains_snapshot_register_source(base)
                    || Self::expr_contains_snapshot_register_source(index)
            }
            ExprKind::FieldAccess { base, .. } => {
                Self::expr_contains_snapshot_register_source(base)
            }
            ExprKind::Call { args, .. } | ExprKind::Phi(args) => args
                .iter()
                .any(Self::expr_contains_snapshot_register_source),
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                Self::expr_contains_snapshot_register_source(cond)
                    || Self::expr_contains_snapshot_register_source(then_expr)
                    || Self::expr_contains_snapshot_register_source(else_expr)
            }
            ExprKind::IntLit(_) | ExprKind::GotRef { .. } | ExprKind::Unknown(_) => false,
        }
    }

    fn expr_is_parameter_derived(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Var(var) => {
                looks_like_parameter_name(&var.name)
                    || get_arg_register_index(&var.name.to_lowercase()).is_some()
            }
            ExprKind::Unknown(name) => looks_like_parameter_name(name),
            ExprKind::AddressOf(inner) | ExprKind::Cast { expr: inner, .. } => {
                Self::expr_is_parameter_derived(inner)
            }
            ExprKind::BinOp { op, left, right } => {
                matches!(op, BinOpKind::Add | BinOpKind::Sub)
                    && ((Self::expr_is_parameter_derived(left)
                        && matches!(right.kind, ExprKind::IntLit(_)))
                        || (Self::expr_is_parameter_derived(right)
                            && matches!(left.kind, ExprKind::IntLit(_))))
            }
            _ => false,
        }
    }

    fn is_parameter_snapshot_target(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Deref { addr, .. } => Self::expr_is_parameter_derived(addr),
            ExprKind::ArrayAccess { base, .. } | ExprKind::FieldAccess { base, .. } => {
                Self::expr_is_parameter_derived(base)
            }
            _ => false,
        }
    }

    fn is_register_snapshot_store(stmt: &Expr) -> bool {
        let ExprKind::Assign { lhs, rhs } = &stmt.kind else {
            return false;
        };
        Self::is_parameter_snapshot_target(lhs) && Self::expr_contains_snapshot_register_source(rhs)
    }

    // TODO(32.3): lift jmp_buf register-save helpers earlier in the pipeline so
    // __sigsetjmp-style functions structure as named buffer fields instead of raw stores.
    fn should_enable_register_snapshot_mode(nodes: &[StructuredNode]) -> bool {
        fn count_snapshot_stores(node: &StructuredNode) -> usize {
            match node {
                StructuredNode::Block { statements, .. } => statements
                    .iter()
                    .filter(|stmt| PseudoCodeEmitter::is_register_snapshot_store(stmt))
                    .count(),
                StructuredNode::Expr(expr) => {
                    usize::from(PseudoCodeEmitter::is_register_snapshot_store(expr))
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    then_body.iter().map(count_snapshot_stores).sum::<usize>()
                        + else_body
                            .as_ref()
                            .map(|nodes| nodes.iter().map(count_snapshot_stores).sum())
                            .unwrap_or(0)
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => body.iter().map(count_snapshot_stores).sum(),
                StructuredNode::For { body, .. } => body.iter().map(count_snapshot_stores).sum(),
                StructuredNode::Switch { cases, default, .. } => {
                    let case_count: usize = cases
                        .iter()
                        .map(|(_, body)| body.iter().map(count_snapshot_stores).sum::<usize>())
                        .sum();
                    let default_count = default
                        .as_ref()
                        .map(|body| body.iter().map(count_snapshot_stores).sum())
                        .unwrap_or(0);
                    case_count + default_count
                }
                StructuredNode::Sequence(nodes) => nodes.iter().map(count_snapshot_stores).sum(),
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    try_body.iter().map(count_snapshot_stores).sum::<usize>()
                        + catch_handlers
                            .iter()
                            .map(|handler| {
                                handler
                                    .body
                                    .iter()
                                    .map(count_snapshot_stores)
                                    .sum::<usize>()
                            })
                            .sum::<usize>()
                }
                _ => 0,
            }
        }

        nodes.iter().map(count_snapshot_stores).sum::<usize>() >= 3
    }

    fn arg_register_display_name(&self, name: &str) -> Option<String> {
        let lower = name.to_lowercase();
        if let Some(idx) = self
            .calling_convention
            .integer_arg_registers()
            .iter()
            .position(|reg| reg.eq_ignore_ascii_case(&lower))
            .or_else(|| {
                self.calling_convention
                    .integer_arg_registers_32()
                    .iter()
                    .position(|reg| reg.eq_ignore_ascii_case(&lower))
            })
        {
            // Only treat it as a parameter if the function actually has that
            // many integer arguments; otherwise the register is a local temp.
            if idx >= self.integer_arg_param_count.get() {
                return None;
            }
            return Some(match self.calling_convention {
                CallingConvention::RiscV => format!("a{}", idx),
                _ => format!("arg{}", idx),
            });
        }

        let idx = self
            .calling_convention
            .float_arg_registers()
            .iter()
            .position(|reg| reg.eq_ignore_ascii_case(&lower))?;
        if idx >= self.float_arg_param_count.get() {
            return None;
        }
        Some(format!("farg{}", idx))
    }

    fn resolve_display_identifier_name(&self, name: &str) -> String {
        if let Some(semantic_name) = self.try_get_semantic_var_name(name) {
            let overridden = self.apply_param_name_override(&semantic_name);
            return normalize_variable_name(&overridden);
        }

        let renamed = self.rename_register_for_display(name);
        let overridden = self.apply_param_name_override(&renamed);
        normalize_variable_name(&overridden)
    }

    fn should_prefer_specific_param_name(candidate: &str) -> bool {
        !looks_like_parameter_name(candidate)
            && !candidate.starts_with("var_")
            && !candidate.starts_with("local_")
            && !candidate.starts_with("arg_")
    }

    fn is_lifted_stack_identifier(name: &str) -> bool {
        name.starts_with("var_") || name.starts_with("local_") || name.starts_with("arg_")
    }

    fn parse_lifted_stack_offset(var_name: &str) -> Option<(i128, bool)> {
        if let Some(suffix) = var_name.strip_prefix("var_") {
            let offset = i128::from_str_radix(suffix, 16).ok()?;
            Some((offset, true))
        } else if let Some(suffix) = var_name.strip_prefix("local_") {
            let positive = i128::from_str_radix(suffix, 16).ok()?;
            Some((-positive, false))
        } else if let Some(suffix) = var_name.strip_prefix("arg_") {
            let offset = i128::from_str_radix(suffix, 16).ok()?;
            Some((offset, true))
        } else {
            None
        }
    }

    /// Sets the calling convention for signature recovery.
    pub fn with_calling_convention(mut self, convention: CallingConvention) -> Self {
        self.calling_convention = convention;
        self
    }

    /// Enables or disables advanced signature recovery.
    pub fn with_signature_recovery(mut self, enabled: bool) -> Self {
        self.use_signature_recovery = enabled;
        self
    }

    /// Sets the string table for resolving addresses.
    pub fn with_string_table(mut self, table: Option<StringTable>) -> Self {
        self.string_table = table;
        self
    }

    /// Sets the symbol table for resolving function addresses.
    pub fn with_symbol_table(mut self, table: Option<SymbolTable>) -> Self {
        self.symbol_table = table;
        *self.gnu_version_ambiguous_bases.borrow_mut() = None;
        self
    }

    /// Sets the relocation table for resolving call targets in relocatable files.
    pub fn with_relocation_table(mut self, table: Option<RelocationTable>) -> Self {
        self.relocation_table = table;
        *self.gnu_version_ambiguous_bases.borrow_mut() = None;
        self
    }

    /// Sets thread-pointer-relative TLS symbol names keyed by byte offset.
    pub fn with_tls_symbol_offsets(mut self, offsets: HashMap<i64, String>) -> Self {
        self.tls_symbol_offsets = offsets;
        self
    }

    /// Sets type information for variables.
    /// Keys should be variable names (e.g., "var_8", "local_10"),
    /// values should be C type strings (e.g., "int", "char*", "float").
    pub fn with_type_info(mut self, type_info: std::collections::HashMap<String, String>) -> Self {
        self.type_info = type_info;
        self
    }

    /// Sets DWARF variable names.
    /// Keys are stack offsets (frame-relative), values are variable names.
    pub fn with_dwarf_names(mut self, names: std::collections::HashMap<i128, String>) -> Self {
        // Also add to naming context for consistent lookup
        self.naming_ctx.borrow_mut().add_dwarf_names(names.clone());
        self.dwarf_names = names;
        self
    }

    /// Sets DWARF parameter names in declaration order.
    pub fn with_dwarf_param_names(mut self, names: Vec<String>) -> Self {
        self.dwarf_param_names = names;
        self
    }

    /// Sets DWARF lexical-block ranges keyed by local variable name.
    pub fn with_dwarf_scope_ranges(
        mut self,
        ranges: std::collections::HashMap<String, (u64, u64)>,
    ) -> Self {
        self.dwarf_scope_ranges = ranges;
        self
    }

    /// Sets the type database for struct field access and function prototypes.
    ///
    /// When set, the emitter will use the type database to:
    /// - Convert pointer dereferences with offsets to struct field access
    /// - Look up function prototypes for better call site rendering
    pub fn with_type_database(mut self, db: Arc<TypeDatabase>) -> Self {
        self.type_database = Some(db);
        self
    }

    /// Sets the constant database for magic number recognition.
    ///
    /// When set, the emitter will recognize and replace magic numbers with
    /// symbolic names (e.g., TIOCGWINSZ, SIGINT, O_RDONLY).
    pub fn with_constant_database(mut self, db: Arc<ConstantDatabase>) -> Self {
        self.constant_database = Some(db);
        self
    }

    /// Sets inter-procedural summaries for signature recovery hints.
    pub fn with_summary_database(mut self, db: Arc<SummaryDatabase>) -> Self {
        self.summary_database = Some(db);
        self
    }

    /// Gets the DWARF name for a stack offset, if available.
    fn get_dwarf_name(&self, offset: i128) -> Option<&str> {
        self.dwarf_names
            .get(&offset)
            .or_else(|| self.dwarf_names.get(&-offset))
            .map(|s| s.as_str())
    }

    /// Gets the type string for a variable, defaulting to "int".
    fn get_type(&self, var_name: &str) -> &str {
        self.lookup_type_info(var_name).unwrap_or("int")
    }

    /// Gets the type of an expression if known.
    ///
    /// This checks:
    /// 1. Stack slot variables (var_X, local_X) in type_info
    /// 2. Register names with known roles
    /// 3. DWARF variable names
    fn get_expr_type(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            // For stack slot dereferences, try to get the variable name and its type
            ExprKind::Deref { addr, .. } => {
                if let Some(var_name) = self.try_get_stack_var_name(addr) {
                    if let Some(ty) = self.type_info.get(&var_name) {
                        return Some(ty.clone());
                    }
                }
                None
            }
            // For named variables
            ExprKind::Var(var) => {
                // Check type_info for this variable
                if let Some(ty) = self.type_info.get(&var.name) {
                    return Some(ty.clone());
                }
                // Try lowercase version
                if let Some(ty) = self.type_info.get(&var.name.to_lowercase()) {
                    return Some(ty.clone());
                }
                None
            }
            ExprKind::Unknown(name) => self.lookup_type_info(name).map(str::to_string),
            _ => None,
        }
    }

    /// Try to extract a stack variable name from an address expression.
    fn try_get_stack_var_name(&self, addr: &Expr) -> Option<String> {
        if let ExprKind::BinOp { op, left, right } = &addr.kind {
            if let ExprKind::Var(base) = &left.kind {
                // Check for frame/stack pointers
                let is_frame_ptr = matches!(base.name.as_str(), "rbp" | "x29" | "fp");
                let is_stack_ptr = matches!(base.name.as_str(), "rsp" | "sp");

                if is_frame_ptr || is_stack_ptr {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        let actual_offset = match op {
                            BinOpKind::Add => *offset,
                            BinOpKind::Sub => -*offset,
                            _ => return None,
                        };
                        // Generate variable name for this offset
                        if actual_offset < 0 {
                            return Some(format!("local_{:x}", (-actual_offset) as u128));
                        } else {
                            return Some(format!("var_{:x}", actual_offset as u128));
                        }
                    }
                }
            }
        }
        None
    }

    /// Checks if a type string matches a cast target.
    ///
    /// Returns true if the variable's type is compatible with the cast,
    /// meaning the cast is redundant and can be eliminated.
    fn type_matches_cast(&self, type_str: &str, to_size: u8, signed: bool) -> bool {
        let type_lower = type_str.to_lowercase();

        // Match common C type names
        match (to_size, signed) {
            (1, true) => {
                matches!(
                    type_lower.as_str(),
                    "int8_t" | "char" | "signed char" | "i8"
                )
            }
            (1, false) => {
                matches!(
                    type_lower.as_str(),
                    "uint8_t" | "unsigned char" | "u8" | "byte"
                )
            }
            (2, true) => {
                matches!(type_lower.as_str(), "int16_t" | "short" | "i16")
            }
            (2, false) => {
                matches!(
                    type_lower.as_str(),
                    "uint16_t" | "unsigned short" | "u16" | "ushort"
                )
            }
            (4, true) => {
                matches!(
                    type_lower.as_str(),
                    "int32_t" | "int" | "i32" | "long" | "int32"
                )
            }
            (4, false) => {
                matches!(
                    type_lower.as_str(),
                    "uint32_t"
                        | "unsigned int"
                        | "unsigned"
                        | "u32"
                        | "uint"
                        | "unsigned long"
                        | "uint32"
                        | "size_t"
                )
            }
            (8, true) => {
                matches!(
                    type_lower.as_str(),
                    "int64_t" | "long long" | "i64" | "int64" | "ssize_t" | "ptrdiff_t"
                )
            }
            (8, false) => {
                matches!(
                    type_lower.as_str(),
                    "uint64_t" | "unsigned long long" | "u64" | "uint64" | "size_t" | "uintptr_t"
                )
            }
            _ => false,
        }
    }

    /// Try to format a dereference as struct field access using the type database.
    ///
    /// Given a deref like `*(ptr + 8)` and the knowledge that ptr points to struct stat,
    /// this will return `ptr->st_ino` (assuming offset 8 is st_ino).
    ///
    /// For now, this is opportunistic - it will look at the variable's type hint
    /// in type_info to determine the struct type.
    fn try_format_struct_field(
        &self,
        addr: &Expr,
        _size: usize,
        table: &StringTable,
    ) -> Option<String> {
        let type_db = self.type_database.as_ref()?;

        // Extract base + offset from the address expression
        // Common patterns: base + offset, base - offset
        let (base, offset) = match &addr.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                // base + offset
                if let ExprKind::IntLit(off) = right.kind {
                    (left.as_ref(), off as usize)
                } else if let ExprKind::IntLit(off) = left.kind {
                    (right.as_ref(), off as usize)
                } else {
                    return None;
                }
            }
            ExprKind::BinOp {
                op: BinOpKind::Sub,
                left,
                right,
            } => {
                // base - offset (negative offset)
                if let ExprKind::IntLit(off) = right.kind {
                    // Negative offsets are unusual for struct fields
                    if off >= 0 {
                        return None;
                    }
                    (left.as_ref(), (-off) as usize)
                } else {
                    return None;
                }
            }
            // Direct dereference: *ptr (offset 0)
            _ => (addr, 0),
        };

        // Get the base expression's variable name to look up its type
        let var_name = match &base.kind {
            ExprKind::Var(v) => &v.name,
            _ => return None,
        };

        // Look up the type of this variable in type_info
        let type_str = self.type_info.get(var_name)?;

        // Extract struct name from type string
        // Patterns: "struct foo *", "struct foo*", "struct foo"
        let struct_name = if let Some(rest) = type_str.strip_prefix("struct ") {
            // Skip "struct "
            // Find the end of the struct name (before * or space or end)
            let name_end = rest.find(['*', ' ']).unwrap_or(rest.len());
            let name = rest[..name_end].trim();
            format!("struct {}", name)
        } else {
            return None;
        };

        // Look up field at offset in type database
        let field_access = type_db.format_field_access(&struct_name, offset)?;

        // Format as ptr->field (pointer) or base.field (direct)
        let base_str = self.format_expr_with_strings(base, table);
        let is_pointer = type_str.contains('*');

        if is_pointer {
            Some(format!("{}{}", base_str, field_access.replace('.', "->")))
        } else {
            Some(format!("{}{}", base_str, field_access))
        }
    }

    fn try_format_struct_pointer_field_fallback(
        &self,
        base: &Expr,
        offset: usize,
        table: &StringTable,
    ) -> Option<String> {
        let base_name = match &base.kind {
            ExprKind::Var(var) => var.name.clone(),
            ExprKind::Unknown(name) => name.clone(),
            _ => self.try_get_var_name(base)?,
        };
        let type_str = self.lookup_type_info(&base_name)?.trim();
        if !type_str.starts_with("struct ") || !Self::is_pointer_like_type_hint(type_str) {
            return None;
        }

        let base_str = self.format_postfix_base(base, table);
        Some(format!("{}->field_{:x}", base_str, offset))
    }

    /// Formats a function call argument with context-aware constant recognition.
    ///
    /// Given the function name and argument index, this tries to recognize magic constants
    /// (like TIOCGWINSZ for ioctl, SIGINT for signal, etc.) and replace them with symbolic names.
    fn format_call_arg(
        &self,
        arg: &Expr,
        func_name: &str,
        arg_index: usize,
        args: &[Expr],
        table: &StringTable,
    ) -> String {
        // signal/signaction handler argument: resolve raw addresses to function names.
        if matches!(func_name, "signal" | "_signal" | "sigaction") && matches!(arg_index, 1 | 2) {
            if let Some(name) = self.resolve_function_pointer_arg(arg) {
                return name;
            }
        }

        if let Some(name) = self.resolve_function_literal_arg(arg) {
            return name;
        }

        // Try to recognize magic constants based on the function and argument position
        if let Some(ref const_db) = self.constant_database {
            // Check if this argument position has a known constant category
            if let Some(category) = get_argument_category(func_name, arg_index) {
                // If the argument is an integer literal, try to resolve it
                if let ExprKind::IntLit(value) = &arg.kind {
                    // For flag-type arguments, try to format as combined flags
                    match category {
                        ConstantCategory::OpenFlags
                        | ConstantCategory::FdFlags
                        | ConstantCategory::MmapProt
                        | ConstantCategory::MmapFlags
                        | ConstantCategory::PollEvents
                        | ConstantCategory::CloneFlags
                        | ConstantCategory::EpollCreateFlags
                        | ConstantCategory::CloseRangeFlags
                        | ConstantCategory::OpenHowResolveFlags
                        | ConstantCategory::SignalfdFlags
                        | ConstantCategory::EventfdFlags
                        | ConstantCategory::TimerfdFlags
                        | ConstantCategory::LandlockAccessFs
                        | ConstantCategory::MemfdSecretFlags => {
                            return const_db.format_flags(*value, category);
                        }
                        ConstantCategory::FileMode => {
                            // Format file modes as octal (e.g., 0644)
                            if *value >= 0 && *value <= 0o7777 {
                                return format!("0{:o}", value);
                            }
                        }
                        _ => {
                            // Single value lookup
                            if let Some(name) = const_db.lookup(*value, Some(category)) {
                                return name.to_string();
                            }
                        }
                    }
                }
            }
        }
        // Fall back to normal expression formatting
        if let Some(address_str) = self.try_format_global_address_materialization(arg) {
            return address_str;
        }
        if let Some(name) = Self::format_known_callback_literal(func_name, arg_index, arg) {
            return name;
        }
        self.format_expr_with_explicit_string_len(
            arg,
            table,
            self.explicit_string_arg_len(func_name, args, arg_index),
        )
    }

    /// For an `Assign(FieldAccess(Var(struct_local), field, …), IntLit(N))`
    /// expression, look up the field's [`ConstantCategory`] (e.g.
    /// `struct epoll_event.events` → `PollEvents`) and, if found, return a
    /// pre-formatted RHS string (`"EPOLLIN | EPOLLRDHUP"` or a single named
    /// constant). This is the struct-field analogue of `format_call_arg`'s
    /// category dispatch. Returns `None` when the LHS isn't a typed-struct
    /// field access, the RHS isn't an integer literal, or the field has no
    /// associated category.
    fn try_format_field_categorical_rhs(&self, lhs: &Expr, rhs: &Expr) -> Option<String> {
        let ExprKind::IntLit(value) = &rhs.kind else {
            return None;
        };
        let const_db = self.constant_database.as_ref()?;
        let ExprKind::FieldAccess {
            base, field_name, ..
        } = &lhs.kind
        else {
            return None;
        };
        let ExprKind::Var(v) = &base.kind else {
            return None;
        };
        let struct_type = self
            .type_info
            .get(&v.name)
            .or_else(|| self.type_info.get(&v.name.to_lowercase()))?;
        let trimmed = struct_type.trim().trim_end_matches(';').trim();
        let category = get_field_category(trimmed, field_name)?;
        Some(match category {
            ConstantCategory::OpenFlags
            | ConstantCategory::FdFlags
            | ConstantCategory::MmapProt
            | ConstantCategory::MmapFlags
            | ConstantCategory::PollEvents
            | ConstantCategory::CloneFlags
            | ConstantCategory::EpollCreateFlags
            | ConstantCategory::CloseRangeFlags
            | ConstantCategory::OpenHowResolveFlags
            | ConstantCategory::SignalfdFlags
            | ConstantCategory::EventfdFlags
            | ConstantCategory::TimerfdFlags
            | ConstantCategory::LandlockAccessFs
            | ConstantCategory::MemfdSecretFlags => const_db.format_flags(*value, category),
            _ => const_db.lookup(*value, Some(category))?.to_string(),
        })
    }

    /// Resolve a function pointer-like argument to a symbol name, when possible.
    fn resolve_function_pointer_arg(&self, arg: &Expr) -> Option<String> {
        let sym = self.symbol_table.as_ref()?;
        match &arg.kind {
            ExprKind::IntLit(n) if *n > 0 => sym.get(*n as u64).map(ToOwned::to_owned),
            ExprKind::GotRef { address, .. } => sym.get(*address).map(ToOwned::to_owned),
            _ => None,
        }
    }

    fn resolve_function_literal_arg(&self, arg: &Expr) -> Option<String> {
        let ExprKind::IntLit(addr) = &arg.kind else {
            return None;
        };
        if *addr < 0 || *addr > u64::MAX as i128 {
            return None;
        }

        let symbol = self.symbol_table.as_ref()?.get_match(*addr as u64)?;
        if !symbol.is_defined || symbol.is_data_symbol {
            return None;
        }

        Some(self.format_call_target_name(symbol.name))
    }

    fn format_known_callback_literal(
        func_name: &str,
        arg_index: usize,
        arg: &Expr,
    ) -> Option<String> {
        let ExprKind::IntLit(addr) = &arg.kind else {
            return None;
        };
        if *addr <= 0 || *addr > u64::MAX as i128 {
            return None;
        }
        if !Self::is_known_callback_arg_position(func_name, arg_index) {
            return None;
        }
        Some(format!("sub_{:x}", *addr as u64))
    }

    fn is_known_callback_arg_position(func_name: &str, arg_index: usize) -> bool {
        let normalized = hexray_core::unversioned_symbol_name(Self::strip_plt_suffix(func_name))
            .trim_start_matches('_');
        matches!(
            (normalized, arg_index),
            ("qsort", 3)
                | ("qsort_r" | "hexray_qsort_r" | "qsort_s", 3)
                | ("bsd_qsort_r" | "hexray_bsd_qsort_r", 4)
                | ("bsearch", 4)
                | ("pthread_create", 2)
                | ("signal", 1)
                | ("atexit" | "at_quick_exit", 0)
                | ("on_exit" | "hexray_on_exit", 0)
                | ("pthread_atfork", 0..=2)
        )
    }

    fn explicit_string_arg_len(
        &self,
        func_name: &str,
        args: &[Expr],
        arg_index: usize,
    ) -> Option<usize> {
        // Rust string slices are commonly lowered as adjacent `(ptr, len)` pairs in
        // demangled `path::to::function` calls. Keep the heuristic narrow enough to
        // avoid truncating classic C string arguments like `printf("...", 2)`.
        if !(func_name.contains("::") || func_name.starts_with('<')) {
            return None;
        }

        let len_expr = args.get(arg_index + 1)?;
        let ExprKind::IntLit(len) = len_expr.kind else {
            return None;
        };
        usize::try_from(len).ok()
    }

    fn truncate_resolved_string<'a>(&self, value: &'a str, max_len: Option<usize>) -> &'a str {
        let Some(max_len) = max_len else {
            return value;
        };
        if max_len >= value.len() {
            return value;
        }
        value.get(..max_len).unwrap_or(value)
    }

    fn format_string_literal_at(
        &self,
        address: u64,
        table: &StringTable,
        max_len: Option<usize>,
    ) -> Option<String> {
        let value = table.get(address)?;
        let truncated = self.truncate_resolved_string(value, max_len);
        Some(format!("\"{}\"", escape_string(truncated)))
    }

    /// Formats comparison operands, converting integers to character literals when appropriate.
    ///
    /// This detects patterns like `*ptr == 97` (checking for 'a') and formats them as
    /// `*ptr == 'a'` for better readability.
    fn format_char_comparison_operands(
        &self,
        left: &Expr,
        right: &Expr,
        op: BinOpKind,
        _table: &StringTable,
    ) -> (String, String) {
        // First format both sides normally
        let left_str = self.format_expr_no_string_resolve(left);
        let right_str = self.format_expr_no_string_resolve(right);

        // Check if either side is an integer that should be formatted as a character
        let left_is_char_context = self.is_byte_context(left) || looks_like_char_context(&left_str);
        let right_is_char_context =
            self.is_byte_context(right) || looks_like_char_context(&right_str);

        // The "this Var might hold a character" heuristic is only safe for
        // equality comparisons (`x == 'A'`). For ordering comparisons
        // (`x > 100`), char rendering would turn the numeric threshold into
        // a nonsense letter like `'e'`.
        let allow_var_char_promotion = matches!(op, BinOpKind::Eq | BinOpKind::Ne);
        let left_is_var = allow_var_char_promotion && matches!(left.kind, ExprKind::Var(_));
        let right_is_var = allow_var_char_promotion && matches!(right.kind, ExprKind::Var(_));

        let left_str = if let ExprKind::IntLit(n) = &left.kind {
            if is_likely_character_constant(*n) {
                // For very likely character values (letters, digits), always show as char
                format_as_char_literal(*n)
            } else if is_special_char_value(*n) {
                // Special characters (null, tab, newline, CR) only in byte contexts
                if right_is_char_context {
                    format_as_char_literal(*n)
                } else {
                    left_str
                }
            } else if (right_is_char_context || right_is_var) && is_printable_char_value(*n) {
                // Other printable chars when comparing with byte context or variable
                format_as_char_literal(*n)
            } else {
                left_str
            }
        } else {
            left_str
        };

        let right_str = if let ExprKind::IntLit(n) = &right.kind {
            if is_likely_character_constant(*n) {
                // For very likely character values (letters, digits), always show as char
                format_as_char_literal(*n)
            } else if is_special_char_value(*n) {
                // Special characters (null, tab, newline, CR) only in byte contexts
                if left_is_char_context {
                    format_as_char_literal(*n)
                } else {
                    right_str
                }
            } else if (left_is_char_context || left_is_var) && is_printable_char_value(*n) {
                // Other printable chars when comparing with byte context or variable
                format_as_char_literal(*n)
            } else {
                right_str
            }
        } else {
            right_str
        };

        (left_str, right_str)
    }

    /// Checks if an expression represents a byte/character context.
    ///
    /// Returns true for:
    /// - 1-byte dereferences
    /// - Array indexing (which typically accesses bytes)
    /// - Cast to 1-byte type
    fn is_byte_context(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // 1-byte dereference: *(uint8_t*)ptr
            ExprKind::Deref { size, .. } if *size == 1 => true,
            // Cast to 1-byte type
            ExprKind::Cast { to_size, .. } if *to_size == 1 => true,
            _ => false,
        }
    }

    /// Formats an expression, resolving strings from the string table.
    fn format_expr(&self, expr: &Expr) -> String {
        // Always use format_expr_with_strings for stack slot resolution and DWARF names
        // The string table is optional - we pass an empty one if not available
        let empty = super::StringTable::new();
        let table = self.string_table.as_ref().unwrap_or(&empty);
        self.format_expr_with_strings(expr, table)
    }

    /// Formats a condition expression, handling degenerate condition comments.
    /// When a condition is just a comment like /* signed_le */, we couldn't resolve
    /// the actual comparison operands. In this case, output a placeholder that
    /// makes it clear the condition couldn't be fully resolved.
    fn format_condition_expr(&self, expr: &Expr) -> String {
        let formatted = self.format_expr(expr);

        // Check if this is a standalone condition comment (no operands found)
        // These look like "/* signed_le */" or similar
        if let Some(placeholder) = Self::placeholder_condition_name(&formatted) {
            // This is a degenerate condition - we couldn't find the comparison.
            // Emit a named placeholder instead of forcing the branch to look
            // unconditionally taken.
            format!("{placeholder} {formatted}")
        } else {
            formatted
        }
    }

    fn placeholder_condition_name(formatted: &str) -> Option<String> {
        let inner = formatted.strip_prefix("/*")?.strip_suffix("*/")?.trim();
        if inner.is_empty() {
            return Some("cond_unknown".to_string());
        }

        let mut name = String::from("cond_");
        let mut last_was_separator = false;
        for ch in inner.chars() {
            if ch.is_ascii_alphanumeric() {
                name.push(ch.to_ascii_lowercase());
                last_was_separator = false;
            } else if !last_was_separator && !name.ends_with('_') {
                name.push('_');
                last_was_separator = true;
            }
        }

        while name.ends_with('_') {
            name.pop();
        }

        if name == "cond" || name == "cond_" {
            Some("cond_unknown".to_string())
        } else {
            Some(name)
        }
    }

    /// Formats an expression without resolving addresses to string literals.
    /// Used for comparisons and other contexts where string resolution doesn't make sense.
    fn format_expr_no_string_resolve(&self, expr: &Expr) -> String {
        let empty = super::StringTable::new();
        self.format_lvalue(expr, &empty)
    }

    fn format_expr_with_explicit_string_len(
        &self,
        expr: &Expr,
        table: &StringTable,
        max_len: Option<usize>,
    ) -> String {
        match &expr.kind {
            ExprKind::IntLit(n) if *n > 0 && *n < i128::from(u64::MAX) => {
                let addr = *n as u64;
                if let Some(rendered) = self.format_string_literal_at(addr, table, max_len) {
                    return rendered;
                }
                format_integer(*n)
            }
            ExprKind::GotRef { address, .. } => {
                if let Some(rendered) = self.format_string_literal_at(*address, table, max_len) {
                    return rendered;
                }
                self.format_expr_with_strings(expr, table)
            }
            _ => self.format_expr_with_strings(expr, table),
        }
    }

    /// Formats a binary operation's operand, adding parentheses if needed based on precedence.
    /// The child expression needs parentheses if it has lower precedence than the parent operator,
    /// or if it's on the right side of a left-associative operator with the same precedence.
    fn format_binop_operand(
        &self,
        expr: &Expr,
        parent_op: BinOpKind,
        is_right_side: bool,
        table: &StringTable,
    ) -> String {
        let expr_str = self.format_expr_with_strings(expr, table);

        // Check if we need to add parentheses based on precedence
        if let ExprKind::BinOp { op: child_op, .. } = &expr.kind {
            let child_precedence = child_op.precedence();
            let parent_precedence = parent_op.precedence();

            // Add parentheses if:
            // 1. Child has lower precedence than parent
            // 2. For right side of left-associative operators with same precedence
            if child_precedence < parent_precedence
                || (child_precedence == parent_precedence
                    && is_right_side
                    && matches!(
                        parent_op,
                        BinOpKind::Sub
                            | BinOpKind::Div
                            | BinOpKind::Mod
                            | BinOpKind::Shr
                            | BinOpKind::Sar
                    ))
            {
                return format!("({})", expr_str);
            }
        }

        expr_str
    }

    /// Returns true when a `FieldAccess(base, field)` should render as
    /// `base.field` rather than `base->field`. Resolves the type of `base`
    /// per-level: when `base` is itself a `FieldAccess`, we look up the
    /// containing struct/union (in the user type DB, falling back to the
    /// posix/linux/libc builtin DB used by stack-struct binding), then ask
    /// what type the named field has there. So `outer.inner.value` keeps
    /// `.` when `inner` is a struct value, and `outer.next->id` correctly
    /// flips to `->` when `next` is a pointer field — a one-shot walk to
    /// the root would have missed that. Conservative on unknowns: anything
    /// we can't classify keeps the existing `->` rendering.
    fn field_access_uses_dot(&self, base: &Expr) -> bool {
        let Some(ty) = self.expr_type_string(base) else {
            return false;
        };
        Self::type_string_is_struct_value(&ty)
    }

    /// True when a C-syntax type string denotes a `struct` / `union` *value*
    /// (not a pointer or array of one). `to_c_string` formats pointer types
    /// with a `*` anywhere inside the string, so a single `contains('*')`
    /// check is enough to reject `struct foo *`, `struct foo **`, etc.
    fn type_string_is_struct_value(ty: &str) -> bool {
        let trimmed = ty.trim().trim_end_matches(';').trim();
        if trimmed.contains('*') || trimmed.contains("[]") {
            return false;
        }
        trimmed.starts_with("struct ") || trimmed.starts_with("union ")
    }

    /// Best-effort C-syntax type of `expr` for the dot/arrow walk. For a
    /// `Var` we read [`type_info`](Self::type_info) directly; for a
    /// `FieldAccess` we recursively determine the base's type, look up the
    /// containing struct/union in the type DBs, and render the named field's
    /// declared type via [`CType::to_c_string`]. Returns `None` when any
    /// hop can't be classified (missing type entry, type not in any DB,
    /// field name not found) so the caller falls back to `->`.
    fn expr_type_string(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(v) => self
                .type_info
                .get(&v.name)
                .or_else(|| self.type_info.get(&v.name.to_lowercase()))
                .cloned(),
            ExprKind::FieldAccess {
                base, field_name, ..
            } => {
                let base_ty = self.expr_type_string(base)?;
                // Resolve through a pointer hop: `(struct A *).field` looks
                // up field on `struct A`. Multi-level pointers (`**`) don't
                // appear in real C field-access chains, so a single strip
                // is sufficient and we punt on anything weirder.
                let cleaned = base_ty
                    .trim()
                    .trim_end_matches(';')
                    .trim()
                    .trim_end_matches('*')
                    .trim()
                    .to_string();
                let ty = self.lookup_type_in_dbs(&cleaned)?;
                let field_ty = Self::field_ctype_in_aggregate(ty, field_name)?;
                Some(field_ty.to_c_string(None))
            }
            _ => None,
        }
    }

    /// Find a field/member named `field_name` inside a struct/union type
    /// (peeling typedefs first). Returns `None` for non-aggregate types or
    /// when no field by that name exists.
    fn field_ctype_in_aggregate<'a>(
        ty: &'a hexray_types::CType,
        field_name: &str,
    ) -> Option<&'a hexray_types::CType> {
        use hexray_types::CType;
        let mut cur = ty;
        while let CType::Typedef(t) = cur {
            cur = &t.target;
        }
        match cur {
            CType::Struct(s) => s
                .fields
                .iter()
                .find(|f| f.name == field_name)
                .map(|f| &f.field_type),
            CType::Union(u) => u
                .members
                .iter()
                .find(|m| m.name == field_name)
                .map(|m| &m.member_type),
            _ => None,
        }
    }

    /// Look up a type by name in the user-supplied DB (if any), falling back
    /// to the builtin posix/linux/libc DB used by stack-struct binding so
    /// that types introduced by that pass (e.g. `struct epoll_event`) are
    /// always resolvable here even when the host hasn't wired a DB.
    fn lookup_type_in_dbs<'a>(&'a self, name: &str) -> Option<&'a hexray_types::CType> {
        if let Some(db) = self.type_database.as_ref() {
            if let Some(ty) = db.get_type(name) {
                return Some(ty);
            }
        }
        crate::decompiler::stack_struct_binding::builtin_db().get_type(name)
    }

    /// Formats an expression as the base of a postfix operation (array subscript, member access).
    /// Adds parentheses if the base is a binary operation, since [] and . bind tighter than any binary operator.
    fn format_postfix_base(&self, expr: &Expr, table: &StringTable) -> String {
        let expr_str = self.format_expr_with_strings(expr, table);

        // Postfix operators ([] and .) have the highest precedence.
        // Any binary operation as a base needs parentheses.
        if matches!(&expr.kind, ExprKind::BinOp { .. }) {
            return format!("({})", expr_str);
        }

        expr_str
    }

    /// Normalizes known libc global symbols to user-friendly names.
    fn simplify_libc_global_name(&self, raw: &str) -> Option<&'static str> {
        let mut sym = raw;

        // Strip common import prefixes (Windows/PE style)
        if let Some(rest) = sym.strip_prefix("__imp_") {
            sym = rest;
        }
        if let Some(rest) = sym.strip_prefix("imp_") {
            sym = rest;
        }

        // Handle macOS-style triple-underscore prefixed stdio pointers
        // These are ___stderrp, ___stdinp, ___stdoutp on macOS
        if sym.starts_with("___std") {
            match sym {
                "___stderrp" => return Some("stderr"),
                "___stdinp" => return Some("stdin"),
                "___stdoutp" => return Some("stdout"),
                _ => {}
            }
        }

        // Strip leading underscores (common on macOS/ELF)
        while let Some(rest) = sym.strip_prefix('_') {
            sym = rest;
        }

        match sym {
            // Standard I/O streams
            "stdin" | "stdinp" => Some("stdin"),
            "stdout" | "stdoutp" => Some("stdout"),
            "stderr" | "stderrp" => Some("stderr"),

            // Error handling
            "errno" => Some("errno"),
            "h_errno" => Some("h_errno"),

            // Environment
            "environ" | "_environ" => Some("environ"),
            "__environ" => Some("environ"),

            // Program name (GNU extensions)
            "__progname" => Some("__progname"),
            "program_invocation_name" => Some("program_invocation_name"),
            "program_invocation_short_name" => Some("program_invocation_short_name"),

            // getopt globals
            "optind" => Some("optind"),
            "opterr" => Some("opterr"),
            "optarg" => Some("optarg"),
            "optopt" => Some("optopt"),

            // Time zone
            "timezone" => Some("timezone"),
            "daylight" => Some("daylight"),
            "tzname" => Some("tzname"),

            // Error message arrays
            "sys_nerr" => Some("sys_nerr"),
            "sys_errlist" => Some("sys_errlist"),

            // Common libc functions that may appear as globals
            "getenv" => Some("getenv"),
            "setenv" => Some("setenv"),

            _ => None,
        }
    }

    fn simplify_symbol_name(&self, raw: &str) -> String {
        let normalized = self.normalize_pseudo_c_symbol_name(raw);
        self.simplify_libc_global_name(normalized)
            .unwrap_or(normalized)
            .to_string()
    }

    fn relocated_symbol_name(&self, instruction_address: u64, address: u64) -> Option<&str> {
        let reloc_table = self.relocation_table.as_ref()?;
        reloc_table
            .get_got(instruction_address)
            .or_else(|| reloc_table.get_data(instruction_address))
            .or_else(|| reloc_table.get_got(address))
            .or_else(|| reloc_table.get_data(address))
    }

    fn libc_global_matches_candidate(&self, raw: &str, candidate: &str) -> bool {
        self.simplify_libc_global_name(raw) == Some(candidate)
            || self.simplify_libc_global_name(hexray_core::unversioned_symbol_name(raw))
                == Some(candidate)
    }

    fn has_libc_global_evidence(&self, candidate: &str) -> bool {
        self.symbol_table.as_ref().is_some_and(|table| {
            table
                .iter()
                .any(|(_, name)| self.libc_global_matches_candidate(name, candidate))
        }) || self.relocation_table.as_ref().is_some_and(|table| {
            table
                .symbol_names()
                .any(|name| self.libc_global_matches_candidate(name, candidate))
        })
    }

    fn global_deref_prefix(size: u8) -> &'static str {
        match size {
            1 => "*(uint8_t*)",
            2 => "*(uint16_t*)",
            4 => "*(uint32_t*)",
            8 => "*(uint64_t*)",
            _ => "*",
        }
    }

    fn resolve_global_symbol(&self, address: u64) -> Option<GlobalSymbolResolution> {
        let table = self.symbol_table.as_ref()?;

        if let Some(symbol) = table.get_match(address) {
            if symbol.is_defined && symbol.is_data_symbol {
                return Some(GlobalSymbolResolution::Exact(
                    self.simplify_symbol_name(symbol.name),
                ));
            }
        }

        if let Some(symbol) = table.get_containing_match(address) {
            let offset = address.saturating_sub(symbol.address);
            if offset == 0 {
                return Some(GlobalSymbolResolution::Exact(
                    self.simplify_symbol_name(symbol.name),
                ));
            }
            return Some(GlobalSymbolResolution::Interior {
                base_name: self.simplify_symbol_name(symbol.name),
                offset,
            });
        }

        table
            .get_match(address)
            .map(|symbol| GlobalSymbolResolution::Exact(self.simplify_symbol_name(symbol.name)))
    }

    fn format_global_address(&self, address: u64) -> Option<String> {
        match self.resolve_global_symbol(address)? {
            GlobalSymbolResolution::Exact(name) => Some(format!("&{}", name)),
            GlobalSymbolResolution::Interior { base_name, offset } => {
                Some(format!("{} + {}", base_name, offset))
            }
        }
    }

    fn format_exact_global_address(&self, address: u64) -> Option<String> {
        match self.resolve_global_symbol(address)? {
            GlobalSymbolResolution::Exact(name) => Some(format!("&{}", name)),
            GlobalSymbolResolution::Interior { .. } => None,
        }
    }

    fn format_global_value(&self, address: u64, size: u8) -> Option<String> {
        let table = self.symbol_table.as_ref()?;

        if let Some(symbol) = table.get_match(address) {
            if symbol.is_defined && symbol.is_data_symbol {
                let name = self.simplify_symbol_name(symbol.name);
                if symbol.size > u64::from(size) {
                    return Some(self.format_global_field_access(&name, 0));
                }
                return Some(name);
            }
        }

        if let Some(symbol) = table.get_containing_match(address) {
            let offset = address.saturating_sub(symbol.address);
            let base_name = self.simplify_symbol_name(symbol.name);
            return Some(self.format_global_field_access(&base_name, offset));
        }

        match self.resolve_global_symbol(address)? {
            GlobalSymbolResolution::Exact(name) => Some(name),
            GlobalSymbolResolution::Interior { base_name, offset } => Some(format!(
                "{}({} + {})",
                Self::global_deref_prefix(size),
                base_name,
                offset
            )),
        }
    }

    fn try_format_global_address_materialization(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::GotRef {
                address,
                is_deref: false,
                ..
            } => self.format_global_address(*address),
            ExprKind::IntLit(value) if *value > 0 && *value < i128::from(u64::MAX) => {
                self.format_exact_global_address(*value as u64)
            }
            _ => None,
        }
    }

    fn format_global_field_access(&self, base_name: &str, offset: u64) -> String {
        if let Some(field_access) = self.try_format_named_global_field(base_name, offset) {
            return field_access;
        }

        if offset == 0 {
            format!("{base_name}.field_0")
        } else {
            format!("{base_name}.field_{offset:x}")
        }
    }

    fn try_format_named_global_field(&self, base_name: &str, offset: u64) -> Option<String> {
        let type_db = self.type_database.as_ref()?;
        let type_str = self.type_info.get(base_name)?;
        let rest = type_str.strip_prefix("struct ")?;
        let name_end = rest.find(['*', ' ']).unwrap_or(rest.len());
        let struct_name = format!("struct {}", rest[..name_end].trim());
        let field_access =
            type_db.format_field_access(&struct_name, usize::try_from(offset).ok()?)?;
        Some(format!("{base_name}{field_access}"))
    }

    fn try_extract_materialized_address(expr: &Expr) -> Option<u64> {
        match &expr.kind {
            ExprKind::GotRef {
                address,
                is_deref: false,
                ..
            } => Some(*address),
            ExprKind::IntLit(value) if *value > 0 && *value < i128::from(u64::MAX) => {
                Some(*value as u64)
            }
            _ => None,
        }
    }

    fn strip_plt_suffix(name: &str) -> &str {
        name.split_once("@plt").map_or(name, |(base, _)| base)
    }

    fn is_glibc_family_version(version_name: &str) -> bool {
        version_name.starts_with("GLIBC_") || version_name.starts_with("GLIBCXX_")
    }

    fn collect_ambiguous_gnu_version_bases(&self) -> HashSet<String> {
        let mut names_by_base: HashMap<String, HashSet<String>> = HashMap::new();
        let mut has_glibc_version = HashSet::new();

        let mut record = |name: &str| {
            let bare = Self::strip_plt_suffix(name);
            let base = hexray_core::unversioned_symbol_name(bare);
            names_by_base
                .entry(base.to_string())
                .or_default()
                .insert(bare.to_string());
            if hexray_core::gnu_symbol_version(bare)
                .is_some_and(|version| Self::is_glibc_family_version(version.name))
            {
                has_glibc_version.insert(base.to_string());
            }
        };

        if let Some(symbol_table) = &self.symbol_table {
            for (_, name) in symbol_table.iter() {
                record(name);
            }
        }

        if let Some(relocation_table) = &self.relocation_table {
            for name in relocation_table.symbol_names() {
                record(name);
            }
        }

        names_by_base
            .into_iter()
            .filter_map(|(base, names)| {
                (names.len() > 1 && has_glibc_version.contains(base.as_str())).then_some(base)
            })
            .collect()
    }

    fn has_ambiguous_gnu_version_base(&self, base_name: &str) -> bool {
        if self.gnu_version_ambiguous_bases.borrow().is_none() {
            let ambiguous = self.collect_ambiguous_gnu_version_bases();
            *self.gnu_version_ambiguous_bases.borrow_mut() = Some(ambiguous);
        }

        self.gnu_version_ambiguous_bases
            .borrow()
            .as_ref()
            .is_some_and(|bases| bases.contains(base_name))
    }

    /// Strips GLIBC/GLIBCXX version suffixes for pseudo-C output unless the
    /// current binary imports multiple symbols with the same unversioned base.
    fn strip_glibc_version_suffix<'a>(&self, name: &'a str) -> &'a str {
        let Some(version) = hexray_core::gnu_symbol_version(name) else {
            return name;
        };
        if !Self::is_glibc_family_version(version.name) {
            return name;
        }

        let base = hexray_core::unversioned_symbol_name(name);
        if self.has_ambiguous_gnu_version_base(base) {
            name
        } else {
            base
        }
    }

    fn normalize_pseudo_c_symbol_name<'a>(&self, name: &'a str) -> &'a str {
        let stripped = Self::strip_plt_suffix(name);
        self.strip_glibc_version_suffix(stripped)
    }

    fn strip_demangled_signature(name: &str) -> &str {
        strip_demangled_symbol_signature(name)
    }

    fn format_call_target_name(&self, name: &str) -> String {
        let normalized = self.normalize_pseudo_c_symbol_name(name);
        // Relocation tables hand the emitter the raw mangled symbol name
        // (`_ZNRSt8optionalIiEdeEv`); the SymbolTable already pre-demangles
        // at load time but relocation lookups bypass that path. Render call
        // sites with the demangled form when the input is mangled so the
        // pseudo-C reads `std::optional<int>::operator*()` instead of
        // surfacing the raw Itanium-ABI string. Falls through unchanged
        // when the name is already demangled or isn't mangled at all.
        let demangled_owned = hexray_demangle::demangle(normalized);
        let source: &str = demangled_owned.as_deref().unwrap_or(normalized);
        // Strip cv- and ref-qualifiers that Itanium-ABI demangling appends
        // to method names (`has_value() const`, `operator*() &`,
        // `bar() && noexcept`). Without this the trailing `(args)` we
        // append below produces awkward forms like `has_value() const(...)`.
        let qualifier_stripped = Self::strip_method_cvref_qualifiers(source);
        // Strip ctor/dtor / clone disambiguator labels (`Dog::Dog() [base]`,
        // `foo() [clone .cold]`); without this the embedded `()` survives
        // the next step and we end up with `Dog::Dog() [base](...)`.
        let label_stripped =
            crate::symbol_names::strip_demangler_disambiguator_labels(qualifier_stripped);
        Self::strip_demangled_signature(label_stripped).to_string()
    }

    /// Repeatedly strip trailing C++ method qualifiers from a demangled
    /// name so the leftover identifier is a clean
    /// `Namespace::Class::method` chain. Itanium-ABI demangling emits
    /// these in any combination (`const`, `volatile`, `&`, `&&`,
    /// `noexcept`); the trimmer walks them off in any order. Operates on
    /// the borrowed source so callers can keep the demangled string
    /// allocated once and pass references around.
    fn strip_method_cvref_qualifiers(name: &str) -> &str {
        let mut s = name.trim_end();
        loop {
            let mut shrank = false;
            for suffix in [" const", " volatile", " &&", " &", " noexcept"] {
                if let Some(stripped) = s.strip_suffix(suffix) {
                    s = stripped.trim_end();
                    shrank = true;
                    break;
                }
            }
            if !shrank {
                break;
            }
        }
        s
    }

    fn format_indirect_got_call_target(&self, name: &str) -> String {
        format!("(*{}@got)", self.normalize_pseudo_c_symbol_name(name))
    }

    fn is_tls_get_addr_name(name: &str) -> bool {
        let stripped = Self::strip_plt_suffix(name);
        let unversioned = hexray_core::unversioned_symbol_name(stripped);
        unversioned == "__tls_get_addr"
    }

    fn is_thread_pointer_expr(expr: &Expr) -> bool {
        matches!(
            &Self::strip_expr_casts(expr).kind,
            ExprKind::Call {
                target: CallTarget::Named(name),
                args,
            } if args.is_empty()
                && hexray_core::unversioned_symbol_name(Self::strip_plt_suffix(name))
                    == "__builtin_thread_pointer"
        )
    }

    fn try_format_tls_descriptor_arg(&self, expr: &Expr) -> Option<String> {
        let descriptor_addr = Self::try_extract_materialized_address(expr)?;
        let relocations = self.relocation_table.as_ref()?;
        let symbol = relocations.get_tls_descriptor(descriptor_addr)?;
        let simplified = self.simplify_symbol_name(symbol);
        Some(format!("&_TLS_{simplified}_"))
    }

    fn try_format_tls_thread_pointer_access(
        &self,
        base: &Expr,
        index: &Expr,
        element_size: usize,
    ) -> Option<String> {
        if !Self::is_thread_pointer_expr(base) {
            return None;
        }

        let ExprKind::IntLit(index) = &Self::strip_expr_casts(index).kind else {
            return None;
        };
        let index = i64::try_from(*index).ok()?;
        let element_size = i64::try_from(element_size).ok()?;
        let byte_offset = index.checked_mul(element_size)?;
        self.tls_symbol_offsets.get(&byte_offset).cloned()
    }

    fn try_format_global_array_base(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::IntLit(value) if *value > 0 && *value < i128::from(u64::MAX) => {
                match self.resolve_global_symbol(*value as u64)? {
                    GlobalSymbolResolution::Exact(name) => Some(name),
                    GlobalSymbolResolution::Interior { base_name, offset } => {
                        Some(format!("{} + {}", base_name, offset))
                    }
                }
            }
            ExprKind::GotRef {
                address,
                is_deref: false,
                ..
            } => match self.resolve_global_symbol(*address)? {
                GlobalSymbolResolution::Exact(name) => Some(name),
                GlobalSymbolResolution::Interior { base_name, offset } => {
                    Some(format!("{} + {}", base_name, offset))
                }
            },
            _ => None,
        }
    }

    /// Generates a fallback name for an unknown global address based on usage context.
    ///
    /// The naming strategy (in priority order):
    /// - Check for well-known libc globals by address patterns (stdin/stdout/stderr)
    /// - Use explicit usage hints for semantic naming
    /// - Fall back to type-based naming with size hints
    ///
    /// Prefixes:
    /// - `g_stdin/g_stdout/g_stderr` - standard I/O streams
    /// - `g_counter_XXXX` - incremented/decremented variables
    /// - `g_const_XXXX` - read-only globals
    /// - `g_state_XXXX` - write-heavy state variables
    /// - `g_str_XXXX` - string pointers
    /// - `g_arr_XXXX` - array base pointers
    /// - `g_ptr_XXXX` - general pointer dereference
    /// - `g_flags_XXXX` - bitwise operation targets
    /// - `g_func_XXXX` - function pointers
    /// - `g_XXXX` - default fallback
    fn format_global_fallback_name(&self, address: u64, hint: GlobalUsageHint) -> String {
        // Check for cached name first (consistency within emission)
        if let Some(cached) = self.global_tracker.borrow().get_cached_name(address) {
            return cached.to_string();
        }

        // Check for well-known libc globals by common address patterns
        if let Some(libc_name) = Self::detect_libc_global_by_pattern(address) {
            if self.has_libc_global_evidence(libc_name) {
                let name = format!("g_{}", libc_name);
                self.global_tracker
                    .borrow_mut()
                    .cache_name(address, name.clone());
                return name;
            }
        }

        // Get the best hint by combining explicit hint with inferred patterns
        // PointerDeref is a low-priority default, so we still try inference
        let tracker = self.global_tracker.borrow();
        let best_hint = if hint != GlobalUsageHint::Unknown && hint != GlobalUsageHint::PointerDeref
        {
            // Strong hint - use it directly
            hint
        } else {
            // Try inference first, fall back to provided hint
            let inferred = tracker.infer_best_hint(address);
            if inferred != GlobalUsageHint::Unknown {
                inferred
            } else {
                hint
            }
        };
        let size_hint = tracker.get_size_hint(address);
        drop(tracker);

        let prefix = match best_hint {
            GlobalUsageHint::StdioStream => "g_stream",
            GlobalUsageHint::Counter => "g_counter",
            GlobalUsageHint::ReadOnly => "g_const",
            GlobalUsageHint::WriteHeavy => "g_state",
            GlobalUsageHint::StringPointer => "g_str",
            GlobalUsageHint::ArrayBase => "g_arr",
            GlobalUsageHint::PointerDeref => "g_ptr",
            GlobalUsageHint::BitwiseOps => "g_flags",
            GlobalUsageHint::FunctionPointer => "g_func",
            GlobalUsageHint::Unknown => {
                // Use size-based prefix for unknown globals
                match size_hint {
                    GlobalSizeHint::Byte => "g_byte",
                    GlobalSizeHint::Word => "g_word",
                    GlobalSizeHint::DWord => "g_dword",
                    GlobalSizeHint::QWord => "g_qword",
                    GlobalSizeHint::Unknown => "g",
                }
            }
        };

        let name = format!("{}_{:x}", prefix, address);
        self.global_tracker
            .borrow_mut()
            .cache_name(address, name.clone());
        name
    }

    /// Detects well-known libc globals by address patterns.
    ///
    /// On many systems, stdin/stdout/stderr are at predictable addresses
    /// relative to each other (often 8 bytes apart in .bss).
    fn detect_libc_global_by_pattern(address: u64) -> Option<&'static str> {
        // Common patterns for stdio streams:
        // - Often in .bss section, consecutive 8-byte pointers
        // - Sometimes named _IO_stdin, _IO_stdout, _IO_stderr in glibc
        // - Address endings can hint at which stream it is

        // Check for common address suffixes that correlate with stdio streams
        // These are heuristics based on typical linker layouts
        let addr_low = address & 0xFFF; // Lower 12 bits

        // Some binaries have stdio at predictable offsets
        // This is a heuristic - not foolproof but helps in many cases
        match addr_low {
            // Common glibc patterns (stdin often at 0x40, stdout at 0x48, stderr at 0x50)
            0x040 | 0x840 | 0x1040 => Some("stdin"),
            0x048 | 0x848 | 0x1048 => Some("stdout"),
            0x050 | 0x850 | 0x1050 => Some("stderr"),
            _ => None,
        }
    }

    /// Records a global access and returns the appropriate fallback name.
    fn record_and_name_global(&self, address: u64, hint: GlobalUsageHint) -> String {
        self.global_tracker
            .borrow_mut()
            .record_access(address, hint);
        self.format_global_fallback_name(address, hint)
    }

    /// Records a global access with size information for type inference.
    fn record_and_name_global_with_size(
        &self,
        address: u64,
        hint: GlobalUsageHint,
        size: u8,
    ) -> String {
        {
            let mut tracker = self.global_tracker.borrow_mut();
            tracker.record_access(address, hint);
            tracker.record_size(address, size);
        }
        self.format_global_fallback_name(address, hint)
    }

    /// Records a global read access (rvalue usage).
    fn record_global_read(&self, address: u64) {
        self.global_tracker.borrow_mut().record_read(address);
    }

    /// Records a global write access (lvalue usage).
    fn record_global_write(&self, address: u64) {
        self.global_tracker.borrow_mut().record_write(address);
    }

    /// Records a global increment/decrement operation.
    fn record_global_increment(&self, address: u64) {
        self.global_tracker.borrow_mut().record_increment(address);
    }

    /// Marks a global as a string pointer (points to string data).
    fn mark_global_as_string(&self, address: u64) {
        self.global_tracker
            .borrow_mut()
            .record_access(address, GlobalUsageHint::StringPointer);
    }

    /// Marks a global as an array base pointer.
    fn mark_global_as_array(&self, address: u64) {
        self.global_tracker
            .borrow_mut()
            .record_access(address, GlobalUsageHint::ArrayBase);
    }

    /// Pre-scans structured nodes to gather global access patterns.
    /// This must run before emission so naming can use the inferred patterns.
    fn prescan_global_accesses(&self, nodes: &[StructuredNode]) {
        for node in nodes {
            self.prescan_node(node);
        }
    }

    /// Pre-scans a single node for global accesses.
    fn prescan_node(&self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.prescan_expr(stmt, false);
                }
            }
            StructuredNode::Expr(expr) => {
                // Check if this is an assignment
                if let ExprKind::Assign { lhs, rhs } = &expr.kind {
                    // Left side is a write
                    self.prescan_expr(lhs, true);
                    // Check for increment pattern: x = x + 1
                    if let Some(addr) = Self::extract_gotref_address(lhs) {
                        if self.is_increment_pattern(lhs, rhs) {
                            self.record_global_increment(addr);
                        }
                    }
                    // Right side is a read
                    self.prescan_expr(rhs, false);
                } else {
                    self.prescan_expr(expr, false);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                self.prescan_expr(condition, false);
                self.prescan_global_accesses(then_body);
                if let Some(eb) = else_body {
                    self.prescan_global_accesses(eb);
                }
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                self.prescan_expr(condition, false);
                self.prescan_global_accesses(body);
            }
            StructuredNode::DoWhile {
                condition, body, ..
            } => {
                self.prescan_global_accesses(body);
                self.prescan_expr(condition, false);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(i) = init {
                    self.prescan_expr(i, false);
                }
                self.prescan_expr(condition, false);
                if let Some(u) = update {
                    self.prescan_expr(u, false);
                }
                self.prescan_global_accesses(body);
            }
            StructuredNode::Loop { body, .. } => {
                self.prescan_global_accesses(body);
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                self.prescan_expr(value, false);
                for (_, case_body) in cases {
                    self.prescan_global_accesses(case_body);
                }
                if let Some(d) = default {
                    self.prescan_global_accesses(d);
                }
            }
            StructuredNode::Return(Some(expr)) => {
                self.prescan_expr(expr, false);
            }
            StructuredNode::Sequence(seq) => {
                self.prescan_global_accesses(seq);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                self.prescan_global_accesses(try_body);
                for h in catch_handlers {
                    self.prescan_global_accesses(&h.body);
                }
            }
            _ => {}
        }
    }

    /// Pre-scans an expression for global accesses.
    fn prescan_expr(&self, expr: &Expr, is_write: bool) {
        match &expr.kind {
            ExprKind::GotRef {
                address, is_deref, ..
            } => {
                if is_write {
                    self.record_global_write(*address);
                } else if *is_deref {
                    self.record_global_read(*address);
                }
            }
            ExprKind::Deref { addr, .. } => {
                if let Some(address) = Self::extract_gotref_address(addr) {
                    if is_write {
                        self.record_global_write(address);
                    } else {
                        self.record_global_read(address);
                    }
                }
                self.prescan_expr(addr, false);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.prescan_expr(lhs, true);
                // Check for increment pattern
                if let Some(addr) = Self::extract_gotref_address(lhs) {
                    if self.is_increment_pattern(lhs, rhs) {
                        self.record_global_increment(addr);
                    }
                }
                self.prescan_expr(rhs, false);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.prescan_expr(left, false);
                self.prescan_expr(right, false);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.prescan_expr(operand, false);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.prescan_expr(inner, is_write);
            }
            ExprKind::Call { target, args } => {
                if let CallTarget::Indirect(e) = target {
                    self.prescan_expr(e, false);
                }
                for arg in args {
                    self.prescan_expr(arg, false);
                }
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.prescan_expr(base, false);
                self.prescan_expr(index, false);
            }
            ExprKind::AddressOf(inner) => {
                self.prescan_expr(inner, false);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.prescan_expr(cond, false);
                self.prescan_expr(then_expr, false);
                self.prescan_expr(else_expr, false);
            }
            _ => {}
        }
    }

    /// Checks if an assignment is an increment pattern (x = x + 1 or x = x - 1).
    fn is_increment_pattern(&self, lhs: &Expr, rhs: &Expr) -> bool {
        if let ExprKind::BinOp {
            op: BinOpKind::Add | BinOpKind::Sub,
            left,
            right,
        } = &rhs.kind
        {
            // Check if left operand matches lhs
            let lhs_addr = Self::extract_gotref_address(lhs);
            let left_addr = Self::extract_gotref_address(left);
            if lhs_addr.is_some() && lhs_addr == left_addr {
                // Check if right is a small constant
                if let ExprKind::IntLit(val) = &right.kind {
                    return *val >= -10 && *val <= 10;
                }
            }
        }
        false
    }

    /// Checks if a statement is a gcov counter increment/readback artifact.
    fn is_gcov_counter_statement(&self, expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => self.is_gcov_counter_increment(lhs, rhs),
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                matches!(op, BinOpKind::Add | BinOpKind::Sub)
                    && Self::is_unit_step_literal(rhs)
                    && self.expr_references_gcov_counter(lhs)
            }
            _ => false,
        }
    }

    fn is_gcov_counter_increment(&self, _lhs: &Expr, rhs: &Expr) -> bool {
        let ExprKind::BinOp { op, left, right } = &rhs.kind else {
            return false;
        };
        if !matches!(op, BinOpKind::Add | BinOpKind::Sub) || !Self::is_unit_step_literal(right) {
            return false;
        }

        self.expr_references_gcov_counter(left)
    }

    fn expr_references_gcov_counter(&self, expr: &Expr) -> bool {
        if let Some(address) = Self::extract_gotref_address(expr) {
            if let Some(symbol_table) = self.symbol_table.as_ref() {
                if let Some(name) = symbol_table
                    .get(address)
                    .or_else(|| symbol_table.get_containing(address))
                {
                    return Self::is_gcov_symbol_name(name);
                }
            }
        }

        match &expr.kind {
            ExprKind::Var(var) => Self::is_gcov_symbol_name(&var.name),
            ExprKind::Unknown(name) => Self::is_gcov_symbol_name(name),
            ExprKind::AddressOf(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.expr_references_gcov_counter(inner)
            }
            ExprKind::Deref { addr, .. } => self.expr_references_gcov_counter(addr),
            _ => false,
        }
    }

    fn is_gcov_symbol_name(name: &str) -> bool {
        name.starts_with("__gcov") || name.starts_with("_gcov")
    }

    fn is_unit_step_literal(expr: &Expr) -> bool {
        matches!(expr.kind, ExprKind::IntLit(1))
    }

    /// Extracts the GotRef address from an expression, if present.
    /// Traverses through Deref and Cast to find the underlying GotRef.
    fn extract_gotref_address(expr: &Expr) -> Option<u64> {
        match &expr.kind {
            ExprKind::GotRef { address, .. } => Some(*address),
            ExprKind::Deref { addr, .. } => Self::extract_gotref_address(addr),
            ExprKind::AddressOf(inner) => Self::extract_gotref_address(inner),
            ExprKind::Cast { expr: inner, .. } => Self::extract_gotref_address(inner),
            _ => None,
        }
    }

    /// Returns the global access tracker for analysis.
    pub fn global_tracker(&self) -> std::cell::Ref<'_, GlobalAccessTracker> {
        self.global_tracker.borrow()
    }

    /// Recursively marks any GotRef expressions as function pointers.
    fn mark_gotref_as_funcptr(&self, expr: &Expr) {
        match &expr.kind {
            ExprKind::GotRef { address, .. } => {
                self.global_tracker
                    .borrow_mut()
                    .record_access(*address, GlobalUsageHint::FunctionPointer);
            }
            ExprKind::Deref { addr, .. } => self.mark_gotref_as_funcptr(addr),
            ExprKind::Cast { expr: inner, .. } => self.mark_gotref_as_funcptr(inner),
            ExprKind::BinOp { left, right, .. } => {
                self.mark_gotref_as_funcptr(left);
                self.mark_gotref_as_funcptr(right);
            }
            _ => {}
        }
    }

    /// Recursively marks any GotRef expressions used in bitwise operations.
    fn mark_gotref_as_bitwise(&self, expr: &Expr) {
        match &expr.kind {
            ExprKind::GotRef { address, .. } => {
                self.global_tracker
                    .borrow_mut()
                    .record_access(*address, GlobalUsageHint::BitwiseOps);
            }
            ExprKind::Deref { addr, .. } => self.mark_gotref_as_bitwise(addr),
            ExprKind::Cast { expr: inner, .. } => self.mark_gotref_as_bitwise(inner),
            ExprKind::BinOp { left, right, .. } => {
                self.mark_gotref_as_bitwise(left);
                self.mark_gotref_as_bitwise(right);
            }
            _ => {}
        }
    }

    /// Best-effort recognition for libc globals from already-formatted text fragments.
    fn simplify_libc_global_text(&self, raw: &str) -> Option<&'static str> {
        let trimmed = raw.trim();
        let lowered = trimmed.to_lowercase();

        for candidate in ["stderr", "stdout", "stdin", "errno"] {
            if lowered == candidate
                || lowered.ends_with(&format!("({candidate})"))
                || lowered.contains(&format!("*{candidate}"))
                || lowered.contains(&format!("&{candidate}"))
            {
                return Some(candidate);
            }
        }
        None
    }

    /// Formats dereference chains rooted in known libc globals as `*name` / `**name`.
    fn try_format_libc_global_deref_chain(&self, addr: &Expr) -> Option<String> {
        let mut deref_depth = 1usize;
        let mut cursor = addr;

        loop {
            match &cursor.kind {
                ExprKind::Deref { addr: inner, .. } => {
                    deref_depth += 1;
                    cursor = inner;
                }
                // Strip no-op casts around pointer expressions.
                ExprKind::Cast { expr: inner, .. } => {
                    cursor = inner;
                }
                _ => break,
            }
        }

        let alias = match &cursor.kind {
            ExprKind::GotRef {
                address,
                instruction_address,
                ..
            } => {
                if let Some(name) = self.relocated_symbol_name(*instruction_address, *address) {
                    self.simplify_libc_global_name(name)
                } else if let Some(ref sym_table) = self.symbol_table {
                    sym_table
                        .get(*address)
                        .and_then(|name| self.simplify_libc_global_name(name))
                } else {
                    None
                }
            }
            ExprKind::Var(v) => self.simplify_libc_global_name(&v.name),
            // Some lowering paths keep global names as unknown textual atoms.
            ExprKind::Unknown(s) => self.simplify_libc_global_name(s),
            _ => None,
        }?;

        Some(format!("{}{}", "*".repeat(deref_depth), alias))
    }

    fn strip_expr_casts(expr: &Expr) -> &Expr {
        let mut current = expr;
        while let ExprKind::Cast { expr, .. } = &current.kind {
            current = expr;
        }
        current
    }

    fn parse_virtual_target<'a>(&self, expr: &'a Expr) -> Option<(&'a Expr, usize)> {
        let expr = Self::strip_expr_casts(expr);
        let ExprKind::Deref { addr, .. } = &expr.kind else {
            return None;
        };

        let (vptr_expr, slot_offset) = match &Self::strip_expr_casts(addr).kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                let ExprKind::IntLit(offset) = Self::strip_expr_casts(right).kind else {
                    return None;
                };
                let offset = usize::try_from(offset).ok()?;
                (left.as_ref(), offset)
            }
            _ => (addr.as_ref(), 0),
        };

        let vptr_expr = Self::strip_expr_casts(vptr_expr);
        let ExprKind::Deref {
            addr: object_expr, ..
        } = &vptr_expr.kind
        else {
            return None;
        };
        Some((Self::strip_expr_casts(object_expr), slot_offset))
    }

    fn try_format_virtual_dispatch(
        &self,
        target: &CallTarget,
        args: &[Expr],
        table: &StringTable,
    ) -> Option<String> {
        let CallTarget::Indirect(target_expr) = target else {
            return None;
        };
        let (target_object, slot_offset) = self.parse_virtual_target(target_expr)?;
        let object_expr = if let Some(object_arg) = args.first() {
            let object_arg = Self::strip_expr_casts(object_arg);
            if !exprs_equal(target_object, object_arg) {
                return None;
            }
            object_arg
        } else {
            target_object
        };

        let object_text = self.format_expr_with_strings(object_expr, table);
        let rendered_args = if args.is_empty() {
            vec![object_text.clone()]
        } else {
            let mut rendered = vec![object_text.clone()];
            rendered.extend(
                args.iter()
                    .skip(1)
                    .map(|arg| self.format_expr_with_strings(arg, table)),
            );
            rendered
        };

        // TODO: Recover slot names from the vtable database once class metadata
        // is threaded through the emitter.
        Some(format!(
            "(({})->vftable[{}])({})",
            object_text,
            slot_offset / 8,
            rendered_args.join(", ")
        ))
    }

    /// Formats an lvalue (left-hand side of assignment).
    /// This is like format_expr_with_strings but doesn't resolve addresses to string literals,
    /// since you can't assign to a string literal.
    fn format_lvalue(&self, expr: &Expr, table: &StringTable) -> String {
        match &expr.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                if let ExprKind::Var(v) = &base.kind {
                    if (v.name == "rip" || v.name == "eip")
                        && matches!(index.kind, ExprKind::IntLit(_))
                    {
                        if let ExprKind::IntLit(idx) = &index.kind {
                            let byte_offset = (*idx as u64).wrapping_mul(*element_size as u64);
                            // Try to find a symbol at this relative offset
                            if let Some(ref sym_table) = self.symbol_table {
                                if let Some(name) = sym_table.get(byte_offset) {
                                    if let Some(alias) = self.simplify_libc_global_name(name) {
                                        return alias.to_string();
                                    }
                                    return name.to_string();
                                }
                            }
                            // Fall back to a typed dereference of a global address (lvalue)
                            let prefix = match element_size {
                                1 => "*(uint8_t*)",
                                2 => "*(uint16_t*)",
                                4 => "*(uint32_t*)",
                                8 => "*(uint64_t*)",
                                _ => "*",
                            };
                            return format!("{}(&g_{:x})", prefix, byte_offset);
                        }
                    }
                }
                self.format_expr_with_strings(expr, table)
            }
            // For GotRef as lvalue, never resolve to string - use data_ naming
            ExprKind::GotRef {
                address,
                instruction_address,
                size,
                is_deref,
                ..
            } => {
                if let Some(name) = self.relocated_symbol_name(*instruction_address, *address) {
                    let resolved = self.simplify_symbol_name(name);
                    if *is_deref {
                        return resolved;
                    }
                    return format!("&{}", resolved);
                }
                if *is_deref {
                    if let Some(value) = self.format_global_value(*address, *size) {
                        return value;
                    }
                } else if let Some(address_text) = self.format_global_address(*address) {
                    return address_text;
                }
                // Skip string table lookup for lvalues - you can't write to string literals
                // Fall back to context-aware naming (lvalues are pointer derefs)
                // Record as a write access since this is an lvalue
                self.record_global_write(*address);
                if *is_deref {
                    let name = self.record_and_name_global_with_size(
                        *address,
                        GlobalUsageHint::PointerDeref,
                        *size,
                    );
                    format!("{}(&{})", Self::global_deref_prefix(*size), name)
                } else {
                    self.record_and_name_global(*address, GlobalUsageHint::PointerDeref)
                }
            }
            // For other expression types, delegate to format_expr_with_strings
            _ => self.format_expr_with_strings(expr, table),
        }
    }

    /// Formats an expression with string resolution.
    fn format_expr_with_strings(&self, expr: &Expr, table: &StringTable) -> String {
        match &expr.kind {
            ExprKind::IntLit(n) => {
                // Check if this integer might be a string address
                if *n > 0 && *n < i128::from(u64::MAX) {
                    let addr = *n as u64;
                    if let Some(s) = table.get(addr) {
                        // Escape the string for C output
                        return format!("\"{}\"", escape_string(s));
                    }
                }
                // Format integers as decimal for readability
                format_integer(*n)
            }
            ExprKind::BinOp { op, left, right } => {
                // Mark globals involved in bitwise operations for better naming
                if matches!(op, BinOpKind::Or | BinOpKind::And | BinOpKind::Xor) {
                    self.mark_gotref_as_bitwise(left);
                    self.mark_gotref_as_bitwise(right);
                }

                // Simplify constant folding for chained operations: (a op c1) op c2 -> a op (c1 op c2)
                if let Some(simplified) = self.try_fold_chained_constants(op, left, right, table) {
                    return simplified;
                }

                // For comparison operators, don't resolve the operands to strings
                // because comparisons like `ptr == 0` should show the pointer variable,
                // not the string it points to (e.g., "hello" == 0 doesn't make sense)
                if op.is_comparison() {
                    // Check if this looks like a character comparison and format accordingly
                    let (left_str, right_str) =
                        self.format_char_comparison_operands(left, right, *op, table);
                    format!("{} {} {}", left_str, op.as_str(), right_str)
                } else {
                    // Use precedence-aware formatting for arithmetic operations
                    let left_str = self.format_binop_operand(left, *op, false, table);
                    let right_str = self.format_binop_operand(right, *op, true, table);
                    format!("{} {} {}", left_str, op.as_str(), right_str)
                }
            }
            ExprKind::UnaryOp { op, operand } => {
                let operand_text = self.format_expr_with_strings(operand, table);
                let needs_parens = matches!(
                    operand.kind,
                    ExprKind::BinOp { .. }
                        | ExprKind::Assign { .. }
                        | ExprKind::CompoundAssign { .. }
                        | ExprKind::Conditional { .. }
                );
                if needs_parens {
                    format!("{}({})", op.as_str(), operand_text)
                } else {
                    format!("{}{}", op.as_str(), operand_text)
                }
            }
            ExprKind::Deref { addr, size } => {
                // Special case: nested dereferences rooted at libc globals.
                if let Some(simplified) = self.try_format_libc_global_deref_chain(addr) {
                    return simplified;
                }
                if let ExprKind::IntLit(address) = &addr.kind {
                    if let Ok(address) = u64::try_from(*address) {
                        if let Some(value) = self.format_global_value(address, *size) {
                            return value;
                        }
                    }
                }
                // Check if this is a stack slot access (rbp + offset or rbp - offset)
                if let Some(var_name) = self.try_format_stack_slot(addr, *size) {
                    return var_name;
                }
                // Check if this is a struct field access using the type database
                if let Some(field_access) =
                    self.try_format_struct_field(addr, *size as usize, table)
                {
                    return field_access;
                }
                // Check if this is an array access pattern: base + index * size
                if let Some((base, index)) = try_extract_array_access(addr, *size) {
                    // Don't resolve strings in array base/index - those should be pointers
                    // Use format_postfix_base to add parentheses if base is a binary operation
                    let empty = super::StringTable::new();
                    let base_str = self
                        .try_format_global_array_base(&base)
                        .unwrap_or_else(|| self.format_postfix_base(&base, &empty));
                    let index_str = self.format_expr_no_string_resolve(&index);
                    return format!("{}[{}]", base_str, index_str);
                }
                // Check if this is a RIP/EIP-relative address (global variable reference)
                if let Some(offset) = try_extract_rip_relative_offset(addr) {
                    if let Some(value) = self.format_global_value(offset, *size) {
                        return value;
                    }
                    return format!("{}(&g_{:x})", Self::global_deref_prefix(*size), offset);
                }
                // Fall back to default deref formatting
                // Don't resolve strings in deref address - dereferencing a string literal
                // doesn't make sense. Show the pointer/data variable instead.
                let addr_text = self.format_expr_no_string_resolve(addr);
                if let Some(alias) = self.simplify_libc_global_text(&addr_text) {
                    return format!("*{}", alias);
                }
                format!("{}({})", Self::global_deref_prefix(*size), addr_text)
            }
            ExprKind::Assign { lhs, rhs } => {
                let preserve_snapshot_rhs = self.register_snapshot_mode.get()
                    && Self::expr_contains_snapshot_register_source(rhs);
                let preserve_snapshot_lhs =
                    self.register_snapshot_mode.get() && self.lhs_is_snapshot_register(lhs);

                // Check for compound assignment patterns: x = x op y → x op= y
                if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                    if exprs_equal(lhs, left) {
                        if matches!(op, BinOpKind::Or | BinOpKind::And | BinOpKind::Xor) {
                            // Mark globals used in bitwise ops for better naming
                            self.mark_gotref_as_bitwise(lhs);
                            self.mark_gotref_as_bitwise(right);
                            if let Some(flag_name) = self.try_format_flag_lvalue(lhs) {
                                if let ExprKind::IntLit(mask) = right.kind {
                                    if let Some(compound_op) = op.compound_op_str() {
                                        return format!(
                                            "{} {}= {}",
                                            flag_name,
                                            compound_op,
                                            self.format_flag_mask(mask)
                                        );
                                    }
                                }
                            }
                        }
                        // For lhs, don't resolve strings (can't write to string literals)
                        let lhs_str = if preserve_snapshot_lhs {
                            self.format_lvalue_preserving_register_names(lhs, table)
                        } else {
                            self.format_lvalue(lhs, table)
                        };
                        let rhs_str = if preserve_snapshot_rhs {
                            self.format_expr_preserving_register_names(right, table)
                        } else if let Some(address_str) =
                            self.try_format_global_address_materialization(right)
                        {
                            address_str
                        } else {
                            self.format_expr_with_strings(right, table)
                        };

                        // Special case: x = x + 1 → x++ and x = x - 1 → x--
                        if let ExprKind::IntLit(1) = right.kind {
                            match op {
                                super::expression::BinOpKind::Add => {
                                    // Track increment for counter detection
                                    if let Some(addr) = Self::extract_gotref_address(lhs) {
                                        self.record_global_increment(addr);
                                    }
                                    return format!("{}++", lhs_str);
                                }
                                super::expression::BinOpKind::Sub => {
                                    // Track decrement for counter detection
                                    if let Some(addr) = Self::extract_gotref_address(lhs) {
                                        self.record_global_increment(addr);
                                    }
                                    return format!("{}--", lhs_str);
                                }
                                _ => {}
                            }
                        }

                        // General compound assignment: x = x op y → x op= y
                        if let Some(compound_op) = op.compound_op_str() {
                            return format!("{} {}= {}", lhs_str, compound_op, rhs_str);
                        }
                    }
                }
                // Field-category-aware RHS: e.g. `epoll_event_14.events =
                // EPOLLIN | EPOLLRDHUP` instead of `… = 8193`. Mirrors the
                // category dispatch used for call args.
                if !preserve_snapshot_rhs {
                    if let Some(categorical_rhs) = self.try_format_field_categorical_rhs(lhs, rhs) {
                        let lhs_str = if preserve_snapshot_lhs {
                            self.format_lvalue_preserving_register_names(lhs, table)
                        } else {
                            self.format_lvalue(lhs, table)
                        };
                        return format!("{} = {}", lhs_str, categorical_rhs);
                    }
                }
                format!(
                    "{} = {}",
                    if preserve_snapshot_lhs {
                        self.format_lvalue_preserving_register_names(lhs, table)
                    } else {
                        // For lhs, don't resolve strings (can't write to string literals)
                        self.format_lvalue(lhs, table)
                    },
                    if preserve_snapshot_rhs {
                        self.format_expr_preserving_register_names(rhs, table)
                    } else if let Some(address_str) =
                        self.try_format_global_address_materialization(rhs)
                    {
                        address_str
                    } else {
                        self.format_expr_with_strings(rhs, table)
                    }
                )
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr: _,
                is_deref,
            } => {
                if let Some(name) = self.relocated_symbol_name(*instruction_address, *address) {
                    let resolved = self.simplify_symbol_name(name);
                    if *is_deref {
                        return resolved;
                    }
                    return format!("&{}", resolved);
                }
                // Try symbol table
                if *is_deref {
                    if let Some(value) = self.format_global_value(*address, *size) {
                        return value;
                    }
                } else if let Some(address_text) = self.format_global_address(*address) {
                    return address_text;
                }
                // Try string table
                if let Some(s) = table.get(*address) {
                    return format!("\"{}\"", escape_string(s));
                }
                // Fall back to showing computed address (better than "rip + offset")
                // Use context-aware naming based on usage pattern with size info
                if *is_deref {
                    // Pointer dereference pattern - record size for type inference
                    let name = self.record_and_name_global_with_size(
                        *address,
                        GlobalUsageHint::PointerDeref,
                        *size,
                    );
                    // Record as a read access
                    self.record_global_read(*address);
                    format!("{}(&{})", Self::global_deref_prefix(*size), name)
                } else {
                    // Address-of (LEA) - preserve the address semantics in the emitted text.
                    let name = self.record_and_name_global(*address, GlobalUsageHint::Unknown);
                    format!("&{}", name)
                }
            }
            ExprKind::Call { target, args } => {
                if let Some(virtual_call) = self.try_format_virtual_dispatch(target, args, table) {
                    return virtual_call;
                }
                if let CallTarget::Named(name) = target {
                    if name == "madd" && args.len() == 3 {
                        let expr = Expr::binop(
                            BinOpKind::Add,
                            args[2].clone(),
                            Expr::binop(BinOpKind::Mul, args[0].clone(), args[1].clone()),
                        );
                        return self.format_expr_with_strings(&expr, table);
                    }
                }
                let target_str = match target {
                    super::expression::CallTarget::Direct {
                        target: addr,
                        call_site,
                    } => {
                        // First check relocation table (for kernel modules)
                        // This uses the call instruction address to find the target symbol
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get(*call_site) {
                                self.format_call_target_name(name)
                            } else if let Some(ref sym_table) = self.symbol_table {
                                // Fall back to symbol table by target address
                                if let Some(name) = sym_table.get(*addr) {
                                    self.format_call_target_name(name)
                                } else {
                                    format!("sub_{:x}", addr)
                                }
                            } else {
                                format!("sub_{:x}", addr)
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Check symbol table by target address
                            if let Some(name) = sym_table.get(*addr) {
                                self.format_call_target_name(name)
                            } else if let Some(s) = table.get(*addr) {
                                // Check if this is a string address (for lea/adr patterns)
                                return format!("\"{}\"", escape_string(s));
                            } else {
                                format!("sub_{:x}", addr)
                            }
                        } else if let Some(s) = table.get(*addr) {
                            // Check if this is a string address (for lea/adr patterns)
                            return format!("\"{}\"", escape_string(s));
                        } else {
                            format!("sub_{:x}", addr)
                        }
                    }
                    super::expression::CallTarget::Named(name) => {
                        self.format_call_target_name(name)
                    }
                    super::expression::CallTarget::Indirect(e) => {
                        // Mark any GotRef in the indirect target as a function pointer
                        self.mark_gotref_as_funcptr(e);
                        // If the indirect target collapsed to a literal address
                        // that matches a known function symbol, render the
                        // symbol name instead of `(0xNNNNNN)(...)`. This
                        // happens when a stack-spilled function pointer
                        // (movq $func, [rbp-N]; call *[rbp-N]) is propagated.
                        let resolved = if let super::expression::ExprKind::IntLit(addr) = &e.kind {
                            if *addr >= 0 && *addr <= u64::MAX as i128 {
                                let addr64 = *addr as u64;
                                self.symbol_table
                                    .as_ref()
                                    .and_then(|st| st.get(addr64))
                                    .map(|name| self.format_call_target_name(name))
                            } else {
                                None
                            }
                        } else {
                            None
                        };
                        if let Some(name) = resolved {
                            name
                        } else {
                            format!("({})", self.format_expr_with_strings(e, table))
                        }
                    }
                    super::expression::CallTarget::IndirectGot { got_address, expr } => {
                        // Mark this as a function pointer access
                        self.global_tracker
                            .borrow_mut()
                            .record_access(*got_address, GlobalUsageHint::FunctionPointer);
                        // Try to resolve the GOT entry to a symbol name
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get_got(*got_address) {
                                self.format_indirect_got_call_target(name)
                            } else {
                                // Fall back to showing the expression
                                format!("({})", self.format_expr_with_strings(expr, table))
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Try symbol table by GOT address (rare, but possible)
                            if let Some(name) = sym_table.get(*got_address) {
                                self.format_indirect_got_call_target(name)
                            } else {
                                format!("({})", self.format_expr_with_strings(expr, table))
                            }
                        } else {
                            format!("({})", self.format_expr_with_strings(expr, table))
                        }
                    }
                };
                // Format arguments with context-aware constant recognition
                let args_str: Vec<_> = args
                    .iter()
                    .enumerate()
                    .map(|(idx, a)| {
                        if Self::is_tls_get_addr_name(&target_str) {
                            if let Some(arg) = self.try_format_tls_descriptor_arg(a) {
                                return arg;
                            }
                        }
                        if self.register_snapshot_mode.get()
                            && target_str == "rdsspq"
                            && Self::expr_contains_snapshot_register_source(a)
                        {
                            self.format_expr_preserving_register_names(a, table)
                        } else {
                            // Try to resolve argument as a magic constant
                            self.format_call_arg(a, &target_str, idx, args, table)
                        }
                    })
                    .collect();
                format!("{}({})", target_str, args_str.join(", "))
            }
            // Handle variables - convert registers to meaningful names
            ExprKind::Var(var) => {
                let name_lower = var.name.to_lowercase();
                if name_lower == "wzr" || name_lower == "xzr" {
                    // ARM64 zero register represents constant 0
                    "0".to_string()
                } else if matches!(name_lower.as_str(), "rip" | "eip") {
                    // RIP/EIP should not appear in output - these should have been resolved
                    // to GotRef during analysis. If they appear here, it's likely an unresolved
                    // RIP-relative access. Show as a placeholder to avoid confusing output.
                    "/* unresolved_pc_relative */".to_string()
                } else {
                    // Try to get a semantic name from NamingContext for stack variables
                    // Check if this variable represents a stack offset (var_N format)
                    if let Some(semantic_name) = self.try_get_semantic_var_name(&var.name) {
                        // Apply parameter name overrides and normalization
                        let overridden = self.apply_param_name_override(&semantic_name);
                        normalize_variable_name(&overridden)
                    } else {
                        // Rename callee-saved registers to meaningful names
                        // These are commonly used to hold return values/error codes
                        let renamed = self.rename_register_for_display(&var.name);
                        let overridden = self.apply_param_name_override(&renamed);
                        normalize_variable_name(&overridden)
                    }
                }
            }
            ExprKind::Unknown(name) => {
                // Check if this is a condition comment placeholder (e.g., /* signed_le */)
                // These appear when we can't resolve the actual comparison operands
                if name.starts_with("/*") && name.ends_with("*/") {
                    // It's a comment - keep it but note it's a placeholder condition
                    // In boolean context, this will evaluate as-is which isn't ideal,
                    // but at least preserves the semantic information
                    name.clone()
                } else {
                    self.resolve_display_identifier_name(name)
                }
            }
            // Handle casts with potential elimination based on known types
            ExprKind::Cast {
                expr: inner,
                to_size,
                signed,
            } => {
                let inner_str = self.format_expr_with_strings(inner, table);

                // Try to eliminate redundant casts based on known variable types
                if let Some(var_type) = self.get_expr_type(inner) {
                    if self.type_matches_cast(&var_type, *to_size, *signed) {
                        // Cast is redundant - the variable already has the right type
                        return inner_str;
                    }
                }

                // Generate the cast
                let type_name = match (to_size, signed) {
                    (1, true) => "int8_t",
                    (1, false) => "uint8_t",
                    (2, true) => "int16_t",
                    (2, false) => "uint16_t",
                    (4, true) => "int32_t",
                    (4, false) => "uint32_t",
                    (8, true) => "int64_t",
                    (8, false) => "uint64_t",
                    _ => "int",
                };
                format!("({}){}", type_name, inner_str)
            }
            // Compound assignment: x op= y
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                let lhs_str = self.format_lvalue(lhs, table);
                let rhs_str = self
                    .try_format_global_address_materialization(rhs)
                    .unwrap_or_else(|| self.format_expr_with_strings(rhs, table));
                format!("{} {}= {}", lhs_str, op.as_str(), rhs_str)
            }
            // Conditional: cond ? then : else
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                let cond_str = self.format_expr_with_strings(cond, table);
                let then_str = self.format_expr_with_strings(then_expr, table);
                let else_str = self.format_expr_with_strings(else_expr, table);
                format!("{} ? {} : {}", cond_str, then_str, else_str)
            }
            ExprKind::BitField {
                expr: inner,
                start,
                width,
            } => {
                let inner_str = self.format_expr_with_strings(inner, table);
                format!("BITS({}, {}, {})", inner_str, start, width)
            }
            // Address-of: &expr
            ExprKind::AddressOf(inner) => {
                let inner_str = self.format_expr_with_strings(inner, table);
                format!("&{}", inner_str)
            }
            // Field access: base->field
            ExprKind::FieldAccess {
                base,
                field_name,
                offset,
            } => {
                // Use parentheses if base is a binary operation (postfix has highest precedence)
                let base_str = self.format_postfix_base(base, table);

                // If the field name is generic (field_N pattern without type info),
                // use array notation for better readability.
                if field_name.starts_with("field_") {
                    // Convert byte offset to element index (assume 8-byte pointers)
                    let elem_size = 8usize;
                    if *offset % elem_size == 0 {
                        let idx = *offset / elem_size;
                        return format!("{}[{}]", base_str, idx);
                    }
                }
                // Pick `.` vs `->` based on the base's declared type: a
                // struct/union value uses `.`, a pointer (or anything we
                // can't classify) uses `->`. This makes a stack-local
                // `struct epoll_event ev; ev.events = …` render correctly
                // instead of `ev->events = …`.
                let op = if self.field_access_uses_dot(base) {
                    "."
                } else {
                    "->"
                };
                format!("{}{}{}", base_str, op, field_name)
            }
            // Array access: check if this is a stack slot (sp[N] or x29[N])
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                if let Some(symbol) =
                    self.try_format_tls_thread_pointer_access(base, index, *element_size)
                {
                    return symbol;
                }
                if let Some(stack_array) =
                    self.try_format_stack_slot_array_access(base, index, *element_size)
                {
                    return stack_array;
                }
                if let ExprKind::IntLit(idx) = &index.kind {
                    if *idx >= 0 {
                        let off = (*idx as usize) * *element_size;
                        if let Some(field_access) =
                            self.try_format_struct_pointer_field_fallback(base, off, table)
                        {
                            return field_access;
                        }
                        if let ExprKind::Var(base_var) = &base.kind {
                            let is_stack_like = matches!(
                                base_var.name.as_str(),
                                "sp" | "rsp" | "rbp" | "x29" | "rip" | "eip"
                            );
                            if !is_stack_like {
                                // Only use struct field notation if we have type database info.
                                // Otherwise prefer array notation (e.g., argv[1] not argv->field_8).
                                let addr_expr = if off == 0 {
                                    (**base).clone()
                                } else {
                                    Expr::binop(
                                        BinOpKind::Add,
                                        (**base).clone(),
                                        Expr::int(off as i128),
                                    )
                                };
                                if let Some(field_access) =
                                    self.try_format_struct_field(&addr_expr, *element_size, table)
                                {
                                    return field_access;
                                }
                                // Use array notation - cleaner for pointer arrays like argv
                                let base_str = self.format_expr_no_string_resolve(base);
                                return format!("{}[{}]", base_str, idx);
                            }
                        }
                    }
                }
                // Check if base is a stack/frame pointer or RIP/EIP
                if let ExprKind::Var(v) = &base.kind {
                    let is_stack_ptr = v.name == "sp" || v.name == "rsp";
                    let is_frame_ptr = v.name == "rbp" || v.name == "x29";
                    let is_pc_relative = v.name == "rip" || v.name == "eip";

                    if is_stack_ptr || is_frame_ptr {
                        // Check if index is a constant
                        if let ExprKind::IntLit(idx) = &index.kind {
                            // Calculate actual byte offset
                            let byte_offset = *idx * (*element_size as i128);
                            let actual_offset = if is_frame_ptr {
                                -byte_offset // Frame pointer uses negative offsets for locals
                            } else {
                                byte_offset
                            };

                            // Check for DWARF name first
                            if let Some(name) = self.get_dwarf_name(actual_offset) {
                                return name.to_string();
                            }

                            // Use NamingContext for pattern-based naming
                            let is_param = is_frame_ptr && actual_offset > 0;
                            let name = self
                                .naming_ctx
                                .borrow_mut()
                                .get_name(actual_offset, is_param);
                            return normalize_variable_name(&name);
                        }
                    } else if is_pc_relative {
                        // RIP/EIP-relative array access - this is a global variable reference
                        // Try to resolve using the symbol table if we have a constant index
                        if let ExprKind::IntLit(idx) = &index.kind {
                            // saturating_mul: attacker-shaped IL can carry
                            // an index × element_size that doesn't fit in
                            // u64. The product is only used for symbol
                            // lookup (no real binary places a symbol at
                            // u64::MAX, so the lookup just misses) and
                            // for hex rendering of the synthesised global
                            // name below — both fine with the clamp.
                            let byte_offset = (*idx as u64).saturating_mul(*element_size as u64);
                            // Try to find a symbol at this relative offset
                            if let Some(ref sym_table) = self.symbol_table {
                                if let Some(name) = sym_table.get(byte_offset) {
                                    if let Some(alias) = self.simplify_libc_global_name(name) {
                                        return alias.to_string();
                                    }
                                    return name.to_string();
                                }
                            }
                            // Fall back to a typed dereference of a global address
                            let prefix = match element_size {
                                1 => "*(uint8_t*)",
                                2 => "*(uint16_t*)",
                                4 => "*(uint32_t*)",
                                8 => "*(uint64_t*)",
                                _ => "*",
                            };
                            return format!("{}(&g_{:x})", prefix, byte_offset);
                        }
                        // Non-constant index - use a generic global array name
                        let index_str = self.format_expr_with_strings(index, table);
                        return format!("_globals[{}]", index_str);
                    }
                }
                // Default array access formatting
                // Use parentheses if base is a binary operation (postfix has highest precedence)
                let base_str = self
                    .try_format_global_array_base(base)
                    .unwrap_or_else(|| self.format_postfix_base(base, table));
                let index_str = self.format_expr_with_strings(index, table);
                format!("{}[{}]", base_str, index_str)
            }
            // For other cases, use default formatting
            _ => expr.to_string(),
        }
    }

    fn try_format_flag_lvalue(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Deref { addr, .. } => {
                if let ExprKind::GotRef { address, .. } = &addr.kind {
                    return Some(format!("g_flags_{:x}", address));
                }
                None
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                if let ExprKind::Var(v) = &base.kind {
                    if (v.name == "rip" || v.name == "eip")
                        && matches!(index.kind, ExprKind::IntLit(_))
                    {
                        if let ExprKind::IntLit(idx) = &index.kind {
                            if *idx >= 0 {
                                let off = (*idx as usize) * *element_size;
                                return Some(format!("g_flags_rip_{:x}", off));
                            }
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn format_flag_mask(&self, value: i128) -> String {
        if value > 0 && (value & (value - 1)) == 0 {
            format!("FLAG_{:x}", value)
        } else {
            format_integer(value)
        }
    }

    /// Emits pseudo-code for a structured CFG.
    pub fn emit(&self, cfg: &StructuredCfg, func_name: &str) -> String {
        let mut output = String::new();
        let is_main_like = matches!(func_name, "main" | "_main");
        let rename_main_param = |name: &str, idx: usize| -> String {
            if is_main_like {
                match (idx, name) {
                    (0, "arg0") => "argc".to_string(),
                    (1, "arg1") => "argv".to_string(),
                    _ => name.to_string(),
                }
            } else {
                name.to_string()
            }
        };

        // Use advanced signature recovery if enabled
        let signature = if self.use_signature_recovery {
            let mut recovery = SignatureRecovery::new(self.calling_convention)
                .with_relocation_table(self.relocation_table.clone())
                .with_symbol_table(self.symbol_table.clone())
                .with_summary_database(self.summary_database.clone())
                .with_dwarf_param_names(self.dwarf_param_names.clone())
                .with_function_name(func_name);
            Some(recovery.analyze(cfg))
        } else {
            None
        };

        let provisional_body = self.rewrite_small_aggregate_slots_for_emission(&cfg.body);
        let legacy_func_info = self.analyze_function(&provisional_body);
        let allow_tail_return_folding = signature.as_ref().is_some_and(|sig| sig.has_return)
            || legacy_func_info.has_return_value;
        let display_body = if signature.is_some() && allow_tail_return_folding {
            let rewritten =
                Self::rewrite_tail_call_returns_for_emission(&cfg.body, allow_tail_return_folding);
            self.rewrite_small_aggregate_slots_for_emission(&rewritten)
        } else {
            provisional_body
        };
        let display_body = self.rewrite_destructor_cleanup_returns_for_emission(&display_body);
        let previous_snapshot_mode = self
            .register_snapshot_mode
            .replace(Self::should_enable_register_snapshot_mode(&display_body));

        // Analyze function body for pattern-based variable naming (loop indices, etc.)
        self.naming_ctx.borrow_mut().analyze(&display_body);

        // Pre-scan for global access patterns before emission
        // This allows us to infer read-only, write-heavy, counter patterns
        self.prescan_global_accesses(&display_body);

        let func_info = if let Some(ref sig) = signature {
            // Convert recovered signature to FunctionInfo for compatibility
            let params: Vec<String> = sig.parameters.iter().map(|p| p.name.clone()).collect();

            let info = self.analyze_function(&display_body);
            let mut merged_param_names = params.clone();
            if merged_param_names.len() < info.parameters.len() {
                merged_param_names.resize(info.parameters.len(), String::new());
            }
            for (idx, name) in info.parameters.iter().enumerate() {
                if !name.is_empty() {
                    merged_param_names[idx] = name.clone();
                }
            }
            FunctionInfo {
                parameters: if merged_param_names.is_empty() {
                    info.parameters
                } else {
                    merged_param_names
                },
                has_return_value: sig.has_return || info.has_return_value,
                skip_statements: info.skip_statements,
            }
        } else {
            self.analyze_function(&display_body)
        };

        let param_override_sources: Vec<String> = if let Some(ref sig) = signature {
            if sig.parameters.is_empty() {
                func_info.parameters.clone()
            } else {
                sig.parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        if let Some(recovered_name) = func_info.parameters.get(idx) {
                            if Self::should_prefer_specific_param_name(recovered_name)
                                && !Self::should_prefer_specific_param_name(&p.name)
                            {
                                return recovered_name.clone();
                            }
                        }

                        // SignatureRecovery's `var_NN` heuristic for
                        // stack-spilled register params shadows the
                        // DWARF parameter name when the function was
                        // compiled with -O0 -g (the body var was lifted
                        // from a slot at offset -NN). Override here:
                        // if `var_NN` matches a DWARF entry, prefer
                        // the DWARF name.
                        if let Some(suffix) = p.name.strip_prefix("var_") {
                            if let Ok(abs) = i128::from_str_radix(suffix, 16) {
                                let offset = -abs;
                                if let Some(dwarf) = self.dwarf_names.get(&offset) {
                                    return dwarf.clone();
                                }
                            }
                        }
                        p.name.clone()
                    })
                    .collect()
            }
        } else {
            func_info.parameters.clone()
        };
        let rendered_param_names: Vec<String> = param_override_sources
            .iter()
            .enumerate()
            .map(|(idx, name)| rename_main_param(name, idx))
            .collect();

        self.clear_param_name_overrides();
        for (idx, source_name) in param_override_sources.iter().enumerate() {
            let rendered_name = &rendered_param_names[idx];
            self.set_param_name_override(source_name, rendered_name);
            self.set_param_name_override(&format!("arg{}", idx), rendered_name);
            self.set_lifted_param_slot_overrides(idx, rendered_name);
        }

        // Function header with detected signature
        if let Some(ref sig) = signature {
            // Use the recovered signature for type information
            let return_type = if sig.has_return {
                sig.return_type.to_c_string()
            } else if func_info.has_return_value {
                "int".to_string()
            } else {
                "void".to_string()
            };
            self.set_return_fallback_expr_for_type(&return_type);

            if sig.parameters.is_empty() && func_info.parameters.is_empty() {
                writeln!(output, "{} {}(void)", return_type, func_name).unwrap();
            } else if !sig.parameters.is_empty() {
                let params: Vec<_> = sig
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let source_name = &param_override_sources[idx];
                        let rendered_name = rendered_param_names[idx].clone();
                        let type_hint = self.find_param_type_hint(idx, source_name, &rendered_name);
                        self.format_signature_param_with_type_hint(
                            p,
                            &rendered_name,
                            type_hint.as_deref(),
                        )
                    })
                    .collect();
                writeln!(
                    output,
                    "{}",
                    Self::format_function_header(
                        &sig.return_type,
                        func_name,
                        &params,
                        sig.is_variadic,
                    )
                )
                .unwrap();
            } else {
                // Fall back to legacy parameter detection
                let params: Vec<_> = func_info
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let name = rendered_param_names[idx].clone();
                        format!("{} {}", self.get_type(p), name)
                    })
                    .collect();
                writeln!(
                    output,
                    "{} {}({})",
                    return_type,
                    func_name,
                    params.join(", ")
                )
                .unwrap();
            }
        } else {
            // Legacy fallback
            let return_type = if func_info.has_return_value {
                "int"
            } else {
                "void"
            };
            self.set_return_fallback_expr_for_type(return_type);
            if func_info.parameters.is_empty() {
                writeln!(output, "{} {}()", return_type, func_name).unwrap();
            } else {
                let params: Vec<_> = func_info
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let name = rendered_param_names[idx].clone();
                        format!("{} {}", self.get_type(p), name)
                    })
                    .collect();
                writeln!(
                    output,
                    "{} {}({})",
                    return_type,
                    func_name,
                    params.join(", ")
                )
                .unwrap();
            }
        }
        writeln!(output, "{{").unwrap();

        let mut param_exclusion_names = HashSet::new();
        for (idx, _) in param_override_sources.iter().enumerate() {
            param_exclusion_names.insert(rendered_param_names[idx].clone());
            param_exclusion_names.insert(format!("arg{}", idx));
        }
        let param_exclusion_list: Vec<String> = param_exclusion_names.into_iter().collect();

        // Collect all local variables used in the function (excluding parameters)
        let all_vars = self.collect_local_variables(&display_body, &param_exclusion_list);
        let loop_zero_init_vars = self.find_loop_condition_vars_needing_init(&display_body);

        // Emit body into a temporary buffer first so declarations can be filtered
        // to only identifiers that actually appear after skip/noise pruning.
        let mut body_output = String::new();
        let mut declared_vars: HashSet<String> = param_exclusion_list.clone().into_iter().collect();
        declared_vars.extend(all_vars.iter().cloned());
        self.emit_nodes_with_skip_and_decls(
            &display_body,
            &mut body_output,
            1,
            &func_info.skip_statements,
            &mut declared_vars,
        );
        if let Some(comment) = Self::special_function_prelude_comment(func_name) {
            body_output = format!("{}{}\n{}", self.indent, comment, body_output);
        }
        if body_output.trim().is_empty() {
            writeln!(
                body_output,
                "{}/* decompilation body not recoverable */",
                self.indent
            )
            .unwrap();
        }
        if let Some(fallback) = self.return_fallback_expr.borrow().clone() {
            if !self.body_ends_with_control_exit(&display_body)
                && !Self::output_ends_with_return_stmt(&body_output)
            {
                writeln!(body_output, "{}return {};", self.indent, fallback).unwrap();
            }
        }

        let mut all_vars_set: HashSet<String> = all_vars
            .into_iter()
            .filter(|var| contains_identifier_token(&body_output, var))
            .collect();
        let inferred_assignment_types = self.collect_assignment_based_local_types(&display_body);
        let inferred_pointer_usage_types = self.collect_pointer_usage_types(&display_body);
        for inferred in collect_decl_identifiers_from_emitted_body(&body_output) {
            if !param_exclusion_list.contains(&inferred)
                && !self.is_known_global_identifier(&inferred)
            {
                all_vars_set.insert(inferred);
            }
        }
        for arg_index in 0..8 {
            let leaked_arg = format!("arg{}", arg_index);
            if !param_exclusion_list.contains(&leaked_arg)
                && contains_identifier_token(&body_output, &leaked_arg)
            {
                all_vars_set.insert(leaked_arg);
            }
        }
        let mut all_vars: Vec<String> = all_vars_set.into_iter().collect();
        all_vars.sort();

        // A recovered SysV variadic function threads a `va_list ap` cursor
        // through `va_start`/`va_arg`; declare it so the body reads as valid C.
        let needs_va_list =
            body_output.contains("va_start(ap") || body_output.contains("va_arg(ap");

        // Emit variable declarations at the top (C89 style)
        if !all_vars.is_empty() || needs_va_list {
            let indent = &self.indent;
            if needs_va_list {
                writeln!(output, "{}va_list ap;", indent).unwrap();
            }
            for var in &all_vars {
                let var_type = inferred_assignment_types
                    .get(var)
                    .map(String::as_str)
                    .or_else(|| inferred_pointer_usage_types.get(var).map(String::as_str))
                    .unwrap_or_else(|| {
                        if self.get_type(var) == "int" && body_output.contains(&format!("{}[", var))
                        {
                            "char*"
                        } else {
                            self.get_type(var)
                        }
                    });
                let scope_comment = self.dwarf_scope_comment(var).unwrap_or_default();
                if loop_zero_init_vars.contains(var) {
                    writeln!(
                        output,
                        "{}{} {} = 0;{}",
                        indent, var_type, var, scope_comment
                    )
                    .unwrap();
                } else {
                    writeln!(output, "{}{} {};{}", indent, var_type, var, scope_comment).unwrap();
                }
            }
            writeln!(output).unwrap(); // Blank line after declarations
        }

        write!(output, "{}", body_output).unwrap();
        writeln!(output, "}}").unwrap();
        self.clear_return_fallback_expr();
        self.register_snapshot_mode.set(previous_snapshot_mode);
        Self::repair_packed_small_aggregate_output(output)
    }

    /// Emits pseudo-code with a specific function signature.
    ///
    /// This allows providing a pre-computed signature for cases where
    /// additional context (like symbol information) is available.
    pub fn emit_with_signature(
        &self,
        cfg: &StructuredCfg,
        func_name: &str,
        signature: &FunctionSignature,
    ) -> String {
        let mut output = String::new();
        let rename_main_param = |name: &str, index: usize| -> String {
            if func_name == "main" || func_name == "_main" {
                match (index, name) {
                    (0, "arg0") => "argc".to_string(),
                    (1, "arg1") => "argv".to_string(),
                    _ => name.to_string(),
                }
            } else {
                name.to_string()
            }
        };

        let display_body = self.rewrite_small_aggregate_slots_for_emission(
            &Self::rewrite_tail_call_returns_for_emission(&cfg.body, signature.has_return),
        );
        let display_body = self.rewrite_destructor_cleanup_returns_for_emission(&display_body);
        let display_body =
            Self::rewrite_param_restore_artifacts_for_emission(&display_body, signature);
        let previous_snapshot_mode = self
            .register_snapshot_mode
            .replace(Self::should_enable_register_snapshot_mode(&display_body));

        // Analyze function body for pattern-based variable naming
        self.naming_ctx.borrow_mut().analyze(&display_body);
        let signature_param_names: Vec<String> = signature
            .parameters
            .iter()
            .map(|p| p.name.clone())
            .collect();
        let rendered_param_names: Vec<String> = signature
            .parameters
            .iter()
            .enumerate()
            .map(|(idx, p)| rename_main_param(&p.name, idx))
            .collect();

        self.clear_param_name_overrides();
        for (idx, source_name) in signature_param_names.iter().enumerate() {
            let rendered_name = &rendered_param_names[idx];
            self.set_param_name_override(source_name, rendered_name);
            self.set_param_name_override(&format!("arg{}", idx), rendered_name);
            self.set_lifted_param_slot_overrides(idx, rendered_name);
        }

        // Record how many argument registers are actual parameters, so a higher
        // argument register used as a temporary is not displayed as `argN`. A
        // variadic function may use argument registers for its varargs, so leave
        // those ungated.
        if signature.is_variadic {
            self.integer_arg_param_count.set(usize::MAX);
            self.float_arg_param_count.set(usize::MAX);
        } else {
            use super::signature::ParameterLocation;
            let int_count = signature
                .parameters
                .iter()
                .filter_map(|p| match p.location {
                    ParameterLocation::IntegerRegister { index, .. } => Some(index + 1),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            let float_count = signature
                .parameters
                .iter()
                .filter_map(|p| match p.location {
                    ParameterLocation::FloatRegister { index, .. } => Some(index + 1),
                    _ => None,
                })
                .max()
                .unwrap_or(0);
            self.integer_arg_param_count.set(int_count);
            self.float_arg_param_count.set(float_count);
        }

        // Use provided signature for header
        let return_type = if signature.has_return {
            signature.return_type.to_c_string()
        } else {
            "void".to_string()
        };
        self.set_return_fallback_expr_for_type(&return_type);

        let params: Vec<_> = signature
            .parameters
            .iter()
            .enumerate()
            .map(|(idx, p)| {
                let source_name = &signature_param_names[idx];
                let rendered_name = rendered_param_names[idx].clone();
                let type_hint = self.find_param_type_hint(idx, source_name, &rendered_name);
                self.format_signature_param_with_type_hint(p, &rendered_name, type_hint.as_deref())
            })
            .collect();
        writeln!(
            output,
            "{}",
            Self::format_function_header(
                &signature.return_type,
                func_name,
                &params,
                signature.is_variadic,
            )
        )
        .unwrap();
        writeln!(output, "{{").unwrap();

        // Legacy analysis for skipping parameter statements
        let func_info = self.analyze_function(&display_body);

        let mut param_exclusion_names = HashSet::new();
        for (idx, _) in signature_param_names.iter().enumerate() {
            param_exclusion_names.insert(rendered_param_names[idx].clone());
            param_exclusion_names.insert(format!("arg{}", idx));
        }
        let param_exclusion_list: Vec<String> = param_exclusion_names.into_iter().collect();

        // Collect all local variables used in the function (excluding parameters)
        let all_vars = self.collect_local_variables(&display_body, &param_exclusion_list);
        let loop_zero_init_vars = self.find_loop_condition_vars_needing_init(&display_body);

        // Emit body into a temporary buffer first so declarations can be filtered
        // to only identifiers that survive statement skipping.
        let mut body_output = String::new();
        let mut declared_vars: HashSet<String> = param_exclusion_list.clone().into_iter().collect();
        declared_vars.extend(all_vars.iter().cloned());
        self.emit_nodes_with_skip_and_decls(
            &display_body,
            &mut body_output,
            1,
            &func_info.skip_statements,
            &mut declared_vars,
        );
        if let Some(comment) = Self::special_function_prelude_comment(func_name) {
            body_output = format!("{}{}\n{}", self.indent, comment, body_output);
        }
        if body_output.trim().is_empty() {
            writeln!(
                body_output,
                "{}/* decompilation body not recoverable */",
                self.indent
            )
            .unwrap();
        }
        if let Some(fallback) = self.return_fallback_expr.borrow().clone() {
            if !self.body_ends_with_control_exit(&display_body)
                && !Self::output_ends_with_return_stmt(&body_output)
            {
                writeln!(body_output, "{}return {};", self.indent, fallback).unwrap();
            }
        }

        let mut all_vars_set: HashSet<String> = all_vars
            .into_iter()
            .filter(|var| contains_identifier_token(&body_output, var))
            .collect();
        let inferred_assignment_types = self.collect_assignment_based_local_types(&display_body);
        let inferred_pointer_usage_types = self.collect_pointer_usage_types(&display_body);
        for inferred in collect_decl_identifiers_from_emitted_body(&body_output) {
            if !param_exclusion_list.contains(&inferred)
                && !self.is_known_global_identifier(&inferred)
            {
                all_vars_set.insert(inferred);
            }
        }
        for arg_index in 0..8 {
            let leaked_arg = format!("arg{}", arg_index);
            if !param_exclusion_list.contains(&leaked_arg)
                && contains_identifier_token(&body_output, &leaked_arg)
            {
                all_vars_set.insert(leaked_arg);
            }
        }
        let mut all_vars: Vec<String> = all_vars_set.into_iter().collect();
        all_vars.sort();

        // A recovered SysV variadic function threads a `va_list ap` cursor
        // through `va_start`/`va_arg`; declare it so the body reads as valid C.
        let needs_va_list =
            body_output.contains("va_start(ap") || body_output.contains("va_arg(ap");

        // Emit variable declarations at the top (C89 style)
        if !all_vars.is_empty() || needs_va_list {
            let indent = &self.indent;
            if needs_va_list {
                writeln!(output, "{}va_list ap;", indent).unwrap();
            }
            for var in &all_vars {
                let var_type = inferred_assignment_types
                    .get(var)
                    .map(String::as_str)
                    .or_else(|| inferred_pointer_usage_types.get(var).map(String::as_str))
                    .unwrap_or_else(|| {
                        if self.get_type(var) == "int" && body_output.contains(&format!("{}[", var))
                        {
                            "char*"
                        } else {
                            self.get_type(var)
                        }
                    });
                let scope_comment = self.dwarf_scope_comment(var).unwrap_or_default();
                if loop_zero_init_vars.contains(var) {
                    writeln!(
                        output,
                        "{}{} {} = 0;{}",
                        indent, var_type, var, scope_comment
                    )
                    .unwrap();
                } else {
                    writeln!(output, "{}{} {};{}", indent, var_type, var, scope_comment).unwrap();
                }
            }
            writeln!(output).unwrap();
        }

        write!(output, "{}", body_output).unwrap();
        writeln!(output, "}}").unwrap();
        self.clear_return_fallback_expr();
        self.register_snapshot_mode.set(previous_snapshot_mode);
        Self::repair_packed_small_aggregate_output(output)
    }

    /// Recovers the function signature for the given CFG.
    ///
    /// This can be used to get the signature separately from emission,
    /// for example to display it in a symbol table or for further analysis.
    pub fn recover_signature(&self, cfg: &StructuredCfg) -> FunctionSignature {
        self.recover_signature_with_name(cfg, None)
    }

    /// Recovers the function signature with optional function name for known signatures.
    ///
    /// If the function name matches a known library function (e.g., "main", "malloc"),
    /// the parameter names will be set to their canonical names.
    pub fn recover_signature_with_name(
        &self,
        cfg: &StructuredCfg,
        func_name: Option<&str>,
    ) -> FunctionSignature {
        let mut recovery = SignatureRecovery::new(self.calling_convention)
            .with_relocation_table(self.relocation_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_summary_database(self.summary_database.clone())
            .with_dwarf_param_names(self.dwarf_param_names.clone());
        if let Some(name) = func_name {
            recovery = recovery.with_function_name(name);
        }
        recovery.analyze(cfg)
    }

    /// Collects all local variables assigned to in the function body.
    fn collect_local_variables(&self, nodes: &[StructuredNode], params: &[String]) -> Vec<String> {
        let mut vars = HashSet::new();
        self.collect_vars_from_nodes(nodes, &mut vars);
        self.collect_display_assigned_names(nodes, &mut vars);
        vars = vars
            .into_iter()
            .filter_map(|name| canonical_decl_var_name(&name))
            .filter(|name| !is_likely_global_identifier(name))
            .filter(|name| !self.is_known_global_identifier(name))
            .collect();

        // Remove parameters
        for p in params {
            vars.remove(p);
        }

        // Sort for consistent output
        let mut vars: Vec<_> = vars.into_iter().collect();
        vars.sort();
        vars
    }

    fn collect_vars_from_nodes(&self, nodes: &[StructuredNode], vars: &mut HashSet<String>) {
        for node in nodes {
            self.collect_vars_from_node(node, vars);
        }
    }

    fn collect_vars_from_node(&self, node: &StructuredNode, vars: &mut HashSet<String>) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    // Collect variables from entire statement expression
                    self.collect_vars_from_expr(stmt, vars);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                // Collect variables from condition
                self.collect_vars_from_expr(condition, vars);
                self.collect_vars_from_nodes(then_body, vars);
                if let Some(else_nodes) = else_body {
                    self.collect_vars_from_nodes(else_nodes, vars);
                }
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                // Collect variables from condition
                self.collect_vars_from_expr(condition, vars);
                self.collect_vars_from_nodes(body, vars);
            }
            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                // Collect variables from condition
                self.collect_vars_from_expr(condition, vars);
                self.collect_vars_from_nodes(body, vars);
            }
            StructuredNode::Loop { body, .. } => {
                self.collect_vars_from_nodes(body, vars);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                // Collect variables from init expression
                if let Some(init_expr) = init {
                    self.collect_vars_from_expr(init_expr, vars);
                }
                // Collect variables from condition
                self.collect_vars_from_expr(condition, vars);
                // Collect variables from update expression
                if let Some(update_expr) = update {
                    self.collect_vars_from_expr(update_expr, vars);
                }
                self.collect_vars_from_nodes(body, vars);
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
                ..
            } => {
                // Collect variables from switch expression
                self.collect_vars_from_expr(value, vars);
                for (_, case_body) in cases {
                    self.collect_vars_from_nodes(case_body, vars);
                }
                if let Some(def) = default {
                    self.collect_vars_from_nodes(def, vars);
                }
            }
            StructuredNode::Sequence(nodes) => {
                self.collect_vars_from_nodes(nodes, vars);
            }
            StructuredNode::Return(Some(expr)) => {
                // Collect variables from return expression
                self.collect_vars_from_expr(expr, vars);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                self.collect_vars_from_nodes(try_body, vars);
                for handler in catch_handlers {
                    self.collect_vars_from_nodes(&handler.body, vars);
                }
            }
            _ => {}
        }
    }

    fn find_loop_condition_vars_needing_init(&self, nodes: &[StructuredNode]) -> HashSet<String> {
        let mut needed = HashSet::new();
        let mut definitely_assigned = HashSet::new();
        self.collect_loop_condition_uninitialized_vars(
            nodes,
            &mut definitely_assigned,
            &mut needed,
        );
        needed
            .into_iter()
            .filter(|name| is_declarable_variable(name) && is_loop_counter_like_name(name))
            .collect()
    }

    fn collect_loop_condition_uninitialized_vars(
        &self,
        nodes: &[StructuredNode],
        definitely_assigned: &mut HashSet<String>,
        needed: &mut HashSet<String>,
    ) {
        for node in nodes {
            self.collect_loop_condition_uninitialized_in_node(node, definitely_assigned, needed);
        }
    }

    fn collect_loop_condition_uninitialized_in_node(
        &self,
        node: &StructuredNode,
        definitely_assigned: &mut HashSet<String>,
        needed: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if self.is_prologue_epilogue(stmt)
                        || self.is_noop_assignment(stmt)
                        || self.is_skippable_statement(stmt)
                    {
                        continue;
                    }
                    self.collect_assigned_vars_from_expr(stmt, definitely_assigned);
                }
            }
            StructuredNode::Expr(expr) => {
                if self.is_prologue_epilogue(expr)
                    || self.is_noop_assignment(expr)
                    || self.is_skippable_statement(expr)
                {
                    return;
                }
                self.collect_assigned_vars_from_expr(expr, definitely_assigned)
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                // Condition executes before either branch.
                self.collect_assigned_vars_from_expr(condition, definitely_assigned);
                let mut then_assigned = definitely_assigned.clone();
                self.collect_loop_condition_uninitialized_vars(
                    then_body,
                    &mut then_assigned,
                    needed,
                );

                let mut else_assigned = definitely_assigned.clone();
                if let Some(else_nodes) = else_body {
                    self.collect_loop_condition_uninitialized_vars(
                        else_nodes,
                        &mut else_assigned,
                        needed,
                    );
                }

                *definitely_assigned = then_assigned
                    .intersection(&else_assigned)
                    .cloned()
                    .collect();
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                let mut condition_vars = HashSet::new();
                self.collect_vars_from_expr(condition, &mut condition_vars);
                for var in condition_vars {
                    if !definitely_assigned.contains(&var) {
                        needed.insert(var);
                    }
                }

                // While conditions execute at least once.
                self.collect_assigned_vars_from_expr(condition, definitely_assigned);

                // Body assignments are not guaranteed (zero iterations), but nested loops still
                // need analysis for their own uninitialized condition variables.
                let mut body_assigned = definitely_assigned.clone();
                self.collect_loop_condition_uninitialized_vars(body, &mut body_assigned, needed);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                // For init executes before the first condition check.
                if let Some(init_expr) = init {
                    self.collect_assigned_vars_from_expr(init_expr, definitely_assigned);
                }

                let mut condition_vars = HashSet::new();
                self.collect_vars_from_expr(condition, &mut condition_vars);
                for var in condition_vars {
                    if !definitely_assigned.contains(&var) {
                        needed.insert(var);
                    }
                }

                // For condition executes when loop is reached.
                self.collect_assigned_vars_from_expr(condition, definitely_assigned);

                // Body/update assignments are not guaranteed to run.
                let mut body_assigned = definitely_assigned.clone();
                self.collect_loop_condition_uninitialized_vars(body, &mut body_assigned, needed);
                if let Some(update_expr) = update {
                    self.collect_assigned_vars_from_expr(update_expr, &mut body_assigned);
                }
            }
            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                // Do-while body executes before first condition.
                self.collect_loop_condition_uninitialized_vars(body, definitely_assigned, needed);

                let mut condition_vars = HashSet::new();
                self.collect_vars_from_expr(condition, &mut condition_vars);
                for var in condition_vars {
                    if !definitely_assigned.contains(&var) {
                        needed.insert(var);
                    }
                }
                self.collect_assigned_vars_from_expr(condition, definitely_assigned);
            }
            StructuredNode::Loop { body, .. } => {
                let mut body_assigned = definitely_assigned.clone();
                self.collect_loop_condition_uninitialized_vars(body, &mut body_assigned, needed);
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
                ..
            } => {
                self.collect_assigned_vars_from_expr(value, definitely_assigned);

                let mut merged: Option<HashSet<String>> = None;
                for (_, case_body) in cases {
                    let mut case_assigned = definitely_assigned.clone();
                    self.collect_loop_condition_uninitialized_vars(
                        case_body,
                        &mut case_assigned,
                        needed,
                    );
                    merged = Some(match merged {
                        Some(current) => current.intersection(&case_assigned).cloned().collect(),
                        None => case_assigned,
                    });
                }

                if let Some(default_nodes) = default {
                    let mut default_assigned = definitely_assigned.clone();
                    self.collect_loop_condition_uninitialized_vars(
                        default_nodes,
                        &mut default_assigned,
                        needed,
                    );
                    merged = Some(match merged {
                        Some(current) => current.intersection(&default_assigned).cloned().collect(),
                        None => default_assigned,
                    });
                } else if let Some(current) = merged.take() {
                    // No default means no case may execute.
                    merged = Some(current.intersection(definitely_assigned).cloned().collect());
                }

                if let Some(result) = merged {
                    *definitely_assigned = result;
                }
            }
            StructuredNode::Sequence(inner) => {
                self.collect_loop_condition_uninitialized_vars(inner, definitely_assigned, needed);
            }
            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                let mut try_assigned = definitely_assigned.clone();
                self.collect_loop_condition_uninitialized_vars(try_body, &mut try_assigned, needed);

                let mut merged = try_assigned;
                for handler in catch_handlers {
                    let mut catch_assigned = definitely_assigned.clone();
                    self.collect_loop_condition_uninitialized_vars(
                        &handler.body,
                        &mut catch_assigned,
                        needed,
                    );
                    merged = merged.intersection(&catch_assigned).cloned().collect();
                }
                *definitely_assigned = merged;
            }
            StructuredNode::Break
            | StructuredNode::Continue
            | StructuredNode::Return(_)
            | StructuredNode::Goto(_)
            | StructuredNode::Label(_) => {}
        }
    }

    fn collect_assigned_vars_from_expr(&self, expr: &Expr, assigned: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                if let Some(name) = self.try_get_assigned_var_name(lhs) {
                    assigned.insert(name);
                }
                self.collect_assigned_vars_from_expr(rhs, assigned);
            }
            ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let Some(name) = self.try_get_assigned_var_name(lhs) {
                    assigned.insert(name);
                }
                self.collect_assigned_vars_from_expr(rhs, assigned);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.collect_assigned_vars_from_expr(arg, assigned);
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_assigned_vars_from_expr(left, assigned);
                self.collect_assigned_vars_from_expr(right, assigned);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.collect_assigned_vars_from_expr(operand, assigned);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.collect_assigned_vars_from_expr(base, assigned);
                self.collect_assigned_vars_from_expr(index, assigned);
            }
            ExprKind::Deref { addr, .. } => {
                self.collect_assigned_vars_from_expr(addr, assigned);
            }
            ExprKind::AddressOf(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.collect_assigned_vars_from_expr(inner, assigned);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_assigned_vars_from_expr(cond, assigned);
                self.collect_assigned_vars_from_expr(then_expr, assigned);
                self.collect_assigned_vars_from_expr(else_expr, assigned);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_assigned_vars_from_expr(base, assigned);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    self.collect_assigned_vars_from_expr(value, assigned);
                }
            }
            ExprKind::BitField { expr: inner, .. } => {
                self.collect_assigned_vars_from_expr(inner, assigned);
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                display_expr,
                ..
            } => {
                if self.should_recurse_into_gotref_display_expr(*address, *instruction_address) {
                    self.collect_assigned_vars_from_expr(display_expr, assigned);
                }
            }
            _ => {}
        }
    }

    fn collect_display_assigned_names(&self, nodes: &[StructuredNode], vars: &mut HashSet<String>) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        if self.is_prologue_epilogue(stmt)
                            || self.is_noop_assignment(stmt)
                            || self.is_skippable_statement(stmt)
                        {
                            continue;
                        }
                        self.collect_display_assigned_names_from_expr(stmt, vars);
                    }
                }
                StructuredNode::Expr(expr) => {
                    if self.is_prologue_epilogue(expr)
                        || self.is_noop_assignment(expr)
                        || self.is_skippable_statement(expr)
                    {
                        continue;
                    }
                    self.collect_display_assigned_names_from_expr(expr, vars);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                    ..
                } => {
                    self.collect_display_assigned_names_from_expr(condition, vars);
                    self.collect_display_assigned_names(then_body, vars);
                    if let Some(else_nodes) = else_body {
                        self.collect_display_assigned_names(else_nodes, vars);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                } => {
                    self.collect_display_assigned_names_from_expr(condition, vars);
                    self.collect_display_assigned_names(body, vars);
                }
                StructuredNode::DoWhile {
                    body, condition, ..
                } => {
                    self.collect_display_assigned_names(body, vars);
                    self.collect_display_assigned_names_from_expr(condition, vars);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(init_expr) = init {
                        self.collect_display_assigned_names_from_expr(init_expr, vars);
                    }
                    self.collect_display_assigned_names_from_expr(condition, vars);
                    if let Some(update_expr) = update {
                        self.collect_display_assigned_names_from_expr(update_expr, vars);
                    }
                    self.collect_display_assigned_names(body, vars);
                }
                StructuredNode::Loop { body, .. } => {
                    self.collect_display_assigned_names(body, vars);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    self.collect_display_assigned_names_from_expr(value, vars);
                    for (_, case_body) in cases {
                        self.collect_display_assigned_names(case_body, vars);
                    }
                    if let Some(default_nodes) = default {
                        self.collect_display_assigned_names(default_nodes, vars);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.collect_display_assigned_names(inner, vars);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    self.collect_display_assigned_names(try_body, vars);
                    for handler in catch_handlers {
                        self.collect_display_assigned_names(&handler.body, vars);
                    }
                }
                StructuredNode::Break
                | StructuredNode::Continue
                | StructuredNode::Return(_)
                | StructuredNode::Goto(_)
                | StructuredNode::Label(_) => {}
            }
        }
    }

    fn collect_display_assigned_names_from_expr(&self, expr: &Expr, vars: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let Some(name) = self.extract_display_assigned_identifier(lhs) {
                    vars.insert(name);
                }
                self.collect_display_assigned_names_from_expr(lhs, vars);
                self.collect_display_assigned_names_from_expr(rhs, vars);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.collect_display_assigned_names_from_expr(arg, vars);
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_display_assigned_names_from_expr(left, vars);
                self.collect_display_assigned_names_from_expr(right, vars);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.collect_display_assigned_names_from_expr(operand, vars);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.collect_display_assigned_names_from_expr(base, vars);
                self.collect_display_assigned_names_from_expr(index, vars);
            }
            ExprKind::Deref { addr, .. } => {
                self.collect_display_assigned_names_from_expr(addr, vars);
            }
            ExprKind::AddressOf(inner) | ExprKind::Cast { expr: inner, .. } => {
                self.collect_display_assigned_names_from_expr(inner, vars);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_display_assigned_names_from_expr(cond, vars);
                self.collect_display_assigned_names_from_expr(then_expr, vars);
                self.collect_display_assigned_names_from_expr(else_expr, vars);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_display_assigned_names_from_expr(base, vars);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    self.collect_display_assigned_names_from_expr(value, vars);
                }
            }
            ExprKind::BitField { expr: inner, .. } => {
                self.collect_display_assigned_names_from_expr(inner, vars);
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                display_expr,
                ..
            } => {
                if self.should_recurse_into_gotref_display_expr(*address, *instruction_address) {
                    self.collect_display_assigned_names_from_expr(display_expr, vars);
                }
            }
            ExprKind::Var(_) | ExprKind::Unknown(_) | ExprKind::IntLit(_) => {}
        }
    }

    fn should_recurse_into_gotref_display_expr(
        &self,
        address: u64,
        instruction_address: u64,
    ) -> bool {
        if self.resolve_global_symbol(address).is_some() {
            return false;
        }

        if let Some(relocations) = &self.relocation_table {
            if relocations.get_got(address).is_some()
                || relocations.get_got(instruction_address).is_some()
                || relocations.get_tls_descriptor(address).is_some()
            {
                return false;
            }
        }

        true
    }

    fn is_known_global_identifier(&self, name: &str) -> bool {
        self.symbol_table
            .as_ref()
            .is_some_and(|table| table.contains_name(name))
    }

    fn extract_display_assigned_identifier(&self, lhs: &Expr) -> Option<String> {
        let raw = match &lhs.kind {
            ExprKind::Unknown(name) => self.resolve_display_identifier_name(name),
            ExprKind::Var(var) => {
                let renamed = self.rename_register_for_display(&var.name);
                self.apply_param_name_override(&renamed)
            }
            _ => return None,
        };
        let normalized = normalize_variable_name(&raw);
        let canonical = canonical_decl_var_name(&normalized)?;
        if is_likely_global_identifier(&canonical) {
            return None;
        }
        Some(canonical)
    }

    /// Recursively collects all variable names used in an expression.
    /// This includes variables on both LHS and RHS of assignments, in conditions, etc.
    fn collect_vars_from_expr(&self, expr: &Expr, vars: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                // Collect simple variable references that need declaration
                // This includes both original names (var_N, local_N, arg_N) and
                // semantically renamed variables (iter, idx, tmp0, saved1, etc.)
                let display_name = self.rename_register_for_display(&v.name);
                if is_declarable_variable(&v.name)
                    || (display_name != v.name
                        && is_declarable_variable(&display_name)
                        && !looks_like_parameter_name(&display_name))
                {
                    vars.insert(display_name);
                }
            }
            ExprKind::Deref { addr, .. } => {
                // Try to get the variable name from the dereference
                if let Some(var_name) = self.try_get_var_name(expr) {
                    vars.insert(var_name);
                }
                // Also collect variables from the address expression
                self.collect_vars_from_expr(addr, vars);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_vars_from_expr(left, vars);
                self.collect_vars_from_expr(right, vars);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.collect_vars_from_expr(operand, vars);
            }
            ExprKind::AddressOf(expr) => {
                self.collect_vars_from_expr(expr, vars);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                if let Some(var_name) = self.try_get_var_name(expr) {
                    vars.insert(var_name);
                }
                self.collect_vars_from_expr(base, vars);
                self.collect_vars_from_expr(index, vars);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_vars_from_expr(base, vars);
            }
            ExprKind::Call { target, args } => {
                // `va_arg(ap, T)` / `va_start(ap, last)` operands are rendered
                // verbatim — the `ap` cursor, type name, and last-parameter name
                // are not declarable locals.
                if matches!(target, CallTarget::Named(name) if name == "va_arg" || name == "va_start")
                {
                    return;
                }
                for arg in args {
                    self.collect_vars_from_expr(arg, vars);
                }
            }
            ExprKind::Assign { lhs, rhs } => {
                // Collect from LHS (for variable declarations)
                if let Some(var_name) = self.try_get_assigned_var_name(lhs) {
                    vars.insert(var_name);
                }
                // Also collect variables used in LHS address computation
                self.collect_vars_from_expr(lhs, vars);
                // Collect from RHS
                self.collect_vars_from_expr(rhs, vars);
            }
            ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let Some(var_name) = self.try_get_assigned_var_name(lhs) {
                    vars.insert(var_name);
                }
                self.collect_vars_from_expr(lhs, vars);
                self.collect_vars_from_expr(rhs, vars);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_vars_from_expr(cond, vars);
                self.collect_vars_from_expr(then_expr, vars);
                self.collect_vars_from_expr(else_expr, vars);
            }
            ExprKind::Cast { expr, .. } => {
                self.collect_vars_from_expr(expr, vars);
            }
            ExprKind::BitField { expr, .. } => {
                self.collect_vars_from_expr(expr, vars);
            }
            ExprKind::Phi(exprs) => {
                for e in exprs {
                    self.collect_vars_from_expr(e, vars);
                }
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                display_expr,
                ..
            } => {
                if self.should_recurse_into_gotref_display_expr(*address, *instruction_address) {
                    self.collect_vars_from_expr(display_expr, vars);
                }
            }
            // Literals don't contain variables.
            ExprKind::IntLit(_) => {}
            ExprKind::Unknown(name) => {
                if is_assignable_unknown_name(name) {
                    vars.insert(self.resolve_display_identifier_name(name));
                }
            }
        }
    }

    fn collect_assignment_based_local_types(
        &self,
        nodes: &[StructuredNode],
    ) -> HashMap<String, String> {
        let mut inferred = HashMap::new();
        self.collect_assignment_based_local_types_from_nodes(nodes, &mut inferred);
        inferred
    }

    fn collect_pointer_usage_types(&self, nodes: &[StructuredNode]) -> HashMap<String, String> {
        let mut inferred = HashMap::new();
        self.collect_pointer_usage_types_from_nodes(nodes, &mut inferred);
        inferred
    }

    fn collect_pointer_usage_types_from_nodes(
        &self,
        nodes: &[StructuredNode],
        inferred: &mut HashMap<String, String>,
    ) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.collect_pointer_usage_types_from_expr(stmt, inferred);
                    }
                }
                StructuredNode::Expr(expr) => {
                    self.collect_pointer_usage_types_from_expr(expr, inferred);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.collect_pointer_usage_types_from_expr(condition, inferred);
                    self.collect_pointer_usage_types_from_nodes(then_body, inferred);
                    if let Some(else_body) = else_body {
                        self.collect_pointer_usage_types_from_nodes(else_body, inferred);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                }
                | StructuredNode::DoWhile {
                    condition, body, ..
                } => {
                    self.collect_pointer_usage_types_from_expr(condition, inferred);
                    self.collect_pointer_usage_types_from_nodes(body, inferred);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(init) = init {
                        self.collect_pointer_usage_types_from_expr(init, inferred);
                    }
                    self.collect_pointer_usage_types_from_expr(condition, inferred);
                    if let Some(update) = update {
                        self.collect_pointer_usage_types_from_expr(update, inferred);
                    }
                    self.collect_pointer_usage_types_from_nodes(body, inferred);
                }
                StructuredNode::Loop { body, .. } => {
                    self.collect_pointer_usage_types_from_nodes(body, inferred);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    self.collect_pointer_usage_types_from_expr(value, inferred);
                    for (_, body) in cases {
                        self.collect_pointer_usage_types_from_nodes(body, inferred);
                    }
                    if let Some(default) = default {
                        self.collect_pointer_usage_types_from_nodes(default, inferred);
                    }
                }
                StructuredNode::Return(Some(expr)) => {
                    self.collect_pointer_usage_types_from_expr(expr, inferred);
                }
                StructuredNode::Sequence(nodes) => {
                    self.collect_pointer_usage_types_from_nodes(nodes, inferred);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    self.collect_pointer_usage_types_from_nodes(try_body, inferred);
                    for handler in catch_handlers {
                        self.collect_pointer_usage_types_from_nodes(&handler.body, inferred);
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

    fn collect_pointer_usage_types_from_expr(
        &self,
        expr: &Expr,
        inferred: &mut HashMap<String, String>,
    ) {
        match &expr.kind {
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                if let Some(base_name) = self.try_get_assigned_var_name(base) {
                    let should_update = inferred
                        .get(&base_name)
                        .is_none_or(|existing| !Self::is_pointer_like_type(existing));
                    if should_update {
                        if let Some(pointer_type) =
                            Self::pointer_type_for_element_size(*element_size)
                        {
                            inferred.insert(base_name, pointer_type.to_string());
                        }
                    }
                }
                self.collect_pointer_usage_types_from_expr(base, inferred);
                self.collect_pointer_usage_types_from_expr(index, inferred);
            }
            ExprKind::Assign { lhs, rhs } | ExprKind::CompoundAssign { lhs, rhs, .. } => {
                self.collect_pointer_usage_types_from_expr(lhs, inferred);
                self.collect_pointer_usage_types_from_expr(rhs, inferred);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_pointer_usage_types_from_expr(left, inferred);
                self.collect_pointer_usage_types_from_expr(right, inferred);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                self.collect_pointer_usage_types_from_expr(operand, inferred);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_pointer_usage_types_from_expr(base, inferred);
            }
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Indirect(expr) => {
                        self.collect_pointer_usage_types_from_expr(expr, inferred);
                    }
                    CallTarget::IndirectGot { expr, .. } => {
                        self.collect_pointer_usage_types_from_expr(expr, inferred);
                    }
                    CallTarget::Direct { .. } | CallTarget::Named(_) => {}
                }
                for arg in args {
                    self.collect_pointer_usage_types_from_expr(arg, inferred);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_pointer_usage_types_from_expr(cond, inferred);
                self.collect_pointer_usage_types_from_expr(then_expr, inferred);
                self.collect_pointer_usage_types_from_expr(else_expr, inferred);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    self.collect_pointer_usage_types_from_expr(value, inferred);
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                self.collect_pointer_usage_types_from_expr(display_expr, inferred);
            }
            ExprKind::Var(_) | ExprKind::IntLit(_) | ExprKind::Unknown(_) => {}
        }
    }

    fn pointer_type_for_element_size(element_size: usize) -> Option<&'static str> {
        match element_size {
            1 => Some("char*"),
            2 => Some("int16_t*"),
            4 => Some("int32_t*"),
            8 => Some("int64_t*"),
            _ => None,
        }
    }

    fn collect_assignment_based_local_types_from_nodes(
        &self,
        nodes: &[StructuredNode],
        inferred: &mut HashMap<String, String>,
    ) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.collect_assignment_based_local_types_from_expr(stmt, inferred);
                    }
                }
                StructuredNode::Expr(expr) => {
                    self.collect_assignment_based_local_types_from_expr(expr, inferred);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    self.collect_assignment_based_local_types_from_expr(condition, inferred);
                    self.collect_assignment_based_local_types_from_nodes(then_body, inferred);
                    if let Some(else_body) = else_body {
                        self.collect_assignment_based_local_types_from_nodes(else_body, inferred);
                    }
                }
                StructuredNode::While {
                    condition, body, ..
                }
                | StructuredNode::DoWhile {
                    condition, body, ..
                } => {
                    self.collect_assignment_based_local_types_from_expr(condition, inferred);
                    self.collect_assignment_based_local_types_from_nodes(body, inferred);
                }
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    if let Some(init) = init {
                        self.collect_assignment_based_local_types_from_expr(init, inferred);
                    }
                    self.collect_assignment_based_local_types_from_expr(condition, inferred);
                    if let Some(update) = update {
                        self.collect_assignment_based_local_types_from_expr(update, inferred);
                    }
                    self.collect_assignment_based_local_types_from_nodes(body, inferred);
                }
                StructuredNode::Loop { body, .. } => {
                    self.collect_assignment_based_local_types_from_nodes(body, inferred);
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                } => {
                    self.collect_assignment_based_local_types_from_expr(value, inferred);
                    for (_, body) in cases {
                        self.collect_assignment_based_local_types_from_nodes(body, inferred);
                    }
                    if let Some(default) = default {
                        self.collect_assignment_based_local_types_from_nodes(default, inferred);
                    }
                }
                StructuredNode::Return(Some(expr)) => {
                    self.collect_assignment_based_local_types_from_expr(expr, inferred);
                }
                StructuredNode::Sequence(nodes) => {
                    self.collect_assignment_based_local_types_from_nodes(nodes, inferred);
                }
                StructuredNode::TryCatch {
                    try_body,
                    catch_handlers,
                } => {
                    self.collect_assignment_based_local_types_from_nodes(try_body, inferred);
                    for handler in catch_handlers {
                        self.collect_assignment_based_local_types_from_nodes(
                            &handler.body,
                            inferred,
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

    fn collect_assignment_based_local_types_from_expr(
        &self,
        expr: &Expr,
        inferred: &mut HashMap<String, String>,
    ) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                if let Some(lhs_name) = self.try_get_assigned_var_name(lhs) {
                    if self.get_type(&lhs_name) == "int" {
                        if let Some(rhs_type) = self.infer_assignment_rhs_type(rhs) {
                            inferred.entry(lhs_name).or_insert(rhs_type);
                        }
                    }
                }
                self.collect_assignment_based_local_types_from_expr(lhs, inferred);
                self.collect_assignment_based_local_types_from_expr(rhs, inferred);
            }
            ExprKind::CompoundAssign { lhs, rhs, .. } => {
                self.collect_assignment_based_local_types_from_expr(lhs, inferred);
                self.collect_assignment_based_local_types_from_expr(rhs, inferred);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_assignment_based_local_types_from_expr(left, inferred);
                self.collect_assignment_based_local_types_from_expr(right, inferred);
            }
            ExprKind::UnaryOp { operand, .. }
            | ExprKind::Deref { addr: operand, .. }
            | ExprKind::AddressOf(operand)
            | ExprKind::Cast { expr: operand, .. }
            | ExprKind::BitField { expr: operand, .. } => {
                self.collect_assignment_based_local_types_from_expr(operand, inferred);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.collect_assignment_based_local_types_from_expr(base, inferred);
                self.collect_assignment_based_local_types_from_expr(index, inferred);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_assignment_based_local_types_from_expr(base, inferred);
            }
            ExprKind::Call { target, args } => {
                match target {
                    CallTarget::Indirect(expr) => {
                        self.collect_assignment_based_local_types_from_expr(expr, inferred);
                    }
                    CallTarget::IndirectGot { expr, .. } => {
                        self.collect_assignment_based_local_types_from_expr(expr, inferred);
                    }
                    CallTarget::Direct { .. } | CallTarget::Named(_) => {}
                }
                for arg in args {
                    self.collect_assignment_based_local_types_from_expr(arg, inferred);
                }
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.collect_assignment_based_local_types_from_expr(cond, inferred);
                self.collect_assignment_based_local_types_from_expr(then_expr, inferred);
                self.collect_assignment_based_local_types_from_expr(else_expr, inferred);
            }
            ExprKind::Phi(values) => {
                for value in values {
                    self.collect_assignment_based_local_types_from_expr(value, inferred);
                }
            }
            ExprKind::GotRef { display_expr, .. } => {
                self.collect_assignment_based_local_types_from_expr(display_expr, inferred);
            }
            ExprKind::Var(_) | ExprKind::IntLit(_) | ExprKind::Unknown(_) => {}
        }
    }

    fn infer_assignment_rhs_type(&self, rhs: &Expr) -> Option<String> {
        self.try_get_var_name(rhs)
            .and_then(|name| self.lookup_type_info(&name).map(str::to_string))
            .or_else(|| {
                if let ExprKind::Unknown(name) = &rhs.kind {
                    self.lookup_type_info(name).map(str::to_string)
                } else {
                    None
                }
            })
            .filter(|ty| Self::is_pointer_like_type(ty))
            .or_else(|| {
                self.get_expr_type(rhs)
                    .filter(|ty| Self::is_pointer_like_type(ty))
            })
    }

    fn is_pointer_like_type(ty: &str) -> bool {
        let ty = ty.trim();
        ty.contains("(*)") || ty.contains('*') || ty.ends_with("[]")
    }

    /// Analyzes a function body to detect parameters and return type.
    fn analyze_function(&self, body: &[StructuredNode]) -> FunctionInfo {
        let mut info = FunctionInfo {
            parameters: Vec::new(),
            has_return_value: false,
            skip_statements: HashSet::new(),
        };

        // Check first block for parameter patterns and prologue
        if let Some(StructuredNode::Block { id, statements, .. }) = body.first() {
            let block_id = *id;
            for (idx, stmt) in statements.iter().enumerate() {
                // Parameter setup should happen before any real call in prologue.
                // If we already reached a call, stop scanning to avoid treating
                // post-call return-register uses as function parameters.
                if let ExprKind::Call { .. } = &stmt.kind {
                    break;
                }

                // Skip prologue statements
                if is_prologue_statement(stmt) {
                    info.skip_statements.insert((block_id, idx));
                    continue;
                }

                // Check for parameter assignments (var = arg_register)
                if let ExprKind::Assign { lhs, rhs } = &stmt.kind {
                    // Check if RHS is an argument register
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if let Some(arg_idx) = get_arg_register_index(&rhs_var.name) {
                            // Check if LHS is a stack variable - use DWARF-aware naming
                            let lhs_name = self.try_get_var_name(lhs);
                            if let Some(var_name) = lhs_name {
                                // Accept any DWARF name or standard stack var patterns
                                if !var_name.is_empty() {
                                    // This is a parameter: use the stack var name as param name
                                    // Ensure we have enough slots
                                    while info.parameters.len() <= arg_idx {
                                        info.parameters.push(String::new());
                                    }
                                    info.parameters[arg_idx] = var_name;
                                    info.skip_statements.insert((block_id, idx));
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Stop after the first non-prologue, non-parameter-setup statement.
                // This keeps parameter inference anchored to function entry setup.
                break;
            }
        }

        // Check all blocks for epilogue statements
        for node in body.iter() {
            if let StructuredNode::Block { id, statements, .. } = node {
                let block_id = *id;
                for (idx, stmt) in statements.iter().enumerate() {
                    if is_epilogue_statement(stmt) {
                        info.skip_statements.insert((block_id, idx));
                    }
                }
            }
        }

        // Remove empty parameter slots (non-contiguous parameters)
        info.parameters = info
            .parameters
            .into_iter()
            .take_while(|p| !p.is_empty())
            .collect();

        // Check for return values
        info.has_return_value = self.has_return_value(body);

        info
    }

    /// Checks if the function body has any return statements with values.
    #[allow(clippy::only_used_in_recursion)] // recurses through nested control structures
    fn has_return_value(&self, nodes: &[StructuredNode]) -> bool {
        for node in nodes {
            match node {
                StructuredNode::Return(Some(_)) => return true,
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    if self.has_return_value(then_body) {
                        return true;
                    }
                    if let Some(else_nodes) = else_body {
                        if self.has_return_value(else_nodes) {
                            return true;
                        }
                    }
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    if self.has_return_value(body) {
                        return true;
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        if self.has_return_value(case_body) {
                            return true;
                        }
                    }
                    if let Some(def) = default {
                        if self.has_return_value(def) {
                            return true;
                        }
                    }
                }
                StructuredNode::Sequence(nodes) => {
                    if self.has_return_value(nodes) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Emits nodes, skipping specified statements and tracking variable declarations.
    ///
    /// When `is_top_level` is true, we don't break on control exits because labeled
    /// sections after gotos are still reachable via those gotos.
    fn emit_nodes_with_skip_and_decls(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        skip: &HashSet<(BasicBlockId, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        self.emit_nodes_with_skip_and_decls_inner(nodes, output, depth, skip, declared_vars, true)
    }

    fn emit_nodes_with_skip_and_decls_inner(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        skip: &HashSet<(BasicBlockId, usize)>,
        declared_vars: &mut HashSet<String>,
        is_top_level: bool,
    ) {
        for (block_idx, node) in nodes.iter().enumerate() {
            self.emit_node_with_skip_and_decls(node, output, depth, skip, declared_vars);
            if self.is_control_exit(node) {
                if !is_top_level {
                    break;
                }
                // At top-level, keep scanning only when there are labels ahead that
                // can still be reached via explicit gotos.
                let has_later_label = nodes[block_idx + 1..]
                    .iter()
                    .any(|n| matches!(n, StructuredNode::Label(_)));
                if !has_later_label {
                    break;
                }
            }
        }
    }

    fn rewrite_single_call_condition_while_for_emission(
        &self,
        condition: &Expr,
        body: &[StructuredNode],
    ) -> Option<Vec<StructuredNode>> {
        let (tail, prefix) = body.split_last()?;

        if prefix.is_empty() {
            if let Some(exit_body) = self.match_single_call_loop_exit_for_emission(tail, condition)
            {
                return Some(self.build_single_call_loop_body_for_emission(
                    Vec::new(),
                    condition.clone(),
                    exit_body,
                ));
            }
        }

        let captured_condition =
            self.extract_single_call_loop_condition_capture_for_emission(prefix, condition)?;
        let exit_body = self.match_single_call_loop_exit_for_emission(tail, &captured_condition)?;
        Some(self.build_single_call_loop_body_for_emission(
            prefix.to_vec(),
            captured_condition,
            exit_body,
        ))
    }

    fn build_single_call_loop_body_for_emission(
        &self,
        mut prefix: Vec<StructuredNode>,
        condition: Expr,
        mut exit_body: Vec<StructuredNode>,
    ) -> Vec<StructuredNode> {
        if !super::structurer::body_terminates(&exit_body) {
            exit_body.push(StructuredNode::Break);
        }

        prefix.push(StructuredNode::If {
            condition: condition.negate(),
            then_body: exit_body,
            else_body: None,
        });
        prefix
    }

    fn extract_single_call_loop_condition_capture_for_emission(
        &self,
        prefix: &[StructuredNode],
        loop_condition: &Expr,
    ) -> Option<Expr> {
        let last_expr = match prefix.last()? {
            StructuredNode::Expr(expr) => Some(expr),
            StructuredNode::Block { statements, .. } => statements.last(),
            _ => None,
        }?;

        let ExprKind::Assign { lhs, rhs } = &last_expr.kind else {
            return None;
        };

        if self.exprs_match_for_single_call_loop_emission(rhs, loop_condition) {
            return Some((**lhs).clone());
        }

        None
    }

    fn match_single_call_loop_exit_for_emission(
        &self,
        tail: &StructuredNode,
        success_condition: &Expr,
    ) -> Option<Vec<StructuredNode>> {
        let StructuredNode::If {
            condition,
            then_body,
            else_body,
        } = tail
        else {
            return None;
        };

        let success_base = self.single_call_loop_condition_base_for_emission(success_condition)?;
        let (if_base, if_positive) =
            self.single_call_loop_condition_base_with_polarity_for_emission(condition)?;
        if if_base != success_base {
            return None;
        }

        if if_positive && then_body.is_empty() {
            return else_body.clone();
        }

        if !if_positive && else_body.is_none() {
            return Some(then_body.clone());
        }

        None
    }

    fn single_call_loop_condition_base_for_emission(&self, expr: &Expr) -> Option<String> {
        let (base, _) = self.single_call_loop_condition_base_with_polarity_for_emission(expr)?;
        Some(base)
    }

    fn single_call_loop_condition_base_with_polarity_for_emission(
        &self,
        expr: &Expr,
    ) -> Option<(String, bool)> {
        match &expr.kind {
            ExprKind::UnaryOp {
                op: UnaryOpKind::Not,
                operand,
            } => self
                .single_call_loop_condition_base_with_polarity_for_emission(operand)
                .map(|(base, positive)| (base, !positive)),
            ExprKind::BinOp {
                op: BinOpKind::Ne,
                left,
                right,
            } => {
                if matches!(right.kind, ExprKind::IntLit(0)) {
                    return Some((format!("{left}"), true));
                }
                if matches!(left.kind, ExprKind::IntLit(0)) {
                    return Some((format!("{right}"), true));
                }
                None
            }
            ExprKind::BinOp {
                op: BinOpKind::Eq,
                left,
                right,
            } => {
                if matches!(right.kind, ExprKind::IntLit(0)) {
                    return Some((format!("{left}"), false));
                }
                if matches!(left.kind, ExprKind::IntLit(0)) {
                    return Some((format!("{right}"), false));
                }
                None
            }
            ExprKind::Var(_) | ExprKind::Call { .. } | ExprKind::Unknown(_) => {
                Some((format!("{expr}"), true))
            }
            _ => None,
        }
    }

    fn exprs_match_for_single_call_loop_emission(&self, left: &Expr, right: &Expr) -> bool {
        format!("{left}") == format!("{right}")
    }

    fn emit_node_with_skip_and_decls(
        &self,
        node: &StructuredNode,
        output: &mut String,
        depth: usize,
        skip: &HashSet<(BasicBlockId, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                let block_id = *id;
                // Filter out skipped statements using BasicBlockId
                let filtered: Vec<_> = statements
                    .iter()
                    .enumerate()
                    .filter(|(stmt_idx, _)| !skip.contains(&(block_id, *stmt_idx)))
                    .map(|(_, stmt)| stmt)
                    .collect();

                if self.emit_addresses {
                    let indent = self.indent.repeat(depth);
                    writeln!(
                        output,
                        "{}// bb{} [{:#x}..{:#x}]",
                        indent, id.0, address_range.0, address_range.1
                    )
                    .unwrap();
                }

                // Get data relocations for this block to resolve `reg = 0` assignments
                let data_relocs = if let Some(ref reloc_table) = self.relocation_table {
                    reloc_table.get_data_in_range(address_range.0, address_range.1)
                } else {
                    Vec::new()
                };
                let mut reloc_idx = 0;

                for stmt in filtered {
                    // Check if this is a Call with IntLit(0) arguments and we have relocations
                    if !data_relocs.is_empty() {
                        if let ExprKind::Call { target, args } = &stmt.kind {
                            let has_zero_arg = args
                                .iter()
                                .any(|arg| matches!(arg.kind, ExprKind::IntLit(0)));
                            if has_zero_arg {
                                self.emit_call_with_relocations(
                                    target,
                                    args,
                                    &data_relocs,
                                    &mut reloc_idx,
                                    output,
                                    depth,
                                );
                                continue;
                            }
                        }
                    }
                    self.emit_statement_with_decl(stmt, output, depth, declared_vars);
                }
            }
            // For control flow structures, recurse with the same declared_vars
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Skip stack canary check: if (check) { __stack_chk_fail(); }
                // Check both then and else bodies since compiler may invert the condition
                if self.is_guarded_stack_canary_branch(condition, then_body) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if self.is_guarded_stack_canary_branch(condition, else_nodes) {
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().is_none_or(|e| self.is_body_empty(e));

                // Skip entirely if both bodies are empty
                if then_empty && else_empty {
                    return;
                }

                let indent = self.indent.repeat(depth);

                // Determine actual condition and bodies
                let (actual_cond, actual_then, actual_else) = if then_empty && !else_empty {
                    (
                        condition.clone().negate(),
                        else_body.as_ref().unwrap(),
                        None,
                    )
                } else if !then_empty && else_empty {
                    (condition.clone(), then_body, None)
                } else {
                    (condition.clone(), then_body, else_body.as_ref())
                };

                writeln!(
                    output,
                    "{}if ({}) {{",
                    indent,
                    self.format_condition_expr(&actual_cond)
                )
                .unwrap();
                self.emit_nodes_with_decls(actual_then, output, depth + 1, declared_vars);
                // Emit else clause (handles else-if chains recursively)
                self.emit_else_clause_with_decls(
                    &actual_else.map(|v| v.to_vec()),
                    output,
                    depth,
                    &indent,
                    declared_vars,
                );
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                // Eliminate dead loops: while (0) { ... } - body never executes
                if let Some(0) = self.try_eval_constant(condition) {
                    return;
                }
                let indent = self.indent.repeat(depth);
                if let Some(rewritten_body) =
                    self.rewrite_single_call_condition_while_for_emission(condition, body)
                {
                    writeln!(output, "{}while (1) {{", indent).unwrap();
                    self.emit_nodes_with_decls(&rewritten_body, output, depth + 1, declared_vars);
                    writeln!(output, "{}}}", indent).unwrap();
                    return;
                }
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(
                    output,
                    "{}}} while ({});",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
            }
            StructuredNode::Loop { body, .. } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            // For other node types, delegate to the normal emit_node
            _ => self.emit_node(node, output, depth),
        }
    }

    /// Emits nodes tracking variable declarations.
    fn emit_nodes_with_decls(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        declared_vars: &mut HashSet<String>,
    ) {
        for node in nodes {
            self.emit_node_with_decls(node, output, depth, declared_vars);
            if self.is_control_exit(node) {
                break;
            }
        }
    }

    fn emit_node_with_decls(
        &self,
        node: &StructuredNode,
        output: &mut String,
        depth: usize,
        declared_vars: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                if self.emit_addresses {
                    let indent = self.indent.repeat(depth);
                    writeln!(
                        output,
                        "{}// bb{} [{:#x}..{:#x}]",
                        indent, id.0, address_range.0, address_range.1
                    )
                    .unwrap();
                }

                // Get data relocations for this block to resolve `reg = 0` assignments
                let data_relocs = if let Some(ref reloc_table) = self.relocation_table {
                    reloc_table.get_data_in_range(address_range.0, address_range.1)
                } else {
                    Vec::new()
                };
                let mut reloc_idx = 0;

                for stmt in statements {
                    // Check if this is a Call with IntLit(0) arguments and we have relocations
                    if !data_relocs.is_empty() {
                        if let ExprKind::Call { target, args } = &stmt.kind {
                            let has_zero_arg = args
                                .iter()
                                .any(|arg| matches!(arg.kind, ExprKind::IntLit(0)));
                            if has_zero_arg {
                                self.emit_call_with_relocations(
                                    target,
                                    args,
                                    &data_relocs,
                                    &mut reloc_idx,
                                    output,
                                    depth,
                                );
                                continue;
                            }
                        }
                    }
                    self.emit_statement_with_decl(stmt, output, depth, declared_vars);
                }
            }
            // For control flow structures, recurse
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Skip stack canary check: if (check) { __stack_chk_fail(); }
                // Check both then and else bodies since compiler may invert the condition
                if self.is_guarded_stack_canary_branch(condition, then_body) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if self.is_guarded_stack_canary_branch(condition, else_nodes) {
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().is_none_or(|e| self.is_body_empty(e));

                // Skip entirely if both bodies are empty
                if then_empty && else_empty {
                    return;
                }

                let indent = self.indent.repeat(depth);

                // Determine actual condition and bodies
                let (actual_cond, actual_then, actual_else) = if then_empty && !else_empty {
                    (
                        condition.clone().negate(),
                        else_body.as_ref().unwrap(),
                        None,
                    )
                } else if !then_empty && else_empty {
                    (condition.clone(), then_body, None)
                } else {
                    (condition.clone(), then_body, else_body.as_ref())
                };

                writeln!(
                    output,
                    "{}if ({}) {{",
                    indent,
                    self.format_condition_expr(&actual_cond)
                )
                .unwrap();
                self.emit_nodes_with_decls(actual_then, output, depth + 1, declared_vars);
                // Emit else clause (handles else-if chains recursively)
                self.emit_else_clause_with_decls(
                    &actual_else.map(|v| v.to_vec()),
                    output,
                    depth,
                    &indent,
                    declared_vars,
                );
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                // Eliminate dead loops: while (0) { ... } - body never executes
                if let Some(0) = self.try_eval_constant(condition) {
                    return;
                }
                let indent = self.indent.repeat(depth);
                if let Some(rewritten_body) =
                    self.rewrite_single_call_condition_while_for_emission(condition, body)
                {
                    writeln!(output, "{}while (1) {{", indent).unwrap();
                    self.emit_nodes_with_decls(&rewritten_body, output, depth + 1, declared_vars);
                    writeln!(output, "{}}}", indent).unwrap();
                    return;
                }
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(
                    output,
                    "{}}} while ({});",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
            }
            StructuredNode::Loop { body, .. } => {
                let indent = self.indent.repeat(depth);
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes_with_decls(body, output, depth + 1, declared_vars);
                writeln!(output, "{}}}", indent).unwrap();
            }
            _ => self.emit_node(node, output, depth),
        }
    }

    /// Emits a Call expression with data relocations resolved for IntLit(0) arguments.
    fn emit_call_with_relocations(
        &self,
        target: &super::expression::CallTarget,
        args: &[Expr],
        data_relocs: &[(u64, &str)],
        reloc_idx: &mut usize,
        output: &mut String,
        depth: usize,
    ) {
        let indent = self.indent.repeat(depth);

        // Format the call target
        let target_str = match target {
            super::expression::CallTarget::Direct {
                target: addr,
                call_site,
            } => {
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get(*call_site) {
                        self.format_call_target_name(name)
                    } else if let Some(ref sym_table) = self.symbol_table {
                        sym_table
                            .get(*addr)
                            .map(|s| self.format_call_target_name(s))
                            .unwrap_or_else(|| format!("sub_{:x}", addr))
                    } else {
                        format!("sub_{:x}", addr)
                    }
                } else if let Some(ref sym_table) = self.symbol_table {
                    sym_table
                        .get(*addr)
                        .map(|s| self.format_call_target_name(s))
                        .unwrap_or_else(|| format!("sub_{:x}", addr))
                } else {
                    format!("sub_{:x}", addr)
                }
            }
            super::expression::CallTarget::Named(name) => self.format_call_target_name(name),
            super::expression::CallTarget::Indirect(e) => format!("({})", self.format_expr(e)),
            super::expression::CallTarget::IndirectGot { got_address, expr } => {
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*got_address) {
                        self.format_indirect_got_call_target(name)
                    } else {
                        format!("({})", self.format_expr(expr))
                    }
                } else {
                    format!("({})", self.format_expr(expr))
                }
            }
        };

        // Format arguments, replacing IntLit(0) with relocation symbols
        let mut formatted_args = Vec::new();
        for arg in args {
            if let ExprKind::IntLit(0) = arg.kind {
                if *reloc_idx < data_relocs.len() {
                    let (_, symbol) = data_relocs[*reloc_idx];
                    *reloc_idx += 1;
                    // String literals (starting with ") don't need & prefix
                    if symbol.starts_with('"') {
                        formatted_args.push(symbol.to_string());
                    } else {
                        formatted_args.push(format!("&{}", symbol));
                    }
                    continue;
                }
            }
            formatted_args.push(self.format_expr(arg));
        }

        writeln!(
            output,
            "{}{}({});",
            indent,
            target_str,
            formatted_args.join(", ")
        )
        .unwrap();
    }

    fn is_comment_statement_text(text: &str) -> bool {
        let trimmed = text.trim();
        (trimmed.starts_with("/*") && trimmed.ends_with("*/")) || trimmed.starts_with("//")
    }

    fn opaque_x86_integer_simd_statement(expr: &Expr) -> Option<String> {
        let ExprKind::Call { target, .. } = &expr.kind else {
            return None;
        };
        let CallTarget::Named(name) = target else {
            return None;
        };
        if Self::looks_like_x86_integer_simd_mnemonic(name) {
            Some(format!("/* SSE: {} */", name.to_ascii_lowercase()))
        } else {
            None
        }
    }

    fn looks_like_x86_integer_simd_mnemonic(name: &str) -> bool {
        let mnemonic = name.to_ascii_lowercase();
        [
            "punpck", "vpunpck", "pshuf", "vpshuf", "padd", "vpadd", "psub", "vpsub", "pmul",
            "vpmul", "pack", "vpack", "pcmp", "vpcmp", "pand", "vpand", "por", "vpor", "pxor",
            "vpxor", "psll", "vpsll", "psrl", "vpsrl", "psra", "vpsra", "palignr", "vpalignr",
            "pblend", "vpblend", "pinsr", "vpinsr", "pextr", "vpextr", "phadd", "vphadd", "phsub",
            "vphsub", "pabs", "vpabs", "pavg", "vpavg", "pmax", "vpmax", "pmin", "vpmin", "pmadd",
            "vpmadd", "pmov", "vpmov", "ptest", "vptest", "psadbw", "vpsadbw", "mpsadbw",
            "vmpsadbw",
        ]
        .iter()
        .any(|prefix| mnemonic.starts_with(prefix))
    }

    /// Emits a statement (variables are declared at function top, so no inline declarations).
    fn emit_statement_with_decl(
        &self,
        expr: &Expr,
        output: &mut String,
        depth: usize,
        _declared_vars: &mut HashSet<String>,
    ) {
        // Skip prologue/epilogue boilerplate
        if self.is_prologue_epilogue(expr) {
            return;
        }

        // Skip redundant no-op assignments
        if self.is_noop_assignment(expr) {
            return;
        }

        // Skip ARM64 argument setup noise and other skippable patterns
        if self.is_skippable_statement(expr) {
            return;
        }

        let indent = self.indent.repeat(depth);
        if let Some(comment) = Self::opaque_x86_integer_simd_statement(expr) {
            writeln!(output, "{}{}", indent, comment).unwrap();
            return;
        }
        let expr_str = self.format_expr(expr);

        // Skip empty/nop statements and trivial literal statements
        if expr_str.is_empty() || expr_str == "/* nop */" || expr_str == "0" || expr_str == "1" {
            return;
        }

        // Skip stack adjustment patterns that result from ARM64 sp operations
        // These appear as "0 -= N" or "0 += N" when the stack pointer isn't resolved
        if expr_str.starts_with("0 -= ") || expr_str.starts_with("0 += ") {
            return;
        }

        if Self::is_comment_statement_text(&expr_str) {
            writeln!(output, "{}{}", indent, expr_str).unwrap();
            return;
        }

        if expr_str == "return" {
            self.emit_return_line(output, &indent, None);
            return;
        }

        writeln!(output, "{}{};", indent, expr_str).unwrap();
    }

    fn emit_nodes(&self, nodes: &[StructuredNode], output: &mut String, depth: usize) {
        for node in nodes {
            self.emit_node(node, output, depth);
            // Stop emitting after control flow that exits the current scope
            if self.is_control_exit(node) {
                break;
            }
        }
    }

    /// Emit an else clause, handling else-if chains without extra indentation.
    fn emit_else_clause(
        &self,
        else_body: &Option<Vec<StructuredNode>>,
        output: &mut String,
        depth: usize,
        indent: &str,
    ) {
        let Some(else_nodes) = else_body else {
            return;
        };

        if self.is_body_empty(else_nodes) {
            return;
        }

        // Check for else-if pattern: single If node in else body
        if else_nodes.len() == 1 {
            if let StructuredNode::If {
                condition,
                then_body,
                else_body: nested_else,
            } = &else_nodes[0]
            {
                // Skip stack canary checks in else-if
                if self.is_guarded_stack_canary_branch(condition, then_body) {
                    return;
                }

                // Emit as "} else if (cond) {" on one line
                writeln!(
                    output,
                    "{}}} else if ({}) {{",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
                self.emit_nodes(then_body, output, depth + 1);

                // Recursively handle nested else clauses
                self.emit_else_clause(nested_else, output, depth, indent);
                return;
            }
        }

        // Regular else block
        writeln!(output, "{}}} else {{", indent).unwrap();
        self.emit_nodes(else_nodes, output, depth + 1);
    }

    /// Emit an else clause with variable declarations, handling else-if chains.
    fn emit_else_clause_with_decls(
        &self,
        else_body: &Option<Vec<StructuredNode>>,
        output: &mut String,
        depth: usize,
        indent: &str,
        declared_vars: &mut HashSet<String>,
    ) {
        let Some(else_nodes) = else_body else {
            return;
        };

        if self.is_body_empty(else_nodes) {
            return;
        }

        // Check for else-if pattern: single If node in else body
        if else_nodes.len() == 1 {
            if let StructuredNode::If {
                condition,
                then_body,
                else_body: nested_else,
            } = &else_nodes[0]
            {
                // Skip stack canary checks in else-if
                if self.is_guarded_stack_canary_branch(condition, then_body) {
                    return;
                }

                // Emit as "} else if (cond) {" on one line
                writeln!(
                    output,
                    "{}}} else if ({}) {{",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
                self.emit_nodes_with_decls(then_body, output, depth + 1, declared_vars);

                // Recursively handle nested else clauses
                self.emit_else_clause_with_decls(nested_else, output, depth, indent, declared_vars);
                return;
            }
        }

        // Regular else block
        writeln!(output, "{}}} else {{", indent).unwrap();
        self.emit_nodes_with_decls(else_nodes, output, depth + 1, declared_vars);
    }

    /// Checks if a body (list of nodes) ends with a control flow exit.
    fn body_ends_with_control_exit(&self, body: &[StructuredNode]) -> bool {
        body.last().is_some_and(|n| self.is_control_exit(n))
            || Self::body_ends_with_throw_thunk_call(body)
    }

    /// Checks if a node is a control flow exit (goto, return, break, continue, noreturn call).
    #[allow(clippy::only_used_in_recursion)] // recurses into nested If branches
    fn is_control_exit(&self, node: &StructuredNode) -> bool {
        match node {
            StructuredNode::Goto(_)
            | StructuredNode::Return(_)
            | StructuredNode::Break
            | StructuredNode::Continue => true,
            // Check if an if-else exits on both branches
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                let then_exits = self.body_ends_with_control_exit(then_body);
                let else_exits = else_body
                    .as_ref()
                    .is_some_and(|body| self.body_ends_with_control_exit(body));
                then_exits && else_exits
            }
            // Check for noreturn function calls or recovered throw markers.
            StructuredNode::Expr(expr) => {
                Self::is_noreturn_call(expr) || Self::is_throw_marker_expr(expr)
            }
            StructuredNode::Block { statements, .. } => statements
                .last()
                .is_some_and(|s| Self::is_noreturn_call(s) || Self::is_throw_marker_expr(s)),
            _ => false,
        }
    }

    /// Recognise the recovered-throw `Expr::unknown` shapes (cold-clone
    /// thunk marker from deferral #4 and the `__cxa_throw` triple
    /// collapse marker from deferral #6) as control-flow exits. Codex
    /// review on PR #13 flagged that without this check, the throw
    /// marker inside a Block's tail statement didn't propagate up to
    /// `body_ends_with_control_exit`, leaving a spurious `return 0;`
    /// after `throw 42;` in non-void throw-only functions.
    fn is_throw_marker_expr(expr: &Expr) -> bool {
        let ExprKind::Unknown(text) = &expr.kind else {
            return false;
        };
        let trimmed = text.trim_start();
        if trimmed.starts_with("throw /* via ") && text.trim_end().ends_with("*/") {
            return true;
        }
        if let Some(rest) = trimmed.strip_prefix("throw ") {
            return !rest.is_empty();
        }
        false
    }

    fn body_ends_with_throw_thunk_call(body: &[StructuredNode]) -> bool {
        let Some(StructuredNode::Expr(last)) = body.last() else {
            return false;
        };
        let ExprKind::Unknown(text) = &last.kind else {
            return false;
        };
        // Two emitter-produced markers that have to be treated as
        // control-flow exits so we don't append a synthetic fallback
        // return or fall through:
        //
        // 1. The cold-clone throw thunk shape from deferral #4:
        //    `throw /* via NAME() */`.
        // 2. The collapsed `__cxa_throw` triple from deferral #6:
        //    `throw VALUE` or `throw Class(args)`.
        //
        // Codex review on PR #13 flagged that shape (2) was missing
        // here, which let non-void throw-only functions surface a
        // bogus `return 0;` after the recovered throw.
        let trimmed = text.trim_start();
        if trimmed.starts_with("throw /* via ") && text.trim_end().ends_with("*/") {
            return true;
        }
        // Any "throw <expr>" line is terminal. Constrain to a single
        // statement so a stray identifier starting with "throw_" can't
        // collide.
        if let Some(rest) = trimmed.strip_prefix("throw ") {
            return !rest.is_empty();
        }
        false
    }

    /// Checks if an expression is a call to a noreturn function.
    fn is_noreturn_call(expr: &Expr) -> bool {
        match &expr.kind {
            ExprKind::Call {
                target: CallTarget::Named(name),
                ..
            } => Self::is_noreturn_function(name),
            ExprKind::Assign { rhs, .. } => Self::is_noreturn_call(rhs),
            _ => false,
        }
    }

    /// Checks if a function name is a known noreturn function.
    fn is_noreturn_function(name: &str) -> bool {
        crate::is_noreturn_function_name(name)
    }

    /// Checks if a body (list of nodes) is empty or contains only empty/skippable blocks.
    fn is_body_empty(&self, nodes: &[StructuredNode]) -> bool {
        if nodes.is_empty() {
            return true;
        }
        // Check if all nodes are empty blocks or blocks with only skippable statements
        nodes.iter().all(|node| match node {
            StructuredNode::Block { statements, .. } => {
                statements.is_empty() || statements.iter().all(|s| self.is_skippable_statement(s))
            }
            StructuredNode::Sequence(inner) => self.is_body_empty(inner),
            // An If with empty bodies is itself empty
            StructuredNode::If {
                then_body,
                else_body,
                ..
            } => {
                self.is_body_empty(then_body)
                    && else_body.as_ref().is_none_or(|e| self.is_body_empty(e))
            }
            _ => false,
        })
    }

    /// Try to evaluate an expression as a constant integer value.
    /// Returns Some(value) if the expression is a constant, None otherwise.
    #[allow(clippy::only_used_in_recursion)] // recursive constant folding over Expr
    fn try_eval_constant(&self, expr: &Expr) -> Option<i128> {
        match &expr.kind {
            ExprKind::IntLit(val) => Some(*val),
            ExprKind::BinOp { op, left, right } => {
                let l = self.try_eval_constant(left)?;
                let r = self.try_eval_constant(right)?;
                match op {
                    BinOpKind::Add => Some(l.wrapping_add(r)),
                    BinOpKind::Sub => Some(l.wrapping_sub(r)),
                    BinOpKind::Mul => Some(l.wrapping_mul(r)),
                    BinOpKind::Div if r != 0 => Some(l / r),
                    BinOpKind::Mod if r != 0 => Some(l % r),
                    BinOpKind::And => Some(l & r),
                    BinOpKind::Or => Some(l | r),
                    BinOpKind::Xor => Some(l ^ r),
                    BinOpKind::Eq => Some(if l == r { 1 } else { 0 }),
                    BinOpKind::Ne => Some(if l != r { 1 } else { 0 }),
                    BinOpKind::Lt => Some(if l < r { 1 } else { 0 }),
                    BinOpKind::Le => Some(if l <= r { 1 } else { 0 }),
                    BinOpKind::Gt => Some(if l > r { 1 } else { 0 }),
                    BinOpKind::Ge => Some(if l >= r { 1 } else { 0 }),
                    BinOpKind::LogicalAnd => Some(if l != 0 && r != 0 { 1 } else { 0 }),
                    BinOpKind::LogicalOr => Some(if l != 0 || r != 0 { 1 } else { 0 }),
                    _ => None,
                }
            }
            ExprKind::UnaryOp { op, operand } => {
                let val = self.try_eval_constant(operand)?;
                match op {
                    UnaryOpKind::Neg => Some(-val),
                    UnaryOpKind::Not => Some(!val),
                    UnaryOpKind::LogicalNot => Some(if val == 0 { 1 } else { 0 }),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Try to fold chained constant operations: (a op c1) op c2 -> a op (c1 op c2)
    /// For associative operations like &, |, ^, +, * where constants can be folded together.
    fn try_fold_chained_constants(
        &self,
        op: &BinOpKind,
        left: &Expr,
        right: &Expr,
        table: &StringTable,
    ) -> Option<String> {
        // Only handle associative operations where constant folding makes sense
        if !matches!(
            op,
            BinOpKind::And | BinOpKind::Or | BinOpKind::Xor | BinOpKind::Add | BinOpKind::Mul
        ) {
            return None;
        }

        // Pattern: (expr op c1) op c2 where c1 and c2 are constants
        if let ExprKind::BinOp {
            op: inner_op,
            left: inner_left,
            right: inner_right,
        } = &left.kind
        {
            if inner_op == op {
                // Both operations are the same type
                if let (Some(c1), Some(c2)) = (
                    self.try_eval_constant(inner_right),
                    self.try_eval_constant(right),
                ) {
                    // Fold the constants
                    let folded = match op {
                        BinOpKind::And => c1 & c2,
                        BinOpKind::Or => c1 | c2,
                        BinOpKind::Xor => c1 ^ c2,
                        BinOpKind::Add => c1.wrapping_add(c2),
                        BinOpKind::Mul => c1.wrapping_mul(c2),
                        _ => return None,
                    };

                    // Format as: inner_left op folded
                    let left_str = self.format_expr_with_strings(inner_left, table);
                    let right_str = format_integer(folded);
                    return Some(format!("{} {} {}", left_str, op.as_str(), right_str));
                }
            }
        }

        None
    }

    /// Checks if a statement would be skipped during emission (prologue/epilogue/etc).
    fn is_skippable_statement(&self, expr: &Expr) -> bool {
        use super::expression::ExprKind;

        match &expr.kind {
            // Trivial integer literals (0, 1) - often from ARM64 wzr/xzr zero register
            ExprKind::IntLit(n) if *n == 0 || *n == 1 => true,
            // pop(reg) - epilogue
            ExprKind::Call { target, .. } => {
                if let super::expression::CallTarget::Named(name) = target {
                    if name == "pop" || name == "push" {
                        return true;
                    }
                }
                false
            }
            // Return value setup: rax/eax = something
            // Also skip ARM64 argument setup patterns
            ExprKind::Assign { lhs, rhs } => {
                if self.is_gcov_counter_statement(expr) {
                    return true;
                }
                // Return-register assignments can be real loop-carried state, not just
                // epilogue setup. Only skip the epilogue-shaped cases handled elsewhere.
                // ARM64 argument setup: *(uint64_t*)(x9) = x8 or similar
                // Store through temporary registers (x8-x17) to stack
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    if is_arm64_temp_register_expr(addr) {
                        // Store through temp register (likely argument setup)
                        return true;
                    }
                }
                // ARM64: var = w9 or similar (sign extension artifact)
                // BUT: Don't skip if LHS is a parameter register that may be a loop variable
                if let ExprKind::Var(rhs_var) = &rhs.kind {
                    if is_arm64_temp_register(&rhs_var.name) {
                        // Don't skip if LHS is a parameter register (x0-x7/w0-w7)
                        // because those may be loop variables being updated
                        if let ExprKind::Var(lhs_var) = &lhs.kind {
                            if matches!(
                                lhs_var.name.as_str(),
                                "x0" | "x1"
                                    | "x2"
                                    | "x3"
                                    | "x4"
                                    | "x5"
                                    | "x6"
                                    | "x7"
                                    | "w0"
                                    | "w1"
                                    | "w2"
                                    | "w3"
                                    | "w4"
                                    | "w5"
                                    | "w6"
                                    | "w7"
                            ) {
                                return false; // Don't skip - preserve this assignment
                            }
                        }
                        // For all other LHS (locals, unknowns, etc.), skip it
                        return true;
                    }
                }
                // Stack canary load: var = *(*(GOT_address))
                if is_stack_canary_load(expr) {
                    return true;
                }
                false
            }
            ExprKind::CompoundAssign { .. } => self.is_gcov_counter_statement(expr),
            _ => false,
        }
    }

    fn emit_node(&self, node: &StructuredNode, output: &mut String, depth: usize) {
        let indent = self.indent.repeat(depth);

        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                if self.emit_addresses {
                    writeln!(
                        output,
                        "{}// {} [{:#x} - {:#x}]",
                        indent, id, address_range.0, address_range.1
                    )
                    .unwrap();
                }
                // Get data relocations for this block to resolve `reg = 0` assignments
                let data_relocs = if let Some(ref reloc_table) = self.relocation_table {
                    let relocs = reloc_table.get_data_in_range(address_range.0, address_range.1);
                    relocs
                } else {
                    Vec::new()
                };
                let mut reloc_idx = 0;

                for stmt in statements {
                    // Check if this is an assignment of 0 and we have a data relocation
                    if let ExprKind::Assign { rhs, .. } = &stmt.kind {
                        if let ExprKind::IntLit(0) = rhs.kind {
                            if reloc_idx < data_relocs.len() {
                                // Replace with symbol reference
                                let (_, symbol) = data_relocs[reloc_idx];
                                reloc_idx += 1;
                                self.emit_statement_with_data_symbol(stmt, symbol, output, depth);
                                continue;
                            }
                        }
                    }
                    self.emit_statement(stmt, output, depth);
                }
            }

            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Skip stack canary check: if (check) { __stack_chk_fail(); }
                // Check both then and else bodies since compiler may invert the condition
                if self.is_guarded_stack_canary_branch(condition, then_body) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if self.is_guarded_stack_canary_branch(condition, else_nodes) {
                        return;
                    }
                }

                // Eliminate dead branches: if (0) { ... } or if (1) { ... }
                if let Some(const_val) = self.try_eval_constant(condition) {
                    if const_val == 0 {
                        // Condition is always false - skip then, emit else if exists
                        if let Some(else_nodes) = else_body {
                            self.emit_nodes(else_nodes, output, depth);
                        }
                        return;
                    } else {
                        // Condition is always true - emit then, skip else
                        self.emit_nodes(then_body, output, depth);
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().is_none_or(|e| self.is_body_empty(e));

                // If both bodies are empty, skip the if statement entirely
                if then_empty && else_empty {
                    return;
                }

                // If then_body is empty but else_body has content, invert the condition
                let (actual_cond, actual_then, actual_else) = if then_empty && !else_empty {
                    (
                        condition.clone().negate(),
                        else_body.as_ref().unwrap().clone(),
                        None,
                    )
                } else if !then_empty && else_empty {
                    // Only then_body has content, no else needed
                    (condition.clone(), then_body.clone(), None)
                } else {
                    (condition.clone(), then_body.clone(), else_body.clone())
                };

                writeln!(
                    output,
                    "{}if ({}) {{",
                    indent,
                    self.format_condition_expr(&actual_cond)
                )
                .unwrap();
                self.emit_nodes(&actual_then, output, depth + 1);

                // Emit else clause (handles else-if chains recursively)
                self.emit_else_clause(&actual_else, output, depth, &indent);

                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::While {
                condition, body, ..
            } => {
                // Eliminate dead loops: while (0) { ... } - body never executes
                if let Some(0) = self.try_eval_constant(condition) {
                    return;
                }
                if let Some(rewritten_body) =
                    self.rewrite_single_call_condition_while_for_emission(condition, body)
                {
                    writeln!(output, "{}while (1) {{", indent).unwrap();
                    self.emit_nodes(&rewritten_body, output, depth + 1);
                    writeln!(output, "{}}}", indent).unwrap();
                    return;
                }
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                writeln!(output, "{}do {{", indent).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(
                    output,
                    "{}}} while ({});",
                    indent,
                    self.format_condition_expr(condition)
                )
                .unwrap();
            }

            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                let init_str = init
                    .as_ref()
                    .map(|e| self.format_expr(e))
                    .unwrap_or_default();
                let update_str = update
                    .as_ref()
                    .map(|e| self.format_expr(e))
                    .unwrap_or_default();
                writeln!(
                    output,
                    "{}for ({}; {}; {}) {{",
                    indent,
                    init_str,
                    self.format_condition_expr(condition),
                    update_str
                )
                .unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Loop { body, .. } => {
                writeln!(output, "{}while (1) {{", indent).unwrap();
                self.emit_nodes(body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Break => {
                writeln!(output, "{}break;", indent).unwrap();
            }

            StructuredNode::Continue => {
                writeln!(output, "{}continue;", indent).unwrap();
            }

            StructuredNode::Return(expr) => {
                self.emit_return_line(output, &indent, expr.as_ref());
            }

            StructuredNode::Goto(target) => {
                writeln!(output, "{}goto {};", indent, target).unwrap();
            }

            StructuredNode::Label(id) => {
                // Labels are at column 0
                writeln!(output, "{}:", id).unwrap();
            }

            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                writeln!(output, "{}switch ({}) {{", indent, self.format_expr(value)).unwrap();
                for (values, body) in cases {
                    // Detect consecutive ranges for cleaner output
                    let ranges = collapse_case_values(values);
                    for range in ranges {
                        match range {
                            CaseRange::Single(v) => {
                                let case_str = if is_likely_character_constant(v) {
                                    format_as_char_literal(v)
                                } else {
                                    format!("{}", v)
                                };
                                writeln!(output, "{}case {}:", indent, case_str).unwrap();
                            }
                            CaseRange::Range(start, end) => {
                                // Use GCC case range extension: case 1 ... 5:
                                let start_str = if is_likely_character_constant(start) {
                                    format_as_char_literal(start)
                                } else {
                                    format!("{}", start)
                                };
                                let end_str = if is_likely_character_constant(end) {
                                    format_as_char_literal(end)
                                } else {
                                    format!("{}", end)
                                };
                                writeln!(output, "{}case {} ... {}:", indent, start_str, end_str)
                                    .unwrap();
                            }
                        }
                    }
                    self.emit_nodes(body, output, depth + 1);
                    // Only emit break if the body doesn't already end with a control exit
                    if !self.body_ends_with_control_exit(body) {
                        writeln!(output, "{}    break;", indent).unwrap();
                    }
                }
                if let Some(default_body) = default {
                    writeln!(output, "{}default:", indent).unwrap();
                    self.emit_nodes(default_body, output, depth + 1);
                }
                writeln!(output, "{}}}", indent).unwrap();
            }

            StructuredNode::Sequence(nodes) => {
                self.emit_nodes(nodes, output, depth);
            }

            StructuredNode::Expr(expr) => {
                self.emit_statement(expr, output, depth);
            }

            StructuredNode::TryCatch {
                try_body,
                catch_handlers,
            } => {
                writeln!(output, "{}try {{", indent).unwrap();
                self.emit_nodes(try_body, output, depth + 1);
                writeln!(output, "{}}}", indent).unwrap();

                for handler in catch_handlers {
                    let type_decl = if let Some(ref ex_type) = handler.exception_type {
                        let var_name = handler.variable_name.as_deref().unwrap_or("e");
                        format!("{}& {}", ex_type, var_name)
                    } else {
                        "...".to_string()
                    };
                    if self.emit_addresses {
                        writeln!(
                            output,
                            "{}catch ({}) {{ // landing pad @ {:#x}",
                            indent, type_decl, handler.landing_pad
                        )
                        .unwrap();
                    } else {
                        writeln!(output, "{}catch ({}) {{", indent, type_decl).unwrap();
                    }
                    self.emit_nodes(&handler.body, output, depth + 1);
                    writeln!(output, "{}}}", indent).unwrap();
                }
            }
        }
    }

    fn emit_statement(&self, expr: &Expr, output: &mut String, depth: usize) {
        // Skip prologue/epilogue boilerplate
        if self.is_prologue_epilogue(expr) {
            return;
        }

        // Skip redundant no-op assignments
        if self.is_noop_assignment(expr) {
            return;
        }

        // Skip ARM64 argument setup noise and other skippable patterns
        if self.is_skippable_statement(expr) {
            return;
        }

        let indent = self.indent.repeat(depth);
        if let Some(comment) = Self::opaque_x86_integer_simd_statement(expr) {
            writeln!(output, "{}{}", indent, comment).unwrap();
            return;
        }
        let expr_str = self.format_expr(expr);

        // Skip empty/nop statements and trivial literal statements
        if expr_str.is_empty() || expr_str == "/* nop */" || expr_str == "0" || expr_str == "1" {
            return;
        }

        // Skip stack adjustment patterns that result from ARM64 sp operations
        // These appear as "0 -= N" or "0 += N" when the stack pointer isn't resolved
        if expr_str.starts_with("0 -= ") || expr_str.starts_with("0 += ") {
            return;
        }

        if Self::is_comment_statement_text(&expr_str) {
            writeln!(output, "{}{}", indent, expr_str).unwrap();
            return;
        }

        // Check if it's a return
        if expr_str == "return" {
            self.emit_return_line(output, &indent, None);
            return;
        }

        writeln!(output, "{}{};", indent, expr_str).unwrap();
    }

    /// Checks if a statement is function prologue/epilogue boilerplate.
    /// These patterns don't add semantic value and clutter the output.
    fn is_prologue_epilogue(&self, expr: &Expr) -> bool {
        match &expr.kind {
            // push/pop of callee-saved registers - prologue/epilogue
            // x86-64: rbp, rbx, r12-r15 are callee-saved
            ExprKind::Call { target, args } => {
                if let CallTarget::Named(name) = target {
                    if name == "push" || name == "pop" {
                        if let Some(arg) = args.first() {
                            if let ExprKind::Var(v) = &arg.kind {
                                if is_callee_saved_register(&v.name) {
                                    return true;
                                }
                            }
                        }
                    }
                }
                false
            }
            // rbp = rsp (prologue) or rsp = rsp +/- N (stack frame)
            ExprKind::Assign { lhs, rhs } => {
                // ARM64: stur wzr, [x29 - N] - implicit return value initialization
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    if let ExprKind::BinOp {
                        op: super::expression::BinOpKind::Add,
                        left,
                        right,
                    } = &addr.kind
                    {
                        if let ExprKind::Var(base) = &left.kind {
                            if base.name == "x29" || base.name == "rbp" {
                                if let ExprKind::IntLit(offset) = &right.kind {
                                    if *offset < 0 {
                                        let is_zero = match &rhs.kind {
                                            ExprKind::IntLit(0) => true,
                                            ExprKind::Var(v) => v.name == "wzr" || v.name == "xzr",
                                            _ => false,
                                        };
                                        if is_zero {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if let ExprKind::Var(lhs_var) = &lhs.kind {
                    // rbp = rsp (frame pointer setup)
                    if lhs_var.name == "rbp" {
                        if let ExprKind::Var(rhs_var) = &rhs.kind {
                            if rhs_var.name == "rsp" {
                                return true;
                            }
                        }
                    }
                    // rsp = rsp +/- N (stack allocation/deallocation)
                    if lhs_var.name == "rsp" {
                        if let ExprKind::BinOp { left, .. } = &rhs.kind {
                            if let ExprKind::Var(inner_var) = &left.kind {
                                if inner_var.name == "rsp" {
                                    return true;
                                }
                            }
                        }
                    }
                    // Callee-saved register restore from stack: x21 = var_10, saved1 = sp[2], etc.
                    // These are epilogue patterns that restore callee-saved registers before return
                    // Check both original register names and renamed versions
                    if is_callee_saved_or_renamed(&lhs_var.name) {
                        // Check for plain var with var_ prefix
                        if let ExprKind::Var(rhs_var) = &rhs.kind {
                            if rhs_var.name.starts_with("var_") {
                                return true;
                            }
                        }
                        // Check for ArrayAccess of sp (ARM64 epilogue pattern: sp[N])
                        if let ExprKind::ArrayAccess { base, index, .. } = &rhs.kind {
                            if let ExprKind::Var(base_var) = &base.kind {
                                if (base_var.name == "sp" || base_var.name == "rsp")
                                    && matches!(index.kind, ExprKind::IntLit(_))
                                {
                                    return true;
                                }
                            }
                        }
                        // Also check for Deref of stack slot (x86-64 pattern)
                        if let ExprKind::Deref { addr, .. } = &rhs.kind {
                            if let ExprKind::BinOp { left, right, .. } = &addr.kind {
                                if let ExprKind::Var(base) = &left.kind {
                                    if (base.name == "x29"
                                        || base.name == "fp"
                                        || base.name == "rbp")
                                        && matches!(right.kind, ExprKind::IntLit(_))
                                    {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                    // Prologue save to stack: var_N = callee_saved_reg
                    // This saves a callee-saved register to the stack at function entry
                    if lhs_var.name.starts_with("var_") {
                        if let ExprKind::Var(rhs_var) = &rhs.kind {
                            if is_callee_saved_or_renamed(&rhs_var.name) {
                                return true;
                            }
                        }
                    }
                }
                false
            }
            // Compound assignment: rsp -= N or sp -= N (stack allocation/deallocation)
            ExprKind::CompoundAssign { op, lhs, rhs } => {
                if let ExprKind::Var(lhs_var) = &lhs.kind {
                    if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                        // rsp -= N (stack allocation) or rsp += N (stack deallocation)
                        if (matches!(op, super::expression::BinOpKind::Sub)
                            || matches!(op, super::expression::BinOpKind::Add))
                            && matches!(rhs.kind, ExprKind::IntLit(_))
                        {
                            return true;
                        }
                    }
                }
                false
            }
            _ => false,
        }
    }

    /// Checks if an assignment is a no-op (e.g., x = x, x = x + 0, x = x * 1).
    fn is_noop_assignment(&self, expr: &Expr) -> bool {
        use super::expression::BinOpKind;

        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            // Check for exact self-assignment: x = x
            if exprs_equal(lhs, rhs) {
                return true;
            }

            // Check for identity operations: x = x + 0, x = x - 0, x = x * 1, x = x | 0, x = x ^ 0
            if let ExprKind::BinOp { op, left, right } = &rhs.kind {
                if exprs_equal(lhs, left) {
                    // Check if the right operand is an identity value for this operation
                    if let ExprKind::IntLit(n) = &right.kind {
                        match op {
                            BinOpKind::Add
                            | BinOpKind::Sub
                            | BinOpKind::Or
                            | BinOpKind::Xor
                            | BinOpKind::Shl
                            | BinOpKind::Shr => {
                                if *n == 0 {
                                    return true;
                                }
                            }
                            BinOpKind::Mul | BinOpKind::Div => {
                                if *n == 1 {
                                    return true;
                                }
                            }
                            BinOpKind::And => {
                                // x & -1 (all bits set) is identity
                                if *n == -1 {
                                    return true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        false
    }

    /// Try to get a variable name from an expression (either Var or Deref of stack slot).
    /// Uses DWARF names when available. Returns the display name (after renaming).
    fn try_get_var_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(v) => {
                // Include both original and semantically renamed variables
                if is_declarable_variable(&v.name) {
                    // Return the renamed name for consistency with format_expr
                    Some(self.rename_register_for_display(&v.name))
                } else {
                    None
                }
            }
            ExprKind::Deref { addr, size } => self.try_format_stack_slot(addr, *size),
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => self.try_get_array_base_name(base, index, *element_size),
            ExprKind::Unknown(name) if Self::is_lifted_stack_identifier(name) => {
                Some(self.resolve_display_identifier_name(name))
            }
            _ => None,
        }
    }

    fn try_get_assigned_var_name(&self, expr: &Expr) -> Option<String> {
        self.try_get_var_name(expr).or_else(|| {
            if let ExprKind::Unknown(name) = &expr.kind {
                if is_assignable_unknown_name(name) {
                    return Some(self.resolve_display_identifier_name(name));
                }
            }
            None
        })
    }

    /// Try to get a semantic name for a variable using the NamingContext.
    /// This handles variables with names like var_8, var_c, tmp0, local_10, etc.
    /// Returns None if the variable doesn't match a pattern or if no semantic name is available.
    fn try_get_semantic_var_name(&self, var_name: &str) -> Option<String> {
        let (offset, is_param) = Self::parse_lifted_stack_offset(var_name)?;

        if let Some(name) = self.get_dwarf_name(offset) {
            return Some(name.to_string());
        }
        if var_name.starts_with("var_") {
            if let Some(name) = self.get_dwarf_name(-offset) {
                return Some(name.to_string());
            }
        }

        // Ask NamingContext for a better name based on usage patterns.
        let semantic_name = self.naming_ctx.borrow_mut().get_name(offset, is_param);

        // Only return the semantic name if it's different from the default naming
        // This avoids replacing var_8 with var_8
        if semantic_name.starts_with("var_")
            || semantic_name.starts_with("local_")
            || semantic_name.starts_with("arg_")
        {
            // NamingContext returned a default name, not a semantic one
            None
        } else {
            Some(semantic_name)
        }
    }

    /// Try to format a stack slot dereference as a local variable name.
    /// Detects patterns like rbp + -0x8 and converts to var_8.
    fn try_format_stack_slot(&self, addr: &Expr, _size: u8) -> Option<String> {
        use super::expression::BinOpKind;

        // Check for base-only pattern (offset 0): just "sp" or "x29"
        if let ExprKind::Var(base) = &addr.kind {
            if base.name == "sp" {
                // Check for DWARF name at offset 0
                if let Some(name) = self.get_dwarf_name(0) {
                    return Some(normalize_variable_name(name));
                }
                return Some("var_0".to_string());
            }
        }

        // Check for base + offset pattern
        if let ExprKind::BinOp { op, left, right } = &addr.kind {
            if let ExprKind::Var(base) = &left.kind {
                // Frame pointers: rbp (x86-64), x29 (ARM64) - locals at negative offsets
                let is_frame_pointer = base.name == "rbp" || base.name == "x29";
                // Stack pointer: sp (ARM64), rsp (x86-64) - locals at positive offsets
                let is_stack_pointer = base.name == "sp" || base.name == "rsp";

                if is_frame_pointer || is_stack_pointer {
                    if let ExprKind::IntLit(offset) = &right.kind {
                        let actual_offset = match op {
                            BinOpKind::Add => *offset,
                            BinOpKind::Sub => -*offset,
                            _ => return None,
                        };

                        // First, check for DWARF name at this offset
                        if let Some(name) = self.get_dwarf_name(actual_offset) {
                            return Some(normalize_variable_name(name));
                        }

                        // Use NamingContext for pattern-based naming (loop indices, type hints, etc.)
                        // This will return names like 'i', 'j', 'k' for loop counters
                        let is_param = is_frame_pointer && actual_offset > 0;
                        let name = self
                            .naming_ctx
                            .borrow_mut()
                            .get_name(actual_offset, is_param);
                        return Some(normalize_variable_name(&name));
                    }
                }
            }
        }
        None
    }

    fn try_format_stack_slot_array_access(
        &self,
        base: &Expr,
        index: &Expr,
        element_size: usize,
    ) -> Option<String> {
        use super::expression::BinOpKind;

        let ExprKind::IntLit(slot_index) = &index.kind else {
            return None;
        };

        let (stack_base, dynamic_index) = match &base.kind {
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => match (&left.kind, &right.kind) {
                (ExprKind::Var(_base_var), ExprKind::IntLit(_)) => return None,
                (ExprKind::Var(base_var), _) => (base_var, &**right),
                (_, ExprKind::Var(base_var)) => (base_var, &**left),
                _ => return None,
            },
            _ => return None,
        };

        let is_frame_ptr = stack_base.name == "rbp" || stack_base.name == "x29";
        let is_stack_ptr = stack_base.name == "rsp" || stack_base.name == "sp";
        if !(is_frame_ptr || is_stack_ptr) {
            return None;
        }

        let actual_offset = *slot_index * element_size as i128;
        let stack_name = if let Some(name) = self.get_dwarf_name(actual_offset) {
            name.to_string()
        } else {
            let is_param = is_frame_ptr && actual_offset > 0;
            self.naming_ctx
                .borrow_mut()
                .get_name(actual_offset, is_param)
        };

        let base_name = normalize_variable_name(&stack_name);
        let index_str = self.format_expr_no_string_resolve(dynamic_index);
        Some(format!("{}[{}]", base_name, index_str))
    }

    fn try_get_array_base_name(
        &self,
        base: &Expr,
        index: &Expr,
        element_size: usize,
    ) -> Option<String> {
        if let ExprKind::Var(v) = &base.kind {
            let is_stack_ptr = v.name == "sp" || v.name == "rsp";
            let is_frame_ptr = v.name == "rbp" || v.name == "x29";
            if is_stack_ptr || is_frame_ptr {
                if let ExprKind::IntLit(idx) = &index.kind {
                    let byte_offset = *idx * element_size as i128;
                    let actual_offset = if is_frame_ptr {
                        -byte_offset
                    } else {
                        byte_offset
                    };

                    let name = if let Some(name) = self.get_dwarf_name(actual_offset) {
                        name.to_string()
                    } else {
                        let is_param = is_frame_ptr && actual_offset > 0;
                        self.naming_ctx
                            .borrow_mut()
                            .get_name(actual_offset, is_param)
                    };
                    return Some(normalize_variable_name(&name));
                }
            }
        }

        self.try_format_stack_slot_array_access(base, index, element_size)
            .and_then(|formatted| formatted.split('[').next().map(str::to_string))
    }

    /// Emits a statement where the RHS 0 should be replaced with a symbol.
    fn emit_statement_with_data_symbol(
        &self,
        expr: &Expr,
        symbol: &str,
        output: &mut String,
        depth: usize,
    ) {
        let indent = self.indent.repeat(depth);

        if let ExprKind::Assign { lhs, .. } = &expr.kind {
            let lhs_str = self.format_expr(lhs);
            // Format as address-of symbol (since we're loading an address)
            writeln!(output, "{}{} = &{};", indent, lhs_str, symbol).unwrap();
        } else {
            // Fallback to regular emission
            self.emit_statement(expr, output, depth);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::expression::BinOpKind;
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn arg_register_display_gated_by_param_count() {
        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_calling_convention(CallingConvention::SystemV);
        // A function with two integer parameters: rdx (arg2) is a local temp.
        emitter.integer_arg_param_count.set(2);
        assert_eq!(
            emitter.arg_register_display_name("rdi").as_deref(),
            Some("arg0")
        );
        assert_eq!(
            emitter.arg_register_display_name("rsi").as_deref(),
            Some("arg1")
        );
        assert_eq!(
            emitter.arg_register_display_name("rdx"),
            None,
            "rdx is not a parameter of a 2-arg function"
        );
        // With three parameters, rdx (arg2) is a genuine argument again.
        emitter.integer_arg_param_count.set(3);
        assert_eq!(
            emitter.arg_register_display_name("rdx").as_deref(),
            Some("arg2")
        );
    }

    #[test]
    fn test_emit_if_else() {
        let cond = Expr::binop(BinOpKind::Eq, Expr::unknown("x"), Expr::int(0));
        let then_body = vec![StructuredNode::Expr(Expr::assign(
            Expr::unknown("y"),
            Expr::int(1),
        ))];
        let else_body = Some(vec![StructuredNode::Expr(Expr::assign(
            Expr::unknown("y"),
            Expr::int(2),
        ))]);

        let node = StructuredNode::If {
            condition: cond,
            then_body,
            else_body,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("if (x == 0)"));
        assert!(output.contains("y = 1"));
        assert!(output.contains("else"));
        assert!(output.contains("y = 2"));
    }

    #[test]
    fn test_emit_if_with_unresolved_condition_comment_uses_placeholder_name() {
        let node = StructuredNode::If {
            condition: Expr::unknown("/* negative */"),
            then_body: vec![StructuredNode::Expr(Expr::assign(
                Expr::unknown("y"),
                Expr::int(1),
            ))],
            else_body: None,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(
            output.contains("if (cond_negative /* negative */)"),
            "expected unresolved condition placeholder, got:\n{output}"
        );
        assert!(
            !output.contains("if (true /* negative */)"),
            "truthy fallback regressed:\n{output}"
        );
    }

    #[test]
    fn test_emit_user_authored_stack_chk_fail_branch_without_guard() {
        let call = Expr::call(
            CallTarget::Named("__stack_chk_fail".to_string()),
            Vec::new(),
        );
        let cfg = StructuredCfg {
            body: vec![StructuredNode::If {
                condition: Expr::binop(BinOpKind::Ne, Expr::unknown("ret"), Expr::unknown("arg0")),
                then_body: vec![StructuredNode::Block {
                    id: hexray_core::BasicBlockId::new(1),
                    statements: vec![call],
                    address_range: (0x1000, 0x1005),
                }],
                else_body: Some(vec![StructuredNode::Return(Some(Expr::int(1)))]),
            }],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "manual_sub_fail");

        assert!(
            output.contains("if (ret != arg0)"),
            "user-authored fail branch should remain visible:\n{output}"
        );
        assert!(
            output.contains("__stack_chk_fail"),
            "user-authored fail call should not be elided:\n{output}"
        );
    }

    #[test]
    fn test_emit_inserts_placeholder_for_empty_body() {
        let cfg = StructuredCfg {
            body: Vec::new(),
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "empty_body");

        assert!(output.contains("/* decompilation body not recoverable */"));
    }

    #[test]
    fn test_emit_tags_coroutine_handle_resume_bodies() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: hexray_core::BasicBlockId::new(0),
                statements: vec![Expr::call(
                    CallTarget::Indirect(Box::new(Expr::unknown("frame_slot"))),
                    vec![],
                )],
                address_range: (0x1000, 0x1004),
            }],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(
            &cfg,
            "std::__n4861::coroutine_handle<generator::promise_type>::resume() const",
        );

        assert!(
            output.contains("/* resume coroutine via coroutine frame */"),
            "expected recognized coroutine handle op to emit a tagging comment:\n{output}"
        );
    }

    #[test]
    fn test_format_function_header_reuses_demangled_qualifiers_without_double_parens() {
        let header = PseudoCodeEmitter::format_function_header(
            &super::super::signature::ParamType::SignedInt(32),
            "Square::area() const",
            &[String::from("int32_t* this")],
            false,
        );

        assert_eq!(header, "int32_t Square::area(int32_t* this) const");
    }

    #[test]
    fn test_format_function_header_appends_variadic_ellipsis() {
        let header = PseudoCodeEmitter::format_function_header(
            &super::super::signature::ParamType::SignedInt(32),
            "my_log",
            &[String::from("void* format")],
            true,
        );

        assert_eq!(header, "int32_t my_log(void* format, ...)");
    }

    #[test]
    fn test_emit_virtual_dispatch_placeholder_for_itanium_shape() {
        let err = Expr::var(super::super::expression::Variable::reg("err", 8));
        let object = Expr::deref(err.clone(), 8);
        let vptr = Expr::deref(object.clone(), 8);
        let slot = Expr::deref(vptr, 8);
        let call = Expr::assign(
            Expr::unknown("ret_0"),
            Expr::call(CallTarget::Indirect(Box::new(slot)), vec![object.clone()]),
        );

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(call)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("((*(uint64_t*)(err))->vftable[0])(*(uint64_t*)(err))"));
    }

    #[test]
    fn test_emit_virtual_dispatch_placeholder_without_explicit_this_arg() {
        let err = Expr::var(super::super::expression::Variable::reg("err", 8));
        let object = Expr::deref(err.clone(), 8);
        let vptr = Expr::deref(object.clone(), 8);
        let slot = Expr::deref(vptr, 8);
        let call = Expr::assign(
            Expr::unknown("ret_0"),
            Expr::call(CallTarget::Indirect(Box::new(slot)), vec![]),
        );

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(call)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("((*(uint64_t*)(err))->vftable[0])(*(uint64_t*)(err))"));
    }

    #[test]
    fn test_emit_rust_slice_string_arg_truncates_with_explicit_len() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(Expr::call(
                CallTarget::Named("main::parse".to_string()),
                vec![Expr::unknown("dst"), Expr::int(0x4000), Expr::int(2)],
            ))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut table = StringTable::new();
        table.insert(0x4000, "42Error".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_string_table(Some(table));
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("main::parse(dst, \"42\", 2);"), "{output}");
    }

    #[test]
    fn test_emit_classic_c_string_arg_does_not_truncate_without_rust_slice_shape() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(Expr::call(
                CallTarget::Named("printf".to_string()),
                vec![Expr::int(0x5000), Expr::int(2)],
            ))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut table = StringTable::new();
        table.insert(0x5000, "hello".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_string_table(Some(table));
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("printf(\"hello\", 2);"), "{output}");
    }

    #[test]
    fn test_emit_struct_pointer_byte_offset_field_fallback() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(Expr::assign(
                Expr::array_access(Expr::unknown("ret"), Expr::int(3), 1),
                Expr::unknown("local_c"),
            ))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut type_info = HashMap::new();
        type_info.insert("ret".to_string(), "struct Circle*".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output = emitter.emit(&cfg, "test");

        assert!(output.contains("ret->field_3 = local_c;"));
    }

    #[test]
    fn test_emit_rewrites_destructor_cleanup_tail_return() {
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Block {
                    id: hexray_core::BasicBlockId::new(0),
                    statements: vec![
                        Expr::assign(
                            Expr::unknown("err"),
                            Expr::call(
                                CallTarget::Named("Circle::area() const".to_string()),
                                vec![],
                            ),
                        ),
                        Expr::assign(
                            Expr::unknown("ret_0"),
                            Expr::call(CallTarget::Named("Circle::~Circle()".to_string()), vec![]),
                        ),
                    ],
                    address_range: (0x1000, 0x1008),
                },
                StructuredNode::Return(Some(Expr::unknown("ret_0"))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let output = PseudoCodeEmitter::new("    ", false).emit(&cfg, "cleanup_wrapper");

        assert!(output.contains("Circle::~Circle();"));
        assert!(output.contains("return err;"));
        assert!(!output.contains("return ret_0;"));
    }

    #[test]
    fn test_emit_direct_call_strips_demangled_signature_suffix() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::Direct {
                    target: 0x401000,
                    call_site: 0x1010,
                },
                vec![Expr::unknown("arg0"), Expr::unknown("n")],
            )))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sym = SymbolTable::new();
        sym.insert(0x401000, "sum_ints(int const*, int)".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let output = emitter.emit(&cfg, "call_sum");

        assert!(output.contains("return sum_ints(arg0, n);"), "{output}");
        assert!(!output.contains("sum_ints(int const*, int)("), "{output}");
    }

    #[test]
    fn test_emit_direct_call_preserves_template_parens_when_stripping_signature() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::Direct {
                    target: 0x401000,
                    call_site: 0x1010,
                },
                vec![Expr::unknown("arg0")],
            )))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sym = SymbolTable::new();
        sym.insert(
            0x401000,
            "std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset()".to_string(),
        );

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let output = emitter.emit(&cfg, "reset_widget");

        assert!(
            output.contains(
                "return std::__shared_ptr<Widget, std::allocator<Widget>(int)>::reset(arg0);"
            ),
            "{output}"
        );
        assert!(!output.contains("std::__shared_ptr<Widget, std::allocator<Widget>(arg0);"));
    }

    #[test]
    fn test_emit_while() {
        let cond = Expr::binop(BinOpKind::Lt, Expr::unknown("i"), Expr::int(10));
        let body = vec![StructuredNode::Expr(Expr::assign(
            Expr::unknown("i"),
            Expr::binop(BinOpKind::Add, Expr::unknown("i"), Expr::int(1)),
        ))];

        let node = StructuredNode::While {
            condition: cond,
            body,
            header: None,
            exit_block: None,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(
            output.contains("while (i < 10)"),
            "Expected 'while (i < 10)', got: {}",
            output
        );
        assert!(
            output.contains("i++") || output.contains("i = i + 1"),
            "Expected increment, got: {}",
            output
        );
    }

    #[test]
    fn test_emit_single_call_condition_while_with_captured_poll_result_once() {
        let poll_call = Expr::call(
            CallTarget::Named("poll".to_string()),
            vec![Expr::unknown("err")],
        );
        let body = vec![
            StructuredNode::Expr(Expr::assign(Expr::unknown("ret_0"), poll_call.clone())),
            StructuredNode::If {
                condition: Expr::unknown("ret_0"),
                then_body: vec![],
                else_body: Some(vec![StructuredNode::Return(Some(Expr::int(42)))]),
            },
        ];

        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::While {
                    condition: poll_call,
                    body,
                    header: None,
                    exit_block: None,
                },
                StructuredNode::Return(Some(Expr::int(0))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert_eq!(
            output.matches("poll(err)").count(),
            1,
            "expected one poll call in the emitted loop, got:\n{output}"
        );
    }

    #[test]
    fn test_emit_stops_after_top_level_return_without_labels() {
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Return(Some(Expr::int(0))),
                StructuredNode::Expr(Expr::assign(Expr::unknown("x"), Expr::int(1))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");
        assert!(
            output.contains("return 0;"),
            "Expected return statement:\n{}",
            output
        );
        assert!(
            !output.contains("x = 1;"),
            "Did not expect statements after top-level return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_initializes_unassigned_loop_iterator() {
        use super::super::expression::Variable;

        let cond = Expr::binop(
            BinOpKind::Lt,
            Expr::var(Variable::reg("iter", 4)),
            Expr::int(8),
        );
        let node = StructuredNode::While {
            condition: cond,
            body: Vec::new(),
            header: None,
            exit_block: None,
        };
        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");
        assert!(
            output.contains("int iter = 0;"),
            "Expected loop iterator zero-init declaration, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_initializes_iterator_when_only_assigned_in_while_body() {
        use super::super::expression::Variable;

        let cond = Expr::binop(
            BinOpKind::Lt,
            Expr::var(Variable::reg("iter", 4)),
            Expr::int(8),
        );
        let body_stmt = Expr::assign(
            Expr::var(Variable::reg("iter", 4)),
            Expr::binop(
                BinOpKind::Add,
                Expr::var(Variable::reg("iter", 4)),
                Expr::int(1),
            ),
        );
        let loop_node = StructuredNode::While {
            condition: cond,
            body: vec![StructuredNode::Expr(body_stmt)],
            header: None,
            exit_block: None,
        };
        let cfg = StructuredCfg {
            body: vec![loop_node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");
        assert!(
            output.contains("int iter = 0;"),
            "Expected zero-init for condition iterator even when assigned in loop body, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_does_not_zero_init_for_loop_counter_with_init() {
        let init = Expr::assign(Expr::unknown("iter"), Expr::int(0));
        let cond = Expr::binop(BinOpKind::Lt, Expr::unknown("iter"), Expr::int(8));
        let update = Expr::assign(
            Expr::unknown("iter"),
            Expr::binop(BinOpKind::Add, Expr::unknown("iter"), Expr::int(1)),
        );
        let loop_node = StructuredNode::For {
            init: Some(init),
            condition: cond,
            update: Some(update),
            body: Vec::new(),
            header: None,
            exit_block: None,
        };
        let cfg = StructuredCfg {
            body: vec![loop_node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");
        assert!(
            !output.contains("int iter = 0;"),
            "Expected for-loop init to satisfy iterator initialization, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_zero_init_when_only_pre_loop_assign_is_skipped_temp_setup() {
        use super::super::expression::Variable;

        let pre_loop = StructuredNode::Expr(Expr::assign(
            Expr::unknown("iter"),
            Expr::var(Variable::reg("w9", 4)),
        ));
        let cond = Expr::binop(BinOpKind::Lt, Expr::unknown("iter"), Expr::int(8));
        let loop_node = StructuredNode::While {
            condition: cond,
            body: Vec::new(),
            header: None,
            exit_block: None,
        };
        let cfg = StructuredCfg {
            body: vec![pre_loop, loop_node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");
        assert!(
            output.contains("int iter = 0;"),
            "Expected skipped temp-setup assign not to suppress loop iterator zero-init:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_main_param_name_matches_body_usage() {
        use super::super::expression::Variable;

        let read_arg0 = Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("x0", 8)));
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![read_arg0],
            address_range: (0x1000, 0x1010),
        };
        let ret = StructuredNode::Return(Some(Expr::int(0)));
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_calling_convention(CallingConvention::Aarch64);
        let output = emitter.emit(&cfg, "_main");

        assert!(
            output.contains("_main(int32_t argc)"),
            "Expected argc in main signature, got:\n{}",
            output
        );
        assert!(
            output.contains("tmp = argc;"),
            "Expected body usage to align with renamed parameter, got:\n{}",
            output
        );
        assert!(
            !output.contains(" arg0"),
            "Did not expect leaked arg0 names in output:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_win64_param_names_match_body_usage() {
        use super::super::expression::Variable;

        let product = Expr::binop(
            BinOpKind::Mul,
            Expr::var(Variable::reg("ecx", 4)),
            Expr::var(Variable::reg("edx", 4)),
        );
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(product))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_calling_convention(CallingConvention::Win64);
        let output = emitter.emit(&cfg, "mul");

        assert!(
            output.contains("mul(") && output.contains("arg0") && output.contains("arg1"),
            "Expected Win64 parameter names in signature/body, got:\n{}",
            output
        );
        assert!(
            output.contains("return arg0 * arg1;"),
            "Expected Win64 body argument numbering, got:\n{}",
            output
        );
        assert!(
            !output.contains("arg2") && !output.contains("arg3"),
            "Did not expect SysV-only numbering in Win64 output:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_lifted_arg_slot_name_matches_body_usage() {
        // Lifted IR may refer to the first argument as arg_8.
        // Header/body should stay aligned on arg0 naming, not leak local_8.
        let read_lifted_arg = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg_8"));
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![read_lifted_arg],
            address_range: (0x1100, 0x1110),
        };
        let ret = StructuredNode::Return(Some(Expr::int(0)));
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_calling_convention(CallingConvention::SystemV);
        let output = emitter.emit(&cfg, "lifted_arg_slot");

        assert!(
            output.contains("lifted_arg_slot(int32_t arg0)"),
            "Expected arg0 in signature for lifted arg slot, got:\n{}",
            output
        );
        assert!(
            output.contains("tmp = arg0;"),
            "Expected body usage to align with signature parameter name, got:\n{}",
            output
        );
        assert!(
            !output.contains("arg_8"),
            "Did not expect raw lifted arg name leak, got:\n{}",
            output
        );
        assert!(
            !output.contains("local_8"),
            "Did not expect lifted arg slot to normalize into local_8, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_declares_unknown_lhs_local_names() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("sum"), Expr::int(0)),
                Expr::assign(
                    Expr::unknown("sum"),
                    Expr::binop(BinOpKind::Add, Expr::unknown("sum"), Expr::int(5)),
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::unknown("sum")))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "accumulate");
        assert!(
            output.contains("int sum;"),
            "Expected declaration for inferred local 'sum', got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_does_not_declare_global_like_unknown_names() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::assign(
                Expr::unknown("ret"),
                Expr::unknown("__stack_chk_guard"),
            )],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::unknown("ret")))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "guard_read");

        assert!(
            !output.contains("int __stack_chk_guard;"),
            "Did not expect a local declaration for __stack_chk_guard, got:\n{}",
            output
        );
        assert!(
            output.contains("__stack_chk_guard"),
            "Expected symbolic guard reference to remain in output, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_declares_renamed_return_register_aliases() {
        use super::super::expression::Variable;

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::call(
                CallTarget::Named("atoi".to_string()),
                vec![Expr::var(Variable::reg("rax", 8))],
            )],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::int(0)))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "declare_ret_alias");
        assert!(
            output.contains("int ret;"),
            "Expected declaration for renamed return alias, got:\n{}",
            output
        );
        assert!(
            output.contains("atoi(ret);"),
            "Expected renamed return register use in body, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_applies_dwarf_names_to_unknown_stack_slots_and_params() {
        use super::super::expression::Variable;

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    Expr::unknown("local_18"),
                    Expr::var(Variable::reg("rdi", 8)),
                ),
                Expr::assign(
                    Expr::unknown("local_1c"),
                    Expr::var(Variable::reg("rsi", 8)),
                ),
                Expr::assign(
                    Expr::unknown("local_28"),
                    Expr::var(Variable::reg("rdx", 8)),
                ),
                Expr::assign(
                    Expr::unknown("local_20"),
                    Expr::var(Variable::reg("rcx", 8)),
                ),
                Expr::assign(Expr::unknown("local_8"), Expr::int(0)),
                Expr::assign(Expr::unknown("local_4"), Expr::int(0)),
                Expr::assign(
                    Expr::unknown("local_8"),
                    Expr::binop(
                        BinOpKind::Add,
                        Expr::unknown("local_8"),
                        Expr::unknown("local_4"),
                    ),
                ),
                Expr::assign(
                    Expr::unknown("local_4"),
                    Expr::binop(BinOpKind::Add, Expr::unknown("local_4"), Expr::int(1)),
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::unknown("local_8"))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let dwarf_names = HashMap::from([
            (-24, "arr".to_string()),
            (-28, "n".to_string()),
            (-40, "fn".to_string()),
            (-32, "factor".to_string()),
            (-8, "total".to_string()),
            (-4, "i".to_string()),
        ]);
        let emitter = PseudoCodeEmitter::new("    ", false).with_dwarf_names(dwarf_names);
        let output = emitter.emit(&cfg, "accumulate_named");
        let header = output.lines().next().unwrap_or_default();

        assert!(
            header.contains("arr")
                && header.contains("n")
                && header.contains("fn")
                && header.contains("factor"),
            "Expected DWARF parameter names in header, got:\n{}",
            output
        );
        assert!(
            !header.contains("arg1") && !header.contains("arg2") && !header.contains("arg3"),
            "Did not expect generic parameter names in header, got:\n{}",
            output
        );
        assert!(
            output.contains("int i;") && output.contains("int total;"),
            "Expected DWARF local names in declarations, got:\n{}",
            output
        );
        assert!(
            output.contains("total = 0;") && output.contains("i = 0;"),
            "Expected DWARF local names in body, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_uses_dwarf_param_names_by_index_without_stack_spills() {
        use super::super::expression::Variable;

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::assign(
                Expr::unknown("sum"),
                Expr::binop(
                    BinOpKind::Add,
                    Expr::var(Variable::reg("rdi", 8)),
                    Expr::var(Variable::reg("rsi", 8)),
                ),
            )],
            address_range: (0x1000, 0x1008),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(Some(Expr::unknown("sum")))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let output = PseudoCodeEmitter::new("    ", false)
            .with_dwarf_param_names(vec!["lhs".to_string(), "rhs".to_string()])
            .emit(&cfg, "add_named");
        let header = output.lines().next().unwrap_or_default();

        assert!(
            header.contains("lhs") && header.contains("rhs"),
            "Expected DWARF parameter names in header, got:\n{}",
            output
        );
        assert!(
            output.contains("sum = lhs + rhs;"),
            "Expected body usage to follow DWARF parameter names, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_rewrites_packed_small_aggregate_return_slot() {
        use super::super::expression::Variable;

        let rbp = Expr::var(Variable::reg("rbp", 8));
        let slot_base = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-8));
        let high_base = Expr::binop(BinOpKind::Add, rbp, Expr::int(-4));

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::deref(slot_base.clone(), 4), Expr::unknown("left")),
                Expr::assign(Expr::deref(high_base, 4), Expr::unknown("right")),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::deref(slot_base, 8))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(64);
        sig.parameters.push(super::super::signature::Parameter::new(
            "left",
            super::super::signature::ParamType::SignedInt(64),
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(super::super::signature::Parameter::new(
            "right",
            super::super::signature::ParamType::SignedInt(64),
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let output =
            PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "make_pair", &sig);

        assert!(
            output.contains("return (uint32_t)left | (uint32_t)right << 32;"),
            "Expected packed return reconstruction, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_rewrites_packed_small_aggregate_param_slot_reads() {
        use super::super::expression::Variable;

        let rbp = Expr::var(Variable::reg("rbp", 8));
        let slot_base = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-8));
        let high_base = Expr::binop(BinOpKind::Add, rbp, Expr::int(-4));

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(
                    Expr::deref(slot_base.clone(), 8),
                    Expr::var(Variable::reg("rdi", 8)),
                ),
                Expr::call(
                    CallTarget::Named("printf".to_string()),
                    vec![
                        Expr::unknown("label"),
                        Expr::deref(slot_base, 4),
                        Expr::deref(high_base, 4),
                    ],
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.parameters.push(super::super::signature::Parameter::new(
            "pair",
            super::super::signature::ParamType::SignedInt(64),
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(super::super::signature::Parameter::new(
            "label",
            super::super::signature::ParamType::Pointer,
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let output =
            PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "print_pair_sum", &sig);

        assert!(
            output.contains("printf(label, (uint32_t)pair, BITS(pair, 32, 32));"),
            "Expected packed param field extraction, got:\n{}",
            output
        );
        assert!(
            !output.contains("local_4"),
            "Did not expect dangling high-half local after rewrite, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_rewrites_lifted_identifier_based_packed_reads() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("local_8"), Expr::unknown("left")),
                Expr::assign(Expr::unknown("local_4"), Expr::unknown("right")),
                Expr::call(
                    CallTarget::Named("printf".to_string()),
                    vec![Expr::unknown("label"), Expr::unknown("local_4")],
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::unknown("local_8"))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let output = PseudoCodeEmitter::new("    ", false).emit(&cfg, "lifted_pack");

        assert!(
            output.contains("printf(label, local_4);"),
            "Expected unrelated lifted identifiers to stay untouched without a param source, got:\n{}",
            output
        );
        assert!(
            output.contains("return (uint32_t)left | (uint32_t)right << 32;"),
            "Expected lifted whole-slot read to reconstruct the packed return, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_rewrites_lifted_identifier_high_half_from_param_source() {
        use super::super::expression::Variable;

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("local_8"), Expr::var(Variable::reg("rdi", 8))),
                Expr::call(
                    CallTarget::Named("printf".to_string()),
                    vec![Expr::unknown("label"), Expr::unknown("local_4")],
                ),
            ],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.parameters.push(super::super::signature::Parameter::new(
            "pair",
            super::super::signature::ParamType::SignedInt(64),
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(super::super::signature::Parameter::new(
            "label",
            super::super::signature::ParamType::Pointer,
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let output =
            PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "lifted_pair", &sig);

        assert!(
            output.contains("printf(label, BITS(pair, 32, 32));"),
            "Expected lifted high-half identifier to rewrite from the packed param source, got:\n{}",
            output
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_preserves_return_high_half() {
        let input = r#"int64_t make_pair(int64_t left, int64_t right)
{
    int local_4;
    int out;

    left = left;
    right = right;
    out = left;
    local_4 = right;
    return out;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("return { .lo = out, .hi = local_4 };"),
            "Expected packed return repair, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_rewrites_printf_high_half() {
        let input = r#"void print_pair_sum(int64_t pair, int64_t label)
{
    int arg2;
    int local_4;
    int ret_0;

    pair = pair;
    label = label;
    ret_0 = printf("%s: %d %d\n", label, pair, local_4);
    arg2 = pair;
    return;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains(r#"printf("%s: %d %d\n", label, pair, BITS(pair, 32, 32));"#),
            "Expected packed printf repair, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("int local_4;"),
            "Expected unused high-half temp declaration to be removed, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_removes_redundant_second_shift() {
        let input = r#"int64_t make_pair(int32_t arg0, int64_t arg1)
{
    arg1 <<= 32;
    return arg0 | arg1 << 32;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("return { .lo = arg0, .hi = arg1 };"),
            "Expected redundant second shift repair to preserve the packed pair field-literal, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("arg1 <<= 32;") && !repaired.contains("arg1 << 32;"),
            "Expected repaired output to avoid redundant shifts, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_rewrites_shift_then_or_return() {
        let input = r#"int64_t make_pair(int32_t arg0, int64_t arg1)
{
    arg1 <<= 32;
    return arg0 | arg1;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("return { .lo = arg0, .hi = arg1 };"),
            "Expected shift-then-or pair return repair, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("arg1 <<= 32;"),
            "Expected repaired output to drop the redundant left shift, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_normalizes_shifted_set_bits_source() {
        let input = r#"int32_t set_count(int16_t* arr, int8_t arg1)
{
    int ret;

    ret = arg1;
    ret <<= 4;
    arg1 = SET_BITS(*(uint16_t*)(arr), ret, 4, 8);
    *(uint16_t*)(arr) = SET_BITS(*(uint16_t*)(arr), ret, 4, 8);
    return ret;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("*(uint16_t*)(arr) = SET_BITS(*(uint16_t*)(arr), arg1, 4, 8);"),
            "Expected SET_BITS repair to recover the unshifted source value, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("arg1 = SET_BITS("),
            "Expected redundant alias assignment to be removed, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_drops_dead_param_restore_artifacts() {
        let input = r#"int32_t hex_float(double farg0)
{
    int local_8;
    int ret;

    ret = local_8;
    return printf("%a\n", farg0);
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            !repaired.contains("int local_8;") && !repaired.contains("int ret;"),
            "Expected dead restore locals to be dropped, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("ret = local_8;"),
            "Expected dead restore copy to be dropped, got:\n{}",
            repaired
        );
        assert!(
            repaired.contains("return printf(\"%a\\n\", farg0);"),
            "Expected forwarding call to remain, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_rewrites_stack_guard_return_to_helper_arg() {
        let input = r#"int64_t make_one_alloc(int32_t arg0, int32_t arg1, int32_t arg2)
{
    int local_8;

    local_8 = __stack_chk_guard;
    helper(arg0, arg1, arg2);
    return local_8;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("return arg0;"),
            "expected repaired return to use helper sret arg, got:\n{}",
            repaired
        );
        assert!(
            !repaired.contains("local_8 = __stack_chk_guard;")
                && !repaired.contains("int local_8;"),
            "expected dead guard temp to be removed, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_repair_packed_small_aggregate_output_preserves_return_statement() {
        let input = r#"int32_t main(void)
{
    return 0;
}"#;

        let repaired = PseudoCodeEmitter::repair_packed_small_aggregate_output(input.to_string());
        assert!(
            repaired.contains("return 0;"),
            "Expected return statement to remain, got:\n{}",
            repaired
        );
    }

    #[test]
    fn test_canonical_decl_var_name_strips_array_suffix() {
        assert_eq!(
            canonical_decl_var_name("tmp1[idx]"),
            Some("tmp1".to_string())
        );
        assert_eq!(canonical_decl_var_name("sum"), Some("sum".to_string()));
    }

    #[test]
    fn test_collect_decl_identifiers_from_emitted_body_parses_assignments_only() {
        let body = r#"
    sum = 0;
    ptr[idx] = value;
    if (sum == 0) {
        sum += ptr[idx];
    }
    while (ptr != 0) {
        ptr = next;
    }
"#;
        let vars = collect_decl_identifiers_from_emitted_body(body);
        assert!(vars.contains("sum"));
        assert!(vars.contains("ptr"));
        assert!(!vars.contains("if"));
        assert!(!vars.contains("while"));
    }

    #[test]
    fn test_extract_assignment_lhs_handles_xor_assign() {
        assert_eq!(
            super::predicates::extract_assignment_lhs("var_148 ^= saved3;"),
            Some("var_148")
        );
    }

    #[test]
    fn test_collect_decl_identifiers_from_emitted_body_handles_xor_assign() {
        let vars = collect_decl_identifiers_from_emitted_body("    var_148 ^= saved3;\n");
        assert!(vars.contains("var_148"));
        assert!(!vars.contains("var_148 ^"));
        assert!(!is_declarable_variable("var_148 ^"));
    }

    #[test]
    fn test_emit_statement_preserves_comment_without_semicolon() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(Expr::unknown("/* SSE: punpcklqdq */"))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(
            output.contains("    /* SSE: punpcklqdq */\n"),
            "expected standalone comment emission, got:\n{output}"
        );
        assert!(
            !output.contains("/* SSE: punpcklqdq */;"),
            "did not expect a comment statement to gain a semicolon, got:\n{output}"
        );
    }

    #[test]
    fn test_emit_statement_rewrites_integer_simd_call_to_comment() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Expr(Expr::call(
                CallTarget::Named("punpcklqdq".to_string()),
                vec![Expr::unknown("arr"), Expr::unknown("var_108")],
            ))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        assert!(
            output.contains("    /* SSE: punpcklqdq */\n"),
            "expected integer SIMD call to be suppressed into a comment, got:\n{output}"
        );
        assert!(
            !output.contains("punpcklqdq(arr, var_108);"),
            "did not expect raw SIMD pseudo-call to survive, got:\n{output}"
        );
    }

    #[test]
    fn test_type_inference_integration() {
        use super::super::expression::Variable;

        // Create a structured CFG with stack slot variables
        // Simulating [rbp - 0x8] and [rbp - 0x10] patterns that become local_8 and local_10

        // Create expressions for stack slots: *(rbp + -8) and *(rbp + -16)
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let local_8_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-8));
        let local_10_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-16));

        // Create deref expressions for the stack slots
        let local_8 = Expr::deref(local_8_addr.clone(), 8);
        let local_10 = Expr::deref(local_10_addr.clone(), 4);

        // Create assignments to these stack slots
        let stmt1 = Expr::assign(local_8.clone(), Expr::int(42));
        let stmt2 = Expr::assign(local_10.clone(), Expr::int(100));

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![stmt1, stmt2],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        // Test without type info - should use pattern-based naming
        // Since these stack slots are being dereferenced, they're detected as pointers
        // and named "ptr", "ptr2" instead of "local_8", "local_10"
        let emitter_no_types = PseudoCodeEmitter::new("    ", false);
        let output_no_types = emitter_no_types.emit(&cfg, "test_func");

        // Variable declarations should show pointer names (pattern-based naming)
        // or fall back to local_X names if pattern detection doesn't trigger
        assert!(
            output_no_types.contains("ptr") || output_no_types.contains("local_8"),
            "Expected ptr or local_8 variables in output:\n{}",
            output_no_types
        );

        // Test with type info - should use inferred types
        // Note: type_info keys should match the generated names (ptr, ptr2)
        let mut type_info = HashMap::new();
        type_info.insert("ptr".to_string(), "int64_t".to_string());
        type_info.insert("ptr2".to_string(), "uint32_t".to_string());

        let emitter_with_types = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output_with_types = emitter_with_types.emit(&cfg, "test_func");

        // Variable declarations should use the inferred types with pattern-based names
        assert!(
            output_with_types.contains("int64_t ptr")
                || output_with_types.contains("int64_t local_8"),
            "Expected 'int64_t ptr' or 'int64_t local_8' in output:\n{}",
            output_with_types
        );
        assert!(
            output_with_types.contains("uint32_t ptr2")
                || output_with_types.contains("uint32_t local_10"),
            "Expected 'uint32_t ptr2' or 'uint32_t local_10' in output:\n{}",
            output_with_types
        );
    }

    #[test]
    fn test_type_inference_with_parameters() {
        use super::super::expression::Variable;

        // Test that type info is used for function parameters

        // Create a function with a parameter (simulating ARM64 w0 -> local_4)
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let local_4_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-4));
        let local_4 = Expr::deref(local_4_addr, 4);

        // Parameter setup: local_4 = w0 (first parameter)
        let param_setup = Expr::assign(local_4.clone(), Expr::var(Variable::reg("w0", 4)));

        // Some computation using the parameter
        let result = Expr::assign(
            Expr::unknown("result"),
            Expr::binop(BinOpKind::Mul, local_4.clone(), Expr::int(2)),
        );

        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![param_setup, result],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        // Test with type info for the parameter
        // Note: pattern-based naming may rename this to "ptr" since it's dereferenced
        let mut type_info = HashMap::new();
        type_info.insert("local_4".to_string(), "size_t".to_string());
        type_info.insert("ptr".to_string(), "size_t".to_string()); // Also add for pattern-based name

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output = emitter.emit(&cfg, "compute");

        // The parameter should have the inferred type (either as local_4 or ptr)
        assert!(
            output.contains("size_t local_4") || output.contains("size_t ptr"),
            "Expected 'size_t local_4' or 'size_t ptr' in output:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_infers_spilled_pointer_width_from_assignment_and_indexed_use() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::assign(Expr::unknown("local_8"), Expr::unknown("arr"))],
            address_range: (0x1000, 0x1008),
        };
        let cfg = StructuredCfg {
            body: vec![
                block,
                StructuredNode::Return(Some(Expr::array_access(
                    Expr::unknown("local_8"),
                    Expr::int(1),
                    2,
                ))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut type_info = HashMap::new();
        type_info.insert("arr".to_string(), "int16_t*".to_string());

        let output = PseudoCodeEmitter::new("    ", false)
            .with_type_info(type_info)
            .emit(&cfg, "read_version");

        assert!(
            output.contains("int16_t* arr"),
            "Expected preserved 16-bit pointer type in the emitted signature, got:\n{}",
            output
        );
        assert!(
            output.contains("return arr[1];") || output.contains("return local_8[1];"),
            "Expected indexed reload to stay 16-bit wide, got:\n{}",
            output
        );
        assert!(
            !output.contains("char* local_8"),
            "Did not expect the spill to degrade into a byte pointer, got:\n{}",
            output
        );
    }

    #[test]
    fn test_get_type_defaults_to_int() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Without type info, should default to "int"
        assert_eq!(emitter.get_type("var_4"), "int");
        assert_eq!(emitter.get_type("local_8"), "int");
        assert_eq!(emitter.get_type("unknown_var"), "int");
    }

    #[test]
    fn test_recover_signature_with_summary_callback_hint() {
        use super::super::expression::Variable;

        let call = Expr::call(
            CallTarget::Named("bsearch".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_summary_database(Arc::new(SummaryDatabase::new()));
        let sig = emitter.recover_signature(&cfg);

        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_low_confidence_callback_parameter_renders_as_void_ptr() {
        let param = super::super::signature::Parameter::new(
            "compar",
            super::super::signature::ParamType::FunctionPointer {
                return_type: Box::new(super::super::signature::ParamType::SignedInt(32)),
                params: vec![
                    super::super::signature::ParamType::Pointer,
                    super::super::signature::ParamType::Pointer,
                ],
            },
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rcx".to_string(),
                index: 3,
            },
        )
        .with_confidence(1);

        assert_eq!(
            PseudoCodeEmitter::format_signature_param(&param, "compar"),
            "void* compar"
        );
    }

    #[test]
    fn test_emit_with_signature_applies_pointer_type_hint_to_generic_param() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::int(0)))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);
        sig.parameters
            .push(super::super::signature::Parameter::from_int_register(
                0,
                "rdi",
                super::super::signature::ParamType::SignedInt(64),
            ));

        let mut type_info = HashMap::new();
        type_info.insert("arg0".to_string(), "int*".to_string());
        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output = emitter.emit_with_signature(&cfg, "typed_arg", &sig);
        let header = output.lines().next().unwrap_or_default();
        assert!(
            header.contains("int* arg0"),
            "expected pointer type hint in header, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_non_void_bare_return_uses_zero_fallback() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "ret_fixup", &sig);
        assert!(
            output.contains("return 0;"),
            "non-void bare return should emit value fallback:\n{}",
            output
        );
        assert!(
            !output.contains("return;"),
            "non-void output must not emit bare return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_void_bare_return_stays_void() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "void_ret_ok", &sig);
        assert!(
            output.contains("return;"),
            "void bare return should be preserved:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_folds_terminal_tail_call_return() {
        let tail_call = Expr::call(
            CallTarget::Named("helper".to_string()),
            vec![Expr::unknown("argc")],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1000, 0x1010),
        };
        let padding = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(1),
            statements: vec![Expr::unknown("/* nop */")],
            address_range: (0x1010, 0x1012),
        };
        let cfg = StructuredCfg {
            body: vec![block, padding, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "main", &sig);
        assert!(
            output.contains("return helper(argc);"),
            "expected terminal tail call to become a return:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(argc);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_folds_terminal_tail_call_from_legacy_return_analysis() {
        let tail_call = Expr::call(
            CallTarget::Named("helper".to_string()),
            vec![Expr::unknown("argc")],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1200, 0x1210),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "main");
        assert!(
            output.contains("return helper(argc);"),
            "emit() should still fold a non-void tail call:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(argc);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_folds_stack_backed_terminal_tail_call() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("local_4"), Expr::unknown("argc")),
                Expr::assign(Expr::unknown("local_10"), Expr::unknown("argv")),
                Expr::call(
                    CallTarget::Named("helper".to_string()),
                    vec![Expr::unknown("local_4")],
                ),
            ],
            address_range: (0x1220, 0x1230),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "main");
        assert!(
            output.contains("return helper(local_4);"),
            "emit() should fold stack-backed tail-call returns:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(local_4);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_folds_terminal_tail_call_across_epilogue_padding() {
        use super::super::expression::Variable;

        let call_block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::call(
                CallTarget::Named("helper".to_string()),
                vec![Expr::unknown("argc")],
            )],
            address_range: (0x1240, 0x1250),
        };
        let epilogue_block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(1),
            statements: vec![Expr::call(
                CallTarget::Named("pop".to_string()),
                vec![Expr::var(Variable::reg("rbp", 8))],
            )],
            address_range: (0x1250, 0x1252),
        };
        let cfg = StructuredCfg {
            body: vec![call_block, epilogue_block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "main");
        assert!(
            output.contains("return helper(argc);"),
            "emit() should fold tail calls across epilogue-only padding:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(argc);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_does_not_fold_atomic_store_or_fence_into_return() {
        let store_block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::call(
                    CallTarget::Named("atomic_store".to_string()),
                    vec![Expr::unknown("&g_counter"), Expr::unknown("arg0")],
                ),
                Expr::call(
                    CallTarget::Named("__atomic_thread_fence".to_string()),
                    vec![Expr::unknown("memory_order_seq_cst")],
                ),
            ],
            address_range: (0x1300, 0x1310),
        };
        let cfg = StructuredCfg {
            body: vec![store_block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "store_counter");
        assert!(
            output.contains("atomic_store(&g_counter, arg0);"),
            "pseudo atomic store should remain a statement:\n{}",
            output
        );
        assert!(
            output.contains("__atomic_thread_fence(memory_order_seq_cst);"),
            "pseudo fence should remain a statement:\n{}",
            output
        );
        assert!(
            output.contains("\n    return;\n"),
            "expected bare return after pseudo atomic statements:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_does_not_fold_builtin_prefetch_into_return() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::call(
                CallTarget::Named("__builtin_prefetch".to_string()),
                vec![Expr::unknown("arg0"), Expr::int(0), Expr::int(3)],
            )],
            address_range: (0x1310, 0x1320),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "prefetch_addr");

        assert!(
            output.contains("__builtin_prefetch(arg0, 0, 3);"),
            "builtin prefetch should remain a statement:\n{}",
            output
        );
        assert!(
            !output.contains("return __builtin_prefetch"),
            "builtin prefetch should not be folded into a return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_folds_terminal_tail_call_with_same_block_padding() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::assign(Expr::unknown("local_4"), Expr::unknown("argc")),
                Expr::call(
                    CallTarget::Named("helper".to_string()),
                    vec![Expr::unknown("local_4")],
                ),
                Expr::unknown("/* nop */"),
            ],
            address_range: (0x1260, 0x1270),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_signature_recovery(true);
        let output = emitter.emit(&cfg, "main");
        assert!(
            output.contains("return helper(local_4);"),
            "emit() should fold terminal calls past same-block tail padding:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(local_4);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_folds_terminal_tail_call_fallthrough() {
        let tail_call = Expr::call(
            CallTarget::Named("helper".to_string()),
            vec![Expr::unknown("argc")],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1100, 0x1110),
        };
        let padding = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(1),
            statements: vec![Expr::unknown("/* nop */")],
            address_range: (0x1110, 0x1112),
        };
        let cfg = StructuredCfg {
            body: vec![block, padding],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "main", &sig);
        assert!(
            output.contains("return helper(argc);"),
            "expected fallthrough tail call to become a return:\n{}",
            output
        );
        assert!(
            !output.contains("return 0;"),
            "tail-call fold should suppress fallback return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_folds_terminal_tail_call_across_epilogue_padding() {
        use super::super::expression::Variable;

        let call_block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr::call(
                CallTarget::Named("helper".to_string()),
                vec![Expr::unknown("argc")],
            )],
            address_range: (0x1120, 0x1130),
        };
        let epilogue_block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(1),
            statements: vec![Expr::call(
                CallTarget::Named("pop".to_string()),
                vec![Expr::var(Variable::reg("rbp", 8))],
            )],
            address_range: (0x1130, 0x1132),
        };
        let cfg = StructuredCfg {
            body: vec![call_block, epilogue_block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "main", &sig);
        assert!(
            output.contains("return helper(argc);"),
            "expected terminal tail call to fold across epilogue padding:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(argc);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_folds_terminal_tail_call_with_same_block_padding() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::call(
                    CallTarget::Named("helper".to_string()),
                    vec![Expr::unknown("argc")],
                ),
                Expr::unknown("/* nop */"),
            ],
            address_range: (0x1140, 0x1150),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "main", &sig);
        assert!(
            output.contains("return helper(argc);"),
            "expected terminal tail call to fold across same-block padding:\n{}",
            output
        );
        assert!(
            !output.contains("\n    helper(argc);\n"),
            "tail call should not remain a standalone statement:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_keeps_void_tail_call_as_statement() {
        let tail_call = Expr::call(
            CallTarget::Named("cleanup".to_string()),
            vec![Expr::unknown("arg0")],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1020, 0x1030),
        };
        let cfg = StructuredCfg {
            body: vec![block, StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "cleanup_wrapper", &sig);
        assert!(
            output.contains("\n    cleanup(arg0);\n"),
            "void tail call should remain a statement:\n{}",
            output
        );
        assert!(
            output.contains("return;"),
            "void signature should preserve bare return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_does_not_fold_noreturn_tail_call() {
        let tail_call = Expr::call(
            CallTarget::Named("__longjmp_chk@GLIBC_2.11@plt".to_string()),
            vec![Expr::unknown("&env"), Expr::int(2)],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1040, 0x1050),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "inner", &sig);
        assert!(
            output.contains("\n    __longjmp_chk(&env, 2);\n"),
            "noreturn tail call should remain a statement:\n{}",
            output
        );
        assert!(
            !output.contains("return __longjmp_chk"),
            "noreturn tail call must not be folded into a return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_does_not_fold_std_throw_tail_call() {
        let tail_call = Expr::call(
            CallTarget::Named("std::__throw_bad_optional_access".to_string()),
            vec![],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![tail_call],
            address_range: (0x1050, 0x1060),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "unwrap_or_throw", &sig);
        assert!(
            output.contains("\n    std::__throw_bad_optional_access();\n"),
            "noreturn tail call should remain a statement:\n{}",
            output
        );
        assert!(
            !output.contains("return std::__throw_bad_optional_access"),
            "noreturn tail call must not be folded into a return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_does_not_append_fallback_after_throw_thunk_call() {
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::If {
                    condition: Expr::unknown("arg0 != 0"),
                    then_body: vec![StructuredNode::Return(Some(Expr::int(7)))],
                    else_body: None,
                },
                StructuredNode::Expr(Expr::unknown(
                    "throw /* via unwrap_or_throw(std::optional<int>) [clone .cold]() */",
                )),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "unwrap_or_throw", &sig);
        // Single-line throw marker keeps the thunk name as a tail comment for
        // provenance; the raw cold-thunk call must not appear separately.
        assert!(
            output.contains("throw /* via unwrap_or_throw(std::optional<int>) [clone .cold]() */"),
            "throw marker should be preserved:\n{}",
            output
        );
        assert!(
            !output.contains("unwrap_or_throw(std::optional<int>) [clone .cold]();"),
            "raw cold-thunk call must not be emitted alongside the throw marker:\n{}",
            output
        );
        assert!(
            !output.contains("return unwrap_or_throw(std::optional<int>) [clone .cold]();"),
            "cold thunk path must not be folded into a synthetic return:\n{}",
            output
        );
        assert!(
            !output.contains("\n    return 0;\n"),
            "terminal throw marker must suppress fallback return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_does_not_fold_branch_local_fallthrough_call() {
        let branch_call = Expr::call(
            CallTarget::Named("atoi".to_string()),
            vec![Expr::unknown("arg0")],
        );
        let tail_call = Expr::call(
            CallTarget::Named("finish".to_string()),
            vec![Expr::unknown("arg1")],
        );
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::If {
                    condition: Expr::unknown("cond"),
                    then_body: vec![StructuredNode::Block {
                        id: hexray_core::BasicBlockId::new(0),
                        statements: vec![Expr::assign(Expr::unknown("x"), Expr::int(2))],
                        address_range: (0x1200, 0x1204),
                    }],
                    else_body: Some(vec![StructuredNode::Block {
                        id: hexray_core::BasicBlockId::new(1),
                        statements: vec![branch_call],
                        address_range: (0x1210, 0x1218),
                    }]),
                },
                StructuredNode::Block {
                    id: hexray_core::BasicBlockId::new(2),
                    statements: vec![tail_call],
                    address_range: (0x1220, 0x1228),
                },
                StructuredNode::Return(None),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "main", &sig);
        assert!(
            output.contains("\n        atoi(arg0);\n"),
            "branch-local fallthrough call should remain a statement:\n{}",
            output
        );
        assert!(
            !output.contains("return atoi(arg0);"),
            "branch-local fallthrough call should not become a return:\n{}",
            output
        );
        assert!(
            output.contains("return finish(arg1);"),
            "top-level tail call should still fold into a return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_appends_fallback_return_on_top_level_fallthrough() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::If {
                condition: Expr::unknown("cond"),
                then_body: vec![StructuredNode::Return(Some(Expr::int(1)))],
                else_body: None,
            }],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };
        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "fallthrough_fixup", &sig);
        assert!(
            output.contains("return 0;"),
            "non-void fallthrough should emit fallback return:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_keeps_function_pointer_param_shape() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::int(0)))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(32);
        sig.parameters.push(super::super::signature::Parameter::new(
            "arg0",
            super::super::signature::ParamType::FunctionPointer {
                return_type: Box::new(super::super::signature::ParamType::SignedInt(32)),
                params: vec![
                    super::super::signature::ParamType::Pointer,
                    super::super::signature::ParamType::Pointer,
                ],
            },
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));

        let mut type_info = HashMap::new();
        type_info.insert("arg0".to_string(), "void*".to_string());
        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output = emitter.emit_with_signature(&cfg, "typed_cb", &sig);
        let header = output.lines().next().unwrap_or_default();
        assert!(
            header.contains("(*arg0)("),
            "function-pointer signature should be preserved, got:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_with_signature_formats_function_pointer_return_header() {
        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(None)],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::new(
            super::super::signature::CallingConvention::SystemV,
        );
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::FunctionPointer {
            return_type: Box::new(super::super::signature::ParamType::Void),
            params: vec![super::super::signature::ParamType::SignedInt(32)],
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit_with_signature(&cfg, "fp_ret", &sig);
        let header = output.lines().next().unwrap_or_default();
        assert_eq!(header, "void (*fp_ret(void))(int32_t)");
    }

    #[test]
    fn test_emit_does_not_force_callback_type_for_static_callback_symbol() {
        use super::super::expression::Variable;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::int(4),
                Expr::unknown("cmp_ints"),
            ],
        );
        let keep_r8_live = Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("r8", 8)));
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![call, keep_r8_live],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "qsort_wrapper");
        let header = output.lines().next().unwrap_or_default();
        assert!(
            !header.contains("(*arg"),
            "Header should keep static callback symbols as non-parameter values:\n{}",
            output
        );
    }

    #[test]
    fn test_emit_types_bsearch_callback_when_lifted_to_arg4() {
        use super::super::expression::Variable;

        let call = Expr::call(
            CallTarget::Named("bsearch".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::int(4),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "lookup_wrapper");
        let header = output.lines().next().unwrap_or_default();
        assert!(
            header.contains("(*arg4)(void*, void*)") || header.contains("(*compar)(void*, void*)"),
            "Header should include typed bsearch callback in arg4 position:\n{}",
            output
        );
    }

    #[test]
    fn test_try_format_stack_slot() {
        use super::super::expression::Variable;

        let emitter = PseudoCodeEmitter::new("    ", false);

        // Test rbp + -8 pattern (frame pointer with negative offset)
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let addr = Expr::binop(BinOpKind::Add, rbp, Expr::int(-8));
        let result = emitter.try_format_stack_slot(&addr, 8);
        assert!(result.is_some(), "Expected Some for rbp + -8, got None");
        let name = result.unwrap();
        assert!(
            name.contains("local") || name.contains("var"),
            "Expected local/var name, got: {}",
            name
        );

        // Test sp + 16 pattern (stack pointer with positive offset)
        let sp = Expr::var(Variable::reg("sp", 8));
        let addr_sp = Expr::binop(BinOpKind::Add, sp, Expr::int(16));
        let result_sp = emitter.try_format_stack_slot(&addr_sp, 4);
        assert!(result_sp.is_some(), "Expected Some for sp + 16, got None");
    }

    #[test]
    fn test_emit_formats_stack_slot_array_access_with_dynamic_index() {
        use super::super::expression::Variable;

        let rbp = Expr::var(Variable::reg("rbp", 8));
        let dynamic_index = Expr::unknown("ret");
        let base = Expr::binop(BinOpKind::Add, rbp, dynamic_index.clone());
        let access = Expr::array_access(base, Expr::int(-1088), 1);
        let assign = Expr::assign(access, Expr::int(0));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: hexray_core::BasicBlockId::new(0),
                statements: vec![assign],
                address_range: (0x1000, 0x1004),
            }],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut type_info = HashMap::new();
        type_info.insert("local_440".to_string(), "char*".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let output = emitter.emit(&cfg, "stack_array");

        assert!(
            output.contains("char* local_440;"),
            "expected a typed stack slot declaration, got:\n{}",
            output
        );
        assert!(
            output.contains("local_440[ret] = 0;"),
            "expected stack-slot array formatting, got:\n{}",
            output
        );
        assert!(
            !output.contains("(rbp + ret)"),
            "did not expect raw frame-pointer arithmetic, got:\n{}",
            output
        );
    }

    #[test]
    fn test_get_type_uses_type_info() {
        let mut type_info = HashMap::new();
        type_info.insert("var_4".to_string(), "uint64_t".to_string());
        type_info.insert("local_8".to_string(), "float".to_string());
        type_info.insert("ptr".to_string(), "char*".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);

        // Should use the provided type info
        assert_eq!(emitter.get_type("var_4"), "uint64_t");
        assert_eq!(emitter.get_type("local_8"), "float");
        assert_eq!(emitter.get_type("ptr"), "char*");

        // Unknown variables should still default to "int"
        assert_eq!(emitter.get_type("unknown_var"), "int");
    }

    #[test]
    fn test_type_lookup_uses_argument_register_aliases() {
        let mut type_info = HashMap::new();
        type_info.insert("rdi".to_string(), "void*".to_string());
        type_info.insert("xmm1".to_string(), "double".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);

        assert_eq!(emitter.get_type("arg1"), "double");
        assert_eq!(
            emitter.find_param_type_hint(0, "arg0", "arg0"),
            Some("void*".to_string())
        );
        assert_eq!(
            emitter.find_param_type_hint(1, "farg1", "farg1"),
            Some("double".to_string())
        );
    }

    #[test]
    fn test_libc_global_gotref_name_simplification() {
        let mut sym = SymbolTable::new();
        sym.insert(0x1000, "__stderrp".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x1000, 0, 8, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "stderr");
    }

    #[test]
    fn test_libc_global_gotref_uses_pc_relative_data_relocation_name() {
        let mut relocations = RelocationTable::new();
        relocations.insert_data(0x27, "stderr".to_string(), 0, true);

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_relocation_table(Some(relocations));
        let expr = Expr::got_ref(0x6e, 0x27, 8, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "stderr");
    }

    #[test]
    fn test_call_target_strips_unambiguous_glibc_version_suffix() {
        let emitter = PseudoCodeEmitter::new("    ", false);
        let call = Expr::call(CallTarget::Named("printf@GLIBC_2.2.5".to_string()), vec![]);

        assert_eq!(emitter.format_expr(&call), "printf()");
    }

    #[test]
    fn test_call_target_keeps_glibc_version_suffix_for_mixed_versions() {
        let mut relocations = RelocationTable::new();
        relocations.insert(0x1000, "printf@GLIBC_2.2.5".to_string());
        relocations.insert(0x1008, "printf@GLIBC_2.34".to_string());

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_relocation_table(Some(relocations));
        let call = Expr::call(CallTarget::Named("printf@GLIBC_2.2.5".to_string()), vec![]);

        assert_eq!(emitter.format_expr(&call), "printf@GLIBC_2.2.5()");
    }

    #[test]
    fn test_global_ref_strips_unambiguous_glibc_version_suffix() {
        let mut sym = SymbolTable::new();
        sym.insert(0x1000, "stdout@@GLIBC_2.2.5".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x1000, 0, 8, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "stdout");
    }

    #[test]
    fn test_libc_global_nested_deref_simplification() {
        let mut sym = SymbolTable::new();
        sym.insert(0x2000, "__stdoutp".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::deref(Expr::got_ref(0x2000, 0, 8, Expr::unknown("rip_ref")), 8);

        assert_eq!(emitter.format_expr(&expr), "*stdout");
    }

    #[test]
    fn test_absolute_deref_symbol_resolution() {
        let mut sym = SymbolTable::new();
        sym.insert(0x403de0, "counter".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::deref(Expr::int(0x403de0), 4);

        assert_eq!(emitter.format_expr(&expr), "counter");
    }

    #[test]
    fn test_absolute_deref_smaller_than_global_uses_field_access() {
        let mut sym = SymbolTable::new();
        sym.insert_with_metadata(0x403de0, "g_tls_struct".to_string(), 16, true, true);

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::deref(Expr::int(0x403de0), 4);

        assert_eq!(emitter.format_expr(&expr), "g_tls_struct.field_0");
    }

    #[test]
    fn test_global_address_materialization_uses_address_of_symbol() {
        let mut sym = SymbolTable::new();
        sym.insert(0x4040e4, "g_counter".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_addr(0x4040e4, 0, Expr::int(0x4040e4));

        assert_eq!(emitter.format_expr(&expr), "&g_counter");
    }

    #[test]
    fn test_assignment_of_absolute_global_address_uses_symbol() {
        let mut sym = SymbolTable::new();
        sym.insert(0x4040e4, "g_counter".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::assign(Expr::deref(Expr::unknown("out"), 8), Expr::int(0x4040e4));

        assert_eq!(emitter.format_expr(&expr), "*(uint64_t*)(out) = &g_counter");
    }

    #[test]
    fn test_array_notation_for_constant_array_access() {
        use super::super::expression::Variable;

        let emitter = PseudoCodeEmitter::new("    ", false);
        // Array access with constant index uses array notation for readability
        // Note: x8 is renamed to tmp0 for ARM64 temporary registers
        let expr = Expr::array_access(Expr::var(Variable::reg("x8", 8)), Expr::int(2), 8);
        assert_eq!(emitter.format_expr(&expr), "tmp0[2]");
    }

    #[test]
    fn test_array_access_with_absolute_global_base_uses_symbol_name() {
        let mut sym = SymbolTable::new();
        sym.insert(0x404040, "g_arr".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::array_access(Expr::int(0x404040), Expr::unknown("i"), 4);

        assert_eq!(emitter.format_expr(&expr), "g_arr[i]");
    }

    #[test]
    fn test_interior_global_access_prefers_defined_container_over_undefined_alias() {
        let mut sym = SymbolTable::new();
        sym.insert_with_metadata(0x5000, "g_struct".to_string(), 16, true, true);
        sym.insert_with_metadata(0x5008, "stdin".to_string(), 0, false, false);

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x5008, 0, 4, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "g_struct.field_8");
    }

    #[test]
    fn test_emit_does_not_declare_resolved_gotref_global() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(Expr::got_ref(
                        0x403df0,
                        0,
                        4,
                        Expr::unknown("s_thread_local"),
                    )),
                    rhs: Box::new(Expr::int(1)),
                },
            }],
            address_range: (0x1000, 0x1004),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sym = SymbolTable::new();
        sym.insert(0x403df0, "s_thread_local".to_string());
        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let output = emitter.emit(&cfg, "incr_static");

        assert!(
            !output.contains("int s_thread_local;"),
            "did not expect a local declaration for resolved TLS global:\n{output}"
        );
        assert!(
            output.contains("s_thread_local += 1;"),
            "expected compound assignment to use the TLS global name:\n{output}"
        );
    }

    #[test]
    fn test_emit_tls_compound_assign_keeps_unit_literal_rhs() {
        let block = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![Expr {
                kind: ExprKind::CompoundAssign {
                    op: BinOpKind::Add,
                    lhs: Box::new(Expr::deref(Expr::int(0x10), 4)),
                    rhs: Box::new(Expr::int(1)),
                },
            }],
            address_range: (0x1000, 0x1004),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sym = SymbolTable::new();
        sym.insert_with_metadata(0x0, "g_tls_struct".to_string(), 16, true, true);
        sym.insert_with_metadata(0x10, "s_thread_local".to_string(), 4, true, true);

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let output = emitter.emit(&cfg, "incr_static");

        assert!(
            output.contains("s_thread_local += 1;"),
            "expected TLS unit increment to keep literal rhs:\n{output}"
        );
        assert!(
            !output.contains("g_tls_struct + 1"),
            "did not expect TLS canonical offset to be reinterpreted as a global address:\n{output}"
        );
    }

    #[test]
    fn test_tls_get_addr_descriptor_argument_is_named() {
        let mut relocations = RelocationTable::new();
        relocations.insert_tls_descriptor(0x3fb8, "lib_counter".to_string());

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_relocation_table(Some(relocations));
        let call = Expr::call(
            super::super::expression::CallTarget::Named("__tls_get_addr@GLIBC_2.3".to_string()),
            vec![Expr::got_addr(0x3fb8, 0, Expr::int(0x3fb8))],
        );

        assert_eq!(
            emitter.format_expr(&call),
            "__tls_get_addr(&_TLS_lib_counter_)"
        );
    }

    #[test]
    fn test_thread_pointer_array_access_resolves_tls_symbol_name() {
        let mut tls_symbol_offsets = HashMap::new();
        tls_symbol_offsets.insert(-4, "tls_counter".to_string());

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_tls_symbol_offsets(tls_symbol_offsets);
        let expr = Expr::array_access(
            Expr::call(
                CallTarget::Named("__builtin_thread_pointer".to_string()),
                vec![],
            ),
            Expr::int(-4),
            1,
        );

        assert_eq!(emitter.format_expr(&expr), "tls_counter");
    }

    #[test]
    fn test_thread_pointer_array_access_scales_index_for_tls_lookup() {
        let mut tls_symbol_offsets = HashMap::new();
        tls_symbol_offsets.insert(-4, "tls_counter".to_string());

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_tls_symbol_offsets(tls_symbol_offsets);
        let expr = Expr::array_access(
            Expr::call(
                CallTarget::Named("__builtin_thread_pointer".to_string()),
                vec![],
            ),
            Expr::int(-1),
            4,
        );

        assert_eq!(emitter.format_expr(&expr), "tls_counter");
    }

    #[test]
    fn test_flag_name_for_rip_relative_array_lvalue() {
        use super::super::expression::Variable;

        let emitter = PseudoCodeEmitter::new("    ", false);
        let lhs = Expr::array_access(Expr::var(Variable::reg("rip", 8)), Expr::int(12), 4);
        let rhs = Expr::binop(BinOpKind::Or, lhs.clone(), Expr::int(1));
        let stmt = Expr::assign(lhs, rhs);

        assert_eq!(emitter.format_expr(&stmt), "g_flags_rip_30 |= FLAG_1");
    }

    #[test]
    fn test_signal_handler_argument_symbol_resolution() {
        let mut sym = SymbolTable::new();
        sym.insert(0x1234, "signal_handler".to_string());
        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));

        let call = Expr::call(
            super::super::expression::CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), Expr::int(0x1234)],
        );

        assert_eq!(emitter.format_expr(&call), "signal(2, signal_handler)");
    }

    #[test]
    fn test_call_literal_argument_prefers_exact_function_symbol() {
        let mut sym = SymbolTable::new();
        sym.insert_with_metadata(0x4012b0, "sub_4012b0".to_string(), 0, true, false);
        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));

        let call = Expr::call(
            super::super::expression::CallTarget::Named("helper".to_string()),
            vec![Expr::int(0x4012b0)],
        );

        assert_eq!(emitter.format_expr(&call), "helper(sub_4012b0)");
    }

    #[test]
    fn test_qsort_callback_literal_argument_falls_back_to_sub_name() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        let call = Expr::call(
            super::super::expression::CallTarget::Named("qsort".to_string()),
            vec![
                Expr::unknown("base"),
                Expr::unknown("nmemb"),
                Expr::int(4),
                Expr::int(0x4012b0),
            ],
        );

        assert_eq!(
            emitter.format_expr(&call),
            "qsort(base, nmemb, 4, sub_4012b0)"
        );
    }

    #[test]
    fn test_madd_calls_render_as_arithmetic() {
        let emitter = PseudoCodeEmitter::new("    ", false);
        let expr = Expr::call(
            super::super::expression::CallTarget::Named("madd".to_string()),
            vec![Expr::unknown("count"), Expr::int(4), Expr::unknown("arr")],
        );

        assert_eq!(emitter.format_expr(&expr), "arr + count * 4");
    }

    #[test]
    fn test_normalize_arg_hex_variable_name() {
        use super::super::expression::{VarKind, Variable};

        let emitter = PseudoCodeEmitter::new("    ", false);
        let expr = Expr::unknown("arg_4");
        // Unknown stays unknown; use Var path to test normalization.
        let var_expr = Expr::var(Variable {
            kind: VarKind::Temp(1),
            name: "arg_4".to_string(),
            size: 4,
        });
        let out = emitter.format_expr(&var_expr);
        assert_eq!(out, "local_4");
        assert_eq!(normalize_variable_name("arg_30"), "local_30");
        assert_eq!(normalize_variable_name("arg0"), "arg0");
        assert_eq!(normalize_variable_name("result"), "result");
        // Ensure no panic on non-hex suffix.
        assert_eq!(normalize_variable_name("arg_xyz"), "arg_xyz");
        assert_eq!(emitter.format_expr(&expr), "local_4");
    }

    #[test]
    fn test_expanded_libc_globals_environ() {
        let mut sym = SymbolTable::new();
        sym.insert(0x3000, "__environ".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x3000, 0, 8, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "environ");
    }

    #[test]
    fn test_expanded_libc_globals_optind() {
        let mut sym = SymbolTable::new();
        sym.insert(0x4000, "_optind".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x4000, 0, 4, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "optind");
    }

    #[test]
    fn test_macos_triple_underscore_stdio_simplification() {
        let mut sym = SymbolTable::new();
        sym.insert(0x5000, "___stderrp".to_string());
        sym.insert(0x5008, "___stdoutp".to_string());
        sym.insert(0x5010, "___stdinp".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));

        assert_eq!(
            emitter.format_expr(&Expr::got_ref(0x5000, 0, 8, Expr::unknown("ref"))),
            "stderr"
        );
        assert_eq!(
            emitter.format_expr(&Expr::got_ref(0x5008, 0, 8, Expr::unknown("ref"))),
            "stdout"
        );
        assert_eq!(
            emitter.format_expr(&Expr::got_ref(0x5010, 0, 8, Expr::unknown("ref"))),
            "stdin"
        );
    }

    #[test]
    fn test_global_access_tracking_frequency() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Access an unknown global multiple times via got_ref (is_deref: true by default)
        let expr = Expr::got_ref(0x6000, 0, 8, Expr::unknown("ref"));
        let _ = emitter.format_expr(&expr);
        let _ = emitter.format_expr(&expr);
        let _ = emitter.format_expr(&expr);

        let tracker = emitter.global_tracker();
        assert_eq!(tracker.get_count(0x6000), 3);
    }

    #[test]
    fn test_global_usage_hint_pointer_deref() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Access via dereference (got_ref with is_deref: true) should mark as PointerDeref
        let expr = Expr::got_ref(0x7000, 0, 8, Expr::unknown("ref"));
        let formatted = emitter.format_expr(&expr);

        // Should use g_ptr_ prefix for pointer dereference (now with g_ prefix)
        assert!(
            formatted.contains("g_ptr_7000"),
            "Expected g_ptr_7000 in '{}' for pointer dereference",
            formatted
        );
    }

    #[test]
    fn test_global_fallback_name_formats() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Test different naming hints - now with g_ prefix
        assert_eq!(
            emitter.format_global_fallback_name(0x1234, GlobalUsageHint::PointerDeref),
            "g_ptr_1234"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x5678, GlobalUsageHint::BitwiseOps),
            "g_flags_5678"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x9abc, GlobalUsageHint::FunctionPointer),
            "g_func_9abc"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0xdef0, GlobalUsageHint::Unknown),
            "g_def0"
        );

        // Test new hint variants
        assert_eq!(
            emitter.format_global_fallback_name(0x1000, GlobalUsageHint::Counter),
            "g_counter_1000"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x2000, GlobalUsageHint::ReadOnly),
            "g_const_2000"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x3000, GlobalUsageHint::WriteHeavy),
            "g_state_3000"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x4000, GlobalUsageHint::StringPointer),
            "g_str_4000"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x5000, GlobalUsageHint::ArrayBase),
            "g_arr_5000"
        );
        assert_eq!(
            emitter.format_global_fallback_name(0x6000, GlobalUsageHint::StdioStream),
            "g_stream_6000"
        );
    }

    #[test]
    fn test_libc_global_pattern_guess_requires_import_evidence() {
        let emitter = PseudoCodeEmitter::new("    ", false);
        assert_eq!(
            emitter.format_global_fallback_name(0x1040, GlobalUsageHint::Unknown),
            "g_1040"
        );

        let mut relocations = RelocationTable::new();
        relocations.insert_got(0x5000, "stdin@GLIBC_2.2.5".to_string());

        let emitter =
            PseudoCodeEmitter::new("    ", false).with_relocation_table(Some(relocations));
        assert_eq!(
            emitter.format_global_fallback_name(0x1040, GlobalUsageHint::Unknown),
            "g_stdin"
        );
    }

    #[test]
    fn test_global_tracker_read_write_counts() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Simulate read and write accesses
        emitter.record_global_read(0x1000);
        emitter.record_global_read(0x1000);
        emitter.record_global_write(0x1000);

        let tracker = emitter.global_tracker();
        assert_eq!(tracker.get_read_count(0x1000), 2);
        assert_eq!(tracker.get_write_count(0x1000), 1);
        assert!(!tracker.is_read_only(0x1000)); // Has writes
        assert!(!tracker.is_write_heavy(0x1000)); // More reads than writes
    }

    #[test]
    fn test_global_tracker_read_only_detection() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Only read, no writes
        emitter.record_global_read(0x2000);
        emitter.record_global_read(0x2000);
        emitter.record_global_read(0x2000);

        let tracker = emitter.global_tracker();
        assert!(tracker.is_read_only(0x2000));
        assert_eq!(tracker.infer_best_hint(0x2000), GlobalUsageHint::ReadOnly);
    }

    #[test]
    fn test_global_tracker_write_heavy_detection() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // More writes than reads
        emitter.record_global_write(0x3000);
        emitter.record_global_write(0x3000);
        emitter.record_global_write(0x3000);
        emitter.record_global_read(0x3000);

        let tracker = emitter.global_tracker();
        assert!(tracker.is_write_heavy(0x3000));
        assert_eq!(tracker.infer_best_hint(0x3000), GlobalUsageHint::WriteHeavy);
    }

    #[test]
    fn test_global_tracker_counter_detection() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Increment operation
        emitter.record_global_increment(0x4000);

        let tracker = emitter.global_tracker();
        assert!(tracker.is_counter(0x4000));
        assert_eq!(tracker.infer_best_hint(0x4000), GlobalUsageHint::Counter);
    }

    #[test]
    fn test_global_tracker_size_hints() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Record size info
        {
            let mut tracker = emitter.global_tracker.borrow_mut();
            tracker.record_size(0x5000, 4);
            tracker.record_size(0x5008, 8);
            tracker.record_size(0x5010, 1);
        }

        let tracker = emitter.global_tracker();
        assert_eq!(tracker.get_size_hint(0x5000), GlobalSizeHint::DWord);
        assert_eq!(tracker.get_size_hint(0x5008), GlobalSizeHint::QWord);
        assert_eq!(tracker.get_size_hint(0x5010), GlobalSizeHint::Byte);
    }

    #[test]
    fn test_global_tracker_proximity_grouping() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Create globals that should be grouped (within 64 bytes of each other)
        {
            let mut tracker = emitter.global_tracker.borrow_mut();
            tracker.record_access(0x1000, GlobalUsageHint::Unknown);
            tracker.record_access(0x1008, GlobalUsageHint::Unknown);
            tracker.record_access(0x1010, GlobalUsageHint::Unknown);
            // This one is far away
            tracker.record_access(0x2000, GlobalUsageHint::Unknown);
            tracker.record_access(0x2008, GlobalUsageHint::Unknown);
        }

        let tracker = emitter.global_tracker();
        let groups = tracker.group_by_proximity();

        // Should have 2 groups
        assert_eq!(groups.len(), 2);

        // First group should have 3 members
        assert_eq!(groups[0].0, 0x1000);
        assert_eq!(groups[0].1.len(), 3);

        // Second group should have 2 members
        assert_eq!(groups[1].0, 0x2000);
        assert_eq!(groups[1].1.len(), 2);
    }

    #[test]
    fn test_global_fallback_name_with_size_inference() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Record size for an unknown global
        emitter.record_and_name_global_with_size(0x1234, GlobalUsageHint::Unknown, 4);

        // Now the name should include size info
        let tracker = emitter.global_tracker();
        assert_eq!(tracker.get_size_hint(0x1234), GlobalSizeHint::DWord);
    }

    #[test]
    fn test_global_name_caching_consistency() {
        let emitter = PseudoCodeEmitter::new("    ", false);

        // First access - should generate and cache the name
        let name1 = emitter.format_global_fallback_name(0xABCD, GlobalUsageHint::PointerDeref);

        // Second access - should return cached name
        let name2 = emitter.format_global_fallback_name(0xABCD, GlobalUsageHint::BitwiseOps);

        // Both should be the same (cached value)
        assert_eq!(name1, name2);
        assert_eq!(name1, "g_ptr_abcd");
    }

    #[test]
    fn test_switch_no_redundant_break_after_goto() {
        // Test that break is not emitted after goto in switch cases
        let node = StructuredNode::Switch {
            value: Expr::unknown("x"),
            cases: vec![
                // Case 1: ends with goto - should NOT have break after
                (
                    vec![1],
                    vec![
                        StructuredNode::Expr(Expr::assign(Expr::unknown("y"), Expr::int(1))),
                        StructuredNode::Goto(hexray_core::BasicBlockId::new(99)),
                    ],
                ),
                // Case 2: ends with return - should NOT have break after
                (
                    vec![2],
                    vec![
                        StructuredNode::Expr(Expr::assign(Expr::unknown("y"), Expr::int(2))),
                        StructuredNode::Return(Some(Expr::int(0))),
                    ],
                ),
                // Case 3: no control exit - should have break
                (
                    vec![3],
                    vec![StructuredNode::Expr(Expr::assign(
                        Expr::unknown("y"),
                        Expr::int(3),
                    ))],
                ),
            ],
            default: None,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        // Case 1: goto without break after (bb99 is the target block)
        assert!(
            output.contains("goto bb99;") && !output.contains("goto bb99;\n        break;"),
            "Case 1 should not have break after goto:\n{}",
            output
        );

        // Case 2: return without break after
        assert!(
            output.contains("return 0;") && !output.contains("return 0;\n        break;"),
            "Case 2 should not have break after return:\n{}",
            output
        );

        // Case 3: should have break since it ends with normal expression
        // Look for case 3 followed by break
        let case3_section = output.split("case 3:").nth(1).unwrap_or("");
        assert!(
            case3_section.contains("break;"),
            "Case 3 should have break:\n{}",
            output
        );
    }

    #[test]
    fn test_switch_no_redundant_break_after_break() {
        // Test that break is not duplicated when case body already ends with break
        let node = StructuredNode::Switch {
            value: Expr::unknown("x"),
            cases: vec![(
                vec![1],
                vec![
                    StructuredNode::Expr(Expr::assign(Expr::unknown("y"), Expr::int(1))),
                    StructuredNode::Break,
                ],
            )],
            default: None,
        };

        let cfg = StructuredCfg {
            body: vec![node],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false);
        let output = emitter.emit(&cfg, "test");

        // Count occurrences of "break;" in the case body section
        let case_section = output.split("case 1:").nth(1).unwrap_or("");
        let break_count = case_section.matches("break;").count();
        assert_eq!(
            break_count, 1,
            "Should have exactly one break in case 1:\n{}",
            output
        );
    }

    #[test]
    fn test_rip_relative_deref_resolution() {
        use super::super::expression::{VarKind, Variable};
        // Test that *(type*)(rip + offset) resolves to _g_<offset> instead of
        // *(type*)(/* unresolved_pc_relative */ + offset)
        let emitter = PseudoCodeEmitter::new("    ", false);
        let table = StringTable::new();

        // Create a Deref expression with rip + 6842 as the address
        let rip_var = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "rip".to_string(),
            size: 8,
        });
        let offset = Expr::int(6842);
        let addr = Expr::binop(BinOpKind::Add, rip_var, offset);
        let deref = Expr::deref(addr, 4);

        let formatted = emitter.format_expr_with_strings(&deref, &table);

        // Should resolve to *(uint32_t*)(&g_1aba) (6842 in hex) instead of containing "unresolved_pc_relative"
        assert!(
            !formatted.contains("unresolved_pc_relative"),
            "Should not contain unresolved_pc_relative: {}",
            formatted
        );
        assert_eq!(
            formatted, "*(uint32_t*)(&g_1aba)",
            "Should format as *(typeN*)(&g_<hex_offset>)"
        );

        // Also test with eip
        let eip_var = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "eip".to_string(),
            size: 4,
        });
        let addr2 = Expr::binop(BinOpKind::Add, eip_var, Expr::int(0x1000));
        let deref2 = Expr::deref(addr2, 8);

        let formatted2 = emitter.format_expr_with_strings(&deref2, &table);
        assert!(
            !formatted2.contains("unresolved_pc_relative"),
            "Should not contain unresolved_pc_relative for eip: {}",
            formatted2
        );
        assert_eq!(
            formatted2, "*(uint64_t*)(&g_1000)",
            "Should format as *(typeN*)(&g_<hex_offset>) for eip"
        );
    }

    #[test]
    fn test_rip_relative_deref_in_compound_assignment() {
        use super::super::expression::{VarKind, Variable};

        // Test that compound assignment like `*(uint32_t*)(rip + 6842) |= 1`
        // correctly resolves to `*(uint32_t*)(&g_1aba) |= 1` instead of
        // `*(uint32_t*)(/* unresolved_pc_relative */ + 6842) |= 1`
        let emitter = PseudoCodeEmitter::new("    ", false);
        let table = StringTable::new();

        // Create a Deref expression with rip + 6842 as the address
        let rip_var = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "rip".to_string(),
            size: 8,
        });
        let offset = Expr::int(6842);
        let addr = Expr::binop(BinOpKind::Add, rip_var.clone(), offset);
        let deref = Expr::deref(addr.clone(), 4);

        // Create x = x | 1 pattern which becomes x |= 1 compound assignment
        let rhs_binop = Expr::binop(BinOpKind::Or, deref.clone(), Expr::int(1));
        let assign = Expr::assign(deref, rhs_binop);

        let formatted = emitter.format_expr_with_strings(&assign, &table);

        // Should resolve to `*(uint32_t*)(&g_1aba) |= 1` instead of containing "unresolved_pc_relative"
        assert!(
            !formatted.contains("unresolved_pc_relative"),
            "Should not contain unresolved_pc_relative in compound assignment: {}",
            formatted
        );
        assert!(
            formatted.contains("g_1aba"),
            "Should contain resolved global name g_1aba: {}",
            formatted
        );
        assert!(
            formatted.contains("|= 1"),
            "Should contain compound assignment operator: {}",
            formatted
        );
    }

    #[test]
    fn test_semantic_variable_naming_var_parsing() {
        // This tests the variable name parsing in try_get_semantic_var_name
        // The actual semantic naming is tested in naming.rs tests

        let emitter = PseudoCodeEmitter::new("    ", false);

        // Test var_ prefix parsing (var_8 -> offset 0x8 = 8)
        // Note: Without patterns detected, this will return None because
        // NamingContext will return a default name like var_8
        let result = emitter.try_get_semantic_var_name("var_8");
        // Should return None because no patterns detected yet
        assert!(
            result.is_none(),
            "var_8 without detected pattern should return None"
        );

        // Test local_ prefix parsing (local_10 -> offset -0x10 = -16)
        let result = emitter.try_get_semantic_var_name("local_10");
        assert!(
            result.is_none(),
            "local_10 without detected pattern should return None"
        );

        // Test arg_ prefix parsing (arg_8 -> offset 0x8 = 8, is_param=true)
        let result = emitter.try_get_semantic_var_name("arg_8");
        assert!(
            result.is_none(),
            "arg_8 without detected pattern should return None"
        );

        // Test that non-var names return None
        let result = emitter.try_get_semantic_var_name("foo");
        assert!(result.is_none(), "Non-var names should return None");

        // Test that invalid hex returns None
        let result = emitter.try_get_semantic_var_name("var_xyz");
        assert!(result.is_none(), "Invalid hex suffix should return None");

        // Test that empty suffix returns None
        let result = emitter.try_get_semantic_var_name("var_");
        assert!(result.is_none(), "Empty suffix should return None");
    }

    #[test]
    fn test_emit_skips_gcov_counter_increment_noise() {
        let mut sym = SymbolTable::new();
        sym.insert_with_size(0x4062e0, "__gcov0.classify".to_string(), 40);

        let exact = Expr::got_ref(0x4062e0, 0, 8, Expr::unknown("rip_ref"));
        let interior = Expr::got_ref(0x4062f8, 0, 8, Expr::unknown("rip_ref"));

        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Expr(Expr::assign(
                    Expr::unknown("ret"),
                    Expr::binop(BinOpKind::Add, exact.clone(), Expr::int(1)),
                )),
                StructuredNode::Expr(Expr::assign(
                    exact.clone(),
                    Expr::binop(BinOpKind::Add, exact, Expr::int(1)),
                )),
                StructuredNode::Expr(Expr::assign(
                    interior.clone(),
                    Expr::binop(BinOpKind::Add, interior, Expr::int(1)),
                )),
                StructuredNode::Expr(Expr::assign(Expr::unknown("result"), Expr::int(42))),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let output = emitter.emit(&cfg, "test");

        assert!(
            output.contains("result = 42;"),
            "expected live code, got:\n{output}"
        );
        assert!(
            !output.contains("__gcov0.classify"),
            "did not expect exact gcov symbol noise:\n{output}"
        );
        assert!(
            !output.contains("g_ptr_4062f8"),
            "did not expect interior gcov counter noise:\n{output}"
        );
        assert!(
            !output.contains("ret ="),
            "did not expect gcov temp readback to survive:\n{output}"
        );
    }

    #[test]
    fn test_emit_register_snapshot_store_preserves_raw_register_names() {
        use super::super::expression::Variable;

        let env = Expr::var(Variable::reg("rdi", 8));
        let rax = Expr::var(Variable::reg("rax", 8));
        let rbx = Expr::var(Variable::reg("rbx", 8));
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let r12 = Expr::var(Variable::reg("r12", 8));

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Block {
                id: hexray_core::BasicBlockId::new(0),
                statements: vec![
                    Expr::assign(Expr::deref(env.clone(), 8), rbx),
                    Expr::assign(
                        rax.clone(),
                        Expr::binop(BinOpKind::Xor, rbp, Expr::int(0x30)),
                    ),
                    Expr::assign(
                        Expr {
                            kind: ExprKind::ArrayAccess {
                                base: Box::new(env.clone()),
                                index: Box::new(Expr::int(1)),
                                element_size: 8,
                            },
                        },
                        rax,
                    ),
                    Expr::assign(
                        Expr {
                            kind: ExprKind::ArrayAccess {
                                base: Box::new(env),
                                index: Box::new(Expr::int(2)),
                                element_size: 8,
                            },
                        },
                        r12,
                    ),
                ],
                address_range: (0x1000, 0x1010),
            }],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::default();
        sig.parameters.push(super::super::signature::Parameter::new(
            "env",
            super::super::signature::ParamType::Pointer,
            super::super::signature::ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));

        let output =
            PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "snapshot", &sig);

        assert!(
            output.contains("*(uint64_t*)(env) = rbx;"),
            "expected raw rbx store, got:\n{output}"
        );
        assert!(
            output.contains("rbp ^ 48"),
            "expected raw register setup, got:\n{output}"
        );
        assert!(
            output.contains("env[1] = rax;") && output.contains("env[2] = r12;"),
            "expected raw register saves in buffer stores, got:\n{output}"
        );
        assert!(
            !output.contains("err") && !output.contains("result") && !output.contains("ret ="),
            "did not expect semantic pseudo-locals in snapshot helper, got:\n{output}"
        );
    }

    #[test]
    fn test_emit_plt_stub_as_got_trampoline() {
        let mut relocations = RelocationTable::new();
        relocations.insert_got(0x404000, "public_add".to_string());

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::IndirectGot {
                    got_address: 0x404000,
                    expr: Box::new(Expr::unknown("jmp *[rip+0x2f76]")),
                },
                vec![],
            )))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let output = PseudoCodeEmitter::new("    ", false)
            .with_relocation_table(Some(relocations))
            .emit(&cfg, "public_add@plt");

        assert!(
            output.contains("return (*public_add@got)();"),
            "expected GOT trampoline rendering, got:\n{output}"
        );
        assert!(
            !output.contains("return public_add();"),
            "PLT trampoline should not collapse into a recursive self-call:\n{output}"
        );
    }

    #[test]
    fn test_emit_plt_stub_strips_unambiguous_glibc_version_suffix_from_got_target() {
        let mut relocations = RelocationTable::new();
        relocations.insert_got(0x404000, "puts@GLIBC_2.2.5".to_string());

        let cfg = StructuredCfg {
            body: vec![StructuredNode::Return(Some(Expr::call(
                CallTarget::IndirectGot {
                    got_address: 0x404000,
                    expr: Box::new(Expr::unknown("jmp *[rip+0x2f76]")),
                },
                vec![],
            )))],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let output = PseudoCodeEmitter::new("    ", false)
            .with_relocation_table(Some(relocations))
            .emit(&cfg, "puts@plt");

        assert!(
            output.contains("return (*puts@got)();"),
            "expected versionless GOT trampoline rendering, got:\n{output}"
        );
    }

    #[test]
    fn test_format_expr_uses_float_argument_names_for_xmm_registers() {
        use super::super::expression::Variable;

        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_calling_convention(CallingConvention::SystemV);
        let expr = Expr::var(Variable::reg("xmm0", 16));

        assert_eq!(emitter.format_expr(&expr), "farg0");
    }

    #[test]
    fn test_emit_with_signature_breaks_block_param_restore_cycles() {
        use super::super::expression::Variable;

        let tmp = Expr::var(Variable::reg("tmp", 8));
        let arg0 = Expr::var(Variable::reg("arg0", 8));
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Block {
                    id: hexray_core::BasicBlockId::new(0),
                    statements: vec![
                        Expr::assign(tmp.clone(), arg0.clone()),
                        Expr::assign(arg0.clone(), tmp),
                    ],
                    address_range: (0x1000, 0x1008),
                },
                StructuredNode::Return(Some(arg0)),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::default();
        sig.parameters
            .push(super::super::signature::Parameter::from_int_register(
                0,
                "rdi",
                super::super::signature::ParamType::SignedInt(64),
            ));
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(64);

        let output = PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "cycle", &sig);

        assert!(
            output.contains("return arg0;"),
            "expected emitter to finish block-cycle restoration cleanup, got:\n{output}"
        );
    }

    #[test]
    fn test_emit_with_signature_breaks_node_param_restore_cycles() {
        use super::super::expression::Variable;

        let tmp = Expr::var(Variable::reg("tmp", 8));
        let arg0 = Expr::var(Variable::reg("arg0", 8));
        let cfg = StructuredCfg {
            body: vec![
                StructuredNode::Expr(Expr::assign(tmp.clone(), arg0.clone())),
                StructuredNode::Expr(Expr::assign(arg0.clone(), tmp)),
                StructuredNode::Return(Some(arg0)),
            ],
            cfg_entry: hexray_core::BasicBlockId::new(0),
        };

        let mut sig = super::super::signature::FunctionSignature::default();
        sig.parameters
            .push(super::super::signature::Parameter::from_int_register(
                0,
                "rdi",
                super::super::signature::ParamType::SignedInt(64),
            ));
        sig.has_return = true;
        sig.return_type = super::super::signature::ParamType::SignedInt(64);

        let output =
            PseudoCodeEmitter::new("    ", false).emit_with_signature(&cfg, "cycle_nodes", &sig);

        assert!(
            output.contains("return arg0;"),
            "expected emitter to finish node-cycle restoration cleanup, got:\n{output}"
        );
    }

    #[test]
    fn field_access_uses_dot_flips_to_arrow_through_pointer_field() {
        // Two-level chain `s.p->id` where `s: struct foo` is a value and
        // `p: struct bar *` is a pointer field. The old root-only walk
        // would have rendered `s.p.id`; the per-level walk must resolve
        // `p`'s field type, see it's a pointer, and answer `false`
        // (use `->`) for the outer `id` access.
        use hexray_types::{CType, StructType};

        let mut bar = StructType::new(Some("bar".to_string()));
        bar.add_field("id".to_string(), CType::int());
        bar.finalize();

        let mut foo = StructType::new(Some("foo".to_string()));
        foo.add_field(
            "p".to_string(),
            CType::ptr(CType::Named("struct bar".to_string())),
        );
        foo.finalize();

        let mut db = TypeDatabase::new();
        db.add_type("struct bar", CType::Struct(bar));
        db.add_type("struct foo", CType::Struct(foo));

        let mut type_info = HashMap::new();
        type_info.insert("s".to_string(), "struct foo".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false)
            .with_type_info(type_info)
            .with_type_database(Arc::new(db));

        // Outer field `id`: base is `s.p` (a struct-bar pointer) → `->`.
        let s_dot_p = Expr::field_access(
            Expr::var(super::super::expression::Variable::reg("s", 8)),
            "p".to_string(),
            0,
        );
        assert!(
            !emitter.field_access_uses_dot(&s_dot_p),
            "outer access through pointer field must render as '->', got '.'"
        );

        // Sanity: the inner `s.p` access (`s` is a struct value) must stay `.`.
        let bare_s = Expr::var(super::super::expression::Variable::reg("s", 8));
        assert!(
            emitter.field_access_uses_dot(&bare_s),
            "single-level access into a struct value must render as '.'"
        );
    }

    #[test]
    fn field_access_uses_dot_resolves_via_builtin_db_without_user_database() {
        // A stack-struct binding inserts `("epoll_event_14", "struct
        // epoll_event")` into type_info. The emitter has no user-supplied
        // type DB, so it must fall through to the posix/linux/libc builtin
        // DB to know that struct epoll_event exists and that `.events` is
        // a `uint` (not a pointer), so the outer FieldAccess renders with
        // `.`. Regression guard against silently breaking the
        // stack-struct rendering path when no DB is wired.
        let mut type_info = HashMap::new();
        type_info.insert(
            "epoll_event_14".to_string(),
            "struct epoll_event".to_string(),
        );

        let emitter = PseudoCodeEmitter::new("    ", false).with_type_info(type_info);
        let base = Expr::var(super::super::expression::Variable::reg(
            "epoll_event_14",
            12,
        ));
        assert!(
            emitter.field_access_uses_dot(&base),
            "stack-bound struct local must render with '.' even without a user TypeDatabase"
        );
    }

    #[test]
    fn format_call_target_name_demangles_mangled_input() {
        // Relocation tables in object files store the raw Itanium-ABI
        // string. Before the demangle wire-up, call sites surfaced as
        // `_ZNRSt8optionalIiEdeEv(...)` instead of the source-readable
        // `std::optional<int>::operator*(...)`. Regression guard for the
        // C++ optional/variant deferral remediation.
        let emitter = PseudoCodeEmitter::new("    ", false);
        let formatted = emitter.format_call_target_name("_ZNRSt8optionalIiEdeEv");
        assert_eq!(formatted, "std::optional<int>::operator*");
    }

    #[test]
    fn format_call_target_name_strips_method_cvref_qualifiers() {
        // Method demanglings carry trailing `const`, `&`, `&&`,
        // `volatile`, `noexcept` qualifiers; these aren't useful at a
        // call site and would produce `has_value() const(args)` after
        // the trailing-args append. The strip walks combinations in
        // any order.
        let emitter = PseudoCodeEmitter::new("    ", false);
        assert_eq!(
            emitter.format_call_target_name("_ZNKSt8optionalIiE9has_valueEv"),
            "std::optional<int>::has_value"
        );
        assert_eq!(
            PseudoCodeEmitter::strip_method_cvref_qualifiers("foo::bar() const &&"),
            "foo::bar()"
        );
        assert_eq!(
            PseudoCodeEmitter::strip_method_cvref_qualifiers("foo::baz() volatile noexcept &"),
            "foo::baz()"
        );
    }

    #[test]
    fn body_ends_with_throw_marker_treats_recovered_throw_as_terminal() {
        // Codex review on PR #13: the `__cxa_throw` recogniser replaces
        // the three-statement throw triple with a single
        // `Expr::unknown("throw VALUE")`. Without extending the
        // control-flow exit detection, non-void throw-only functions
        // got a synthetic `return 0;` appended after `throw 42;`.
        let emitter = PseudoCodeEmitter::new("    ", false);

        // Both shapes — top-level Expr and inside-a-Block tail — must
        // be recognised; production output puts the marker inside a
        // Block (alongside the function-prologue push/pop/push), so
        // the Block-tail check is what actually fires in real binaries.
        let throw_expr = StructuredNode::Expr(Expr::unknown("throw 42".to_string()));
        assert!(
            emitter.is_control_exit(&throw_expr),
            "top-level `throw 42` Expr must be a control-flow exit"
        );

        let block_with_throw = StructuredNode::Block {
            id: hexray_core::BasicBlockId::new(0),
            statements: vec![
                Expr::call(CallTarget::Named("push".to_string()), vec![]),
                Expr::unknown("throw 42".to_string()),
            ],
            address_range: (0x1000, 0x1010),
        };
        assert!(
            emitter.is_control_exit(&block_with_throw),
            "Block ending in throw marker must be a control-flow exit"
        );

        // Constructor-form throw also recognised.
        let throw_ctor =
            StructuredNode::Expr(Expr::unknown("throw std::runtime_error(\"x\")".to_string()));
        assert!(
            emitter.is_control_exit(&throw_ctor),
            "constructor-form throw must be a control-flow exit"
        );

        // Sanity: identifiers that happen to start with `throw_` must
        // NOT trigger the prefix match.
        let not_throw = StructuredNode::Expr(Expr::unknown("throw_int(x)".to_string()));
        assert!(
            !emitter.is_control_exit(&not_throw),
            "`throw_int(x)` must not be confused with a throw expression"
        );

        // And the cold-clone marker from PR #10 still matches.
        let cold = StructuredNode::Expr(Expr::unknown(
            "throw /* via may_throw(int) [clone .cold]() */".to_string(),
        ));
        assert!(
            emitter.is_control_exit(&cold),
            "cold-clone throw thunk marker must remain a control-flow exit"
        );
    }

    #[test]
    fn format_call_target_name_preserves_operator_call() {
        // Codex review on PR #12: `_ZN3FooclEv` demangles to
        // `Foo::operator()()` — the `()` IS the operator name and must
        // survive the signature strip. The original front-walking
        // stripper truncated at the first top-level `(` and emitted
        // `Foo::operator`, losing the operator identity entirely.
        let emitter = PseudoCodeEmitter::new("    ", false);
        assert_eq!(
            emitter.format_call_target_name("_ZN3FooclEv"),
            "Foo::operator()"
        );
    }

    #[test]
    fn format_call_target_name_strips_ctor_dtor_clone_labels() {
        // Codex review on PR #12: `_ZN3DogC2Ev` demangles to
        // `Dog::Dog() [base]`; the trailing `[base]` label blocks the
        // signature stripper from seeing the embedded `()`, so the
        // emitter ended up appending its own `(args)` and surfacing
        // `Dog::Dog() [base](...)` — invalid-looking pseudo-C.
        let emitter = PseudoCodeEmitter::new("    ", false);
        assert_eq!(emitter.format_call_target_name("_ZN3DogC2Ev"), "Dog::Dog");
        // Cold-clone helper labels behave the same way.
        assert_eq!(
            emitter.format_call_target_name("foo(int) [clone .cold]"),
            "foo"
        );
    }

    #[test]
    fn format_call_target_name_leaves_already_demangled_input_alone() {
        // Non-mangled C-style names must pass through unchanged so we
        // don't accidentally rewrite `printf` or other already-readable
        // call targets.
        let emitter = PseudoCodeEmitter::new("    ", false);
        assert_eq!(emitter.format_call_target_name("printf"), "printf");
        assert_eq!(
            emitter.format_call_target_name("__cxa_throw"),
            "__cxa_throw"
        );
    }
}
