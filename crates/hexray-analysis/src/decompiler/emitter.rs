//! Pseudo-code emitter.
//!
//! Emits readable pseudo-code from structured control flow.

#![allow(dead_code)]

use super::abi::{get_arg_register_index, is_callee_saved_register};
use super::expression::{BinOpKind, CallTarget, Expr, ExprKind};
use super::naming::NamingContext;
use super::signature::{CallingConvention, FunctionSignature, SignatureRecovery};
use super::structurer::{StructuredCfg, StructuredNode};
use super::{RelocationTable, StringTable, SummaryDatabase, SymbolTable};
use hexray_types::{get_argument_category, ConstantCategory, ConstantDatabase, TypeDatabase};
use std::cell::RefCell;
use std::collections::HashSet;
use std::fmt::Write;
use std::sync::Arc;

/// Represents a case value or range for switch statement output.
enum CaseRange {
    /// A single case value.
    Single(i128),
    /// A range of consecutive values (inclusive).
    Range(i128, i128),
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
    /// Statements to skip (block_idx, stmt_idx) - these are parameter assignments.
    skip_statements: HashSet<(usize, usize)>,
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
        addrs.sort_by(|a, b| b.1.cmp(&a.1)); // Sort descending by count
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
    /// Type information for variables (var_name -> type_string).
    type_info: std::collections::HashMap<String, String>,
    /// DWARF variable names (stack_offset -> name).
    dwarf_names: std::collections::HashMap<i128, String>,
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

    /// Creates a new emitter.
    pub fn new(indent: &str, emit_addresses: bool) -> Self {
        Self {
            indent: indent.to_string(),
            emit_addresses,
            string_table: None,
            symbol_table: None,
            relocation_table: None,
            type_info: std::collections::HashMap::new(),
            dwarf_names: std::collections::HashMap::new(),
            naming_ctx: RefCell::new(NamingContext::new()),
            calling_convention: CallingConvention::default(),
            use_signature_recovery: true,
            type_database: None,
            constant_database: None,
            summary_database: None,
            global_tracker: RefCell::new(GlobalAccessTracker::new()),
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
        self
    }

    /// Sets the relocation table for resolving call targets in relocatable files.
    pub fn with_relocation_table(mut self, table: Option<RelocationTable>) -> Self {
        self.relocation_table = table;
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
        self.dwarf_names.get(&offset).map(|s| s.as_str())
    }

    /// Gets the type string for a variable, defaulting to "int".
    fn get_type(&self, var_name: &str) -> &str {
        self.type_info
            .get(var_name)
            .map(|s| s.as_str())
            .unwrap_or("int")
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

    /// Formats a function call argument with context-aware constant recognition.
    ///
    /// Given the function name and argument index, this tries to recognize magic constants
    /// (like TIOCGWINSZ for ioctl, SIGINT for signal, etc.) and replace them with symbolic names.
    fn format_call_arg(
        &self,
        arg: &Expr,
        func_name: &str,
        arg_index: usize,
        table: &StringTable,
    ) -> String {
        // signal/signaction handler argument: resolve raw addresses to function names.
        if matches!(func_name, "signal" | "_signal" | "sigaction") && matches!(arg_index, 1 | 2) {
            if let Some(name) = self.resolve_function_pointer_arg(arg) {
                return name;
            }
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
                        | ConstantCategory::MmapProt
                        | ConstantCategory::MmapFlags
                        | ConstantCategory::PollEvents => {
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
        self.format_expr_with_strings(arg, table)
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

    /// Formats comparison operands, converting integers to character literals when appropriate.
    ///
    /// This detects patterns like `*ptr == 97` (checking for 'a') and formats them as
    /// `*ptr == 'a'` for better readability.
    fn format_char_comparison_operands(
        &self,
        left: &Expr,
        right: &Expr,
        _table: &StringTable,
    ) -> (String, String) {
        // First format both sides normally
        let left_str = self.format_expr_no_string_resolve(left);
        let right_str = self.format_expr_no_string_resolve(right);

        // Check if either side is an integer that should be formatted as a character
        let left_is_char_context = self.is_byte_context(left) || looks_like_char_context(&left_str);
        let right_is_char_context =
            self.is_byte_context(right) || looks_like_char_context(&right_str);

        // Check if either side is a variable (register) that might hold a character
        let left_is_var = matches!(left.kind, ExprKind::Var(_));
        let right_is_var = matches!(right.kind, ExprKind::Var(_));

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
            // Array indexing with implicit 1-byte element
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                // Check for ptr[index] pattern where the final deref would be 1 byte
                // This is heuristic - check if one side looks like a base pointer
                matches!(left.kind, ExprKind::Var(_) | ExprKind::GotRef { .. })
                    || matches!(right.kind, ExprKind::Var(_) | ExprKind::GotRef { .. })
            }
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

    /// Formats an expression without resolving addresses to string literals.
    /// Used for comparisons and other contexts where string resolution doesn't make sense.
    fn format_expr_no_string_resolve(&self, expr: &Expr) -> String {
        let empty = super::StringTable::new();
        self.format_lvalue(expr, &empty)
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
            let name = format!("g_{}", libc_name);
            self.global_tracker
                .borrow_mut()
                .cache_name(address, name.clone());
            return name;
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

    /// Extracts the GotRef address from an expression, if present.
    /// Traverses through Deref and Cast to find the underlying GotRef.
    fn extract_gotref_address(expr: &Expr) -> Option<u64> {
        match &expr.kind {
            ExprKind::GotRef { address, .. } => Some(*address),
            ExprKind::Deref { addr, .. } => Self::extract_gotref_address(addr),
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
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*instruction_address) {
                        self.simplify_libc_global_name(name)
                    } else if let Some(name) = reloc_table.get_got(*address) {
                        self.simplify_libc_global_name(name)
                    } else {
                        None
                    }
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
                            let byte_offset = (*idx as u64) * (*element_size as u64);
                            // Try to find a symbol at this relative offset
                            if let Some(ref sym_table) = self.symbol_table {
                                if let Some(name) = sym_table.get(byte_offset) {
                                    if let Some(alias) = self.simplify_libc_global_name(name) {
                                        return alias.to_string();
                                    }
                                    return name.to_string();
                                }
                            }
                            // Fall back to a generic global name with the offset
                            return format!("_g_{:x}", byte_offset);
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
                // Try to resolve using instruction address first (for relocatable objects)
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*instruction_address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                    if let Some(name) = reloc_table.get_got(*address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                }
                // Try symbol table
                if let Some(ref sym_table) = self.symbol_table {
                    if let Some(name) = sym_table.get(*address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                }
                // Skip string table lookup for lvalues - you can't write to string literals
                // Fall back to context-aware naming (lvalues are pointer derefs)
                // Record as a write access since this is an lvalue
                self.record_global_write(*address);
                if *is_deref {
                    let prefix = match size {
                        1 => "*(uint8_t*)",
                        2 => "*(uint16_t*)",
                        4 => "*(uint32_t*)",
                        8 => "*(uint64_t*)",
                        _ => "*",
                    };
                    let name = self.record_and_name_global_with_size(
                        *address,
                        GlobalUsageHint::PointerDeref,
                        *size,
                    );
                    format!("{}(&{})", prefix, name)
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
                // For comparison operators, don't resolve the operands to strings
                // because comparisons like `ptr == 0` should show the pointer variable,
                // not the string it points to (e.g., "hello" == 0 doesn't make sense)
                if op.is_comparison() {
                    // Check if this looks like a character comparison and format accordingly
                    let (left_str, right_str) =
                        self.format_char_comparison_operands(left, right, table);
                    format!("{} {} {}", left_str, op.as_str(), right_str)
                } else {
                    // Use precedence-aware formatting for arithmetic operations
                    let left_str = self.format_binop_operand(left, *op, false, table);
                    let right_str = self.format_binop_operand(right, *op, true, table);
                    format!("{} {} {}", left_str, op.as_str(), right_str)
                }
            }
            ExprKind::UnaryOp { op, operand } => {
                format!(
                    "{}{}",
                    op.as_str(),
                    self.format_expr_with_strings(operand, table)
                )
            }
            ExprKind::Deref { addr, size } => {
                // Special case: nested dereferences rooted at libc globals.
                if let Some(simplified) = self.try_format_libc_global_deref_chain(addr) {
                    return simplified;
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
                    let base_str = self.format_postfix_base(&base, &empty);
                    let index_str = self.format_expr_no_string_resolve(&index);
                    return format!("{}[{}]", base_str, index_str);
                }
                // Check if this is a RIP/EIP-relative address (global variable reference)
                if let Some(offset) = try_extract_rip_relative_offset(addr) {
                    // Try to find a symbol at this relative offset
                    if let Some(ref sym_table) = self.symbol_table {
                        if let Some(name) = sym_table.get(offset) {
                            if let Some(alias) = self.simplify_libc_global_name(name) {
                                return alias.to_string();
                            }
                            return name.to_string();
                        }
                    }
                    // Fall back to a generic global name with the offset
                    return format!("_g_{:x}", offset);
                }
                // Fall back to default deref formatting
                let prefix = match size {
                    1 => "*(uint8_t*)",
                    2 => "*(uint16_t*)",
                    4 => "*(uint32_t*)",
                    8 => "*(uint64_t*)",
                    _ => "*",
                };
                // Don't resolve strings in deref address - dereferencing a string literal
                // doesn't make sense. Show the pointer/data variable instead.
                let addr_text = self.format_expr_no_string_resolve(addr);
                if let Some(alias) = self.simplify_libc_global_text(&addr_text) {
                    return format!("*{}", alias);
                }
                format!("{}({})", prefix, addr_text)
            }
            ExprKind::Assign { lhs, rhs } => {
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
                        let lhs_str = self.format_lvalue(lhs, table);
                        let rhs_str = self.format_expr_with_strings(right, table);

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
                format!(
                    "{} = {}",
                    // For lhs, don't resolve strings (can't write to string literals)
                    self.format_lvalue(lhs, table),
                    self.format_expr_with_strings(rhs, table)
                )
            }
            ExprKind::GotRef {
                address,
                instruction_address,
                size,
                display_expr: _,
                is_deref,
            } => {
                // Try to resolve using instruction address first (for relocatable objects)
                // This uses the relocation at the instruction to find the symbol
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*instruction_address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                    // Fall back to computed address (for linked binaries)
                    if let Some(name) = reloc_table.get_got(*address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                }
                // Try symbol table
                if let Some(ref sym_table) = self.symbol_table {
                    if let Some(name) = sym_table.get(*address) {
                        if let Some(alias) = self.simplify_libc_global_name(name) {
                            return alias.to_string();
                        }
                        return name.to_string();
                    }
                }
                // Try string table
                if let Some(s) = table.get(*address) {
                    return format!("\"{}\"", escape_string(s));
                }
                // Fall back to showing computed address (better than "rip + offset")
                // Use context-aware naming based on usage pattern with size info
                if *is_deref {
                    let prefix = match size {
                        1 => "*(uint8_t*)",
                        2 => "*(uint16_t*)",
                        4 => "*(uint32_t*)",
                        8 => "*(uint64_t*)",
                        _ => "*",
                    };
                    // Pointer dereference pattern - record size for type inference
                    let name = self.record_and_name_global_with_size(
                        *address,
                        GlobalUsageHint::PointerDeref,
                        *size,
                    );
                    // Record as a read access
                    self.record_global_read(*address);
                    format!("{}(&{})", prefix, name)
                } else {
                    // Address-of (LEA) - use default naming, tracker will categorize later if needed
                    self.record_and_name_global(*address, GlobalUsageHint::Unknown)
                }
            }
            ExprKind::Call { target, args } => {
                let target_str = match target {
                    super::expression::CallTarget::Direct {
                        target: addr,
                        call_site,
                    } => {
                        // First check relocation table (for kernel modules)
                        // This uses the call instruction address to find the target symbol
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get(*call_site) {
                                name.to_string()
                            } else if let Some(ref sym_table) = self.symbol_table {
                                // Fall back to symbol table by target address
                                if let Some(name) = sym_table.get(*addr) {
                                    name.to_string()
                                } else {
                                    format!("sub_{:x}", addr)
                                }
                            } else {
                                format!("sub_{:x}", addr)
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Check symbol table by target address
                            if let Some(name) = sym_table.get(*addr) {
                                name.to_string()
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
                    super::expression::CallTarget::Named(name) => name.clone(),
                    super::expression::CallTarget::Indirect(e) => {
                        // Mark any GotRef in the indirect target as a function pointer
                        self.mark_gotref_as_funcptr(e);
                        format!("({})", self.format_expr_with_strings(e, table))
                    }
                    super::expression::CallTarget::IndirectGot { got_address, expr } => {
                        // Mark this as a function pointer access
                        self.global_tracker
                            .borrow_mut()
                            .record_access(*got_address, GlobalUsageHint::FunctionPointer);
                        // Try to resolve the GOT entry to a symbol name
                        if let Some(ref reloc_table) = self.relocation_table {
                            if let Some(name) = reloc_table.get_got(*got_address) {
                                name.to_string()
                            } else {
                                // Fall back to showing the expression
                                format!("({})", self.format_expr_with_strings(expr, table))
                            }
                        } else if let Some(ref sym_table) = self.symbol_table {
                            // Try symbol table by GOT address (rare, but possible)
                            if let Some(name) = sym_table.get(*got_address) {
                                name.to_string()
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
                        // Try to resolve argument as a magic constant
                        self.format_call_arg(a, &target_str, idx, table)
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
                    // Rename callee-saved registers to meaningful names
                    // These are commonly used to hold return values/error codes
                    normalize_variable_name(&rename_register(&var.name))
                }
            }
            ExprKind::Unknown(name) => normalize_variable_name(name),
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
                let lhs_str = self.format_expr_with_strings(lhs, table);
                let rhs_str = self.format_expr_with_strings(rhs, table);
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
                // Use -> for pointer access when we have real struct field names
                format!("{}->{}", base_str, field_name)
            }
            // Array access: check if this is a stack slot (sp[N] or x29[N])
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                if let ExprKind::IntLit(idx) = &index.kind {
                    if *idx >= 0 {
                        if let ExprKind::Var(base_var) = &base.kind {
                            let is_stack_like = matches!(
                                base_var.name.as_str(),
                                "sp" | "rsp" | "rbp" | "x29" | "rip" | "eip"
                            );
                            if !is_stack_like {
                                let off = (*idx as usize) * *element_size;
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
                            return name;
                        }
                    } else if is_pc_relative {
                        // RIP/EIP-relative array access - this is a global variable reference
                        // Try to resolve using the symbol table if we have a constant index
                        if let ExprKind::IntLit(idx) = &index.kind {
                            let byte_offset = (*idx as u64) * (*element_size as u64);
                            // Try to find a symbol at this relative offset
                            if let Some(ref sym_table) = self.symbol_table {
                                if let Some(name) = sym_table.get(byte_offset) {
                                    if let Some(alias) = self.simplify_libc_global_name(name) {
                                        return alias.to_string();
                                    }
                                    return name.to_string();
                                }
                            }
                            // Fall back to a generic global name with the offset
                            return format!("_g_{:x}", byte_offset);
                        }
                        // Non-constant index - use a generic global array name
                        let index_str = self.format_expr_with_strings(index, table);
                        return format!("_globals[{}]", index_str);
                    }
                }
                // Default array access formatting
                // Use parentheses if base is a binary operation (postfix has highest precedence)
                let base_str = self.format_postfix_base(base, table);
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

        // Analyze function body for pattern-based variable naming (loop indices, etc.)
        self.naming_ctx.borrow_mut().analyze(&cfg.body);

        // Pre-scan for global access patterns before emission
        // This allows us to infer read-only, write-heavy, counter patterns
        self.prescan_global_accesses(&cfg.body);

        // Use advanced signature recovery if enabled
        let (signature, func_info) = if self.use_signature_recovery {
            let mut recovery = SignatureRecovery::new(self.calling_convention)
                .with_relocation_table(self.relocation_table.clone())
                .with_symbol_table(self.symbol_table.clone())
                .with_summary_database(self.summary_database.clone())
                .with_function_name(func_name);
            let sig = recovery.analyze(cfg);

            // Convert recovered signature to FunctionInfo for compatibility
            let params: Vec<String> = sig.parameters.iter().map(|p| p.name.clone()).collect();

            let info = self.analyze_function(&cfg.body);
            let merged_info = FunctionInfo {
                parameters: if params.is_empty() {
                    info.parameters
                } else {
                    params
                },
                has_return_value: sig.has_return || info.has_return_value,
                skip_statements: info.skip_statements,
            };

            (Some(sig), merged_info)
        } else {
            (None, self.analyze_function(&cfg.body))
        };

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

            if sig.parameters.is_empty() && func_info.parameters.is_empty() {
                writeln!(output, "{} {}(void)", return_type, func_name).unwrap();
            } else if !sig.parameters.is_empty() {
                let params: Vec<_> = sig
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let rendered_name = rename_main_param(&p.name, idx);
                        Self::format_signature_param(p, &rendered_name)
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
            } else {
                // Fall back to legacy parameter detection
                let params: Vec<_> = func_info
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let name = rename_main_param(p, idx);
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
            if func_info.parameters.is_empty() {
                writeln!(output, "{} {}()", return_type, func_name).unwrap();
            } else {
                let params: Vec<_> = func_info
                    .parameters
                    .iter()
                    .enumerate()
                    .map(|(idx, p)| {
                        let name = rename_main_param(p, idx);
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

        // Collect all local variables used in the function (excluding parameters)
        let all_vars = self.collect_local_variables(&cfg.body, &func_info.parameters);

        // Emit variable declarations at the top (C89 style)
        if !all_vars.is_empty() {
            let indent = &self.indent;
            for var in &all_vars {
                let var_type = self.get_type(var);
                writeln!(output, "{}{} {};", indent, var_type, var).unwrap();
            }
            writeln!(output).unwrap(); // Blank line after declarations
        }

        // Track declared variables (parameters + locals)
        let mut declared_vars: HashSet<String> = func_info.parameters.iter().cloned().collect();
        declared_vars.extend(all_vars);

        // Emit body, skipping parameter assignment statements
        self.emit_nodes_with_skip_and_decls(
            &cfg.body,
            &mut output,
            1,
            &func_info.skip_statements,
            &mut declared_vars,
        );

        writeln!(output, "}}").unwrap();
        output
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

        // Analyze function body for pattern-based variable naming
        self.naming_ctx.borrow_mut().analyze(&cfg.body);

        // Use provided signature for header
        let return_type = if signature.has_return {
            signature.return_type.to_c_string()
        } else {
            "void".to_string()
        };

        if signature.parameters.is_empty() {
            writeln!(output, "{} {}(void)", return_type, func_name).unwrap();
        } else {
            let params: Vec<_> = signature
                .parameters
                .iter()
                .map(|p| p.param_type.format_with_name(&p.name))
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
        writeln!(output, "{{").unwrap();

        // Legacy analysis for skipping parameter statements
        let func_info = self.analyze_function(&cfg.body);

        // Collect parameter names from signature
        let param_names: Vec<String> = signature
            .parameters
            .iter()
            .map(|p| p.name.clone())
            .collect();

        // Collect all local variables used in the function (excluding parameters)
        let all_vars = self.collect_local_variables(&cfg.body, &param_names);

        // Emit variable declarations at the top (C89 style)
        if !all_vars.is_empty() {
            let indent = &self.indent;
            for var in &all_vars {
                let var_type = self.get_type(var);
                writeln!(output, "{}{} {};", indent, var_type, var).unwrap();
            }
            writeln!(output).unwrap();
        }

        // Track declared variables (parameters + locals)
        let mut declared_vars: HashSet<String> = param_names.into_iter().collect();
        declared_vars.extend(all_vars);

        // Emit body
        self.emit_nodes_with_skip_and_decls(
            &cfg.body,
            &mut output,
            1,
            &func_info.skip_statements,
            &mut declared_vars,
        );

        writeln!(output, "}}").unwrap();
        output
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
            .with_summary_database(self.summary_database.clone());
        if let Some(name) = func_name {
            recovery = recovery.with_function_name(name);
        }
        recovery.analyze(cfg)
    }

    /// Collects all local variables assigned to in the function body.
    fn collect_local_variables(&self, nodes: &[StructuredNode], params: &[String]) -> Vec<String> {
        let mut vars = HashSet::new();
        self.collect_vars_from_nodes(nodes, &mut vars);

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
                    // Skip prologue/epilogue
                    if self.is_prologue_epilogue(stmt) {
                        continue;
                    }
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

    /// Recursively collects all variable names used in an expression.
    /// This includes variables on both LHS and RHS of assignments, in conditions, etc.
    fn collect_vars_from_expr(&self, expr: &Expr, vars: &mut HashSet<String>) {
        match &expr.kind {
            ExprKind::Var(v) => {
                // Collect simple variable references
                if v.name.starts_with("var_")
                    || v.name.starts_with("local_")
                    || v.name.starts_with("arg_")
                {
                    vars.insert(v.name.clone());
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
                self.collect_vars_from_expr(base, vars);
                self.collect_vars_from_expr(index, vars);
            }
            ExprKind::FieldAccess { base, .. } => {
                self.collect_vars_from_expr(base, vars);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.collect_vars_from_expr(arg, vars);
                }
            }
            ExprKind::Assign { lhs, rhs } => {
                // Collect from LHS (for variable declarations)
                if let Some(var_name) = self.try_get_var_name(lhs) {
                    vars.insert(var_name);
                }
                // Also collect variables used in LHS address computation
                self.collect_vars_from_expr(lhs, vars);
                // Collect from RHS
                self.collect_vars_from_expr(rhs, vars);
            }
            ExprKind::CompoundAssign { lhs, rhs, .. } => {
                if let Some(var_name) = self.try_get_var_name(lhs) {
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
            ExprKind::GotRef { display_expr, .. } => {
                self.collect_vars_from_expr(display_expr, vars);
            }
            // Literals don't contain variables
            ExprKind::IntLit(_) | ExprKind::Unknown(_) => {}
        }
    }

    /// Analyzes a function body to detect parameters and return type.
    fn analyze_function(&self, body: &[StructuredNode]) -> FunctionInfo {
        let mut info = FunctionInfo {
            parameters: Vec::new(),
            has_return_value: false,
            skip_statements: HashSet::new(),
        };

        // Check first block for parameter patterns and prologue
        if let Some(StructuredNode::Block { statements, .. }) = body.first() {
            for (idx, stmt) in statements.iter().enumerate() {
                // Parameter setup should happen before any real call in prologue.
                // If we already reached a call, stop scanning to avoid treating
                // post-call return-register uses as function parameters.
                if let ExprKind::Call { .. } = &stmt.kind {
                    break;
                }

                // Skip prologue statements
                if is_prologue_statement(stmt) {
                    info.skip_statements.insert((0, idx));
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
                                    info.skip_statements.insert((0, idx));
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

        // Check last block for epilogue
        for (block_idx, node) in body.iter().enumerate() {
            if let StructuredNode::Block { statements, .. } = node {
                for (idx, stmt) in statements.iter().enumerate() {
                    if is_epilogue_statement(stmt) {
                        info.skip_statements.insert((block_idx, idx));
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
        skip: &HashSet<(usize, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        self.emit_nodes_with_skip_and_decls_inner(nodes, output, depth, skip, declared_vars, true)
    }

    fn emit_nodes_with_skip_and_decls_inner(
        &self,
        nodes: &[StructuredNode],
        output: &mut String,
        depth: usize,
        skip: &HashSet<(usize, usize)>,
        declared_vars: &mut HashSet<String>,
        is_top_level: bool,
    ) {
        for (block_idx, node) in nodes.iter().enumerate() {
            self.emit_node_with_skip_and_decls(node, output, depth, block_idx, skip, declared_vars);
            // At top level, don't break on control exits - labeled sections after gotos
            // are reachable. Only break within nested structures (if/while bodies).
            if !is_top_level && self.is_control_exit(node) {
                break;
            }
        }
    }

    fn emit_node_with_skip_and_decls(
        &self,
        node: &StructuredNode,
        output: &mut String,
        depth: usize,
        block_idx: usize,
        skip: &HashSet<(usize, usize)>,
        declared_vars: &mut HashSet<String>,
    ) {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => {
                // Filter out skipped statements
                let filtered: Vec<_> = statements
                    .iter()
                    .enumerate()
                    .filter(|(stmt_idx, _)| !skip.contains(&(block_idx, *stmt_idx)))
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
                if is_stack_canary_check_body(then_body, self.symbol_table.as_ref()) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if is_stack_canary_check_body(else_nodes, self.symbol_table.as_ref()) {
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().map_or(true, |e| self.is_body_empty(e));

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
                    self.format_expr(&actual_cond)
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
                let indent = self.indent.repeat(depth);
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_expr(condition)
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
                    self.format_expr(condition)
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
                if is_stack_canary_check_body(then_body, self.symbol_table.as_ref()) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if is_stack_canary_check_body(else_nodes, self.symbol_table.as_ref()) {
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().map_or(true, |e| self.is_body_empty(e));

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
                    self.format_expr(&actual_cond)
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
                let indent = self.indent.repeat(depth);
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_expr(condition)
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
                    self.format_expr(condition)
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
                        name.to_string()
                    } else if let Some(ref sym_table) = self.symbol_table {
                        sym_table
                            .get(*addr)
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("sub_{:x}", addr))
                    } else {
                        format!("sub_{:x}", addr)
                    }
                } else if let Some(ref sym_table) = self.symbol_table {
                    sym_table
                        .get(*addr)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| format!("sub_{:x}", addr))
                } else {
                    format!("sub_{:x}", addr)
                }
            }
            super::expression::CallTarget::Named(name) => name.clone(),
            super::expression::CallTarget::Indirect(e) => format!("({})", self.format_expr(e)),
            super::expression::CallTarget::IndirectGot { got_address, expr } => {
                if let Some(ref reloc_table) = self.relocation_table {
                    if let Some(name) = reloc_table.get_got(*got_address) {
                        name.to_string()
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
        let expr_str = self.format_expr(expr);

        if expr_str.is_empty() || expr_str == "/* nop */" {
            return;
        }

        if expr_str == "return" {
            writeln!(output, "{}return;", indent).unwrap();
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
                if is_stack_canary_check_body(then_body, self.symbol_table.as_ref()) {
                    return;
                }

                // Emit as "} else if (cond) {" on one line
                writeln!(
                    output,
                    "{}}} else if ({}) {{",
                    indent,
                    self.format_expr(condition)
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
                if is_stack_canary_check_body(then_body, self.symbol_table.as_ref()) {
                    return;
                }

                // Emit as "} else if (cond) {" on one line
                writeln!(
                    output,
                    "{}}} else if ({}) {{",
                    indent,
                    self.format_expr(condition)
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
    }

    /// Checks if a node is a control flow exit (goto, return, break, continue, noreturn call).
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
                let then_exits = then_body.last().is_some_and(|n| self.is_control_exit(n));
                let else_exits = else_body
                    .as_ref()
                    .and_then(|e| e.last())
                    .is_some_and(|n| self.is_control_exit(n));
                then_exits && else_exits
            }
            // Check for noreturn function calls
            StructuredNode::Expr(expr) => Self::is_noreturn_call(expr),
            StructuredNode::Block { statements, .. } => {
                statements.last().is_some_and(Self::is_noreturn_call)
            }
            _ => false,
        }
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
        // Strip leading underscore(s) for Mach-O symbols
        let name = name.trim_start_matches('_');
        matches!(
            name,
            "exit"
                | "_exit"
                | "_Exit"
                | "abort"
                | "__assert_fail"
                | "__assert_rtn"
                | "__assert"
                | "panic"
                | "longjmp"
                | "siglongjmp"
                | "__cxa_throw"
                | "__cxa_rethrow"
                | "err"
                | "errx"
                | "verr"
                | "verrx"
                | "pthread_exit"
                | "thrd_exit"
                | "quick_exit"
        )
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
            _ => false,
        })
    }

    /// Checks if a statement would be skipped during emission (prologue/epilogue/etc).
    fn is_skippable_statement(&self, expr: &Expr) -> bool {
        use super::expression::ExprKind;

        match &expr.kind {
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
                if let ExprKind::Var(v) = &lhs.kind {
                    // Return register assignments at end of block are skipped
                    if matches!(v.name.as_str(), "eax" | "rax" | "x0" | "w0" | "a0") {
                        return true;
                    }
                }
                // ARM64 argument setup: *(uint64_t*)(x9) = x8 or similar
                // Store through temporary registers (x8-x17) to stack
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    if is_arm64_temp_register_expr(addr) {
                        // Store through temp register (likely argument setup)
                        return true;
                    }
                }
                // ARM64: var = w9 or similar (sign extension artifact)
                if let ExprKind::Var(rhs_var) = &rhs.kind {
                    if is_arm64_temp_register(&rhs_var.name) {
                        return true;
                    }
                }
                // Stack canary load: var = *(*(GOT_address))
                if is_stack_canary_load(expr) {
                    return true;
                }
                false
            }
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
                    // Debug: show which range we're searching
                    if address_range.0 >= 0x98ce0 && address_range.0 < 0x99000 {
                        eprintln!(
                            "DEBUG EMITTER: searching {} [{:#x}..{:#x}]",
                            id, address_range.0, address_range.1
                        );
                    }
                    let relocs = reloc_table.get_data_in_range(address_range.0, address_range.1);
                    if !relocs.is_empty() {
                        eprintln!(
                            "DEBUG EMITTER: {} [{:#x}..{:#x}] found {} data relocs: {:?}",
                            id,
                            address_range.0,
                            address_range.1,
                            relocs.len(),
                            relocs
                                .iter()
                                .map(|(a, s)| format!("{:#x}={}", a, s))
                                .collect::<Vec<_>>()
                        );
                    }
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
                if is_stack_canary_check_body(then_body, self.symbol_table.as_ref()) {
                    return;
                }
                if let Some(else_nodes) = else_body {
                    if is_stack_canary_check_body(else_nodes, self.symbol_table.as_ref()) {
                        return;
                    }
                }

                let then_empty = self.is_body_empty(then_body);
                let else_empty = else_body.as_ref().map_or(true, |e| self.is_body_empty(e));

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
                    self.format_expr(&actual_cond)
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
                writeln!(
                    output,
                    "{}while ({}) {{",
                    indent,
                    self.format_expr(condition)
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
                    self.format_expr(condition)
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
                    self.format_expr(condition),
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
                if let Some(e) = expr {
                    writeln!(output, "{}return {};", indent, self.format_expr(e)).unwrap();
                } else {
                    writeln!(output, "{}return;", indent).unwrap();
                }
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
        let expr_str = self.format_expr(expr);

        // Skip empty/nop statements
        if expr_str.is_empty() || expr_str == "/* nop */" {
            return;
        }

        // Check if it's a return
        if expr_str == "return" {
            writeln!(output, "{}return;", indent).unwrap();
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
    /// Uses DWARF names when available.
    fn try_get_var_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(v) => {
                if v.name.starts_with("var_")
                    || v.name.starts_with("arg_")
                    || v.name.starts_with("local_")
                {
                    Some(v.name.clone())
                } else {
                    None
                }
            }
            ExprKind::Deref { addr, size } => self.try_format_stack_slot(addr, *size),
            _ => None,
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
                    return Some(name.to_string());
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
                            return Some(name.to_string());
                        }

                        // Use NamingContext for pattern-based naming (loop indices, type hints, etc.)
                        // This will return names like 'i', 'j', 'k' for loop counters
                        let is_param = is_frame_pointer && actual_offset > 0;
                        let name = self
                            .naming_ctx
                            .borrow_mut()
                            .get_name(actual_offset, is_param);
                        return Some(name);
                    }
                }
            }
        }
        None
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

/// Formats an integer for C output.
/// Uses decimal for "normal" values and hex for large addresses.
fn recognize_magic_constant(value: i128) -> Option<&'static str> {
    let n = value as u64;
    match n {
        0xDEADBEEFDEADBEEF => Some("DEADBEEF_DEADBEEF"),
        0xdead000000000000 => Some("POISON_POINTER_DELTA"),
        0xDEADBEEF => Some("DEADBEEF"),
        0xFEEDFACE => Some("FEEDFACE"),
        0xCAFEBABE => Some("CAFEBABE"),
        0xDEADC0DE => Some("DEADC0DE"),
        0xBADC0DE => Some("BADC0DE"),
        0xCCCCCCCC => Some("CCCCCCCC"),
        0xCDCDCDCD => Some("CDCDCDCD"),
        0x00100100 => Some("LIST_POISON1"),
        0x00200200 => Some("LIST_POISON2"),
        _ => {
            if value < 0 {
                let abs_val = (-value) as u64;
                match abs_val {
                    0xDEADBEEF => Some("DEADBEEF"),
                    0xFEEDFACE => Some("FEEDFACE"),
                    0xCAFEBABE => Some("CAFEBABE"),
                    0xDEADC0DE => Some("DEADC0DE"),
                    0xBADC0DE => Some("BADC0DE"),
                    0xCCCCCCCC => Some("CCCCCCCC"),
                    0xCDCDCDCD => Some("CDCDCDCD"),
                    _ => None,
                }
            } else {
                None
            }
        }
    }
}

fn format_integer(n: i128) -> String {
    if let Some(constant_name) = recognize_magic_constant(n) {
        return constant_name.to_string();
    }

    if n < 0 {
        // Negative numbers in decimal
        format!("{}", n)
    } else if n <= 255 {
        // Small values in decimal
        format!("{}", n)
    } else if n <= 0xFFFF && !looks_like_address(n) {
        // Medium values in decimal if they don't look like addresses
        format!("{}", n)
    } else {
        // Large values (likely addresses) in hex
        format!("{:#x}", n)
    }
}

/// Heuristic: does this value look like a memory address?
fn looks_like_address(n: i128) -> bool {
    // Common address ranges for x86-64
    let n = n as u64;
    // Stack addresses (high memory)
    if n >= 0x7FFF_0000_0000 {
        return true;
    }
    // Code/data addresses (typically 0x400000+ for ELF, 0x100000000+ for Mach-O)
    if n >= 0x400000 && (n & 0xFFF) == 0 {
        return true; // Page-aligned addresses
    }
    false
}

/// Escapes a string for C output.
fn escape_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            c if c.is_ascii_control() => {
                result.push_str(&format!("\\x{:02x}", c as u8));
            }
            c => result.push(c),
        }
    }
    result
}

/// Checks if a formatted expression string suggests a byte/character context.
///
/// This looks for patterns like:
/// - Array subscript: `x[0]`, `ptr[i]`
/// - 8-bit dereference: `*(uint8_t*)`
/// - Char pointer dereference: `*str`
fn looks_like_char_context(s: &str) -> bool {
    // Array subscript pattern - often used for string/byte access
    // e.g., "str[0]", "buf[i]", "rbp[-0x7][1]"
    if s.ends_with(']') && s.contains('[') {
        return true;
    }
    // Explicit 8-bit dereference
    if s.contains("uint8_t") || s.contains("int8_t") || s.contains("char") {
        return true;
    }
    false
}

/// Checks if a value is likely a character value worth displaying as a char literal.
///
/// This includes:
/// - Printable ASCII characters (32-126)
/// - Common special characters (null, tab, newline, carriage return)
fn is_printable_char_value(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    let n = n as u8;
    // Printable ASCII range only (not special characters like 0, 9, 10, 13)
    // Those special characters should only be shown as char literals in byte contexts
    (32..=126).contains(&n)
}

/// Checks if a value is a special character (null, tab, newline, CR).
/// These should only be shown as character literals in explicit byte contexts.
fn is_special_char_value(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    matches!(n as u8, 0 | 9 | 10 | 13)
}

/// Checks if a value is very likely to be a character constant.
/// These are values that almost certainly represent characters in comparisons,
/// specifically punctuation/escape characters that would be meaningless as numbers.
///
/// Note: We explicitly EXCLUDE letters (A-Z, a-z) and digits ('0'-'9') from this
/// function because values like 90 ('Z'), 80 ('P'), 70 ('F'), 60 are commonly used
/// as numeric thresholds (grades, percentages, etc.). These should only be shown
/// as char literals when there's explicit byte context (int8_t, char*, derefs, etc.).
///
/// We also exclude 0 (null) because 0 is commonly used as a regular integer
/// (false, count, etc.). Null comparisons like `str[i] == 0` are handled by the
/// byte-context detection instead.
///
/// We intentionally exclude less-common control characters (7=\a, 8=\b, 11=\v, 12=\f)
/// because comparisons like `x > 8` are often numeric bounds checks, not character
/// comparisons. Those are still formatted as escape sequences in byte contexts.
fn is_likely_character_constant(n: i128) -> bool {
    if !(0..=127).contains(&n) {
        return false;
    }
    let c = n as u8;
    // Only punctuation/escape characters that would be meaningless as raw numbers
    matches!(
        c,
        b'\\'  // Backslash - 92
            | b'\''  // Single quote - 39
            | b'"' // Double quote - 34
    )
}

/// Formats an integer as a C character literal.
fn format_as_char_literal(n: i128) -> String {
    if !(0..=127).contains(&n) {
        return format!("{}", n);
    }
    let c = n as u8;
    match c {
        0 => "'\\0'".to_string(),
        7 => "'\\a'".to_string(),  // Bell
        8 => "'\\b'".to_string(),  // Backspace
        9 => "'\\t'".to_string(),  // Tab
        10 => "'\\n'".to_string(), // Newline
        11 => "'\\v'".to_string(), // Vertical tab
        12 => "'\\f'".to_string(), // Form feed
        13 => "'\\r'".to_string(), // Carriage return
        b'\\' => "'\\\\'".to_string(),
        b'\'' => "'\\''".to_string(),
        32..=126 => format!("'{}'", c as char),
        _ => format!("{}", n),
    }
}

/// Helper to format a condition nicely.
pub fn format_condition(cond: &Expr) -> String {
    cond.to_string()
}

/// Extracts the stack variable name from an expression.
/// Handles both Var("var_4") and Deref patterns like [rbp - 0x4] → "var_4".
fn get_stack_var_name(expr: &Expr) -> Option<String> {
    use super::expression::BinOpKind;

    match &expr.kind {
        ExprKind::Var(v) => {
            if v.name.starts_with("var_")
                || v.name.starts_with("arg_")
                || v.name.starts_with("local_")
            {
                Some(v.name.clone())
            } else {
                None
            }
        }
        ExprKind::Deref { addr, .. } => {
            // Check for base-only pattern (offset 0): just "sp" or "rsp"
            if let ExprKind::Var(base) = &addr.kind {
                if base.name == "sp" || base.name == "rsp" {
                    return Some("var_0".to_string());
                }
            }

            // Check for base + offset pattern
            if let ExprKind::BinOp { op, left, right } = &addr.kind {
                if let ExprKind::Var(base) = &left.kind {
                    // Frame pointers: rbp (x86-64), x29 (ARM64)
                    let is_frame_pointer = base.name == "rbp" || base.name == "x29";
                    // Stack pointer: sp (ARM64), rsp (x86-64)
                    let is_stack_pointer = base.name == "sp" || base.name == "rsp";

                    if is_frame_pointer || is_stack_pointer {
                        if let ExprKind::IntLit(offset) = &right.kind {
                            let actual_offset = match op {
                                BinOpKind::Add => *offset,
                                BinOpKind::Sub => -*offset,
                                _ => return None,
                            };

                            if is_frame_pointer {
                                // Frame pointer: locals at negative offsets, args at positive
                                if actual_offset < 0 {
                                    return Some(format!("local_{:x}", -actual_offset));
                                } else if actual_offset > 0 {
                                    return Some(format!("arg_{:x}", actual_offset));
                                }
                            } else {
                                // Stack pointer: locals at positive offsets
                                if actual_offset >= 0 {
                                    return Some(format!("var_{:x}", actual_offset));
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}

/// Checks if a statement is a prologue pattern (push rbp, rbp = rsp, sp = sp - N, etc.)
fn is_prologue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // push(rbp) - x86-64 prologue
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "push" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: stp (store pair) for x29, x30
                if name == "stp" {
                    return true;
                }
            }
            false
        }
        // Frame setup patterns for x86-64 and ARM64
        ExprKind::Assign { lhs, rhs } => {
            // ARM64: stur wzr, [x29 - N] - implicit return value initialization
            // This stores 0 (zero register) to a frame-relative location
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
                                // Negative offset (frame-relative local) assigned 0 or zero register
                                if *offset < 0 {
                                    // Check for IntLit(0) or zero register (wzr/xzr)
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

            // ARM64: x29[-N] = 0 (ArrayAccess form of frame-relative zero initialization)
            if let ExprKind::ArrayAccess {
                base,
                index,
                element_size: _,
            } = &lhs.kind
            {
                if let ExprKind::Var(base_var) = &base.kind {
                    if base_var.name == "x29" || base_var.name == "rbp" {
                        if let ExprKind::IntLit(idx) = &index.kind {
                            // Negative index (or negative offset)
                            if *idx < 0 {
                                // Check for IntLit(0) or zero register
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

            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rbp = rsp (frame pointer setup)
                if lhs_var.name == "rbp" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        return rhs_var.name == "rsp";
                    }
                }
                // x86-64: rsp = rsp - N (stack allocation)
                // ARM64: sp = sp - N or sp = N (stack allocation)
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // sp = 0 or sp = constant (ARM64 sub sp, sp, #N becomes sp = 0 after structuring)
                    if let ExprKind::IntLit(_) = &rhs.kind {
                        return true;
                    }
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = sp + N (frame pointer setup)
                if lhs_var.name == "x29" {
                    return true;
                }
                // ARM64: x30 = x29 (link register save pattern)
                if lhs_var.name == "x30" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x29" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        // Compound assignment: rsp -= N or sp -= N (stack allocation)
        ExprKind::CompoundAssign { op, lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // rsp -= N (stack allocation)
                    if matches!(op, super::expression::BinOpKind::Sub)
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

/// Checks if a statement is an epilogue pattern (pop rbp, rsp = rsp + N, ldp, etc.)
fn is_epilogue_statement(expr: &Expr) -> bool {
    match &expr.kind {
        // pop(rbp) - x86-64 epilogue
        // ldp - ARM64 epilogue (load pair, restores x29/x30)
        ExprKind::Call { target, args } => {
            if let CallTarget::Named(name) = target {
                if name == "pop" {
                    if let Some(arg) = args.first() {
                        if let ExprKind::Var(v) = &arg.kind {
                            return v.name == "rbp";
                        }
                    }
                }
                // ARM64: ldp (load pair) for x29, x30
                if name == "ldp" {
                    return true;
                }
            }
            false
        }
        // Stack deallocation patterns
        ExprKind::Assign { lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                // x86-64: rsp = rsp + N
                // ARM64: sp = sp + N
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    if let ExprKind::BinOp { left, .. } = &rhs.kind {
                        if let ExprKind::Var(inner_var) = &left.kind {
                            if inner_var.name == "rsp" || inner_var.name == "sp" {
                                return true;
                            }
                        }
                    }
                }
                // ARM64: x29 = x30 (restore frame pointer from link register)
                if lhs_var.name == "x29" {
                    if let ExprKind::Var(rhs_var) = &rhs.kind {
                        if rhs_var.name == "x30" {
                            return true;
                        }
                    }
                }
            }
            false
        }
        // Compound assignment: rsp += N or sp += N (stack deallocation)
        ExprKind::CompoundAssign { op, lhs, rhs } => {
            if let ExprKind::Var(lhs_var) = &lhs.kind {
                if lhs_var.name == "rsp" || lhs_var.name == "sp" {
                    // rsp += N (stack deallocation)
                    if matches!(op, super::expression::BinOpKind::Add)
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

/// Renames registers to more meaningful variable names.
/// Callee-saved registers used for return values/error codes get renamed.
/// Low-byte registers used as boolean temporaries get renamed to temp_N.
fn rename_register(name: &str) -> String {
    let name_lower = name.to_lowercase();
    match name_lower.as_str() {
        // x86-64 return value register
        "eax" | "rax" => "ret".to_string(),
        // x86-64 callee-saved registers commonly used for error/result
        "ebx" | "rbx" => "err".to_string(),
        "r12" | "r12d" | "r12w" | "r12b" => "result".to_string(),
        "r13" | "r13d" | "r13w" | "r13b" => "saved1".to_string(),
        "r14" | "r14d" | "r14w" | "r14b" => "saved2".to_string(),
        "r15" | "r15d" | "r15w" | "r15b" => "saved3".to_string(),
        // x86-64 argument registers (64-bit only for function args)
        "rdi" => "arg0".to_string(),
        "rsi" => "arg1".to_string(),
        "rdx" => "arg2".to_string(),
        "rcx" => "arg3".to_string(),
        "r8" => "arg4".to_string(),
        "r9" => "arg5".to_string(),
        // ARM64 callee-saved registers
        "x19" | "w19" => "err".to_string(),
        "x20" | "w20" => "result".to_string(),
        "x21" | "w21" => "saved1".to_string(),
        "x22" | "w22" => "saved2".to_string(),
        // ARM64 argument registers (x0 is both arg0 and return value - treat as arg0 here,
        // return value handling is done separately by the return statement)
        "x0" | "w0" => "arg0".to_string(),
        "x1" | "w1" => "arg1".to_string(),
        "x2" | "w2" => "arg2".to_string(),
        "x3" | "w3" => "arg3".to_string(),
        "x4" | "w4" => "arg4".to_string(),
        "x5" | "w5" => "arg5".to_string(),
        "x6" | "w6" => "arg6".to_string(),
        "x7" | "w7" => "arg7".to_string(),
        // x86-64 low-byte and partial registers used as temporaries
        // These are often used for boolean conditions (setcc results)
        "al" | "ah" => "tmp_a".to_string(),
        "bl" | "bh" => "tmp_b".to_string(),
        "cl" | "ch" => "tmp_c".to_string(),
        "dl" | "dh" => "tmp_d".to_string(),
        "sil" => "tmp_si".to_string(),
        "dil" => "tmp_di".to_string(),
        "spl" => "tmp_sp".to_string(),
        "bpl" => "tmp_bp".to_string(),
        "r8b" | "r8w" => "tmp_r8".to_string(),
        "r9b" | "r9w" => "tmp_r9".to_string(),
        "r10b" | "r10w" => "tmp_r10".to_string(),
        "r11b" | "r11w" => "tmp_r11".to_string(),
        // 32-bit subregister forms of the first argument registers.
        // These appear frequently in parameter setup and should keep arg naming.
        "edi" => "arg0".to_string(),
        "esi" => "arg1".to_string(),
        "edx" => "arg2".to_string(),
        "ecx" => "arg3".to_string(),
        "r8d" => "tmp_r8".to_string(),
        "r9d" => "tmp_r9".to_string(),
        "r10d" => "tmp_r10".to_string(),
        "r11d" => "tmp_r11".to_string(),
        // Keep other registers as-is (rsp, rbp, rip, etc.)
        _ => name.to_string(),
    }
}

fn normalize_variable_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("arg_") {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_hexdigit()) {
            return format!("local_{}", rest.to_lowercase());
        }
    }
    name.to_string()
}

/// Checks if two expressions are structurally equal.
fn exprs_equal(a: &Expr, b: &Expr) -> bool {
    match (&a.kind, &b.kind) {
        (ExprKind::Var(va), ExprKind::Var(vb)) => va.name == vb.name,
        (ExprKind::IntLit(na), ExprKind::IntLit(nb)) => na == nb,
        (
            ExprKind::BinOp {
                op: opa,
                left: la,
                right: ra,
            },
            ExprKind::BinOp {
                op: opb,
                left: lb,
                right: rb,
            },
        ) => opa == opb && exprs_equal(la, lb) && exprs_equal(ra, rb),
        (
            ExprKind::UnaryOp {
                op: opa,
                operand: oa,
            },
            ExprKind::UnaryOp {
                op: opb,
                operand: ob,
            },
        ) => opa == opb && exprs_equal(oa, ob),
        (ExprKind::Deref { addr: aa, size: sa }, ExprKind::Deref { addr: ab, size: sb }) => {
            sa == sb && exprs_equal(aa, ab)
        }
        (
            ExprKind::ArrayAccess {
                base: ba,
                index: ia,
                element_size: ea,
            },
            ExprKind::ArrayAccess {
                base: bb,
                index: ib,
                element_size: eb,
            },
        ) => ea == eb && exprs_equal(ba, bb) && exprs_equal(ia, ib),
        (
            ExprKind::FieldAccess {
                base: ba,
                field_name: fa,
                offset: oa,
            },
            ExprKind::FieldAccess {
                base: bb,
                field_name: fb,
                offset: ob,
            },
        ) => oa == ob && fa == fb && exprs_equal(ba, bb),
        _ => false,
    }
}

/// Checks if a body contains only a call to __stack_chk_fail.
fn is_stack_canary_check_body(
    nodes: &[StructuredNode],
    symbol_table: Option<&SymbolTable>,
) -> bool {
    // Look for a single statement that calls __stack_chk_fail
    for node in nodes {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    if is_stack_chk_fail_call(stmt, symbol_table) {
                        return true;
                    }
                }
            }
            StructuredNode::Expr(expr) => {
                if is_stack_chk_fail_call(expr, symbol_table) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Checks if an expression is a call to __stack_chk_fail.
fn is_stack_chk_fail_call(expr: &Expr, symbol_table: Option<&SymbolTable>) -> bool {
    if let ExprKind::Call { target, .. } = &expr.kind {
        match target {
            CallTarget::Named(name) => {
                if name.contains("stack_chk_fail") {
                    return true;
                }
            }
            CallTarget::Direct { target: addr, .. } => {
                // Check if this address resolves to stack_chk_fail
                if let Some(sym_table) = symbol_table {
                    if let Some(name) = sym_table.get(*addr) {
                        if name.contains("stack_chk_fail") {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Checks if an expression is a stack canary load.
/// Pattern: local_X = *(*(GOT_address))
fn is_stack_canary_load(expr: &Expr) -> bool {
    if let ExprKind::Assign { rhs, .. } = &expr.kind {
        // Check for double dereference: *(*(something))
        if let ExprKind::Deref { addr: inner, .. } = &rhs.kind {
            if let ExprKind::Deref { .. } = &inner.kind {
                // Double dereference - likely GOT access to __stack_chk_guard
                return true;
            }
        }
    }
    false
}

/// Checks if a register name is an ARM64 temporary/scratch register (x8-x17 or w8-w17).
/// These are used for intermediate values during argument setup and don't need to appear
/// in the output.
fn is_arm64_temp_register(name: &str) -> bool {
    matches!(
        name,
        "x8" | "x9"
            | "x10"
            | "x11"
            | "x12"
            | "x13"
            | "x14"
            | "x15"
            | "x16"
            | "x17"
            | "w8"
            | "w9"
            | "w10"
            | "w11"
            | "w12"
            | "w13"
            | "w14"
            | "w15"
            | "w16"
            | "w17"
    )
}

/// Checks if an expression is an ARM64 temporary register variable.
fn is_arm64_temp_register_expr(expr: &Expr) -> bool {
    if let ExprKind::Var(v) = &expr.kind {
        return is_arm64_temp_register(&v.name);
    }
    false
}

/// Attempts to extract array access components from an address expression.
/// Matches patterns like `base + index * element_size` where `element_size == size`.
/// Returns `Some((base, index))` if the pattern matches, `None` otherwise.
fn try_extract_array_access(addr: &Expr, size: u8) -> Option<(Expr, Expr)> {
    // Pattern: base + (index * element_size) or (index * element_size) + base
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Try left as base, right as index * size
        if let Some((index, element_size)) = extract_mul_by_constant(right) {
            if element_size == size as i128 {
                return Some(((**left).clone(), index));
            }
        }
        // Try right as base, left as index * size (commutative)
        if let Some((index, element_size)) = extract_mul_by_constant(left) {
            if element_size == size as i128 {
                return Some(((**right).clone(), index));
            }
        }
        // Also try shift patterns: base + (index << shift) where 1 << shift == size
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(right) {
            if (1i128 << shift_amount) == size as i128 {
                return Some(((**left).clone(), index));
            }
        }
        if let Some((index, shift_amount)) = extract_shift_left_by_constant(left) {
            if (1i128 << shift_amount) == size as i128 {
                return Some(((**right).clone(), index));
            }
        }
    }
    None
}

/// Extracts (operand, constant) from expressions like `operand * constant` or `constant * operand`.
fn extract_mul_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Mul,
        left,
        right,
    } = &expr.kind
    {
        // Try left * constant
        if let ExprKind::IntLit(n) = right.kind {
            return Some(((**left).clone(), n));
        }
        // Try constant * right
        if let ExprKind::IntLit(n) = left.kind {
            return Some(((**right).clone(), n));
        }
    }
    None
}

/// Extracts (operand, shift_amount) from expressions like `operand << constant`.
fn extract_shift_left_by_constant(expr: &Expr) -> Option<(Expr, i128)> {
    if let ExprKind::BinOp {
        op: BinOpKind::Shl,
        left,
        right,
    } = &expr.kind
    {
        if let ExprKind::IntLit(n) = right.kind {
            return Some(((**left).clone(), n));
        }
    }
    None
}

/// Extracts the byte offset from a RIP/EIP-relative address expression.
/// Matches patterns like `rip + offset` or `eip + offset` where `offset` is an integer literal.
/// Returns `Some(offset)` if the pattern matches, `None` otherwise.
fn try_extract_rip_relative_offset(addr: &Expr) -> Option<u64> {
    if let ExprKind::BinOp {
        op: BinOpKind::Add,
        left,
        right,
    } = &addr.kind
    {
        // Check if left is rip/eip and right is an integer offset
        if let ExprKind::Var(v) = &left.kind {
            if v.name == "rip" || v.name == "eip" {
                if let ExprKind::IntLit(offset) = &right.kind {
                    if *offset >= 0 {
                        return Some(*offset as u64);
                    }
                }
            }
        }
        // Check if right is rip/eip and left is an integer offset (commutative)
        if let ExprKind::Var(v) = &right.kind {
            if v.name == "rip" || v.name == "eip" {
                if let ExprKind::IntLit(offset) = &left.kind {
                    if *offset >= 0 {
                        return Some(*offset as u64);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::super::expression::BinOpKind;
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

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
    fn test_emit_can_use_shape_fallback_for_callback_type_without_direct_param_mapping() {
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
            header.contains("(*arg1)(void*, void*)")
                || header.contains("(*arg2)(void*, void*)")
                || header.contains("(*arg3)(void*, void*)"),
            "Header should include inferred callback type via fallback mapping:\n{}",
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
    fn test_libc_global_gotref_name_simplification() {
        let mut sym = SymbolTable::new();
        sym.insert(0x1000, "__stderrp".to_string());

        let emitter = PseudoCodeEmitter::new("    ", false).with_symbol_table(Some(sym));
        let expr = Expr::got_ref(0x1000, 0, 8, Expr::unknown("rip_ref"));

        assert_eq!(emitter.format_expr(&expr), "stderr");
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
    fn test_array_notation_for_constant_array_access() {
        use super::super::expression::Variable;

        let emitter = PseudoCodeEmitter::new("    ", false);
        // Array access with constant index uses array notation for readability
        let expr = Expr::array_access(Expr::var(Variable::reg("x8", 8)), Expr::int(2), 8);
        assert_eq!(emitter.format_expr(&expr), "x8[2]");
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

        // Should resolve to _g_1aba (6842 in hex) instead of containing "unresolved_pc_relative"
        assert!(
            !formatted.contains("unresolved_pc_relative"),
            "Should not contain unresolved_pc_relative: {}",
            formatted
        );
        assert_eq!(formatted, "_g_1aba", "Should format as _g_<hex_offset>");

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
            formatted2, "_g_1000",
            "Should format as _g_<hex_offset> for eip"
        );
    }

    #[test]
    fn test_rip_relative_deref_in_compound_assignment() {
        use super::super::expression::{VarKind, Variable};

        // Test that compound assignment like `*(uint32_t*)(rip + 6842) |= 1`
        // correctly resolves to `_g_1aba |= 1` instead of
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

        // Should resolve to `_g_1aba |= 1` instead of containing "unresolved_pc_relative"
        assert!(
            !formatted.contains("unresolved_pc_relative"),
            "Should not contain unresolved_pc_relative in compound assignment: {}",
            formatted
        );
        assert!(
            formatted.contains("_g_1aba"),
            "Should contain resolved global name _g_1aba: {}",
            formatted
        );
        assert!(
            formatted.contains("|= 1"),
            "Should contain compound assignment operator: {}",
            formatted
        );
    }
}
