//! Variable naming heuristics for the decompiler.
//!
//! This module provides intelligent variable naming based on:
//! - Usage patterns (loop counters, pointers, strings)
//! - Type inference results
//! - DWARF debug info (when available)
//! - Context-aware naming conventions

use std::collections::HashMap;

use super::expression::{Expr, ExprKind, BinOpKind};
use super::structurer::StructuredNode;

/// Naming context for tracking variable usage and generating names.
#[derive(Debug, Default)]
pub struct NamingContext {
    /// Assigned names for stack slots (offset -> name).
    slot_names: HashMap<i128, String>,
    /// Counter for generic variable names.
    var_counter: usize,
    /// Counter for loop index variables.
    loop_counter: usize,
    /// Counter for pointer variables.
    ptr_counter: usize,
    /// Counter for string variables.
    str_counter: usize,
    /// Counter for buffer/array variables.
    buf_counter: usize,
    /// Counter for result variables.
    #[allow(dead_code)]
    result_counter: usize,
    /// DWARF-sourced names (offset -> name).
    dwarf_names: HashMap<i128, String>,
    /// Inferred types (offset -> type hint).
    type_hints: HashMap<i128, TypeHint>,
    /// Loop index variables detected.
    loop_indices: Vec<i128>,
}

/// Type hint for a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeHint {
    /// An integer value.
    Int,
    /// A pointer to data.
    Pointer,
    /// A pointer to a string.
    StringPtr,
    /// A boolean/flag value.
    Bool,
    /// A floating-point value.
    Float,
    /// An array/buffer.
    Buffer,
    /// A counter/index.
    Counter,
    /// Unknown type.
    Unknown,
}

impl NamingContext {
    /// Create a new naming context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a naming context with DWARF variable names.
    ///
    /// Takes a map of stack offsets to variable names extracted from DWARF info.
    pub fn with_dwarf_names(names: std::collections::HashMap<i128, String>) -> Self {
        Self {
            dwarf_names: names,
            ..Default::default()
        }
    }

    /// Add a DWARF-sourced name for a stack offset.
    pub fn add_dwarf_name(&mut self, offset: i128, name: String) {
        self.dwarf_names.insert(offset, name);
    }

    /// Add multiple DWARF-sourced names from a map.
    pub fn add_dwarf_names(&mut self, names: std::collections::HashMap<i128, String>) {
        self.dwarf_names.extend(names);
    }

    /// Returns whether DWARF names are available.
    pub fn has_dwarf_names(&self) -> bool {
        !self.dwarf_names.is_empty()
    }

    /// Add a type hint for a stack offset.
    pub fn add_type_hint(&mut self, offset: i128, hint: TypeHint) {
        self.type_hints.insert(offset, hint);
    }

    /// Analyze function body to detect patterns and assign names.
    pub fn analyze(&mut self, body: &[StructuredNode]) {
        // First pass: detect loop indices
        self.detect_loop_indices(body);

        // Second pass: detect type usage patterns
        self.detect_type_patterns(body);
    }

    /// Detect loop index variables from loop patterns.
    fn detect_loop_indices(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::For { init, condition, update, body, .. } => {
                    // For loops: the init expression typically initializes the loop var
                    if let Some(init_expr) = init {
                        if let Some(offset) = self.extract_stack_offset(init_expr) {
                            if !self.loop_indices.contains(&offset) {
                                self.loop_indices.push(offset);
                            }
                        }
                    }
                    // Also check the condition for the loop variable
                    if let Some(offset) = self.extract_comparison_var(condition) {
                        if !self.loop_indices.contains(&offset) {
                            self.loop_indices.push(offset);
                        }
                    }
                    // Check the update expression
                    if let Some(update_expr) = update {
                        if let Some(offset) = self.extract_increment_var(update_expr) {
                            if !self.loop_indices.contains(&offset) {
                                self.loop_indices.push(offset);
                            }
                        }
                    }
                    self.detect_loop_indices(body);
                }
                StructuredNode::While { condition, body, .. } |
                StructuredNode::DoWhile { body, condition, .. } => {
                    // While loops: check if condition involves an incrementing variable
                    if let Some(offset) = self.extract_comparison_var(condition) {
                        // Check if this variable is incremented in the body
                        if self.is_incremented_in_body(offset, body) {
                            if !self.loop_indices.contains(&offset) {
                                self.loop_indices.push(offset);
                            }
                        }
                    }
                    self.detect_loop_indices(body);
                }
                StructuredNode::If { then_body, else_body, .. } => {
                    self.detect_loop_indices(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_loop_indices(else_nodes);
                    }
                }
                StructuredNode::Loop { body } => {
                    self.detect_loop_indices(body);
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_loop_indices(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_loop_indices(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_loop_indices(inner);
                }
                _ => {}
            }
        }
    }

    /// Detect type patterns from variable usage.
    fn detect_type_patterns(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.analyze_statement_types(stmt);
                    }
                }
                StructuredNode::If { then_body, else_body, .. } => {
                    self.detect_type_patterns(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_type_patterns(else_nodes);
                    }
                }
                StructuredNode::While { body, .. } |
                StructuredNode::DoWhile { body, .. } |
                StructuredNode::For { body, .. } |
                StructuredNode::Loop { body } => {
                    self.detect_type_patterns(body);
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_type_patterns(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_type_patterns(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_type_patterns(inner);
                }
                _ => {}
            }
        }
    }

    /// Analyze a statement for type information.
    fn analyze_statement_types(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                if let Some(offset) = self.extract_stack_offset(lhs) {
                    // Check what's being assigned
                    let hint = self.infer_type_from_expr(rhs);
                    if hint != TypeHint::Unknown {
                        self.type_hints.entry(offset).or_insert(hint);
                    }
                }
            }
            ExprKind::Call { args, .. } => {
                // Analyze call arguments
                for arg in args {
                    self.analyze_statement_types(arg);
                }
            }
            _ => {}
        }
    }

    /// Infer a type hint from an expression.
    fn infer_type_from_expr(&self, expr: &Expr) -> TypeHint {
        match &expr.kind {
            // String literals
            ExprKind::IntLit(_) => TypeHint::Int,
            // Address-of suggests pointer
            ExprKind::BinOp { op: BinOpKind::Add, left, .. } => {
                if self.is_likely_pointer(left) {
                    TypeHint::Pointer
                } else {
                    TypeHint::Unknown
                }
            }
            ExprKind::Deref { .. } => TypeHint::Pointer,
            // Comparison results are bools
            ExprKind::BinOp { op, .. } if op.is_comparison() => TypeHint::Bool,
            _ => TypeHint::Unknown,
        }
    }

    /// Check if an expression looks like a pointer.
    fn is_likely_pointer(&self, expr: &Expr) -> bool {
        matches!(&expr.kind,
            ExprKind::Deref { .. } |
            ExprKind::GotRef { .. }
        )
    }

    /// Extract stack offset from an lvalue expression.
    fn extract_stack_offset(&self, expr: &Expr) -> Option<i128> {
        match &expr.kind {
            ExprKind::Deref { addr, .. } => {
                if let ExprKind::BinOp { op, left, right } = &addr.kind {
                    if let ExprKind::Var(base) = &left.kind {
                        if is_frame_or_stack_pointer(&base.name) {
                            if let ExprKind::IntLit(offset) = &right.kind {
                                let actual = match op {
                                    BinOpKind::Add => *offset,
                                    BinOpKind::Sub => -*offset,
                                    _ => return None,
                                };
                                return Some(actual);
                            }
                        }
                    }
                }
                None
            }
            ExprKind::Var(v) => {
                // Check for named stack variables (var_N format)
                if let Some(offset) = parse_var_offset(&v.name) {
                    return Some(offset);
                }
                None
            }
            _ => None,
        }
    }

    /// Extract variable from comparison for loop detection.
    fn extract_comparison_var(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::BinOp { op, left, .. } = &expr.kind {
            if op.is_comparison() {
                return self.extract_stack_offset(left);
            }
        }
        None
    }

    /// Extract variable from increment expression.
    fn extract_increment_var(&self, expr: &Expr) -> Option<i128> {
        match &expr.kind {
            // i = i + 1 or i++
            ExprKind::Assign { lhs, rhs } => {
                let lhs_offset = self.extract_stack_offset(lhs)?;
                // Check if rhs is lhs + constant
                if let ExprKind::BinOp { op: BinOpKind::Add | BinOpKind::Sub, left, right } = &rhs.kind {
                    if let (Some(rhs_offset), ExprKind::IntLit(_)) = (self.extract_stack_offset(left), &right.kind) {
                        if lhs_offset == rhs_offset {
                            return Some(lhs_offset);
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Check if a variable is incremented in a loop body.
    fn is_incremented_in_body(&self, offset: i128, body: &[StructuredNode]) -> bool {
        for node in body {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        if let Some(inc_offset) = self.extract_increment_var(stmt) {
                            if inc_offset == offset {
                                return true;
                            }
                        }
                    }
                }
                StructuredNode::Sequence(inner) => {
                    if self.is_incremented_in_body(offset, inner) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }

    /// Get the name for a stack slot, generating one if needed.
    pub fn get_name(&mut self, offset: i128, is_parameter: bool) -> String {
        // Check for DWARF name first
        if let Some(name) = self.dwarf_names.get(&offset) {
            return name.clone();
        }

        // Check for already assigned name
        if let Some(name) = self.slot_names.get(&offset) {
            return name.clone();
        }

        // Generate name based on context
        let name = if is_parameter {
            self.generate_param_name(offset)
        } else {
            self.generate_local_name(offset)
        };

        self.slot_names.insert(offset, name.clone());
        name
    }

    /// Generate a name for a parameter.
    fn generate_param_name(&mut self, offset: i128) -> String {
        // Check for type hint
        if let Some(hint) = self.type_hints.get(&offset) {
            match hint {
                TypeHint::StringPtr => {
                    self.str_counter += 1;
                    return format!("str{}", if self.str_counter == 1 { String::new() } else { self.str_counter.to_string() });
                }
                TypeHint::Pointer => {
                    self.ptr_counter += 1;
                    return format!("ptr{}", if self.ptr_counter == 1 { String::new() } else { self.ptr_counter.to_string() });
                }
                TypeHint::Buffer => {
                    self.buf_counter += 1;
                    return format!("buf{}", if self.buf_counter == 1 { String::new() } else { self.buf_counter.to_string() });
                }
                _ => {}
            }
        }

        // Generic argument name
        format!("arg_{:x}", offset.unsigned_abs())
    }

    /// Generate a name for a local variable.
    fn generate_local_name(&mut self, offset: i128) -> String {
        // Check if this is a loop index
        if let Some(idx) = self.loop_indices.iter().position(|&o| o == offset) {
            // Use i, j, k, l, m, n for loop indices
            let names = ['i', 'j', 'k', 'l', 'm', 'n'];
            if idx < names.len() {
                return names[idx].to_string();
            }
            return format!("idx{}", idx - names.len());
        }

        // Check for type hint
        if let Some(hint) = self.type_hints.get(&offset) {
            match hint {
                TypeHint::Bool => return format!("flag_{:x}", offset.unsigned_abs()),
                TypeHint::Float => return format!("f_{:x}", offset.unsigned_abs()),
                TypeHint::StringPtr => {
                    self.str_counter += 1;
                    return format!("str{}", if self.str_counter == 1 { String::new() } else { self.str_counter.to_string() });
                }
                TypeHint::Pointer => {
                    self.ptr_counter += 1;
                    return format!("ptr{}", if self.ptr_counter == 1 { String::new() } else { self.ptr_counter.to_string() });
                }
                TypeHint::Counter => {
                    self.loop_counter += 1;
                    let names = ['i', 'j', 'k'];
                    if self.loop_counter <= names.len() {
                        return names[self.loop_counter - 1].to_string();
                    }
                    return format!("cnt{}", self.loop_counter - names.len());
                }
                _ => {}
            }
        }

        // Generic local name
        self.var_counter += 1;
        if offset < 0 {
            format!("local_{:x}", (-offset) as u128)
        } else {
            format!("var_{:x}", offset as u128)
        }
    }

    /// Rename a register to a more meaningful name.
    pub fn rename_register(&self, name: &str) -> String {
        let name_lower = name.to_lowercase();
        match name_lower.as_str() {
            // Zero registers
            "wzr" | "xzr" => "0".to_string(),
            // Return value registers
            "eax" | "rax" | "x0" | "w0" | "a0" => "ret".to_string(),
            // Callee-saved commonly used for error codes
            "ebx" | "rbx" | "x19" | "w19" => "err".to_string(),
            // Callee-saved commonly used for saved results
            "r12" | "r12d" | "x20" | "w20" => "result".to_string(),
            // Other callee-saved
            "r13" | "r13d" | "x21" | "w21" => "saved1".to_string(),
            "r14" | "r14d" | "x22" | "w22" => "saved2".to_string(),
            "r15" | "r15d" | "x23" | "w23" => "saved3".to_string(),
            // Keep others as-is
            _ => name.to_string(),
        }
    }
}

/// Check if a register name is a frame or stack pointer.
fn is_frame_or_stack_pointer(name: &str) -> bool {
    matches!(name, "rbp" | "rsp" | "x29" | "sp" | "fp")
}

/// Parse a variable offset from names like "var_8" or "local_10".
fn parse_var_offset(name: &str) -> Option<i128> {
    if let Some(suffix) = name.strip_prefix("var_") {
        i128::from_str_radix(suffix, 16).ok()
    } else if let Some(suffix) = name.strip_prefix("local_") {
        i128::from_str_radix(suffix, 16).ok().map(|n| -n)
    } else if let Some(suffix) = name.strip_prefix("arg_") {
        i128::from_str_radix(suffix, 16).ok()
    } else {
        None
    }
}

impl BinOpKind {
    /// Check if this is a comparison operator.
    fn is_comparison(&self) -> bool {
        matches!(self,
            BinOpKind::Eq | BinOpKind::Ne |
            BinOpKind::Lt | BinOpKind::Le |
            BinOpKind::Gt | BinOpKind::Ge
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_naming_context_basic() {
        let mut ctx = NamingContext::new();

        // First variable should get a default name
        let name1 = ctx.get_name(-8, false);
        assert!(name1.contains("local") || name1.contains("var"));

        // Same offset should return same name
        let name1_again = ctx.get_name(-8, false);
        assert_eq!(name1, name1_again);
    }

    #[test]
    fn test_dwarf_name_priority() {
        let mut ctx = NamingContext::new();
        ctx.add_dwarf_name(-8, "count".to_string());

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "count");
    }

    #[test]
    fn test_loop_index_naming() {
        let mut ctx = NamingContext::new();
        ctx.loop_indices.push(-4);
        ctx.loop_indices.push(-8);

        let name1 = ctx.get_name(-4, false);
        let name2 = ctx.get_name(-8, false);

        assert_eq!(name1, "i");
        assert_eq!(name2, "j");
    }

    #[test]
    fn test_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-16, TypeHint::StringPtr);

        let name = ctx.get_name(-16, false);
        assert!(name.starts_with("str"));
    }

    #[test]
    fn test_many_loop_indices() {
        let mut ctx = NamingContext::new();
        // Add 8 loop indices
        for i in 0..8 {
            ctx.loop_indices.push(-(i as i128 + 1) * 4);
        }

        // First 6 should be i, j, k, l, m, n
        assert_eq!(ctx.get_name(-4, false), "i");
        assert_eq!(ctx.get_name(-8, false), "j");
        assert_eq!(ctx.get_name(-12, false), "k");
        assert_eq!(ctx.get_name(-16, false), "l");
        assert_eq!(ctx.get_name(-20, false), "m");
        assert_eq!(ctx.get_name(-24, false), "n");
        // Beyond 6 should be idx0, idx1
        assert_eq!(ctx.get_name(-28, false), "idx0");
        assert_eq!(ctx.get_name(-32, false), "idx1");
    }

    #[test]
    fn test_pointer_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Pointer);
        ctx.add_type_hint(-16, TypeHint::Pointer);

        let name1 = ctx.get_name(-8, false);
        let name2 = ctx.get_name(-16, false);

        assert_eq!(name1, "ptr");
        assert_eq!(name2, "ptr2");
    }

    #[test]
    fn test_parameter_naming() {
        let mut ctx = NamingContext::new();

        // Parameters should use arg_ prefix
        let name = ctx.get_name(8, true);
        assert!(name.starts_with("arg_"), "Expected arg_ prefix, got: {}", name);
    }

    #[test]
    fn test_dwarf_overrides_loop_index() {
        let mut ctx = NamingContext::new();
        // Even if detected as loop index, DWARF name should take priority
        ctx.loop_indices.push(-4);
        ctx.add_dwarf_name(-4, "counter".to_string());

        let name = ctx.get_name(-4, false);
        assert_eq!(name, "counter");
    }

    #[test]
    fn test_mixed_naming() {
        let mut ctx = NamingContext::new();

        // Add various hints and indices
        ctx.loop_indices.push(-4);
        ctx.loop_indices.push(-8);
        ctx.add_type_hint(-12, TypeHint::Pointer);
        ctx.add_dwarf_name(-16, "buffer".to_string());

        assert_eq!(ctx.get_name(-4, false), "i");
        assert_eq!(ctx.get_name(-8, false), "j");
        assert_eq!(ctx.get_name(-12, false), "ptr");
        assert_eq!(ctx.get_name(-16, false), "buffer");
        // Unnamed variable gets default name
        let unnamed = ctx.get_name(-20, false);
        assert!(unnamed.contains("local") || unnamed.contains("var"));
    }
}
