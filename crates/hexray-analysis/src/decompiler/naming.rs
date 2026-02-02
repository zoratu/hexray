//! Variable naming heuristics for the decompiler.
//!
//! This module provides intelligent variable naming based on:
//! - Usage patterns (loop counters, pointers, strings)
//! - Type inference results
//! - DWARF debug info (when available)
//! - Context-aware naming conventions

use std::collections::HashMap;

use super::expression::{BinOpKind, Expr, ExprKind};
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
    result_counter: usize,
    /// Counter for size/length variables.
    size_counter: usize,
    /// Counter for accumulator/sum variables.
    sum_counter: usize,
    /// Counter for error code variables.
    err_counter: usize,
    /// Counter for array variables.
    arr_counter: usize,
    /// Counter for destination variables.
    dst_counter: usize,
    /// Counter for source variables.
    src_counter: usize,
    /// Counter for offset variables.
    offset_counter: usize,
    /// Counter for callback/function pointer variables.
    callback_counter: usize,
    /// DWARF-sourced names (offset -> name).
    dwarf_names: HashMap<i128, String>,
    /// Inferred types (offset -> type hint).
    type_hints: HashMap<i128, TypeHint>,
    /// Loop index variables detected.
    loop_indices: Vec<i128>,
    /// Size/length variables detected (used in loop bounds).
    size_vars: Vec<i128>,
    /// Accumulator variables detected (sum += x patterns).
    accumulator_vars: Vec<i128>,
    /// Error code variables detected (from function returns).
    error_vars: Vec<i128>,
    /// Function result variables (assigned from non-error-checked calls).
    result_vars: Vec<i128>,
    /// Destination variables (used as first arg to memcpy-like functions).
    dest_vars: Vec<i128>,
    /// Source variables (used as second arg to memcpy-like functions).
    source_vars: Vec<i128>,
    /// Offset variables (used in pointer arithmetic but not as indices).
    offset_vars: Vec<i128>,
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
    /// An array base pointer (used with indexing).
    Array,
    /// A size/length variable (used in loop bounds).
    Size,
    /// An accumulator/sum variable (pattern: sum += x).
    Sum,
    /// An error code from function return.
    ErrorCode,
    /// A function result (return value from a call).
    Result,
    /// A destination pointer (first arg to memcpy-like functions).
    Destination,
    /// A source pointer (second arg to memcpy-like functions).
    Source,
    /// An offset used in pointer arithmetic.
    Offset,
    /// A function pointer or callback.
    Callback,
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
        // First pass: detect loop indices and size variables
        self.detect_loop_indices(body);

        // Second pass: detect accumulator patterns (sum += x)
        self.detect_accumulators(body);

        // Third pass: detect error code patterns
        self.detect_error_codes(body);

        // Fourth pass: detect array indexing patterns
        self.detect_array_patterns(body);

        // Fifth pass: detect function result patterns
        self.detect_result_vars(body);

        // Sixth pass: detect memcpy-like dest/src patterns
        self.detect_memcpy_patterns(body);

        // Seventh pass: detect offset variables in pointer arithmetic
        self.detect_offset_vars(body);

        // Eighth pass: detect function call argument types
        self.detect_call_arg_types(body);

        // Ninth pass: detect counter variables (standalone increments)
        self.detect_counter_vars(body);

        // Last pass: detect other type usage patterns
        self.detect_type_patterns(body);
    }

    /// Detect types from function call arguments (e.g., printf format string).
    fn detect_call_arg_types(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.detect_call_arg_types_in_expr(stmt);
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_call_arg_types(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_call_arg_types(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_call_arg_types(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_call_arg_types(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_call_arg_types(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_call_arg_types(inner);
                }
                _ => {}
            }
        }
    }

    /// Detect types from function call arguments.
    fn detect_call_arg_types_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { target, args } => {
                let func_name = match target {
                    super::expression::CallTarget::Named(name) => name.to_lowercase(),
                    _ => String::new(),
                };

                // Printf family: first arg is format string
                if func_name.contains("printf")
                    || func_name.contains("sprintf")
                    || func_name.contains("snprintf")
                    || func_name.contains("fprintf")
                {
                    // Skip fprintf's file handle arg
                    let fmt_idx = if func_name.contains("fprintf") { 1 } else { 0 };
                    if let Some(fmt_arg) = args.get(fmt_idx) {
                        if let Some(offset) = self.extract_stack_offset(fmt_arg) {
                            self.type_hints.entry(offset).or_insert(TypeHint::StringPtr);
                        }
                    }
                }

                // String functions: args are typically strings or pointers
                if func_name.contains("str")
                    && (func_name.contains("cmp")
                        || func_name.contains("cat")
                        || func_name.contains("chr")
                        || func_name.contains("len"))
                {
                    for arg in args {
                        if let Some(offset) = self.extract_stack_offset(arg) {
                            self.type_hints.entry(offset).or_insert(TypeHint::StringPtr);
                        }
                    }
                }

                // File operations: fopen returns FILE*, first arg is filename
                if func_name == "fopen" || func_name == "_fopen" {
                    if let Some(first_arg) = args.first() {
                        if let Some(offset) = self.extract_stack_offset(first_arg) {
                            self.type_hints.entry(offset).or_insert(TypeHint::StringPtr);
                        }
                    }
                }

                // Read/write: first arg is file handle, second is buffer
                if func_name.contains("fread")
                    || func_name.contains("fwrite")
                    || func_name.contains("read")
                    || func_name.contains("write")
                {
                    if let Some(buf_arg) = args.first() {
                        if let Some(offset) = self.extract_stack_offset(buf_arg) {
                            self.type_hints.entry(offset).or_insert(TypeHint::Buffer);
                        }
                    }
                }

                // Recurse into args
                for arg in args {
                    self.detect_call_arg_types_in_expr(arg);
                }
            }
            ExprKind::Assign { lhs, rhs } => {
                // Check for fopen result
                if let ExprKind::Call {
                    target: super::expression::CallTarget::Named(name),
                    ..
                } = &rhs.kind
                {
                    let lower = name.to_lowercase();
                    if lower == "fopen" || lower == "_fopen" {
                        if let Some(offset) = self.extract_stack_offset(lhs) {
                            self.type_hints.entry(offset).or_insert(TypeHint::Pointer);
                        }
                    }
                    // malloc/calloc returns a pointer
                    if lower.contains("alloc") {
                        if let Some(offset) = self.extract_stack_offset(lhs) {
                            self.type_hints.entry(offset).or_insert(TypeHint::Pointer);
                        }
                    }
                }
                self.detect_call_arg_types_in_expr(lhs);
                self.detect_call_arg_types_in_expr(rhs);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.detect_call_arg_types_in_expr(left);
                self.detect_call_arg_types_in_expr(right);
            }
            _ => {}
        }
    }

    /// Detect counter variables from standalone increments (not loop indices).
    fn detect_counter_vars(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        if let Some(offset) = self.extract_standalone_increment(stmt) {
                            // Only mark as counter if not already a loop index
                            if !self.loop_indices.contains(&offset)
                                && !self.accumulator_vars.contains(&offset)
                            {
                                self.type_hints.entry(offset).or_insert(TypeHint::Counter);
                            }
                        }
                    }
                }
                // Don't recurse into loops - those are loop indices
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_counter_vars(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_counter_vars(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_counter_vars(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_counter_vars(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_counter_vars(inner);
                }
                _ => {}
            }
        }
    }

    /// Extract a variable from a standalone increment (x++ or x += 1).
    fn extract_standalone_increment(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            let lhs_offset = self.extract_stack_offset(lhs)?;

            // Check for x = x + 1 or x = x - 1
            if let ExprKind::BinOp {
                op: BinOpKind::Add | BinOpKind::Sub,
                left,
                right,
            } = &rhs.kind
            {
                // Must be increment by 1
                let is_inc_by_one =
                    matches!(right.kind, ExprKind::IntLit(1) | ExprKind::IntLit(-1));
                if is_inc_by_one {
                    if let Some(rhs_offset) = self.extract_stack_offset(left) {
                        if lhs_offset == rhs_offset {
                            return Some(lhs_offset);
                        }
                    }
                }
            }
        }
        None
    }

    /// Detect loop index variables from loop patterns.
    /// Also detects size/bound variables used in loop conditions.
    fn detect_loop_indices(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::For {
                    init,
                    condition,
                    update,
                    body,
                    ..
                } => {
                    // For loops: the init expression typically initializes the loop var
                    if let Some(init_expr) = init {
                        if let Some(offset) = self.extract_stack_offset(init_expr) {
                            if !self.loop_indices.contains(&offset) {
                                self.loop_indices.push(offset);
                            }
                        }
                    }
                    // Also check the condition for the loop variable and bound
                    if let Some(offset) = self.extract_comparison_var(condition) {
                        if !self.loop_indices.contains(&offset) {
                            self.loop_indices.push(offset);
                        }
                    }
                    // Extract the size/bound variable from condition (RHS of comparison)
                    if let Some(size_offset) = self.extract_comparison_bound(condition) {
                        if !self.size_vars.contains(&size_offset) {
                            self.size_vars.push(size_offset);
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
                StructuredNode::While {
                    condition, body, ..
                }
                | StructuredNode::DoWhile {
                    body, condition, ..
                } => {
                    // While loops: check if condition involves an incrementing variable
                    if let Some(offset) = self.extract_comparison_var(condition) {
                        // Check if this variable is incremented in the body
                        if self.is_incremented_in_body(offset, body)
                            && !self.loop_indices.contains(&offset)
                        {
                            self.loop_indices.push(offset);
                        }
                    }
                    // Extract size/bound from while condition too
                    if let Some(size_offset) = self.extract_comparison_bound(condition) {
                        if !self.size_vars.contains(&size_offset) {
                            self.size_vars.push(size_offset);
                        }
                    }
                    self.detect_loop_indices(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_loop_indices(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_loop_indices(else_nodes);
                    }
                }
                StructuredNode::Loop { body, .. } => {
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
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_type_patterns(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_type_patterns(else_nodes);
                    }
                }
                StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::For { body, .. }
                | StructuredNode::Loop { body, .. } => {
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
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                ..
            } => {
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
        matches!(&expr.kind, ExprKind::Deref { .. } | ExprKind::GotRef { .. })
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
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                // Handle sp[N] or x29[N] patterns
                if let ExprKind::Var(v) = &base.kind {
                    if is_frame_or_stack_pointer(&v.name) {
                        if let ExprKind::IntLit(idx) = &index.kind {
                            let byte_offset = *idx * (*element_size as i128);
                            // Frame pointer (rbp/x29) uses negative offsets for locals
                            let is_frame_ptr = v.name == "rbp" || v.name == "x29";
                            let actual = if is_frame_ptr {
                                -byte_offset
                            } else {
                                byte_offset
                            };
                            return Some(actual);
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

    /// Extract the bound/size variable from comparison (RHS of `i < size`).
    fn extract_comparison_bound(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::BinOp { op, right, .. } = &expr.kind {
            // Only for < <= > >= comparisons (loop bounds)
            if matches!(
                op,
                BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge
            ) {
                // Skip if RHS is a constant (not a size variable)
                if matches!(right.kind, ExprKind::IntLit(_)) {
                    return None;
                }
                return self.extract_stack_offset(right);
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
                if let ExprKind::BinOp {
                    op: BinOpKind::Add | BinOpKind::Sub,
                    left,
                    right,
                } = &rhs.kind
                {
                    if let (Some(rhs_offset), ExprKind::IntLit(_)) =
                        (self.extract_stack_offset(left), &right.kind)
                    {
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

    /// Detect accumulator patterns (sum += x, product *= x).
    fn detect_accumulators(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        if let Some(offset) = self.extract_accumulator_var(stmt) {
                            if !self.accumulator_vars.contains(&offset) {
                                self.accumulator_vars.push(offset);
                            }
                        }
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    // Accumulators inside loops are more likely to be actual sums
                    self.detect_accumulators(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_accumulators(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_accumulators(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_accumulators(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_accumulators(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_accumulators(inner);
                }
                _ => {}
            }
        }
    }

    /// Extract an accumulator variable from an expression like `sum += x`.
    fn extract_accumulator_var(&self, expr: &Expr) -> Option<i128> {
        // Handle compound assignment: sum += x or sum *= x
        if let ExprKind::CompoundAssign { op, lhs, rhs } = &expr.kind {
            if matches!(op, BinOpKind::Add | BinOpKind::Mul) {
                let lhs_offset = self.extract_stack_offset(lhs)?;
                // Exclude simple increments (i += 1)
                if !matches!(rhs.kind, ExprKind::IntLit(1)) {
                    return Some(lhs_offset);
                }
            }
        }

        // Handle expanded form: x = x + y or x = x * y
        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            let lhs_offset = self.extract_stack_offset(lhs)?;

            // Check for patterns: x = x + y or x = x * y
            if let ExprKind::BinOp {
                op: BinOpKind::Add | BinOpKind::Mul,
                left,
                right,
            } = &rhs.kind
            {
                // Check if one operand is the same variable
                let left_offset = self.extract_stack_offset(left);
                let right_offset = self.extract_stack_offset(right);

                if left_offset == Some(lhs_offset) || right_offset == Some(lhs_offset) {
                    // Exclude simple increments (i = i + 1)
                    let is_constant = matches!(right.kind, ExprKind::IntLit(1))
                        || matches!(left.kind, ExprKind::IntLit(1));
                    if !is_constant {
                        return Some(lhs_offset);
                    }
                }
            }
        }
        None
    }

    /// Detect error code patterns (return value checked in conditional).
    fn detect_error_codes(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for (i, stmt) in statements.iter().enumerate() {
                        // Look for: err = func_call()
                        if let Some(offset) = self.extract_error_code_candidate(stmt) {
                            // Check if the next statement or siblings check this variable
                            if i + 1 < statements.len()
                                && self.is_checked_in_condition(offset, &statements[i + 1..])
                                && !self.error_vars.contains(&offset)
                            {
                                self.error_vars.push(offset);
                            }
                        }
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_error_codes(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_error_codes(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_error_codes(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_error_codes(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_error_codes(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_error_codes(inner);
                }
                _ => {}
            }
        }
    }

    /// Extract a variable assigned from a function call (error code candidate).
    fn extract_error_code_candidate(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            // RHS must be a function call
            if matches!(rhs.kind, ExprKind::Call { .. }) {
                return self.extract_stack_offset(lhs);
            }
        }
        None
    }

    /// Check if a variable is tested in a condition following its assignment.
    fn is_checked_in_condition(&self, offset: i128, remaining: &[Expr]) -> bool {
        for expr in remaining {
            if self.expr_tests_offset(expr, offset) {
                return true;
            }
        }
        false
    }

    /// Check if an expression tests a given offset (for error code detection).
    fn expr_tests_offset(&self, expr: &Expr, offset: i128) -> bool {
        match &expr.kind {
            ExprKind::BinOp { op, left, right } if op.is_comparison() => {
                // Check if either side references our variable
                self.extract_stack_offset(left) == Some(offset)
                    || self.extract_stack_offset(right) == Some(offset)
            }
            _ => false,
        }
    }

    /// Detect array indexing patterns.
    fn detect_array_patterns(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.detect_array_usage_in_expr(stmt);
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_array_patterns(body);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_array_usage_in_expr(condition);
                    self.detect_array_patterns(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_array_patterns(else_nodes);
                    }
                }
                StructuredNode::Switch {
                    value,
                    cases,
                    default,
                    ..
                } => {
                    self.detect_array_usage_in_expr(value);
                    for (_, case_body) in cases {
                        self.detect_array_patterns(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_array_patterns(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_array_patterns(inner);
                }
                _ => {}
            }
        }
    }

    /// Detect array base pointers and simple pointer dereferences.
    fn detect_array_usage_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            // Dereference patterns
            ExprKind::Deref { addr, .. } => {
                // First check for array pattern: base + index*scale
                if let Some(base_offset) = self.extract_array_base(addr) {
                    self.type_hints
                        .entry(base_offset)
                        .or_insert(TypeHint::Array);
                }
                // Check for simple pointer dereference: *ptr or *(ptr + offset)
                else if let Some(ptr_offset) = self.extract_pointer_base(addr) {
                    // Only mark as Pointer if not already Array
                    self.type_hints
                        .entry(ptr_offset)
                        .or_insert(TypeHint::Pointer);
                }
                // Recurse into the address expression
                self.detect_array_usage_in_expr(addr);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.detect_array_usage_in_expr(lhs);
                self.detect_array_usage_in_expr(rhs);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.detect_array_usage_in_expr(left);
                self.detect_array_usage_in_expr(right);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.detect_array_usage_in_expr(arg);
                }
            }
            _ => {}
        }
    }

    /// Extract pointer base from a simple dereference address expression.
    /// Returns the stack offset if addr is a pointer variable (not an array index pattern).
    fn extract_pointer_base(&self, addr: &Expr) -> Option<i128> {
        match &addr.kind {
            // Direct variable dereference: *ptr
            ExprKind::Var(v) => {
                if let Some(offset) = parse_var_offset(&v.name) {
                    return Some(offset);
                }
                None
            }
            // Stack slot: *(rbp + offset)
            ExprKind::BinOp { op, left, right } => {
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
                // Also check for ptr + constant_offset (struct field access)
                // Don't mark as pointer if it's multiplication (array index)
                if *op == BinOpKind::Add {
                    if let ExprKind::IntLit(_) = &right.kind {
                        // ptr + const -> ptr is a pointer
                        return self.extract_stack_offset(left);
                    }
                    if let ExprKind::IntLit(_) = &left.kind {
                        // const + ptr -> ptr is a pointer
                        return self.extract_stack_offset(right);
                    }
                }
                None
            }
            // Deref of a deref: **ptr - the inner addr is a pointer
            ExprKind::Deref { addr: inner, .. } => self.extract_pointer_base(inner),
            _ => None,
        }
    }

    /// Extract array base from address expression (base + idx * scale).
    fn extract_array_base(&self, addr: &Expr) -> Option<i128> {
        if let ExprKind::BinOp {
            op: BinOpKind::Add,
            left,
            right,
        } = &addr.kind
        {
            // Pattern: base + (idx * scale) or (idx * scale) + base
            // Check if right is multiplication (scaled index)
            if matches!(
                right.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Mul,
                    ..
                }
            ) {
                return self.extract_stack_offset(left);
            }
            // Or left is multiplication
            if matches!(
                left.kind,
                ExprKind::BinOp {
                    op: BinOpKind::Mul,
                    ..
                }
            ) {
                return self.extract_stack_offset(right);
            }
        }
        None
    }

    /// Detect function result variables (assigned from calls but not error-checked).
    fn detect_result_vars(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        // Look for: result = func_call()
                        if let Some(offset) = self.extract_call_result(stmt) {
                            // Don't add if already an error var or loop index
                            if !self.error_vars.contains(&offset)
                                && !self.loop_indices.contains(&offset)
                                && !self.result_vars.contains(&offset)
                            {
                                self.result_vars.push(offset);
                            }
                        }
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_result_vars(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_result_vars(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_result_vars(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_result_vars(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_result_vars(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_result_vars(inner);
                }
                _ => {}
            }
        }
    }

    /// Extract a variable assigned from a function call (not error-checked).
    fn extract_call_result(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::Assign { lhs, rhs } = &expr.kind {
            // RHS must be a function call
            if matches!(rhs.kind, ExprKind::Call { .. }) {
                return self.extract_stack_offset(lhs);
            }
        }
        None
    }

    /// Detect memcpy-like patterns where first arg is dest, second is src.
    fn detect_memcpy_patterns(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.detect_memcpy_in_expr(stmt);
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_memcpy_patterns(body);
                }
                StructuredNode::If {
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_memcpy_patterns(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_memcpy_patterns(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_memcpy_patterns(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_memcpy_patterns(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_memcpy_patterns(inner);
                }
                _ => {}
            }
        }
    }

    /// Detect dest/src variables in memcpy-like function calls.
    fn detect_memcpy_in_expr(&mut self, expr: &Expr) {
        if let ExprKind::Call { target, args } = &expr.kind {
            // Check if this looks like a memcpy/memmove/strcpy function
            let is_copy_func = match target {
                super::expression::CallTarget::Named(name) => {
                    let lower = name.to_lowercase();
                    lower.contains("cpy")
                        || lower.contains("copy")
                        || lower.contains("move")
                        || lower.contains("dup")
                }
                _ => false,
            };

            if is_copy_func && args.len() >= 2 {
                // First arg is typically destination
                if let Some(offset) = self.extract_stack_offset(&args[0]) {
                    if !self.dest_vars.contains(&offset) {
                        self.dest_vars.push(offset);
                    }
                }
                // Second arg is typically source
                if let Some(offset) = self.extract_stack_offset(&args[1]) {
                    if !self.source_vars.contains(&offset) {
                        self.source_vars.push(offset);
                    }
                }
            }
        }
    }

    /// Detect offset variables used in pointer arithmetic.
    fn detect_offset_vars(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            match node {
                StructuredNode::Block { statements, .. } => {
                    for stmt in statements {
                        self.detect_offset_in_expr(stmt);
                    }
                }
                StructuredNode::For { body, .. }
                | StructuredNode::While { body, .. }
                | StructuredNode::DoWhile { body, .. }
                | StructuredNode::Loop { body, .. } => {
                    self.detect_offset_vars(body);
                }
                StructuredNode::If {
                    condition,
                    then_body,
                    else_body,
                    ..
                } => {
                    self.detect_offset_in_expr(condition);
                    self.detect_offset_vars(then_body);
                    if let Some(else_nodes) = else_body {
                        self.detect_offset_vars(else_nodes);
                    }
                }
                StructuredNode::Switch { cases, default, .. } => {
                    for (_, case_body) in cases {
                        self.detect_offset_vars(case_body);
                    }
                    if let Some(def) = default {
                        self.detect_offset_vars(def);
                    }
                }
                StructuredNode::Sequence(inner) => {
                    self.detect_offset_vars(inner);
                }
                _ => {}
            }
        }
    }

    /// Detect offset variables in pointer arithmetic expressions.
    /// Looks for patterns like *(ptr + offset) where offset is not a loop index.
    fn detect_offset_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            // Dereference of (base + offset)
            ExprKind::Deref { addr, .. } => {
                if let ExprKind::BinOp {
                    op: BinOpKind::Add,
                    left,
                    right,
                } = &addr.kind
                {
                    // Check right side for non-index offset
                    if let Some(offset) = self.extract_stack_offset(right) {
                        // Not a loop index and not a constant
                        if !self.loop_indices.contains(&offset)
                            && !self.offset_vars.contains(&offset)
                            && !matches!(right.kind, ExprKind::IntLit(_))
                        {
                            self.offset_vars.push(offset);
                        }
                    }
                    // Check left side too
                    if let Some(offset) = self.extract_stack_offset(left) {
                        if !self.loop_indices.contains(&offset)
                            && !self.offset_vars.contains(&offset)
                            && !matches!(left.kind, ExprKind::IntLit(_))
                        {
                            self.offset_vars.push(offset);
                        }
                    }
                }
                self.detect_offset_in_expr(addr);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.detect_offset_in_expr(lhs);
                self.detect_offset_in_expr(rhs);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.detect_offset_in_expr(left);
                self.detect_offset_in_expr(right);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.detect_offset_in_expr(arg);
                }
            }
            _ => {}
        }
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
        if let Some(hint) = self.type_hints.get(&offset).copied() {
            match hint {
                TypeHint::StringPtr => {
                    self.str_counter += 1;
                    return if self.str_counter == 1 {
                        "str".to_string()
                    } else {
                        format!("str{}", self.str_counter)
                    };
                }
                TypeHint::Pointer => {
                    self.ptr_counter += 1;
                    return if self.ptr_counter == 1 {
                        "ptr".to_string()
                    } else {
                        format!("ptr{}", self.ptr_counter)
                    };
                }
                TypeHint::Buffer => {
                    self.buf_counter += 1;
                    return if self.buf_counter == 1 {
                        "data".to_string()
                    } else {
                        format!("data{}", self.buf_counter)
                    };
                }
                TypeHint::Array => {
                    self.arr_counter += 1;
                    return if self.arr_counter == 1 {
                        "arr".to_string()
                    } else {
                        format!("arr{}", self.arr_counter)
                    };
                }
                TypeHint::Size => {
                    self.size_counter += 1;
                    return if self.size_counter == 1 {
                        "count".to_string()
                    } else {
                        format!("count{}", self.size_counter)
                    };
                }
                _ => {}
            }
        }

        // Generic argument name
        format!("arg_{:x}", offset.unsigned_abs())
    }

    /// Generate a name for a local variable.
    fn generate_local_name(&mut self, offset: i128) -> String {
        // Check if this is a loop index (highest priority after DWARF)
        if let Some(idx) = self.loop_indices.iter().position(|&o| o == offset) {
            // Use i, j, k, l, m, n for loop indices
            let names = ['i', 'j', 'k', 'l', 'm', 'n'];
            if idx < names.len() {
                return names[idx].to_string();
            }
            return format!("idx{}", idx - names.len());
        }

        // Check if this is a size/length variable (used in loop bounds)
        if self.size_vars.contains(&offset) {
            self.size_counter += 1;
            return if self.size_counter == 1 {
                "len".to_string()
            } else {
                format!("len{}", self.size_counter)
            };
        }

        // Check if this is an accumulator variable (sum += x patterns)
        if self.accumulator_vars.contains(&offset) {
            self.sum_counter += 1;
            return if self.sum_counter == 1 {
                "sum".to_string()
            } else {
                format!("sum{}", self.sum_counter)
            };
        }

        // Check if this is an error code variable
        if self.error_vars.contains(&offset) {
            self.err_counter += 1;
            return if self.err_counter == 1 {
                "err".to_string()
            } else {
                format!("err{}", self.err_counter)
            };
        }

        // Check for type hint
        if let Some(hint) = self.type_hints.get(&offset).copied() {
            match hint {
                TypeHint::Bool => return format!("flag_{:x}", offset.unsigned_abs()),
                TypeHint::Float => return format!("f_{:x}", offset.unsigned_abs()),
                TypeHint::StringPtr => {
                    self.str_counter += 1;
                    return if self.str_counter == 1 {
                        "str".to_string()
                    } else {
                        format!("str{}", self.str_counter)
                    };
                }
                TypeHint::Pointer => {
                    self.ptr_counter += 1;
                    return if self.ptr_counter == 1 {
                        "ptr".to_string()
                    } else {
                        format!("ptr{}", self.ptr_counter)
                    };
                }
                TypeHint::Counter => {
                    self.loop_counter += 1;
                    let names = ['i', 'j', 'k'];
                    if self.loop_counter <= names.len() {
                        return names[self.loop_counter - 1].to_string();
                    }
                    return format!("cnt{}", self.loop_counter - names.len());
                }
                TypeHint::Array => {
                    self.arr_counter += 1;
                    return if self.arr_counter == 1 {
                        "arr".to_string()
                    } else {
                        format!("arr{}", self.arr_counter)
                    };
                }
                TypeHint::Size => {
                    self.size_counter += 1;
                    return if self.size_counter == 1 {
                        "size".to_string()
                    } else {
                        format!("size{}", self.size_counter)
                    };
                }
                TypeHint::Sum => {
                    self.sum_counter += 1;
                    return if self.sum_counter == 1 {
                        "total".to_string()
                    } else {
                        format!("total{}", self.sum_counter)
                    };
                }
                TypeHint::ErrorCode => {
                    self.err_counter += 1;
                    return if self.err_counter == 1 {
                        "result".to_string()
                    } else {
                        format!("result{}", self.err_counter)
                    };
                }
                TypeHint::Buffer => {
                    self.buf_counter += 1;
                    return if self.buf_counter == 1 {
                        "buf".to_string()
                    } else {
                        format!("buf{}", self.buf_counter)
                    };
                }
                TypeHint::Result => {
                    self.result_counter += 1;
                    return if self.result_counter == 1 {
                        "result".to_string()
                    } else {
                        format!("result{}", self.result_counter)
                    };
                }
                TypeHint::Destination => {
                    self.dst_counter += 1;
                    return if self.dst_counter == 1 {
                        "dst".to_string()
                    } else {
                        format!("dst{}", self.dst_counter)
                    };
                }
                TypeHint::Source => {
                    self.src_counter += 1;
                    return if self.src_counter == 1 {
                        "src".to_string()
                    } else {
                        format!("src{}", self.src_counter)
                    };
                }
                TypeHint::Offset => {
                    self.offset_counter += 1;
                    return if self.offset_counter == 1 {
                        "offset".to_string()
                    } else {
                        format!("offset{}", self.offset_counter)
                    };
                }
                TypeHint::Callback => {
                    self.callback_counter += 1;
                    return if self.callback_counter == 1 {
                        "callback".to_string()
                    } else {
                        format!("callback{}", self.callback_counter)
                    };
                }
                TypeHint::Int | TypeHint::Unknown => {}
            }
        }

        // Check detected pattern variables (not via type hint)
        if self.result_vars.contains(&offset) {
            self.result_counter += 1;
            return if self.result_counter == 1 {
                "ret".to_string()
            } else {
                format!("ret{}", self.result_counter)
            };
        }

        if self.dest_vars.contains(&offset) {
            self.dst_counter += 1;
            return if self.dst_counter == 1 {
                "dst".to_string()
            } else {
                format!("dst{}", self.dst_counter)
            };
        }

        if self.source_vars.contains(&offset) {
            self.src_counter += 1;
            return if self.src_counter == 1 {
                "src".to_string()
            } else {
                format!("src{}", self.src_counter)
            };
        }

        if self.offset_vars.contains(&offset) {
            self.offset_counter += 1;
            return if self.offset_counter == 1 {
                "off".to_string()
            } else {
                format!("off{}", self.offset_counter)
            };
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
            // Return value registers (x86-64)
            "eax" | "rax" => "ret".to_string(),
            // ARM64 argument registers (x0 is both arg0 and return - treat as arg0)
            "x0" | "w0" => "arg0".to_string(),
            // RISC-V return value
            "a0" => "ret".to_string(),
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
        assert!(
            name.starts_with("arg_"),
            "Expected arg_ prefix, got: {}",
            name
        );
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

    #[test]
    fn test_size_variable_naming() {
        let mut ctx = NamingContext::new();
        // Simulate detection of size variables
        ctx.size_vars.push(-8);
        ctx.size_vars.push(-16);

        let name1 = ctx.get_name(-8, false);
        let name2 = ctx.get_name(-16, false);

        assert_eq!(name1, "len");
        assert_eq!(name2, "len2");
    }

    #[test]
    fn test_accumulator_naming() {
        let mut ctx = NamingContext::new();
        // Simulate detection of accumulator variables
        ctx.accumulator_vars.push(-8);
        ctx.accumulator_vars.push(-16);

        let name1 = ctx.get_name(-8, false);
        let name2 = ctx.get_name(-16, false);

        assert_eq!(name1, "sum");
        assert_eq!(name2, "sum2");
    }

    #[test]
    fn test_error_code_naming() {
        let mut ctx = NamingContext::new();
        // Simulate detection of error code variables
        ctx.error_vars.push(-8);
        ctx.error_vars.push(-16);

        let name1 = ctx.get_name(-8, false);
        let name2 = ctx.get_name(-16, false);

        assert_eq!(name1, "err");
        assert_eq!(name2, "err2");
    }

    #[test]
    fn test_array_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Array);
        ctx.add_type_hint(-16, TypeHint::Array);

        let name1 = ctx.get_name(-8, false);
        let name2 = ctx.get_name(-16, false);

        assert_eq!(name1, "arr");
        assert_eq!(name2, "arr2");
    }

    #[test]
    fn test_size_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Size);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "size");
    }

    #[test]
    fn test_sum_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Sum);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "total");
    }

    #[test]
    fn test_error_code_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::ErrorCode);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "result");
    }

    #[test]
    fn test_parameter_with_array_hint() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(8, TypeHint::Array);

        let name = ctx.get_name(8, true);
        assert_eq!(name, "arr");
    }

    #[test]
    fn test_parameter_with_size_hint() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(8, TypeHint::Size);

        let name = ctx.get_name(8, true);
        assert_eq!(name, "count");
    }

    #[test]
    fn test_naming_priority() {
        // Test that detected patterns take priority over type hints
        let mut ctx = NamingContext::new();

        // Add as both loop index and add type hint
        ctx.loop_indices.push(-4);
        ctx.add_type_hint(-4, TypeHint::Int);

        // Loop index should win
        assert_eq!(ctx.get_name(-4, false), "i");

        // Add as both size var and type hint
        ctx.size_vars.push(-8);
        ctx.add_type_hint(-8, TypeHint::Int);

        // Size var should win
        assert_eq!(ctx.get_name(-8, false), "len");
    }

    #[test]
    fn test_buffer_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Buffer);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "buf");
    }

    #[test]
    fn test_buffer_param_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(8, TypeHint::Buffer);

        // Parameters with buffer hint get "data" prefix
        let name = ctx.get_name(8, true);
        assert_eq!(name, "data");
    }

    #[test]
    fn test_result_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Result);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "result");
    }

    #[test]
    fn test_destination_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Destination);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "dst");
    }

    #[test]
    fn test_source_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Source);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "src");
    }

    #[test]
    fn test_offset_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Offset);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "offset");
    }

    #[test]
    fn test_callback_type_hint_naming() {
        let mut ctx = NamingContext::new();
        ctx.add_type_hint(-8, TypeHint::Callback);

        let name = ctx.get_name(-8, false);
        assert_eq!(name, "callback");
    }

    #[test]
    fn test_result_vars_naming() {
        let mut ctx = NamingContext::new();
        ctx.result_vars.push(-8);
        ctx.result_vars.push(-16);

        assert_eq!(ctx.get_name(-8, false), "ret");
        assert_eq!(ctx.get_name(-16, false), "ret2");
    }

    #[test]
    fn test_dest_vars_naming() {
        let mut ctx = NamingContext::new();
        ctx.dest_vars.push(-8);

        assert_eq!(ctx.get_name(-8, false), "dst");
    }

    #[test]
    fn test_source_vars_naming() {
        let mut ctx = NamingContext::new();
        ctx.source_vars.push(-8);

        assert_eq!(ctx.get_name(-8, false), "src");
    }

    #[test]
    fn test_offset_vars_naming() {
        let mut ctx = NamingContext::new();
        ctx.offset_vars.push(-8);
        ctx.offset_vars.push(-16);

        assert_eq!(ctx.get_name(-8, false), "off");
        assert_eq!(ctx.get_name(-16, false), "off2");
    }
}
