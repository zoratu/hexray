//! Struct field inference for the decompiler.
//!
//! This module analyzes memory access patterns to infer struct field layouts.
//! When code accesses memory through a base pointer at consistent offsets,
//! we can infer the existence of a struct type with fields at those offsets.
//!
//! ## Access Pattern Recognition
//!
//! Common patterns that indicate struct field access:
//! - `mov eax, [rbx + 0x8]` → reading field at offset 8
//! - `mov [rbx + 0x10], rcx` → writing field at offset 16
//! - `lea rax, [rbx + 0x20]` → taking address of field at offset 32
//!
//! ## Type Inference
//!
//! Field types are inferred from usage:
//! - If a field is dereferenced, it's likely a pointer
//! - If a field is used in arithmetic, it's likely an integer
//! - If a field is passed to functions with known signatures, we can infer its type
//! - Access size determines the base field size (1/2/4/8 bytes)

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use super::expression::{BinOpKind, Expr, ExprKind, VarKind, Variable};
use super::structurer::StructuredNode;

/// An inferred struct type.
#[derive(Debug, Clone)]
pub struct InferredStruct {
    /// Generated name for the struct (e.g., "struct_0", "struct_1").
    pub name: String,
    /// Fields of the struct, sorted by offset.
    pub fields: Vec<InferredField>,
    /// Total size of the struct (if known).
    pub size: Option<usize>,
    /// Number of times this struct pattern was accessed.
    pub access_count: usize,
}

/// An inferred field within a struct.
#[derive(Debug, Clone)]
pub struct InferredField {
    /// Offset from struct base in bytes.
    pub offset: usize,
    /// Size of the field in bytes.
    pub size: usize,
    /// Inferred type of the field.
    pub field_type: InferredType,
    /// Generated name for the field (e.g., "field_8", "field_10").
    pub name: String,
}

/// Inferred type for a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InferredType {
    /// Unknown type (default).
    Unknown,
    /// Signed integer of specified size.
    SignedInt(usize),
    /// Unsigned integer of specified size.
    UnsignedInt(usize),
    /// Pointer to another type.
    Pointer(Box<InferredType>),
    /// Pointer to a struct (by name).
    StructPointer(String),
    /// Boolean (likely from comparison usage).
    Bool,
    /// Floating-point type.
    Float(usize),
    /// Array of elements.
    Array {
        element_type: Box<InferredType>,
        count: Option<usize>,
    },
    /// Union of multiple types at the same offset.
    /// Used when the same memory location is accessed with different sizes/types.
    Union {
        /// Name of the inferred union.
        name: String,
        /// The alternative types.
        members: Vec<(String, InferredType)>,
    },
}

impl InferredType {
    /// Returns a C-style type string representation.
    pub fn to_c_string(&self) -> String {
        match self {
            InferredType::Unknown => "unknown".to_string(),
            InferredType::SignedInt(size) => match size {
                1 => "int8_t".to_string(),
                2 => "int16_t".to_string(),
                4 => "int32_t".to_string(),
                8 => "int64_t".to_string(),
                _ => format!("int{}_t", size * 8),
            },
            InferredType::UnsignedInt(size) => match size {
                1 => "uint8_t".to_string(),
                2 => "uint16_t".to_string(),
                4 => "uint32_t".to_string(),
                8 => "uint64_t".to_string(),
                _ => format!("uint{}_t", size * 8),
            },
            InferredType::Pointer(inner) => {
                format!("{}*", inner.to_c_string())
            }
            InferredType::StructPointer(name) => {
                format!("struct {}*", name)
            }
            InferredType::Bool => "bool".to_string(),
            InferredType::Float(size) => match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                _ => format!("float{}", size * 8),
            },
            InferredType::Array {
                element_type,
                count,
            } => {
                if let Some(n) = count {
                    format!("{}[{}]", element_type.to_c_string(), n)
                } else {
                    format!("{}[]", element_type.to_c_string())
                }
            }
            InferredType::Union { name, .. } => {
                format!("union {}", name)
            }
        }
    }

    /// Returns the size in bytes, if known.
    pub fn size(&self) -> Option<usize> {
        match self {
            InferredType::Unknown => None,
            InferredType::SignedInt(s) | InferredType::UnsignedInt(s) => Some(*s),
            InferredType::Pointer(_) | InferredType::StructPointer(_) => Some(8), // 64-bit
            InferredType::Bool => Some(1),
            InferredType::Float(s) => Some(*s),
            InferredType::Array {
                element_type,
                count,
            } => {
                let elem_size = element_type.size()?;
                Some(elem_size * (*count)?)
            }
            InferredType::Union { members, .. } => {
                // Union size is the maximum of all member sizes
                members.iter().filter_map(|(_, t)| t.size()).max()
            }
        }
    }
}

impl fmt::Display for InferredType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_c_string())
    }
}

/// Tracks memory access information for a single access.
#[derive(Debug, Clone)]
struct MemoryAccess {
    /// Offset from base.
    offset: usize,
    /// Size of access in bytes.
    size: usize,
    /// Whether this is a read or write (tracked for future write-pattern analysis).
    #[allow(dead_code)]
    is_write: bool,
    /// Whether the value is dereferenced (indicating pointer type).
    is_dereferenced: bool,
    /// Whether arithmetic is performed on the value.
    is_arithmetic: bool,
    /// Whether used in signed comparison.
    is_signed: bool,
    /// Whether used in unsigned comparison.
    is_unsigned: bool,
}

/// Tracks all accesses through a particular base variable.
#[derive(Debug)]
struct BasePointerAccesses {
    /// The base variable name (e.g., "rbx", "arg_0").
    #[allow(dead_code)] // Used as HashMap key, not via field access
    base_name: String,
    /// All accesses through this base, keyed by offset.
    accesses: BTreeMap<usize, Vec<MemoryAccess>>,
}

impl BasePointerAccesses {
    fn new(base_name: String) -> Self {
        Self {
            base_name,
            accesses: BTreeMap::new(),
        }
    }

    fn add_access(&mut self, access: MemoryAccess) {
        self.accesses.entry(access.offset).or_default().push(access);
    }
}

/// Struct inference engine.
///
/// Analyzes memory access patterns in decompiled code to infer struct layouts.
pub struct StructInference {
    /// Accesses grouped by base pointer.
    base_accesses: HashMap<String, BasePointerAccesses>,
    /// Generated struct definitions.
    structs: Vec<InferredStruct>,
    /// Counter for generating struct names.
    struct_counter: usize,
    /// Mapping from base variable to struct name.
    base_to_struct: HashMap<String, String>,
    /// Minimum number of field accesses to consider it a struct.
    min_field_count: usize,
}

impl StructInference {
    /// Creates a new struct inference engine.
    pub fn new() -> Self {
        Self {
            base_accesses: HashMap::new(),
            structs: Vec::new(),
            struct_counter: 0,
            base_to_struct: HashMap::new(),
            min_field_count: 2, // At least 2 fields to be considered a struct
        }
    }

    /// Sets the minimum number of fields required to infer a struct.
    pub fn with_min_field_count(mut self, count: usize) -> Self {
        self.min_field_count = count;
        self
    }

    /// Analyzes structured code to infer struct layouts.
    pub fn analyze(&mut self, nodes: &[StructuredNode]) {
        // Pass 1: Collect all memory accesses
        for node in nodes {
            self.collect_accesses_from_node(node);
        }

        // Pass 2: Analyze usage patterns for type inference
        for node in nodes {
            self.analyze_usage_patterns(node);
        }

        // Pass 3: Generate struct definitions
        self.generate_structs();
    }

    /// Collects memory accesses from a structured node.
    fn collect_accesses_from_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.collect_accesses_from_expr(stmt);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                self.collect_accesses_from_expr(condition);
                for n in then_body {
                    self.collect_accesses_from_node(n);
                }
                if let Some(else_nodes) = else_body {
                    for n in else_nodes {
                        self.collect_accesses_from_node(n);
                    }
                }
            }
            StructuredNode::While {
                condition, body, ..
            } => {
                self.collect_accesses_from_expr(condition);
                for n in body {
                    self.collect_accesses_from_node(n);
                }
            }
            StructuredNode::DoWhile {
                body, condition, ..
            } => {
                for n in body {
                    self.collect_accesses_from_node(n);
                }
                self.collect_accesses_from_expr(condition);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    self.collect_accesses_from_expr(e);
                }
                self.collect_accesses_from_expr(condition);
                if let Some(e) = update {
                    self.collect_accesses_from_expr(e);
                }
                for n in body {
                    self.collect_accesses_from_node(n);
                }
            }
            StructuredNode::Loop { body, .. } => {
                for n in body {
                    self.collect_accesses_from_node(n);
                }
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                self.collect_accesses_from_expr(value);
                for (_, case_body) in cases {
                    for n in case_body {
                        self.collect_accesses_from_node(n);
                    }
                }
                if let Some(def) = default {
                    for n in def {
                        self.collect_accesses_from_node(n);
                    }
                }
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.collect_accesses_from_node(n);
                }
            }
            StructuredNode::Return(Some(e)) => {
                self.collect_accesses_from_expr(e);
            }
            StructuredNode::Expr(e) => {
                self.collect_accesses_from_expr(e);
            }
            _ => {}
        }
    }

    /// Collects memory accesses from an expression.
    fn collect_accesses_from_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                // Check if LHS is a struct field access (write)
                if let Some((base, offset, size)) = self.extract_field_access(lhs) {
                    self.record_access(&base, offset, size, true, false, false);
                }
                // Check RHS for struct field access (read)
                if let Some((base, offset, size)) = self.extract_field_access(rhs) {
                    self.record_access(&base, offset, size, false, false, false);
                }
                // Recurse into subexpressions
                self.collect_accesses_from_expr(lhs);
                self.collect_accesses_from_expr(rhs);
            }
            ExprKind::Deref { addr, size } => {
                if let Some((base, offset, _)) = self.extract_field_access_addr(addr) {
                    self.record_access(&base, offset, *size as usize, false, false, false);
                }
                self.collect_accesses_from_expr(addr);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.collect_accesses_from_expr(left);
                self.collect_accesses_from_expr(right);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.collect_accesses_from_expr(operand);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.collect_accesses_from_expr(arg);
                }
            }
            _ => {}
        }
    }

    /// Records a memory access.
    fn record_access(
        &mut self,
        base: &str,
        offset: usize,
        size: usize,
        is_write: bool,
        is_dereferenced: bool,
        is_arithmetic: bool,
    ) {
        let entry = self
            .base_accesses
            .entry(base.to_string())
            .or_insert_with(|| BasePointerAccesses::new(base.to_string()));

        entry.add_access(MemoryAccess {
            offset,
            size,
            is_write,
            is_dereferenced,
            is_arithmetic,
            is_signed: false,
            is_unsigned: false,
        });
    }

    /// Extracts field access pattern: base + offset with dereference.
    /// Returns (base_name, offset, size).
    fn extract_field_access(&self, expr: &Expr) -> Option<(String, usize, usize)> {
        if let ExprKind::Deref { addr, size } = &expr.kind {
            if let Some((base, offset, _)) = self.extract_field_access_addr(addr) {
                return Some((base, offset, *size as usize));
            }
        }
        None
    }

    /// Extracts field access address pattern: base + offset.
    /// Returns (base_name, offset, size) where size is from the base variable.
    fn extract_field_access_addr(&self, addr: &Expr) -> Option<(String, usize, usize)> {
        match &addr.kind {
            // base + offset
            ExprKind::BinOp {
                op: BinOpKind::Add,
                left,
                right,
            } => {
                // Left is base variable, right is offset
                if let (ExprKind::Var(base), ExprKind::IntLit(offset)) = (&left.kind, &right.kind) {
                    if self.is_valid_base_register(&base.name) && *offset >= 0 {
                        return Some((base.name.clone(), *offset as usize, base.size as usize));
                    }
                }
                // Right is base variable, left is offset (commutative)
                if let (ExprKind::IntLit(offset), ExprKind::Var(base)) = (&left.kind, &right.kind) {
                    if self.is_valid_base_register(&base.name) && *offset >= 0 {
                        return Some((base.name.clone(), *offset as usize, base.size as usize));
                    }
                }
            }
            // base - negative_offset (e.g., rbx + -8 is sometimes represented as rbx - 8)
            ExprKind::BinOp {
                op: BinOpKind::Sub,
                left,
                right,
            } => {
                if let (ExprKind::Var(base), ExprKind::IntLit(offset)) = (&left.kind, &right.kind) {
                    // Negative offset means this isn't a forward struct field
                    // but could be a field before the pointer (rare, but possible)
                    if self.is_valid_base_register(&base.name) && *offset < 0 {
                        return Some((base.name.clone(), (-*offset) as usize, base.size as usize));
                    }
                }
            }
            // Just a variable (offset 0)
            ExprKind::Var(base) => {
                if self.is_valid_base_register(&base.name) {
                    return Some((base.name.clone(), 0, base.size as usize));
                }
            }
            _ => {}
        }
        None
    }

    /// Checks if a register is a valid base for struct access.
    fn is_valid_base_register(&self, name: &str) -> bool {
        // Exclude stack/frame pointers as they are stack slots, not struct pointers
        // Also exclude temporary/scratch registers that are unlikely to hold struct pointers
        !matches!(
            name,
            "rsp" | "rbp" | "sp" | "x29" | "fp" |  // Stack/frame pointers
            "rip" | "pc" |                          // Instruction pointers
            "rflags" | "eflags" // Flags
        )
    }

    /// Analyzes usage patterns to refine type inference.
    fn analyze_usage_patterns(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.analyze_expr_usage(stmt);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Check if condition involves a field access
                self.mark_comparison_types(condition);
                self.analyze_usage_patterns_list(then_body);
                if let Some(else_nodes) = else_body {
                    self.analyze_usage_patterns_list(else_nodes);
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.mark_comparison_types(condition);
                self.analyze_usage_patterns_list(body);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    self.analyze_expr_usage(e);
                }
                self.mark_comparison_types(condition);
                if let Some(e) = update {
                    self.analyze_expr_usage(e);
                }
                self.analyze_usage_patterns_list(body);
            }
            StructuredNode::Loop { body, .. } => {
                self.analyze_usage_patterns_list(body);
            }
            StructuredNode::Switch { cases, default, .. } => {
                for (_, case_body) in cases {
                    self.analyze_usage_patterns_list(case_body);
                }
                if let Some(def) = default {
                    self.analyze_usage_patterns_list(def);
                }
            }
            StructuredNode::Sequence(nodes) => {
                self.analyze_usage_patterns_list(nodes);
            }
            StructuredNode::Return(Some(e)) => {
                self.analyze_expr_usage(e);
            }
            StructuredNode::Expr(e) => {
                self.analyze_expr_usage(e);
            }
            _ => {}
        }
    }

    fn analyze_usage_patterns_list(&mut self, nodes: &[StructuredNode]) {
        for node in nodes {
            self.analyze_usage_patterns(node);
        }
    }

    /// Analyzes expression usage for type information.
    fn analyze_expr_usage(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                // Check if RHS is dereferenced (assigned to a pointer that's later dereferenced)
                if let Some((base, offset, size)) = self.extract_field_access(rhs) {
                    // If LHS is also dereferenced later, this field is a pointer
                    if let ExprKind::Deref { .. } = &lhs.kind {
                        self.mark_field_as_pointer(&base, offset, size);
                    }
                }
                // Check if RHS involves arithmetic on a field
                if let ExprKind::BinOp { op, left, .. } = &rhs.kind {
                    if is_arithmetic_op(*op) {
                        if let Some((base, offset, size)) = self.extract_field_access(left) {
                            self.mark_field_as_arithmetic(&base, offset, size);
                        }
                    }
                }
                self.analyze_expr_usage(lhs);
                self.analyze_expr_usage(rhs);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.analyze_expr_usage(left);
                self.analyze_expr_usage(right);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.analyze_expr_usage(operand);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.analyze_expr_usage(arg);
                }
            }
            ExprKind::Deref { addr, .. } => {
                self.analyze_expr_usage(addr);
            }
            _ => {}
        }
    }

    /// Marks a field as being used in comparison (for signedness).
    fn mark_comparison_types(&mut self, condition: &Expr) {
        if let ExprKind::BinOp { op, left, right } = &condition.kind {
            let is_signed = matches!(
                op,
                BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge
            );
            let is_unsigned = matches!(
                op,
                BinOpKind::ULt | BinOpKind::ULe | BinOpKind::UGt | BinOpKind::UGe
            );

            if let Some((base, offset, size)) = self.extract_field_access(left) {
                self.mark_field_signedness(&base, offset, size, is_signed, is_unsigned);
            }
            if let Some((base, offset, size)) = self.extract_field_access(right) {
                self.mark_field_signedness(&base, offset, size, is_signed, is_unsigned);
            }
        }
    }

    fn mark_field_as_pointer(&mut self, base: &str, offset: usize, _size: usize) {
        if let Some(accesses) = self.base_accesses.get_mut(base) {
            if let Some(access_list) = accesses.accesses.get_mut(&offset) {
                for access in access_list.iter_mut() {
                    access.is_dereferenced = true;
                }
            }
        }
    }

    fn mark_field_as_arithmetic(&mut self, base: &str, offset: usize, _size: usize) {
        if let Some(accesses) = self.base_accesses.get_mut(base) {
            if let Some(access_list) = accesses.accesses.get_mut(&offset) {
                for access in access_list.iter_mut() {
                    access.is_arithmetic = true;
                }
            }
        }
    }

    fn mark_field_signedness(
        &mut self,
        base: &str,
        offset: usize,
        _size: usize,
        is_signed: bool,
        is_unsigned: bool,
    ) {
        if let Some(accesses) = self.base_accesses.get_mut(base) {
            if let Some(access_list) = accesses.accesses.get_mut(&offset) {
                for access in access_list.iter_mut() {
                    access.is_signed = access.is_signed || is_signed;
                    access.is_unsigned = access.is_unsigned || is_unsigned;
                }
            }
        }
    }

    /// Generates struct definitions from collected accesses.
    fn generate_structs(&mut self) {
        for (base_name, accesses) in &self.base_accesses {
            // Only create a struct if there are multiple field accesses
            if accesses.accesses.len() < self.min_field_count {
                continue;
            }

            // Skip if this looks like a stack frame (all negative offsets)
            // This is handled by the existing stack slot analysis

            let mut fields = Vec::new();
            let mut max_end = 0usize;

            // Collect all field data first
            let field_data: Vec<_> = accesses
                .accesses
                .iter()
                .map(|(&offset, access_list)| {
                    let size = access_list.iter().map(|a| a.size).max().unwrap_or(8);
                    (offset, size, access_list.clone())
                })
                .collect();

            for (offset, size, access_list) in field_data {
                // Infer type from usage (may be a union if multiple sizes)
                let field_type = self.infer_field_type(&access_list, size, offset);

                let field = InferredField {
                    offset,
                    size,
                    field_type,
                    name: format!("field_{:x}", offset),
                };

                max_end = max_end.max(offset + size);
                fields.push(field);
            }

            // Sort fields by offset
            fields.sort_by_key(|f| f.offset);

            // Create struct
            let struct_name = format!("struct_{}", self.struct_counter);
            self.struct_counter += 1;

            let inferred_struct = InferredStruct {
                name: struct_name.clone(),
                fields,
                size: Some(max_end),
                access_count: accesses.accesses.values().map(|v| v.len()).sum(),
            };

            self.base_to_struct.insert(base_name.clone(), struct_name);
            self.structs.push(inferred_struct);
        }
    }

    /// Infers the type of a field from its accesses.
    fn infer_field_type(
        &self,
        accesses: &[MemoryAccess],
        size: usize,
        offset: usize,
    ) -> InferredType {
        // Collect unique sizes accessed at this offset
        let mut unique_sizes: Vec<usize> = accesses.iter().map(|a| a.size).collect();
        unique_sizes.sort();
        unique_sizes.dedup();

        // If multiple different sizes are used, this is likely a union
        if unique_sizes.len() > 1 {
            let union_name = format!("union_{:x}", offset);
            let mut members = Vec::new();

            for &member_size in &unique_sizes {
                let member_name = format!("as_{}", size_name(member_size));
                let member_type = self.infer_simple_type(accesses, member_size);
                members.push((member_name, member_type));
            }

            return InferredType::Union {
                name: union_name,
                members,
            };
        }

        self.infer_simple_type(accesses, size)
    }

    /// Infers a simple (non-union) type from accesses.
    fn infer_simple_type(&self, accesses: &[MemoryAccess], size: usize) -> InferredType {
        // Check if any access shows this is a pointer (dereferenced)
        if accesses.iter().any(|a| a.is_dereferenced) {
            return InferredType::Pointer(Box::new(InferredType::Unknown));
        }

        // Check for signedness from comparisons
        let is_signed = accesses.iter().any(|a| a.is_signed);
        let is_unsigned = accesses.iter().any(|a| a.is_unsigned);

        if is_signed && !is_unsigned {
            InferredType::SignedInt(size)
        } else if is_unsigned && !is_signed {
            InferredType::UnsignedInt(size)
        } else {
            // Default to unsigned for ambiguous cases
            InferredType::UnsignedInt(size)
        }
    }

    /// Returns all inferred structs.
    pub fn structs(&self) -> &[InferredStruct] {
        &self.structs
    }

    /// Returns the struct associated with a base variable, if any.
    pub fn struct_for_base(&self, base: &str) -> Option<&InferredStruct> {
        let struct_name = self.base_to_struct.get(base)?;
        self.structs.iter().find(|s| &s.name == struct_name)
    }

    /// Transforms expressions to use field access syntax.
    ///
    /// This converts patterns like `*(base + 8)` to `base->field_8`.
    pub fn transform_expr(&self, expr: &Expr) -> Expr {
        self.transform_expr_inner(expr, false)
    }

    fn transform_expr_inner(&self, expr: &Expr, _in_address_of: bool) -> Expr {
        match &expr.kind {
            ExprKind::Deref { addr, size } => {
                // Check if this is a struct field access
                if let Some((base, offset, _)) = self.extract_field_access_addr(addr) {
                    if let Some(struct_def) = self.struct_for_base(&base) {
                        // Find the field at this offset
                        if let Some(field) = struct_def.fields.iter().find(|f| f.offset == offset) {
                            return Expr {
                                kind: ExprKind::FieldAccess {
                                    base: Box::new(Expr::var(Variable {
                                        kind: VarKind::Register(0),
                                        name: base,
                                        size: 8,
                                    })),
                                    field_name: field.name.clone(),
                                    offset,
                                },
                            };
                        }
                    }
                }
                // Not a struct field, transform the address recursively
                Expr {
                    kind: ExprKind::Deref {
                        addr: Box::new(self.transform_expr_inner(addr, false)),
                        size: *size,
                    },
                }
            }
            ExprKind::Assign { lhs, rhs } => Expr {
                kind: ExprKind::Assign {
                    lhs: Box::new(self.transform_expr_inner(lhs, false)),
                    rhs: Box::new(self.transform_expr_inner(rhs, false)),
                },
            },
            ExprKind::BinOp { op, left, right } => Expr {
                kind: ExprKind::BinOp {
                    op: *op,
                    left: Box::new(self.transform_expr_inner(left, false)),
                    right: Box::new(self.transform_expr_inner(right, false)),
                },
            },
            ExprKind::UnaryOp { op, operand } => Expr {
                kind: ExprKind::UnaryOp {
                    op: *op,
                    operand: Box::new(self.transform_expr_inner(operand, false)),
                },
            },
            ExprKind::Call { target, args } => Expr {
                kind: ExprKind::Call {
                    target: target.clone(),
                    args: args
                        .iter()
                        .map(|a| self.transform_expr_inner(a, false))
                        .collect(),
                },
            },
            ExprKind::AddressOf(inner) => Expr {
                kind: ExprKind::AddressOf(Box::new(self.transform_expr_inner(inner, true))),
            },
            // Other expressions pass through unchanged
            _ => expr.clone(),
        }
    }

    /// Transforms all expressions in a structured node.
    pub fn transform_node(&self, node: &StructuredNode) -> StructuredNode {
        match node {
            StructuredNode::Block {
                id,
                statements,
                address_range,
            } => StructuredNode::Block {
                id: *id,
                statements: statements.iter().map(|s| self.transform_expr(s)).collect(),
                address_range: *address_range,
            },
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => StructuredNode::If {
                condition: self.transform_expr(condition),
                then_body: then_body.iter().map(|n| self.transform_node(n)).collect(),
                else_body: else_body
                    .as_ref()
                    .map(|nodes| nodes.iter().map(|n| self.transform_node(n)).collect()),
            },
            StructuredNode::While {
                condition,
                body,
                header,
                exit_block,
            } => StructuredNode::While {
                condition: self.transform_expr(condition),
                body: body.iter().map(|n| self.transform_node(n)).collect(),
                header: *header,
                exit_block: *exit_block,
            },
            StructuredNode::DoWhile {
                body,
                condition,
                header,
                exit_block,
            } => StructuredNode::DoWhile {
                body: body.iter().map(|n| self.transform_node(n)).collect(),
                condition: self.transform_expr(condition),
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
                init: init.as_ref().map(|e| self.transform_expr(e)),
                condition: self.transform_expr(condition),
                update: update.as_ref().map(|e| self.transform_expr(e)),
                body: body.iter().map(|n| self.transform_node(n)).collect(),
                header: *header,
                exit_block: *exit_block,
            },
            StructuredNode::Loop {
                body,
                header,
                exit_block,
            } => StructuredNode::Loop {
                body: body.iter().map(|n| self.transform_node(n)).collect(),
                header: *header,
                exit_block: *exit_block,
            },
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => StructuredNode::Switch {
                value: self.transform_expr(value),
                cases: cases
                    .iter()
                    .map(|(vals, body)| {
                        (
                            vals.clone(),
                            body.iter().map(|n| self.transform_node(n)).collect(),
                        )
                    })
                    .collect(),
                default: default
                    .as_ref()
                    .map(|nodes| nodes.iter().map(|n| self.transform_node(n)).collect()),
            },
            StructuredNode::Sequence(nodes) => {
                StructuredNode::Sequence(nodes.iter().map(|n| self.transform_node(n)).collect())
            }
            StructuredNode::Return(Some(e)) => StructuredNode::Return(Some(self.transform_expr(e))),
            StructuredNode::Expr(e) => StructuredNode::Expr(self.transform_expr(e)),
            // Other nodes pass through unchanged
            _ => node.clone(),
        }
    }

    /// Generates C-style struct definitions as a string.
    pub fn generate_struct_definitions(&self) -> String {
        let mut output = String::new();

        // First, output any union type definitions used by the structs
        for s in &self.structs {
            for field in &s.fields {
                if let InferredType::Union { name, members } = &field.field_type {
                    output.push_str(&format!("union {} {{\n", name));
                    for (member_name, member_type) in members {
                        output.push_str(&format!(
                            "    {} {};\n",
                            member_type.to_c_string(),
                            member_name
                        ));
                    }
                    output.push_str("};\n\n");
                }
            }
        }

        // Then output struct definitions
        for s in &self.structs {
            output.push_str(&format!("struct {} {{\n", s.name));

            let mut prev_end = 0;
            for field in &s.fields {
                // Check for padding
                if field.offset > prev_end {
                    let padding = field.offset - prev_end;
                    output.push_str(&format!("    char _padding_{}[{}];\n", prev_end, padding));
                }

                output.push_str(&format!(
                    "    {} {};  // offset {:#x}\n",
                    field.field_type.to_c_string(),
                    field.name,
                    field.offset
                ));

                prev_end = field.offset + field.size;
            }

            output.push_str("};\n\n");
        }

        output
    }
}

impl Default for StructInference {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns a human-readable name for a size in bytes.
fn size_name(size: usize) -> &'static str {
    match size {
        1 => "byte",
        2 => "word",
        4 => "dword",
        8 => "qword",
        16 => "xmmword",
        _ => "data",
    }
}

/// Checks if an operator is an arithmetic operation.
fn is_arithmetic_op(op: BinOpKind) -> bool {
    matches!(
        op,
        BinOpKind::Add
            | BinOpKind::Sub
            | BinOpKind::Mul
            | BinOpKind::Div
            | BinOpKind::Mod
            | BinOpKind::And
            | BinOpKind::Or
            | BinOpKind::Xor
            | BinOpKind::Shl
            | BinOpKind::Shr
            | BinOpKind::Sar
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};
    use hexray_core::BasicBlockId;

    fn make_var(name: &str, size: u8) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Register(0),
            name: name.to_string(),
            size,
        })
    }

    fn make_field_access(base: &str, offset: i128, size: u8) -> Expr {
        let base_expr = make_var(base, 8);
        let offset_expr = Expr::int(offset);
        let addr = Expr::binop(BinOpKind::Add, base_expr, offset_expr);
        Expr::deref(addr, size)
    }

    #[test]
    fn test_basic_struct_inference() {
        let mut inference = StructInference::new().with_min_field_count(2);

        // Create some struct field accesses through rbx
        let access1 = make_field_access("rbx", 0, 8);
        let access2 = make_field_access("rbx", 8, 4);
        let access3 = make_field_access("rbx", 16, 8);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(make_var("rax", 8), access1),
                Expr::assign(make_var("ecx", 4), access2),
                Expr::assign(make_var("rdx", 8), access3),
            ],
            address_range: (0x1000, 0x1020),
        };

        inference.analyze(&[block]);

        // Should have inferred one struct
        assert_eq!(inference.structs().len(), 1);

        let s = &inference.structs()[0];
        assert_eq!(s.fields.len(), 3);
        assert_eq!(s.fields[0].offset, 0);
        assert_eq!(s.fields[1].offset, 8);
        assert_eq!(s.fields[2].offset, 16);
    }

    #[test]
    fn test_field_type_inference() {
        let mut inference = StructInference::new().with_min_field_count(2);

        // Create accesses with different sizes
        let access_byte = make_field_access("rdi", 0, 1);
        let access_word = make_field_access("rdi", 2, 2);
        let access_dword = make_field_access("rdi", 4, 4);
        let access_qword = make_field_access("rdi", 8, 8);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(make_var("al", 1), access_byte),
                Expr::assign(make_var("ax", 2), access_word),
                Expr::assign(make_var("eax", 4), access_dword),
                Expr::assign(make_var("rax", 8), access_qword),
            ],
            address_range: (0x1000, 0x1020),
        };

        inference.analyze(&[block]);

        let s = &inference.structs()[0];
        assert_eq!(s.fields[0].size, 1);
        assert_eq!(s.fields[1].size, 2);
        assert_eq!(s.fields[2].size, 4);
        assert_eq!(s.fields[3].size, 8);
    }

    #[test]
    fn test_inferred_type_display() {
        assert_eq!(InferredType::SignedInt(4).to_c_string(), "int32_t");
        assert_eq!(InferredType::UnsignedInt(8).to_c_string(), "uint64_t");
        assert_eq!(
            InferredType::Pointer(Box::new(InferredType::SignedInt(1))).to_c_string(),
            "int8_t*"
        );
        assert_eq!(
            InferredType::StructPointer("foo".to_string()).to_c_string(),
            "struct foo*"
        );
    }

    #[test]
    fn test_struct_definition_generation() {
        let s = InferredStruct {
            name: "my_struct".to_string(),
            fields: vec![
                InferredField {
                    offset: 0,
                    size: 8,
                    field_type: InferredType::Pointer(Box::new(InferredType::Unknown)),
                    name: "field_0".to_string(),
                },
                InferredField {
                    offset: 8,
                    size: 4,
                    field_type: InferredType::SignedInt(4),
                    name: "field_8".to_string(),
                },
                InferredField {
                    offset: 16,
                    size: 8,
                    field_type: InferredType::UnsignedInt(8),
                    name: "field_10".to_string(),
                },
            ],
            size: Some(24),
            access_count: 5,
        };

        let inference = StructInference {
            base_accesses: HashMap::new(),
            structs: vec![s],
            struct_counter: 1,
            base_to_struct: HashMap::new(),
            min_field_count: 2,
        };

        let output = inference.generate_struct_definitions();
        assert!(output.contains("struct my_struct"));
        assert!(output.contains("field_0"));
        assert!(output.contains("field_8"));
        assert!(output.contains("field_10"));
        assert!(output.contains("unknown*")); // pointer to unknown
        assert!(output.contains("int32_t"));
        assert!(output.contains("uint64_t"));
    }

    #[test]
    fn test_no_struct_for_single_access() {
        let mut inference = StructInference::new().with_min_field_count(2);

        // Only one field access - should not create a struct
        let access = make_field_access("rcx", 0, 8);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![Expr::assign(make_var("rax", 8), access)],
            address_range: (0x1000, 0x1010),
        };

        inference.analyze(&[block]);

        // Should have no structs
        assert!(inference.structs().is_empty());
    }

    #[test]
    fn test_transform_to_field_access() {
        let mut inference = StructInference::new().with_min_field_count(2);

        // Create accesses
        let access1 = make_field_access("rsi", 0, 8);
        let access2 = make_field_access("rsi", 8, 4);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(make_var("rax", 8), access1.clone()),
                Expr::assign(make_var("ecx", 4), access2.clone()),
            ],
            address_range: (0x1000, 0x1020),
        };

        inference.analyze(std::slice::from_ref(&block));

        // Transform the block
        let transformed = inference.transform_node(&block);

        // Verify transformation
        if let StructuredNode::Block { statements, .. } = transformed {
            // First statement should now use FieldAccess
            if let ExprKind::Assign { rhs, .. } = &statements[0].kind {
                assert!(matches!(rhs.kind, ExprKind::FieldAccess { .. }));
            } else {
                panic!("Expected assignment");
            }
        } else {
            panic!("Expected Block");
        }
    }

    #[test]
    fn test_union_inference_from_different_sizes() {
        let mut inference = StructInference::new().with_min_field_count(2);

        // Access the same offset with different sizes - this indicates a union
        let access_qword = make_field_access("rbx", 0, 8);
        let access_dword = make_field_access("rbx", 0, 4);
        let access_other = make_field_access("rbx", 8, 8);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![
                Expr::assign(make_var("rax", 8), access_qword),
                Expr::assign(make_var("eax", 4), access_dword),
                Expr::assign(make_var("rdx", 8), access_other),
            ],
            address_range: (0x1000, 0x1030),
        };

        inference.analyze(&[block]);

        // Should have inferred one struct
        assert_eq!(inference.structs().len(), 1);

        let s = &inference.structs()[0];
        // Should have 2 fields: one at offset 0 (union) and one at offset 8
        assert_eq!(s.fields.len(), 2);

        // First field at offset 0 should be a union
        let field_0 = &s.fields[0];
        assert_eq!(field_0.offset, 0);
        assert!(
            matches!(&field_0.field_type, InferredType::Union { members, .. } if members.len() == 2)
        );

        // Union should have dword and qword members
        if let InferredType::Union { members, .. } = &field_0.field_type {
            let sizes: Vec<_> = members.iter().filter_map(|(_, t)| t.size()).collect();
            assert!(sizes.contains(&4));
            assert!(sizes.contains(&8));
        }
    }

    #[test]
    fn test_union_type_display() {
        let union_type = InferredType::Union {
            name: "test_union".to_string(),
            members: vec![
                ("as_dword".to_string(), InferredType::UnsignedInt(4)),
                ("as_qword".to_string(), InferredType::UnsignedInt(8)),
            ],
        };

        assert_eq!(union_type.to_c_string(), "union test_union");
        assert_eq!(union_type.size(), Some(8)); // Max of member sizes
    }

    #[test]
    fn test_generate_union_definitions() {
        let s = InferredStruct {
            name: "my_struct".to_string(),
            fields: vec![InferredField {
                offset: 0,
                size: 8,
                field_type: InferredType::Union {
                    name: "union_0".to_string(),
                    members: vec![
                        ("as_dword".to_string(), InferredType::UnsignedInt(4)),
                        ("as_qword".to_string(), InferredType::UnsignedInt(8)),
                    ],
                },
                name: "field_0".to_string(),
            }],
            size: Some(8),
            access_count: 3,
        };

        let inference = StructInference {
            base_accesses: HashMap::new(),
            structs: vec![s],
            struct_counter: 1,
            base_to_struct: HashMap::new(),
            min_field_count: 2,
        };

        let output = inference.generate_struct_definitions();
        // Should contain union definition
        assert!(output.contains("union union_0"));
        assert!(output.contains("as_dword"));
        assert!(output.contains("as_qword"));
        // Should contain struct definition
        assert!(output.contains("struct my_struct"));
        assert!(output.contains("union union_0 field_0"));
    }
}
