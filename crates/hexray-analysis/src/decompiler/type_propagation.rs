//! Expression-level type propagation for the decompiler.
//!
//! This module provides advanced type inference that works on high-level expressions,
//! propagating types through:
//!
//! - Function calls (arguments inherit types from known function signatures)
//! - Comparisons with character constants
//! - Pointer dereferences (tracking pointee types)
//! - Array access patterns (inferring element types)
//! - Arithmetic and bitwise operations
//!
//! This complements the SSA-level type inference by working on structured expressions
//! after the CFG has been lifted to high-level form.

use super::expression::{BinOpKind, CallTarget, Expr, ExprKind, UnaryOpKind};
use super::structurer::StructuredNode;
use std::collections::HashMap;

/// Inferred type for an expression.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ExprType {
    /// Unknown type.
    #[default]
    Unknown,
    /// Void type.
    Void,
    /// Boolean type (from comparisons).
    Bool,
    /// Character type (signed or unsigned 8-bit).
    Char { signed: bool },
    /// Integer with size in bytes and signedness.
    Int { size: u8, signed: bool },
    /// Floating-point type with size in bytes.
    Float { size: u8 },
    /// Pointer to another type.
    Pointer(Box<ExprType>),
    /// Array with element type and optional count.
    Array {
        element: Box<ExprType>,
        count: Option<usize>,
    },
    /// Function pointer.
    FunctionPointer {
        return_type: Box<ExprType>,
        params: Vec<ExprType>,
    },
    /// C-style string (char*).
    CString,
}

impl ExprType {
    /// Creates an integer type.
    pub fn int(size: u8, signed: bool) -> Self {
        ExprType::Int { size, signed }
    }

    /// Creates an unsigned integer.
    pub fn uint(size: u8) -> Self {
        ExprType::Int {
            size,
            signed: false,
        }
    }

    /// Creates a signed integer.
    pub fn sint(size: u8) -> Self {
        ExprType::Int { size, signed: true }
    }

    /// Creates a pointer type.
    pub fn ptr(pointee: ExprType) -> Self {
        ExprType::Pointer(Box::new(pointee))
    }

    /// Creates a char type.
    pub fn char(signed: bool) -> Self {
        ExprType::Char { signed }
    }

    /// Returns true if this is a pointer type.
    pub fn is_pointer(&self) -> bool {
        matches!(self, ExprType::Pointer(_) | ExprType::CString)
    }

    /// Returns true if this is a character type.
    pub fn is_char(&self) -> bool {
        matches!(self, ExprType::Char { .. })
    }

    /// Returns true if this is a numeric type.
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            ExprType::Int { .. } | ExprType::Float { .. } | ExprType::Char { .. }
        )
    }

    /// Returns the size in bytes, if known.
    pub fn size(&self) -> Option<u8> {
        match self {
            ExprType::Unknown | ExprType::Void => None,
            ExprType::Bool => Some(1),
            ExprType::Char { .. } => Some(1),
            ExprType::Int { size, .. } => Some(*size),
            ExprType::Float { size } => Some(*size),
            ExprType::Pointer(_) | ExprType::FunctionPointer { .. } | ExprType::CString => Some(8),
            ExprType::Array { element, count } => {
                let elem_size = element.size()?;
                Some(elem_size * (*count)? as u8)
            }
        }
    }

    /// Dereferences a pointer type, returning the pointee type.
    pub fn deref(&self) -> ExprType {
        match self {
            ExprType::Pointer(inner) => (**inner).clone(),
            ExprType::CString => ExprType::Char { signed: true },
            ExprType::Array { element, .. } => (**element).clone(),
            _ => ExprType::Unknown,
        }
    }

    /// Creates an address-of type (pointer to this type).
    pub fn address_of(&self) -> ExprType {
        ExprType::Pointer(Box::new(self.clone()))
    }

    /// Merges two types, taking the more specific one.
    pub fn merge(&self, other: &ExprType) -> ExprType {
        match (self, other) {
            (ExprType::Unknown, t) | (t, ExprType::Unknown) => t.clone(),
            // Char is more specific than Int
            (ExprType::Char { signed }, ExprType::Int { size: 1, .. })
            | (ExprType::Int { size: 1, .. }, ExprType::Char { signed }) => {
                ExprType::Char { signed: *signed }
            }
            // Int merging
            (
                ExprType::Int {
                    size: s1,
                    signed: sg1,
                },
                ExprType::Int {
                    size: s2,
                    signed: sg2,
                },
            ) => ExprType::Int {
                size: (*s1).max(*s2),
                signed: *sg1 || *sg2,
            },
            // Pointer merging
            (ExprType::Pointer(p1), ExprType::Pointer(p2)) => {
                ExprType::Pointer(Box::new(p1.merge(p2)))
            }
            // CString is more specific than char*
            (ExprType::CString, ExprType::Pointer(_))
            | (ExprType::Pointer(_), ExprType::CString) => ExprType::CString,
            // Default: keep first
            _ => self.clone(),
        }
    }

    /// Converts to a C-style type string.
    pub fn to_c_string(&self) -> String {
        match self {
            ExprType::Unknown => "int".to_string(),
            ExprType::Void => "void".to_string(),
            ExprType::Bool => "bool".to_string(),
            ExprType::Char { signed: true } => "char".to_string(),
            ExprType::Char { signed: false } => "unsigned char".to_string(),
            ExprType::Int { size, signed } => match (size, signed) {
                (1, true) => "int8_t".to_string(),
                (1, false) => "uint8_t".to_string(),
                (2, true) => "int16_t".to_string(),
                (2, false) => "uint16_t".to_string(),
                (4, true) => "int".to_string(),
                (4, false) => "unsigned int".to_string(),
                (8, true) => "int64_t".to_string(),
                (8, false) => "uint64_t".to_string(),
                _ => {
                    if *signed {
                        "int".to_string()
                    } else {
                        "unsigned int".to_string()
                    }
                }
            },
            ExprType::Float { size } => match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                16 => "long double".to_string(),
                _ => "double".to_string(),
            },
            ExprType::Pointer(inner) => format!("{}*", inner.to_c_string()),
            ExprType::Array { element, count } => {
                if let Some(n) = count {
                    format!("{}[{}]", element.to_c_string(), n)
                } else {
                    format!("{}[]", element.to_c_string())
                }
            }
            ExprType::FunctionPointer {
                return_type,
                params,
            } => {
                let param_strs: Vec<_> = params.iter().map(|p| p.to_c_string()).collect();
                format!(
                    "{}(*)({})",
                    return_type.to_c_string(),
                    param_strs.join(", ")
                )
            }
            ExprType::CString => "char*".to_string(),
        }
    }
}

/// Known function signature for type propagation.
#[derive(Debug, Clone)]
pub struct KnownSignature {
    /// Return type of the function.
    pub return_type: ExprType,
    /// Parameter types.
    pub params: Vec<ExprType>,
    /// Whether the function is variadic.
    pub variadic: bool,
}

/// Expression-level type propagation engine.
///
/// This analyzes structured code to infer and propagate types through expressions.
pub struct ExpressionTypePropagation {
    /// Known function signatures.
    signatures: HashMap<String, KnownSignature>,
    /// Inferred types for variables (var_name -> type).
    variable_types: HashMap<String, ExprType>,
    /// Type hints from context (e.g., comparison with char constant).
    context_hints: HashMap<String, ExprType>,
}

impl ExpressionTypePropagation {
    /// Creates a new type propagation engine.
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
            variable_types: HashMap::new(),
            context_hints: HashMap::new(),
        }
    }

    /// Creates an engine with standard C library signatures.
    pub fn with_libc() -> Self {
        let mut engine = Self::new();
        engine.add_libc_signatures();
        engine
    }

    /// Adds a known function signature.
    pub fn add_signature(&mut self, name: impl Into<String>, sig: KnownSignature) {
        self.signatures.insert(name.into(), sig);
    }

    /// Adds standard C library function signatures.
    fn add_libc_signatures(&mut self) {
        // String functions with char* parameters
        self.add_signature(
            "strlen",
            KnownSignature {
                return_type: ExprType::uint(8),
                params: vec![ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "strcmp",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString, ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "strncmp",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString, ExprType::CString, ExprType::uint(8)],
                variadic: false,
            },
        );
        self.add_signature(
            "strcpy",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "strncpy",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::CString, ExprType::uint(8)],
                variadic: false,
            },
        );
        self.add_signature(
            "strcat",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "strchr",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::sint(4)], // char is promoted to int
                variadic: false,
            },
        );
        self.add_signature(
            "strrchr",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::sint(4)],
                variadic: false,
            },
        );
        self.add_signature(
            "strstr",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString, ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "strdup",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString],
                variadic: false,
            },
        );

        // Character classification functions (ctype.h)
        let char_func_sig = KnownSignature {
            return_type: ExprType::sint(4),
            params: vec![ExprType::sint(4)], // takes int (promoted char)
            variadic: false,
        };
        for func in [
            "isalpha", "isdigit", "isalnum", "isspace", "isupper", "islower", "isprint", "iscntrl",
            "ispunct", "isxdigit", "isgraph", "isblank",
        ] {
            self.add_signature(func, char_func_sig.clone());
        }
        self.add_signature(
            "toupper",
            KnownSignature {
                return_type: ExprType::sint(4), // returns int (promoted char)
                params: vec![ExprType::sint(4)],
                variadic: false,
            },
        );
        self.add_signature(
            "tolower",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::sint(4)],
                variadic: false,
            },
        );

        // Memory functions
        self.add_signature(
            "memcpy",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::ptr(ExprType::Void),
                    ExprType::uint(8),
                ],
                variadic: false,
            },
        );
        self.add_signature(
            "memmove",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::ptr(ExprType::Void),
                    ExprType::uint(8),
                ],
                variadic: false,
            },
        );
        self.add_signature(
            "memset",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::sint(4),
                    ExprType::uint(8),
                ],
                variadic: false,
            },
        );
        self.add_signature(
            "memcmp",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::ptr(ExprType::Void),
                    ExprType::uint(8),
                ],
                variadic: false,
            },
        );

        // I/O functions
        self.add_signature(
            "getchar",
            KnownSignature {
                return_type: ExprType::sint(4), // returns int (can be EOF)
                params: vec![],
                variadic: false,
            },
        );
        self.add_signature(
            "putchar",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::sint(4)],
                variadic: false,
            },
        );
        self.add_signature(
            "getc",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "putc",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::sint(4), ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "fgetc",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "fputc",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::sint(4), ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "fgets",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![
                    ExprType::CString,
                    ExprType::sint(4),
                    ExprType::ptr(ExprType::Void),
                ],
                variadic: false,
            },
        );
        self.add_signature(
            "fputs",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString, ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "puts",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "gets",
            KnownSignature {
                return_type: ExprType::CString,
                params: vec![ExprType::CString],
                variadic: false,
            },
        );

        // Printf family
        self.add_signature(
            "printf",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString],
                variadic: true,
            },
        );
        self.add_signature(
            "fprintf",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::ptr(ExprType::Void), ExprType::CString],
                variadic: true,
            },
        );
        self.add_signature(
            "sprintf",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString, ExprType::CString],
                variadic: true,
            },
        );
        self.add_signature(
            "snprintf",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::CString, ExprType::uint(8), ExprType::CString],
                variadic: true,
            },
        );

        // Memory allocation
        self.add_signature(
            "malloc",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![ExprType::uint(8)],
                variadic: false,
            },
        );
        self.add_signature(
            "calloc",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![ExprType::uint(8), ExprType::uint(8)],
                variadic: false,
            },
        );
        self.add_signature(
            "realloc",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![ExprType::ptr(ExprType::Void), ExprType::uint(8)],
                variadic: false,
            },
        );
        self.add_signature(
            "free",
            KnownSignature {
                return_type: ExprType::Void,
                params: vec![ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );

        // File I/O
        self.add_signature(
            "fopen",
            KnownSignature {
                return_type: ExprType::ptr(ExprType::Void),
                params: vec![ExprType::CString, ExprType::CString],
                variadic: false,
            },
        );
        self.add_signature(
            "fclose",
            KnownSignature {
                return_type: ExprType::sint(4),
                params: vec![ExprType::ptr(ExprType::Void)],
                variadic: false,
            },
        );
        self.add_signature(
            "fread",
            KnownSignature {
                return_type: ExprType::uint(8),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::uint(8),
                    ExprType::uint(8),
                    ExprType::ptr(ExprType::Void),
                ],
                variadic: false,
            },
        );
        self.add_signature(
            "fwrite",
            KnownSignature {
                return_type: ExprType::uint(8),
                params: vec![
                    ExprType::ptr(ExprType::Void),
                    ExprType::uint(8),
                    ExprType::uint(8),
                    ExprType::ptr(ExprType::Void),
                ],
                variadic: false,
            },
        );
    }

    /// Analyzes structured code to propagate types.
    pub fn analyze(&mut self, nodes: &[StructuredNode]) {
        // Pass 1: Collect type hints from context
        for node in nodes {
            self.collect_type_hints_from_node(node);
        }

        // Pass 2: Propagate types through expressions
        for node in nodes {
            self.propagate_types_in_node(node);
        }

        // Pass 3: Propagate through function calls
        for node in nodes {
            self.propagate_call_types_in_node(node);
        }
    }

    /// Collects type hints from a structured node.
    fn collect_type_hints_from_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.collect_type_hints_from_expr(stmt);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                // Comparisons in conditions provide type hints
                self.collect_comparison_hints(condition);
                self.collect_type_hints_from_expr(condition);
                for n in then_body {
                    self.collect_type_hints_from_node(n);
                }
                if let Some(else_nodes) = else_body {
                    for n in else_nodes {
                        self.collect_type_hints_from_node(n);
                    }
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.collect_comparison_hints(condition);
                self.collect_type_hints_from_expr(condition);
                for n in body {
                    self.collect_type_hints_from_node(n);
                }
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    self.collect_type_hints_from_expr(e);
                }
                self.collect_comparison_hints(condition);
                self.collect_type_hints_from_expr(condition);
                if let Some(e) = update {
                    self.collect_type_hints_from_expr(e);
                }
                for n in body {
                    self.collect_type_hints_from_node(n);
                }
            }
            StructuredNode::Loop { body, .. } => {
                for n in body {
                    self.collect_type_hints_from_node(n);
                }
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                self.collect_type_hints_from_expr(value);
                for (_, case_body) in cases {
                    for n in case_body {
                        self.collect_type_hints_from_node(n);
                    }
                }
                if let Some(def) = default {
                    for n in def {
                        self.collect_type_hints_from_node(n);
                    }
                }
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.collect_type_hints_from_node(n);
                }
            }
            StructuredNode::Return(Some(e)) => {
                self.collect_type_hints_from_expr(e);
            }
            StructuredNode::Expr(e) => {
                self.collect_type_hints_from_expr(e);
            }
            _ => {}
        }
    }

    /// Collects type hints from an expression.
    fn collect_type_hints_from_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                self.collect_type_hints_from_expr(lhs);
                self.collect_type_hints_from_expr(rhs);

                // Type propagation: if RHS has a known type, propagate to LHS
                if let ExprKind::Var(var) = &lhs.kind {
                    if let Some(rhs_type) = self.infer_expr_type(rhs) {
                        self.set_variable_type(&var.name, rhs_type);
                    }
                }
            }
            ExprKind::BinOp { op, left, right } => {
                self.collect_type_hints_from_expr(left);
                self.collect_type_hints_from_expr(right);

                // Comparisons with character constants
                if op.is_comparison() {
                    self.collect_comparison_hints(expr);
                }
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.collect_type_hints_from_expr(operand);
            }
            ExprKind::Deref { addr, size } => {
                self.collect_type_hints_from_expr(addr);

                // 1-byte dereference suggests char type
                if *size == 1 {
                    if let Some(var_name) = self.extract_var_name(addr) {
                        // The pointer points to char
                        self.set_variable_type(
                            &var_name,
                            ExprType::ptr(ExprType::Char { signed: true }),
                        );
                    }
                }
            }
            ExprKind::Call { target, args } => {
                for arg in args {
                    self.collect_type_hints_from_expr(arg);
                }

                // Propagate argument types from known signatures
                if let Some(func_name) = self.get_call_name(target) {
                    if let Some(sig) = self.signatures.get(&func_name).cloned() {
                        for (i, arg) in args.iter().enumerate() {
                            if let Some(param_type) = sig.params.get(i) {
                                if let Some(var_name) = self.extract_var_name(arg) {
                                    self.set_variable_type(&var_name, param_type.clone());
                                }
                            }
                        }
                    }
                }
            }
            ExprKind::ArrayAccess {
                base,
                index,
                element_size,
            } => {
                self.collect_type_hints_from_expr(base);
                self.collect_type_hints_from_expr(index);

                // Index is typically unsigned
                if let Some(var_name) = self.extract_var_name(index) {
                    self.set_variable_type(&var_name, ExprType::uint(8));
                }

                // Infer array element type from element size
                if let Some(var_name) = self.extract_var_name(base) {
                    let elem_type = match element_size {
                        1 => ExprType::Char { signed: true },
                        2 => ExprType::sint(2),
                        4 => ExprType::sint(4),
                        8 => ExprType::sint(8),
                        _ => ExprType::sint(*element_size as u8),
                    };
                    self.set_variable_type(
                        &var_name,
                        ExprType::Array {
                            element: Box::new(elem_type),
                            count: None,
                        },
                    );
                }
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.collect_type_hints_from_expr(inner);
            }
            ExprKind::AddressOf(inner) => {
                self.collect_type_hints_from_expr(inner);
            }
            _ => {}
        }
    }

    /// Collects type hints from comparison expressions.
    fn collect_comparison_hints(&mut self, expr: &Expr) {
        if let ExprKind::BinOp { op, left, right } = &expr.kind {
            if !op.is_comparison() {
                return;
            }

            // Check for comparison with character constant
            if let ExprKind::IntLit(value) = &right.kind {
                if is_likely_char_constant(*value) {
                    // Left operand is likely a char
                    if let Some(var_name) = self.extract_var_name(left) {
                        self.context_hints
                            .insert(var_name, ExprType::Char { signed: true });
                    }
                }
            }
            if let ExprKind::IntLit(value) = &left.kind {
                if is_likely_char_constant(*value) {
                    // Right operand is likely a char
                    if let Some(var_name) = self.extract_var_name(right) {
                        self.context_hints
                            .insert(var_name, ExprType::Char { signed: true });
                    }
                }
            }

            // Check for null pointer comparison
            if let ExprKind::IntLit(0) = &right.kind {
                if let Some(var_name) = self.extract_var_name(left) {
                    if !self.variable_types.contains_key(&var_name) {
                        // Could be pointer or integer, leave as unknown
                    }
                }
            }

            // Infer signedness from comparison operators
            match op {
                BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge => {
                    // Signed comparison
                    if let Some(var_name) = self.extract_var_name(left) {
                        self.mark_signed(&var_name);
                    }
                    if let Some(var_name) = self.extract_var_name(right) {
                        self.mark_signed(&var_name);
                    }
                }
                BinOpKind::ULt | BinOpKind::ULe | BinOpKind::UGt | BinOpKind::UGe => {
                    // Unsigned comparison
                    if let Some(var_name) = self.extract_var_name(left) {
                        self.mark_unsigned(&var_name);
                    }
                    if let Some(var_name) = self.extract_var_name(right) {
                        self.mark_unsigned(&var_name);
                    }
                }
                _ => {}
            }
        }
    }

    /// Propagates types through a node.
    fn propagate_types_in_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.propagate_types_in_expr(stmt);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                self.propagate_types_in_expr(condition);
                for n in then_body {
                    self.propagate_types_in_node(n);
                }
                if let Some(else_nodes) = else_body {
                    for n in else_nodes {
                        self.propagate_types_in_node(n);
                    }
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.propagate_types_in_expr(condition);
                for n in body {
                    self.propagate_types_in_node(n);
                }
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    self.propagate_types_in_expr(e);
                }
                self.propagate_types_in_expr(condition);
                if let Some(e) = update {
                    self.propagate_types_in_expr(e);
                }
                for n in body {
                    self.propagate_types_in_node(n);
                }
            }
            StructuredNode::Loop { body, .. } => {
                for n in body {
                    self.propagate_types_in_node(n);
                }
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                self.propagate_types_in_expr(value);
                for (_, case_body) in cases {
                    for n in case_body {
                        self.propagate_types_in_node(n);
                    }
                }
                if let Some(def) = default {
                    for n in def {
                        self.propagate_types_in_node(n);
                    }
                }
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.propagate_types_in_node(n);
                }
            }
            StructuredNode::Return(Some(e)) => {
                self.propagate_types_in_expr(e);
            }
            StructuredNode::Expr(e) => {
                self.propagate_types_in_expr(e);
            }
            _ => {}
        }
    }

    /// Propagates types in an expression.
    fn propagate_types_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                self.propagate_types_in_expr(lhs);
                self.propagate_types_in_expr(rhs);

                // Propagate type from RHS to LHS
                if let ExprKind::Var(var) = &lhs.kind {
                    if let Some(rhs_type) = self.infer_expr_type(rhs) {
                        self.set_variable_type(&var.name, rhs_type);
                    }
                }

                // Propagate type from LHS to RHS (for casts)
                if let ExprKind::Var(var) = &rhs.kind {
                    if let Some(lhs_type) = self.infer_expr_type(lhs) {
                        // Only propagate if RHS is unknown
                        if !self.variable_types.contains_key(&var.name) {
                            self.set_variable_type(&var.name, lhs_type);
                        }
                    }
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                self.propagate_types_in_expr(left);
                self.propagate_types_in_expr(right);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.propagate_types_in_expr(operand);
            }
            ExprKind::Deref { addr, .. } => {
                self.propagate_types_in_expr(addr);
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.propagate_types_in_expr(arg);
                }
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.propagate_types_in_expr(base);
                self.propagate_types_in_expr(index);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.propagate_types_in_expr(inner);
            }
            ExprKind::AddressOf(inner) => {
                self.propagate_types_in_expr(inner);
            }
            _ => {}
        }
    }

    /// Propagates types from function call arguments.
    fn propagate_call_types_in_node(&mut self, node: &StructuredNode) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for stmt in statements {
                    self.propagate_call_types_in_expr(stmt);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
            } => {
                self.propagate_call_types_in_expr(condition);
                for n in then_body {
                    self.propagate_call_types_in_node(n);
                }
                if let Some(else_nodes) = else_body {
                    for n in else_nodes {
                        self.propagate_call_types_in_node(n);
                    }
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.propagate_call_types_in_expr(condition);
                for n in body {
                    self.propagate_call_types_in_node(n);
                }
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(e) = init {
                    self.propagate_call_types_in_expr(e);
                }
                self.propagate_call_types_in_expr(condition);
                if let Some(e) = update {
                    self.propagate_call_types_in_expr(e);
                }
                for n in body {
                    self.propagate_call_types_in_node(n);
                }
            }
            StructuredNode::Loop { body, .. } => {
                for n in body {
                    self.propagate_call_types_in_node(n);
                }
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
            } => {
                self.propagate_call_types_in_expr(value);
                for (_, case_body) in cases {
                    for n in case_body {
                        self.propagate_call_types_in_node(n);
                    }
                }
                if let Some(def) = default {
                    for n in def {
                        self.propagate_call_types_in_node(n);
                    }
                }
            }
            StructuredNode::Sequence(nodes) => {
                for n in nodes {
                    self.propagate_call_types_in_node(n);
                }
            }
            StructuredNode::Return(Some(e)) => {
                self.propagate_call_types_in_expr(e);
            }
            StructuredNode::Expr(e) => {
                self.propagate_call_types_in_expr(e);
            }
            _ => {}
        }
    }

    /// Propagates types from function call arguments in expressions.
    fn propagate_call_types_in_expr(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Call { target, args } => {
                // Get function name
                if let Some(func_name) = self.get_call_name(target) {
                    if let Some(sig) = self.signatures.get(&func_name).cloned() {
                        // Propagate argument types
                        for (i, arg) in args.iter().enumerate() {
                            if let Some(param_type) = sig.params.get(i) {
                                self.propagate_type_to_expr(arg, param_type);
                            }
                        }
                    }
                }

                // Recurse into arguments
                for arg in args {
                    self.propagate_call_types_in_expr(arg);
                }
            }
            ExprKind::Assign { lhs, rhs } => {
                self.propagate_call_types_in_expr(lhs);
                self.propagate_call_types_in_expr(rhs);
            }
            ExprKind::BinOp { left, right, .. } => {
                self.propagate_call_types_in_expr(left);
                self.propagate_call_types_in_expr(right);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.propagate_call_types_in_expr(operand);
            }
            ExprKind::Deref { addr, .. } => {
                self.propagate_call_types_in_expr(addr);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                self.propagate_call_types_in_expr(base);
                self.propagate_call_types_in_expr(index);
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.propagate_call_types_in_expr(inner);
            }
            ExprKind::AddressOf(inner) => {
                self.propagate_call_types_in_expr(inner);
            }
            _ => {}
        }
    }

    /// Propagates a type to an expression (setting variable types).
    fn propagate_type_to_expr(&mut self, expr: &Expr, target_type: &ExprType) {
        match &expr.kind {
            ExprKind::Var(var) => {
                self.set_variable_type(&var.name, target_type.clone());
            }
            ExprKind::Deref { addr, .. } => {
                // If dereferencing, the address is a pointer to the target type
                if let Some(var_name) = self.extract_var_name(addr) {
                    self.set_variable_type(&var_name, ExprType::ptr(target_type.clone()));
                }
            }
            ExprKind::ArrayAccess { base, .. } => {
                // The base is an array of the target type
                if let Some(var_name) = self.extract_var_name(base) {
                    self.set_variable_type(
                        &var_name,
                        ExprType::Array {
                            element: Box::new(target_type.clone()),
                            count: None,
                        },
                    );
                }
            }
            ExprKind::Cast { expr: inner, .. } => {
                // Propagate through cast
                self.propagate_type_to_expr(inner, target_type);
            }
            _ => {}
        }
    }

    /// Infers the type of an expression.
    pub fn infer_expr_type(&self, expr: &Expr) -> Option<ExprType> {
        match &expr.kind {
            ExprKind::Var(var) => {
                // Check context hints first
                if let Some(hint) = self.context_hints.get(&var.name) {
                    return Some(hint.clone());
                }
                // Then check inferred types
                if let Some(ty) = self.variable_types.get(&var.name) {
                    return Some(ty.clone());
                }
                // Default based on size
                Some(ExprType::Int {
                    size: var.size,
                    signed: true,
                })
            }
            ExprKind::IntLit(value) => {
                // Infer type from value
                if is_likely_char_constant(*value) {
                    Some(ExprType::Char { signed: true })
                } else if *value >= 0 && *value <= 255 {
                    Some(ExprType::uint(1))
                } else if *value >= i8::MIN as i128 && *value <= i8::MAX as i128 {
                    Some(ExprType::sint(1))
                } else if *value >= i16::MIN as i128 && *value <= i16::MAX as i128 {
                    Some(ExprType::sint(2))
                } else if *value >= i32::MIN as i128 && *value <= i32::MAX as i128 {
                    Some(ExprType::sint(4))
                } else {
                    Some(ExprType::sint(8))
                }
            }
            ExprKind::BinOp { op, left, right } => {
                if op.is_comparison() {
                    Some(ExprType::Bool)
                } else {
                    // Result type based on operands
                    let left_type = self.infer_expr_type(left);
                    let right_type = self.infer_expr_type(right);
                    match (left_type, right_type) {
                        (Some(l), Some(r)) => Some(l.merge(&r)),
                        (Some(t), None) | (None, Some(t)) => Some(t),
                        (None, None) => None,
                    }
                }
            }
            ExprKind::UnaryOp { op, operand } => match op {
                UnaryOpKind::LogicalNot => Some(ExprType::Bool),
                _ => self.infer_expr_type(operand),
            },
            ExprKind::Deref { addr, size } => {
                // Check if we know the pointer type
                if let Some(ptr_type) = self.infer_expr_type(addr) {
                    Some(ptr_type.deref())
                } else {
                    // Default based on size
                    Some(ExprType::Int {
                        size: *size,
                        signed: true,
                    })
                }
            }
            ExprKind::Call { target, .. } => {
                // Return type from signature
                if let Some(func_name) = self.get_call_name(target) {
                    if let Some(sig) = self.signatures.get(&func_name) {
                        return Some(sig.return_type.clone());
                    }
                }
                None
            }
            ExprKind::ArrayAccess { base, .. } => {
                // Element type of array
                self.infer_expr_type(base)
                    .map(|array_type| array_type.deref())
            }
            ExprKind::Cast {
                to_size, signed, ..
            } => Some(ExprType::Int {
                size: *to_size,
                signed: *signed,
            }),
            ExprKind::AddressOf(inner) => {
                if let Some(inner_type) = self.infer_expr_type(inner) {
                    Some(inner_type.address_of())
                } else {
                    Some(ExprType::ptr(ExprType::Unknown))
                }
            }
            _ => None,
        }
    }

    /// Gets the name of a call target.
    fn get_call_name(&self, target: &CallTarget) -> Option<String> {
        match target {
            CallTarget::Named(name) => Some(normalize_function_name(name)),
            CallTarget::Direct { .. } => None,
            CallTarget::Indirect(_) => None,
            CallTarget::IndirectGot { .. } => None,
        }
    }

    /// Extracts the variable name from an expression.
    fn extract_var_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(var) => Some(var.name.clone()),
            ExprKind::Cast { expr: inner, .. } => self.extract_var_name(inner),
            _ => None,
        }
    }

    /// Sets or merges a variable type.
    fn set_variable_type(&mut self, name: &str, ty: ExprType) {
        if let Some(existing) = self.variable_types.get(name) {
            let merged = existing.merge(&ty);
            self.variable_types.insert(name.to_string(), merged);
        } else {
            self.variable_types.insert(name.to_string(), ty);
        }
    }

    /// Marks a variable as signed.
    fn mark_signed(&mut self, name: &str) {
        if let Some(existing) = self.variable_types.get_mut(name) {
            if let ExprType::Int { size, .. } = existing {
                *existing = ExprType::Int {
                    size: *size,
                    signed: true,
                };
            }
        }
    }

    /// Marks a variable as unsigned.
    fn mark_unsigned(&mut self, name: &str) {
        if let Some(existing) = self.variable_types.get_mut(name) {
            if let ExprType::Int { size, .. } = existing {
                *existing = ExprType::Int {
                    size: *size,
                    signed: false,
                };
            }
        }
    }

    /// Exports inferred types as a HashMap<String, String> for the decompiler.
    pub fn export_for_decompiler(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // Export variable types
        for (name, ty) in &self.variable_types {
            let type_str = ty.to_c_string();
            // Only export meaningful types (not just "int")
            if type_str != "int" && type_str != "unknown" {
                result.insert(name.clone(), type_str);
            }
        }

        // Export context hints
        for (name, ty) in &self.context_hints {
            if !result.contains_key(name) {
                let type_str = ty.to_c_string();
                if type_str != "int" && type_str != "unknown" {
                    result.insert(name.clone(), type_str);
                }
            }
        }

        result
    }

    /// Returns the inferred type for a variable.
    pub fn get_variable_type(&self, name: &str) -> Option<&ExprType> {
        self.context_hints
            .get(name)
            .or_else(|| self.variable_types.get(name))
    }

    /// Returns all inferred variable types.
    pub fn all_variable_types(&self) -> &HashMap<String, ExprType> {
        &self.variable_types
    }
}

impl Default for ExpressionTypePropagation {
    fn default() -> Self {
        Self::new()
    }
}

/// Checks if a value is likely a character constant.
fn is_likely_char_constant(value: i128) -> bool {
    // Printable ASCII range
    if (0x20..=0x7e).contains(&value) {
        return true;
    }
    // Common escape characters
    matches!(value, 0 | 9 | 10 | 13) // null, tab, newline, carriage return
}

/// Normalizes a function name by stripping common prefixes/suffixes.
fn normalize_function_name(name: &str) -> String {
    let mut result = name.to_string();

    // Strip leading underscores (common on macOS/Windows)
    while result.starts_with('_') {
        result = result[1..].to_string();
    }

    // Strip @plt suffix (PLT entries)
    if let Some(idx) = result.find("@plt") {
        result = result[..idx].to_string();
    }

    // Strip __imp_ prefix (Windows imports)
    if let Some(rest) = result.strip_prefix("imp_") {
        result = rest.to_string();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::{VarKind, Variable};

    fn make_var(name: &str, size: u8) -> Expr {
        Expr::var(Variable {
            kind: VarKind::Register(0),
            name: name.to_string(),
            size,
        })
    }

    #[test]
    fn test_expr_type_merge() {
        let char_type = ExprType::Char { signed: true };
        let int1 = ExprType::Int {
            size: 1,
            signed: true,
        };

        // Char is more specific than 1-byte int
        let merged = char_type.merge(&int1);
        assert!(matches!(merged, ExprType::Char { signed: true }));
    }

    #[test]
    fn test_expr_type_to_c_string() {
        assert_eq!(ExprType::Char { signed: true }.to_c_string(), "char");
        assert_eq!(ExprType::sint(4).to_c_string(), "int");
        assert_eq!(ExprType::uint(8).to_c_string(), "uint64_t");
        assert_eq!(ExprType::CString.to_c_string(), "char*");
        assert_eq!(ExprType::ptr(ExprType::sint(4)).to_c_string(), "int*");
    }

    #[test]
    fn test_is_likely_char_constant() {
        assert!(is_likely_char_constant('a' as i128));
        assert!(is_likely_char_constant('Z' as i128));
        assert!(is_likely_char_constant('0' as i128));
        assert!(is_likely_char_constant('\n' as i128));
        assert!(is_likely_char_constant('\0' as i128));
        assert!(!is_likely_char_constant(1000));
        assert!(!is_likely_char_constant(-50));
    }

    #[test]
    fn test_normalize_function_name() {
        assert_eq!(normalize_function_name("_printf"), "printf");
        assert_eq!(normalize_function_name("__printf"), "printf");
        assert_eq!(normalize_function_name("printf@plt"), "printf");
        assert_eq!(normalize_function_name("_printf@plt"), "printf");
        assert_eq!(normalize_function_name("imp_printf"), "printf");
    }

    #[test]
    fn test_type_propagation_with_libc() {
        let engine = ExpressionTypePropagation::with_libc();

        // Check that libc signatures are loaded
        assert!(engine.signatures.contains_key("strlen"));
        assert!(engine.signatures.contains_key("strcmp"));
        assert!(engine.signatures.contains_key("malloc"));
    }

    #[test]
    fn test_infer_expr_type_for_char_constant() {
        let engine = ExpressionTypePropagation::new();

        // Character constant
        let char_lit = Expr::int('a' as i128);
        let ty = engine.infer_expr_type(&char_lit);
        assert!(matches!(ty, Some(ExprType::Char { .. })));
    }

    #[test]
    fn test_comparison_with_char_sets_hint() {
        let mut engine = ExpressionTypePropagation::new();

        // Create: x == 'a'
        let var_x = make_var("x", 4);
        let char_a = Expr::int('a' as i128);
        let cmp = Expr::binop(BinOpKind::Eq, var_x, char_a);

        // Collect hints from comparison
        engine.collect_comparison_hints(&cmp);

        // x should be hinted as char
        assert!(engine.context_hints.contains_key("x"));
        assert!(matches!(
            engine.context_hints.get("x"),
            Some(ExprType::Char { .. })
        ));
    }

    #[test]
    fn test_deref_size_1_hints_char_ptr() {
        let mut engine = ExpressionTypePropagation::new();

        // Create: *ptr (1-byte deref)
        let ptr = make_var("ptr", 8);
        let deref = Expr::deref(ptr, 1);

        // Collect hints
        engine.collect_type_hints_from_expr(&deref);

        // ptr should be typed as char*
        if let Some(ExprType::Pointer(inner)) = engine.variable_types.get("ptr") {
            assert!(matches!(**inner, ExprType::Char { .. }));
        } else {
            panic!("Expected ptr to be typed as char*");
        }
    }

    #[test]
    fn test_export_for_decompiler() {
        let mut engine = ExpressionTypePropagation::new();

        engine
            .variable_types
            .insert("ptr".to_string(), ExprType::CString);
        engine
            .context_hints
            .insert("ch".to_string(), ExprType::Char { signed: true });

        let exported = engine.export_for_decompiler();

        assert_eq!(exported.get("ptr"), Some(&"char*".to_string()));
        assert_eq!(exported.get("ch"), Some(&"char".to_string()));
    }

    #[test]
    fn test_signed_comparison_marks_variable() {
        let mut engine = ExpressionTypePropagation::new();

        // Pre-create variable type
        engine.variable_types.insert(
            "x".to_string(),
            ExprType::Int {
                size: 4,
                signed: false,
            },
        );

        // Create: x < 0 (signed comparison)
        let var_x = make_var("x", 4);
        let zero = Expr::int(0);
        let cmp = Expr::binop(BinOpKind::Lt, var_x, zero);

        // Collect hints
        engine.collect_comparison_hints(&cmp);

        // x should now be signed
        assert!(matches!(
            engine.variable_types.get("x"),
            Some(ExprType::Int { signed: true, .. })
        ));
    }

    #[test]
    fn test_array_access_infers_element_type() {
        let mut engine = ExpressionTypePropagation::new();

        // Create: arr[i] with element_size=4
        let arr = make_var("arr", 8);
        let idx = make_var("i", 8);
        let access = Expr::array_access(arr, idx, 4);

        // Collect hints
        engine.collect_type_hints_from_expr(&access);

        // arr should be typed as array of int32
        if let Some(ExprType::Array { element, .. }) = engine.variable_types.get("arr") {
            assert!(matches!(**element, ExprType::Int { size: 4, .. }));
        } else {
            panic!("Expected arr to be typed as array");
        }

        // i should be unsigned
        assert!(matches!(
            engine.variable_types.get("i"),
            Some(ExprType::Int { signed: false, .. })
        ));
    }

    #[test]
    fn test_function_argument_type_propagation() {
        let mut engine = ExpressionTypePropagation::with_libc();

        // Create: strlen(str)
        let str_var = make_var("str", 8);
        let call = Expr {
            kind: ExprKind::Call {
                target: CallTarget::Named("strlen".to_string()),
                args: vec![str_var],
            },
        };

        // Collect hints
        engine.collect_type_hints_from_expr(&call);

        // str should be typed as char* (CString)
        assert!(matches!(
            engine.variable_types.get("str"),
            Some(ExprType::CString)
        ));
    }

    #[test]
    fn test_multiple_function_calls_propagate_types() {
        let mut engine = ExpressionTypePropagation::with_libc();

        // Create: strcmp(s1, s2)
        let s1 = make_var("s1", 8);
        let s2 = make_var("s2", 8);
        let call = Expr {
            kind: ExprKind::Call {
                target: CallTarget::Named("strcmp".to_string()),
                args: vec![s1, s2],
            },
        };

        // Collect hints
        engine.collect_type_hints_from_expr(&call);

        // Both s1 and s2 should be typed as char*
        assert!(matches!(
            engine.variable_types.get("s1"),
            Some(ExprType::CString)
        ));
        assert!(matches!(
            engine.variable_types.get("s2"),
            Some(ExprType::CString)
        ));
    }

    #[test]
    fn test_pointer_dereference_type_tracking() {
        let mut engine = ExpressionTypePropagation::new();

        // Set up a pointer type for ptr
        engine
            .variable_types
            .insert("ptr".to_string(), ExprType::ptr(ExprType::sint(4)));

        // Create: *ptr
        let ptr = make_var("ptr", 8);
        let deref = Expr::deref(ptr, 4);

        // Infer type of the dereference
        let ty = engine.infer_expr_type(&deref);

        // Should be int32 (the pointee type)
        assert!(matches!(
            ty,
            Some(ExprType::Int {
                size: 4,
                signed: true
            })
        ));
    }

    #[test]
    fn test_address_of_type_inference() {
        let engine = ExpressionTypePropagation::new();

        // Create: &x where x is int32
        let x = Expr::var(Variable {
            kind: VarKind::Register(0),
            name: "x".to_string(),
            size: 4,
        });
        let addr_of = Expr::address_of(x);

        // Infer type
        let ty = engine.infer_expr_type(&addr_of);

        // Should be int* (pointer to int)
        if let Some(ExprType::Pointer(inner)) = ty {
            assert!(matches!(*inner, ExprType::Int { size: 4, .. }));
        } else {
            panic!("Expected pointer type");
        }
    }

    #[test]
    fn test_binary_op_type_inference() {
        let engine = ExpressionTypePropagation::new();

        // Create: x + y where x and y are integers
        let x = make_var("x", 4);
        let y = make_var("y", 4);
        let add = Expr::binop(BinOpKind::Add, x, y);

        // The result type should be inferred
        let ty = engine.infer_expr_type(&add);
        assert!(matches!(ty, Some(ExprType::Int { .. })));
    }

    #[test]
    fn test_comparison_returns_bool() {
        let engine = ExpressionTypePropagation::new();

        // Create: x == y
        let x = make_var("x", 4);
        let y = make_var("y", 4);
        let cmp = Expr::binop(BinOpKind::Eq, x, y);

        // Comparison should return bool
        let ty = engine.infer_expr_type(&cmp);
        assert!(matches!(ty, Some(ExprType::Bool)));
    }

    #[test]
    fn test_call_return_type_inference() {
        let engine = ExpressionTypePropagation::with_libc();

        // Create: malloc(size)
        let size = make_var("size", 8);
        let call = Expr {
            kind: ExprKind::Call {
                target: CallTarget::Named("malloc".to_string()),
                args: vec![size],
            },
        };

        // malloc returns void*
        let ty = engine.infer_expr_type(&call);
        if let Some(ExprType::Pointer(inner)) = ty {
            assert!(matches!(*inner, ExprType::Void));
        } else {
            panic!("Expected pointer type from malloc");
        }
    }

    #[test]
    fn test_unsigned_comparison_marks_unsigned() {
        let mut engine = ExpressionTypePropagation::new();

        // Pre-create variable
        engine.variable_types.insert(
            "x".to_string(),
            ExprType::Int {
                size: 4,
                signed: true,
            },
        );

        // Create: x >u y (unsigned comparison)
        let x = make_var("x", 4);
        let y = make_var("y", 4);
        let cmp = Expr::binop(BinOpKind::UGt, x, y);

        // Collect hints
        engine.collect_comparison_hints(&cmp);

        // x should now be unsigned
        assert!(matches!(
            engine.variable_types.get("x"),
            Some(ExprType::Int { signed: false, .. })
        ));
    }

    #[test]
    fn test_char_array_element_size_1() {
        let mut engine = ExpressionTypePropagation::new();

        // Create: arr[i] with element_size=1 (char array)
        let arr = make_var("str_arr", 8);
        let idx = make_var("idx", 8);
        let access = Expr::array_access(arr, idx, 1);

        // Collect hints
        engine.collect_type_hints_from_expr(&access);

        // arr should be typed as array of char
        if let Some(ExprType::Array { element, .. }) = engine.variable_types.get("str_arr") {
            assert!(matches!(**element, ExprType::Char { .. }));
        } else {
            panic!("Expected str_arr to be typed as char array");
        }
    }

    #[test]
    fn test_cast_expression_type() {
        let engine = ExpressionTypePropagation::new();

        // Create: (int64_t)x
        let x = make_var("x", 4);
        let cast = Expr {
            kind: ExprKind::Cast {
                expr: Box::new(x),
                to_size: 8,
                signed: true,
            },
        };

        // The cast result should be int64
        let ty = engine.infer_expr_type(&cast);
        assert!(matches!(
            ty,
            Some(ExprType::Int {
                size: 8,
                signed: true
            })
        ));
    }

    #[test]
    fn test_logical_not_returns_bool() {
        let engine = ExpressionTypePropagation::new();

        // Create: !x
        let x = make_var("x", 4);
        let not_x = Expr::unary(UnaryOpKind::LogicalNot, x);

        // Should return bool
        let ty = engine.infer_expr_type(&not_x);
        assert!(matches!(ty, Some(ExprType::Bool)));
    }

    #[test]
    fn test_cstring_deref_is_char() {
        let mut engine = ExpressionTypePropagation::new();

        // Set ptr as CString
        engine
            .variable_types
            .insert("ptr".to_string(), ExprType::CString);

        // Create: *ptr
        let ptr = make_var("ptr", 8);
        let deref = Expr::deref(ptr, 1);

        // Deref of CString should be char
        let ty = engine.infer_expr_type(&deref);
        assert!(matches!(ty, Some(ExprType::Char { signed: true })));
    }

    #[test]
    fn test_type_merge_prefers_specific() {
        // CString should win over Pointer(Void)
        let cstring = ExprType::CString;
        let void_ptr = ExprType::ptr(ExprType::Void);

        let merged1 = cstring.merge(&void_ptr);
        let merged2 = void_ptr.merge(&cstring);

        assert!(matches!(merged1, ExprType::CString));
        assert!(matches!(merged2, ExprType::CString));
    }

    #[test]
    fn test_expr_type_size() {
        assert_eq!(ExprType::Bool.size(), Some(1));
        assert_eq!(ExprType::Char { signed: true }.size(), Some(1));
        assert_eq!(ExprType::sint(4).size(), Some(4));
        assert_eq!(ExprType::Float { size: 8 }.size(), Some(8));
        assert_eq!(ExprType::ptr(ExprType::sint(4)).size(), Some(8));
        assert_eq!(ExprType::CString.size(), Some(8));
        assert_eq!(ExprType::Unknown.size(), None);
        assert_eq!(ExprType::Void.size(), None);
    }

    #[test]
    fn test_expr_type_is_predicates() {
        assert!(ExprType::ptr(ExprType::Void).is_pointer());
        assert!(ExprType::CString.is_pointer());
        assert!(!ExprType::sint(4).is_pointer());

        assert!(ExprType::Char { signed: true }.is_char());
        assert!(!ExprType::sint(1).is_char());

        assert!(ExprType::sint(4).is_numeric());
        assert!(ExprType::Float { size: 4 }.is_numeric());
        assert!(ExprType::Char { signed: true }.is_numeric());
        assert!(!ExprType::ptr(ExprType::Void).is_numeric());
    }
}
