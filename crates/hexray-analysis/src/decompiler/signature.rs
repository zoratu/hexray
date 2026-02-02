//! Function signature recovery from calling conventions.
//!
//! This module provides:
//! - Calling convention definitions for x86_64 System V, Windows x64, and ARM64 AAPCS
//! - Function signature recovery by analyzing register usage patterns
//! - Parameter location tracking (register vs. stack)
//! - Return type inference from return register usage
//!
//! # Calling Conventions
//!
//! ## x86_64 System V ABI (Linux/macOS/BSD)
//! - Integer args: RDI, RSI, RDX, RCX, R8, R9
//! - Float args: XMM0-XMM7
//! - Return: RAX (int), XMM0 (float)
//! - Callee-saved: RBX, RBP, R12-R15
//!
//! ## x86_64 Windows ABI
//! - Integer args: RCX, RDX, R8, R9
//! - Float args: XMM0-XMM3
//! - Return: RAX (int), XMM0 (float)
//! - Callee-saved: RBX, RBP, RDI, RSI, R12-R15
//!
//! ## ARM64 AAPCS
//! - Integer args: X0-X7
//! - Float args: V0-V7 (D0-D7)
//! - Return: X0 (int), V0/D0 (float)
//! - Callee-saved: X19-X28, X29 (FP), X30 (LR)
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::decompiler::signature::{SignatureRecovery, CallingConvention};
//!
//! let recovery = SignatureRecovery::new(CallingConvention::SystemV);
//! let signature = recovery.analyze(&cfg);
//!
//! // Produces: int64_t function(int64_t arg0, int64_t arg1, int32_t arg2)
//! ```

use super::expression::{BinOpKind, Expr, ExprKind};
use super::structurer::{StructuredCfg, StructuredNode};
use std::collections::{HashMap, HashSet};

/// Calling convention types supported by the decompiler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallingConvention {
    /// System V AMD64 ABI (Linux, macOS, BSD, Solaris)
    #[default]
    SystemV,
    /// Microsoft x64 calling convention (Windows)
    Win64,
    /// ARM64 AAPCS (Procedure Call Standard for ARM 64-bit)
    Aarch64,
    /// RISC-V calling convention
    RiscV,
}

impl CallingConvention {
    /// Detects the calling convention from architecture hints.
    pub fn from_architecture(arch: &str) -> Self {
        let arch_lower = arch.to_lowercase();
        if arch_lower.contains("aarch64") || arch_lower.contains("arm64") {
            CallingConvention::Aarch64
        } else if arch_lower.contains("riscv") || arch_lower.contains("risc-v") {
            CallingConvention::RiscV
        } else if arch_lower.contains("win") || arch_lower.contains("pe") {
            CallingConvention::Win64
        } else {
            CallingConvention::SystemV
        }
    }

    /// Returns the list of integer argument registers for this convention.
    pub fn integer_arg_registers(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::SystemV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            CallingConvention::Win64 => &["rcx", "rdx", "r8", "r9"],
            CallingConvention::Aarch64 => &["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
            CallingConvention::RiscV => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        }
    }

    /// Returns the 32-bit variants of integer argument registers.
    pub fn integer_arg_registers_32(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::SystemV => &["edi", "esi", "edx", "ecx", "r8d", "r9d"],
            CallingConvention::Win64 => &["ecx", "edx", "r8d", "r9d"],
            CallingConvention::Aarch64 => &["w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"],
            CallingConvention::RiscV => &["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"],
        }
    }

    /// Returns the list of floating-point argument registers.
    pub fn float_arg_registers(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::SystemV => &[
                "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
            ],
            CallingConvention::Win64 => &["xmm0", "xmm1", "xmm2", "xmm3"],
            CallingConvention::Aarch64 => &["d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7"],
            CallingConvention::RiscV => &["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"],
        }
    }

    /// Returns the integer return register.
    pub fn integer_return_register(&self) -> &'static str {
        match self {
            CallingConvention::SystemV | CallingConvention::Win64 => "rax",
            CallingConvention::Aarch64 => "x0",
            CallingConvention::RiscV => "a0",
        }
    }

    /// Returns the 32-bit variant of the integer return register.
    pub fn integer_return_register_32(&self) -> &'static str {
        match self {
            CallingConvention::SystemV | CallingConvention::Win64 => "eax",
            CallingConvention::Aarch64 => "w0",
            CallingConvention::RiscV => "a0",
        }
    }

    /// Returns the floating-point return register.
    pub fn float_return_register(&self) -> &'static str {
        match self {
            CallingConvention::SystemV | CallingConvention::Win64 => "xmm0",
            CallingConvention::Aarch64 => "d0",
            CallingConvention::RiscV => "fa0",
        }
    }

    /// Returns the list of callee-saved registers.
    pub fn callee_saved_registers(&self) -> &'static [&'static str] {
        match self {
            CallingConvention::SystemV => &["rbx", "rbp", "r12", "r13", "r14", "r15"],
            CallingConvention::Win64 => &["rbx", "rbp", "rdi", "rsi", "r12", "r13", "r14", "r15"],
            CallingConvention::Aarch64 => &[
                "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30",
            ],
            CallingConvention::RiscV => &[
                "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            ],
        }
    }

    /// Returns the maximum number of integer arguments passed in registers.
    pub fn max_int_args(&self) -> usize {
        self.integer_arg_registers().len()
    }

    /// Returns the maximum number of float arguments passed in registers.
    pub fn max_float_args(&self) -> usize {
        self.float_arg_registers().len()
    }
}

/// Location where a parameter is passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterLocation {
    /// Parameter passed in an integer register.
    IntegerRegister {
        /// Register name (e.g., "rdi", "x0").
        name: String,
        /// Argument index (0-based).
        index: usize,
    },
    /// Parameter passed in a floating-point register.
    FloatRegister {
        /// Register name (e.g., "xmm0", "d0").
        name: String,
        /// Argument index (0-based).
        index: usize,
    },
    /// Parameter passed on the stack.
    Stack {
        /// Offset from the stack pointer at function entry.
        offset: i64,
    },
}

/// Inferred type for a parameter or return value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ParamType {
    /// Unknown type (default).
    #[default]
    Unknown,
    /// Void type (no return value).
    Void,
    /// Boolean type.
    Bool,
    /// Signed integer of specified size in bits (8, 16, 32, 64).
    SignedInt(u8),
    /// Unsigned integer of specified size in bits.
    UnsignedInt(u8),
    /// Pointer type.
    Pointer,
    /// Floating-point type (32 = float, 64 = double).
    Float(u8),
}

impl ParamType {
    /// Converts the type to a C-style type string.
    pub fn to_c_string(&self) -> String {
        match self {
            ParamType::Unknown => "int64_t".to_string(),
            ParamType::Void => "void".to_string(),
            ParamType::Bool => "bool".to_string(),
            ParamType::SignedInt(8) => "int8_t".to_string(),
            ParamType::SignedInt(16) => "int16_t".to_string(),
            ParamType::SignedInt(32) => "int32_t".to_string(),
            ParamType::SignedInt(64) => "int64_t".to_string(),
            ParamType::SignedInt(_) => "int".to_string(),
            ParamType::UnsignedInt(8) => "uint8_t".to_string(),
            ParamType::UnsignedInt(16) => "uint16_t".to_string(),
            ParamType::UnsignedInt(32) => "uint32_t".to_string(),
            ParamType::UnsignedInt(64) => "uint64_t".to_string(),
            ParamType::UnsignedInt(_) => "unsigned int".to_string(),
            ParamType::Pointer => "void*".to_string(),
            ParamType::Float(32) => "float".to_string(),
            ParamType::Float(64) => "double".to_string(),
            ParamType::Float(_) => "double".to_string(),
        }
    }

    /// Returns the size in bytes.
    pub fn size(&self) -> u8 {
        match self {
            ParamType::Unknown | ParamType::Pointer => 8,
            ParamType::Void => 0,
            ParamType::Bool | ParamType::SignedInt(8) | ParamType::UnsignedInt(8) => 1,
            ParamType::SignedInt(16) | ParamType::UnsignedInt(16) => 2,
            ParamType::SignedInt(32) | ParamType::UnsignedInt(32) | ParamType::Float(32) => 4,
            ParamType::SignedInt(64) | ParamType::UnsignedInt(64) | ParamType::Float(64) => 8,
            ParamType::SignedInt(n) | ParamType::UnsignedInt(n) | ParamType::Float(n) => *n / 8,
        }
    }
}

/// A function parameter with inferred type and location.
#[derive(Debug, Clone)]
pub struct Parameter {
    /// Name of the parameter (e.g., "arg0", "count", "ptr").
    pub name: String,
    /// Inferred type of the parameter.
    pub param_type: ParamType,
    /// Where the parameter is passed (register or stack).
    pub location: ParameterLocation,
}

impl Parameter {
    /// Creates a new parameter.
    pub fn new(
        name: impl Into<String>,
        param_type: ParamType,
        location: ParameterLocation,
    ) -> Self {
        Self {
            name: name.into(),
            param_type,
            location,
        }
    }

    /// Creates a parameter from an integer register.
    pub fn from_int_register(index: usize, reg_name: &str, param_type: ParamType) -> Self {
        Self {
            name: format!("arg{}", index),
            param_type,
            location: ParameterLocation::IntegerRegister {
                name: reg_name.to_string(),
                index,
            },
        }
    }

    /// Creates a parameter from a floating-point register.
    pub fn from_float_register(index: usize, reg_name: &str) -> Self {
        Self {
            name: format!("farg{}", index),
            param_type: ParamType::Float(64),
            location: ParameterLocation::FloatRegister {
                name: reg_name.to_string(),
                index,
            },
        }
    }
}

/// A recovered function signature.
#[derive(Debug, Clone, Default)]
pub struct FunctionSignature {
    /// Inferred return type.
    pub return_type: ParamType,
    /// List of parameters in order.
    pub parameters: Vec<Parameter>,
    /// The calling convention used.
    pub convention: CallingConvention,
    /// Whether the function appears to be variadic.
    pub is_variadic: bool,
    /// Whether a return value was detected.
    pub has_return: bool,
}

impl FunctionSignature {
    /// Creates a new empty signature with the given calling convention.
    pub fn new(convention: CallingConvention) -> Self {
        Self {
            convention,
            ..Default::default()
        }
    }

    /// Formats the signature as a C-style function declaration.
    pub fn to_c_declaration(&self, func_name: &str) -> String {
        let return_str = if self.has_return {
            self.return_type.to_c_string()
        } else {
            "void".to_string()
        };

        if self.parameters.is_empty() {
            if self.is_variadic {
                format!("{} {}(...)", return_str, func_name)
            } else {
                format!("{} {}(void)", return_str, func_name)
            }
        } else {
            let params: Vec<String> = self
                .parameters
                .iter()
                .map(|p| format!("{} {}", p.param_type.to_c_string(), p.name))
                .collect();

            if self.is_variadic {
                format!("{} {}({}, ...)", return_str, func_name, params.join(", "))
            } else {
                format!("{} {}({})", return_str, func_name, params.join(", "))
            }
        }
    }

    /// Returns just the parameter list for use in function headers.
    pub fn params_string(&self) -> String {
        if self.parameters.is_empty() {
            if self.is_variadic {
                "...".to_string()
            } else {
                String::new()
            }
        } else {
            let params: Vec<String> = self
                .parameters
                .iter()
                .map(|p| format!("{} {}", p.param_type.to_c_string(), p.name))
                .collect();

            if self.is_variadic {
                format!("{}, ...", params.join(", "))
            } else {
                params.join(", ")
            }
        }
    }
}

/// Signature recovery engine.
///
/// Analyzes a structured CFG to recover function signatures by:
/// 1. Identifying which argument registers are read before being written
/// 2. Tracking register sizes to infer parameter types
/// 3. Detecting return value usage before the return instruction
#[derive(Debug)]
pub struct SignatureRecovery {
    /// The calling convention to use.
    convention: CallingConvention,
    /// Registers that have been read (used as arguments).
    read_regs: HashSet<String>,
    /// Registers that have been written (clobbered).
    written_regs: HashSet<String>,
    /// Size hints for registers (from memory operations).
    reg_sizes: HashMap<String, u8>,
    /// Whether a return register was set before return.
    return_value_set: bool,
    /// Size of the return value.
    return_size: u8,
    /// Whether a float return register was used.
    float_return: bool,
    /// Parameter names assigned from stack slot analysis.
    param_names: HashMap<usize, String>,
}

impl SignatureRecovery {
    /// Creates a new signature recovery engine with the given calling convention.
    pub fn new(convention: CallingConvention) -> Self {
        Self {
            convention,
            read_regs: HashSet::new(),
            written_regs: HashSet::new(),
            reg_sizes: HashMap::new(),
            return_value_set: false,
            return_size: 8,
            float_return: false,
            param_names: HashMap::new(),
        }
    }

    /// Analyzes a structured CFG to recover the function signature.
    pub fn analyze(&mut self, cfg: &StructuredCfg) -> FunctionSignature {
        // Reset state
        self.read_regs.clear();
        self.written_regs.clear();
        self.reg_sizes.clear();
        self.return_value_set = false;
        self.return_size = 8;
        self.float_return = false;
        self.param_names.clear();

        // Analyze the function body
        self.analyze_nodes(&cfg.body, false);

        // Build the signature
        self.build_signature()
    }

    /// Analyzes a list of structured nodes.
    fn analyze_nodes(&mut self, nodes: &[StructuredNode], in_return_path: bool) {
        for (i, node) in nodes.iter().enumerate() {
            // Check if this is the last node and might lead to return
            let is_near_return = in_return_path || (i == nodes.len() - 1);
            self.analyze_node(node, is_near_return);
        }
    }

    /// Analyzes a single structured node.
    fn analyze_node(&mut self, node: &StructuredNode, in_return_path: bool) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for (i, stmt) in statements.iter().enumerate() {
                    // For the last statement in a block near return, check for return value setup
                    let near_ret = in_return_path && (i == statements.len() - 1);
                    self.analyze_statement(stmt, near_ret);
                }
            }
            StructuredNode::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                self.analyze_expr_reads(condition);
                self.analyze_nodes(then_body, in_return_path);
                if let Some(else_nodes) = else_body {
                    self.analyze_nodes(else_nodes, in_return_path);
                }
            }
            StructuredNode::While {
                condition, body, ..
            }
            | StructuredNode::DoWhile {
                body, condition, ..
            } => {
                self.analyze_expr_reads(condition);
                self.analyze_nodes(body, false);
            }
            StructuredNode::For {
                init,
                condition,
                update,
                body,
                ..
            } => {
                if let Some(init_expr) = init {
                    self.analyze_statement(init_expr, false);
                }
                self.analyze_expr_reads(condition);
                if let Some(update_expr) = update {
                    self.analyze_statement(update_expr, false);
                }
                self.analyze_nodes(body, false);
            }
            StructuredNode::Loop { body } => {
                self.analyze_nodes(body, false);
            }
            StructuredNode::Switch {
                value,
                cases,
                default,
                ..
            } => {
                self.analyze_expr_reads(value);
                for (_, case_body) in cases {
                    self.analyze_nodes(case_body, in_return_path);
                }
                if let Some(def) = default {
                    self.analyze_nodes(def, in_return_path);
                }
            }
            StructuredNode::Return(Some(expr)) => {
                self.analyze_expr_reads(expr);
                self.return_value_set = true;
                // Infer return type from expression
                if let Some(size) = self.infer_expr_size(expr) {
                    self.return_size = size;
                }
            }
            StructuredNode::Return(None) => {
                // void return
            }
            StructuredNode::Expr(expr) => {
                self.analyze_statement(expr, in_return_path);
            }
            StructuredNode::Sequence(inner) => {
                self.analyze_nodes(inner, in_return_path);
            }
            _ => {}
        }
    }

    /// Analyzes a statement for register reads/writes.
    fn analyze_statement(&mut self, expr: &Expr, near_return: bool) {
        match &expr.kind {
            ExprKind::Assign { lhs, rhs } => {
                // First, analyze the RHS for reads
                self.analyze_expr_reads(rhs);

                // Check if LHS is a register being written
                if let Some(reg_name) = self.extract_register_name(lhs) {
                    let reg_lower = reg_name.to_lowercase();
                    self.written_regs.insert(reg_lower.clone());

                    // If this is an argument register being assigned from a stack slot,
                    // it might be a parameter being saved
                    if self.is_arg_register(&reg_lower) {
                        if let Some(offset) = self.extract_stack_offset(rhs) {
                            // This is reading an argument and storing it
                            // The argument was already read, mark it
                            if !self.written_regs.contains(&reg_lower) {
                                self.read_regs.insert(reg_lower.clone());
                            }
                            // Track the parameter name from the stack slot
                            if let Some(idx) = self.arg_register_index(&reg_lower) {
                                self.param_names
                                    .insert(idx, format!("var_{:x}", offset.unsigned_abs()));
                            }
                        }
                    }

                    // Check for return value setup near return
                    if near_return && self.is_return_register(&reg_lower) {
                        self.return_value_set = true;
                        if let Some(size) = self.infer_expr_size(rhs) {
                            self.return_size = size;
                        }
                        if self.is_float_return_register(&reg_lower) {
                            self.float_return = true;
                        }
                    }
                }

                // For parameter detection: check if an arg register is read and stored to stack
                // Pattern: *(rbp + offset) = rdi  means rdi is a parameter
                if let ExprKind::Var(rhs_var) = &rhs.kind {
                    let rhs_name = rhs_var.name.to_lowercase();
                    if self.is_arg_register(&rhs_name) && !self.written_regs.contains(&rhs_name) {
                        self.read_regs.insert(rhs_name.clone());
                        // Track the size from the register variant
                        let size = self.reg_size_from_name(&rhs_var.name);
                        if size > 0 {
                            self.reg_sizes.insert(rhs_name, size);
                        }
                    }
                }
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.analyze_expr_reads(arg);
                }
            }
            _ => {
                self.analyze_expr_reads(expr);
            }
        }
    }

    /// Analyzes an expression for register reads (argument detection).
    fn analyze_expr_reads(&mut self, expr: &Expr) {
        match &expr.kind {
            ExprKind::Var(var) => {
                let name = var.name.to_lowercase();
                // If this register is an argument register and hasn't been written yet,
                // it's being used as an argument
                if self.is_arg_register(&name) && !self.written_regs.contains(&name) {
                    self.read_regs.insert(name.clone());
                    // Track the size
                    let size = self.reg_size_from_name(&var.name);
                    if size > 0 {
                        self.reg_sizes.insert(name, size);
                    }
                }
            }
            ExprKind::BinOp { left, right, .. } => {
                self.analyze_expr_reads(left);
                self.analyze_expr_reads(right);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.analyze_expr_reads(operand);
            }
            ExprKind::Deref { addr, .. } => {
                self.analyze_expr_reads(addr);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.analyze_expr_reads(rhs);
                // Don't analyze LHS reads - it's being written
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    self.analyze_expr_reads(addr);
                }
            }
            ExprKind::Call { args, .. } => {
                for arg in args {
                    self.analyze_expr_reads(arg);
                }
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.analyze_expr_reads(inner);
            }
            ExprKind::Conditional {
                cond,
                then_expr,
                else_expr,
            } => {
                self.analyze_expr_reads(cond);
                self.analyze_expr_reads(then_expr);
                self.analyze_expr_reads(else_expr);
            }
            _ => {}
        }
    }

    /// Extracts a register name from an expression if it's a simple register reference.
    fn extract_register_name(&self, expr: &Expr) -> Option<String> {
        if let ExprKind::Var(var) = &expr.kind {
            Some(var.name.clone())
        } else {
            None
        }
    }

    /// Extracts a stack offset from a deref expression.
    fn extract_stack_offset(&self, expr: &Expr) -> Option<i128> {
        if let ExprKind::Deref { addr, .. } = &expr.kind {
            if let ExprKind::BinOp { op, left, right } = &addr.kind {
                if let ExprKind::Var(base) = &left.kind {
                    if is_frame_pointer(&base.name) {
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
        }
        None
    }

    /// Checks if a register name is an argument register.
    fn is_arg_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();

        // Check for renamed argument variables (arg0, arg1, etc.)
        if name_lower.starts_with("arg") {
            if let Some(suffix) = name_lower.strip_prefix("arg") {
                if suffix.parse::<usize>().is_ok() {
                    return true;
                }
            }
        }

        // Check both 64-bit and 32-bit register variants
        self.convention
            .integer_arg_registers()
            .iter()
            .any(|r| r.to_lowercase() == name_lower)
            || self
                .convention
                .integer_arg_registers_32()
                .iter()
                .any(|r| r.to_lowercase() == name_lower)
            || self
                .convention
                .float_arg_registers()
                .iter()
                .any(|r| r.to_lowercase() == name_lower)
    }

    /// Returns the argument index for a register, or None.
    fn arg_register_index(&self, name: &str) -> Option<usize> {
        let name_lower = name.to_lowercase();

        // Check for renamed argument variables (arg0, arg1, etc.)
        if let Some(suffix) = name_lower.strip_prefix("arg") {
            if let Ok(idx) = suffix.parse::<usize>() {
                return Some(idx);
            }
        }

        // Check 64-bit integer registers
        if let Some(idx) = self
            .convention
            .integer_arg_registers()
            .iter()
            .position(|r| r.to_lowercase() == name_lower)
        {
            return Some(idx);
        }

        // Check 32-bit integer registers
        if let Some(idx) = self
            .convention
            .integer_arg_registers_32()
            .iter()
            .position(|r| r.to_lowercase() == name_lower)
        {
            return Some(idx);
        }

        None
    }

    /// Checks if a register is a return register.
    fn is_return_register(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        name_lower == self.convention.integer_return_register()
            || name_lower == self.convention.integer_return_register_32()
            || name_lower == self.convention.float_return_register()
    }

    /// Checks if a register is a float return register.
    fn is_float_return_register(&self, name: &str) -> bool {
        name.to_lowercase() == self.convention.float_return_register()
    }

    /// Returns the size in bytes based on register name variant.
    fn reg_size_from_name(&self, name: &str) -> u8 {
        let name_lower = name.to_lowercase();

        // x86-64 register naming
        if name_lower.starts_with('r') && !name_lower.ends_with('d') {
            return 8; // 64-bit (rax, rdi, etc.)
        }
        if name_lower.starts_with('e') || name_lower.ends_with('d') {
            return 4; // 32-bit (eax, r8d, etc.)
        }
        if name_lower.ends_with('w') {
            return 2; // 16-bit
        }
        if name_lower.ends_with('b') || name_lower.ends_with('l') {
            return 1; // 8-bit
        }

        // ARM64 register naming
        if name_lower.starts_with('x') {
            return 8; // 64-bit
        }
        if name_lower.starts_with('w') {
            return 4; // 32-bit
        }
        if name_lower.starts_with('d') || name_lower.starts_with('q') {
            return 8; // 64-bit float/SIMD
        }
        if name_lower.starts_with('s') && name_lower.len() <= 3 {
            return 4; // 32-bit float
        }

        // RISC-V: all registers are typically full width
        8
    }

    /// Infers the size of an expression result.
    fn infer_expr_size(&self, expr: &Expr) -> Option<u8> {
        match &expr.kind {
            ExprKind::Var(var) => {
                // First try to infer from register name (w0 = 4, x0 = 8, etc.)
                let size = self.reg_size_from_name(&var.name);
                if size > 0 {
                    Some(size)
                } else if var.size > 0 {
                    // Fall back to variable's stored size (for stack variables, etc.)
                    Some(var.size)
                } else {
                    None
                }
            }
            ExprKind::IntLit(n) => {
                if *n >= i8::MIN as i128 && *n <= i8::MAX as i128 {
                    Some(1)
                } else if *n >= i16::MIN as i128 && *n <= i16::MAX as i128 {
                    Some(2)
                } else if *n >= i32::MIN as i128 && *n <= i32::MAX as i128 {
                    Some(4)
                } else {
                    Some(8)
                }
            }
            ExprKind::Deref { size, .. } => Some(*size),
            ExprKind::ArrayAccess { element_size, .. } => Some(*element_size as u8),
            ExprKind::Cast { to_size, .. } => Some(*to_size),
            ExprKind::BinOp { left, right, .. } => {
                let left_size = self.infer_expr_size(left);
                let right_size = self.infer_expr_size(right);
                match (left_size, right_size) {
                    (Some(l), Some(r)) => Some(l.max(r)),
                    (Some(s), None) | (None, Some(s)) => Some(s),
                    (None, None) => None,
                }
            }
            _ => None,
        }
    }

    /// Builds the final signature from collected information.
    fn build_signature(&self) -> FunctionSignature {
        let mut sig = FunctionSignature::new(self.convention);

        // Determine which argument registers were used
        let int_regs = self.convention.integer_arg_registers();
        let int_regs_32 = self.convention.integer_arg_registers_32();

        // Track the highest argument index used
        let mut max_int_arg: Option<usize> = None;

        for (idx, (reg64, reg32)) in int_regs.iter().zip(int_regs_32.iter()).enumerate() {
            let reg64_lower = reg64.to_lowercase();
            let reg32_lower = reg32.to_lowercase();

            if self.read_regs.contains(&reg64_lower) || self.read_regs.contains(&reg32_lower) {
                max_int_arg = Some(idx);
            }
        }

        // Create parameters for all argument slots up to the max used
        // (to handle cases where an earlier arg isn't used but a later one is)
        if let Some(max_idx) = max_int_arg {
            for idx in 0..=max_idx {
                let reg64 = int_regs[idx].to_lowercase();
                let reg32 = int_regs_32[idx].to_lowercase();

                // Determine the size from register usage
                let size = if let Some(s) = self.reg_sizes.get(&reg64) {
                    *s
                } else if let Some(s) = self.reg_sizes.get(&reg32) {
                    *s
                } else {
                    8 // Default to 64-bit
                };

                let param_type = match size {
                    1 => ParamType::SignedInt(8),
                    2 => ParamType::SignedInt(16),
                    4 => ParamType::SignedInt(32),
                    _ => ParamType::SignedInt(64),
                };

                // Use a custom name if we have one
                let name = self
                    .param_names
                    .get(&idx)
                    .cloned()
                    .unwrap_or_else(|| format!("arg{}", idx));

                sig.parameters.push(Parameter::new(
                    name,
                    param_type,
                    ParameterLocation::IntegerRegister {
                        name: int_regs[idx].to_string(),
                        index: idx,
                    },
                ));
            }
        }

        // Check for float arguments
        let float_regs = self.convention.float_arg_registers();
        for (idx, reg) in float_regs.iter().enumerate() {
            let reg_lower = reg.to_lowercase();
            if self.read_regs.contains(&reg_lower) {
                sig.parameters
                    .push(Parameter::from_float_register(idx, reg));
            }
        }

        // Determine return type
        sig.has_return = self.return_value_set;
        if self.return_value_set {
            if self.float_return {
                sig.return_type = ParamType::Float(64);
            } else {
                sig.return_type = match self.return_size {
                    1 => ParamType::SignedInt(8),
                    2 => ParamType::SignedInt(16),
                    4 => ParamType::SignedInt(32),
                    _ => ParamType::SignedInt(64),
                };
            }
        } else {
            sig.return_type = ParamType::Void;
        }

        sig
    }
}

/// Checks if a register name is a frame pointer.
fn is_frame_pointer(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "rbp" | "ebp" | "x29" | "fp" | "s0"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompiler::expression::Variable;

    #[test]
    fn test_calling_convention_registers() {
        let sysv = CallingConvention::SystemV;
        assert_eq!(sysv.integer_arg_registers().len(), 6);
        assert_eq!(sysv.float_arg_registers().len(), 8);
        assert_eq!(sysv.integer_return_register(), "rax");

        let win64 = CallingConvention::Win64;
        assert_eq!(win64.integer_arg_registers().len(), 4);
        assert_eq!(win64.float_arg_registers().len(), 4);

        let aarch64 = CallingConvention::Aarch64;
        assert_eq!(aarch64.integer_arg_registers().len(), 8);
        assert_eq!(aarch64.integer_return_register(), "x0");
    }

    #[test]
    fn test_inferred_type_to_c_string() {
        assert_eq!(ParamType::Void.to_c_string(), "void");
        assert_eq!(ParamType::SignedInt(32).to_c_string(), "int32_t");
        assert_eq!(ParamType::SignedInt(64).to_c_string(), "int64_t");
        assert_eq!(ParamType::UnsignedInt(8).to_c_string(), "uint8_t");
        assert_eq!(ParamType::Float(32).to_c_string(), "float");
        assert_eq!(ParamType::Float(64).to_c_string(), "double");
        assert_eq!(ParamType::Pointer.to_c_string(), "void*");
    }

    #[test]
    fn test_signature_to_c_declaration() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.has_return = true;
        sig.return_type = ParamType::SignedInt(32);
        sig.parameters.push(Parameter::new(
            "arg0",
            ParamType::SignedInt(64),
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(Parameter::new(
            "arg1",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let decl = sig.to_c_declaration("my_function");
        assert!(decl.contains("int32_t"));
        assert!(decl.contains("my_function"));
        assert!(decl.contains("int64_t arg0"));
        assert!(decl.contains("void* arg1"));
    }

    #[test]
    fn test_signature_void_function() {
        let sig = FunctionSignature::new(CallingConvention::SystemV);
        let decl = sig.to_c_declaration("void_func");
        assert!(decl.starts_with("void"));
        assert!(decl.contains("void_func(void)"));
    }

    #[test]
    fn test_signature_variadic() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.has_return = true;
        sig.return_type = ParamType::SignedInt(32);
        sig.is_variadic = true;
        sig.parameters.push(Parameter::new(
            "fmt",
            ParamType::Pointer,
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));

        let decl = sig.to_c_declaration("printf_like");
        assert!(decl.contains("..."));
    }

    #[test]
    fn test_reg_size_from_name() {
        let recovery = SignatureRecovery::new(CallingConvention::SystemV);

        // x86-64
        assert_eq!(recovery.reg_size_from_name("rax"), 8);
        assert_eq!(recovery.reg_size_from_name("eax"), 4);
        assert_eq!(recovery.reg_size_from_name("rdi"), 8);
        assert_eq!(recovery.reg_size_from_name("edi"), 4);
        assert_eq!(recovery.reg_size_from_name("r8"), 8);
        assert_eq!(recovery.reg_size_from_name("r8d"), 4);
    }

    #[test]
    fn test_aarch64_reg_size_from_name() {
        let recovery = SignatureRecovery::new(CallingConvention::Aarch64);

        // ARM64
        assert_eq!(recovery.reg_size_from_name("x0"), 8);
        assert_eq!(recovery.reg_size_from_name("w0"), 4);
        assert_eq!(recovery.reg_size_from_name("x19"), 8);
        assert_eq!(recovery.reg_size_from_name("w19"), 4);
    }

    #[test]
    fn test_convention_from_architecture() {
        assert_eq!(
            CallingConvention::from_architecture("aarch64"),
            CallingConvention::Aarch64
        );
        assert_eq!(
            CallingConvention::from_architecture("arm64"),
            CallingConvention::Aarch64
        );
        assert_eq!(
            CallingConvention::from_architecture("x86_64"),
            CallingConvention::SystemV
        );
        assert_eq!(
            CallingConvention::from_architecture("x86_64-pc-windows-msvc"),
            CallingConvention::Win64
        );
        assert_eq!(
            CallingConvention::from_architecture("riscv64"),
            CallingConvention::RiscV
        );
    }

    #[test]
    fn test_simple_signature_recovery() {
        use hexray_core::BasicBlockId;

        // Create a simple function that uses rdi and rsi
        // Pattern: var_8 = rdi; var_10 = rsi;
        let rbp = Expr::var(Variable::reg("rbp", 8));
        let rdi = Expr::var(Variable::reg("rdi", 8));
        let rsi = Expr::var(Variable::reg("rsi", 8));

        let local_8_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-8));
        let local_10_addr = Expr::binop(BinOpKind::Add, rbp.clone(), Expr::int(-16));

        let local_8 = Expr::deref(local_8_addr, 8);
        let local_10 = Expr::deref(local_10_addr, 8);

        let stmt1 = Expr::assign(local_8, rdi);
        let stmt2 = Expr::assign(local_10, rsi);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt1, stmt2],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        // Should detect 2 parameters
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    #[test]
    fn test_return_value_detection() {
        use hexray_core::BasicBlockId;

        // Function that sets eax before return (32-bit return)
        let eax = Expr::var(Variable::reg("eax", 4));
        let result = Expr::assign(eax, Expr::int(42));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![result],
            address_range: (0x1000, 0x1008),
        };

        let ret_node = StructuredNode::Return(Some(Expr::var(Variable::reg("eax", 4))));

        let cfg = StructuredCfg {
            body: vec![block, ret_node],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        // Return type should be detected
        assert!(!matches!(sig.return_type, ParamType::Void));
    }

    #[test]
    fn test_arm64_signature() {
        use hexray_core::BasicBlockId;

        // ARM64 function using x0, x1, x2
        let x0 = Expr::var(Variable::reg("x0", 8));
        let x1 = Expr::var(Variable::reg("x1", 8));
        let x2 = Expr::var(Variable::reg("w2", 4)); // 32-bit variant

        // x0 + x1 + x2
        let add1 = Expr::binop(BinOpKind::Add, x0, x1);
        let add2 = Expr::binop(BinOpKind::Add, add1, x2);

        let stmt = Expr::assign(Expr::var(Variable::reg("x3", 8)), add2);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Aarch64);
        let sig = recovery.analyze(&cfg);

        // Should detect 3 parameters
        assert_eq!(sig.parameters.len(), 3);
        // Third parameter should be 32-bit (from w2)
        assert!(matches!(
            sig.parameters[2].param_type,
            ParamType::SignedInt(32)
        ));
    }

    #[test]
    fn test_windows_calling_convention() {
        use hexray_core::BasicBlockId;

        // Windows x64: uses RCX, RDX, R8, R9
        let rcx = Expr::var(Variable::reg("rcx", 8));
        let rdx = Expr::var(Variable::reg("rdx", 8));

        let add = Expr::binop(BinOpKind::Add, rcx, rdx);
        let stmt = Expr::assign(Expr::var(Variable::reg("rax", 8)), add);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::Win64);
        let sig = recovery.analyze(&cfg);

        // Should detect 2 parameters
        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(sig.parameters[0].name, "arg0");
        assert_eq!(sig.parameters[1].name, "arg1");
    }

    #[test]
    fn test_riscv_calling_convention() {
        use hexray_core::BasicBlockId;

        // RISC-V: uses a0-a7
        let a0 = Expr::var(Variable::reg("a0", 8));
        let a1 = Expr::var(Variable::reg("a1", 8));
        let a2 = Expr::var(Variable::reg("a2", 8));

        let add1 = Expr::binop(BinOpKind::Add, a0, a1);
        let add2 = Expr::binop(BinOpKind::Add, add1, a2);
        let stmt = Expr::assign(Expr::var(Variable::reg("t0", 8)), add2);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::RiscV);
        let sig = recovery.analyze(&cfg);

        // Should detect 3 parameters
        assert_eq!(sig.parameters.len(), 3);
    }

    #[test]
    fn test_params_string() {
        let mut sig = FunctionSignature::new(CallingConvention::SystemV);
        sig.parameters.push(Parameter::new(
            "arg0",
            ParamType::SignedInt(32),
            ParameterLocation::IntegerRegister {
                name: "rdi".to_string(),
                index: 0,
            },
        ));
        sig.parameters.push(Parameter::new(
            "arg1",
            ParamType::SignedInt(64),
            ParameterLocation::IntegerRegister {
                name: "rsi".to_string(),
                index: 1,
            },
        ));

        let params = sig.params_string();
        assert_eq!(params, "int32_t arg0, int64_t arg1");
    }

    #[test]
    fn test_param_type_size() {
        assert_eq!(ParamType::Void.size(), 0);
        assert_eq!(ParamType::Bool.size(), 1);
        assert_eq!(ParamType::SignedInt(8).size(), 1);
        assert_eq!(ParamType::SignedInt(16).size(), 2);
        assert_eq!(ParamType::SignedInt(32).size(), 4);
        assert_eq!(ParamType::SignedInt(64).size(), 8);
        assert_eq!(ParamType::Float(32).size(), 4);
        assert_eq!(ParamType::Float(64).size(), 8);
        assert_eq!(ParamType::Pointer.size(), 8);
    }

    #[test]
    fn test_callee_saved_registers() {
        let sysv = CallingConvention::SystemV;
        let callee_saved = sysv.callee_saved_registers();
        assert!(callee_saved.contains(&"rbx"));
        assert!(callee_saved.contains(&"rbp"));
        assert!(callee_saved.contains(&"r12"));

        let aarch64 = CallingConvention::Aarch64;
        let callee_saved = aarch64.callee_saved_registers();
        assert!(callee_saved.contains(&"x19"));
        assert!(callee_saved.contains(&"x29"));
    }

    #[test]
    fn test_max_args() {
        let sysv = CallingConvention::SystemV;
        assert_eq!(sysv.max_int_args(), 6);
        assert_eq!(sysv.max_float_args(), 8);

        let win64 = CallingConvention::Win64;
        assert_eq!(win64.max_int_args(), 4);
        assert_eq!(win64.max_float_args(), 4);

        let aarch64 = CallingConvention::Aarch64;
        assert_eq!(aarch64.max_int_args(), 8);
        assert_eq!(aarch64.max_float_args(), 8);
    }

    #[test]
    fn test_parameter_from_helpers() {
        let param = Parameter::from_int_register(0, "rdi", ParamType::SignedInt(64));
        assert_eq!(param.name, "arg0");
        assert_eq!(param.param_type, ParamType::SignedInt(64));
        if let ParameterLocation::IntegerRegister { name, index } = param.location {
            assert_eq!(name, "rdi");
            assert_eq!(index, 0);
        } else {
            panic!("Expected IntegerRegister location");
        }

        let fparam = Parameter::from_float_register(0, "xmm0");
        assert_eq!(fparam.name, "farg0");
        assert_eq!(fparam.param_type, ParamType::Float(64));
    }

    #[test]
    fn test_mixed_register_sizes_x86() {
        use hexray_core::BasicBlockId;

        // Function with mixed register sizes
        let rdi = Expr::var(Variable::reg("rdi", 8)); // 64-bit
        let esi = Expr::var(Variable::reg("esi", 4)); // 32-bit

        let add = Expr::binop(BinOpKind::Add, rdi, esi);
        let stmt = Expr::assign(Expr::var(Variable::reg("rax", 8)), add);

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        // First param is 64-bit (from rdi)
        assert!(matches!(
            sig.parameters[0].param_type,
            ParamType::SignedInt(64)
        ));
        // Second param is 32-bit (from esi)
        assert!(matches!(
            sig.parameters[1].param_type,
            ParamType::SignedInt(32)
        ));
    }
}
