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
use super::{RelocationTable, SymbolTable};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

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

/// Parameter usage pattern hints for better type inference.
#[derive(Debug, Clone, Default)]
pub struct ParameterUsageHints {
    /// Parameter is dereferenced as a pointer.
    pub is_dereferenced: bool,
    /// Parameter is used in pointer arithmetic.
    pub is_pointer_arithmetic: bool,
    /// Parameter is compared against null.
    pub is_null_checked: bool,
    /// Parameter is passed to a string function (strlen, strcmp, etc.).
    pub is_string_arg: bool,
    /// Parameter is used as an array index.
    pub is_array_index: bool,
    /// Parameter is used as a loop bound.
    pub is_loop_bound: bool,
    /// Parameter is used in a comparison (likely signed).
    pub is_signed_comparison: bool,
    /// Parameter is used in unsigned operations.
    pub is_unsigned_ops: bool,
    /// Parameter is part of a pointer+size pair (common pattern).
    pub is_size_param: bool,
    /// Functions this parameter is passed to (for type propagation).
    pub passed_to_functions: Vec<String>,
    /// Function/argument positions where this parameter is used as a callback.
    pub passed_as_callback_to: Vec<(String, usize)>,
    /// Parameter is used as an indirect call target.
    pub is_function_pointer: bool,
    /// Best-effort inferred argument types when this parameter is called indirectly.
    pub function_pointer_arg_types: Vec<ParamType>,
    /// Best-effort inferred return type when this parameter is called indirectly.
    pub function_pointer_return_type: Option<ParamType>,
    /// Confidence score for function-pointer inference from indirect evidence.
    pub function_pointer_confidence: u8,
    /// Human-readable reasons that led to function-pointer typing.
    pub function_pointer_reasons: Vec<String>,
}

impl ParameterUsageHints {
    fn normalize_callback_name(function_name: &str) -> &str {
        let no_prefix = function_name.trim_start_matches('_');
        no_prefix.split('@').next().unwrap_or(no_prefix)
    }

    fn add_function_pointer_reason(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.function_pointer_reasons.iter().any(|r| r == &reason) {
            self.function_pointer_reasons.push(reason);
        }
    }

    /// Returns a callback signature for known APIs and callback argument positions.
    fn callback_signature(function_name: &str, arg_index: usize) -> Option<ParamType> {
        let clean_name = Self::normalize_callback_name(function_name);
        match (clean_name, arg_index) {
            ("qsort", 3) | ("bsearch", 3) | ("bsearch", 4) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::SignedInt(32)),
                params: vec![ParamType::Pointer, ParamType::Pointer],
            }),
            // glibc qsort_r/qsort_s callback.
            ("qsort_r", 3) | ("qsort_s", 3) | ("hexray_qsort_r", 3) => {
                Some(ParamType::FunctionPointer {
                    return_type: Box::new(ParamType::SignedInt(32)),
                    params: vec![ParamType::Pointer, ParamType::Pointer, ParamType::Pointer],
                })
            }
            // Fixture-local BSD-style qsort_r callback shim.
            ("hexray_bsd_qsort_r", 4) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::SignedInt(32)),
                params: vec![ParamType::Pointer, ParamType::Pointer, ParamType::Pointer],
            }),
            // BSD qsort_r callback (typically exposed as bsd_qsort_r symbols).
            ("bsd_qsort_r", 4) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::SignedInt(32)),
                params: vec![ParamType::Pointer, ParamType::Pointer, ParamType::Pointer],
            }),
            ("pthread_create", 2) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Pointer),
                params: vec![ParamType::Pointer],
            }),
            ("signal", 1) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::SignedInt(32)],
            }),
            ("atexit", 0) | ("at_quick_exit", 0) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::Void],
            }),
            ("on_exit", 0) | ("hexray_on_exit", 0) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::SignedInt(32), ParamType::Pointer],
            }),
            ("pthread_atfork", 0)
            | ("pthread_atfork", 1)
            | ("pthread_atfork", 2)
            | ("hexray_pthread_atfork", 0)
            | ("hexray_pthread_atfork", 1)
            | ("hexray_pthread_atfork", 2) => Some(ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::Void],
            }),
            _ => None,
        }
    }

    /// Infers a type from the usage hints.
    pub fn infer_type(&self, base_size: u8) -> ParamType {
        for (func_name, arg_index) in &self.passed_as_callback_to {
            if let Some(sig) = Self::callback_signature(func_name, *arg_index) {
                return sig;
            }
        }

        if self.is_function_pointer {
            if self.function_pointer_confidence < 2 && self.function_pointer_arg_types.is_empty() {
                return ParamType::Pointer;
            }
            let params = if self.function_pointer_arg_types.is_empty() {
                vec![ParamType::Pointer]
            } else {
                self.function_pointer_arg_types.clone()
            };
            return ParamType::FunctionPointer {
                return_type: Box::new(
                    self.function_pointer_return_type
                        .clone()
                        .unwrap_or(ParamType::SignedInt(64)),
                ),
                params,
            };
        }

        // If dereferenced, it's a pointer
        if self.is_dereferenced || self.is_pointer_arithmetic || self.is_null_checked {
            return ParamType::Pointer;
        }

        // If passed to string functions, it's a char*
        if self.is_string_arg {
            return ParamType::Pointer;
        }

        // If used as array index or loop bound, likely unsigned
        if self.is_array_index || self.is_loop_bound || self.is_size_param {
            return ParamType::UnsignedInt(base_size * 8);
        }

        // If unsigned operations, use unsigned
        if self.is_unsigned_ops {
            return ParamType::UnsignedInt(base_size * 8);
        }

        // Default to signed
        ParamType::SignedInt(base_size * 8)
    }

    /// Returns a better parameter name based on usage.
    pub fn suggest_name(&self, index: usize) -> String {
        if self.is_string_arg {
            return match index {
                0 => "str".to_string(),
                1 => "str2".to_string(),
                _ => format!("str{}", index),
            };
        }

        if self.is_dereferenced || self.is_pointer_arithmetic {
            return match index {
                0 => "ptr".to_string(),
                1 => "ptr2".to_string(),
                _ => format!("ptr{}", index),
            };
        }

        if self.is_size_param || self.is_loop_bound {
            return match index {
                0 => "size".to_string(),
                1 => "count".to_string(),
                2 => "len".to_string(),
                _ => format!("n{}", index),
            };
        }

        if self.is_array_index {
            return match index {
                0 => "index".to_string(),
                1 => "idx".to_string(),
                _ => format!("i{}", index),
            };
        }

        format!("arg{}", index)
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
    /// Function pointer type.
    FunctionPointer {
        /// Return type of the callback.
        return_type: Box<ParamType>,
        /// Callback parameter types.
        params: Vec<ParamType>,
    },
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
            ParamType::FunctionPointer {
                return_type,
                params,
            } => {
                let params_str = if params.is_empty() {
                    "void".to_string()
                } else {
                    params
                        .iter()
                        .map(ParamType::to_c_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!("{} (*)({})", return_type.to_c_string(), params_str)
            }
        }
    }

    /// Formats a type as a C parameter declaration with a variable name.
    pub fn format_with_name(&self, name: &str) -> String {
        match self {
            ParamType::FunctionPointer {
                return_type,
                params,
            } => {
                let params_str = if params.is_empty() {
                    "void".to_string()
                } else {
                    params
                        .iter()
                        .map(ParamType::to_c_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                format!("{} (*{})({})", return_type.to_c_string(), name, params_str)
            }
            _ => format!("{} {}", self.to_c_string(), name),
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
            ParamType::FunctionPointer { .. } => 8,
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
    /// Confidence in inferred type (0-255, higher is better).
    pub type_confidence: u8,
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
            type_confidence: u8::MAX,
        }
    }

    /// Sets type confidence for this parameter.
    pub fn with_confidence(mut self, confidence: u8) -> Self {
        self.type_confidence = confidence;
        self
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
            type_confidence: u8::MAX,
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
            type_confidence: u8::MAX,
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
    /// Per-parameter inference reasons, keyed by parameter index.
    pub parameter_provenance: HashMap<usize, Vec<String>>,
    /// Inference reasons for return type recovery.
    pub return_provenance: Vec<String>,
    /// Confidence in inferred return type (0-255, higher is better).
    pub return_confidence: u8,
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
                .map(|p| p.param_type.format_with_name(&p.name))
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
                .map(|p| p.param_type.format_with_name(&p.name))
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
/// 4. Analyzing usage patterns for better type inference
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
    /// Recovered function-pointer return type when applicable.
    return_function_pointer: Option<ParamType>,
    /// Candidate return type inferred from tail-position call forwarding.
    tail_call_return_type: Option<ParamType>,
    /// Human-readable reasons that led to return type inference.
    return_provenance: Vec<String>,
    /// Confidence in return type inference.
    return_confidence: u8,
    /// Parameter names assigned from stack slot analysis.
    param_names: HashMap<usize, String>,
    /// Usage hints for parameters (indexed by arg register index).
    param_hints: HashMap<usize, ParameterUsageHints>,
    /// Aliases from local variable name to candidate function-pointer parameter indices.
    ///
    /// A single alias can map to multiple argument indices when lifted temporaries are reused.
    /// We only treat alias mappings as precise when the candidate set is unambiguous.
    function_pointer_aliases: HashMap<String, BTreeSet<usize>>,
    /// Function-pointer typed locals derived from assignments/returns.
    value_function_pointer_types: HashMap<String, ParamType>,
    /// String functions for detection.
    string_functions: HashSet<&'static str>,
    /// Optional relocation table for resolving IndirectGot call targets.
    relocation_table: Option<RelocationTable>,
    /// Optional symbol table for resolving direct-call targets.
    symbol_table: Option<SymbolTable>,
    /// Optional inter-procedural summary database for signature hints.
    summary_database: Option<Arc<super::interprocedural::SummaryDatabase>>,
}

impl SignatureRecovery {
    /// Creates a new signature recovery engine with the given calling convention.
    pub fn new(convention: CallingConvention) -> Self {
        let string_functions: HashSet<&'static str> = [
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat", "strncat", "strchr",
            "strrchr", "strstr", "strtok", "strdup", "strndup", "sprintf", "snprintf", "sscanf",
            "printf", "fprintf", "puts", "fputs", "gets", "fgets", "atoi", "atol", "atof",
            "strtol", "strtoul", "strtod",
        ]
        .into_iter()
        .collect();

        Self {
            convention,
            read_regs: HashSet::new(),
            written_regs: HashSet::new(),
            reg_sizes: HashMap::new(),
            return_value_set: false,
            return_size: 8,
            float_return: false,
            return_function_pointer: None,
            tail_call_return_type: None,
            return_provenance: Vec::new(),
            return_confidence: 0,
            param_names: HashMap::new(),
            param_hints: HashMap::new(),
            function_pointer_aliases: HashMap::new(),
            value_function_pointer_types: HashMap::new(),
            string_functions,
            relocation_table: None,
            symbol_table: None,
            summary_database: None,
        }
    }

    /// Provides relocation data for resolving indirect GOT call targets.
    pub fn with_relocation_table(mut self, relocation_table: Option<RelocationTable>) -> Self {
        self.relocation_table = relocation_table;
        self
    }

    /// Provides symbol names for resolving direct call targets.
    pub fn with_symbol_table(mut self, symbol_table: Option<SymbolTable>) -> Self {
        self.symbol_table = symbol_table;
        self
    }

    /// Provides inter-procedural summaries for additional signature hints.
    pub fn with_summary_database(
        mut self,
        summary_database: Option<Arc<super::interprocedural::SummaryDatabase>>,
    ) -> Self {
        self.summary_database = summary_database;
        self
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
        self.return_function_pointer = None;
        self.tail_call_return_type = None;
        self.return_provenance.clear();
        self.return_confidence = 0;
        self.param_names.clear();
        self.param_hints.clear();
        self.function_pointer_aliases.clear();
        self.value_function_pointer_types.clear();

        // Analyze the function body
        self.analyze_nodes(&cfg.body, false);

        // Recover "return callee(...);" style wrappers where only a tail-position call is present.
        if !self.return_value_set {
            if let Some(candidate) = self.tail_call_return_type.clone() {
                if !matches!(candidate, ParamType::Void | ParamType::Unknown) {
                    self.return_value_set = true;
                    self.return_size = candidate.size().max(1);
                    if matches!(candidate, ParamType::FunctionPointer { .. }) {
                        self.return_function_pointer = Some(candidate);
                    } else {
                        self.return_confidence = self.return_confidence.max(140);
                    }
                    self.return_provenance
                        .push("tail-position call return forwarding".to_string());
                }
            }
        }

        // Build the signature
        self.build_signature()
    }

    /// Records a usage hint for a parameter.
    fn record_usage_hint(
        &mut self,
        reg_name: &str,
        hint_fn: impl FnOnce(&mut ParameterUsageHints),
    ) {
        if let Some(idx) = self.arg_register_index(reg_name) {
            let hints = self.param_hints.entry(idx).or_default();
            hint_fn(hints);
        }
    }

    /// Checks if an expression is a null constant (0).
    fn is_null_constant(expr: &Expr) -> bool {
        matches!(expr.kind, ExprKind::IntLit(0))
    }

    /// Extracts a function name from a call target.
    fn extract_call_name(&self, target: &super::expression::CallTarget) -> Option<String> {
        match target {
            super::expression::CallTarget::Named(name) => Some(name.clone()),
            super::expression::CallTarget::Direct { target, call_site } => self
                .relocation_table
                .as_ref()
                .and_then(|t| t.get(*call_site).map(ToString::to_string))
                .or_else(|| {
                    self.symbol_table
                        .as_ref()
                        .and_then(|t| t.get(*target).map(ToString::to_string))
                }),
            super::expression::CallTarget::Indirect(_) => None,
            super::expression::CallTarget::IndirectGot { got_address, .. } => self
                .relocation_table
                .as_ref()
                .and_then(|t| t.get_got(*got_address).map(|s| s.to_string()))
                .or_else(|| {
                    self.symbol_table
                        .as_ref()
                        .and_then(|t| t.get(*got_address).map(ToString::to_string))
                }),
        }
    }

    /// Analyzes a list of structured nodes.
    fn analyze_nodes(&mut self, nodes: &[StructuredNode], in_return_path: bool) {
        for (i, node) in nodes.iter().enumerate() {
            // Check if this node is on, or directly feeds, a return path.
            let next_is_void_return = nodes
                .get(i + 1)
                .is_some_and(|n| matches!(n, StructuredNode::Return(None)));
            let is_near_return = in_return_path || (i == nodes.len() - 1) || next_is_void_return;
            self.analyze_node(node, is_near_return);
        }
    }

    /// Analyzes a single structured node.
    fn analyze_node(&mut self, node: &StructuredNode, in_return_path: bool) {
        match node {
            StructuredNode::Block { statements, .. } => {
                for (i, stmt) in statements.iter().enumerate() {
                    // For statements near the end of a block on a return path, check for
                    // return value setup and tail-call forwarding patterns.
                    let near_ret = in_return_path && i + 3 >= statements.len();
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
            StructuredNode::Loop { body, .. } => {
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
                if !self
                    .return_provenance
                    .iter()
                    .any(|r| r == "explicit return expression")
                {
                    self.return_provenance
                        .push("explicit return expression".to_string());
                }
                self.return_confidence = self.return_confidence.max(200);
                // Infer return type from expression
                if let Some(size) = self.infer_expr_size(expr) {
                    self.return_size = size;
                    let reason = format!("return expression width inferred as {} byte(s)", size);
                    if !self.return_provenance.iter().any(|r| r == &reason) {
                        self.return_provenance.push(reason);
                    }
                }
                if let Some(fp) = self.infer_return_function_pointer(expr) {
                    self.return_function_pointer = Some(fp);
                    if !self
                        .return_provenance
                        .iter()
                        .any(|r| r == "return expression inferred as function pointer")
                    {
                        self.return_provenance
                            .push("return expression inferred as function pointer".to_string());
                    }
                    self.return_confidence = self.return_confidence.max(240);
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
                if near_return && !self.return_value_set {
                    if let Some(candidate) = self.infer_tail_call_return_type(rhs) {
                        self.tail_call_return_type = Some(candidate);
                    }
                }

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
                        let reason = format!(
                            "value assigned to return register '{}' near return",
                            reg_lower
                        );
                        if !self.return_provenance.iter().any(|r| r == &reason) {
                            self.return_provenance.push(reason);
                        }
                        self.return_confidence = self.return_confidence.max(160);
                        if let Some(size) = self.infer_expr_size(rhs) {
                            self.return_size = size;
                            let reason =
                                format!("return register value width inferred as {} byte(s)", size);
                            if !self.return_provenance.iter().any(|r| r == &reason) {
                                self.return_provenance.push(reason);
                            }
                            self.return_confidence = self.return_confidence.max(170);
                        }
                        if let Some(fp) = self.infer_return_function_pointer(rhs) {
                            self.return_function_pointer = Some(fp);
                            if !self.return_provenance.iter().any(|r| {
                                r == "return register assignment inferred as function pointer"
                            }) {
                                self.return_provenance.push(
                                    "return register assignment inferred as function pointer"
                                        .to_string(),
                                );
                            }
                            self.return_confidence = self.return_confidence.max(230);
                        }
                        if self.is_float_return_register(&reg_lower) {
                            self.float_return = true;
                            if !self
                                .return_provenance
                                .iter()
                                .any(|r| r == "float return register observed")
                            {
                                self.return_provenance
                                    .push("float return register observed".to_string());
                            }
                            self.return_confidence = self.return_confidence.max(200);
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

                if let Some(lhs_name) = self.extract_var_name(lhs) {
                    if let Some(idx) = self.resolve_param_index_from_expr_precise(rhs) {
                        self.insert_function_pointer_alias(&lhs_name, idx);
                    }
                    if let Some(rhs_name) = self.extract_var_name(rhs) {
                        if let Some(ty) = self.value_function_pointer_types.get(&rhs_name).cloned()
                        {
                            self.value_function_pointer_types
                                .insert(lhs_name.clone(), ty);
                        }
                    }
                    if let Some(fp_ty) = self.infer_return_function_pointer(rhs) {
                        self.value_function_pointer_types.insert(lhs_name, fp_ty);
                    }
                }
            }
            ExprKind::Call { .. } => {
                if near_return && !self.return_value_set {
                    if let Some(candidate) = self.infer_tail_call_return_type(expr) {
                        self.tail_call_return_type = Some(candidate);
                    }
                }
                self.analyze_expr_reads(expr);
            }
            _ => {
                self.analyze_expr_reads(expr);
            }
        }
    }

    /// Analyzes an expression for register reads (argument detection).
    fn analyze_expr_reads(&mut self, expr: &Expr) {
        self.analyze_expr_reads_with_context(expr, false, false);
    }

    /// Analyzes an expression with context about how it's being used.
    fn analyze_expr_reads_with_context(
        &mut self,
        expr: &Expr,
        is_dereferenced: bool,
        is_comparison: bool,
    ) {
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
                        self.reg_sizes.insert(name.clone(), size);
                    }

                    // Record usage hints
                    if is_dereferenced {
                        self.record_usage_hint(&name, |h| h.is_dereferenced = true);
                    }
                    if is_comparison {
                        self.record_usage_hint(&name, |h| h.is_signed_comparison = true);
                    }
                }
            }
            ExprKind::BinOp { op, left, right } => {
                // Check for null comparison: arg == 0 or arg != 0
                let is_null_cmp = matches!(op, BinOpKind::Eq | BinOpKind::Ne)
                    && (Self::is_null_constant(left) || Self::is_null_constant(right));

                if is_null_cmp {
                    if let ExprKind::Var(var) = &left.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_null_checked = true
                        });
                    }
                    if let ExprKind::Var(var) = &right.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_null_checked = true
                        });
                    }
                }

                // Check for pointer arithmetic - only when adding/subtracting a scaled value
                // (e.g., ptr + i * sizeof(T) or ptr + constant offset)
                if matches!(op, BinOpKind::Add | BinOpKind::Sub) {
                    // Check if right side looks like an offset (scaled index or small constant)
                    let right_is_offset = match &right.kind {
                        ExprKind::BinOp {
                            op: BinOpKind::Mul | BinOpKind::Shl,
                            ..
                        } => true,
                        ExprKind::IntLit(n) => *n != 0 && (*n < 0x1000 || *n > 0), // Small offset
                        _ => false,
                    };

                    if right_is_offset {
                        if let ExprKind::Var(var) = &left.kind {
                            if self.is_arg_register(&var.name.to_lowercase()) {
                                self.record_usage_hint(&var.name.to_lowercase(), |h| {
                                    h.is_pointer_arithmetic = true
                                });
                            }
                        }
                    }
                }

                // Check for signed comparisons
                let is_signed_cmp = matches!(
                    op,
                    BinOpKind::Lt | BinOpKind::Le | BinOpKind::Gt | BinOpKind::Ge
                );

                // Check for unsigned shift right (typically unsigned)
                if matches!(op, BinOpKind::Shr) {
                    if let ExprKind::Var(var) = &left.kind {
                        self.record_usage_hint(&var.name.to_lowercase(), |h| {
                            h.is_unsigned_ops = true
                        });
                    }
                }

                self.analyze_expr_reads_with_context(left, false, is_signed_cmp);
                self.analyze_expr_reads_with_context(right, false, is_signed_cmp);
            }
            ExprKind::UnaryOp { operand, .. } => {
                self.analyze_expr_reads_with_context(operand, false, is_comparison);
            }
            ExprKind::Deref { addr, .. } => {
                // The address expression is being dereferenced
                self.analyze_expr_reads_with_context(addr, true, false);
            }
            ExprKind::ArrayAccess { base, index, .. } => {
                // Base is being used as a pointer
                self.analyze_expr_reads_with_context(base, true, false);
                // Index might be an array index parameter
                if let ExprKind::Var(var) = &index.kind {
                    self.record_usage_hint(&var.name.to_lowercase(), |h| h.is_array_index = true);
                }
                self.analyze_expr_reads_with_context(index, false, false);
            }
            ExprKind::Assign { lhs, rhs } => {
                self.analyze_expr_reads_with_context(rhs, false, false);
                // Don't analyze LHS reads - it's being written
                if let ExprKind::Deref { addr, .. } = &lhs.kind {
                    self.analyze_expr_reads_with_context(addr, true, false);
                }
            }
            ExprKind::Call { target, args } => {
                if let super::expression::CallTarget::Indirect(inner) = target {
                    if let ExprKind::Var(var) = &inner.kind {
                        let name = var.name.to_lowercase();
                        if self.arg_register_index(&name).is_some() {
                            self.record_function_pointer_call_signature(&name, args);
                        } else if let Some(idx) = self.resolve_alias_param_index(&name) {
                            self.record_function_pointer_call_signature_by_index(idx, args);
                        }
                    }
                    self.analyze_expr_reads_with_context(inner, false, false);
                } else if let super::expression::CallTarget::IndirectGot { expr, .. } = target {
                    if let ExprKind::Var(var) = &expr.kind {
                        let name = var.name.to_lowercase();
                        if self.arg_register_index(&name).is_some() {
                            self.record_function_pointer_call_signature(&name, args);
                        } else if let Some(idx) = self.resolve_alias_param_index(&name) {
                            self.record_function_pointer_call_signature_by_index(idx, args);
                        }
                    }
                    self.analyze_expr_reads_with_context(expr, false, false);
                }

                // Check if calling a string function
                let func_name = self.extract_call_name(target);
                let is_string_fn = func_name
                    .as_ref()
                    .map(|n| {
                        let clean_name = n.strip_prefix('_').unwrap_or(n);
                        self.string_functions.contains(clean_name)
                    })
                    .unwrap_or(false);

                for (i, arg) in args.iter().enumerate() {
                    // First arg to string functions is typically a string
                    if is_string_fn && i == 0 {
                        if let ExprKind::Var(var) = &arg.kind {
                            self.record_usage_hint(&var.name.to_lowercase(), |h| {
                                h.is_string_arg = true
                            });
                        }
                    }

                    // Record which functions parameters are passed to.
                    if let Some(fn_name) = &func_name {
                        let var_name = self.extract_var_name(arg);
                        if let Some(name) = &var_name {
                            self.record_usage_hint(name, |h| {
                                h.passed_to_functions.push(fn_name.clone())
                            });
                        }

                        let is_callback_slot = Self::is_callback_position(fn_name, i);
                        let mut resolved_param_idx = self.resolve_param_index_from_expr(arg);
                        let mut used_shape_fallback = false;
                        let mut used_slot_fallback = false;
                        let mut used_slot_zero_bias = false;
                        if is_callback_slot && resolved_param_idx.is_none() {
                            let callback_slots = self.callback_slot_indices(fn_name);
                            if callback_slots.len() > 1
                                && Self::prefer_slot_ordinal_callback_fallback(fn_name)
                            {
                                // Multi-callback APIs (e.g., pthread_atfork) often map each
                                // callback slot to the same-ordinal parameter.
                                resolved_param_idx = Some(i);
                                used_slot_fallback = true;
                            } else {
                                let mut excluded = HashSet::new();
                                for (other_i, other_arg) in args.iter().enumerate() {
                                    if other_i == i
                                        || ParameterUsageHints::callback_signature(fn_name, other_i)
                                            .is_some()
                                    {
                                        continue;
                                    }
                                    if let Some(other_idx) =
                                        self.resolve_param_index_from_expr(other_arg)
                                    {
                                        excluded.insert(other_idx);
                                    }
                                }
                                resolved_param_idx = if callback_slots.as_slice() == [0] {
                                    let slot0_choice = self
                                        .fallback_callback_param_index_excluding_lowest(&excluded);
                                    used_slot_zero_bias = slot0_choice.is_some();
                                    slot0_choice
                                        .or_else(|| {
                                            self.fallback_callback_param_index_excluding(&excluded)
                                        })
                                        .or_else(|| self.fallback_callback_param_index())
                                } else {
                                    self.fallback_callback_param_index_excluding(&excluded)
                                        .or_else(|| self.fallback_callback_param_index())
                                };
                                used_shape_fallback = resolved_param_idx.is_some();
                            }
                        }
                        if is_callback_slot {
                            if let Some(name) = &var_name {
                                self.record_usage_hint(name, |h| {
                                    h.passed_as_callback_to.push((fn_name.clone(), i));
                                    h.function_pointer_confidence =
                                        h.function_pointer_confidence.saturating_add(4);
                                    h.add_function_pointer_reason(format!(
                                        "passed to '{}' argument {} (callback slot)",
                                        fn_name, i
                                    ));
                                });
                            }
                            if let Some(param_idx) = resolved_param_idx {
                                let hints = self.param_hints.entry(param_idx).or_default();
                                hints.is_function_pointer = true;
                                hints.function_pointer_confidence =
                                    hints.function_pointer_confidence.saturating_add(4);
                                hints.passed_as_callback_to.push((fn_name.clone(), i));
                                hints.add_function_pointer_reason(format!(
                                    "[source=alias] alias/forwarded value passed to '{}' argument {} (callback slot)",
                                    fn_name, i
                                ));
                                if used_shape_fallback {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=shape-fallback] mapped callback slot '{}' argument {} by ABI-shaped fallback",
                                        fn_name, i
                                    ));
                                    if used_slot_zero_bias {
                                        hints.add_function_pointer_reason(
                                            "[source=shape-fallback] preferred lowest candidate for slot-0 callback"
                                                .to_string(),
                                        );
                                    }
                                }
                                if used_slot_fallback {
                                    hints.add_function_pointer_reason(format!(
                                        "[source=slot-fallback] mapped callback slot '{}' argument {} by slot ordinal",
                                        fn_name, i
                                    ));
                                }
                            }
                        }
                        if let Some(sig) = self.callback_signature_from_summary(fn_name, i) {
                            if let Some(name) = &var_name {
                                let sig_for_hint = sig.clone();
                                self.record_usage_hint(name, |h| {
                                    h.is_function_pointer = true;
                                    h.function_pointer_confidence =
                                        h.function_pointer_confidence.saturating_add(5);
                                    h.add_function_pointer_reason(format!(
                                        "[source=summary] summary marks '{}' argument {} as function-pointer callback",
                                        fn_name, i
                                    ));
                                    if let ParamType::FunctionPointer {
                                        return_type,
                                        params,
                                    } = sig_for_hint.clone()
                                    {
                                        h.function_pointer_arg_types = params;
                                        h.function_pointer_return_type = Some(*return_type);
                                    }
                                });
                            }
                            if let Some(param_idx) = resolved_param_idx {
                                let hints = self.param_hints.entry(param_idx).or_default();
                                hints.is_function_pointer = true;
                                hints.function_pointer_confidence =
                                    hints.function_pointer_confidence.saturating_add(5);
                                hints.passed_as_callback_to.push((fn_name.clone(), i));
                                hints.add_function_pointer_reason(format!(
                                    "[source=summary] summary callback type propagated through alias for '{}' argument {}",
                                    fn_name, i
                                ));
                                if let ParamType::FunctionPointer {
                                    return_type,
                                    params,
                                } = sig
                                {
                                    hints.function_pointer_arg_types = params;
                                    hints.function_pointer_return_type = Some(*return_type);
                                }
                            }
                        }
                    }

                    self.analyze_expr_reads_with_context(arg, false, false);
                }
            }
            ExprKind::Cast { expr: inner, .. } => {
                self.analyze_expr_reads_with_context(inner, is_dereferenced, is_comparison);
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

    /// Returns true when a function argument position is typically a callback.
    fn is_callback_position(function_name: &str, arg_index: usize) -> bool {
        ParameterUsageHints::callback_signature(function_name, arg_index).is_some()
    }

    fn param_type_from_summary(summary: &super::interprocedural::SummaryType) -> ParamType {
        use super::interprocedural::SummaryType;
        match summary {
            SummaryType::Unknown => ParamType::Unknown,
            SummaryType::Void => ParamType::Void,
            SummaryType::Bool => ParamType::Bool,
            SummaryType::SignedInt(bits) => ParamType::SignedInt((*bits).min(64)),
            SummaryType::UnsignedInt(bits) => ParamType::UnsignedInt((*bits).min(64)),
            SummaryType::Float(bits) => ParamType::Float((*bits).min(64)),
            SummaryType::Pointer(_) => ParamType::Pointer,
            SummaryType::Array(_, _) => ParamType::Pointer,
            SummaryType::Struct(_) => ParamType::Pointer,
            SummaryType::FunctionPointer {
                return_type,
                params,
            } => ParamType::FunctionPointer {
                return_type: Box::new(Self::param_type_from_summary(return_type)),
                params: params.iter().map(Self::param_type_from_summary).collect(),
            },
        }
    }

    fn callback_signature_from_summary(
        &self,
        function_name: &str,
        arg_index: usize,
    ) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        let ty = summary.param_types.get(&arg_index)?;
        match ty {
            super::interprocedural::SummaryType::FunctionPointer { .. } => {
                Some(Self::param_type_from_summary(ty))
            }
            _ => None,
        }
    }

    fn return_function_pointer_from_summary(&self, function_name: &str) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        let ty = summary.return_type.as_ref()?;
        match ty {
            super::interprocedural::SummaryType::FunctionPointer { .. } => {
                Some(Self::param_type_from_summary(ty))
            }
            _ => None,
        }
    }

    fn return_type_from_summary(&self, function_name: &str) -> Option<ParamType> {
        let db = self.summary_database.as_ref()?;
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        let summary = db.get_summary_by_name(clean)?;
        summary
            .return_type
            .as_ref()
            .map(Self::param_type_from_summary)
    }

    fn known_call_return_type(function_name: &str) -> Option<ParamType> {
        let clean = ParameterUsageHints::normalize_callback_name(function_name);
        match clean {
            "qsort" | "qsort_r" | "qsort_s" | "bsd_qsort_r" => Some(ParamType::Void),
            "hexray_qsort_r"
            | "hexray_bsd_qsort_r"
            | "pthread_create"
            | "on_exit"
            | "hexray_on_exit"
            | "pthread_atfork"
            | "hexray_pthread_atfork" => Some(ParamType::SignedInt(32)),
            "bsearch" => Some(ParamType::Pointer),
            "signal" | "bsd_signal" | "sysv_signal" | "sigset" => {
                Some(ParamType::FunctionPointer {
                    return_type: Box::new(ParamType::Void),
                    params: vec![ParamType::SignedInt(32)],
                })
            }
            _ => None,
        }
    }

    fn infer_tail_call_return_type(&self, expr: &Expr) -> Option<ParamType> {
        if let ExprKind::Call { target, .. } = &expr.kind {
            let name = self.extract_call_name(target)?;
            if let Some(summary_ty) = self.return_type_from_summary(&name) {
                return Some(summary_ty);
            }
            return Self::known_call_return_type(&name);
        }
        None
    }

    /// Infers a type for an argument passed into an indirect function call.
    fn infer_indirect_call_arg_type(expr: &Expr) -> ParamType {
        match &expr.kind {
            ExprKind::Deref { .. }
            | ExprKind::AddressOf(_)
            | ExprKind::ArrayAccess { .. }
            | ExprKind::FieldAccess { .. }
            | ExprKind::GotRef { .. } => ParamType::Pointer,
            ExprKind::IntLit(n) => {
                if *n >= i32::MIN as i128 && *n <= i32::MAX as i128 {
                    ParamType::SignedInt(32)
                } else {
                    ParamType::SignedInt(64)
                }
            }
            ExprKind::Var(var) => {
                let name = var.name.to_lowercase();
                if name.starts_with("xmm") || name.starts_with("d") {
                    ParamType::Float(64)
                } else if name.starts_with("s") {
                    ParamType::Float(32)
                } else {
                    match var.size {
                        1 => ParamType::SignedInt(8),
                        2 => ParamType::SignedInt(16),
                        4 => ParamType::SignedInt(32),
                        8 => ParamType::SignedInt(64),
                        _ => ParamType::SignedInt(64),
                    }
                }
            }
            ExprKind::Cast {
                to_size,
                signed,
                expr: _,
            } => match (*to_size, *signed) {
                (1, true) => ParamType::SignedInt(8),
                (2, true) => ParamType::SignedInt(16),
                (4, true) => ParamType::SignedInt(32),
                (8, true) => ParamType::SignedInt(64),
                (1, false) => ParamType::UnsignedInt(8),
                (2, false) => ParamType::UnsignedInt(16),
                (4, false) => ParamType::UnsignedInt(32),
                (8, false) => ParamType::UnsignedInt(64),
                _ => ParamType::SignedInt(64),
            },
            _ => ParamType::SignedInt(64),
        }
    }

    fn merge_param_types(a: &ParamType, b: &ParamType) -> ParamType {
        match (a, b) {
            (ParamType::Unknown, t) | (t, ParamType::Unknown) => t.clone(),
            (ParamType::Pointer, _) | (_, ParamType::Pointer) => ParamType::Pointer,
            (ParamType::Float(sa), ParamType::Float(sb)) => ParamType::Float((*sa).max(*sb)),
            (ParamType::UnsignedInt(sa), ParamType::UnsignedInt(sb)) => {
                ParamType::UnsignedInt((*sa).max(*sb))
            }
            (ParamType::SignedInt(sa), ParamType::SignedInt(sb)) => {
                ParamType::SignedInt((*sa).max(*sb))
            }
            (ParamType::SignedInt(sa), ParamType::UnsignedInt(sb))
            | (ParamType::UnsignedInt(sa), ParamType::SignedInt(sb)) => {
                ParamType::SignedInt((*sa).max(*sb))
            }
            (ParamType::FunctionPointer { .. }, _) | (_, ParamType::FunctionPointer { .. }) => {
                ParamType::Pointer
            }
            _ => ParamType::Unknown,
        }
    }

    fn is_ambiguous_indirect_arg_type(ty: &ParamType) -> bool {
        matches!(ty, ParamType::Unknown | ParamType::SignedInt(64))
    }

    fn record_function_pointer_call_signature(&mut self, reg_name: &str, args: &[Expr]) {
        let Some(idx) = self.arg_register_index(reg_name) else {
            return;
        };
        self.record_function_pointer_call_signature_by_index(idx, args);
    }

    fn record_function_pointer_call_signature_by_index(&mut self, idx: usize, args: &[Expr]) {
        let mut inferred: Vec<ParamType> = args
            .iter()
            .map(Self::infer_indirect_call_arg_type)
            .collect();
        let informative_count = inferred
            .iter()
            .filter(|ty| !Self::is_ambiguous_indirect_arg_type(ty))
            .count();
        if informative_count == 0 {
            inferred = vec![ParamType::Pointer; inferred.len()];
        } else {
            inferred = inferred
                .into_iter()
                .map(|ty| {
                    if Self::is_ambiguous_indirect_arg_type(&ty) {
                        ParamType::Pointer
                    } else {
                        ty
                    }
                })
                .collect();
        }

        let hints = self.param_hints.entry(idx).or_default();
        hints.is_function_pointer = true;
        hints.function_pointer_confidence = hints
            .function_pointer_confidence
            .saturating_add(if informative_count > 0 { 2 } else { 1 });
        hints.add_function_pointer_reason(if informative_count > 0 {
            format!(
                "used as indirect call target with {} observed argument(s)",
                args.len()
            )
        } else {
            "used as indirect call target (argument types ambiguous)".to_string()
        });
        if hints.function_pointer_return_type.is_none() {
            hints.function_pointer_return_type = Some(ParamType::SignedInt(64));
        }
        if hints.function_pointer_arg_types.is_empty() {
            hints.function_pointer_arg_types = inferred;
            return;
        }

        let common_len = hints.function_pointer_arg_types.len().min(inferred.len());
        for (i, inferred_ty) in inferred.iter().enumerate().take(common_len) {
            let merged = Self::merge_param_types(&hints.function_pointer_arg_types[i], inferred_ty);
            hints.function_pointer_arg_types[i] = merged;
        }

        if inferred.len() > hints.function_pointer_arg_types.len() {
            hints
                .function_pointer_arg_types
                .extend_from_slice(&inferred[hints.function_pointer_arg_types.len()..]);
        }
    }

    fn infer_return_function_pointer(&self, expr: &Expr) -> Option<ParamType> {
        match &expr.kind {
            ExprKind::Var(var) => {
                if let Some(idx) = self.arg_register_index(&var.name) {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        let ty = hints.infer_type(var.size.max(8));
                        if matches!(ty, ParamType::FunctionPointer { .. }) {
                            return Some(ty);
                        }
                    }
                }
                self.value_function_pointer_types
                    .get(&var.name.to_lowercase())
                    .cloned()
            }
            ExprKind::Call { target, .. } => {
                let name = self.extract_call_name(target)?;
                let clean = name.strip_prefix('_').unwrap_or(&name);
                match clean {
                    "signal" | "bsd_signal" | "sysv_signal" | "sigset" => {
                        Some(ParamType::FunctionPointer {
                            return_type: Box::new(ParamType::Void),
                            params: vec![ParamType::SignedInt(32)],
                        })
                    }
                    _ => self.return_function_pointer_from_summary(clean),
                }
            }
            ExprKind::Cast { expr: inner, .. } => self.infer_return_function_pointer(inner),
            _ => None,
        }
    }

    fn resolve_alias_param_index(&self, var_name: &str) -> Option<usize> {
        let candidates = self.function_pointer_aliases.get(var_name)?;
        if candidates.len() == 1 {
            candidates.iter().next().copied()
        } else {
            None
        }
    }

    fn insert_function_pointer_alias(&mut self, lhs_name: &str, idx: usize) {
        self.function_pointer_aliases
            .entry(lhs_name.to_string())
            .or_default()
            .insert(idx);
        if let Some(offset_str) = lhs_name.strip_prefix("stack_") {
            if let Ok(offset) = offset_str.parse::<i128>() {
                if offset < 0 {
                    let abs = (-offset) as u128;
                    self.function_pointer_aliases
                        .entry(format!("arg_{:x}", abs))
                        .or_default()
                        .insert(idx);
                    self.function_pointer_aliases
                        .entry(format!("local_{:x}", abs))
                        .or_default()
                        .insert(idx);
                } else {
                    let val = offset as u128;
                    self.function_pointer_aliases
                        .entry(format!("var_{:x}", val))
                        .or_default()
                        .insert(idx);
                }
            }
        }
    }

    fn fallback_callback_param_index(&self) -> Option<usize> {
        let max_from_reads = self
            .read_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
            .max();
        let max_from_writes = self
            .written_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
            .max();
        let max_from_aliases = self
            .function_pointer_aliases
            .values()
            .flat_map(|indices| indices.iter().copied())
            .max();
        [max_from_reads, max_from_writes, max_from_aliases]
            .into_iter()
            .flatten()
            .max()
    }

    fn fallback_callback_param_index_excluding(&self, excluded: &HashSet<usize>) -> Option<usize> {
        let mut candidates = BTreeSet::new();
        for idx in self
            .read_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .written_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .function_pointer_aliases
            .values()
            .flat_map(|indices| indices.iter().copied())
        {
            candidates.insert(idx);
        }
        candidates
            .into_iter()
            .rev()
            .find(|idx| !excluded.contains(idx))
    }

    fn fallback_callback_param_index_excluding_lowest(
        &self,
        excluded: &HashSet<usize>,
    ) -> Option<usize> {
        let mut candidates = BTreeSet::new();
        for idx in self
            .read_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .written_regs
            .iter()
            .filter_map(|name| self.arg_register_index(name))
        {
            candidates.insert(idx);
        }
        for idx in self
            .function_pointer_aliases
            .values()
            .flat_map(|indices| indices.iter().copied())
        {
            candidates.insert(idx);
        }
        candidates.into_iter().find(|idx| !excluded.contains(idx))
    }

    fn callback_slot_indices(&self, function_name: &str) -> Vec<usize> {
        (0..8)
            .filter(|idx| ParameterUsageHints::callback_signature(function_name, *idx).is_some())
            .collect()
    }

    fn prefer_slot_ordinal_callback_fallback(function_name: &str) -> bool {
        matches!(
            ParameterUsageHints::normalize_callback_name(function_name),
            "pthread_atfork" | "hexray_pthread_atfork"
        )
    }

    fn resolve_param_index_from_name_internal(
        &self,
        var_name: &str,
        allow_fallback: bool,
    ) -> Option<usize> {
        if let Some(idx) = self.resolve_alias_param_index(var_name) {
            return Some(idx);
        }
        if self
            .function_pointer_aliases
            .get(var_name)
            .is_some_and(|candidates| candidates.len() > 1)
        {
            return None;
        }
        if let Some(idx) = self.arg_register_index(var_name) {
            return Some(idx);
        }
        if let Some(idx) = Self::lifted_stack_slot_index(var_name) {
            return Some(idx);
        }
        if let Some(idx) = Self::lifted_local_slot_index(var_name) {
            return Some(idx);
        }
        if allow_fallback && self.may_alias_parameter(var_name) {
            return self.fallback_callback_param_index();
        }
        None
    }

    fn resolve_param_index_from_expr(&self, expr: &Expr) -> Option<usize> {
        self.resolve_param_index_from_expr_internal(expr, true)
    }

    fn resolve_param_index_from_expr_precise(&self, expr: &Expr) -> Option<usize> {
        self.resolve_param_index_from_expr_internal(expr, false)
    }

    fn resolve_param_index_from_expr_internal(
        &self,
        expr: &Expr,
        allow_fallback: bool,
    ) -> Option<usize> {
        if let Some(var_name) = self.extract_var_name(expr) {
            if let Some(idx) =
                self.resolve_param_index_from_name_internal(&var_name, allow_fallback)
            {
                return Some(idx);
            }
        }

        if let Some(offset) = self.extract_stack_offset(expr) {
            let stack_name = format!("stack_{}", offset);
            if let Some(idx) =
                self.resolve_param_index_from_name_internal(&stack_name, allow_fallback)
            {
                return Some(idx);
            }
        }

        match &expr.kind {
            ExprKind::Cast { expr: inner, .. } => {
                self.resolve_param_index_from_expr_internal(inner, allow_fallback)
            }
            ExprKind::Unknown(name) => {
                let lowered = name.to_lowercase();
                if lowered.starts_with("arg_")
                    || lowered.starts_with("var_")
                    || lowered.starts_with("local_")
                    || lowered.starts_with("stack_")
                {
                    self.resolve_param_index_from_name_internal(&lowered, allow_fallback)
                        .or_else(|| {
                            if allow_fallback {
                                self.fallback_callback_param_index()
                            } else {
                                None
                            }
                        })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn may_alias_parameter(&self, var_name: &str) -> bool {
        var_name.starts_with("arg")
            || var_name.starts_with("stack_")
            || var_name.starts_with("arg_")
            || var_name.starts_with("var_")
            || var_name.starts_with("local_")
            || self.arg_register_index(var_name).is_some()
    }

    fn extract_var_name(&self, expr: &Expr) -> Option<String> {
        match &expr.kind {
            ExprKind::Var(v) => Some(v.name.to_lowercase()),
            ExprKind::Unknown(name) => Some(name.to_lowercase()),
            ExprKind::Deref { .. } => self
                .extract_stack_offset(expr)
                .map(|offset| format!("stack_{}", offset)),
            ExprKind::Cast { expr: inner, .. } => self.extract_var_name(inner),
            _ => None,
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
        if Self::lifted_arg_slot_index(&name_lower).is_some() {
            return true;
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
        if let Some(idx) = Self::lifted_arg_slot_index(&name_lower) {
            return Some(idx);
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

    fn lifted_arg_slot_index(name: &str) -> Option<usize> {
        let suffix = name.strip_prefix("arg_")?;
        let suffix = suffix.strip_prefix("0x").unwrap_or(suffix);
        let offset = u64::from_str_radix(suffix, 16).ok()?;
        if offset < 8 || offset % 8 != 0 {
            return None;
        }
        Some(((offset - 8) / 8) as usize)
    }

    fn lifted_stack_slot_index(name: &str) -> Option<usize> {
        let suffix = name.strip_prefix("stack_")?;
        let raw = suffix.parse::<i64>().ok()?;
        if raw >= 0 {
            return None;
        }
        let offset = (-raw) as u64;
        if offset < 8 || offset % 8 != 0 {
            return None;
        }
        Some(((offset - 8) / 8) as usize)
    }

    fn lifted_local_slot_index(name: &str) -> Option<usize> {
        let suffix = name
            .strip_prefix("local_")
            .or_else(|| name.strip_prefix("var_"))?;
        let suffix = suffix.strip_prefix("0x").unwrap_or(suffix);
        let offset = u64::from_str_radix(suffix, 16).ok()?;
        if offset < 8 || offset % 8 != 0 {
            return None;
        }
        Some(((offset - 8) / 8) as usize)
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
            let pseudo_arg = format!("arg{}", idx);

            if self.read_regs.contains(&reg64_lower)
                || self.read_regs.contains(&reg32_lower)
                || self.read_regs.contains(&pseudo_arg)
                || self.param_hints.contains_key(&idx)
            {
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

                // Get usage hints for this parameter
                let hints = self.param_hints.get(&idx);

                // Infer type from usage hints if available
                let param_type = if let Some(hints) = hints {
                    hints.infer_type(size)
                } else {
                    match size {
                        1 => ParamType::SignedInt(8),
                        2 => ParamType::SignedInt(16),
                        4 => ParamType::SignedInt(32),
                        _ => ParamType::SignedInt(64),
                    }
                };

                // Use a custom name if we have one, or infer from hints
                let name = if let Some(custom_name) = self.param_names.get(&idx) {
                    custom_name.clone()
                } else if let Some(hints) = hints {
                    hints.suggest_name(idx)
                } else {
                    format!("arg{}", idx)
                };

                let confidence = hints
                    .map(|h| {
                        if matches!(param_type, ParamType::FunctionPointer { .. }) {
                            h.function_pointer_confidence
                        } else {
                            u8::MAX
                        }
                    })
                    .unwrap_or(u8::MAX);

                if matches!(param_type, ParamType::FunctionPointer { .. }) {
                    if let Some(h) = hints {
                        if !h.function_pointer_reasons.is_empty() {
                            sig.parameter_provenance
                                .insert(idx, h.function_pointer_reasons.clone());
                        }
                    }
                }

                sig.parameters.push(
                    Parameter::new(
                        name,
                        param_type,
                        ParameterLocation::IntegerRegister {
                            name: int_regs[idx].to_string(),
                            index: idx,
                        },
                    )
                    .with_confidence(confidence),
                );
            }
        }

        // Detect pointer+size parameter pairs
        self.detect_param_pairs(&mut sig);

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
        sig.return_provenance = self.return_provenance.clone();
        sig.return_confidence = self.return_confidence;
        if self.return_value_set {
            if let Some(ref fp_ty) = self.return_function_pointer {
                sig.return_type = fp_ty.clone();
            } else if self.float_return {
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

    /// Detects common parameter pairs like (buffer, size) and improves naming.
    fn detect_param_pairs(&self, sig: &mut FunctionSignature) {
        if sig.parameters.len() < 2 {
            return;
        }

        // Look for pointer + size pairs
        let mut i = 0;
        while i < sig.parameters.len() - 1 {
            let is_ptr = matches!(sig.parameters[i].param_type, ParamType::Pointer);
            let is_size = matches!(
                sig.parameters[i + 1].param_type,
                ParamType::UnsignedInt(_) | ParamType::SignedInt(32 | 64)
            );

            if is_ptr && is_size {
                // Check if the size param has hints suggesting it's a size
                let next_idx = match &sig.parameters[i + 1].location {
                    ParameterLocation::IntegerRegister { index, .. } => Some(*index),
                    _ => None,
                };

                if let Some(idx) = next_idx {
                    if let Some(hints) = self.param_hints.get(&idx) {
                        if hints.is_loop_bound || hints.is_array_index {
                            // This is likely a size parameter
                            sig.parameters[i + 1].param_type = ParamType::UnsignedInt(64);
                            if sig.parameters[i + 1].name.starts_with("arg") {
                                sig.parameters[i + 1].name = match i {
                                    0 => "size".to_string(),
                                    1 => "count".to_string(),
                                    _ => format!("n{}", i + 1),
                                };
                            }
                        }
                    }
                }
            }
            i += 1;
        }
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
    use crate::decompiler::expression::{CallTarget, Variable};
    use std::sync::Arc;

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
        let fp = ParamType::FunctionPointer {
            return_type: Box::new(ParamType::SignedInt(32)),
            params: vec![ParamType::Pointer, ParamType::Pointer],
        };
        assert_eq!(fp.to_c_string(), "int32_t (*)(void*, void*)");
        assert_eq!(fp.format_with_name("cmp"), "int32_t (*cmp)(void*, void*)");
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
    fn test_lifted_slot_index_helpers() {
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_8"), Some(0));
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_10"), Some(1));
        assert_eq!(SignatureRecovery::lifted_arg_slot_index("arg_18"), Some(2));
        assert_eq!(
            SignatureRecovery::lifted_stack_slot_index("stack_-8"),
            Some(0)
        );
        assert_eq!(
            SignatureRecovery::lifted_stack_slot_index("stack_-16"),
            Some(1)
        );
        assert_eq!(
            SignatureRecovery::lifted_local_slot_index("local_8"),
            Some(0)
        );
        assert_eq!(
            SignatureRecovery::lifted_local_slot_index("var_10"),
            Some(1)
        );
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
        assert_eq!(
            ParamType::FunctionPointer {
                return_type: Box::new(ParamType::Void),
                params: vec![ParamType::Pointer],
            }
            .size(),
            8
        );
    }

    #[test]
    fn test_signature_recovery_detects_qsort_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert!(
            matches!(
                sig.parameters[3].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("cmp"),
            "int32_t (*cmp)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_qsort_callback_via_direct_symbol_table_name() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Direct {
                target: 0x401000,
                call_site: 0x1000,
            },
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut symbols = SymbolTable::new();
        symbols.insert(0x401000, "_qsort@plt".to_string());

        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_symbol_table(Some(symbols));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert!(
            matches!(
                sig.parameters[3].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_detects_bsearch_callback_when_lifted_to_arg4() {
        use hexray_core::BasicBlockId;

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
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_indirect_call_argument() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::var(Variable::reg("rdi", 8)))),
            vec![Expr::var(Variable::reg("rsi", 8))],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty());
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*)"
        );
    }

    #[test]
    fn test_signature_recovery_inferrs_indirect_call_prototype() {
        use hexray_core::BasicBlockId;

        let fn_ptr = Expr::var(Variable::reg("rdi", 8));
        let by_ref_local = Expr::address_of(Expr::var(Variable::stack(-8, 8)));
        let call = Expr::call(
            CallTarget::Indirect(Box::new(fn_ptr)),
            vec![by_ref_local, Expr::int(7)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*, int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_tracks_alias_to_function_pointer_parameter() {
        use hexray_core::BasicBlockId;

        let alias_assign = Expr::assign(
            Expr::var(Variable::stack(-8, 8)),
            Expr::var(Variable::reg("rdi", 8)),
        );
        let indirect_call = Expr::call(
            CallTarget::Indirect(Box::new(Expr::var(Variable::stack(-8, 8)))),
            vec![Expr::var(Variable::reg("rsi", 8)), Expr::int(1)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![alias_assign, indirect_call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty());
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("cb"),
            "int64_t (*cb)(void*, int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_resolves_indirect_got_target_name() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::IndirectGot {
                got_address: 0x4040,
                expr: Box::new(Expr::var(Variable::reg("rax", 8))),
            },
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut relocs = RelocationTable::new();
        relocs.insert_got(0x4040, "qsort".to_string());

        let mut recovery =
            SignatureRecovery::new(CallingConvention::SystemV).with_relocation_table(Some(relocs));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_uses_summary_for_callback_types() {
        use hexray_core::BasicBlockId;

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
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let summary_db = Arc::new(super::super::interprocedural::SummaryDatabase::new());
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_summary_database(Some(summary_db));
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_propagates_callback_hint_through_alias() {
        use hexray_core::BasicBlockId;

        let rbp = Expr::var(Variable::reg("rbp", 8));
        let stack_slot = Expr::deref(Expr::binop(BinOpKind::Add, rbp, Expr::int(-8)), 8);
        let save_arg = Expr::assign(stack_slot.clone(), Expr::var(Variable::reg("rsi", 8)));
        let call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), stack_slot],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![save_arg, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(matches!(
            sig.parameters[1].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_propagates_callback_hint_through_lifted_var_alias() {
        use hexray_core::BasicBlockId;

        let save_arg = Expr::assign(Expr::unknown("var_8"), Expr::var(Variable::reg("rdx", 8)));
        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::int(4),
                Expr::unknown("var_8"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![save_arg, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(matches!(
            sig.parameters[2].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_handles_reused_lifted_alias_in_qsort_callback() {
        use hexray_core::BasicBlockId;

        let stmt1 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg0"));
        let stmt2 = Expr::assign(Expr::unknown("var_10"), Expr::unknown("arg1"));
        let stmt3 = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg2"));
        let call = Expr::call(
            CallTarget::Named("_qsort".to_string()),
            vec![
                Expr::unknown("arg_8"),
                Expr::unknown("var_10"),
                Expr::int(4),
                Expr::unknown("arg_8"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![stmt1, stmt2, stmt3, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.parameters.len() >= 3, "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[2].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_resolves_unknown_lifted_arg_slot_before_shape_fallback() {
        use hexray_core::BasicBlockId;

        let bind_cb = Expr::assign(Expr::unknown("arg_8"), Expr::unknown("arg0"));
        let bind_ctx = Expr::assign(Expr::unknown("var_10"), Expr::unknown("arg1"));
        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![Expr::unknown("arg_8"), Expr::unknown("var_10")],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind_cb, bind_ctx, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.parameters.is_empty(), "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        if sig.parameters.len() > 1 {
            assert!(
                !matches!(
                    sig.parameters[1].param_type,
                    ParamType::FunctionPointer { .. }
                ),
                "params: {:?}",
                sig.parameters
            );
        }
    }

    #[test]
    fn test_signature_recovery_uses_slot_ordinal_fallback_for_ambiguous_multi_callback_alias() {
        use hexray_core::BasicBlockId;

        let bind_prepare = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg0"));
        let bind_parent = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg1"));
        let bind_child = Expr::assign(Expr::unknown("tmp"), Expr::unknown("arg2"));
        let call = Expr::call(
            CallTarget::Named("pthread_atfork".to_string()),
            vec![
                Expr::unknown("tmp"),
                Expr::unknown("tmp"),
                Expr::unknown("tmp"),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![bind_prepare, bind_parent, bind_child, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.parameters.len() >= 3, "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert!(
            matches!(
                sig.parameters[1].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert!(
            matches!(
                sig.parameters[2].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_prefers_lowest_shape_fallback_for_slot0_callback() {
        use hexray_core::BasicBlockId;

        let keep_arg0_live =
            Expr::assign(Expr::unknown("tmp0"), Expr::var(Variable::reg("rdi", 8)));
        let keep_arg1_live =
            Expr::assign(Expr::unknown("tmp1"), Expr::var(Variable::reg("rsi", 8)));
        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![Expr::unknown("mystery"), Expr::int(0)],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![keep_arg0_live, keep_arg1_live, call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.parameters.len() >= 2, "params: {:?}", sig.parameters);
        assert!(
            matches!(
                sig.parameters[0].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
        assert!(
            !matches!(
                sig.parameters[1].param_type,
                ParamType::FunctionPointer { .. }
            ),
            "params: {:?}",
            sig.parameters
        );
    }

    #[test]
    fn test_signature_recovery_does_not_force_fp_for_non_parameter_callback_arg() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::int(4),
                Expr::unknown("cmp_ints"),
            ],
        );
        // Keep a fourth argument register live so fallback "last parameter" behavior
        // would previously mislabel it as a callback.
        let keep_r8_live = Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("r8", 8)));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call, keep_r8_live],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert!(!matches!(
            sig.parameters[4].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_detects_function_pointer_return() {
        use hexray_core::BasicBlockId;

        let signal_call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), Expr::var(Variable::reg("rdi", 8))],
        );

        let ret = StructuredNode::Return(Some(signal_call));
        let cfg = StructuredCfg {
            body: vec![ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(matches!(sig.return_type, ParamType::FunctionPointer { .. }));
        assert_eq!(
            sig.return_type.format_with_name("handler"),
            "void (*handler)(int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_uses_summary_fallback_for_function_pointer_return() {
        use hexray_core::BasicBlockId;

        // "__signal" bypasses the direct hardcoded name match and exercises summary fallback.
        let signal_call = Expr::call(
            CallTarget::Named("__signal".to_string()),
            vec![Expr::int(2), Expr::var(Variable::reg("rdi", 8))],
        );

        let ret = StructuredNode::Return(Some(signal_call));
        let cfg = StructuredCfg {
            body: vec![ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let summary_db = Arc::new(super::super::interprocedural::SummaryDatabase::new());
        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV)
            .with_summary_database(Some(summary_db));
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert!(matches!(sig.return_type, ParamType::FunctionPointer { .. }));
        assert_eq!(
            sig.return_type.format_with_name("handler"),
            "void (*handler)(int32_t)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_pthread_create_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_create".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 4);
        assert_eq!(
            sig.parameters[2]
                .param_type
                .format_with_name("start_routine"),
            "void* (*start_routine)(void*)"
        );
    }

    #[test]
    fn test_signature_recovery_does_not_mark_pthread_arg_when_static_start_is_used() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_create".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::int(0),
                Expr::unknown("thread_trampoline"),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert!(!matches!(
            sig.parameters[1].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_does_not_mark_signal_param_when_static_handler_is_used() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("signal".to_string()),
            vec![Expr::int(2), Expr::unknown("static_handler")],
        );
        let keep_param_live =
            Expr::assign(Expr::unknown("tmp"), Expr::var(Variable::reg("rdi", 8)));

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call, keep_param_live],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 1);
        assert!(!matches!(
            sig.parameters[0].param_type,
            ParamType::FunctionPointer { .. }
        ));
    }

    #[test]
    fn test_signature_recovery_detects_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_bsd_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("bsd_qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[4].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_on_exit_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("fn"),
            "void (*fn)(int32_t, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_hexray_on_exit_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 2);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("fn"),
            "void (*fn)(int32_t, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_pthread_atfork_callbacks() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("pthread_atfork".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };

        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 3);
        assert_eq!(
            sig.parameters[0].param_type.format_with_name("prepare"),
            "void (*prepare)(void)"
        );
        assert_eq!(
            sig.parameters[1].param_type.format_with_name("parent"),
            "void (*parent)(void)"
        );
        assert_eq!(
            sig.parameters[2].param_type.format_with_name("child"),
            "void (*child)(void)"
        );
    }

    #[test]
    fn test_signature_recovery_detects_hexray_qsort_r_callback() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_qsort_r".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
                Expr::var(Variable::reg("r8", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert_eq!(sig.parameters.len(), 5);
        assert_eq!(
            sig.parameters[3].param_type.format_with_name("compar"),
            "int32_t (*compar)(void*, void*, void*)"
        );
    }

    #[test]
    fn test_signature_recovery_infers_tail_call_forwarded_return_type() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
    }

    #[test]
    fn test_signature_recovery_does_not_infer_tail_return_for_void_callee() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("qsort".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
                Expr::var(Variable::reg("rdx", 8)),
                Expr::var(Variable::reg("rcx", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let cfg = StructuredCfg {
            body: vec![block],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(!sig.has_return);
        assert_eq!(sig.return_type, ParamType::Void);
    }

    #[test]
    fn test_signature_recovery_infers_tail_call_return_when_void_return_node_is_separate() {
        use hexray_core::BasicBlockId;

        let call = Expr::call(
            CallTarget::Named("hexray_on_exit".to_string()),
            vec![
                Expr::var(Variable::reg("rdi", 8)),
                Expr::var(Variable::reg("rsi", 8)),
            ],
        );

        let block = StructuredNode::Block {
            id: BasicBlockId::new(0),
            statements: vec![call],
            address_range: (0x1000, 0x1010),
        };
        let ret = StructuredNode::Return(None);
        let cfg = StructuredCfg {
            body: vec![block, ret],
            cfg_entry: BasicBlockId::new(0),
        };

        let mut recovery = SignatureRecovery::new(CallingConvention::SystemV);
        let sig = recovery.analyze(&cfg);

        assert!(sig.has_return);
        assert_eq!(sig.return_type, ParamType::SignedInt(32));
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
