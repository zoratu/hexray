//! Types used by the signature-recovery pass:
//! [`CallingConvention`], [`ParameterUsageHints`],
//! [`ParameterLocation`], [`ParamType`], [`Parameter`], and
//! [`FunctionSignature`].
//!
//! These are the public API surface — both the decompiler crate
//! itself and downstream callers (e.g. the emitter) consume them
//! verbatim. Re-exported from `super` for caller convenience.

use std::collections::HashMap;

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
    /// Parameter is accessed as an array (indexed dereference).
    pub is_array_access: bool,
    /// Element type inferred from dereference operations.
    pub deref_element_type: Option<ParamType>,
    /// Number of dereferences observed.
    pub deref_count: usize,
}

impl ParameterUsageHints {
    pub(super) fn normalize_callback_name(function_name: &str) -> &str {
        let no_prefix = function_name.trim_start_matches('_');
        no_prefix.split('@').next().unwrap_or(no_prefix)
    }

    pub(super) fn add_function_pointer_reason(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        if !self.function_pointer_reasons.iter().any(|r| r == &reason) {
            self.function_pointer_reasons.push(reason);
        }
    }

    /// Returns a callback signature for known APIs and callback argument positions.
    pub(super) fn callback_signature(function_name: &str, arg_index: usize) -> Option<ParamType> {
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

        // If we have inferred an element type from dereferences, return typed pointer
        if let Some(elem_type) = &self.deref_element_type {
            if self.is_dereferenced || self.is_pointer_arithmetic || self.is_array_access {
                return ParamType::TypedPointer(Box::new(elem_type.clone()));
            }
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
                _ => format!("str{}", index + 1),
            };
        }

        if self.is_array_access || self.deref_element_type.is_some() {
            return match index {
                0 => "arr".to_string(),
                1 => "arr2".to_string(),
                _ => format!("arr{}", index + 1),
            };
        }

        if self.is_dereferenced || self.is_pointer_arithmetic {
            return match index {
                0 => "ptr".to_string(),
                1 => "ptr2".to_string(),
                _ => format!("ptr{}", index + 1),
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

    pub(super) fn has_strong_signal(&self) -> bool {
        self.is_dereferenced
            || self.is_pointer_arithmetic
            || self.is_array_index
            || self.is_loop_bound
            || self.is_size_param
            || self.is_null_checked
            || self.is_signed_comparison
            || self.is_unsigned_ops
            || self.is_string_arg
            || self.is_function_pointer
            || !self.passed_as_callback_to.is_empty()
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
    /// Typed pointer (e.g., int32_t*, uint8_t*).
    TypedPointer(Box<ParamType>),
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
            ParamType::TypedPointer(inner) => format!("{}*", inner.to_c_string()),
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
            ParamType::Unknown | ParamType::Pointer | ParamType::TypedPointer(_) => 8,
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
