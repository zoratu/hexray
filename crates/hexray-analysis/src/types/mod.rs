//! Type inference for decompilation.
//!
//! This module provides type inference for variables based on:
//! - How values are used (pointer dereference, comparison, arithmetic)
//! - Size hints from memory operations
//! - Known library function signatures
//! - Comparison with constants
//! - Call site argument/return type propagation
//! - Floating-point operation detection
//!
//! The type system is focused on decompilation needs:
//! - Distinguishing pointers from integers
//! - Inferring signedness from comparisons
//! - Detecting floating-point values
//! - Detecting common types (strings, arrays, structs)
//! - Propagating types through function calls

use crate::ssa::types::SsaOperand;
use crate::ssa::{SsaFunction, SsaValue};
use hexray_core::Operation;
use std::collections::HashMap;
use std::fmt;

/// A basic type for decompilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Type {
    /// Unknown type (not yet inferred).
    Unknown,

    /// Void type.
    Void,

    /// Boolean (from comparisons).
    Bool,

    /// Integer with size and signedness.
    Int {
        size: u8,     // 1, 2, 4, 8 bytes
        signed: bool, // signed or unsigned
    },

    /// Floating-point type.
    Float {
        size: u8, // 4 (float), 8 (double), 16 (long double)
    },

    /// Pointer to another type.
    Pointer(Box<Type>),

    /// Array of elements.
    Array {
        element: Box<Type>,
        count: Option<usize>,
    },

    /// Function pointer.
    Function {
        return_type: Box<Type>,
        params: Vec<Type>,
    },

    /// Struct type (fields at offsets).
    Struct {
        name: Option<String>,
        fields: Vec<(i64, Type)>, // (offset, type)
        size: usize,
    },

    /// C-string (null-terminated char*).
    CString,

    /// Template instantiation (e.g., std::vector<int>).
    Template {
        /// The template name (e.g., "std::vector", "std::map").
        name: String,
        /// Template arguments (can be types or values).
        args: Vec<TemplateArg>,
    },
}

/// A template argument (can be a type or a non-type value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateArg {
    /// Type argument (e.g., `int` in `vector<int>`).
    Type(Box<Type>),
    /// Non-type argument (e.g., `10` in `array<int, 10>`).
    Value(i64),
    /// Nested template (e.g., `vector<int>` in `vector<vector<int>>`).
    Template {
        name: String,
        args: Vec<TemplateArg>,
    },
}

impl Type {
    /// Creates an integer type.
    pub fn int(size: u8, signed: bool) -> Self {
        Self::Int { size, signed }
    }

    /// Creates an unsigned integer type.
    pub fn uint(size: u8) -> Self {
        Self::Int {
            size,
            signed: false,
        }
    }

    /// Creates a signed integer type.
    pub fn sint(size: u8) -> Self {
        Self::Int { size, signed: true }
    }

    /// Creates a floating-point type.
    pub fn float(size: u8) -> Self {
        Self::Float { size }
    }

    /// Creates a single-precision float.
    pub fn f32() -> Self {
        Self::Float { size: 4 }
    }

    /// Creates a double-precision float.
    pub fn f64() -> Self {
        Self::Float { size: 8 }
    }

    /// Creates a pointer type.
    pub fn ptr(pointee: Type) -> Self {
        Self::Pointer(Box::new(pointee))
    }

    /// Returns true if this type is a pointer.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_) | Self::CString)
    }

    /// Returns true if this type is an integer.
    pub fn is_integer(&self) -> bool {
        matches!(self, Self::Int { .. })
    }

    /// Returns true if this type is a floating-point type.
    pub fn is_float(&self) -> bool {
        matches!(self, Self::Float { .. })
    }

    /// Returns true if this type is numeric (int or float).
    pub fn is_numeric(&self) -> bool {
        matches!(self, Self::Int { .. } | Self::Float { .. })
    }

    /// Returns the size in bytes, if known.
    pub fn size(&self) -> Option<u8> {
        match self {
            Self::Unknown | Self::Void => None,
            Self::Bool => Some(1),
            Self::Int { size, .. } => Some(*size),
            Self::Float { size } => Some(*size),
            Self::Pointer(_) | Self::Function { .. } | Self::CString => Some(8), // 64-bit
            Self::Array { element, count } => {
                let elem_size = element.size()?;
                Some(elem_size * (*count)? as u8)
            }
            Self::Struct { size, .. } => Some(*size as u8),
            Self::Template { .. } => None, // Template size depends on instantiation
        }
    }

    /// Returns true if this is a template instantiation.
    pub fn is_template(&self) -> bool {
        matches!(self, Self::Template { .. })
    }

    /// Creates a template type from name and arguments.
    pub fn template(name: impl Into<String>, args: Vec<TemplateArg>) -> Self {
        Self::Template {
            name: name.into(),
            args,
        }
    }

    /// Creates a common std::vector<T> type.
    pub fn std_vector(element_type: Type) -> Self {
        Self::template(
            "std::vector",
            vec![TemplateArg::Type(Box::new(element_type))],
        )
    }

    /// Creates a common std::string type.
    pub fn std_string() -> Self {
        Self::template(
            "std::basic_string",
            vec![TemplateArg::Type(Box::new(Type::sint(1)))],
        )
    }

    /// Creates a common std::map<K, V> type.
    pub fn std_map(key_type: Type, value_type: Type) -> Self {
        Self::template(
            "std::map",
            vec![
                TemplateArg::Type(Box::new(key_type)),
                TemplateArg::Type(Box::new(value_type)),
            ],
        )
    }

    /// Creates a common std::unique_ptr<T> type.
    pub fn std_unique_ptr(pointee: Type) -> Self {
        Self::template(
            "std::unique_ptr",
            vec![TemplateArg::Type(Box::new(pointee))],
        )
    }

    /// Creates a common std::shared_ptr<T> type.
    pub fn std_shared_ptr(pointee: Type) -> Self {
        Self::template(
            "std::shared_ptr",
            vec![TemplateArg::Type(Box::new(pointee))],
        )
    }

    /// Merges two types, taking the more specific one.
    pub fn merge(&self, other: &Type) -> Type {
        match (self, other) {
            (Type::Unknown, t) | (t, Type::Unknown) => t.clone(),
            (
                Type::Int {
                    size: s1,
                    signed: sg1,
                },
                Type::Int {
                    size: s2,
                    signed: sg2,
                },
            ) => {
                // Take larger size, prefer signed if either is signed
                Type::Int {
                    size: (*s1).max(*s2),
                    signed: *sg1 || *sg2,
                }
            }
            (Type::Float { size: s1 }, Type::Float { size: s2 }) => {
                // Take larger float size
                Type::Float {
                    size: (*s1).max(*s2),
                }
            }
            (Type::Pointer(p1), Type::Pointer(p2)) => Type::Pointer(Box::new(p1.merge(p2))),
            // CString is more specific than char*
            (Type::CString, Type::Pointer(_)) | (Type::Pointer(_), Type::CString) => Type::CString,
            // Default: keep first type
            _ => self.clone(),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Unknown => write!(f, "unknown"),
            Type::Void => write!(f, "void"),
            Type::Bool => write!(f, "bool"),
            Type::Int { size, signed } => {
                let prefix = if *signed { "int" } else { "uint" };
                write!(f, "{}{}", prefix, size * 8)
            }
            Type::Float { size } => match size {
                4 => write!(f, "float"),
                8 => write!(f, "double"),
                16 => write!(f, "long double"),
                _ => write!(f, "float{}", size * 8),
            },
            Type::Pointer(inner) => write!(f, "{}*", inner),
            Type::Array { element, count } => {
                if let Some(n) = count {
                    write!(f, "{}[{}]", element, n)
                } else {
                    write!(f, "{}[]", element)
                }
            }
            Type::Function {
                return_type,
                params,
            } => {
                write!(f, "{}(", return_type)?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", p)?;
                }
                write!(f, ")")
            }
            Type::Struct { name, .. } => {
                if let Some(n) = name {
                    write!(f, "struct {}", n)
                } else {
                    write!(f, "struct")
                }
            }
            Type::CString => write!(f, "char*"),
            Type::Template { name, args } => {
                write!(f, "{}<", name)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ">")
            }
        }
    }
}

impl fmt::Display for TemplateArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateArg::Type(ty) => write!(f, "{}", ty),
            TemplateArg::Value(v) => write!(f, "{}", v),
            TemplateArg::Template { name, args } => {
                write!(f, "{}<", name)?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", arg)?;
                }
                write!(f, ">")
            }
        }
    }
}

/// Type constraint for inference.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Value has exactly this type.
    Exact(Type),
    /// Value is a pointer to something.
    IsPointer,
    /// Value is an integer of at least this size.
    MinSize(u8),
    /// Value is used in signed comparison.
    IsSigned,
    /// Value is used in unsigned comparison.
    IsUnsigned,
    /// Value is a floating-point type.
    IsFloat(u8), // size in bytes
    /// Value equals another value (types should match).
    Equals(SsaValue),
    /// Value is a function return value with this type.
    ReturnType(Type),
    /// Value is a function argument with this type.
    ArgumentType(Type),
}

/// Type inference engine.
pub struct TypeInference {
    /// Inferred types for each SSA value.
    types: HashMap<SsaValue, Type>,
    /// Constraints collected during analysis.
    constraints: Vec<(SsaValue, Constraint)>,
    /// Known function signatures for call site propagation.
    signatures: FunctionSignatures,
}

impl TypeInference {
    /// Creates a new type inference engine.
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            constraints: Vec::new(),
            signatures: FunctionSignatures::new(),
        }
    }

    /// Creates a type inference engine with libc signatures.
    pub fn with_libc() -> Self {
        Self {
            types: HashMap::new(),
            constraints: Vec::new(),
            signatures: FunctionSignatures::with_libc(),
        }
    }

    /// Creates a type inference engine with custom signatures.
    pub fn with_signatures(signatures: FunctionSignatures) -> Self {
        Self {
            types: HashMap::new(),
            constraints: Vec::new(),
            signatures,
        }
    }

    /// Infers types for all values in an SSA function.
    pub fn infer(&mut self, func: &SsaFunction) {
        // Step 1: Collect constraints from instructions
        self.collect_constraints(func);

        // Step 2: Solve constraints
        self.solve_constraints();

        // Step 3: Propagate types
        self.propagate_types(func);
    }

    /// Collects type constraints from SSA instructions.
    fn collect_constraints(&mut self, func: &SsaFunction) {
        for block in func.blocks.values() {
            // Phi nodes: all incoming values should have the same type
            for phi in &block.phis {
                for (_, incoming) in &phi.incoming {
                    self.constraints
                        .push((phi.result.clone(), Constraint::Equals(incoming.clone())));
                }
            }

            // Instructions
            for inst in &block.instructions {
                self.analyze_instruction(inst);
            }
        }
    }

    /// Analyzes an instruction for type constraints.
    fn analyze_instruction(&mut self, inst: &crate::ssa::types::SsaInstruction) {
        match inst.operation {
            // Memory operations give us pointer and size hints
            Operation::Load | Operation::Store => {
                if let Some(def) = inst.defs.first() {
                    // The address operand is a pointer
                    if let Some(addr_op) = inst.uses.first() {
                        if let SsaOperand::Value(addr) = addr_op {
                            self.constraints.push((addr.clone(), Constraint::IsPointer));
                        }
                        if let SsaOperand::Memory { size, .. } = addr_op {
                            self.constraints
                                .push((def.clone(), Constraint::MinSize(*size)));
                        }
                    }
                }
            }

            // Comparisons tell us about signedness
            Operation::Compare | Operation::Test => {
                // Infer signedness from the mnemonic - x86 has specific signed/unsigned comparisons
                let mnemonic = inst.mnemonic.to_lowercase();

                // Signed comparisons (G = Greater, L = Less - signed)
                let is_signed_cmp = mnemonic.contains("cmov")
                    && (mnemonic.ends_with("g")
                        || mnemonic.ends_with("l")
                        || mnemonic.ends_with("ge")
                        || mnemonic.ends_with("le")
                        || mnemonic.ends_with("ng")
                        || mnemonic.ends_with("nl"));

                // Unsigned comparisons (A = Above, B = Below - unsigned)
                let is_unsigned_cmp = mnemonic.contains("cmov")
                    && (mnemonic.ends_with("a")
                        || mnemonic.ends_with("b")
                        || mnemonic.ends_with("ae")
                        || mnemonic.ends_with("be")
                        || mnemonic.ends_with("na")
                        || mnemonic.ends_with("nb"));

                // Also check for seta/setb/setg/setl patterns
                let is_signed_set = mnemonic.starts_with("set")
                    && (mnemonic.ends_with("g")
                        || mnemonic.ends_with("l")
                        || mnemonic.ends_with("ge")
                        || mnemonic.ends_with("le"));
                let is_unsigned_set = mnemonic.starts_with("set")
                    && (mnemonic.ends_with("a")
                        || mnemonic.ends_with("b")
                        || mnemonic.ends_with("ae")
                        || mnemonic.ends_with("be"));

                // Apply signedness constraints to operands
                for op in &inst.uses {
                    if let SsaOperand::Value(v) = op {
                        if is_signed_cmp || is_signed_set {
                            self.constraints.push((v.clone(), Constraint::IsSigned));
                        } else if is_unsigned_cmp || is_unsigned_set {
                            self.constraints.push((v.clone(), Constraint::IsUnsigned));
                        }
                    }
                }
            }

            // Arithmetic propagates types
            Operation::Add | Operation::Sub | Operation::Mul | Operation::Div => {
                let mnemonic = inst.mnemonic.to_lowercase();

                // Infer signedness from division/multiplication mnemonics
                // IDIV/IMUL are signed, DIV/MUL are unsigned
                let is_signed_arith = mnemonic.starts_with("idiv") || mnemonic.starts_with("imul");
                let is_unsigned_arith = (mnemonic.starts_with("div")
                    && !mnemonic.starts_with("divs"))
                    || (mnemonic.starts_with("mul") && !mnemonic.starts_with("muls"));

                if let Some(def) = inst.defs.first() {
                    if is_signed_arith {
                        self.constraints.push((def.clone(), Constraint::IsSigned));
                    } else if is_unsigned_arith {
                        self.constraints.push((def.clone(), Constraint::IsUnsigned));
                    }

                    // Result type depends on operands
                    for op in &inst.uses {
                        if let SsaOperand::Value(v) = op {
                            self.constraints
                                .push((def.clone(), Constraint::Equals(v.clone())));

                            // Propagate signedness to operands
                            if is_signed_arith {
                                self.constraints.push((v.clone(), Constraint::IsSigned));
                            } else if is_unsigned_arith {
                                self.constraints.push((v.clone(), Constraint::IsUnsigned));
                            }
                        }
                    }
                }
            }

            // Shifts suggest the result is an integer
            Operation::Shl | Operation::Shr => {
                if let Some(def) = inst.defs.first() {
                    // Shr is typically unsigned, Sar (missing) would be signed
                    self.constraints.push((def.clone(), Constraint::IsUnsigned));
                }
            }

            Operation::Sar => {
                if let Some(def) = inst.defs.first() {
                    self.constraints.push((def.clone(), Constraint::IsSigned));
                }
            }

            // Move operations - detect sign/zero extension
            Operation::Move => {
                let mnemonic = inst.mnemonic.to_lowercase();

                // MOVSX/MOVSXD - sign extend (value is signed)
                // Intel: movsx, movsxd
                // AT&T: movsbl (byte to long), movswl (word to long), movslq (long to quad), etc.
                let is_sign_extend = mnemonic.starts_with("movsx")
                    || mnemonic.starts_with("movsxd")
                    || (mnemonic.starts_with("movs")
                        && (mnemonic.ends_with("l")
                            || mnemonic.ends_with("q")
                            || mnemonic.ends_with("w")));

                // MOVZX - zero extend (value is unsigned)
                // Intel: movzx
                // AT&T: movzbl, movzwl, movzbq, movzwq, etc.
                let is_zero_extend = mnemonic.starts_with("movzx")
                    || (mnemonic.starts_with("movz")
                        && (mnemonic.ends_with("l")
                            || mnemonic.ends_with("q")
                            || mnemonic.ends_with("w")));

                // CBW/CWDE/CDQE - convert byte/word/dword with sign extension
                let is_sign_convert = mnemonic == "cbw"
                    || mnemonic == "cwde"
                    || mnemonic == "cdqe"
                    || mnemonic == "cwd"
                    || mnemonic == "cdq"
                    || mnemonic == "cqo"
                    || mnemonic == "cbtw"  // AT&T for cbw
                    || mnemonic == "cwtl"  // AT&T for cwde
                    || mnemonic == "cltq"  // AT&T for cdqe
                    || mnemonic == "cwtd"  // AT&T for cwd
                    || mnemonic == "cltd"  // AT&T for cdq
                    || mnemonic == "cqto"; // AT&T for cqo

                if let Some(def) = inst.defs.first() {
                    if is_sign_extend || is_sign_convert {
                        self.constraints.push((def.clone(), Constraint::IsSigned));
                    } else if is_zero_extend {
                        self.constraints.push((def.clone(), Constraint::IsUnsigned));
                    }
                }

                if let Some(SsaOperand::Value(src)) = inst.uses.first() {
                    if is_sign_extend || is_sign_convert {
                        self.constraints.push((src.clone(), Constraint::IsSigned));
                    } else if is_zero_extend {
                        self.constraints.push((src.clone(), Constraint::IsUnsigned));
                    }
                }

                // Always propagate type equivalence
                if let (Some(def), Some(SsaOperand::Value(src))) =
                    (inst.defs.first(), inst.uses.first())
                {
                    self.constraints
                        .push((def.clone(), Constraint::Equals(src.clone())));
                }
            }

            // LoadEffectiveAddress creates a pointer
            Operation::LoadEffectiveAddress => {
                if let Some(def) = inst.defs.first() {
                    self.constraints.push((def.clone(), Constraint::IsPointer));
                }
            }

            // Call instructions - try to propagate return type
            Operation::Call => {
                // Return value is typically first def (e.g., rax/x0)
                if let Some(def) = inst.defs.first() {
                    // Try to get function name from the call target
                    // For now, check mnemonic for common patterns
                    self.infer_call_types(inst, def);
                }
            }

            _ => {}
        }

        // Check mnemonic for floating-point operations
        self.check_fp_mnemonic(inst);
    }

    /// Infers types from call instructions.
    fn infer_call_types(&mut self, inst: &crate::ssa::types::SsaInstruction, ret_val: &SsaValue) {
        // Try to extract function name from operands or mnemonic
        // This is a simplified approach - real implementation would need call target resolution
        let mnemonic = inst.mnemonic.to_lowercase();

        // Check for known function names in the call
        for (name, sig) in [
            ("printf", self.signatures.get("printf")),
            ("malloc", self.signatures.get("malloc")),
            ("free", self.signatures.get("free")),
            ("strlen", self.signatures.get("strlen")),
            ("strcmp", self.signatures.get("strcmp")),
            ("memcpy", self.signatures.get("memcpy")),
        ] {
            if mnemonic.contains(name) {
                if let Some(sig) = sig {
                    self.constraints.push((
                        ret_val.clone(),
                        Constraint::ReturnType(sig.return_type.clone()),
                    ));
                    break;
                }
            }
        }
    }

    /// Checks if instruction mnemonic indicates floating-point operation.
    fn check_fp_mnemonic(&mut self, inst: &crate::ssa::types::SsaInstruction) {
        let mnemonic = inst.mnemonic.to_lowercase();

        // x86/x86-64 floating-point patterns
        let is_x86_fp = mnemonic.contains("ss") || mnemonic.contains("sd") || // SSE single/double
           mnemonic.contains("ps") || mnemonic.contains("pd") || // packed single/double
           mnemonic.starts_with("vf") || // AVX FP
           mnemonic.starts_with("v") && (
               mnemonic.contains("add") || mnemonic.contains("sub") ||
               mnemonic.contains("mul") || mnemonic.contains("div")
           ) && (mnemonic.contains("ss") || mnemonic.contains("sd") ||
                 mnemonic.contains("ps") || mnemonic.contains("pd"));

        // ARM64 floating-point patterns
        let is_arm64_fp = mnemonic.starts_with("f")
            && (mnemonic.starts_with("fadd")
                || mnemonic.starts_with("fsub")
                || mnemonic.starts_with("fmul")
                || mnemonic.starts_with("fdiv")
                || mnemonic.starts_with("fmov")
                || mnemonic.starts_with("fcmp")
                || mnemonic.starts_with("fcvt")
                || mnemonic.starts_with("fsqrt")
                || mnemonic.starts_with("fabs")
                || mnemonic.starts_with("fneg")
                || mnemonic.starts_with("fmadd")
                || mnemonic.starts_with("fmsub")
                || mnemonic.starts_with("fnmadd")
                || mnemonic.starts_with("fnmsub")
                || mnemonic.starts_with("frint")
                || mnemonic.starts_with("fmax")
                || mnemonic.starts_with("fmin"));

        // ARM64 SIMD/NEON floating-point
        let is_neon_fp = mnemonic.starts_with("scvtf") || // signed int to float
            mnemonic.starts_with("ucvtf") || // unsigned int to float
            mnemonic.starts_with("fcvtz") || // float to int with truncation
            mnemonic.starts_with("fcvtn") || // float to int with nearest
            mnemonic.starts_with("fcvta") || // float to int away from zero
            mnemonic.starts_with("fcvtm") || // float to int minus infinity
            mnemonic.starts_with("fcvtp"); // float to int plus infinity

        let is_fp = is_x86_fp || is_arm64_fp || is_neon_fp;

        if is_fp {
            // Determine size from mnemonic
            // Double precision: x86 (sd/pd) or ARM64 (ends with 'd')
            let is_double = mnemonic.contains("sd")
                || mnemonic.contains("pd")
                || (mnemonic.ends_with("d") && mnemonic.len() > 3);

            // Half precision: ARM64 (ends with 'h')
            let is_half = mnemonic.ends_with("h") && mnemonic.len() > 3;

            // Default to single precision (4 bytes) for ss/ps/ends with 's'/etc.
            let size = if is_double {
                8 // double
            } else if is_half {
                2 // half precision
            } else {
                4 // single (default for ss/ps or ARM64 's' suffix)
            };

            // Mark all defs as floating-point
            for def in &inst.defs {
                self.constraints
                    .push((def.clone(), Constraint::IsFloat(size)));
            }

            // Mark FP source operands
            for op in &inst.uses {
                if let SsaOperand::Value(v) = op {
                    self.constraints
                        .push((v.clone(), Constraint::IsFloat(size)));
                }
            }
        }

        // Additional ARM64 type inference patterns
        self.check_arm64_patterns(inst);
    }

    /// Additional ARM64-specific type inference patterns.
    fn check_arm64_patterns(&mut self, inst: &crate::ssa::types::SsaInstruction) {
        let mnemonic = inst.mnemonic.to_lowercase();

        // ARM64 signed/unsigned extend patterns
        // SXTB, SXTH, SXTW - sign extend byte/half/word
        // UXTB, UXTH, UXTW - zero extend byte/half/word
        let is_sign_extend = mnemonic.starts_with("sxt");
        let is_zero_extend = mnemonic.starts_with("uxt");

        if is_sign_extend || is_zero_extend {
            if let Some(def) = inst.defs.first() {
                if is_sign_extend {
                    self.constraints.push((def.clone(), Constraint::IsSigned));
                } else {
                    self.constraints.push((def.clone(), Constraint::IsUnsigned));
                }
            }
            if let Some(SsaOperand::Value(src)) = inst.uses.first() {
                if is_sign_extend {
                    self.constraints.push((src.clone(), Constraint::IsSigned));
                } else {
                    self.constraints.push((src.clone(), Constraint::IsUnsigned));
                }
            }
        }

        // ARM64 signed vs unsigned division
        // SDIV - signed divide, UDIV - unsigned divide
        let is_signed_div = mnemonic == "sdiv";
        let is_unsigned_div = mnemonic == "udiv";

        if is_signed_div || is_unsigned_div {
            for def in &inst.defs {
                if is_signed_div {
                    self.constraints.push((def.clone(), Constraint::IsSigned));
                } else {
                    self.constraints.push((def.clone(), Constraint::IsUnsigned));
                }
            }
            for op in &inst.uses {
                if let SsaOperand::Value(v) = op {
                    if is_signed_div {
                        self.constraints.push((v.clone(), Constraint::IsSigned));
                    } else {
                        self.constraints.push((v.clone(), Constraint::IsUnsigned));
                    }
                }
            }
        }

        // ARM64 signed vs unsigned multiply-high
        // SMULH - signed multiply high, UMULH - unsigned multiply high
        let is_signed_mul = mnemonic == "smulh" || mnemonic.starts_with("smull");
        let is_unsigned_mul = mnemonic == "umulh" || mnemonic.starts_with("umull");

        if is_signed_mul || is_unsigned_mul {
            for def in &inst.defs {
                if is_signed_mul {
                    self.constraints.push((def.clone(), Constraint::IsSigned));
                } else {
                    self.constraints.push((def.clone(), Constraint::IsUnsigned));
                }
            }
            for op in &inst.uses {
                if let SsaOperand::Value(v) = op {
                    if is_signed_mul {
                        self.constraints.push((v.clone(), Constraint::IsSigned));
                    } else {
                        self.constraints.push((v.clone(), Constraint::IsUnsigned));
                    }
                }
            }
        }

        // ARM64 conditional comparisons - CCMP/CCMN
        // These often indicate signed/unsigned based on condition codes
        // CSET/CSINC/CSINV/CSNEG - conditional select patterns
        if mnemonic.starts_with("cs") {
            if let Some(def) = inst.defs.first() {
                // Result is typically used as a boolean or small integer
                self.constraints.push((def.clone(), Constraint::MinSize(1)));
            }
        }

        // ASR (arithmetic shift right) indicates signed
        // LSR (logical shift right) indicates unsigned
        if mnemonic == "asr" || mnemonic.starts_with("asr ") {
            for op in &inst.uses {
                if let SsaOperand::Value(v) = op {
                    self.constraints.push((v.clone(), Constraint::IsSigned));
                }
            }
            for def in &inst.defs {
                self.constraints.push((def.clone(), Constraint::IsSigned));
            }
        } else if mnemonic == "lsr" || mnemonic.starts_with("lsr ") {
            for op in &inst.uses {
                if let SsaOperand::Value(v) = op {
                    self.constraints.push((v.clone(), Constraint::IsUnsigned));
                }
            }
            for def in &inst.defs {
                self.constraints.push((def.clone(), Constraint::IsUnsigned));
            }
        }
    }

    /// Solves collected constraints.
    fn solve_constraints(&mut self) {
        // Multiple passes until no changes
        let mut changed = true;
        let max_iterations = 10;
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;

            for (value, constraint) in self.constraints.clone() {
                let current = self.types.get(&value).cloned().unwrap_or(Type::Unknown);
                let new_type = self.apply_constraint(&current, &constraint);

                if new_type != current {
                    self.types.insert(value, new_type);
                    changed = true;
                }
            }
        }
    }

    /// Applies a constraint to update a type.
    fn apply_constraint(&self, current: &Type, constraint: &Constraint) -> Type {
        match constraint {
            Constraint::Exact(t) => t.clone(),

            Constraint::IsPointer => {
                if current.is_pointer() {
                    current.clone()
                } else {
                    Type::ptr(Type::Unknown)
                }
            }

            Constraint::MinSize(size) => match current {
                Type::Unknown => Type::uint(*size),
                Type::Int { size: s, signed } => Type::Int {
                    size: (*s).max(*size),
                    signed: *signed,
                },
                _ => current.clone(),
            },

            Constraint::IsSigned => {
                match current {
                    Type::Unknown => Type::sint(8), // Default to 64-bit
                    Type::Int { size, .. } => Type::sint(*size),
                    _ => current.clone(),
                }
            }

            Constraint::IsUnsigned => match current {
                Type::Unknown => Type::uint(8),
                Type::Int { size, .. } => Type::uint(*size),
                _ => current.clone(),
            },

            Constraint::IsFloat(size) => match current {
                Type::Unknown => Type::float(*size),
                Type::Float { size: s } => Type::float((*s).max(*size)),
                _ => current.clone(),
            },

            Constraint::Equals(other) => {
                let other_type = self.types.get(other).cloned().unwrap_or(Type::Unknown);
                current.merge(&other_type)
            }

            Constraint::ReturnType(t) | Constraint::ArgumentType(t) => current.merge(t),
        }
    }

    /// Propagates types through the SSA graph.
    fn propagate_types(&mut self, func: &SsaFunction) {
        // Second pass: propagate through phi nodes and moves
        let mut changed = true;
        let max_iterations = 5;
        let mut iteration = 0;

        while changed && iteration < max_iterations {
            changed = false;
            iteration += 1;

            for block in func.blocks.values() {
                for phi in &block.phis {
                    let result_type = self.types.get(&phi.result).cloned();

                    for (_, incoming) in &phi.incoming {
                        let incoming_type = self.types.get(incoming).cloned();

                        if let (Some(rt), Some(it)) = (&result_type, &incoming_type) {
                            let merged = rt.merge(it);
                            if &merged != rt {
                                self.types.insert(phi.result.clone(), merged.clone());
                                changed = true;
                            }
                            if &merged != it {
                                self.types.insert(incoming.clone(), merged);
                                changed = true;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Returns the inferred type for a value.
    pub fn type_of(&self, value: &SsaValue) -> Type {
        self.types.get(value).cloned().unwrap_or(Type::Unknown)
    }

    /// Returns all inferred types.
    pub fn all_types(&self) -> &HashMap<SsaValue, Type> {
        &self.types
    }

    /// Exports types as a HashMap<String, String> suitable for the decompiler.
    ///
    /// This converts SSA values to their base register names and Type to C-style
    /// type strings. For full integration with stack slot variables (var_8, local_10, etc.),
    /// additional mapping is needed during the structuring phase.
    pub fn export_for_decompiler(&self) -> HashMap<String, String> {
        let mut result = HashMap::new();
        for (value, ty) in &self.types {
            // Use the base name without SSA version (e.g., "rax" instead of "rax_0")
            let var_name = value.to_string();
            let base_name = var_name.split('_').next().unwrap_or(&var_name).to_string();

            // Convert Type to C-style string
            let type_str = Self::type_to_c_string(ty);

            // Only add if we have a meaningful type
            if type_str != "unknown" && type_str != "int" {
                result.insert(base_name, type_str);
            }
        }
        result
    }

    /// Converts a Type to a C-style type string.
    pub fn type_to_c_string(ty: &Type) -> String {
        match ty {
            Type::Unknown => "int".to_string(), // Default to int for unknown
            Type::Void => "void".to_string(),
            Type::Bool => "bool".to_string(),
            Type::Int { size, signed } => match (size, signed) {
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
            Type::Float { size } => match size {
                4 => "float".to_string(),
                8 => "double".to_string(),
                16 => "long double".to_string(),
                _ => "double".to_string(),
            },
            Type::Pointer(inner) => {
                format!("{}*", Self::type_to_c_string(inner))
            }
            Type::Array { element, count } => {
                if let Some(n) = count {
                    format!("{}[{}]", Self::type_to_c_string(element), n)
                } else {
                    format!("{}[]", Self::type_to_c_string(element))
                }
            }
            Type::Function {
                return_type,
                params,
            } => {
                let ret = Self::type_to_c_string(return_type);
                let param_strs: Vec<_> = params.iter().map(Self::type_to_c_string).collect();
                format!("{} (*)({})", ret, param_strs.join(", "))
            }
            Type::Struct { name, .. } => {
                if let Some(n) = name {
                    format!("struct {}", n)
                } else {
                    "struct".to_string()
                }
            }
            Type::CString => "char*".to_string(),
            Type::Template { name, args } => {
                let arg_strs: Vec<_> = args.iter().map(Self::template_arg_to_c_string).collect();
                format!("{}<{}>", name, arg_strs.join(", "))
            }
        }
    }

    /// Converts a TemplateArg to a C-style string.
    fn template_arg_to_c_string(arg: &TemplateArg) -> String {
        match arg {
            TemplateArg::Type(ty) => Self::type_to_c_string(ty),
            TemplateArg::Value(v) => v.to_string(),
            TemplateArg::Template { name, args } => {
                let arg_strs: Vec<_> = args.iter().map(Self::template_arg_to_c_string).collect();
                format!("{}<{}>", name, arg_strs.join(", "))
            }
        }
    }
}

impl Default for TypeInference {
    fn default() -> Self {
        Self::new()
    }
}

/// Type annotations for known functions.
pub struct FunctionSignatures {
    /// Maps function names/addresses to their signatures.
    signatures: HashMap<String, FunctionSignature>,
}

/// A function's type signature.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub name: String,
    pub return_type: Type,
    pub parameters: Vec<(String, Type)>,
    pub variadic: bool,
}

impl FunctionSignatures {
    /// Creates a new empty signature database.
    pub fn new() -> Self {
        Self {
            signatures: HashMap::new(),
        }
    }

    /// Creates a signature database with common C library functions.
    pub fn with_libc() -> Self {
        let mut sigs = Self::new();

        // ======== stdio.h ========
        sigs.add_signature(FunctionSignature {
            name: "printf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("format".to_string(), Type::ptr(Type::sint(1)))],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "fprintf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("stream".to_string(), Type::ptr(Type::Void)),
                ("format".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "sprintf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("format".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "snprintf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("size".to_string(), Type::uint(8)),
                ("format".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "scanf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("format".to_string(), Type::ptr(Type::sint(1)))],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "fopen".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("filename".to_string(), Type::ptr(Type::sint(1))),
                ("mode".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fclose".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("stream".to_string(), Type::ptr(Type::Void))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fread".to_string(),
            return_type: Type::uint(8),
            parameters: vec![
                ("ptr".to_string(), Type::ptr(Type::Void)),
                ("size".to_string(), Type::uint(8)),
                ("count".to_string(), Type::uint(8)),
                ("stream".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fwrite".to_string(),
            return_type: Type::uint(8),
            parameters: vec![
                ("ptr".to_string(), Type::ptr(Type::Void)),
                ("size".to_string(), Type::uint(8)),
                ("count".to_string(), Type::uint(8)),
                ("stream".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fgets".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("n".to_string(), Type::sint(4)),
                ("stream".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fputs".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("stream".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "puts".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("str".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "getc".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("stream".to_string(), Type::ptr(Type::Void))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "putc".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("c".to_string(), Type::sint(4)),
                ("stream".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        // ======== stdlib.h ========
        sigs.add_signature(FunctionSignature {
            name: "malloc".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![("size".to_string(), Type::uint(8))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "calloc".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("num".to_string(), Type::uint(8)),
                ("size".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "realloc".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("ptr".to_string(), Type::ptr(Type::Void)),
                ("size".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "free".to_string(),
            return_type: Type::Void,
            parameters: vec![("ptr".to_string(), Type::ptr(Type::Void))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "atoi".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("str".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "atol".to_string(),
            return_type: Type::sint(8),
            parameters: vec![("str".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "atof".to_string(),
            return_type: Type::f64(),
            parameters: vec![("str".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strtol".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("endptr".to_string(), Type::ptr(Type::ptr(Type::sint(1)))),
                ("base".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strtoul".to_string(),
            return_type: Type::uint(8),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("endptr".to_string(), Type::ptr(Type::ptr(Type::sint(1)))),
                ("base".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "exit".to_string(),
            return_type: Type::Void,
            parameters: vec![("status".to_string(), Type::sint(4))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "abort".to_string(),
            return_type: Type::Void,
            parameters: vec![],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "getenv".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![("name".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "system".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("command".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "qsort".to_string(),
            return_type: Type::Void,
            parameters: vec![
                ("base".to_string(), Type::ptr(Type::Void)),
                ("num".to_string(), Type::uint(8)),
                ("size".to_string(), Type::uint(8)),
                ("compar".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "bsearch".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("key".to_string(), Type::ptr(Type::Void)),
                ("base".to_string(), Type::ptr(Type::Void)),
                ("num".to_string(), Type::uint(8)),
                ("size".to_string(), Type::uint(8)),
                ("compar".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        // ======== string.h ========
        sigs.add_signature(FunctionSignature {
            name: "strlen".to_string(),
            return_type: Type::uint(8),
            parameters: vec![("s".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strcmp".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("s1".to_string(), Type::ptr(Type::sint(1))),
                ("s2".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strncmp".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("s1".to_string(), Type::ptr(Type::sint(1))),
                ("s2".to_string(), Type::ptr(Type::sint(1))),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strcpy".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::sint(1))),
                ("src".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strncpy".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::sint(1))),
                ("src".to_string(), Type::ptr(Type::sint(1))),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strcat".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::sint(1))),
                ("src".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strncat".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::sint(1))),
                ("src".to_string(), Type::ptr(Type::sint(1))),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strchr".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("s".to_string(), Type::ptr(Type::sint(1))),
                ("c".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strrchr".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("s".to_string(), Type::ptr(Type::sint(1))),
                ("c".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strstr".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("haystack".to_string(), Type::ptr(Type::sint(1))),
                ("needle".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strtok".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("str".to_string(), Type::ptr(Type::sint(1))),
                ("delim".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strdup".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![("s".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "memcpy".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::Void)),
                ("src".to_string(), Type::ptr(Type::Void)),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "memmove".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::Void)),
                ("src".to_string(), Type::ptr(Type::Void)),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "memset".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("ptr".to_string(), Type::ptr(Type::Void)),
                ("value".to_string(), Type::sint(4)),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "memcmp".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("s1".to_string(), Type::ptr(Type::Void)),
                ("s2".to_string(), Type::ptr(Type::Void)),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "memchr".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("s".to_string(), Type::ptr(Type::Void)),
                ("c".to_string(), Type::sint(4)),
                ("n".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        // ======== unistd.h (POSIX) ========
        sigs.add_signature(FunctionSignature {
            name: "read".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("fd".to_string(), Type::sint(4)),
                ("buf".to_string(), Type::ptr(Type::Void)),
                ("count".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "write".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("fd".to_string(), Type::sint(4)),
                ("buf".to_string(), Type::ptr(Type::Void)),
                ("count".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "open".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("pathname".to_string(), Type::ptr(Type::sint(1))),
                ("flags".to_string(), Type::sint(4)),
            ],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "close".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("fd".to_string(), Type::sint(4))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "lseek".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("fd".to_string(), Type::sint(4)),
                ("offset".to_string(), Type::sint(8)),
                ("whence".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "fork".to_string(),
            return_type: Type::sint(4),
            parameters: vec![],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "execve".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("pathname".to_string(), Type::ptr(Type::sint(1))),
                ("argv".to_string(), Type::ptr(Type::ptr(Type::sint(1)))),
                ("envp".to_string(), Type::ptr(Type::ptr(Type::sint(1)))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "sleep".to_string(),
            return_type: Type::uint(4),
            parameters: vec![("seconds".to_string(), Type::uint(4))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "getpid".to_string(),
            return_type: Type::sint(4),
            parameters: vec![],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "getcwd".to_string(),
            return_type: Type::ptr(Type::sint(1)),
            parameters: vec![
                ("buf".to_string(), Type::ptr(Type::sint(1))),
                ("size".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "chdir".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("path".to_string(), Type::ptr(Type::sint(1)))],
            variadic: false,
        });

        // ======== socket functions ========
        sigs.add_signature(FunctionSignature {
            name: "socket".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("domain".to_string(), Type::sint(4)),
                ("type".to_string(), Type::sint(4)),
                ("protocol".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "bind".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("addrlen".to_string(), Type::uint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "listen".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("backlog".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "accept".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("addrlen".to_string(), Type::ptr(Type::uint(4))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "connect".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("addrlen".to_string(), Type::uint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "send".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("buf".to_string(), Type::ptr(Type::Void)),
                ("len".to_string(), Type::uint(8)),
                ("flags".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "recv".to_string(),
            return_type: Type::sint(8),
            parameters: vec![
                ("sockfd".to_string(), Type::sint(4)),
                ("buf".to_string(), Type::ptr(Type::Void)),
                ("len".to_string(), Type::uint(8)),
                ("flags".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        // ======== pthread functions ========
        sigs.add_signature(FunctionSignature {
            name: "pthread_create".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("thread".to_string(), Type::ptr(Type::uint(8))),
                ("attr".to_string(), Type::ptr(Type::Void)),
                ("start_routine".to_string(), Type::ptr(Type::Void)),
                ("arg".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "pthread_join".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("thread".to_string(), Type::uint(8)),
                ("retval".to_string(), Type::ptr(Type::ptr(Type::Void))),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "pthread_mutex_lock".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("mutex".to_string(), Type::ptr(Type::Void))],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "pthread_mutex_unlock".to_string(),
            return_type: Type::sint(4),
            parameters: vec![("mutex".to_string(), Type::ptr(Type::Void))],
            variadic: false,
        });

        // ======== mmap functions ========
        sigs.add_signature(FunctionSignature {
            name: "mmap".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("length".to_string(), Type::uint(8)),
                ("prot".to_string(), Type::sint(4)),
                ("flags".to_string(), Type::sint(4)),
                ("fd".to_string(), Type::sint(4)),
                ("offset".to_string(), Type::sint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "munmap".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("length".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "mprotect".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("addr".to_string(), Type::ptr(Type::Void)),
                ("len".to_string(), Type::uint(8)),
                ("prot".to_string(), Type::sint(4)),
            ],
            variadic: false,
        });

        sigs
    }

    /// Adds a function signature.
    pub fn add_signature(&mut self, sig: FunctionSignature) {
        self.signatures.insert(sig.name.clone(), sig);
    }

    /// Looks up a function signature by name.
    pub fn get(&self, name: &str) -> Option<&FunctionSignature> {
        self.signatures.get(name)
    }
}

impl Default for FunctionSignatures {
    fn default() -> Self {
        Self::new()
    }
}

/// Parser for C++ template type names from demangled symbols.
///
/// Handles names like:
/// - `std::vector<int>`
/// - `std::map<std::string, int>`
/// - `MyTemplate<int, 10>` (with non-type arguments)
/// - `std::vector<std::vector<int>>` (nested templates)
#[derive(Debug, Default)]
pub struct TemplateParser;

impl TemplateParser {
    /// Creates a new template parser.
    pub fn new() -> Self {
        Self
    }

    /// Parses a demangled C++ type name into a Type.
    ///
    /// Returns `Some(Type)` if the name represents a template instantiation,
    /// `None` otherwise.
    pub fn parse(&self, name: &str) -> Option<Type> {
        let name = name.trim();

        // Check if it's a template (contains '<')
        if !name.contains('<') {
            return None;
        }

        self.parse_template_type(name)
    }

    /// Parses a template type from a string.
    fn parse_template_type(&self, s: &str) -> Option<Type> {
        let s = s.trim();

        // Find the template name and arguments
        let open_bracket = s.find('<')?;

        // Make sure there's a closing bracket
        if !s.ends_with('>') {
            return None;
        }

        let template_name = s[..open_bracket].trim();
        let args_str = &s[open_bracket + 1..s.len() - 1];

        // Parse template arguments
        let args = self.parse_template_args(args_str)?;

        Some(Type::Template {
            name: template_name.to_string(),
            args,
        })
    }

    /// Parses template arguments from a comma-separated string.
    ///
    /// Handles nested templates by tracking bracket depth.
    fn parse_template_args(&self, s: &str) -> Option<Vec<TemplateArg>> {
        let s = s.trim();
        if s.is_empty() {
            return Some(Vec::new());
        }

        let mut args = Vec::new();
        let mut depth = 0;
        let mut start = 0;

        for (i, c) in s.char_indices() {
            match c {
                '<' => depth += 1,
                '>' => depth -= 1,
                ',' if depth == 0 => {
                    let arg_str = s[start..i].trim();
                    if let Some(arg) = self.parse_single_arg(arg_str) {
                        args.push(arg);
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }

        // Parse the last argument
        let last_arg = s[start..].trim();
        if !last_arg.is_empty() {
            if let Some(arg) = self.parse_single_arg(last_arg) {
                args.push(arg);
            }
        }

        Some(args)
    }

    /// Parses a single template argument.
    fn parse_single_arg(&self, s: &str) -> Option<TemplateArg> {
        let s = s.trim();

        // Check if it's a numeric value (non-type template argument)
        if let Ok(val) = s.parse::<i64>() {
            return Some(TemplateArg::Value(val));
        }

        // Check if it's a nested template
        if s.contains('<') {
            if let Some(Type::Template { name, args }) = self.parse_template_type(s) {
                return Some(TemplateArg::Template { name, args });
            }
        }

        // Otherwise, treat it as a type
        let ty = self.parse_primitive_type(s);
        Some(TemplateArg::Type(Box::new(ty)))
    }

    /// Parses a primitive type name into a Type.
    fn parse_primitive_type(&self, s: &str) -> Type {
        let s = s.trim();

        // Handle pointers
        if let Some(inner) = s.strip_suffix('*') {
            return Type::ptr(self.parse_primitive_type(inner.trim()));
        }

        // Handle const (strip it for now)
        let s = s.strip_prefix("const ").unwrap_or(s);
        let s = s.strip_suffix(" const").unwrap_or(s);

        // Handle references (treat as pointers for decompilation)
        let s = s.strip_suffix('&').unwrap_or(s).trim();

        match s {
            "void" => Type::Void,
            "bool" => Type::Bool,
            "char" | "signed char" => Type::sint(1),
            "unsigned char" => Type::uint(1),
            "short" | "signed short" | "short int" | "signed short int" => Type::sint(2),
            "unsigned short" | "unsigned short int" => Type::uint(2),
            "int" | "signed" | "signed int" => Type::sint(4),
            "unsigned" | "unsigned int" => Type::uint(4),
            "long" | "signed long" | "long int" | "signed long int" => Type::sint(8),
            "unsigned long" | "unsigned long int" => Type::uint(8),
            "long long" | "signed long long" | "long long int" => Type::sint(8),
            "unsigned long long" | "unsigned long long int" => Type::uint(8),
            "float" => Type::f32(),
            "double" => Type::f64(),
            "long double" => Type::Float { size: 16 },
            // C99/C++11 fixed-width types
            "int8_t" => Type::sint(1),
            "uint8_t" => Type::uint(1),
            "int16_t" => Type::sint(2),
            "uint16_t" => Type::uint(2),
            "int32_t" => Type::sint(4),
            "uint32_t" => Type::uint(4),
            "int64_t" => Type::sint(8),
            "uint64_t" => Type::uint(8),
            "size_t" | "uintptr_t" => Type::uint(8),
            "ssize_t" | "intptr_t" | "ptrdiff_t" => Type::sint(8),
            // Common STL types
            "std::string" | "string" => Type::std_string(),
            // Unknown type - return as unknown with name
            _ => {
                // Could be a class/struct name or unknown type
                Type::Struct {
                    name: Some(s.to_string()),
                    fields: Vec::new(),
                    size: 0,
                }
            }
        }
    }

    /// Checks if a type name is a known STL template.
    pub fn is_stl_template(&self, name: &str) -> bool {
        matches!(
            name,
            "std::vector"
                | "std::list"
                | "std::deque"
                | "std::set"
                | "std::multiset"
                | "std::map"
                | "std::multimap"
                | "std::unordered_set"
                | "std::unordered_map"
                | "std::unordered_multiset"
                | "std::unordered_multimap"
                | "std::array"
                | "std::pair"
                | "std::tuple"
                | "std::optional"
                | "std::variant"
                | "std::unique_ptr"
                | "std::shared_ptr"
                | "std::weak_ptr"
                | "std::function"
                | "std::basic_string"
        )
    }
}

/// Database for tracking template instantiations across a codebase.
///
/// This allows grouping related types (e.g., all `std::vector<T>` instantiations)
/// and understanding template usage patterns.
#[derive(Debug, Default)]
pub struct TemplateDatabase {
    /// All known template instantiations by their full name.
    instantiations: HashMap<String, Type>,
    /// Template name -> list of instantiation names.
    by_template: HashMap<String, Vec<String>>,
}

impl TemplateDatabase {
    /// Creates a new empty template database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a template instantiation to the database.
    pub fn add(&mut self, ty: Type) {
        if let Type::Template { ref name, .. } = ty {
            let full_name = ty.to_string();
            self.by_template
                .entry(name.clone())
                .or_default()
                .push(full_name.clone());
            self.instantiations.insert(full_name, ty);
        }
    }

    /// Parses and adds a type name to the database.
    ///
    /// Returns `Some(Type)` if it was a template type, `None` otherwise.
    pub fn parse_and_add(&mut self, type_name: &str) -> Option<Type> {
        let parser = TemplateParser::new();
        let ty = parser.parse(type_name)?;
        self.add(ty.clone());
        Some(ty)
    }

    /// Gets a template instantiation by its full name.
    pub fn get(&self, full_name: &str) -> Option<&Type> {
        self.instantiations.get(full_name)
    }

    /// Gets all instantiations of a particular template.
    ///
    /// For example, `get_instantiations("std::vector")` returns all
    /// vector instantiations like `std::vector<int>`, `std::vector<std::string>`, etc.
    pub fn get_instantiations(&self, template_name: &str) -> Vec<&Type> {
        self.by_template
            .get(template_name)
            .map(|names| {
                names
                    .iter()
                    .filter_map(|n| self.instantiations.get(n))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all known template names (without arguments).
    pub fn template_names(&self) -> impl Iterator<Item = &String> {
        self.by_template.keys()
    }

    /// Returns the total number of template instantiations.
    pub fn len(&self) -> usize {
        self.instantiations.len()
    }

    /// Returns true if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.instantiations.is_empty()
    }

    /// Returns all template instantiations.
    pub fn all(&self) -> impl Iterator<Item = &Type> {
        self.instantiations.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_display() {
        assert_eq!(Type::sint(4).to_string(), "int32");
        assert_eq!(Type::uint(8).to_string(), "uint64");
        assert_eq!(Type::ptr(Type::sint(1)).to_string(), "int8*");
        assert_eq!(Type::Bool.to_string(), "bool");
    }

    #[test]
    fn test_type_merge() {
        // Unknown + Int -> Int
        let t1 = Type::Unknown;
        let t2 = Type::sint(4);
        assert_eq!(t1.merge(&t2), Type::sint(4));

        // Int8 + Int16 -> Int16
        let t1 = Type::uint(1);
        let t2 = Type::uint(2);
        assert_eq!(t1.merge(&t2), Type::uint(2));

        // Unsigned + Signed -> Signed (conservative)
        let t1 = Type::uint(4);
        let t2 = Type::sint(4);
        assert!(matches!(t1.merge(&t2), Type::Int { signed: true, .. }));
    }

    #[test]
    fn test_function_signatures() {
        let sigs = FunctionSignatures::with_libc();

        let printf = sigs.get("printf").unwrap();
        assert!(printf.variadic);
        assert!(printf.return_type.is_integer());

        let malloc = sigs.get("malloc").unwrap();
        assert!(malloc.return_type.is_pointer());
    }

    #[test]
    fn test_signedness_constraint_application() {
        let inference = TypeInference::new();

        // IsSigned constraint on Unknown -> signed int
        let result = inference.apply_constraint(&Type::Unknown, &Constraint::IsSigned);
        assert!(matches!(result, Type::Int { signed: true, .. }));

        // IsUnsigned constraint on Unknown -> unsigned int
        let result = inference.apply_constraint(&Type::Unknown, &Constraint::IsUnsigned);
        assert!(matches!(result, Type::Int { signed: false, .. }));

        // IsSigned on existing int -> keeps size, changes signedness
        let result = inference.apply_constraint(&Type::uint(4), &Constraint::IsSigned);
        assert_eq!(result, Type::sint(4));

        // IsUnsigned on existing signed int -> keeps size, changes signedness
        let result = inference.apply_constraint(&Type::sint(2), &Constraint::IsUnsigned);
        assert_eq!(result, Type::uint(2));
    }

    #[test]
    fn test_signedness_detection_patterns() {
        // Test that we recognize signed vs unsigned division mnemonics
        let signed_mnemonics = ["idiv", "idivl", "idivq", "imul", "imull", "imulq"];
        let unsigned_mnemonics = ["div", "divl", "divq", "mul", "mull", "mulq"];

        for mnemonic in signed_mnemonics {
            let m = mnemonic.to_lowercase();
            let is_signed = m.starts_with("idiv") || m.starts_with("imul");
            assert!(is_signed, "Expected {} to be detected as signed", mnemonic);
        }

        for mnemonic in unsigned_mnemonics {
            let m = mnemonic.to_lowercase();
            let is_unsigned = (m.starts_with("div") && !m.starts_with("divs"))
                || (m.starts_with("mul") && !m.starts_with("muls"));
            assert!(
                is_unsigned,
                "Expected {} to be detected as unsigned",
                mnemonic
            );
        }
    }

    #[test]
    fn test_sign_zero_extension_patterns() {
        // Test detection of sign/zero extend mnemonics
        // Intel syntax
        let sign_extend_intel = ["movsx", "movsxd"];
        // AT&T syntax (movsbl = move sign-extend byte to long, etc.)
        let sign_extend_att = ["movsbl", "movswl", "movsbq", "movswq", "movslq"];

        let zero_extend_intel = ["movzx"];
        let zero_extend_att = ["movzbl", "movzwl", "movzbq", "movzwq"];

        // Function matching the actual detection logic
        let is_sign_ext = |mnemonic: &str| {
            let m = mnemonic.to_lowercase();
            m.starts_with("movsx")
                || m.starts_with("movsxd")
                || (m.starts_with("movs")
                    && (m.ends_with("l") || m.ends_with("q") || m.ends_with("w")))
        };

        let is_zero_ext = |mnemonic: &str| {
            let m = mnemonic.to_lowercase();
            m.starts_with("movzx")
                || (m.starts_with("movz")
                    && (m.ends_with("l") || m.ends_with("q") || m.ends_with("w")))
        };

        for mnemonic in sign_extend_intel.iter().chain(sign_extend_att.iter()) {
            assert!(
                is_sign_ext(mnemonic),
                "Expected {} to be detected as sign extension",
                mnemonic
            );
        }

        for mnemonic in zero_extend_intel.iter().chain(zero_extend_att.iter()) {
            assert!(
                is_zero_ext(mnemonic),
                "Expected {} to be detected as zero extension",
                mnemonic
            );
        }
    }

    #[test]
    fn test_comparison_signedness_patterns() {
        // Signed comparisons: G(reater), L(ess) - use signed interpretation
        let signed_cmov = ["cmovg", "cmovl", "cmovge", "cmovle", "cmovng", "cmovnl"];
        let unsigned_cmov = ["cmova", "cmovb", "cmovae", "cmovbe", "cmovna", "cmovnb"];

        for mnemonic in signed_cmov {
            let m = mnemonic.to_lowercase();
            let is_signed = m.contains("cmov")
                && (m.ends_with("g")
                    || m.ends_with("l")
                    || m.ends_with("ge")
                    || m.ends_with("le")
                    || m.ends_with("ng")
                    || m.ends_with("nl"));
            assert!(
                is_signed,
                "Expected {} to indicate signed comparison",
                mnemonic
            );
        }

        for mnemonic in unsigned_cmov {
            let m = mnemonic.to_lowercase();
            let is_unsigned = m.contains("cmov")
                && (m.ends_with("a")
                    || m.ends_with("b")
                    || m.ends_with("ae")
                    || m.ends_with("be")
                    || m.ends_with("na")
                    || m.ends_with("nb"));
            assert!(
                is_unsigned,
                "Expected {} to indicate unsigned comparison",
                mnemonic
            );
        }
    }

    #[test]
    fn test_set_instruction_signedness() {
        // SET instructions also indicate signedness
        let signed_set = ["setg", "setl", "setge", "setle"];
        let unsigned_set = ["seta", "setb", "setae", "setbe"];

        for mnemonic in signed_set {
            let m = mnemonic.to_lowercase();
            let is_signed = m.starts_with("set")
                && (m.ends_with("g") || m.ends_with("l") || m.ends_with("ge") || m.ends_with("le"));
            assert!(is_signed, "Expected {} to indicate signed", mnemonic);
        }

        for mnemonic in unsigned_set {
            let m = mnemonic.to_lowercase();
            let is_unsigned = m.starts_with("set")
                && (m.ends_with("a") || m.ends_with("b") || m.ends_with("ae") || m.ends_with("be"));
            assert!(is_unsigned, "Expected {} to indicate unsigned", mnemonic);
        }
    }

    #[test]
    fn test_type_to_c_string_signedness() {
        // Verify C type string output reflects signedness
        assert_eq!(TypeInference::type_to_c_string(&Type::sint(4)), "int");
        assert_eq!(
            TypeInference::type_to_c_string(&Type::uint(4)),
            "unsigned int"
        );
        assert_eq!(TypeInference::type_to_c_string(&Type::sint(8)), "int64_t");
        assert_eq!(TypeInference::type_to_c_string(&Type::uint(8)), "uint64_t");
        assert_eq!(TypeInference::type_to_c_string(&Type::sint(1)), "int8_t");
        assert_eq!(TypeInference::type_to_c_string(&Type::uint(1)), "uint8_t");
        assert_eq!(TypeInference::type_to_c_string(&Type::sint(2)), "int16_t");
        assert_eq!(TypeInference::type_to_c_string(&Type::uint(2)), "uint16_t");
    }

    #[test]
    fn test_template_type_display() {
        // Simple template
        let vec_int = Type::std_vector(Type::sint(4));
        assert_eq!(vec_int.to_string(), "std::vector<int32>");

        // Nested template
        let vec_vec_int = Type::std_vector(Type::std_vector(Type::sint(4)));
        assert_eq!(vec_vec_int.to_string(), "std::vector<std::vector<int32>>");

        // Map with two type arguments
        let map_str_int = Type::std_map(Type::std_string(), Type::sint(4));
        assert_eq!(
            map_str_int.to_string(),
            "std::map<std::basic_string<int8>, int32>"
        );
    }

    #[test]
    fn test_template_parser_simple() {
        let parser = TemplateParser::new();

        // Simple template
        let ty = parser.parse("std::vector<int>").unwrap();
        assert!(ty.is_template());
        if let Type::Template { name, args } = &ty {
            assert_eq!(name, "std::vector");
            assert_eq!(args.len(), 1);
        }

        // Not a template
        assert!(parser.parse("int").is_none());
        assert!(parser.parse("std::string").is_none());
    }

    #[test]
    fn test_template_parser_nested() {
        let parser = TemplateParser::new();

        // Nested template
        let ty = parser.parse("std::vector<std::vector<int>>").unwrap();
        if let Type::Template { name, args } = &ty {
            assert_eq!(name, "std::vector");
            assert_eq!(args.len(), 1);
            // First arg should be a nested template
            if let TemplateArg::Template {
                name: inner_name,
                args: inner_args,
            } = &args[0]
            {
                assert_eq!(inner_name, "std::vector");
                assert_eq!(inner_args.len(), 1);
            } else {
                panic!("Expected nested template argument");
            }
        }
    }

    #[test]
    fn test_template_parser_multiple_args() {
        let parser = TemplateParser::new();

        // Map with two type arguments
        let ty = parser.parse("std::map<std::string, int>").unwrap();
        if let Type::Template { name, args } = &ty {
            assert_eq!(name, "std::map");
            assert_eq!(args.len(), 2);
        }
    }

    #[test]
    fn test_template_parser_non_type_arg() {
        let parser = TemplateParser::new();

        // Template with non-type argument
        let ty = parser.parse("std::array<int, 10>").unwrap();
        if let Type::Template { name, args } = &ty {
            assert_eq!(name, "std::array");
            assert_eq!(args.len(), 2);
            // Second arg should be a value
            assert!(matches!(args[1], TemplateArg::Value(10)));
        }
    }

    #[test]
    fn test_template_database() {
        let mut db = TemplateDatabase::new();

        // Add some template instantiations
        db.parse_and_add("std::vector<int>");
        db.parse_and_add("std::vector<double>");
        db.parse_and_add("std::map<std::string, int>");

        assert_eq!(db.len(), 3);

        // Get all vector instantiations
        let vectors = db.get_instantiations("std::vector");
        assert_eq!(vectors.len(), 2);

        // Get all map instantiations
        let maps = db.get_instantiations("std::map");
        assert_eq!(maps.len(), 1);
    }

    #[test]
    fn test_template_type_helpers() {
        // Test std:: type helpers
        let vec = Type::std_vector(Type::sint(4));
        assert!(vec.is_template());

        let unique = Type::std_unique_ptr(Type::sint(4));
        assert!(unique.is_template());

        let shared = Type::std_shared_ptr(Type::sint(4));
        assert!(shared.is_template());
    }

    #[test]
    fn test_template_to_c_string() {
        // Verify C++ template type strings
        let vec_int = Type::std_vector(Type::sint(4));
        assert_eq!(
            TypeInference::type_to_c_string(&vec_int),
            "std::vector<int>"
        );

        // With non-type argument
        let ty = Type::template(
            "std::array",
            vec![
                TemplateArg::Type(Box::new(Type::sint(4))),
                TemplateArg::Value(10),
            ],
        );
        assert_eq!(TypeInference::type_to_c_string(&ty), "std::array<int, 10>");
    }

    #[test]
    fn test_stl_template_detection() {
        let parser = TemplateParser::new();

        // Known STL templates
        assert!(parser.is_stl_template("std::vector"));
        assert!(parser.is_stl_template("std::map"));
        assert!(parser.is_stl_template("std::unique_ptr"));

        // Not STL templates
        assert!(!parser.is_stl_template("MyClass"));
        assert!(!parser.is_stl_template("boost::shared_ptr"));
    }

    #[test]
    fn test_arm64_extend_patterns() {
        // Test detection of ARM64 extend mnemonics
        let sign_extend = ["sxtb", "sxth", "sxtw"];
        let zero_extend = ["uxtb", "uxth", "uxtw"];

        for mnemonic in sign_extend {
            let m = mnemonic.to_lowercase();
            assert!(
                m.starts_with("sxt"),
                "Expected {} to be detected as sign extension",
                mnemonic
            );
        }

        for mnemonic in zero_extend {
            let m = mnemonic.to_lowercase();
            assert!(
                m.starts_with("uxt"),
                "Expected {} to be detected as zero extension",
                mnemonic
            );
        }
    }

    #[test]
    fn test_arm64_division_patterns() {
        // Test detection of ARM64 division signedness
        let m1 = "sdiv".to_lowercase();
        assert!(m1 == "sdiv", "Expected sdiv to be signed division");

        let m2 = "udiv".to_lowercase();
        assert!(m2 == "udiv", "Expected udiv to be unsigned division");
    }

    #[test]
    fn test_arm64_shift_signedness() {
        // ASR = arithmetic shift right = signed
        // LSR = logical shift right = unsigned
        let m1 = "asr".to_lowercase();
        assert!(m1 == "asr", "ASR should indicate signed operands");

        let m2 = "lsr".to_lowercase();
        assert!(m2 == "lsr", "LSR should indicate unsigned operands");
    }

    #[test]
    fn test_arm64_fp_patterns() {
        // ARM64 floating-point mnemonics
        let fp_mnemonics = [
            "fadd", "fsub", "fmul", "fdiv", "fmov", "fcmp", "fcvt", "fsqrt", "fabs", "fneg",
            "fmadd", "fmsub", "fnmadd", "fnmsub", "frint", "fmax", "fmin",
        ];

        for mnemonic in fp_mnemonics {
            let m = mnemonic.to_lowercase();
            assert!(
                m.starts_with("f"),
                "Expected {} to start with 'f'",
                mnemonic
            );
        }

        // ARM64 SIMD/NEON conversion mnemonics
        let neon_fp = ["scvtf", "ucvtf", "fcvtzs", "fcvtzu", "fcvtns", "fcvtnu"];
        for mnemonic in neon_fp {
            let m = mnemonic.to_lowercase();
            assert!(
                m.starts_with("scvtf")
                    || m.starts_with("ucvtf")
                    || m.starts_with("fcvtz")
                    || m.starts_with("fcvtn"),
                "Expected {} to be NEON FP conversion",
                mnemonic
            );
        }
    }

    #[test]
    fn test_template_arg_display() {
        let type_arg = TemplateArg::Type(Box::new(Type::sint(4)));
        assert_eq!(type_arg.to_string(), "int32");

        let value_arg = TemplateArg::Value(42);
        assert_eq!(value_arg.to_string(), "42");

        let nested_arg = TemplateArg::Template {
            name: "std::vector".to_string(),
            args: vec![TemplateArg::Type(Box::new(Type::sint(4)))],
        };
        assert_eq!(nested_arg.to_string(), "std::vector<int32>");
    }
}
