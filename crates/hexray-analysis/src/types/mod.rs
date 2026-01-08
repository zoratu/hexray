//! Type inference for decompilation.
//!
//! This module provides basic type inference for variables based on:
//! - How values are used (pointer dereference, comparison, arithmetic)
//! - Size hints from memory operations
//! - Known library function signatures
//! - Comparison with constants
//!
//! The type system is simple and focused on decompilation needs:
//! - Distinguishing pointers from integers
//! - Inferring signedness from comparisons
//! - Detecting common types (strings, arrays, structs)

use crate::ssa::{SsaFunction, SsaValue};
use crate::ssa::types::SsaOperand;
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
        size: u8,       // 1, 2, 4, 8 bytes
        signed: bool,   // signed or unsigned
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
}

impl Type {
    /// Creates an integer type.
    pub fn int(size: u8, signed: bool) -> Self {
        Self::Int { size, signed }
    }

    /// Creates an unsigned integer type.
    pub fn uint(size: u8) -> Self {
        Self::Int { size, signed: false }
    }

    /// Creates a signed integer type.
    pub fn sint(size: u8) -> Self {
        Self::Int { size, signed: true }
    }

    /// Creates a pointer type.
    pub fn ptr(pointee: Type) -> Self {
        Self::Pointer(Box::new(pointee))
    }

    /// Returns true if this type is a pointer.
    pub fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_))
    }

    /// Returns true if this type is an integer.
    pub fn is_integer(&self) -> bool {
        matches!(self, Self::Int { .. })
    }

    /// Returns the size in bytes, if known.
    pub fn size(&self) -> Option<u8> {
        match self {
            Self::Unknown | Self::Void => None,
            Self::Bool => Some(1),
            Self::Int { size, .. } => Some(*size),
            Self::Pointer(_) | Self::Function { .. } => Some(8), // Assuming 64-bit
            Self::Array { element, count } => {
                let elem_size = element.size()?;
                Some(elem_size * (*count)? as u8)
            }
            Self::Struct { size, .. } => Some(*size as u8),
        }
    }

    /// Merges two types, taking the more specific one.
    pub fn merge(&self, other: &Type) -> Type {
        match (self, other) {
            (Type::Unknown, t) | (t, Type::Unknown) => t.clone(),
            (Type::Int { size: s1, signed: sg1 }, Type::Int { size: s2, signed: sg2 }) => {
                // Take larger size, prefer signed if either is signed
                Type::Int {
                    size: (*s1).max(*s2),
                    signed: *sg1 || *sg2,
                }
            }
            (Type::Pointer(p1), Type::Pointer(p2)) => {
                Type::Pointer(Box::new(p1.merge(p2)))
            }
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
            Type::Pointer(inner) => write!(f, "{}*", inner),
            Type::Array { element, count } => {
                if let Some(n) = count {
                    write!(f, "{}[{}]", element, n)
                } else {
                    write!(f, "{}[]", element)
                }
            }
            Type::Function { return_type, params } => {
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
    /// Value equals another value (types should match).
    Equals(SsaValue),
}

/// Type inference engine.
pub struct TypeInference {
    /// Inferred types for each SSA value.
    types: HashMap<SsaValue, Type>,
    /// Constraints collected during analysis.
    constraints: Vec<(SsaValue, Constraint)>,
}

impl TypeInference {
    /// Creates a new type inference engine.
    pub fn new() -> Self {
        Self {
            types: HashMap::new(),
            constraints: Vec::new(),
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
                    self.constraints.push((
                        phi.result.clone(),
                        Constraint::Equals(incoming.clone()),
                    ));
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
                            self.constraints.push((
                                addr.clone(),
                                Constraint::IsPointer,
                            ));
                        }
                        if let SsaOperand::Memory { size, .. } = addr_op {
                            self.constraints.push((
                                def.clone(),
                                Constraint::MinSize(*size),
                            ));
                        }
                    }
                }
            }

            // Comparisons tell us about signedness
            Operation::Compare | Operation::Test => {
                // If followed by signed branch, values are signed
                // This is simplified - real analysis would look at branch conditions
            }

            // Arithmetic propagates types
            Operation::Add | Operation::Sub | Operation::Mul | Operation::Div => {
                if let Some(def) = inst.defs.first() {
                    // Result type depends on operands
                    for op in &inst.uses {
                        if let SsaOperand::Value(v) = op {
                            self.constraints.push((
                                def.clone(),
                                Constraint::Equals(v.clone()),
                            ));
                        }
                    }
                }
            }

            // Shifts suggest the result is an integer
            Operation::Shl | Operation::Shr => {
                if let Some(def) = inst.defs.first() {
                    // Shr is typically unsigned, Sar (missing) would be signed
                    self.constraints.push((
                        def.clone(),
                        Constraint::IsUnsigned,
                    ));
                }
            }

            Operation::Sar => {
                if let Some(def) = inst.defs.first() {
                    self.constraints.push((
                        def.clone(),
                        Constraint::IsSigned,
                    ));
                }
            }

            // Move just propagates types
            Operation::Move => {
                if let (Some(def), Some(SsaOperand::Value(src))) =
                    (inst.defs.first(), inst.uses.first())
                {
                    self.constraints.push((
                        def.clone(),
                        Constraint::Equals(src.clone()),
                    ));
                }
            }

            // LoadEffectiveAddress creates a pointer
            Operation::LoadEffectiveAddress => {
                if let Some(def) = inst.defs.first() {
                    self.constraints.push((
                        def.clone(),
                        Constraint::IsPointer,
                    ));
                }
            }

            _ => {}
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

            Constraint::MinSize(size) => {
                match current {
                    Type::Unknown => Type::uint(*size),
                    Type::Int { size: s, signed } => {
                        Type::Int {
                            size: (*s).max(*size),
                            signed: *signed,
                        }
                    }
                    _ => current.clone(),
                }
            }

            Constraint::IsSigned => {
                match current {
                    Type::Unknown => Type::sint(8), // Default to 64-bit
                    Type::Int { size, .. } => Type::sint(*size),
                    _ => current.clone(),
                }
            }

            Constraint::IsUnsigned => {
                match current {
                    Type::Unknown => Type::uint(8),
                    Type::Int { size, .. } => Type::uint(*size),
                    _ => current.clone(),
                }
            }

            Constraint::Equals(other) => {
                let other_type = self.types.get(other).cloned().unwrap_or(Type::Unknown);
                current.merge(&other_type)
            }
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

        // Add common libc signatures
        sigs.add_signature(FunctionSignature {
            name: "printf".to_string(),
            return_type: Type::sint(4),
            parameters: vec![
                ("format".to_string(), Type::ptr(Type::sint(1))),
            ],
            variadic: true,
        });

        sigs.add_signature(FunctionSignature {
            name: "malloc".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("size".to_string(), Type::uint(8)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "free".to_string(),
            return_type: Type::Void,
            parameters: vec![
                ("ptr".to_string(), Type::ptr(Type::Void)),
            ],
            variadic: false,
        });

        sigs.add_signature(FunctionSignature {
            name: "strlen".to_string(),
            return_type: Type::uint(8),
            parameters: vec![
                ("s".to_string(), Type::ptr(Type::sint(1))),
            ],
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
            name: "memcpy".to_string(),
            return_type: Type::ptr(Type::Void),
            parameters: vec![
                ("dest".to_string(), Type::ptr(Type::Void)),
                ("src".to_string(), Type::ptr(Type::Void)),
                ("n".to_string(), Type::uint(8)),
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
}
