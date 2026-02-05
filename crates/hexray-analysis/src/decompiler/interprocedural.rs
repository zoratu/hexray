//! Inter-procedural analysis for type and value propagation across function calls.
//!
//! This module provides infrastructure for analyzing function summaries and propagating
//! type and value information between callers and callees in the call graph.

use std::collections::{HashMap, HashSet};

use crate::callgraph::CallGraph;

/// Summary of a function's effects and characteristics.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FunctionSummary {
    /// Address of the function.
    pub address: u64,

    /// Inferred parameter types (index -> type).
    pub param_types: HashMap<usize, SummaryType>,

    /// Inferred return type.
    pub return_type: Option<SummaryType>,

    /// Whether the function is pure (no side effects).
    pub is_pure: bool,

    /// Whether the function allocates memory.
    pub allocates: bool,

    /// Whether the function frees memory.
    pub frees: bool,

    /// Whether the function may not return (calls exit/abort).
    pub may_not_return: bool,

    /// Global variables read by this function.
    pub globals_read: HashSet<u64>,

    /// Global variables written by this function.
    pub globals_written: HashSet<u64>,

    /// Functions called by this function (for transitive analysis).
    pub callees: HashSet<u64>,

    /// Constant return value if always returns the same value.
    pub constant_return: Option<i128>,

    /// Whether return value depends only on arguments (no global state).
    pub return_depends_only_on_args: bool,
}

/// A type that can be propagated inter-procedurally.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum SummaryType {
    /// Unknown type.
    #[default]
    Unknown,
    /// Void (no value).
    Void,
    /// Signed integer of given bit width.
    SignedInt(u8),
    /// Unsigned integer of given bit width.
    UnsignedInt(u8),
    /// Floating point of given bit width.
    Float(u8),
    /// Pointer to another type.
    Pointer(Box<SummaryType>),
    /// Array of elements.
    Array(Box<SummaryType>, Option<usize>),
    /// Reference to a struct by name or address.
    Struct(String),
    /// Function pointer with parameter and return types.
    FunctionPointer {
        params: Vec<SummaryType>,
        return_type: Box<SummaryType>,
    },
    /// Boolean.
    Bool,
}

impl SummaryType {
    /// Creates a signed integer type.
    pub fn signed(bits: u8) -> Self {
        SummaryType::SignedInt(bits)
    }

    /// Creates an unsigned integer type.
    pub fn unsigned(bits: u8) -> Self {
        SummaryType::UnsignedInt(bits)
    }

    /// Creates a pointer to the given type.
    pub fn pointer(inner: SummaryType) -> Self {
        SummaryType::Pointer(Box::new(inner))
    }

    /// Returns true if this type is more specific than the other.
    pub fn is_more_specific_than(&self, other: &SummaryType) -> bool {
        match (self, other) {
            (_, SummaryType::Unknown) => !matches!(self, SummaryType::Unknown),
            (SummaryType::SignedInt(_), SummaryType::UnsignedInt(_)) => true,
            (SummaryType::Pointer(inner), SummaryType::Pointer(other_inner)) => {
                inner.is_more_specific_than(other_inner)
            }
            _ => false,
        }
    }

    /// Merges two types, returning the more specific one or Unknown if incompatible.
    pub fn merge(&self, other: &SummaryType) -> SummaryType {
        if self == other {
            return self.clone();
        }

        match (self, other) {
            (SummaryType::Unknown, t) | (t, SummaryType::Unknown) => t.clone(),
            (SummaryType::SignedInt(a), SummaryType::SignedInt(b)) if a == b => self.clone(),
            (SummaryType::UnsignedInt(a), SummaryType::UnsignedInt(b)) if a == b => self.clone(),
            (SummaryType::SignedInt(a), SummaryType::UnsignedInt(b))
            | (SummaryType::UnsignedInt(b), SummaryType::SignedInt(a))
                if a == b =>
            {
                // Prefer signed when merging signed and unsigned of same size
                SummaryType::SignedInt(*a)
            }
            (SummaryType::Pointer(a), SummaryType::Pointer(b)) => {
                SummaryType::Pointer(Box::new(a.merge(b)))
            }
            (SummaryType::Array(a, len_a), SummaryType::Array(b, len_b)) => {
                let merged_len = match (len_a, len_b) {
                    (Some(a), Some(b)) if a == b => Some(*a),
                    (Some(a), None) | (None, Some(a)) => Some(*a),
                    _ => None,
                };
                SummaryType::Array(Box::new(a.merge(b)), merged_len)
            }
            _ => SummaryType::Unknown,
        }
    }

    /// Converts to a size in bytes if known.
    pub fn size_bytes(&self) -> Option<usize> {
        match self {
            SummaryType::Bool => Some(1),
            SummaryType::SignedInt(bits) | SummaryType::UnsignedInt(bits) => {
                Some(*bits as usize / 8)
            }
            SummaryType::Float(bits) => Some(*bits as usize / 8),
            SummaryType::Pointer(_) => Some(8), // Assume 64-bit
            SummaryType::Array(elem, Some(len)) => elem.size_bytes().map(|s| s * len),
            _ => None,
        }
    }
}

impl std::fmt::Display for SummaryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SummaryType::Unknown => write!(f, "unknown"),
            SummaryType::Void => write!(f, "void"),
            SummaryType::SignedInt(bits) => write!(f, "i{}", bits),
            SummaryType::UnsignedInt(bits) => write!(f, "u{}", bits),
            SummaryType::Float(32) => write!(f, "float"),
            SummaryType::Float(64) => write!(f, "double"),
            SummaryType::Float(bits) => write!(f, "f{}", bits),
            SummaryType::Pointer(inner) => write!(f, "{}*", inner),
            SummaryType::Array(elem, Some(len)) => write!(f, "{}[{}]", elem, len),
            SummaryType::Array(elem, None) => write!(f, "{}[]", elem),
            SummaryType::Struct(name) => write!(f, "struct {}", name),
            SummaryType::FunctionPointer {
                params,
                return_type,
            } => {
                write!(f, "{}(*)(", return_type)?;
                for (i, param) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", param)?;
                }
                write!(f, ")")
            }
            SummaryType::Bool => write!(f, "bool"),
        }
    }
}

/// Call site information for inter-procedural analysis.
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    /// Address of the call instruction.
    pub call_address: u64,
    /// Address of the caller function.
    pub caller: u64,
    /// Address of the callee function (if resolved).
    pub callee: Option<u64>,
    /// Types of arguments at this call site.
    pub arg_types: Vec<SummaryType>,
    /// Type expected for return value at this call site.
    pub expected_return_type: Option<SummaryType>,
}

/// Database of function summaries for inter-procedural analysis.
#[derive(Debug, Default)]
pub struct SummaryDatabase {
    /// Function summaries indexed by address.
    summaries: HashMap<u64, FunctionSummary>,
    /// Call site information.
    call_sites: Vec<CallSiteInfo>,
    /// Functions that have been fully analyzed.
    analyzed: HashSet<u64>,
    /// Known library function signatures.
    known_functions: HashMap<String, FunctionSummary>,
}

impl SummaryDatabase {
    /// Creates a new summary database.
    pub fn new() -> Self {
        let mut db = Self::default();
        db.populate_known_functions();
        db
    }

    /// Populates the database with known library function signatures.
    fn populate_known_functions(&mut self) {
        // Memory allocation functions
        self.add_known_function(
            "malloc",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::UnsignedInt(64))].into_iter().collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                allocates: true,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "calloc",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::UnsignedInt(64)),
                    (1, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                allocates: true,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "realloc",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                allocates: true,
                frees: true, // May free old pointer
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "free",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::Void))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::Void),
                is_pure: false,
                allocates: false,
                frees: true,
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        // String functions
        self.add_known_function(
            "strlen",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::UnsignedInt(64)),
                is_pure: true,
                allocates: false,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strcmp",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: true,
                allocates: false,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strncmp",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: true,
                allocates: false,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strcpy",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: false,
                allocates: false,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strncpy",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: false,
                allocates: false,
                frees: false,
                may_not_return: false,
                return_depends_only_on_args: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strcat",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strchr",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::SignedInt(32)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strrchr",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::SignedInt(32)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strstr",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::SignedInt(8))),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        // Memory functions
        self.add_known_function(
            "memcpy",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::pointer(SummaryType::Void)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "memmove",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::pointer(SummaryType::Void)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "memset",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::SignedInt(32)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "memcmp",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::pointer(SummaryType::Void)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        // I/O functions
        self.add_known_function(
            "printf",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "fprintf",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)), // FILE*
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "sprintf",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "snprintf",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::UnsignedInt(64)),
                    (2, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "puts",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "putchar",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::SignedInt(32))].into_iter().collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "getchar",
            FunctionSummary {
                address: 0,
                param_types: HashMap::new(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "fopen",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::pointer(SummaryType::Void)),
                is_pure: false,
                allocates: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "fclose",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::Void))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                frees: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "fread",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::UnsignedInt(64)),
                    (2, SummaryType::UnsignedInt(64)),
                    (3, SummaryType::pointer(SummaryType::Void)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::UnsignedInt(64)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "fwrite",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::Void)),
                    (1, SummaryType::UnsignedInt(64)),
                    (2, SummaryType::UnsignedInt(64)),
                    (3, SummaryType::pointer(SummaryType::Void)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::UnsignedInt(64)),
                is_pure: false,
                ..Default::default()
            },
        );

        // No-return functions
        self.add_known_function(
            "exit",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::SignedInt(32))].into_iter().collect(),
                return_type: Some(SummaryType::Void),
                may_not_return: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "_exit",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::SignedInt(32))].into_iter().collect(),
                return_type: Some(SummaryType::Void),
                may_not_return: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "abort",
            FunctionSummary {
                address: 0,
                param_types: HashMap::new(),
                return_type: Some(SummaryType::Void),
                may_not_return: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "__assert_fail",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (2, SummaryType::UnsignedInt(32)),
                    (3, SummaryType::pointer(SummaryType::SignedInt(8))),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::Void),
                may_not_return: true,
                ..Default::default()
            },
        );

        // Conversion functions
        self.add_known_function(
            "atoi",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "atol",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::SignedInt(64)),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "atof",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::pointer(SummaryType::SignedInt(8)))]
                    .into_iter()
                    .collect(),
                return_type: Some(SummaryType::Float(64)),
                is_pure: true,
                return_depends_only_on_args: true,
                ..Default::default()
            },
        );

        self.add_known_function(
            "strtol",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (
                        1,
                        SummaryType::pointer(SummaryType::pointer(SummaryType::SignedInt(8))),
                    ),
                    (2, SummaryType::SignedInt(32)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(64)),
                is_pure: false, // Writes to endptr
                ..Default::default()
            },
        );

        self.add_known_function(
            "strtoul",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (
                        1,
                        SummaryType::pointer(SummaryType::pointer(SummaryType::SignedInt(8))),
                    ),
                    (2, SummaryType::SignedInt(32)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::UnsignedInt(64)),
                is_pure: false,
                ..Default::default()
            },
        );

        // Math functions
        for func in ["abs", "labs", "llabs"] {
            self.add_known_function(
                func,
                FunctionSummary {
                    address: 0,
                    param_types: [(0, SummaryType::SignedInt(64))].into_iter().collect(),
                    return_type: Some(SummaryType::SignedInt(64)),
                    is_pure: true,
                    return_depends_only_on_args: true,
                    ..Default::default()
                },
            );
        }

        for func in [
            "sqrt", "sin", "cos", "tan", "log", "log10", "exp", "pow", "floor", "ceil", "fabs",
        ] {
            let num_params = if func == "pow" { 2 } else { 1 };
            let mut params = HashMap::new();
            for i in 0..num_params {
                params.insert(i, SummaryType::Float(64));
            }
            self.add_known_function(
                func,
                FunctionSummary {
                    address: 0,
                    param_types: params,
                    return_type: Some(SummaryType::Float(64)),
                    is_pure: true,
                    return_depends_only_on_args: true,
                    ..Default::default()
                },
            );
        }

        // POSIX functions
        self.add_known_function(
            "read",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::SignedInt(32)),
                    (1, SummaryType::pointer(SummaryType::Void)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(64)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "write",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::SignedInt(32)),
                    (1, SummaryType::pointer(SummaryType::Void)),
                    (2, SummaryType::UnsignedInt(64)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(64)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "open",
            FunctionSummary {
                address: 0,
                param_types: [
                    (0, SummaryType::pointer(SummaryType::SignedInt(8))),
                    (1, SummaryType::SignedInt(32)),
                ]
                .into_iter()
                .collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );

        self.add_known_function(
            "close",
            FunctionSummary {
                address: 0,
                param_types: [(0, SummaryType::SignedInt(32))].into_iter().collect(),
                return_type: Some(SummaryType::SignedInt(32)),
                is_pure: false,
                ..Default::default()
            },
        );
    }

    /// Adds a known function signature.
    fn add_known_function(&mut self, name: &str, summary: FunctionSummary) {
        self.known_functions.insert(name.to_string(), summary);
    }

    /// Gets the summary for a function by address.
    pub fn get_summary(&self, address: u64) -> Option<&FunctionSummary> {
        self.summaries.get(&address)
    }

    /// Gets the summary for a function by name.
    pub fn get_summary_by_name(&self, name: &str) -> Option<&FunctionSummary> {
        // Strip common prefixes
        let clean_name = name
            .strip_prefix('_')
            .or_else(|| name.strip_prefix("__"))
            .unwrap_or(name);

        self.known_functions
            .get(clean_name)
            .or_else(|| self.known_functions.get(name))
    }

    /// Sets the summary for a function.
    pub fn set_summary(&mut self, address: u64, summary: FunctionSummary) {
        self.summaries.insert(address, summary);
    }

    /// Marks a function as analyzed.
    pub fn mark_analyzed(&mut self, address: u64) {
        self.analyzed.insert(address);
    }

    /// Checks if a function has been analyzed.
    pub fn is_analyzed(&self, address: u64) -> bool {
        self.analyzed.contains(&address)
    }

    /// Adds a call site for later analysis.
    pub fn add_call_site(&mut self, info: CallSiteInfo) {
        self.call_sites.push(info);
    }

    /// Gets all call sites for a given callee.
    pub fn call_sites_to(&self, callee: u64) -> Vec<&CallSiteInfo> {
        self.call_sites
            .iter()
            .filter(|cs| cs.callee == Some(callee))
            .collect()
    }

    /// Gets all call sites from a given caller.
    pub fn call_sites_from(&self, caller: u64) -> Vec<&CallSiteInfo> {
        self.call_sites
            .iter()
            .filter(|cs| cs.caller == caller)
            .collect()
    }

    /// Updates parameter types based on call site information.
    pub fn propagate_arg_types(&mut self, address: u64) {
        let call_sites: Vec<_> = self.call_sites_to(address).into_iter().cloned().collect();

        if call_sites.is_empty() {
            return;
        }

        let summary = self
            .summaries
            .entry(address)
            .or_insert_with(|| FunctionSummary {
                address,
                ..Default::default()
            });

        // Merge argument types from all call sites
        for call_site in &call_sites {
            for (idx, arg_type) in call_site.arg_types.iter().enumerate() {
                let existing = summary
                    .param_types
                    .entry(idx)
                    .or_insert(SummaryType::Unknown);
                *existing = existing.merge(arg_type);
            }
        }
    }

    /// Gets all function summaries.
    pub fn all_summaries(&self) -> impl Iterator<Item = (&u64, &FunctionSummary)> {
        self.summaries.iter()
    }

    /// Returns the number of analyzed functions.
    pub fn analyzed_count(&self) -> usize {
        self.analyzed.len()
    }

    /// Returns the total number of summaries.
    pub fn summary_count(&self) -> usize {
        self.summaries.len()
    }
}

/// Inter-procedural analysis engine.
pub struct InterproceduralAnalysis<'a> {
    /// The call graph.
    call_graph: &'a CallGraph,
    /// Summary database.
    summaries: SummaryDatabase,
    /// Maximum iterations for fixed-point computation.
    max_iterations: usize,
}

impl<'a> InterproceduralAnalysis<'a> {
    /// Creates a new inter-procedural analysis.
    pub fn new(call_graph: &'a CallGraph) -> Self {
        Self {
            call_graph,
            summaries: SummaryDatabase::new(),
            max_iterations: 10,
        }
    }

    /// Sets the maximum iterations for fixed-point computation.
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Runs the inter-procedural analysis.
    pub fn analyze(&mut self) -> &SummaryDatabase {
        // Process functions in reverse topological order (callees before callers)
        // This ensures we have callee summaries before processing callers
        let order = self.compute_analysis_order();

        for _iteration in 0..self.max_iterations {
            let mut changed = false;

            for &func_addr in &order {
                if self.analyze_function(func_addr) {
                    changed = true;
                }
            }

            if !changed {
                // Analysis converged
                break;
            }
        }

        &self.summaries
    }

    /// Computes the order in which to analyze functions.
    fn compute_analysis_order(&self) -> Vec<u64> {
        // Try to get topological order (callees first)
        if let Some(order) = self.call_graph.topological_order() {
            order
        } else {
            // If cyclic, just use arbitrary order
            self.call_graph.nodes().map(|n| n.address).collect()
        }
    }

    /// Analyzes a single function and returns whether the summary changed.
    fn analyze_function(&mut self, address: u64) -> bool {
        let old_summary = self.summaries.get_summary(address).cloned();

        // Get information about callees
        let callees: Vec<u64> = self
            .call_graph
            .callees(address)
            .map(|(callee, _)| callee)
            .collect();

        // Create or update summary
        let mut summary = old_summary.clone().unwrap_or_else(|| FunctionSummary {
            address,
            ..Default::default()
        });

        summary.callees = callees.iter().copied().collect();

        // Check for pure functions (all callees must be pure, no globals written)
        summary.is_pure = summary.globals_written.is_empty()
            && callees.iter().all(|&callee| {
                self.summaries
                    .get_summary(callee)
                    .map(|s| s.is_pure)
                    .unwrap_or(false)
            });

        // Check for may-not-return (any callee may not return)
        summary.may_not_return = callees.iter().any(|&callee| {
            self.summaries
                .get_summary(callee)
                .map(|s| s.may_not_return)
                .unwrap_or(false)
        });

        // Check for allocates/frees transitively
        summary.allocates = summary.allocates
            || callees.iter().any(|&callee| {
                self.summaries
                    .get_summary(callee)
                    .map(|s| s.allocates)
                    .unwrap_or(false)
            });

        summary.frees = summary.frees
            || callees.iter().any(|&callee| {
                self.summaries
                    .get_summary(callee)
                    .map(|s| s.frees)
                    .unwrap_or(false)
            });

        // Propagate argument types from call sites
        self.summaries.propagate_arg_types(address);

        self.summaries.set_summary(address, summary.clone());
        self.summaries.mark_analyzed(address);

        // Check if summary changed
        old_summary.as_ref() != Some(&summary)
    }

    /// Gets the summary database.
    pub fn summaries(&self) -> &SummaryDatabase {
        &self.summaries
    }

    /// Takes ownership of the summary database.
    pub fn into_summaries(self) -> SummaryDatabase {
        self.summaries
    }
}

/// Propagates return types from callees to caller expressions.
pub fn propagate_return_types(
    summaries: &SummaryDatabase,
    function_name: Option<&str>,
) -> Option<SummaryType> {
    function_name.and_then(|name| {
        summaries
            .get_summary_by_name(name)
            .and_then(|s| s.return_type.clone())
    })
}

/// Infers argument types for a call based on expressions.
pub fn infer_arg_types_from_call(args: &[super::expression::Expr]) -> Vec<SummaryType> {
    args.iter().map(infer_type_from_expr).collect()
}

/// Infers a type from an expression.
fn infer_type_from_expr(expr: &super::expression::Expr) -> SummaryType {
    use super::expression::ExprKind;

    match &expr.kind {
        ExprKind::IntLit(val) => {
            // Heuristic: negative values are signed, otherwise unsigned
            if *val < 0 {
                SummaryType::SignedInt(64)
            } else if *val <= 255 {
                SummaryType::UnsignedInt(8)
            } else if *val <= 65535 {
                SummaryType::UnsignedInt(16)
            } else if *val <= u32::MAX as i128 {
                SummaryType::UnsignedInt(32)
            } else {
                SummaryType::UnsignedInt(64)
            }
        }
        ExprKind::Var(var) => {
            // Check for pointer indicators in name
            let name = &var.name;
            if name.contains("ptr")
                || name.contains("addr")
                || name.ends_with("_p")
                || name.starts_with("p_")
            {
                SummaryType::pointer(SummaryType::Void)
            } else if name.contains("str") || name.contains("buf") {
                SummaryType::pointer(SummaryType::SignedInt(8))
            } else if name.contains("size") || name.contains("len") || name.contains("count") {
                SummaryType::UnsignedInt(64)
            } else if name.contains("flag") || name.contains("bool") {
                SummaryType::Bool
            } else {
                SummaryType::Unknown
            }
        }
        ExprKind::Deref { addr, size } => {
            // Dereferencing returns the pointed-to type
            if let SummaryType::Pointer(inner_type) = infer_type_from_expr(addr) {
                (*inner_type).clone()
            } else {
                // Use size hint
                SummaryType::UnsignedInt(*size * 8)
            }
        }
        ExprKind::AddressOf(_) => SummaryType::pointer(SummaryType::Void),
        ExprKind::Cast { to_size, .. } => SummaryType::UnsignedInt(*to_size * 8),
        ExprKind::BinOp { op, .. } => {
            use super::expression::BinOpKind;
            match op {
                BinOpKind::Eq
                | BinOpKind::Ne
                | BinOpKind::Lt
                | BinOpKind::Le
                | BinOpKind::Gt
                | BinOpKind::Ge
                | BinOpKind::And
                | BinOpKind::Or => SummaryType::Bool,
                _ => SummaryType::Unknown,
            }
        }
        ExprKind::ArrayAccess { base, .. } => {
            if let SummaryType::Pointer(elem) = infer_type_from_expr(base) {
                (*elem).clone()
            } else {
                SummaryType::Unknown
            }
        }
        _ => SummaryType::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_summary_type_merge() {
        let unknown = SummaryType::Unknown;
        let i32_type = SummaryType::SignedInt(32);
        let u32_type = SummaryType::UnsignedInt(32);

        // Unknown merges with anything
        assert_eq!(unknown.merge(&i32_type), i32_type);
        assert_eq!(i32_type.merge(&unknown), i32_type);

        // Same types merge to themselves
        assert_eq!(i32_type.merge(&i32_type), i32_type);

        // Signed and unsigned of same size merge to signed
        assert_eq!(i32_type.merge(&u32_type), i32_type);
        assert_eq!(u32_type.merge(&i32_type), i32_type);
    }

    #[test]
    fn test_summary_type_display() {
        assert_eq!(format!("{}", SummaryType::SignedInt(32)), "i32");
        assert_eq!(format!("{}", SummaryType::UnsignedInt(64)), "u64");
        assert_eq!(format!("{}", SummaryType::Float(32)), "float");
        assert_eq!(format!("{}", SummaryType::Float(64)), "double");
        assert_eq!(
            format!("{}", SummaryType::pointer(SummaryType::SignedInt(8))),
            "i8*"
        );
        assert_eq!(
            format!(
                "{}",
                SummaryType::Array(Box::new(SummaryType::SignedInt(32)), Some(10))
            ),
            "i32[10]"
        );
    }

    #[test]
    fn test_summary_database_known_functions() {
        let db = SummaryDatabase::new();

        // Check malloc signature
        let malloc = db.get_summary_by_name("malloc").unwrap();
        assert!(malloc.allocates);
        assert!(!malloc.frees);
        assert!(matches!(malloc.return_type, Some(SummaryType::Pointer(_))));

        // Check strlen signature
        let strlen = db.get_summary_by_name("strlen").unwrap();
        assert!(strlen.is_pure);
        assert!(strlen.return_depends_only_on_args);

        // Check exit signature
        let exit = db.get_summary_by_name("exit").unwrap();
        assert!(exit.may_not_return);

        // Check with underscore prefix
        let _exit = db.get_summary_by_name("_exit").unwrap();
        assert!(_exit.may_not_return);
    }

    #[test]
    fn test_summary_type_size() {
        assert_eq!(SummaryType::SignedInt(32).size_bytes(), Some(4));
        assert_eq!(SummaryType::UnsignedInt(64).size_bytes(), Some(8));
        assert_eq!(SummaryType::Float(32).size_bytes(), Some(4));
        assert_eq!(SummaryType::Bool.size_bytes(), Some(1));
        assert_eq!(
            SummaryType::pointer(SummaryType::Void).size_bytes(),
            Some(8)
        );
        assert_eq!(
            SummaryType::Array(Box::new(SummaryType::SignedInt(32)), Some(10)).size_bytes(),
            Some(40)
        );
    }

    #[test]
    fn test_call_site_tracking() {
        let mut db = SummaryDatabase::new();

        db.add_call_site(CallSiteInfo {
            call_address: 0x1000,
            caller: 0x100,
            callee: Some(0x200),
            arg_types: vec![
                SummaryType::SignedInt(32),
                SummaryType::pointer(SummaryType::Void),
            ],
            expected_return_type: None,
        });

        db.add_call_site(CallSiteInfo {
            call_address: 0x2000,
            caller: 0x100,
            callee: Some(0x300),
            arg_types: vec![SummaryType::UnsignedInt(64)],
            expected_return_type: Some(SummaryType::SignedInt(32)),
        });

        let from_100 = db.call_sites_from(0x100);
        assert_eq!(from_100.len(), 2);

        let to_200 = db.call_sites_to(0x200);
        assert_eq!(to_200.len(), 1);
        assert_eq!(to_200[0].arg_types.len(), 2);
    }

    #[test]
    fn test_propagate_arg_types() {
        let mut db = SummaryDatabase::new();

        // Two call sites to same function with different arg types
        db.add_call_site(CallSiteInfo {
            call_address: 0x1000,
            caller: 0x100,
            callee: Some(0x200),
            arg_types: vec![SummaryType::SignedInt(32)],
            expected_return_type: None,
        });

        db.add_call_site(CallSiteInfo {
            call_address: 0x2000,
            caller: 0x300,
            callee: Some(0x200),
            arg_types: vec![SummaryType::UnsignedInt(32)],
            expected_return_type: None,
        });

        db.propagate_arg_types(0x200);

        let summary = db.get_summary(0x200).unwrap();
        // Should merge to signed (our heuristic)
        assert_eq!(
            summary.param_types.get(&0),
            Some(&SummaryType::SignedInt(32))
        );
    }

    #[test]
    fn test_summary_type_is_more_specific() {
        let unknown = SummaryType::Unknown;
        let i32_type = SummaryType::SignedInt(32);
        let u32_type = SummaryType::UnsignedInt(32);

        assert!(i32_type.is_more_specific_than(&unknown));
        assert!(!unknown.is_more_specific_than(&i32_type));
        assert!(i32_type.is_more_specific_than(&u32_type));
    }
}
