//! Function signature definition.
//!
//! A signature contains the byte pattern, function metadata,
//! and optional type information.

use crate::pattern::BytePattern;
use serde::{Deserialize, Serialize};

/// Calling convention for the function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    /// System V AMD64 ABI (Linux, macOS, BSD).
    #[default]
    SystemV,
    /// Microsoft x64 calling convention.
    Win64,
    /// ARM64 AAPCS64.
    Aarch64,
    /// RISC-V calling convention.
    RiscV,
    /// 32-bit cdecl.
    Cdecl,
    /// 32-bit stdcall (Windows).
    Stdcall,
    /// Unknown/custom.
    Unknown,
}

impl CallingConvention {
    /// Get the calling convention name.
    pub fn name(&self) -> &'static str {
        match self {
            CallingConvention::SystemV => "System V",
            CallingConvention::Win64 => "Win64",
            CallingConvention::Aarch64 => "AAPCS64",
            CallingConvention::RiscV => "RISC-V",
            CallingConvention::Cdecl => "cdecl",
            CallingConvention::Stdcall => "stdcall",
            CallingConvention::Unknown => "unknown",
        }
    }
}

/// Parameter type information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ParameterType {
    /// Void (for return type).
    Void,
    /// Integer type with size in bytes.
    Int { size: u8, signed: bool },
    /// Pointer to another type.
    Pointer(Box<ParameterType>),
    /// Char pointer (string).
    String,
    /// Opaque pointer (void*).
    OpaquePtr,
    /// Size type (size_t).
    Size,
    /// File pointer (FILE*).
    FilePtr,
    /// Unknown type.
    #[default]
    Unknown,
}

impl ParameterType {
    /// Get a human-readable C type string.
    pub fn to_c_string(&self) -> String {
        match self {
            ParameterType::Void => "void".to_string(),
            ParameterType::Int { size, signed } => {
                let base = match (size, signed) {
                    (1, true) => "int8_t",
                    (1, false) => "uint8_t",
                    (2, true) => "int16_t",
                    (2, false) => "uint16_t",
                    (4, true) => "int",
                    (4, false) => "unsigned int",
                    (8, true) => "int64_t",
                    (8, false) => "uint64_t",
                    _ => "int",
                };
                base.to_string()
            }
            ParameterType::Pointer(inner) => format!("{}*", inner.to_c_string()),
            ParameterType::String => "const char*".to_string(),
            ParameterType::OpaquePtr => "void*".to_string(),
            ParameterType::Size => "size_t".to_string(),
            ParameterType::FilePtr => "FILE*".to_string(),
            ParameterType::Unknown => "...".to_string(),
        }
    }
}

/// Function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameter {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub param_type: ParameterType,
}

impl Parameter {
    /// Create a new parameter.
    pub fn new(name: impl Into<String>, param_type: ParameterType) -> Self {
        Self {
            name: name.into(),
            param_type,
        }
    }

    /// Create an int parameter.
    pub fn int(name: impl Into<String>) -> Self {
        Self::new(
            name,
            ParameterType::Int {
                size: 4,
                signed: true,
            },
        )
    }

    /// Create a size_t parameter.
    pub fn size(name: impl Into<String>) -> Self {
        Self::new(name, ParameterType::Size)
    }

    /// Create a string parameter.
    pub fn string(name: impl Into<String>) -> Self {
        Self::new(name, ParameterType::String)
    }

    /// Create a void* parameter.
    pub fn ptr(name: impl Into<String>) -> Self {
        Self::new(name, ParameterType::OpaquePtr)
    }

    /// Create a FILE* parameter.
    pub fn file(name: impl Into<String>) -> Self {
        Self::new(name, ParameterType::FilePtr)
    }
}

/// A function signature for pattern matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name.
    pub name: String,

    /// Byte pattern for matching the function prologue.
    pub pattern: BytePattern,

    /// Expected function size (approximate).
    /// Used to disambiguate matches of similar patterns.
    pub size_hint: Option<usize>,

    /// Calling convention.
    pub calling_convention: CallingConvention,

    /// Return type.
    pub return_type: ParameterType,

    /// Parameters.
    pub parameters: Vec<Parameter>,

    /// Whether the function is variadic.
    pub variadic: bool,

    /// Library this signature comes from.
    pub library: String,

    /// Library version (e.g., "glibc-2.31", "musl-1.2").
    pub version: Option<String>,

    /// Optional documentation.
    pub doc: Option<String>,

    /// Confidence level (0.0 - 1.0).
    /// Higher means more unique pattern, less likely false positive.
    pub confidence: f32,

    /// Alternative names (aliases).
    pub aliases: Vec<String>,
}

impl FunctionSignature {
    /// Create a new function signature.
    pub fn new(name: impl Into<String>, pattern: BytePattern) -> Self {
        Self {
            name: name.into(),
            pattern,
            size_hint: None,
            calling_convention: CallingConvention::default(),
            return_type: ParameterType::Int {
                size: 4,
                signed: true,
            },
            parameters: Vec::new(),
            variadic: false,
            library: "libc".to_string(),
            version: None,
            doc: None,
            confidence: 0.5,
            aliases: Vec::new(),
        }
    }

    /// Create from a hex pattern string.
    pub fn from_hex(name: impl Into<String>, hex_pattern: &str) -> crate::Result<Self> {
        let pattern = BytePattern::parse(hex_pattern)?;
        Ok(Self::new(name, pattern))
    }

    /// Set the size hint.
    pub fn with_size_hint(mut self, size: usize) -> Self {
        self.size_hint = Some(size);
        self
    }

    /// Set the calling convention.
    pub fn with_convention(mut self, convention: CallingConvention) -> Self {
        self.calling_convention = convention;
        self
    }

    /// Set the return type.
    pub fn with_return_type(mut self, ret_type: ParameterType) -> Self {
        self.return_type = ret_type;
        self
    }

    /// Add a parameter.
    pub fn with_param(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Set as variadic.
    pub fn variadic(mut self) -> Self {
        self.variadic = true;
        self
    }

    /// Set the library.
    pub fn with_library(mut self, library: impl Into<String>) -> Self {
        self.library = library.into();
        self
    }

    /// Set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the documentation.
    pub fn with_doc(mut self, doc: impl Into<String>) -> Self {
        self.doc = Some(doc.into());
        self
    }

    /// Set the confidence level.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Add an alias.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.aliases.push(alias.into());
        self
    }

    /// Get the pattern length.
    pub fn pattern_len(&self) -> usize {
        self.pattern.len()
    }

    /// Check if this signature matches the given bytes.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.pattern.matches(bytes)
    }

    /// Get the C function prototype string.
    pub fn to_c_prototype(&self) -> String {
        let ret = self.return_type.to_c_string();
        let params: Vec<String> = self
            .parameters
            .iter()
            .map(|p| format!("{} {}", p.param_type.to_c_string(), p.name))
            .collect();

        let params_str = if params.is_empty() {
            "void".to_string()
        } else if self.variadic {
            format!("{}, ...", params.join(", "))
        } else {
            params.join(", ")
        };

        format!("{} {}({})", ret, self.name, params_str)
    }
}

impl std::fmt::Display for FunctionSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_c_prototype())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_create() {
        let sig = FunctionSignature::from_hex("strlen", "55 48 89 E5")
            .unwrap()
            .with_param(Parameter::string("s"))
            .with_return_type(ParameterType::Size)
            .with_library("libc")
            .with_doc("Calculate string length");

        assert_eq!(sig.name, "strlen");
        assert_eq!(sig.pattern_len(), 4);
        assert_eq!(sig.library, "libc");
        assert!(sig.doc.is_some());
    }

    #[test]
    fn test_signature_matches() {
        let sig = FunctionSignature::from_hex("test", "55 48 ?? E5").unwrap();
        assert!(sig.matches(&[0x55, 0x48, 0x00, 0xE5]));
        assert!(sig.matches(&[0x55, 0x48, 0xFF, 0xE5]));
        assert!(!sig.matches(&[0x55, 0x48, 0x00, 0x00]));
    }

    #[test]
    fn test_c_prototype() {
        let sig = FunctionSignature::from_hex("printf", "55 48 89 E5")
            .unwrap()
            .with_param(Parameter::string("format"))
            .with_return_type(ParameterType::Int {
                size: 4,
                signed: true,
            })
            .variadic();

        assert_eq!(sig.to_c_prototype(), "int printf(const char* format, ...)");
    }

    #[test]
    fn test_c_prototype_void() {
        let sig = FunctionSignature::from_hex("abort", "55 48 89 E5")
            .unwrap()
            .with_return_type(ParameterType::Void);

        assert_eq!(sig.to_c_prototype(), "void abort(void)");
    }
}
