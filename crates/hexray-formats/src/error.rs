//! Error types for binary format parsing.

use thiserror::Error;

/// Error type for binary format parsing.
#[derive(Error, Debug)]
pub enum ParseError {
    /// Invalid magic number at start of file.
    #[error("invalid magic number: expected {expected}, got {actual:02x?}")]
    InvalidMagic {
        expected: &'static str,
        actual: Vec<u8>,
    },

    /// File is too short to contain required data.
    #[error("file too short: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },

    /// Truncated data while parsing.
    #[error("truncated data: expected {expected} bytes, got {actual} while parsing {context}")]
    TruncatedData {
        expected: usize,
        actual: usize,
        context: &'static str,
    },

    /// Invalid value encountered during parsing.
    #[error("invalid value: {0}")]
    InvalidValue(&'static str),

    /// Unsupported format version.
    #[error("unsupported {format} version: {version}")]
    UnsupportedVersion { format: &'static str, version: u32 },

    /// Unsupported architecture.
    #[error("unsupported architecture: {0}")]
    UnsupportedArchitecture(u16),

    /// Invalid section or segment.
    #[error("invalid {kind} at offset {offset:#x}: {reason}")]
    InvalidStructure {
        kind: &'static str,
        offset: u64,
        reason: String,
    },

    /// Invalid string table index.
    #[error("invalid string table index: {index} (table size: {size})")]
    InvalidStringIndex { index: usize, size: usize },

    /// Invalid symbol index.
    #[error("invalid symbol index: {0}")]
    InvalidSymbolIndex(u32),

    /// Integer overflow during parsing.
    #[error("integer overflow while parsing {context}")]
    Overflow { context: &'static str },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl ParseError {
    /// Creates a new InvalidMagic error.
    pub fn invalid_magic(expected: &'static str, actual: &[u8]) -> Self {
        Self::InvalidMagic {
            expected,
            actual: actual.to_vec(),
        }
    }

    /// Creates a new TooShort error.
    pub fn too_short(expected: usize, actual: usize) -> Self {
        Self::TooShort { expected, actual }
    }

    /// Creates a new InvalidStructure error.
    pub fn invalid_structure(kind: &'static str, offset: u64, reason: impl Into<String>) -> Self {
        Self::InvalidStructure {
            kind,
            offset,
            reason: reason.into(),
        }
    }
}
