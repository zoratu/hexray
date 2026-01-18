//! # hexray-signatures
//!
//! Function signature recognition for identifying library functions without symbols.
//!
//! This crate provides FLIRT-like functionality for recognizing common library
//! functions based on their byte patterns. This is useful for:
//! - Identifying stripped binaries
//! - Recognizing statically linked library functions
//! - Improving decompiler output with proper function names
//!
//! # Example
//!
//! ```ignore
//! use hexray_signatures::{SignatureDatabase, SignatureMatcher};
//!
//! // Load builtin signatures
//! let db = SignatureDatabase::builtin_libc();
//!
//! // Match against function bytes
//! let matcher = SignatureMatcher::new(&db);
//! if let Some(sig) = matcher.match_bytes(&function_bytes) {
//!     println!("Identified: {}", sig.name);
//! }
//! ```

mod pattern;
mod signature;
mod database;
mod matcher;
pub mod builtin;

pub use pattern::{BytePattern, PatternByte};
pub use signature::{FunctionSignature, CallingConvention, Parameter, ParameterType};
pub use database::SignatureDatabase;
pub use matcher::{SignatureMatcher, MatchResult};

/// Error type for signature operations.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, SignatureError>;
