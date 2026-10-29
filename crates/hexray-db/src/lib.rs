//! Single-file persistent analysis project for hexray.
//!
//! A `.hxdb` file is a SQLite database holding:
//! - the complete immutable original input (chunked, with a real SHA-256),
//! - the address-space mapping of the analyzed image plus its layout
//!   fingerprint,
//! - the analysis results currently published (instructions, CFG, xrefs,
//!   strings, rendered pseudo-C),
//! - user edits (byte patches, items, functions, names, annotations, types,
//!   variable overrides) with a shared linear undo/redo history,
//! - the dependency and generation bookkeeping that decides what a user edit
//!   invalidates.
//!
//! The crate deliberately knows nothing about binary formats, decompilers or
//! the CLI: it stores and validates data, and the caller supplies analysis
//! payloads. That keeps the store readable without the parsers that wrote it
//! and keeps the foreign-key-heavy write paths testable in isolation.

#![forbid(unsafe_code)]

pub mod address;
pub mod edit;
pub mod legacy;
pub mod model;
pub mod schema;
pub mod store;

use sha2::{Digest, Sha256};

pub use address::{Address, AddressRange, FileOffset, FileRange, RangeError};
pub use edit::Edit;
pub use model::*;
pub use store::{Database, OpenMode, ReadSnapshot};

/// Errors surfaced by the store. Every variant maps to a stable CLI exit
/// class; the SQLite cause is kept but never printed as raw SQL.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("sqlite error: {0}")]
    Sqlite(rusqlite::Error),

    #[error("not an hexray analysis database")]
    NotADatabase,

    #[error("unsupported database schema version {0}")]
    UnsupportedSchema(String),

    #[error("database is corrupt: {0}")]
    Corrupt(String),

    #[error("database is busy: {0}")]
    Busy(String),

    #[error("database changed: expected revision {expected}, actual {actual}; refresh and retry")]
    RevisionConflict { expected: u64, actual: u64 },

    #[error("analysis conflict for {owner}: expected generation {expected}, actual {actual:?}")]
    AnalysisGenerationConflict {
        owner: String,
        expected: u64,
        actual: Option<u64>,
    },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("ambiguous: {0}")]
    Ambiguous(String),

    #[error("invalid edit: {0}")]
    Validation(String),

    #[error("invalid range: {0}")]
    Range(#[from] RangeError),

    #[error("unsupported operation: {0}")]
    Unsupported(String),

    #[error("resource limit: {0}")]
    ResourceLimit(String),

    #[error("nothing to undo")]
    NothingToUndo,

    #[error("nothing to redo")]
    NothingToRedo,

    #[error("identity mismatch: {0}")]
    IdentityMismatch(String),
}

impl DbError {
    /// CLI exit class for this error.
    ///
    /// 0 success, 1 operational/input/corruption error, 2 argument errors
    /// (handled by clap), 3 revision/generation conflicts, 4 resource or lock
    /// limits.
    pub fn exit_code(&self) -> i32 {
        match self {
            DbError::RevisionConflict { .. } | DbError::AnalysisGenerationConflict { .. } => 3,
            DbError::Busy(_) | DbError::ResourceLimit(_) => 4,
            _ => 1,
        }
    }

    /// Map a `rusqlite` error to the closest semantic variant.
    pub fn from_sqlite(error: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;
        match &error {
            rusqlite::Error::SqliteFailure(code, message) => match code.code {
                ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                    DbError::Busy(message.clone().unwrap_or_else(|| code.to_string()))
                }
                ErrorCode::NotADatabase => DbError::NotADatabase,
                ErrorCode::DatabaseCorrupt => DbError::Corrupt("checksum or page failure".into()),
                ErrorCode::DiskFull => DbError::ResourceLimit("disk full".into()),
                _ => DbError::Sqlite(error),
            },
            _ => DbError::Sqlite(error),
        }
    }
}

/// Result alias for the store.
pub type DbResult<T> = Result<T, DbError>;

impl From<rusqlite::Error> for DbError {
    fn from(error: rusqlite::Error) -> Self {
        DbError::from_sqlite(error)
    }
}

/// SHA-256 of a byte slice.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Lower-case hex rendering, the only textual form for digests.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Parse a 64-character hex digest. Odd length or non-hex input is an error,
/// never a panic.
pub fn hex_decode_32(value: &str) -> DbResult<[u8; 32]> {
    if value.len() != 64 {
        return Err(DbError::Validation(format!(
            "digest must be 64 hex characters, got {}",
            value.len()
        )));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|_| DbError::Validation("digest is not ASCII".into()))?;
        out[index] = u8::from_str_radix(text, 16)
            .map_err(|_| DbError::Validation(format!("invalid digest byte '{text}'")))?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_roundtrip() {
        let digest = sha256(b"hexray");
        let text = hex_encode(&digest);
        assert_eq!(hex_decode_32(&text).unwrap(), digest);
    }

    #[test]
    fn malformed_digests_are_errors() {
        assert!(hex_decode_32("").is_err());
        assert!(hex_decode_32("abc").is_err());
        assert!(hex_decode_32(&"z".repeat(64)).is_err());
        // Non-ASCII at the right length must not panic on a char boundary.
        assert!(hex_decode_32(&"é".repeat(32)).is_err());
    }
}
