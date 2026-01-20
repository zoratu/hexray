//! Builtin signature databases.
//!
//! These are signatures for common library functions that ship with hexray.

pub mod libc_aarch64;
pub mod libc_x86_64;

use crate::SignatureDatabase;

/// Load all builtin signatures for x86_64.
pub fn load_x86_64() -> SignatureDatabase {
    let mut db = SignatureDatabase::with_metadata(
        "builtin-x86_64",
        "1.0",
        Some("Builtin signatures for x86_64".to_string()),
    )
    .with_architecture("x86_64");

    libc_x86_64::load_libc(&mut db);
    db
}

/// Load all builtin signatures for ARM64.
pub fn load_aarch64() -> SignatureDatabase {
    let mut db = SignatureDatabase::with_metadata(
        "builtin-aarch64",
        "1.0",
        Some("Builtin signatures for ARM64".to_string()),
    )
    .with_architecture("aarch64");

    libc_aarch64::load_libc(&mut db);
    db
}

/// Load builtin signatures for the given architecture.
pub fn load_for_architecture(arch: &str) -> SignatureDatabase {
    match arch.to_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => load_x86_64(),
        "aarch64" | "arm64" => load_aarch64(),
        _ => SignatureDatabase::new(),
    }
}
