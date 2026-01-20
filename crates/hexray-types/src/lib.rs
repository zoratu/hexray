//! # hexray-types
//!
//! C type library and header parsing for hexray disassembler.
//!
//! This crate provides:
//! - C type representation (structs, unions, enums, typedefs, functions)
//! - Simplified C header parser
//! - Builtin type databases for common platforms (POSIX, Linux, macOS)
//! - Type database for looking up types by name or offset
//!
//! # Example
//!
//! ```ignore
//! use hexray_types::{TypeDatabase, CType, StructType};
//!
//! let mut db = TypeDatabase::new();
//!
//! // Load builtin POSIX types
//! db.load_builtin_posix();
//!
//! // Look up a type
//! if let Some(ty) = db.get_type("struct stat") {
//!     println!("struct stat: {:?}", ty);
//! }
//!
//! // Get field at offset
//! if let Some(field) = db.field_at_offset("struct stat", 0) {
//!     println!("Field at offset 0: {}", field.name);
//! }
//! ```

pub mod builtin;
pub mod database;
pub mod parser;
pub mod types;

pub use database::TypeDatabase;
pub use parser::{ParseError, ParseResult, Parser};
pub use types::*;
