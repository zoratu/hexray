//! Builtin type definitions for common platforms.
//!
//! This module provides pre-defined types for:
//! - POSIX standard types (size_t, pid_t, etc.)
//! - Standard C library functions (printf, malloc, etc.)
//! - Linux-specific types
//! - macOS-specific types

pub mod libc;
pub mod linux;
pub mod macos;
pub mod posix;

pub use libc::load_libc_functions;
pub use linux::load_linux_types;
pub use macos::load_macos_types;
pub use posix::load_posix_types;
