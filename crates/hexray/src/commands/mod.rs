//! Command handlers for hexray CLI.
//!
//! This module contains implementations of CLI command handlers,
//! organized by functionality. Each submodule handles one category
//! of commands.

pub mod emulate;
pub mod signatures;
pub mod trace;
pub mod types;

pub use emulate::handle_emulate_command;
pub use signatures::{handle_signatures_command, handle_signatures_command_no_binary};
pub use trace::handle_trace_command;
pub use types::handle_types_command;
