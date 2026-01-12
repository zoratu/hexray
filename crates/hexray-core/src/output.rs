//! Output format utilities for hexray.
//!
//! This module provides utilities for exporting disassembly data to various
//! output formats:
//! - DOT (Graphviz) format for CFG and call graph visualization
//! - JSON format for tooling integration (planned)
//! - HTML format for interactive viewing (planned)

pub mod dot;

pub use dot::{escape_dot_string, DotConfig};
