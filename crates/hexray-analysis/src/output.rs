//! Output utilities for analysis results.
//!
//! This module provides exporters for visualizing CFGs, call graphs,
//! and other analysis results in various formats.
//!
//! ## Supported Formats
//!
//! - **DOT**: Graphviz format for visualization
//! - **JSON**: Structured data format for tooling integration
//! - **HTML**: Interactive web-based viewer

pub mod dot;
pub mod html;
pub mod json;

pub use dot::{CallGraphDotExporter, CfgDotExporter};
pub use html::{CallGraphHtmlExporter, CfgHtmlExporter};
pub use json::{CallGraphJsonExporter, CfgJsonExporter};
