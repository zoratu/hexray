//! DOT (Graphviz) output utilities.
//!
//! Provides shared utilities for generating Graphviz DOT format output,
//! used for visualizing control flow graphs and call graphs.

/// Escape special characters for DOT format strings.
///
/// DOT format requires escaping:
/// - `\` → `\\` (backslash)
/// - `"` → `\"` (double quote)
/// - `<` → `\<` (less than, for HTML-like labels)
/// - `>` → `\>` (greater than, for HTML-like labels)
///
/// # Example
/// ```
/// use hexray_core::output::escape_dot_string;
/// assert_eq!(escape_dot_string("mov rax, \"hello\""), "mov rax, \\\"hello\\\"");
/// assert_eq!(escape_dot_string("cmp <ptr>"), "cmp \\<ptr\\>");
/// ```
pub fn escape_dot_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\<")
        .replace('>', "\\>")
}

/// Configuration for DOT output generation.
#[derive(Debug, Clone)]
pub struct DotConfig {
    /// Font name for nodes and edges.
    pub font_name: String,
    /// Font size for node labels.
    pub node_font_size: u32,
    /// Font size for edge labels.
    pub edge_font_size: u32,
    /// Graph direction: "TB" (top-bottom), "LR" (left-right), etc.
    pub rankdir: String,
    /// Node shape: "box", "ellipse", etc.
    pub node_shape: String,
}

impl Default for DotConfig {
    fn default() -> Self {
        Self {
            font_name: "Courier".to_string(),
            node_font_size: 10,
            edge_font_size: 9,
            rankdir: "TB".to_string(),
            node_shape: "box".to_string(),
        }
    }
}

impl DotConfig {
    /// Create a config suited for CFG visualization.
    pub fn cfg() -> Self {
        Self::default()
    }

    /// Create a config suited for call graph visualization.
    pub fn callgraph() -> Self {
        Self {
            rankdir: "LR".to_string(),
            ..Self::default()
        }
    }

    /// Generate the DOT header (digraph declaration and attributes).
    pub fn header(&self, name: &str) -> String {
        let escaped_name = escape_dot_string(name);
        format!(
            "digraph \"{}\" {{\n    rankdir={};\n    node [shape={}, fontname=\"{}\", fontsize={}];\n    edge [fontname=\"{}\", fontsize={}];\n",
            escaped_name,
            self.rankdir,
            self.node_shape,
            self.font_name,
            self.node_font_size,
            self.font_name,
            self.edge_font_size
        )
    }

    /// Generate the DOT footer.
    pub fn footer(&self) -> &'static str {
        "}\n"
    }
}

/// Format a DOT node with the given ID and label.
pub fn format_node(id: &str, label: &str) -> String {
    format!("    \"{}\" [label=\"{}\"];\n", escape_dot_string(id), label)
}

/// Format a DOT edge between two nodes.
pub fn format_edge(from: &str, to: &str) -> String {
    format!(
        "    \"{}\" -> \"{}\";\n",
        escape_dot_string(from),
        escape_dot_string(to)
    )
}

/// Format a DOT edge with a label.
pub fn format_edge_labeled(from: &str, to: &str, label: &str) -> String {
    format!(
        "    \"{}\" -> \"{}\" [label=\"{}\"];\n",
        escape_dot_string(from),
        escape_dot_string(to),
        escape_dot_string(label)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_dot_string() {
        assert_eq!(escape_dot_string("hello"), "hello");
        assert_eq!(escape_dot_string("a\\b"), "a\\\\b");
        assert_eq!(escape_dot_string("a\"b"), "a\\\"b");
        assert_eq!(escape_dot_string("a<b>c"), "a\\<b\\>c");
        assert_eq!(escape_dot_string("\\\"<>"), "\\\\\\\"\\<\\>");
    }

    #[test]
    fn test_dot_config_header() {
        let cfg = DotConfig::cfg();
        let header = cfg.header("test_func");
        assert!(header.contains("digraph \"test_func\""));
        assert!(header.contains("rankdir=TB"));
        assert!(header.contains("shape=box"));
    }

    #[test]
    fn test_format_node() {
        let node = format_node("block0", "entry:\\l");
        assert_eq!(node, "    \"block0\" [label=\"entry:\\l\"];\n");
    }

    #[test]
    fn test_format_edge() {
        let edge = format_edge("block0", "block1");
        assert_eq!(edge, "    \"block0\" -> \"block1\";\n");
    }
}
