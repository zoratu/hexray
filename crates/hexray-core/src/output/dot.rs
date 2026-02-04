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

    // --- escape_dot_string Tests ---

    #[test]
    fn test_escape_dot_string() {
        assert_eq!(escape_dot_string("hello"), "hello");
        assert_eq!(escape_dot_string("a\\b"), "a\\\\b");
        assert_eq!(escape_dot_string("a\"b"), "a\\\"b");
        assert_eq!(escape_dot_string("a<b>c"), "a\\<b\\>c");
        assert_eq!(escape_dot_string("\\\"<>"), "\\\\\\\"\\<\\>");
    }

    #[test]
    fn test_escape_dot_string_empty() {
        assert_eq!(escape_dot_string(""), "");
    }

    #[test]
    fn test_escape_dot_string_no_special() {
        assert_eq!(escape_dot_string("mov rax, rbx"), "mov rax, rbx");
        assert_eq!(escape_dot_string("0x1234"), "0x1234");
    }

    #[test]
    fn test_escape_dot_string_multiple_escapes() {
        assert_eq!(escape_dot_string("a\\b\\c"), "a\\\\b\\\\c");
        assert_eq!(escape_dot_string("\"\"\""), "\\\"\\\"\\\"");
    }

    #[test]
    fn test_escape_dot_string_mixed() {
        assert_eq!(escape_dot_string("call <func@plt>"), "call \\<func@plt\\>");
        assert_eq!(
            escape_dot_string("mov rax, \"string\""),
            "mov rax, \\\"string\\\""
        );
    }

    #[test]
    fn test_escape_dot_string_newlines_preserved() {
        // Newlines are not escaped by DOT escaping
        assert_eq!(escape_dot_string("line1\nline2"), "line1\nline2");
    }

    // --- DotConfig Tests ---

    #[test]
    fn test_dot_config_default() {
        let cfg = DotConfig::default();
        assert_eq!(cfg.font_name, "Courier");
        assert_eq!(cfg.node_font_size, 10);
        assert_eq!(cfg.edge_font_size, 9);
        assert_eq!(cfg.rankdir, "TB");
        assert_eq!(cfg.node_shape, "box");
    }

    #[test]
    fn test_dot_config_cfg() {
        let cfg = DotConfig::cfg();
        assert_eq!(cfg.rankdir, "TB");
        assert_eq!(cfg.node_shape, "box");
    }

    #[test]
    fn test_dot_config_callgraph() {
        let cfg = DotConfig::callgraph();
        assert_eq!(cfg.rankdir, "LR");
        assert_eq!(cfg.node_shape, "box");
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
    fn test_dot_config_header_escapes_name() {
        let cfg = DotConfig::cfg();
        let header = cfg.header("func<test>");
        assert!(header.contains("digraph \"func\\<test\\>\""));
    }

    #[test]
    fn test_dot_config_header_contains_font() {
        let cfg = DotConfig::default();
        let header = cfg.header("test");
        assert!(header.contains("fontname=\"Courier\""));
        assert!(header.contains("fontsize=10"));
        assert!(header.contains("fontsize=9"));
    }

    #[test]
    fn test_dot_config_footer() {
        let cfg = DotConfig::default();
        assert_eq!(cfg.footer(), "}\n");
    }

    #[test]
    fn test_dot_config_clone() {
        let cfg1 = DotConfig::cfg();
        let cfg2 = cfg1.clone();
        assert_eq!(cfg1.rankdir, cfg2.rankdir);
        assert_eq!(cfg1.node_shape, cfg2.node_shape);
    }

    #[test]
    fn test_dot_config_debug() {
        let cfg = DotConfig::default();
        let debug = format!("{:?}", cfg);
        assert!(debug.contains("DotConfig"));
        assert!(debug.contains("Courier"));
    }

    // --- format_node Tests ---

    #[test]
    fn test_format_node() {
        let node = format_node("block0", "entry:\\l");
        assert_eq!(node, "    \"block0\" [label=\"entry:\\l\"];\n");
    }

    #[test]
    fn test_format_node_escapes_id() {
        let node = format_node("block<0>", "label");
        assert!(node.contains("\"block\\<0\\>\""));
    }

    #[test]
    fn test_format_node_empty_label() {
        let node = format_node("id", "");
        assert_eq!(node, "    \"id\" [label=\"\"];\n");
    }

    #[test]
    fn test_format_node_multiline_label() {
        let node = format_node("block", "line1\\lline2\\l");
        assert!(node.contains("line1\\lline2\\l"));
    }

    // --- format_edge Tests ---

    #[test]
    fn test_format_edge() {
        let edge = format_edge("block0", "block1");
        assert_eq!(edge, "    \"block0\" -> \"block1\";\n");
    }

    #[test]
    fn test_format_edge_escapes_ids() {
        let edge = format_edge("from<>", "to\"");
        assert!(edge.contains("\"from\\<\\>\""));
        assert!(edge.contains("\"to\\\"\""));
    }

    #[test]
    fn test_format_edge_same_node() {
        let edge = format_edge("block", "block");
        assert_eq!(edge, "    \"block\" -> \"block\";\n");
    }

    // --- format_edge_labeled Tests ---

    #[test]
    fn test_format_edge_labeled() {
        let edge = format_edge_labeled("from", "to", "true");
        assert_eq!(edge, "    \"from\" -> \"to\" [label=\"true\"];\n");
    }

    #[test]
    fn test_format_edge_labeled_escapes_label() {
        let edge = format_edge_labeled("from", "to", "label<with>special");
        assert!(edge.contains("[label=\"label\\<with\\>special\"]"));
    }

    #[test]
    fn test_format_edge_labeled_empty_label() {
        let edge = format_edge_labeled("from", "to", "");
        assert!(edge.contains("[label=\"\"]"));
    }

    // --- Integration Tests ---

    #[test]
    fn test_complete_dot_graph() {
        let cfg = DotConfig::cfg();
        let mut output = String::new();

        output.push_str(&cfg.header("test"));
        output.push_str(&format_node("entry", "Entry Block\\l"));
        output.push_str(&format_node("exit", "Exit Block\\l"));
        output.push_str(&format_edge("entry", "exit"));
        output.push_str(cfg.footer());

        assert!(output.contains("digraph \"test\""));
        assert!(output.contains("\"entry\""));
        assert!(output.contains("\"exit\""));
        assert!(output.contains("->"));
        assert!(output.ends_with("}\n"));
    }

    #[test]
    fn test_dot_graph_with_special_chars() {
        let cfg = DotConfig::cfg();
        let mut output = String::new();

        output.push_str(&cfg.header("func<main>"));
        output.push_str(&format_node("bb0", "mov rax, \"str\"\\l"));
        output.push_str(&format_edge_labeled("bb0", "bb1", "fallthrough"));
        output.push_str(cfg.footer());

        // Verify it's valid-looking DOT
        assert!(output.contains("digraph"));
        assert!(output.contains("->"));
        assert!(output.contains("}"));
    }
}
