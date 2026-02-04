//! DOT format exporters for analysis results.
//!
//! Provides exporters for visualizing CFGs and call graphs in Graphviz DOT format.

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use hexray_core::output::dot::{escape_dot_string, format_edge, DotConfig};
use hexray_core::ControlFlowGraph;

use crate::CallGraph;

/// Exporter for rendering control flow graphs in DOT format.
pub struct CfgDotExporter {
    config: DotConfig,
}

impl Default for CfgDotExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgDotExporter {
    /// Create a new CFG DOT exporter with default configuration.
    pub fn new() -> Self {
        Self {
            config: DotConfig::cfg(),
        }
    }

    /// Create a CFG DOT exporter with custom configuration.
    pub fn with_config(config: DotConfig) -> Self {
        Self { config }
    }

    /// Export the CFG to DOT format, writing to the provided writer.
    pub fn export<W: Write>(
        &self,
        cfg: &ControlFlowGraph,
        name: &str,
        mut writer: W,
    ) -> io::Result<()> {
        // Write header
        write!(writer, "{}", self.config.header(name))?;
        writeln!(writer)?;

        // Create nodes for each basic block
        for block_id in cfg.reverse_post_order() {
            if let Some(block) = cfg.block(block_id) {
                // Build label with block info and instructions
                let mut label = String::new();
                write!(
                    label,
                    "{}:\\l[{:#x} - {:#x})\\l\\l",
                    block_id, block.start, block.end
                )
                .unwrap();

                for inst in &block.instructions {
                    let inst_str = escape_dot_string(&format!("{}", inst));
                    label.push_str(&inst_str);
                    label.push_str("\\l");
                }

                writeln!(writer, "    \"{}\" [label=\"{}\"];", block_id, label)?;
            }
        }

        writeln!(writer)?;

        // Create edges for control flow
        for block_id in cfg.reverse_post_order() {
            for succ in cfg.successors(block_id) {
                write!(
                    writer,
                    "{}",
                    format_edge(&block_id.to_string(), &succ.to_string())
                )?;
            }
        }

        write!(writer, "{}", self.config.footer())?;
        Ok(())
    }

    /// Export the CFG to DOT format, returning it as a String.
    pub fn export_to_string(&self, cfg: &ControlFlowGraph, name: &str) -> String {
        let mut buf = Vec::new();
        self.export(cfg, name, &mut buf)
            .expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("DOT output should be valid UTF-8")
    }

    /// Export the CFG to DOT format, writing to stdout.
    pub fn export_to_stdout(&self, cfg: &ControlFlowGraph, name: &str) -> io::Result<()> {
        self.export(cfg, name, io::stdout())
    }
}

/// Exporter for rendering call graphs in DOT format.
pub struct CallGraphDotExporter {
    config: DotConfig,
}

impl Default for CallGraphDotExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraphDotExporter {
    /// Create a new call graph DOT exporter with default configuration.
    pub fn new() -> Self {
        Self {
            config: DotConfig::callgraph(),
        }
    }

    /// Create a call graph DOT exporter with custom configuration.
    pub fn with_config(config: DotConfig) -> Self {
        Self { config }
    }

    /// Get the display name for a call graph node.
    fn node_display_name(node: &crate::CallGraphNode) -> String {
        node.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", node.address))
    }

    /// Export the call graph to DOT format, writing to the provided writer.
    pub fn export<W: Write>(&self, callgraph: &CallGraph, mut writer: W) -> io::Result<()> {
        // Write header
        write!(writer, "{}", self.config.header("callgraph"))?;
        writeln!(writer)?;

        // Add nodes
        for node in callgraph.nodes() {
            let name = Self::node_display_name(node);
            let escaped_name = escape_dot_string(&name);
            writeln!(
                writer,
                "    \"{}\" [label=\"{}\"];",
                escaped_name, escaped_name
            )?;
        }

        writeln!(writer)?;

        // Add edges
        for node in callgraph.nodes() {
            let caller_name = Self::node_display_name(node);
            let caller_escaped = escape_dot_string(&caller_name);

            for (callee_addr, _call_site) in callgraph.callees(node.address) {
                if let Some(callee) = callgraph.get_node(callee_addr) {
                    let callee_name = Self::node_display_name(callee);
                    let callee_escaped = escape_dot_string(&callee_name);
                    write!(writer, "{}", format_edge(&caller_escaped, &callee_escaped))?;
                }
            }
        }

        write!(writer, "{}", self.config.footer())?;
        Ok(())
    }

    /// Export the call graph to DOT format, returning it as a String.
    pub fn export_to_string(&self, callgraph: &CallGraph) -> String {
        let mut buf = Vec::new();
        self.export(callgraph, &mut buf)
            .expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("DOT output should be valid UTF-8")
    }

    /// Export the call graph to DOT format, writing to stdout.
    pub fn export_to_stdout(&self, callgraph: &CallGraph) -> io::Result<()> {
        self.export(callgraph, io::stdout())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, Instruction};

    fn make_test_cfg() -> ControlFlowGraph {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::ENTRY);

        // Add entry block
        let entry = BasicBlock {
            id: BasicBlockId::ENTRY,
            start: 0x1000,
            end: 0x1010,
            instructions: vec![Instruction::new(0x1000, 4, vec![], "mov")],
            terminator: BlockTerminator::Fallthrough {
                target: BasicBlockId(1),
            },
        };
        cfg.add_block(entry);

        // Add a successor block
        let block1 = BasicBlock {
            id: BasicBlockId(1),
            start: 0x1010,
            end: 0x1020,
            instructions: vec![],
            terminator: BlockTerminator::Return,
        };
        cfg.add_block(block1);

        cfg.add_edge(BasicBlockId::ENTRY, BasicBlockId(1));

        cfg
    }

    #[test]
    fn test_cfg_exporter() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "test_func");

        assert!(dot.contains("digraph \"test_func\""));
        assert!(dot.contains("rankdir=TB"));
        assert!(dot.contains("shape=box"));
        assert!(dot.contains("bb0"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_callgraph_exporter() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("main".to_string()), false);
        callgraph.add_node(0x2000, Some("helper".to_string()), false);
        callgraph.add_call(
            0x1000,
            0x2000,
            crate::CallSite {
                call_address: 0x1008,
                call_type: crate::CallType::Direct,
            },
        );

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("digraph \"callgraph\""));
        assert!(dot.contains("rankdir=LR"));
        assert!(dot.contains("main"));
        assert!(dot.contains("helper"));
        assert!(dot.contains("->"));
    }

    // --- CfgDotExporter Tests ---

    #[test]
    fn test_cfg_dot_exporter_default() {
        let exporter = CfgDotExporter::default();
        let cfg = make_test_cfg();
        let dot = exporter.export_to_string(&cfg, "test");
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn test_cfg_dot_exporter_with_config() {
        let config = DotConfig {
            font_name: "Arial".to_string(),
            node_font_size: 12,
            edge_font_size: 10,
            rankdir: "LR".to_string(),
            node_shape: "ellipse".to_string(),
        };
        let exporter = CfgDotExporter::with_config(config);
        let cfg = make_test_cfg();
        let dot = exporter.export_to_string(&cfg, "test");

        assert!(dot.contains("rankdir=LR"));
        assert!(dot.contains("shape=ellipse"));
        assert!(dot.contains("fontname=\"Arial\""));
    }

    #[test]
    fn test_cfg_dot_exporter_contains_addresses() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "test");

        assert!(dot.contains("0x1000"));
        assert!(dot.contains("0x1010"));
    }

    #[test]
    fn test_cfg_dot_exporter_contains_instructions() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "test");

        assert!(dot.contains("mov"));
    }

    #[test]
    fn test_cfg_dot_exporter_contains_edges() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "test");

        assert!(dot.contains("bb0"));
        assert!(dot.contains("bb1"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_cfg_dot_exporter_escapes_name() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "func<test>");

        assert!(dot.contains("digraph \"func\\<test\\>\""));
    }

    #[test]
    fn test_cfg_dot_exporter_export_to_writer() {
        let cfg = make_test_cfg();
        let exporter = CfgDotExporter::new();
        let mut buf = Vec::new();
        exporter.export(&cfg, "test", &mut buf).unwrap();

        let dot = String::from_utf8(buf).unwrap();
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn test_cfg_dot_exporter_empty_cfg() {
        let cfg = ControlFlowGraph::new(BasicBlockId::ENTRY);
        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "empty");

        assert!(dot.contains("digraph \"empty\""));
        assert!(dot.contains("}"));
    }

    // --- CallGraphDotExporter Tests ---

    #[test]
    fn test_callgraph_dot_exporter_default() {
        let exporter = CallGraphDotExporter::default();
        let callgraph = CallGraph::new();
        let dot = exporter.export_to_string(&callgraph);
        assert!(dot.contains("digraph"));
    }

    #[test]
    fn test_callgraph_dot_exporter_with_config() {
        let config = DotConfig {
            font_name: "Arial".to_string(),
            node_font_size: 14,
            edge_font_size: 12,
            rankdir: "TB".to_string(),
            node_shape: "circle".to_string(),
        };
        let exporter = CallGraphDotExporter::with_config(config);
        let callgraph = CallGraph::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("rankdir=TB"));
        assert!(dot.contains("shape=circle"));
    }

    #[test]
    fn test_callgraph_dot_exporter_empty() {
        let callgraph = CallGraph::new();
        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("digraph \"callgraph\""));
        assert!(dot.contains("}"));
    }

    #[test]
    fn test_callgraph_dot_exporter_single_node() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("main".to_string()), false);

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("main"));
        assert!(!dot.contains("->")); // No edges
    }

    #[test]
    fn test_callgraph_dot_exporter_no_name() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, None, false);

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("sub_1000"));
    }

    #[test]
    fn test_callgraph_dot_exporter_external_node() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("main".to_string()), false);
        callgraph.add_node(0x2000, Some("printf".to_string()), true);
        callgraph.add_call(
            0x1000,
            0x2000,
            crate::CallSite {
                call_address: 0x1008,
                call_type: crate::CallType::Direct,
            },
        );

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("main"));
        assert!(dot.contains("printf"));
        assert!(dot.contains("->"));
    }

    #[test]
    fn test_callgraph_dot_exporter_multiple_callees() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("main".to_string()), false);
        callgraph.add_node(0x2000, Some("foo".to_string()), false);
        callgraph.add_node(0x3000, Some("bar".to_string()), false);
        callgraph.add_call(
            0x1000,
            0x2000,
            crate::CallSite {
                call_address: 0x1008,
                call_type: crate::CallType::Direct,
            },
        );
        callgraph.add_call(
            0x1000,
            0x3000,
            crate::CallSite {
                call_address: 0x1010,
                call_type: crate::CallType::Direct,
            },
        );

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        assert!(dot.contains("main"));
        assert!(dot.contains("foo"));
        assert!(dot.contains("bar"));
        // Should have two edges
        let edge_count = dot.matches("->").count();
        assert_eq!(edge_count, 2);
    }

    #[test]
    fn test_callgraph_dot_exporter_export_to_writer() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("main".to_string()), false);

        let exporter = CallGraphDotExporter::new();
        let mut buf = Vec::new();
        exporter.export(&callgraph, &mut buf).unwrap();

        let dot = String::from_utf8(buf).unwrap();
        assert!(dot.contains("digraph"));
        assert!(dot.contains("main"));
    }

    #[test]
    fn test_callgraph_dot_exporter_special_chars_in_name() {
        let mut callgraph = CallGraph::new();
        callgraph.add_node(0x1000, Some("operator<".to_string()), false);

        let exporter = CallGraphDotExporter::new();
        let dot = exporter.export_to_string(&callgraph);

        // Name should be escaped
        assert!(dot.contains("operator\\<"));
    }

    // --- CFG with Multiple Blocks and Branches ---

    #[test]
    fn test_cfg_dot_exporter_branching() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::ENTRY);

        // Entry block with conditional branch
        let entry = BasicBlock {
            id: BasicBlockId::ENTRY,
            start: 0x1000,
            end: 0x1010,
            instructions: vec![Instruction::new(0x1000, 2, vec![], "cmp")],
            terminator: BlockTerminator::ConditionalBranch {
                condition: hexray_core::Condition::Equal,
                true_target: BasicBlockId(1),
                false_target: BasicBlockId(2),
            },
        };
        cfg.add_block(entry);

        // True branch
        let block1 = BasicBlock {
            id: BasicBlockId(1),
            start: 0x1010,
            end: 0x1020,
            instructions: vec![],
            terminator: BlockTerminator::Return,
        };
        cfg.add_block(block1);

        // False branch
        let block2 = BasicBlock {
            id: BasicBlockId(2),
            start: 0x1020,
            end: 0x1030,
            instructions: vec![],
            terminator: BlockTerminator::Return,
        };
        cfg.add_block(block2);

        cfg.add_edge(BasicBlockId::ENTRY, BasicBlockId(1));
        cfg.add_edge(BasicBlockId::ENTRY, BasicBlockId(2));

        let exporter = CfgDotExporter::new();
        let dot = exporter.export_to_string(&cfg, "branching");

        assert!(dot.contains("bb0"));
        assert!(dot.contains("bb1"));
        assert!(dot.contains("bb2"));
        // Should have two edges from entry
        let edge_count = dot.matches("->").count();
        assert_eq!(edge_count, 2);
    }
}
