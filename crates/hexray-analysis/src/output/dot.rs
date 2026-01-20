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
}
