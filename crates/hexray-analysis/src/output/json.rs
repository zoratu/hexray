//! JSON format exporters for analysis results.
//!
//! Provides exporters for serializing CFGs and call graphs to JSON format
//! for tooling integration and programmatic access.

use std::io::{self, Write};

use serde::Serialize;

use hexray_core::ControlFlowGraph;

use crate::CallGraph;

/// JSON representation of a basic block.
#[derive(Serialize)]
struct JsonBasicBlock {
    id: String,
    start: u64,
    end: u64,
    instructions: Vec<JsonInstruction>,
    successors: Vec<String>,
}

/// JSON representation of an instruction.
#[derive(Serialize)]
struct JsonInstruction {
    address: u64,
    size: usize,
    mnemonic: String,
    operands: String,
    bytes: String,
}

/// JSON representation of a CFG.
#[derive(Serialize)]
struct JsonCfg {
    name: String,
    entry: String,
    blocks: Vec<JsonBasicBlock>,
}

/// Exporter for rendering control flow graphs in JSON format.
pub struct CfgJsonExporter {
    /// Whether to pretty-print the JSON output.
    pretty: bool,
}

impl Default for CfgJsonExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgJsonExporter {
    /// Create a new CFG JSON exporter with compact output.
    pub fn new() -> Self {
        Self { pretty: false }
    }

    /// Create a CFG JSON exporter with pretty-printed output.
    pub fn pretty() -> Self {
        Self { pretty: true }
    }

    /// Export the CFG to JSON format, writing to the provided writer.
    pub fn export<W: Write>(&self, cfg: &ControlFlowGraph, name: &str, mut writer: W) -> io::Result<()> {
        let mut blocks = Vec::new();

        for block_id in cfg.reverse_post_order() {
            if let Some(block) = cfg.block(block_id) {
                let instructions: Vec<JsonInstruction> = block
                    .instructions
                    .iter()
                    .map(|inst| JsonInstruction {
                        address: inst.address,
                        size: inst.size,
                        mnemonic: inst.mnemonic.clone(),
                        operands: inst
                            .operands
                            .iter()
                            .map(|op| format!("{}", op))
                            .collect::<Vec<_>>()
                            .join(", "),
                        bytes: inst
                            .bytes
                            .iter()
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" "),
                    })
                    .collect();

                let successors: Vec<String> = cfg
                    .successors(block_id)
                    .iter()
                    .map(|s| s.to_string())
                    .collect();

                blocks.push(JsonBasicBlock {
                    id: block_id.to_string(),
                    start: block.start,
                    end: block.end,
                    instructions,
                    successors,
                });
            }
        }

        let json_cfg = JsonCfg {
            name: name.to_string(),
            entry: cfg.entry.to_string(),
            blocks,
        };

        if self.pretty {
            serde_json::to_writer_pretty(&mut writer, &json_cfg)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        } else {
            serde_json::to_writer(&mut writer, &json_cfg)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Export the CFG to JSON format, returning it as a String.
    pub fn export_to_string(&self, cfg: &ControlFlowGraph, name: &str) -> String {
        let mut buf = Vec::new();
        self.export(cfg, name, &mut buf).expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("JSON output should be valid UTF-8")
    }

    /// Export the CFG to JSON format, writing to stdout.
    pub fn export_to_stdout(&self, cfg: &ControlFlowGraph, name: &str) -> io::Result<()> {
        self.export(cfg, name, io::stdout())
    }
}

/// JSON representation of a call graph node.
#[derive(Serialize)]
struct JsonCallGraphNode {
    address: u64,
    name: String,
    is_external: bool,
    callees: Vec<JsonCallEdge>,
}

/// JSON representation of a call edge.
#[derive(Serialize)]
struct JsonCallEdge {
    address: u64,
    name: String,
    call_address: u64,
    call_type: String,
}

/// JSON representation of a call graph.
#[derive(Serialize)]
struct JsonCallGraph {
    node_count: usize,
    edge_count: usize,
    nodes: Vec<JsonCallGraphNode>,
}

/// Exporter for rendering call graphs in JSON format.
pub struct CallGraphJsonExporter {
    /// Whether to pretty-print the JSON output.
    pretty: bool,
}

impl Default for CallGraphJsonExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraphJsonExporter {
    /// Create a new call graph JSON exporter with compact output.
    pub fn new() -> Self {
        Self { pretty: false }
    }

    /// Create a call graph JSON exporter with pretty-printed output.
    pub fn pretty() -> Self {
        Self { pretty: true }
    }

    /// Get the display name for a call graph node.
    fn node_display_name(node: &crate::CallGraphNode) -> String {
        node.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", node.address))
    }

    /// Export the call graph to JSON format, writing to the provided writer.
    pub fn export<W: Write>(&self, callgraph: &CallGraph, mut writer: W) -> io::Result<()> {
        let mut nodes = Vec::new();

        for node in callgraph.nodes() {
            let callees: Vec<JsonCallEdge> = callgraph
                .callees(node.address)
                .filter_map(|(addr, site)| {
                    callgraph.get_node(addr).map(|callee| JsonCallEdge {
                        address: callee.address,
                        name: Self::node_display_name(callee),
                        call_address: site.call_address,
                        call_type: format!("{:?}", site.call_type),
                    })
                })
                .collect();

            nodes.push(JsonCallGraphNode {
                address: node.address,
                name: Self::node_display_name(node),
                is_external: node.is_external,
                callees,
            });
        }

        let json_callgraph = JsonCallGraph {
            node_count: callgraph.node_count(),
            edge_count: callgraph.edge_count(),
            nodes,
        };

        if self.pretty {
            serde_json::to_writer_pretty(&mut writer, &json_callgraph)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        } else {
            serde_json::to_writer(&mut writer, &json_callgraph)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Export the call graph to JSON format, returning it as a String.
    pub fn export_to_string(&self, callgraph: &CallGraph) -> String {
        let mut buf = Vec::new();
        self.export(callgraph, &mut buf).expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("JSON output should be valid UTF-8")
    }

    /// Export the call graph to JSON format, writing to stdout.
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

        let entry = BasicBlock {
            id: BasicBlockId::ENTRY,
            start: 0x1000,
            end: 0x1010,
            instructions: vec![Instruction::new(0x1000, 4, vec![0x90], "nop")],
            terminator: BlockTerminator::Fallthrough {
                target: BasicBlockId(1),
            },
        };
        cfg.add_block(entry);

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
    fn test_cfg_json_exporter() {
        let cfg = make_test_cfg();
        let exporter = CfgJsonExporter::new();
        let json = exporter.export_to_string(&cfg, "test_func");

        assert!(json.contains("\"name\":\"test_func\""));
        assert!(json.contains("\"entry\":\"bb0\""));
        assert!(json.contains("\"address\":4096"));
        assert!(json.contains("\"mnemonic\":\"nop\""));
    }

    #[test]
    fn test_cfg_json_exporter_pretty() {
        let cfg = make_test_cfg();
        let exporter = CfgJsonExporter::pretty();
        let json = exporter.export_to_string(&cfg, "test_func");

        // Pretty output has newlines
        assert!(json.contains('\n'));
        assert!(json.contains("\"name\": \"test_func\""));
    }

    #[test]
    fn test_callgraph_json_exporter() {
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

        let exporter = CallGraphJsonExporter::new();
        let json = exporter.export_to_string(&callgraph);

        assert!(json.contains("\"node_count\":2"));
        assert!(json.contains("\"edge_count\":1"));
        assert!(json.contains("\"name\":\"main\""));
        assert!(json.contains("\"name\":\"helper\""));
        assert!(json.contains("\"call_type\":\"Direct\""));
    }
}
