//! HTML format exporters for analysis results.
//!
//! Provides exporters for generating interactive HTML views of CFGs and call graphs.
//! The generated HTML includes embedded JavaScript for interactivity (zoom, pan, search).

use std::fmt::Write as FmtWrite;
use std::io::{self, Write};

use hexray_core::ControlFlowGraph;

use crate::CallGraph;

/// HTML template for the CFG viewer.
const CFG_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CFG: {{NAME}}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            min-height: 100vh;
        }
        .header {
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 16px;
            font-weight: 500;
            color: #cccccc;
        }
        .header .info {
            font-size: 12px;
            color: #808080;
        }
        .controls {
            background: #2d2d2d;
            padding: 8px 20px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .controls input {
            background: #3c3c3c;
            border: 1px solid #4c4c4c;
            color: #d4d4d4;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            width: 200px;
        }
        .controls input:focus {
            outline: none;
            border-color: #007acc;
        }
        .controls button {
            background: #0e639c;
            border: none;
            color: white;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
        }
        .controls button:hover {
            background: #1177bb;
        }
        .container {
            display: flex;
            height: calc(100vh - 90px);
        }
        .sidebar {
            width: 250px;
            background: #252526;
            border-right: 1px solid #3c3c3c;
            overflow-y: auto;
            padding: 12px;
        }
        .sidebar h2 {
            font-size: 11px;
            text-transform: uppercase;
            color: #808080;
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }
        .block-list {
            list-style: none;
        }
        .block-list li {
            padding: 6px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-bottom: 2px;
        }
        .block-list li:hover {
            background: #2a2d2e;
        }
        .block-list li.active {
            background: #094771;
        }
        .block-list .addr {
            color: #808080;
            font-size: 10px;
        }
        .main {
            flex: 1;
            overflow: auto;
            padding: 20px;
        }
        .cfg-container {
            display: flex;
            flex-direction: column;
            gap: 20px;
        }
        .block {
            background: #252526;
            border: 1px solid #3c3c3c;
            border-radius: 6px;
            overflow: hidden;
        }
        .block.entry {
            border-color: #4ec9b0;
        }
        .block.exit {
            border-color: #ce9178;
        }
        .block-header {
            background: #2d2d2d;
            padding: 8px 12px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .block-header .name {
            color: #4ec9b0;
            font-weight: 500;
        }
        .block-header .range {
            color: #808080;
            font-size: 11px;
        }
        .instructions {
            padding: 8px 0;
        }
        .inst {
            padding: 2px 12px;
            display: flex;
            gap: 16px;
            font-size: 12px;
        }
        .inst:hover {
            background: #2a2d2e;
        }
        .inst .addr {
            color: #6a9955;
            min-width: 80px;
        }
        .inst .bytes {
            color: #808080;
            min-width: 100px;
            font-size: 11px;
        }
        .inst .mnemonic {
            color: #569cd6;
            min-width: 60px;
        }
        .inst .operands {
            color: #d4d4d4;
        }
        .successors {
            padding: 8px 12px;
            background: #2d2d2d;
            border-top: 1px solid #3c3c3c;
            font-size: 11px;
            color: #808080;
        }
        .successors a {
            color: #4ec9b0;
            text-decoration: none;
            margin-right: 8px;
        }
        .successors a:hover {
            text-decoration: underline;
        }
        .highlight {
            background: #613214 !important;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{NAME}}</h1>
        <div class="info">{{BLOCK_COUNT}} blocks | Entry: {{ENTRY}}</div>
    </div>
    <div class="controls">
        <input type="text" id="search" placeholder="Search instructions...">
        <button onclick="clearHighlight()">Clear</button>
    </div>
    <div class="container">
        <div class="sidebar">
            <h2>Basic Blocks</h2>
            <ul class="block-list" id="blockList">
{{BLOCK_LIST}}
            </ul>
        </div>
        <div class="main">
            <div class="cfg-container" id="cfgContainer">
{{BLOCKS}}
            </div>
        </div>
    </div>
    <script>
        document.getElementById('search').addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            document.querySelectorAll('.inst').forEach(inst => {
                inst.classList.remove('highlight');
                if (query && inst.textContent.toLowerCase().includes(query)) {
                    inst.classList.add('highlight');
                }
            });
        });

        function clearHighlight() {
            document.getElementById('search').value = '';
            document.querySelectorAll('.inst').forEach(inst => {
                inst.classList.remove('highlight');
            });
        }

        function scrollToBlock(id) {
            const block = document.getElementById(id);
            if (block) {
                block.scrollIntoView({ behavior: 'smooth', block: 'start' });
                document.querySelectorAll('.block-list li').forEach(li => li.classList.remove('active'));
                document.querySelector(`[data-block="${id}"]`).classList.add('active');
            }
        }
    </script>
</body>
</html>
"#;

/// HTML template for call graph viewer.
const CALLGRAPH_HTML_TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Call Graph</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
            min-height: 100vh;
        }
        .header {
            background: #252526;
            padding: 12px 20px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            font-size: 16px;
            font-weight: 500;
            color: #cccccc;
        }
        .header .info {
            font-size: 12px;
            color: #808080;
        }
        .controls {
            background: #2d2d2d;
            padding: 8px 20px;
            border-bottom: 1px solid #3c3c3c;
            display: flex;
            gap: 12px;
            align-items: center;
        }
        .controls input {
            background: #3c3c3c;
            border: 1px solid #4c4c4c;
            color: #d4d4d4;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            width: 300px;
        }
        .controls input:focus {
            outline: none;
            border-color: #007acc;
        }
        .container {
            display: flex;
            height: calc(100vh - 90px);
        }
        .sidebar {
            width: 300px;
            background: #252526;
            border-right: 1px solid #3c3c3c;
            overflow-y: auto;
            padding: 12px;
        }
        .sidebar h2 {
            font-size: 11px;
            text-transform: uppercase;
            color: #808080;
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }
        .func-list {
            list-style: none;
        }
        .func-list li {
            padding: 6px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 12px;
            margin-bottom: 2px;
        }
        .func-list li:hover {
            background: #2a2d2e;
        }
        .func-list li.active {
            background: #094771;
        }
        .func-list li.hidden {
            display: none;
        }
        .func-list .addr {
            color: #808080;
            font-size: 10px;
        }
        .func-list .external {
            color: #ce9178;
        }
        .main {
            flex: 1;
            overflow: auto;
            padding: 20px;
        }
        .func-detail {
            display: none;
        }
        .func-detail.active {
            display: block;
        }
        .func-card {
            background: #252526;
            border: 1px solid #3c3c3c;
            border-radius: 6px;
            overflow: hidden;
            margin-bottom: 20px;
        }
        .func-card-header {
            background: #2d2d2d;
            padding: 12px 16px;
            border-bottom: 1px solid #3c3c3c;
        }
        .func-card-header h3 {
            color: #4ec9b0;
            font-size: 14px;
            font-weight: 500;
        }
        .func-card-header .meta {
            color: #808080;
            font-size: 11px;
            margin-top: 4px;
        }
        .func-card-body {
            padding: 12px 16px;
        }
        .call-section {
            margin-bottom: 16px;
        }
        .call-section:last-child {
            margin-bottom: 0;
        }
        .call-section h4 {
            font-size: 11px;
            text-transform: uppercase;
            color: #808080;
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }
        .call-list {
            list-style: none;
        }
        .call-list li {
            padding: 4px 0;
            font-size: 12px;
        }
        .call-list a {
            color: #569cd6;
            text-decoration: none;
        }
        .call-list a:hover {
            text-decoration: underline;
        }
        .call-list .call-addr {
            color: #6a9955;
            margin-left: 8px;
            font-size: 10px;
        }
        .empty {
            color: #808080;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Call Graph</h1>
        <div class="info">{{NODE_COUNT}} functions | {{EDGE_COUNT}} calls</div>
    </div>
    <div class="controls">
        <input type="text" id="search" placeholder="Search functions...">
    </div>
    <div class="container">
        <div class="sidebar">
            <h2>Functions</h2>
            <ul class="func-list" id="funcList">
{{FUNC_LIST}}
            </ul>
        </div>
        <div class="main" id="mainContent">
            <p style="color: #808080; text-align: center; margin-top: 100px;">
                Select a function from the sidebar to view its call relationships.
            </p>
{{FUNC_DETAILS}}
        </div>
    </div>
    <script>
        document.getElementById('search').addEventListener('input', function(e) {
            const query = e.target.value.toLowerCase();
            document.querySelectorAll('.func-list li').forEach(li => {
                const name = li.textContent.toLowerCase();
                li.classList.toggle('hidden', query && !name.includes(query));
            });
        });

        function showFunc(addr) {
            document.querySelectorAll('.func-detail').forEach(d => d.classList.remove('active'));
            document.querySelectorAll('.func-list li').forEach(li => li.classList.remove('active'));

            const detail = document.getElementById('func-' + addr);
            const listItem = document.querySelector(`[data-addr="${addr}"]`);

            if (detail) detail.classList.add('active');
            if (listItem) listItem.classList.add('active');
        }
    </script>
</body>
</html>
"#;

/// Exporter for rendering control flow graphs in HTML format.
pub struct CfgHtmlExporter;

impl Default for CfgHtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CfgHtmlExporter {
    /// Create a new CFG HTML exporter.
    pub fn new() -> Self {
        Self
    }

    /// Export the CFG to HTML format, writing to the provided writer.
    pub fn export<W: Write>(&self, cfg: &ControlFlowGraph, name: &str, mut writer: W) -> io::Result<()> {
        let mut block_list = String::new();
        let mut blocks_html = String::new();

        let entry_id = cfg.entry;

        for block_id in cfg.reverse_post_order() {
            if let Some(block) = cfg.block(block_id) {
                let is_entry = block_id == entry_id;
                let is_exit = cfg.successors(block_id).is_empty();

                // Build sidebar list item
                writeln!(
                    block_list,
                    r#"                <li data-block="{}" onclick="scrollToBlock('{}')">{} <span class="addr">{:#x}</span></li>"#,
                    block_id, block_id, block_id, block.start
                ).unwrap();

                // Build block HTML
                let block_class = if is_entry {
                    "block entry"
                } else if is_exit {
                    "block exit"
                } else {
                    "block"
                };

                writeln!(blocks_html, r#"                <div class="{}" id="{}">"#, block_class, block_id).unwrap();
                writeln!(blocks_html, r#"                    <div class="block-header">"#).unwrap();
                writeln!(blocks_html, r#"                        <span class="name">{}{}</span>"#,
                    block_id,
                    if is_entry { " (entry)" } else if is_exit { " (exit)" } else { "" }
                ).unwrap();
                writeln!(blocks_html, r#"                        <span class="range">{:#x} - {:#x}</span>"#, block.start, block.end).unwrap();
                writeln!(blocks_html, r#"                    </div>"#).unwrap();

                if !block.instructions.is_empty() {
                    writeln!(blocks_html, r#"                    <div class="instructions">"#).unwrap();
                    for inst in &block.instructions {
                        let bytes_str: String = inst.bytes.iter()
                            .take(8)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        let operands_str = escape_html(&inst.operands.iter()
                            .map(|op| format!("{}", op))
                            .collect::<Vec<_>>()
                            .join(", "));

                        writeln!(blocks_html,
                            r#"                        <div class="inst"><span class="addr">{:#x}</span><span class="bytes">{}</span><span class="mnemonic">{}</span><span class="operands">{}</span></div>"#,
                            inst.address, bytes_str, inst.mnemonic, operands_str
                        ).unwrap();
                    }
                    writeln!(blocks_html, r#"                    </div>"#).unwrap();
                }

                let succs = cfg.successors(block_id);
                if !succs.is_empty() {
                    write!(blocks_html, r#"                    <div class="successors">→ "#).unwrap();
                    for succ in succs {
                        write!(blocks_html,
                            "<a href=\"#{}\" onclick=\"scrollToBlock('{}')\">{}</a>",
                            succ, succ, succ
                        ).unwrap();
                    }
                    writeln!(blocks_html, "</div>").unwrap();
                }

                writeln!(blocks_html, r#"                </div>"#).unwrap();
            }
        }

        let html = CFG_HTML_TEMPLATE
            .replace("{{NAME}}", &escape_html(name))
            .replace("{{BLOCK_COUNT}}", &cfg.num_blocks().to_string())
            .replace("{{ENTRY}}", &entry_id.to_string())
            .replace("{{BLOCK_LIST}}", &block_list)
            .replace("{{BLOCKS}}", &blocks_html);

        write!(writer, "{}", html)?;
        Ok(())
    }

    /// Export the CFG to HTML format, returning it as a String.
    pub fn export_to_string(&self, cfg: &ControlFlowGraph, name: &str) -> String {
        let mut buf = Vec::new();
        self.export(cfg, name, &mut buf).expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("HTML output should be valid UTF-8")
    }

    /// Export the CFG to HTML format, writing to stdout.
    pub fn export_to_stdout(&self, cfg: &ControlFlowGraph, name: &str) -> io::Result<()> {
        self.export(cfg, name, io::stdout())
    }
}

/// Exporter for rendering call graphs in HTML format.
pub struct CallGraphHtmlExporter;

impl Default for CallGraphHtmlExporter {
    fn default() -> Self {
        Self::new()
    }
}

impl CallGraphHtmlExporter {
    /// Create a new call graph HTML exporter.
    pub fn new() -> Self {
        Self
    }

    /// Get the display name for a call graph node.
    fn node_display_name(node: &crate::CallGraphNode) -> String {
        node.name
            .clone()
            .unwrap_or_else(|| format!("sub_{:x}", node.address))
    }

    /// Export the call graph to HTML format, writing to the provided writer.
    pub fn export<W: Write>(&self, callgraph: &CallGraph, mut writer: W) -> io::Result<()> {
        let mut func_list = String::new();
        let mut func_details = String::new();

        // Collect nodes and sort by name
        let mut nodes: Vec<_> = callgraph.nodes().collect();
        nodes.sort_by(|a, b| {
            let a_name = Self::node_display_name(a);
            let b_name = Self::node_display_name(b);
            a_name.cmp(&b_name)
        });

        for node in &nodes {
            let name = Self::node_display_name(node);
            let escaped_name = escape_html(&name);

            // Sidebar list item
            let external_class = if node.is_external { " external" } else { "" };
            writeln!(
                func_list,
                r#"                <li data-addr="{:x}" class="{}" onclick="showFunc('{:x}')">{} <span class="addr">{:#x}</span></li>"#,
                node.address, external_class, node.address, escaped_name, node.address
            ).unwrap();

            // Function detail card
            writeln!(func_details, r#"            <div class="func-detail" id="func-{:x}">"#, node.address).unwrap();
            writeln!(func_details, r#"                <div class="func-card">"#).unwrap();
            writeln!(func_details, r#"                    <div class="func-card-header">"#).unwrap();
            writeln!(func_details, r#"                        <h3>{}</h3>"#, escaped_name).unwrap();
            writeln!(func_details, r#"                        <div class="meta">Address: {:#x}{}</div>"#,
                node.address,
                if node.is_external { " | External" } else { "" }
            ).unwrap();
            writeln!(func_details, r#"                    </div>"#).unwrap();
            writeln!(func_details, r#"                    <div class="func-card-body">"#).unwrap();

            // Callees
            let callees: Vec<_> = callgraph.callees(node.address).collect();
            writeln!(func_details, r#"                        <div class="call-section">"#).unwrap();
            writeln!(func_details, r#"                            <h4>Calls ({} functions)</h4>"#, callees.len()).unwrap();
            if callees.is_empty() {
                writeln!(func_details, r#"                            <p class="empty">No outgoing calls</p>"#).unwrap();
            } else {
                writeln!(func_details, r#"                            <ul class="call-list">"#).unwrap();
                for (callee_addr, site) in &callees {
                    if let Some(callee) = callgraph.get_node(*callee_addr) {
                        let callee_name = escape_html(&Self::node_display_name(callee));
                        writeln!(func_details,
                            "                                <li><a href=\"#\" onclick=\"showFunc('{:x}')\">{}</a><span class=\"call-addr\">at {:#x}</span></li>",
                            callee.address, callee_name, site.call_address
                        ).unwrap();
                    }
                }
                writeln!(func_details, r#"                            </ul>"#).unwrap();
            }
            writeln!(func_details, r#"                        </div>"#).unwrap();

            // Callers
            let callers: Vec<_> = callgraph.callers(node.address).collect();
            writeln!(func_details, r#"                        <div class="call-section">"#).unwrap();
            writeln!(func_details, r#"                            <h4>Called by ({} functions)</h4>"#, callers.len()).unwrap();
            if callers.is_empty() {
                writeln!(func_details, r#"                            <p class="empty">No incoming calls (root or unreferenced)</p>"#).unwrap();
            } else {
                writeln!(func_details, r#"                            <ul class="call-list">"#).unwrap();
                for (caller_addr, site) in &callers {
                    if let Some(caller) = callgraph.get_node(*caller_addr) {
                        let caller_name = escape_html(&Self::node_display_name(caller));
                        writeln!(func_details,
                            "                                <li><a href=\"#\" onclick=\"showFunc('{:x}')\">{}</a><span class=\"call-addr\">at {:#x}</span></li>",
                            caller.address, caller_name, site.call_address
                        ).unwrap();
                    }
                }
                writeln!(func_details, r#"                            </ul>"#).unwrap();
            }
            writeln!(func_details, r#"                        </div>"#).unwrap();

            writeln!(func_details, r#"                    </div>"#).unwrap();
            writeln!(func_details, r#"                </div>"#).unwrap();
            writeln!(func_details, r#"            </div>"#).unwrap();
        }

        let html = CALLGRAPH_HTML_TEMPLATE
            .replace("{{NODE_COUNT}}", &callgraph.node_count().to_string())
            .replace("{{EDGE_COUNT}}", &callgraph.edge_count().to_string())
            .replace("{{FUNC_LIST}}", &func_list)
            .replace("{{FUNC_DETAILS}}", &func_details);

        write!(writer, "{}", html)?;
        Ok(())
    }

    /// Export the call graph to HTML format, returning it as a String.
    pub fn export_to_string(&self, callgraph: &CallGraph) -> String {
        let mut buf = Vec::new();
        self.export(callgraph, &mut buf).expect("writing to Vec should not fail");
        String::from_utf8(buf).expect("HTML output should be valid UTF-8")
    }

    /// Export the call graph to HTML format, writing to stdout.
    pub fn export_to_stdout(&self, callgraph: &CallGraph) -> io::Result<()> {
        self.export(callgraph, io::stdout())
    }
}

/// Escape HTML special characters.
fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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
    fn test_cfg_html_exporter() {
        let cfg = make_test_cfg();
        let exporter = CfgHtmlExporter::new();
        let html = exporter.export_to_string(&cfg, "test_func");

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>CFG: test_func</title>"));
        assert!(html.contains("bb0"));
        assert!(html.contains("bb1"));
        assert!(html.contains("0x1000"));
    }

    #[test]
    fn test_callgraph_html_exporter() {
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

        let exporter = CallGraphHtmlExporter::new();
        let html = exporter.export_to_string(&callgraph);

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<title>Call Graph</title>"));
        assert!(html.contains("main"));
        assert!(html.contains("helper"));
        assert!(html.contains("2 functions"));
    }

    #[test]
    fn test_escape_html() {
        assert_eq!(escape_html("hello"), "hello");
        assert_eq!(escape_html("<script>"), "&lt;script&gt;");
        assert_eq!(escape_html("a & b"), "a &amp; b");
        assert_eq!(escape_html("\"quoted\""), "&quot;quoted&quot;");
    }
}
