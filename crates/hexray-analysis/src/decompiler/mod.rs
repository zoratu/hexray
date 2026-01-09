//! Pseudo-code generator / decompiler.
//!
//! This module transforms disassembled code (CFG) into high-level pseudo-code.
//!
//! The decompilation pipeline:
//! 1. **Control Flow Structuring** - Identify if/else, loops (while, do-while, for)
//! 2. **Expression Recovery** - Convert instructions to high-level expressions
//! 3. **Pseudo-code Emission** - Generate readable pseudo-code output

mod expression;
mod structurer;
mod emitter;

pub use expression::{Expr, ExprKind, Variable};
pub use structurer::{StructuredCfg, StructuredNode, LoopKind};
pub use emitter::PseudoCodeEmitter;

use hexray_core::ControlFlowGraph;
use std::collections::HashMap;

/// String table for resolving addresses to string literals.
#[derive(Debug, Clone, Default)]
pub struct StringTable {
    /// Maps addresses to string values.
    strings: HashMap<u64, String>,
}

impl StringTable {
    /// Creates a new empty string table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a string at a given address.
    pub fn insert(&mut self, address: u64, value: String) {
        self.strings.insert(address, value);
    }

    /// Looks up a string at a given address.
    pub fn get(&self, address: u64) -> Option<&str> {
        self.strings.get(&address).map(|s| s.as_str())
    }

    /// Returns an iterator over all (address, string) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &String)> {
        self.strings.iter()
    }

    /// Merges another string table into this one.
    pub fn merge(&mut self, other: &StringTable) {
        for (addr, s) in other.strings.iter() {
            self.strings.insert(*addr, s.clone());
        }
    }

    /// Extracts strings from binary data.
    ///
    /// Scans sections for null-terminated strings at addresses.
    pub fn from_binary_data(data: &[u8], base_address: u64) -> Self {
        let mut table = Self::new();
        let mut i = 0;

        while i < data.len() {
            // Look for potential string starts (printable ASCII)
            if is_printable_ascii(data[i]) {
                let start = i;
                let mut end = i;

                // Scan forward to find null terminator or non-printable
                while end < data.len() && data[end] != 0 {
                    if !is_printable_ascii(data[end]) {
                        break;
                    }
                    end += 1;
                }

                // Check if we found a null-terminated string of reasonable length
                // Allow shorter strings (min 2 chars) for format strings like "%s"
                if end < data.len() && data[end] == 0 && end - start >= 2 {
                    if let Ok(s) = std::str::from_utf8(&data[start..end]) {
                        table.insert(base_address + start as u64, s.to_string());
                    }
                }

                i = end + 1;
            } else {
                i += 1;
            }
        }

        table
    }
}

/// Checks if a byte is printable ASCII.
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Symbol table for resolving function addresses to names.
#[derive(Debug, Clone, Default)]
pub struct SymbolTable {
    /// Maps addresses to symbol names.
    symbols: HashMap<u64, String>,
}

impl SymbolTable {
    /// Creates a new empty symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a symbol at a given address.
    pub fn insert(&mut self, address: u64, name: String) {
        self.symbols.insert(address, name);
    }

    /// Looks up a symbol at a given address.
    pub fn get(&self, address: u64) -> Option<&str> {
        self.symbols.get(&address).map(|s| s.as_str())
    }
}

/// Relocation table for resolving symbols in relocatable files.
///
/// In kernel modules and other relocatable files, call instructions
/// and data references have unresolved targets (offset = 0) that need
/// relocation info to determine the actual target.
#[derive(Debug, Clone, Default)]
pub struct RelocationTable {
    /// Maps instruction addresses to target symbol names (for calls).
    call_relocations: HashMap<u64, String>,
    /// Maps instruction addresses to data symbol names (for mov/lea with immediates).
    data_relocations: HashMap<u64, String>,
}

impl RelocationTable {
    /// Creates a new empty relocation table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a call relocation entry.
    pub fn insert(&mut self, call_addr: u64, target_symbol: String) {
        self.call_relocations.insert(call_addr, target_symbol);
    }

    /// Adds a data relocation entry.
    pub fn insert_data(&mut self, inst_addr: u64, symbol: String) {
        self.data_relocations.insert(inst_addr, symbol);
    }

    /// Looks up a call target by call instruction address.
    pub fn get(&self, call_addr: u64) -> Option<&str> {
        self.call_relocations.get(&call_addr).map(|s| s.as_str())
    }

    /// Looks up a data symbol by instruction address.
    pub fn get_data(&self, inst_addr: u64) -> Option<&str> {
        self.data_relocations.get(&inst_addr).map(|s| s.as_str())
    }

    /// Gets all data relocations within an address range, sorted by address.
    pub fn get_data_in_range(&self, start: u64, end: u64) -> Vec<(u64, &str)> {
        let mut results: Vec<_> = self.data_relocations
            .iter()
            .filter(|(addr, _)| **addr >= start && **addr < end)
            .map(|(addr, name)| (*addr, name.as_str()))
            .collect();
        results.sort_by_key(|(addr, _)| *addr);
        results
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.call_relocations.is_empty() && self.data_relocations.is_empty()
    }
}

/// Main entry point for decompilation.
///
/// Takes a CFG and produces pseudo-code output.
pub struct Decompiler {
    /// Whether to emit comments with addresses.
    pub emit_addresses: bool,
    /// Indentation string (default: 4 spaces).
    pub indent: String,
    /// String table for resolving addresses.
    pub string_table: Option<StringTable>,
    /// Symbol table for resolving function addresses.
    pub symbol_table: Option<SymbolTable>,
    /// Relocation table for resolving call targets in relocatable files.
    pub relocation_table: Option<RelocationTable>,
}

impl Default for Decompiler {
    fn default() -> Self {
        Self {
            emit_addresses: true,
            indent: "    ".to_string(),
            string_table: None,
            symbol_table: None,
            relocation_table: None,
        }
    }
}

impl Decompiler {
    /// Creates a new decompiler with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables or disables address comments.
    pub fn with_addresses(mut self, emit: bool) -> Self {
        self.emit_addresses = emit;
        self
    }

    /// Sets the indentation string.
    pub fn with_indent(mut self, indent: impl Into<String>) -> Self {
        self.indent = indent.into();
        self
    }

    /// Sets the string table for resolving addresses to strings.
    pub fn with_string_table(mut self, table: StringTable) -> Self {
        self.string_table = Some(table);
        self
    }

    /// Sets the symbol table for resolving function addresses.
    pub fn with_symbol_table(mut self, table: SymbolTable) -> Self {
        self.symbol_table = Some(table);
        self
    }

    /// Sets the relocation table for resolving call targets.
    pub fn with_relocation_table(mut self, table: RelocationTable) -> Self {
        self.relocation_table = Some(table);
        self
    }

    /// Decompiles a CFG to pseudo-code.
    pub fn decompile(&self, cfg: &ControlFlowGraph, func_name: &str) -> String {
        // Step 1: Structure the control flow
        let structured = StructuredCfg::from_cfg(cfg);

        // Step 2: Emit pseudo-code
        let emitter = PseudoCodeEmitter::new(&self.indent, self.emit_addresses)
            .with_string_table(self.string_table.clone())
            .with_symbol_table(self.symbol_table.clone())
            .with_relocation_table(self.relocation_table.clone());
        emitter.emit(&structured, func_name)
    }

    /// Decompiles a CFG and returns the structured representation.
    pub fn structure(&self, cfg: &ControlFlowGraph) -> StructuredCfg {
        StructuredCfg::from_cfg(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, BasicBlockId, BlockTerminator, Condition, Instruction, Operation, ControlFlow};

    fn make_simple_cfg() -> ControlFlowGraph {
        // Simple if/else:
        //   bb0: entry
        //     cmp r0, 0
        //     beq bb2
        //   bb1: then
        //     add r1, r1, 1
        //     jmp bb3
        //   bb2: else
        //     sub r1, r1, 1
        //   bb3: join
        //     ret

        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        // Entry block
        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(
            Instruction::new(0x1000, 4, vec![0; 4], "cmp")
                .with_operation(Operation::Compare)
        );
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        // Then block
        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1004);
        bb1.push_instruction(
            Instruction::new(0x1004, 4, vec![0; 4], "add")
                .with_operation(Operation::Add)
        );
        bb1.terminator = BlockTerminator::Jump { target: BasicBlockId::new(3) };
        cfg.add_block(bb1);

        // Else block
        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1008);
        bb2.push_instruction(
            Instruction::new(0x1008, 4, vec![0; 4], "sub")
                .with_operation(Operation::Sub)
        );
        bb2.terminator = BlockTerminator::Fallthrough { target: BasicBlockId::new(3) };
        cfg.add_block(bb2);

        // Join block
        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x100c);
        bb3.push_instruction(
            Instruction::new(0x100c, 4, vec![0; 4], "ret")
                .with_operation(Operation::Return)
                .with_control_flow(ControlFlow::Return)
        );
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        // Add edges
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        cfg
    }

    #[test]
    fn test_decompile_if_else() {
        let cfg = make_simple_cfg();
        let decompiler = Decompiler::new().with_addresses(false);
        let output = decompiler.decompile(&cfg, "test_func");

        // Should contain if/else structure
        assert!(output.contains("if"));
        assert!(output.contains("else"));
    }
}
