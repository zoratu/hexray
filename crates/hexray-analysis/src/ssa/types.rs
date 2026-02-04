//! SSA form type definitions.

use crate::dataflow::Location;
use hexray_core::{BasicBlockId, Operation};
use std::collections::HashMap;
use std::fmt;

/// A version number for SSA variables.
pub type Version = u32;

/// An SSA value - a versioned variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SsaValue {
    /// The underlying location.
    pub location: Location,
    /// The version number (each definition creates a new version).
    pub version: Version,
}

impl SsaValue {
    /// Creates a new SSA value.
    pub fn new(location: Location, version: Version) -> Self {
        Self { location, version }
    }

    /// Returns the base name for display.
    pub fn base_name(&self) -> String {
        match &self.location {
            Location::Register(id) => format!("r{}", id),
            Location::Stack(off) => {
                if *off < 0 {
                    format!("var_{:x}", -off)
                } else {
                    format!("arg_{:x}", off)
                }
            }
            Location::Memory(addr) => format!("mem_{:x}", addr),
            Location::Flags => "flags".to_string(),
        }
    }
}

impl fmt::Display for SsaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}_{}", self.base_name(), self.version)
    }
}

/// A phi node in SSA form.
///
/// Phi nodes appear at the start of blocks with multiple predecessors
/// and select a value based on which predecessor was taken.
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// The result of the phi node (the new version).
    pub result: SsaValue,
    /// Incoming values: (predecessor block, value from that path).
    pub incoming: Vec<(BasicBlockId, SsaValue)>,
}

impl PhiNode {
    /// Creates a new phi node with a result location.
    pub fn new(result: SsaValue) -> Self {
        Self {
            result,
            incoming: Vec::new(),
        }
    }

    /// Adds an incoming edge.
    pub fn add_incoming(&mut self, from_block: BasicBlockId, value: SsaValue) {
        self.incoming.push((from_block, value));
    }
}

impl fmt::Display for PhiNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} = φ(", self.result)?;
        for (i, (block, value)) in self.incoming.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}: {}", block, value)?;
        }
        write!(f, ")")
    }
}

/// An SSA instruction.
#[derive(Debug, Clone)]
pub struct SsaInstruction {
    /// Address of the original instruction.
    pub address: u64,
    /// Operation being performed.
    pub operation: Operation,
    /// Result value(s) defined by this instruction.
    pub defs: Vec<SsaValue>,
    /// Values used by this instruction.
    pub uses: Vec<SsaOperand>,
    /// Original mnemonic.
    pub mnemonic: String,
}

/// An operand in SSA form.
#[derive(Debug, Clone)]
pub enum SsaOperand {
    /// An SSA value (versioned variable).
    Value(SsaValue),
    /// An immediate constant.
    Immediate(i128),
    /// A memory reference with SSA values for base/index.
    Memory {
        base: Option<SsaValue>,
        index: Option<SsaValue>,
        scale: u8,
        displacement: i64,
        size: u8,
    },
}

impl fmt::Display for SsaOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SsaOperand::Value(v) => write!(f, "{}", v),
            SsaOperand::Immediate(imm) => {
                if *imm >= 0 && *imm < 10 {
                    write!(f, "{}", imm)
                } else {
                    write!(f, "{:#x}", imm)
                }
            }
            SsaOperand::Memory {
                base,
                index,
                scale,
                displacement,
                size,
            } => {
                let prefix = match size {
                    1 => "byte",
                    2 => "word",
                    4 => "dword",
                    8 => "qword",
                    _ => "",
                };
                write!(f, "{}[", prefix)?;
                let mut parts = Vec::new();
                if let Some(b) = base {
                    parts.push(format!("{}", b));
                }
                if let Some(idx) = index {
                    if *scale > 1 {
                        parts.push(format!("{}*{}", idx, scale));
                    } else {
                        parts.push(format!("{}", idx));
                    }
                }
                if *displacement != 0 {
                    if *displacement > 0 {
                        parts.push(format!("{:#x}", displacement));
                    } else {
                        parts.push(format!("-{:#x}", -displacement));
                    }
                }
                write!(f, "{}]", parts.join(" + "))
            }
        }
    }
}

/// An SSA basic block.
#[derive(Debug, Clone)]
pub struct SsaBlock {
    /// Block identifier.
    pub id: BasicBlockId,
    /// Start address.
    pub start: u64,
    /// Phi nodes at the start of the block.
    pub phis: Vec<PhiNode>,
    /// Instructions in SSA form.
    pub instructions: Vec<SsaInstruction>,
}

impl SsaBlock {
    /// Creates a new SSA block.
    pub fn new(id: BasicBlockId, start: u64) -> Self {
        Self {
            id,
            start,
            phis: Vec::new(),
            instructions: Vec::new(),
        }
    }

    /// Adds a phi node.
    pub fn add_phi(&mut self, phi: PhiNode) {
        self.phis.push(phi);
    }

    /// Adds an instruction.
    pub fn add_instruction(&mut self, inst: SsaInstruction) {
        self.instructions.push(inst);
    }
}

/// A complete function in SSA form.
#[derive(Debug)]
pub struct SsaFunction {
    /// Function name.
    pub name: String,
    /// Entry block ID.
    pub entry: BasicBlockId,
    /// Blocks in SSA form.
    pub blocks: HashMap<BasicBlockId, SsaBlock>,
    /// Current version counter for each location.
    pub version_counters: HashMap<Location, Version>,
}

impl Default for SsaFunction {
    fn default() -> Self {
        Self::new("unnamed", BasicBlockId::new(0))
    }
}

impl SsaFunction {
    /// Creates a new SSA function.
    pub fn new(name: impl Into<String>, entry: BasicBlockId) -> Self {
        Self {
            name: name.into(),
            entry,
            blocks: HashMap::new(),
            version_counters: HashMap::new(),
        }
    }

    /// Gets the next version number for a location.
    pub fn next_version(&mut self, location: &Location) -> Version {
        let counter = self.version_counters.entry(location.clone()).or_insert(0);
        let version = *counter;
        *counter += 1;
        version
    }

    /// Adds a block.
    pub fn add_block(&mut self, block: SsaBlock) {
        self.blocks.insert(block.id, block);
    }

    /// Gets a block by ID.
    pub fn block(&self, id: BasicBlockId) -> Option<&SsaBlock> {
        self.blocks.get(&id)
    }

    /// Gets a mutable block by ID.
    pub fn block_mut(&mut self, id: BasicBlockId) -> Option<&mut SsaBlock> {
        self.blocks.get_mut(&id)
    }

    /// Prints the SSA form.
    pub fn display(&self) -> String {
        let mut output = format!("function {}:\n", self.name);

        // Sort blocks by ID for consistent output
        let mut block_ids: Vec<_> = self.blocks.keys().collect();
        block_ids.sort_by_key(|id| id.0);

        for &block_id in &block_ids {
            let block = &self.blocks[block_id];
            output.push_str(&format!("\n  {}:  ; addr {:#x}\n", block_id, block.start));

            // Print phi nodes
            for phi in &block.phis {
                output.push_str(&format!("    {}\n", phi));
            }

            // Print instructions
            for inst in &block.instructions {
                output.push_str(&format!("    ; {:#x}: {}\n", inst.address, inst.mnemonic));
                if !inst.defs.is_empty() {
                    let defs: Vec<_> = inst.defs.iter().map(|d| d.to_string()).collect();
                    let uses: Vec<_> = inst.uses.iter().map(|u| u.to_string()).collect();
                    output.push_str(&format!(
                        "    {} = {:?}({})\n",
                        defs.join(", "),
                        inst.operation,
                        uses.join(", ")
                    ));
                }
            }
        }

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SsaValue Tests ---

    #[test]
    fn test_ssa_value_new() {
        let val = SsaValue::new(Location::Register(0), 5);
        assert_eq!(val.location, Location::Register(0));
        assert_eq!(val.version, 5);
    }

    #[test]
    fn test_ssa_value_base_name_register() {
        let val = SsaValue::new(Location::Register(5), 0);
        assert_eq!(val.base_name(), "r5");
    }

    #[test]
    fn test_ssa_value_base_name_stack_local() {
        // Negative offset = local variable
        let val = SsaValue::new(Location::Stack(-8), 0);
        assert_eq!(val.base_name(), "var_8");
    }

    #[test]
    fn test_ssa_value_base_name_stack_arg() {
        // Positive offset = argument
        let val = SsaValue::new(Location::Stack(16), 0);
        assert_eq!(val.base_name(), "arg_10");
    }

    #[test]
    fn test_ssa_value_base_name_memory() {
        let val = SsaValue::new(Location::Memory(0x601000), 0);
        assert_eq!(val.base_name(), "mem_601000");
    }

    #[test]
    fn test_ssa_value_base_name_flags() {
        let val = SsaValue::new(Location::Flags, 0);
        assert_eq!(val.base_name(), "flags");
    }

    #[test]
    fn test_ssa_value_display() {
        let val = SsaValue::new(Location::Register(0), 3);
        assert_eq!(format!("{}", val), "r0_3");
    }

    #[test]
    fn test_ssa_value_equality() {
        let val1 = SsaValue::new(Location::Register(0), 1);
        let val2 = SsaValue::new(Location::Register(0), 1);
        let val3 = SsaValue::new(Location::Register(0), 2);
        let val4 = SsaValue::new(Location::Register(1), 1);

        assert_eq!(val1, val2);
        assert_ne!(val1, val3); // Different version
        assert_ne!(val1, val4); // Different register
    }

    #[test]
    fn test_ssa_value_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();

        set.insert(SsaValue::new(Location::Register(0), 0));
        set.insert(SsaValue::new(Location::Register(0), 1));
        set.insert(SsaValue::new(Location::Register(0), 0)); // duplicate

        assert_eq!(set.len(), 2);
    }

    // --- PhiNode Tests ---

    #[test]
    fn test_phi_node_new() {
        let result = SsaValue::new(Location::Register(0), 2);
        let phi = PhiNode::new(result.clone());

        assert_eq!(phi.result, result);
        assert!(phi.incoming.is_empty());
    }

    #[test]
    fn test_phi_node_add_incoming() {
        let result = SsaValue::new(Location::Register(0), 2);
        let mut phi = PhiNode::new(result);

        let val1 = SsaValue::new(Location::Register(0), 0);
        let val2 = SsaValue::new(Location::Register(0), 1);

        phi.add_incoming(BasicBlockId::new(1), val1.clone());
        phi.add_incoming(BasicBlockId::new(2), val2.clone());

        assert_eq!(phi.incoming.len(), 2);
        assert_eq!(phi.incoming[0], (BasicBlockId::new(1), val1));
        assert_eq!(phi.incoming[1], (BasicBlockId::new(2), val2));
    }

    #[test]
    fn test_phi_node_display() {
        let result = SsaValue::new(Location::Register(0), 2);
        let mut phi = PhiNode::new(result);

        phi.add_incoming(
            BasicBlockId::new(1),
            SsaValue::new(Location::Register(0), 0),
        );
        phi.add_incoming(
            BasicBlockId::new(2),
            SsaValue::new(Location::Register(0), 1),
        );

        let display = format!("{}", phi);
        assert!(display.contains("r0_2 = φ("));
        assert!(display.contains("bb1: r0_0"));
        assert!(display.contains("bb2: r0_1"));
    }

    #[test]
    fn test_phi_node_display_empty() {
        let result = SsaValue::new(Location::Register(5), 0);
        let phi = PhiNode::new(result);
        assert_eq!(format!("{}", phi), "r5_0 = φ()");
    }

    // --- SsaOperand Tests ---

    #[test]
    fn test_ssa_operand_value_display() {
        let val = SsaValue::new(Location::Register(1), 3);
        let op = SsaOperand::Value(val);
        assert_eq!(format!("{}", op), "r1_3");
    }

    #[test]
    fn test_ssa_operand_immediate_small() {
        let op = SsaOperand::Immediate(5);
        assert_eq!(format!("{}", op), "5");
    }

    #[test]
    fn test_ssa_operand_immediate_large() {
        let op = SsaOperand::Immediate(255);
        assert_eq!(format!("{}", op), "0xff");
    }

    #[test]
    fn test_ssa_operand_immediate_negative() {
        let op = SsaOperand::Immediate(-1);
        // Negative numbers print as hex
        let display = format!("{}", op);
        assert!(display.starts_with("0x") || display.starts_with("-"));
    }

    #[test]
    fn test_ssa_operand_memory_base_only() {
        let op = SsaOperand::Memory {
            base: Some(SsaValue::new(Location::Register(0), 0)),
            index: None,
            scale: 1,
            displacement: 0,
            size: 8,
        };
        let display = format!("{}", op);
        assert!(display.contains("qword"));
        assert!(display.contains("r0_0"));
    }

    #[test]
    fn test_ssa_operand_memory_base_disp() {
        let op = SsaOperand::Memory {
            base: Some(SsaValue::new(Location::Register(5), 0)),
            index: None,
            scale: 1,
            displacement: -8,
            size: 4,
        };
        let display = format!("{}", op);
        assert!(display.contains("dword"));
        assert!(display.contains("r5_0"));
        assert!(display.contains("-0x8"));
    }

    #[test]
    fn test_ssa_operand_memory_scaled_index() {
        let op = SsaOperand::Memory {
            base: Some(SsaValue::new(Location::Register(0), 0)),
            index: Some(SsaValue::new(Location::Register(1), 0)),
            scale: 4,
            displacement: 0,
            size: 4,
        };
        let display = format!("{}", op);
        assert!(display.contains("r1_0*4"));
    }

    #[test]
    fn test_ssa_operand_memory_full_sib() {
        let op = SsaOperand::Memory {
            base: Some(SsaValue::new(Location::Register(0), 1)),
            index: Some(SsaValue::new(Location::Register(1), 2)),
            scale: 8,
            displacement: 0x100,
            size: 8,
        };
        let display = format!("{}", op);
        assert!(display.contains("qword"));
        assert!(display.contains("r0_1"));
        assert!(display.contains("r1_2*8"));
        assert!(display.contains("0x100"));
    }

    #[test]
    fn test_ssa_operand_memory_sizes() {
        let byte_op = SsaOperand::Memory {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x1000,
            size: 1,
        };
        assert!(format!("{}", byte_op).contains("byte"));

        let word_op = SsaOperand::Memory {
            base: None,
            index: None,
            scale: 1,
            displacement: 0x1000,
            size: 2,
        };
        assert!(format!("{}", word_op).contains("word"));
    }

    // --- SsaBlock Tests ---

    #[test]
    fn test_ssa_block_new() {
        let block = SsaBlock::new(BasicBlockId::new(5), 0x1000);
        assert_eq!(block.id, BasicBlockId::new(5));
        assert_eq!(block.start, 0x1000);
        assert!(block.phis.is_empty());
        assert!(block.instructions.is_empty());
    }

    #[test]
    fn test_ssa_block_add_phi() {
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);
        let phi = PhiNode::new(SsaValue::new(Location::Register(0), 0));

        block.add_phi(phi);
        assert_eq!(block.phis.len(), 1);
    }

    #[test]
    fn test_ssa_block_add_instruction() {
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);
        let inst = SsaInstruction {
            address: 0x1000,
            operation: Operation::Move,
            defs: vec![SsaValue::new(Location::Register(0), 0)],
            uses: vec![SsaOperand::Immediate(42)],
            mnemonic: "mov".to_string(),
        };

        block.add_instruction(inst);
        assert_eq!(block.instructions.len(), 1);
    }

    #[test]
    fn test_ssa_block_multiple_phis() {
        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        block.add_phi(PhiNode::new(SsaValue::new(Location::Register(0), 0)));
        block.add_phi(PhiNode::new(SsaValue::new(Location::Register(1), 0)));
        block.add_phi(PhiNode::new(SsaValue::new(Location::Register(2), 0)));

        assert_eq!(block.phis.len(), 3);
    }

    // --- SsaFunction Tests ---

    #[test]
    fn test_ssa_function_new() {
        let func = SsaFunction::new("test_func", BasicBlockId::new(0));
        assert_eq!(func.name, "test_func");
        assert_eq!(func.entry, BasicBlockId::new(0));
        assert!(func.blocks.is_empty());
    }

    #[test]
    fn test_ssa_function_default() {
        let func = SsaFunction::default();
        assert_eq!(func.name, "unnamed");
        assert_eq!(func.entry, BasicBlockId::new(0));
    }

    #[test]
    fn test_ssa_function_next_version() {
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));

        let loc = Location::Register(0);
        assert_eq!(func.next_version(&loc), 0);
        assert_eq!(func.next_version(&loc), 1);
        assert_eq!(func.next_version(&loc), 2);

        // Different location starts at 0
        let loc2 = Location::Register(1);
        assert_eq!(func.next_version(&loc2), 0);
    }

    #[test]
    fn test_ssa_function_add_block() {
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        let block = SsaBlock::new(BasicBlockId::new(0), 0x1000);

        func.add_block(block);
        assert_eq!(func.blocks.len(), 1);
    }

    #[test]
    fn test_ssa_function_block() {
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        func.add_block(SsaBlock::new(BasicBlockId::new(0), 0x1000));
        func.add_block(SsaBlock::new(BasicBlockId::new(1), 0x1010));

        assert!(func.block(BasicBlockId::new(0)).is_some());
        assert!(func.block(BasicBlockId::new(1)).is_some());
        assert!(func.block(BasicBlockId::new(99)).is_none());
    }

    #[test]
    fn test_ssa_function_block_mut() {
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));
        func.add_block(SsaBlock::new(BasicBlockId::new(0), 0x1000));

        let block = func.block_mut(BasicBlockId::new(0)).unwrap();
        block.add_phi(PhiNode::new(SsaValue::new(Location::Register(0), 0)));

        assert_eq!(func.block(BasicBlockId::new(0)).unwrap().phis.len(), 1);
    }

    #[test]
    fn test_ssa_function_display() {
        let mut func = SsaFunction::new("my_func", BasicBlockId::new(0));

        let mut block = SsaBlock::new(BasicBlockId::new(0), 0x1000);
        let mut phi = PhiNode::new(SsaValue::new(Location::Register(0), 1));
        phi.add_incoming(
            BasicBlockId::new(1),
            SsaValue::new(Location::Register(0), 0),
        );
        block.add_phi(phi);

        let inst = SsaInstruction {
            address: 0x1000,
            operation: Operation::Move,
            defs: vec![SsaValue::new(Location::Register(1), 0)],
            uses: vec![SsaOperand::Immediate(42)],
            mnemonic: "mov".to_string(),
        };
        block.add_instruction(inst);

        func.add_block(block);

        let display = func.display();
        assert!(display.contains("function my_func:"));
        assert!(display.contains("bb0:"));
        assert!(display.contains("0x1000"));
        assert!(display.contains("φ("));
        assert!(display.contains("mov"));
    }

    #[test]
    fn test_ssa_function_display_sorted_blocks() {
        let mut func = SsaFunction::new("test", BasicBlockId::new(0));

        // Add blocks out of order
        func.add_block(SsaBlock::new(BasicBlockId::new(2), 0x1020));
        func.add_block(SsaBlock::new(BasicBlockId::new(0), 0x1000));
        func.add_block(SsaBlock::new(BasicBlockId::new(1), 0x1010));

        let display = func.display();

        // Blocks should appear in sorted order
        let bb0_pos = display.find("bb0:").unwrap();
        let bb1_pos = display.find("bb1:").unwrap();
        let bb2_pos = display.find("bb2:").unwrap();

        assert!(bb0_pos < bb1_pos);
        assert!(bb1_pos < bb2_pos);
    }

    // --- SsaInstruction Tests ---

    #[test]
    fn test_ssa_instruction_multiple_defs() {
        let inst = SsaInstruction {
            address: 0x1000,
            operation: Operation::Mul,
            defs: vec![
                SsaValue::new(Location::Register(0), 0), // low result
                SsaValue::new(Location::Register(2), 0), // high result (rdx)
            ],
            uses: vec![
                SsaOperand::Value(SsaValue::new(Location::Register(0), 0)),
                SsaOperand::Value(SsaValue::new(Location::Register(1), 0)),
            ],
            mnemonic: "mul".to_string(),
        };

        assert_eq!(inst.defs.len(), 2);
        assert_eq!(inst.uses.len(), 2);
    }

    #[test]
    fn test_ssa_instruction_no_defs() {
        let inst = SsaInstruction {
            address: 0x1000,
            operation: Operation::Store,
            defs: vec![],
            uses: vec![
                SsaOperand::Value(SsaValue::new(Location::Register(0), 0)),
                SsaOperand::Memory {
                    base: Some(SsaValue::new(Location::Register(5), 0)),
                    index: None,
                    scale: 1,
                    displacement: -8,
                    size: 8,
                },
            ],
            mnemonic: "mov".to_string(),
        };

        assert!(inst.defs.is_empty());
        assert_eq!(inst.uses.len(), 2);
    }
}
