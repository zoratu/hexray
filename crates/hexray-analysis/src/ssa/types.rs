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
