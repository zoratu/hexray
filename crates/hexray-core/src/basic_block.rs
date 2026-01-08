//! Basic block representation.

use crate::{Condition, Instruction, Operand};

/// Unique identifier for a basic block within a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicBlockId(pub u32);

impl BasicBlockId {
    /// The entry block ID (always 0).
    pub const ENTRY: Self = Self(0);

    /// Creates a new basic block ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for BasicBlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bb{}", self.0)
    }
}

/// A basic block - a maximal sequence of straight-line code.
///
/// A basic block has the property that:
/// - It has exactly one entry point (the first instruction)
/// - It has exactly one exit point (the last instruction)
/// - If any instruction in the block executes, all instructions execute (in order)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BasicBlock {
    /// Unique identifier for this block.
    pub id: BasicBlockId,
    /// Start address (address of first instruction).
    pub start: u64,
    /// End address (exclusive, address after last instruction).
    pub end: u64,
    /// Instructions in this block.
    pub instructions: Vec<Instruction>,
    /// How this block terminates.
    pub terminator: BlockTerminator,
}

impl BasicBlock {
    /// Creates a new empty basic block.
    pub fn new(id: BasicBlockId, start: u64) -> Self {
        Self {
            id,
            start,
            end: start,
            instructions: Vec::new(),
            terminator: BlockTerminator::Unknown,
        }
    }

    /// Adds an instruction to this block.
    pub fn push_instruction(&mut self, inst: Instruction) {
        self.end = inst.address + inst.size as u64;
        self.instructions.push(inst);
    }

    /// Returns true if this block is empty.
    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }

    /// Returns the number of instructions in this block.
    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    /// Returns the last instruction in this block, if any.
    pub fn last_instruction(&self) -> Option<&Instruction> {
        self.instructions.last()
    }

    /// Returns the size of this block in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}

/// How a basic block terminates.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum BlockTerminator {
    /// Terminator not yet determined.
    Unknown,

    /// Falls through to next block.
    Fallthrough {
        target: BasicBlockId,
    },

    /// Unconditional jump.
    Jump {
        target: BasicBlockId,
    },

    /// Conditional branch.
    ConditionalBranch {
        condition: Condition,
        true_target: BasicBlockId,
        false_target: BasicBlockId,
    },

    /// Indirect jump (computed target).
    IndirectJump {
        /// The operand containing the target address.
        target: Operand,
        /// Possible targets if known (from analysis).
        possible_targets: Vec<BasicBlockId>,
    },

    /// Function call (control returns afterward).
    Call {
        target: CallTarget,
        return_block: BasicBlockId,
    },

    /// Function return.
    Return,

    /// Unreachable (e.g., after noreturn call, trap, etc.).
    Unreachable,
}

impl BlockTerminator {
    /// Returns the successor block IDs.
    pub fn successors(&self) -> Vec<BasicBlockId> {
        match self {
            Self::Unknown | Self::Return | Self::Unreachable => vec![],
            Self::Fallthrough { target } | Self::Jump { target } => vec![*target],
            Self::ConditionalBranch {
                true_target,
                false_target,
                ..
            } => vec![*true_target, *false_target],
            Self::IndirectJump {
                possible_targets, ..
            } => possible_targets.clone(),
            Self::Call { return_block, .. } => vec![*return_block],
        }
    }

    /// Returns true if this terminator can fall through.
    pub fn can_fall_through(&self) -> bool {
        matches!(
            self,
            Self::Fallthrough { .. }
                | Self::ConditionalBranch { .. }
                | Self::Call { .. }
        )
    }
}

/// Target of a call instruction.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum CallTarget {
    /// Direct call to a known address.
    Direct(u64),
    /// Indirect call through a register or memory.
    Indirect(Operand),
}
