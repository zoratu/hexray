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
    Fallthrough { target: BasicBlockId },

    /// Unconditional jump.
    Jump { target: BasicBlockId },

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
            Self::Fallthrough { .. } | Self::ConditionalBranch { .. } | Self::Call { .. }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Architecture, Register, RegisterClass};

    fn make_instruction(addr: u64, size: usize) -> Instruction {
        Instruction::new(addr, size, vec![0x90; size], "nop")
    }

    // --- BasicBlockId Tests ---

    #[test]
    fn test_basic_block_id_entry() {
        assert_eq!(BasicBlockId::ENTRY, BasicBlockId::new(0));
    }

    #[test]
    fn test_basic_block_id_display() {
        assert_eq!(format!("{}", BasicBlockId::new(0)), "bb0");
        assert_eq!(format!("{}", BasicBlockId::new(42)), "bb42");
    }

    #[test]
    fn test_basic_block_id_equality() {
        assert_eq!(BasicBlockId::new(5), BasicBlockId::new(5));
        assert_ne!(BasicBlockId::new(5), BasicBlockId::new(6));
    }

    #[test]
    fn test_basic_block_id_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(BasicBlockId::new(1));
        set.insert(BasicBlockId::new(2));
        set.insert(BasicBlockId::new(1)); // duplicate

        assert_eq!(set.len(), 2);
    }

    // --- BasicBlock Tests ---

    #[test]
    fn test_basic_block_new() {
        let block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        assert_eq!(block.id, BasicBlockId::new(0));
        assert_eq!(block.start, 0x1000);
        assert_eq!(block.end, 0x1000);
        assert!(block.is_empty());
    }

    #[test]
    fn test_basic_block_push_instruction() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        let inst = make_instruction(0x1000, 4);
        block.push_instruction(inst);

        assert_eq!(block.len(), 1);
        assert_eq!(block.end, 0x1004);
        assert!(!block.is_empty());
    }

    #[test]
    fn test_basic_block_multiple_instructions() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        block.push_instruction(make_instruction(0x1000, 4));
        block.push_instruction(make_instruction(0x1004, 2));
        block.push_instruction(make_instruction(0x1006, 1));

        assert_eq!(block.len(), 3);
        assert_eq!(block.end, 0x1007);
    }

    #[test]
    fn test_basic_block_size() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        block.push_instruction(make_instruction(0x1000, 4));
        block.push_instruction(make_instruction(0x1004, 2));

        assert_eq!(block.size(), 6);
    }

    #[test]
    fn test_basic_block_last_instruction() {
        let mut block = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        assert!(block.last_instruction().is_none());

        block.push_instruction(make_instruction(0x1000, 4));
        block.push_instruction(make_instruction(0x1004, 2));

        let last = block.last_instruction().unwrap();
        assert_eq!(last.address, 0x1004);
    }

    // --- BlockTerminator Tests ---

    #[test]
    fn test_terminator_unknown_no_successors() {
        let term = BlockTerminator::Unknown;
        assert!(term.successors().is_empty());
        assert!(!term.can_fall_through());
    }

    #[test]
    fn test_terminator_return_no_successors() {
        let term = BlockTerminator::Return;
        assert!(term.successors().is_empty());
        assert!(!term.can_fall_through());
    }

    #[test]
    fn test_terminator_unreachable_no_successors() {
        let term = BlockTerminator::Unreachable;
        assert!(term.successors().is_empty());
        assert!(!term.can_fall_through());
    }

    #[test]
    fn test_terminator_fallthrough() {
        let term = BlockTerminator::Fallthrough {
            target: BasicBlockId::new(1),
        };
        assert_eq!(term.successors(), vec![BasicBlockId::new(1)]);
        assert!(term.can_fall_through());
    }

    #[test]
    fn test_terminator_jump() {
        let term = BlockTerminator::Jump {
            target: BasicBlockId::new(5),
        };
        assert_eq!(term.successors(), vec![BasicBlockId::new(5)]);
        assert!(!term.can_fall_through());
    }

    #[test]
    fn test_terminator_conditional_branch() {
        let term = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };

        let succs = term.successors();
        assert_eq!(succs.len(), 2);
        assert!(succs.contains(&BasicBlockId::new(2)));
        assert!(succs.contains(&BasicBlockId::new(3)));
        assert!(term.can_fall_through());
    }

    #[test]
    fn test_terminator_indirect_jump() {
        let reg = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let term = BlockTerminator::IndirectJump {
            target: Operand::reg(reg),
            possible_targets: vec![BasicBlockId::new(1), BasicBlockId::new(2)],
        };

        assert_eq!(term.successors().len(), 2);
        assert!(!term.can_fall_through());
    }

    #[test]
    fn test_terminator_call() {
        let term = BlockTerminator::Call {
            target: CallTarget::Direct(0x2000),
            return_block: BasicBlockId::new(1),
        };

        assert_eq!(term.successors(), vec![BasicBlockId::new(1)]);
        assert!(term.can_fall_through());
    }

    // --- CallTarget Tests ---

    #[test]
    fn test_call_target_direct() {
        let target = CallTarget::Direct(0x1234);
        assert_eq!(target, CallTarget::Direct(0x1234));
    }

    #[test]
    fn test_call_target_indirect() {
        let reg = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let target = CallTarget::Indirect(Operand::reg(reg));
        matches!(target, CallTarget::Indirect(_));
    }

    // --- Condition Tests ---

    #[test]
    fn test_condition_inverse() {
        assert_eq!(Condition::Equal.inverse(), Condition::NotEqual);
        assert_eq!(Condition::NotEqual.inverse(), Condition::Equal);
        assert_eq!(Condition::Above.inverse(), Condition::BelowOrEqual);
        assert_eq!(Condition::AboveOrEqual.inverse(), Condition::Below);
        assert_eq!(Condition::Below.inverse(), Condition::AboveOrEqual);
        assert_eq!(Condition::BelowOrEqual.inverse(), Condition::Above);
        assert_eq!(Condition::Greater.inverse(), Condition::LessOrEqual);
        assert_eq!(Condition::GreaterOrEqual.inverse(), Condition::Less);
        assert_eq!(Condition::Less.inverse(), Condition::GreaterOrEqual);
        assert_eq!(Condition::LessOrEqual.inverse(), Condition::Greater);
    }

    #[test]
    fn test_condition_inverse_idempotent() {
        // inverse(inverse(x)) == x
        let conditions = [
            Condition::Equal,
            Condition::NotEqual,
            Condition::Above,
            Condition::Below,
            Condition::Sign,
            Condition::Overflow,
            Condition::Parity,
            Condition::CounterZero,
        ];

        for cond in conditions {
            assert_eq!(cond.inverse().inverse(), cond);
        }
    }

    #[test]
    fn test_condition_x86_suffix() {
        assert_eq!(Condition::Equal.x86_suffix(), "e");
        assert_eq!(Condition::NotEqual.x86_suffix(), "ne");
        assert_eq!(Condition::Above.x86_suffix(), "a");
        assert_eq!(Condition::Below.x86_suffix(), "b");
        assert_eq!(Condition::Greater.x86_suffix(), "g");
        assert_eq!(Condition::Less.x86_suffix(), "l");
        assert_eq!(Condition::Sign.x86_suffix(), "s");
        assert_eq!(Condition::Overflow.x86_suffix(), "o");
    }
}
