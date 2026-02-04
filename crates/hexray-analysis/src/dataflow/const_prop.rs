//! Constant propagation analysis.
//!
//! This module implements constant propagation, a dataflow analysis that
//! tracks which registers/memory locations hold known constant values.
//!
//! This is useful for:
//! - Simplifying expressions with known values
//! - Detecting dead code (branches that always go one way)
//! - Improving decompiler output quality

use super::Location;
use hexray_core::{BasicBlockId, ControlFlowGraph, Instruction, Operand, Operation};
use std::collections::{HashMap, HashSet};

/// The value of a location in constant propagation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstValue {
    /// Unknown/undefined value.
    Unknown,
    /// A known constant value.
    Constant(i128),
    /// Value is not a constant (varies at runtime).
    NotConstant,
}

impl ConstValue {
    /// Merges two values (meet operation in the lattice).
    /// Unknown ⊓ x = x
    /// Constant(a) ⊓ Constant(a) = Constant(a)
    /// Constant(a) ⊓ Constant(b) = NotConstant (if a != b)
    /// NotConstant ⊓ x = NotConstant
    pub fn meet(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Unknown, x) | (x, Self::Unknown) => x.clone(),
            (Self::NotConstant, _) | (_, Self::NotConstant) => Self::NotConstant,
            (Self::Constant(a), Self::Constant(b)) => {
                if a == b {
                    Self::Constant(*a)
                } else {
                    Self::NotConstant
                }
            }
        }
    }

    /// Returns true if this is a known constant.
    pub fn is_constant(&self) -> bool {
        matches!(self, Self::Constant(_))
    }

    /// Returns the constant value if known.
    pub fn as_constant(&self) -> Option<i128> {
        match self {
            Self::Constant(v) => Some(*v),
            _ => None,
        }
    }
}

/// State at a program point: mapping from locations to their values.
#[derive(Debug, Clone, Default)]
pub struct ConstState {
    values: HashMap<Location, ConstValue>,
}

impl ConstState {
    /// Creates a new empty state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Gets the value of a location.
    pub fn get(&self, loc: &Location) -> ConstValue {
        self.values.get(loc).cloned().unwrap_or(ConstValue::Unknown)
    }

    /// Sets the value of a location.
    pub fn set(&mut self, loc: Location, value: ConstValue) {
        self.values.insert(loc, value);
    }

    /// Merges another state into this one.
    pub fn merge(&mut self, other: &Self) {
        // Merge all values from other
        for (loc, val) in &other.values {
            let current = self.get(loc);
            self.set(loc.clone(), current.meet(val));
        }
        // Mark any locations only in self as potentially different
        let other_locs: HashSet<_> = other.values.keys().cloned().collect();
        for loc in self.values.keys().cloned().collect::<Vec<_>>() {
            if !other_locs.contains(&loc) {
                let current = self.get(&loc);
                self.set(loc, current.meet(&ConstValue::Unknown));
            }
        }
    }

    /// Returns true if this state equals another (for fixed-point detection).
    pub fn equals(&self, other: &Self) -> bool {
        if self.values.len() != other.values.len() {
            return false;
        }
        for (loc, val) in &self.values {
            if other.get(loc) != *val {
                return false;
            }
        }
        true
    }

    /// Returns all locations with known constant values.
    pub fn constants(&self) -> impl Iterator<Item = (&Location, i128)> {
        self.values.iter().filter_map(|(loc, val)| {
            if let ConstValue::Constant(v) = val {
                Some((loc, *v))
            } else {
                None
            }
        })
    }
}

/// Constant propagation analysis.
pub struct ConstantPropagation {
    /// State at the entry of each block.
    block_entry: HashMap<BasicBlockId, ConstState>,
    /// State at the exit of each block.
    block_exit: HashMap<BasicBlockId, ConstState>,
}

impl ConstantPropagation {
    /// Runs constant propagation on a CFG.
    pub fn analyze(cfg: &ControlFlowGraph) -> Self {
        let mut analysis = Self {
            block_entry: HashMap::new(),
            block_exit: HashMap::new(),
        };

        // Initialize all states as empty (Unknown)
        for block_id in cfg.block_ids() {
            analysis.block_entry.insert(block_id, ConstState::new());
            analysis.block_exit.insert(block_id, ConstState::new());
        }

        // Worklist algorithm
        let mut worklist: Vec<BasicBlockId> = cfg.block_ids().collect();
        let mut changed = true;

        while changed {
            changed = false;
            let blocks: Vec<_> = std::mem::take(&mut worklist);

            for block_id in blocks {
                // Merge states from all predecessors
                let mut entry_state = ConstState::new();
                for pred_id in cfg.predecessors(block_id) {
                    if let Some(pred_exit) = analysis.block_exit.get(pred_id) {
                        entry_state.merge(pred_exit);
                    }
                }

                // Check if entry state changed
                let old_entry = analysis.block_entry.get(&block_id);
                if old_entry.map_or(true, |old| !old.equals(&entry_state)) {
                    analysis.block_entry.insert(block_id, entry_state.clone());
                }

                // Transfer function: propagate through block
                let exit_state = if let Some(block) = cfg.block(block_id) {
                    analysis.transfer_block(&block.instructions, entry_state)
                } else {
                    entry_state
                };

                // Check if exit state changed
                let old_exit = analysis.block_exit.get(&block_id);
                if old_exit.map_or(true, |old| !old.equals(&exit_state)) {
                    analysis.block_exit.insert(block_id, exit_state);
                    changed = true;

                    // Add successors to worklist
                    for succ_id in cfg.successors(block_id) {
                        if !worklist.contains(succ_id) {
                            worklist.push(*succ_id);
                        }
                    }
                }
            }
        }

        analysis
    }

    /// Transfer function for a block.
    fn transfer_block(&self, instructions: &[Instruction], mut state: ConstState) -> ConstState {
        for inst in instructions {
            self.transfer_instruction(inst, &mut state);
        }
        state
    }

    /// Transfer function for a single instruction.
    fn transfer_instruction(&self, inst: &Instruction, state: &mut ConstState) {
        match inst.operation {
            // Move: dest = src
            Operation::Move | Operation::Load => {
                if inst.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&inst.operands[0]) {
                        let src_val = self.evaluate_operand(&inst.operands[1], state);
                        state.set(dest_loc, src_val);
                    }
                }
            }

            // LEA: dest = address (immediate)
            Operation::LoadEffectiveAddress => {
                if inst.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&inst.operands[0]) {
                        // LEA typically loads an address, which we treat as an immediate
                        let src_val = self.evaluate_operand(&inst.operands[1], state);
                        state.set(dest_loc, src_val);
                    }
                }
            }

            // Binary operations
            Operation::Add
            | Operation::Sub
            | Operation::Mul
            | Operation::And
            | Operation::Or
            | Operation::Xor => {
                if inst.operands.len() >= 2 {
                    if let Some(dest_loc) = operand_to_location(&inst.operands[0]) {
                        // Evaluate both operands
                        let (left_val, right_val) = if inst.operands.len() >= 3 {
                            (
                                self.evaluate_operand(&inst.operands[1], state),
                                self.evaluate_operand(&inst.operands[2], state),
                            )
                        } else {
                            (
                                self.evaluate_operand(&inst.operands[0], state),
                                self.evaluate_operand(&inst.operands[1], state),
                            )
                        };

                        let result = self.evaluate_binary_op(inst.operation, left_val, right_val);
                        state.set(dest_loc, result);
                    }
                }
            }

            // Call: clobbers return register
            Operation::Call => {
                // Conservatively clobber common return registers
                state.set(Location::Register(0), ConstValue::NotConstant); // rax/x0
            }

            // Other operations: conservatively mark destination as non-constant
            _ => {
                if !inst.operands.is_empty() {
                    if let Some(dest_loc) = operand_to_location(&inst.operands[0]) {
                        state.set(dest_loc, ConstValue::NotConstant);
                    }
                }
            }
        }
    }

    /// Evaluates an operand to get its constant value.
    fn evaluate_operand(&self, operand: &Operand, state: &ConstState) -> ConstValue {
        match operand {
            Operand::Immediate(imm) => ConstValue::Constant(imm.value),
            Operand::Register(reg) => state.get(&Location::Register(reg.id)),
            Operand::Memory(_) => ConstValue::NotConstant, // Conservative for memory
            Operand::PcRelative { target, .. } => ConstValue::Constant(*target as i128),
        }
    }

    /// Evaluates a binary operation with known operand values.
    fn evaluate_binary_op(&self, op: Operation, left: ConstValue, right: ConstValue) -> ConstValue {
        match (left, right) {
            (ConstValue::Constant(l), ConstValue::Constant(r)) => {
                let result = match op {
                    Operation::Add => l.wrapping_add(r),
                    Operation::Sub => l.wrapping_sub(r),
                    Operation::Mul => l.wrapping_mul(r),
                    Operation::And => l & r,
                    Operation::Or => l | r,
                    Operation::Xor => l ^ r,
                    _ => return ConstValue::NotConstant,
                };
                ConstValue::Constant(result)
            }
            (ConstValue::Unknown, _) | (_, ConstValue::Unknown) => ConstValue::Unknown,
            _ => ConstValue::NotConstant,
        }
    }

    /// Gets the constant value of a location at block entry.
    pub fn get_at_entry(&self, block_id: BasicBlockId, loc: &Location) -> ConstValue {
        self.block_entry
            .get(&block_id)
            .map(|s| s.get(loc))
            .unwrap_or(ConstValue::Unknown)
    }

    /// Gets the constant value of a location at block exit.
    pub fn get_at_exit(&self, block_id: BasicBlockId, loc: &Location) -> ConstValue {
        self.block_exit
            .get(&block_id)
            .map(|s| s.get(loc))
            .unwrap_or(ConstValue::Unknown)
    }

    /// Returns all known constants at block entry.
    pub fn constants_at_entry(&self, block_id: BasicBlockId) -> Vec<(Location, i128)> {
        self.block_entry
            .get(&block_id)
            .map(|s| s.constants().map(|(l, v)| (l.clone(), v)).collect())
            .unwrap_or_default()
    }
}

/// Converts an operand to a location (if it's a register).
fn operand_to_location(operand: &Operand) -> Option<Location> {
    match operand {
        Operand::Register(reg) => Some(Location::Register(reg.id)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BasicBlockId, BlockTerminator, ControlFlowGraph, Immediate,
        Instruction, Operand, Operation, Register, RegisterClass,
    };

    // --- ConstValue Tests ---

    #[test]
    fn test_const_value_meet() {
        // Unknown meets anything = the other thing
        assert_eq!(
            ConstValue::Unknown.meet(&ConstValue::Constant(5)),
            ConstValue::Constant(5)
        );
        assert_eq!(
            ConstValue::Constant(5).meet(&ConstValue::Unknown),
            ConstValue::Constant(5)
        );

        // Same constants meet = same constant
        assert_eq!(
            ConstValue::Constant(5).meet(&ConstValue::Constant(5)),
            ConstValue::Constant(5)
        );

        // Different constants meet = not constant
        assert_eq!(
            ConstValue::Constant(5).meet(&ConstValue::Constant(10)),
            ConstValue::NotConstant
        );

        // NotConstant dominates
        assert_eq!(
            ConstValue::NotConstant.meet(&ConstValue::Constant(5)),
            ConstValue::NotConstant
        );
    }

    #[test]
    fn test_const_value_meet_unknown_unknown() {
        assert_eq!(
            ConstValue::Unknown.meet(&ConstValue::Unknown),
            ConstValue::Unknown
        );
    }

    #[test]
    fn test_const_value_meet_not_constant() {
        assert_eq!(
            ConstValue::NotConstant.meet(&ConstValue::NotConstant),
            ConstValue::NotConstant
        );
        assert_eq!(
            ConstValue::NotConstant.meet(&ConstValue::Unknown),
            ConstValue::NotConstant
        );
    }

    #[test]
    fn test_const_value_is_constant() {
        assert!(ConstValue::Constant(5).is_constant());
        assert!(ConstValue::Constant(0).is_constant());
        assert!(ConstValue::Constant(-1).is_constant());
        assert!(!ConstValue::Unknown.is_constant());
        assert!(!ConstValue::NotConstant.is_constant());
    }

    #[test]
    fn test_const_value_as_constant() {
        assert_eq!(ConstValue::Constant(42).as_constant(), Some(42));
        assert_eq!(ConstValue::Constant(-1).as_constant(), Some(-1));
        assert_eq!(ConstValue::Unknown.as_constant(), None);
        assert_eq!(ConstValue::NotConstant.as_constant(), None);
    }

    #[test]
    fn test_const_value_debug() {
        assert!(format!("{:?}", ConstValue::Unknown).contains("Unknown"));
        assert!(format!("{:?}", ConstValue::Constant(5)).contains("5"));
        assert!(format!("{:?}", ConstValue::NotConstant).contains("NotConstant"));
    }

    #[test]
    fn test_const_value_equality() {
        assert_eq!(ConstValue::Unknown, ConstValue::Unknown);
        assert_eq!(ConstValue::NotConstant, ConstValue::NotConstant);
        assert_eq!(ConstValue::Constant(5), ConstValue::Constant(5));
        assert_ne!(ConstValue::Constant(5), ConstValue::Constant(6));
        assert_ne!(ConstValue::Unknown, ConstValue::NotConstant);
    }

    // --- ConstState Tests ---

    #[test]
    fn test_const_state_new() {
        let state = ConstState::new();
        // Unknown for any location
        assert_eq!(state.get(&Location::Register(0)), ConstValue::Unknown);
    }

    #[test]
    fn test_const_state_set_get() {
        let mut state = ConstState::new();
        state.set(Location::Register(0), ConstValue::Constant(42));
        assert_eq!(state.get(&Location::Register(0)), ConstValue::Constant(42));
    }

    #[test]
    fn test_const_state_merge() {
        let mut state1 = ConstState::new();
        state1.set(Location::Register(0), ConstValue::Constant(5));
        state1.set(Location::Register(1), ConstValue::Constant(10));

        let mut state2 = ConstState::new();
        state2.set(Location::Register(0), ConstValue::Constant(5)); // Same
        state2.set(Location::Register(1), ConstValue::Constant(20)); // Different

        state1.merge(&state2);

        // Same constant stays constant
        assert_eq!(state1.get(&Location::Register(0)), ConstValue::Constant(5));
        // Different constants become NotConstant
        assert_eq!(state1.get(&Location::Register(1)), ConstValue::NotConstant);
    }

    #[test]
    fn test_const_state_merge_asymmetric() {
        let mut state1 = ConstState::new();
        state1.set(Location::Register(0), ConstValue::Constant(5));

        let mut state2 = ConstState::new();
        state2.set(Location::Register(1), ConstValue::Constant(10));

        state1.merge(&state2);

        // Location in both becomes meet with Unknown
        assert_eq!(state1.get(&Location::Register(0)), ConstValue::Constant(5));
        assert_eq!(state1.get(&Location::Register(1)), ConstValue::Constant(10));
    }

    #[test]
    fn test_const_state_equals() {
        let mut state1 = ConstState::new();
        state1.set(Location::Register(0), ConstValue::Constant(5));

        let mut state2 = ConstState::new();
        state2.set(Location::Register(0), ConstValue::Constant(5));

        assert!(state1.equals(&state2));

        state2.set(Location::Register(0), ConstValue::Constant(6));
        assert!(!state1.equals(&state2));
    }

    #[test]
    fn test_const_state_equals_different_sizes() {
        let mut state1 = ConstState::new();
        state1.set(Location::Register(0), ConstValue::Constant(5));

        let mut state2 = ConstState::new();
        state2.set(Location::Register(0), ConstValue::Constant(5));
        state2.set(Location::Register(1), ConstValue::Constant(6));

        assert!(!state1.equals(&state2));
    }

    #[test]
    fn test_const_state_constants_iterator() {
        let mut state = ConstState::new();
        state.set(Location::Register(0), ConstValue::Constant(5));
        state.set(Location::Register(1), ConstValue::NotConstant);
        state.set(Location::Register(2), ConstValue::Constant(10));

        let constants: Vec<_> = state.constants().collect();
        assert_eq!(constants.len(), 2);
    }

    // --- ConstantPropagation Tests ---

    fn make_register(id: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    fn make_mov_reg_imm(addr: u64, reg_id: u16, value: i128) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(reg_id)),
            Operand::Immediate(Immediate {
                value,
                size: 8,
                signed: false,
            }),
        ];
        inst
    }

    fn make_add_reg_imm(addr: u64, reg_id: u16, value: i128) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "add");
        inst.operation = Operation::Add;
        inst.operands = vec![
            Operand::Register(make_register(reg_id)),
            Operand::Immediate(Immediate {
                value,
                size: 8,
                signed: false,
            }),
        ];
        inst
    }

    #[test]
    fn test_constant_propagation_simple() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        bb.push_instruction(make_mov_reg_imm(0x1000, 0, 42));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let analysis = ConstantPropagation::analyze(&cfg);

        // rax should be 42 at exit
        assert_eq!(
            analysis.get_at_exit(BasicBlockId::new(0), &Location::Register(0)),
            ConstValue::Constant(42)
        );
    }

    #[test]
    fn test_constant_propagation_add() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        bb.push_instruction(make_mov_reg_imm(0x1000, 0, 10));
        bb.push_instruction(make_add_reg_imm(0x1003, 0, 5));
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let analysis = ConstantPropagation::analyze(&cfg);

        // rax should be 15 at exit
        assert_eq!(
            analysis.get_at_exit(BasicBlockId::new(0), &Location::Register(0)),
            ConstValue::Constant(15)
        );
    }

    #[test]
    fn test_constant_propagation_branch() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_reg_imm(0x1010, 0, 5));
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_mov_reg_imm(0x1020, 0, 10));
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let analysis = ConstantPropagation::analyze(&cfg);

        // At bb3 entry, rax has different values from different paths -> NotConstant
        assert_eq!(
            analysis.get_at_entry(BasicBlockId::new(3), &Location::Register(0)),
            ConstValue::NotConstant
        );
    }

    #[test]
    fn test_constant_propagation_same_value_branch() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_reg_imm(0x1010, 0, 42)); // same value
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_mov_reg_imm(0x1020, 0, 42)); // same value
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let analysis = ConstantPropagation::analyze(&cfg);

        // At bb3 entry, rax has same value from both paths -> still Constant
        assert_eq!(
            analysis.get_at_entry(BasicBlockId::new(3), &Location::Register(0)),
            ConstValue::Constant(42)
        );
    }

    #[test]
    fn test_constant_propagation_constants_at_entry() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        bb.push_instruction(make_mov_reg_imm(0x1000, 0, 1));
        bb.push_instruction(make_mov_reg_imm(0x1003, 1, 2));
        bb.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let analysis = ConstantPropagation::analyze(&cfg);

        let constants = analysis.constants_at_entry(BasicBlockId::new(1));
        assert!(constants
            .iter()
            .any(|(loc, val)| *loc == Location::Register(0) && *val == 1));
        assert!(constants
            .iter()
            .any(|(loc, val)| *loc == Location::Register(1) && *val == 2));
    }

    #[test]
    fn test_constant_propagation_call_clobbers() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        bb.push_instruction(make_mov_reg_imm(0x1000, 0, 42));

        // Call instruction
        let mut call_inst = Instruction::new(0x1003, 5, vec![0; 5], "call");
        call_inst.operation = Operation::Call;
        call_inst.operands = vec![Operand::Immediate(Immediate {
            value: 0x2000,
            size: 8,
            signed: false,
        })];
        bb.push_instruction(call_inst);

        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let analysis = ConstantPropagation::analyze(&cfg);

        // rax should be NotConstant after call (return value register)
        assert_eq!(
            analysis.get_at_exit(BasicBlockId::new(0), &Location::Register(0)),
            ConstValue::NotConstant
        );
    }

    // --- operand_to_location Tests ---

    #[test]
    fn test_operand_to_location_register() {
        let reg = make_register(5);
        let loc = operand_to_location(&Operand::Register(reg));
        assert_eq!(loc, Some(Location::Register(5)));
    }

    #[test]
    fn test_operand_to_location_immediate() {
        let imm = Immediate {
            value: 42,
            size: 8,
            signed: false,
        };
        let loc = operand_to_location(&Operand::Immediate(imm));
        assert_eq!(loc, None);
    }
}
