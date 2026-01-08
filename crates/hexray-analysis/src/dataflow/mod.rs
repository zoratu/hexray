//! Data flow analysis framework.
//!
//! This module provides:
//! - Definition-Use (def-use) chains
//! - Reaching definitions analysis
//! - Liveness analysis
//! - Generic dataflow equation solver
//!
//! These analyses are fundamental for:
//! - Dead code elimination
//! - Constant propagation
//! - SSA construction
//! - Type inference

pub mod def_use;
pub mod liveness;
pub mod reaching_defs;

pub use def_use::{DefUseChain, DefUseInfo, Definition, Use};
pub use liveness::LivenessAnalysis;
pub use reaching_defs::ReachingDefinitions;

use hexray_core::{BasicBlockId, ControlFlowGraph, Instruction, Operand, Operation, Register};
use std::collections::{HashMap, HashSet};

/// A location (register or memory) that can be defined or used.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Location {
    /// A register.
    Register(u16),
    /// A stack slot at offset from frame pointer.
    Stack(i64),
    /// A global memory address.
    Memory(u64),
    /// CPU flags register.
    Flags,
}

impl Location {
    /// Creates a location from a register.
    pub fn from_register(reg: &Register) -> Self {
        Self::Register(reg.id)
    }

    /// Returns true if this is a register location.
    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(_))
    }
}

/// Information about what locations an instruction defines and uses.
#[derive(Debug, Clone, Default)]
pub struct InstructionEffects {
    /// Locations defined (written) by this instruction.
    pub defs: Vec<Location>,
    /// Locations used (read) by this instruction.
    pub uses: Vec<Location>,
}

impl InstructionEffects {
    /// Analyzes an instruction to determine its effects.
    pub fn from_instruction(inst: &Instruction) -> Self {
        let mut effects = Self::default();

        // Analyze operands based on instruction operation
        match inst.operation {
            // Move/Load: dest = src
            Operation::Move | Operation::Load | Operation::LoadEffectiveAddress => {
                if inst.operands.len() >= 2 {
                    effects.add_def(&inst.operands[0]);
                    effects.add_use(&inst.operands[1]);
                }
            }

            // Store: [mem] = src
            Operation::Store => {
                if inst.operands.len() >= 2 {
                    effects.add_memory_def(&inst.operands[1]);
                    effects.add_use(&inst.operands[0]);
                    // Also uses the address components
                    effects.add_address_uses(&inst.operands[1]);
                }
            }

            // Binary ops: dest = dest op src (or dest = src1 op src2)
            Operation::Add | Operation::Sub | Operation::Mul | Operation::Div |
            Operation::And | Operation::Or | Operation::Xor |
            Operation::Shl | Operation::Shr | Operation::Sar => {
                if inst.operands.len() >= 3 {
                    // Three-operand form: dest = src1 op src2
                    effects.add_def(&inst.operands[0]);
                    effects.add_use(&inst.operands[1]);
                    effects.add_use(&inst.operands[2]);
                } else if inst.operands.len() == 2 {
                    // Two-operand form: dest op= src
                    effects.add_def(&inst.operands[0]);
                    effects.add_use(&inst.operands[0]);
                    effects.add_use(&inst.operands[1]);
                }
                // These operations typically set flags
                effects.defs.push(Location::Flags);
            }

            // Unary ops: dest = op dest
            Operation::Neg | Operation::Not | Operation::Inc | Operation::Dec => {
                if !inst.operands.is_empty() {
                    effects.add_def(&inst.operands[0]);
                    effects.add_use(&inst.operands[0]);
                }
                effects.defs.push(Location::Flags);
            }

            // Compare: sets flags
            Operation::Compare | Operation::Test => {
                for op in &inst.operands {
                    effects.add_use(op);
                }
                effects.defs.push(Location::Flags);
            }

            // Branches use flags
            Operation::Jump | Operation::ConditionalJump => {
                effects.uses.push(Location::Flags);
                // Also uses target address if indirect
                for op in &inst.operands {
                    if let Operand::Register(reg) = op {
                        effects.uses.push(Location::from_register(reg));
                    }
                }
            }

            // Call: uses arguments, defines return value
            Operation::Call => {
                // TODO: ABI-specific handling
                // For now, conservatively assume it uses/defines common registers
                for op in &inst.operands {
                    effects.add_use(op);
                }
            }

            // Return: uses return value register
            Operation::Return => {
                // Architecture-specific; common return registers
            }

            // Push/Pop
            Operation::Push => {
                if !inst.operands.is_empty() {
                    effects.add_use(&inst.operands[0]);
                }
                // Also modifies stack pointer
            }
            Operation::Pop => {
                if !inst.operands.is_empty() {
                    effects.add_def(&inst.operands[0]);
                }
            }

            // Default: analyze operands heuristically
            _ => {
                // First operand is often destination
                if !inst.operands.is_empty() {
                    effects.add_def(&inst.operands[0]);
                }
                // Remaining operands are sources
                for op in inst.operands.iter().skip(1) {
                    effects.add_use(op);
                }
            }
        }

        effects
    }

    fn add_def(&mut self, operand: &Operand) {
        match operand {
            Operand::Register(reg) => {
                self.defs.push(Location::from_register(reg));
            }
            Operand::Memory(mem) => {
                // Memory write - can't easily track
                if let Some(ref base) = mem.base {
                    if is_stack_pointer(base.id) && mem.index.is_none() {
                        self.defs.push(Location::Stack(mem.displacement));
                    }
                }
            }
            _ => {}
        }
    }

    fn add_memory_def(&mut self, operand: &Operand) {
        if let Operand::Memory(mem) = operand {
            if let Some(ref base) = mem.base {
                if is_frame_pointer(base.id) && mem.index.is_none() {
                    self.defs.push(Location::Stack(mem.displacement));
                }
            }
        }
    }

    fn add_use(&mut self, operand: &Operand) {
        match operand {
            Operand::Register(reg) => {
                self.uses.push(Location::from_register(reg));
            }
            Operand::Memory(mem) => {
                // Memory read uses the address components
                self.add_address_uses(&Operand::Memory(mem.clone()));
                // And represents a use of the memory location
                if let Some(ref base) = mem.base {
                    if is_frame_pointer(base.id) && mem.index.is_none() {
                        self.uses.push(Location::Stack(mem.displacement));
                    }
                }
            }
            Operand::PcRelative { .. } => {
                // PC-relative doesn't use any register we track
            }
            Operand::Immediate(_) => {
                // Immediates don't use any locations
            }
        }
    }

    fn add_address_uses(&mut self, operand: &Operand) {
        if let Operand::Memory(mem) = operand {
            if let Some(ref base) = mem.base {
                self.uses.push(Location::from_register(base));
            }
            if let Some(ref index) = mem.index {
                self.uses.push(Location::from_register(index));
            }
        }
    }
}

/// Checks if a register ID is the stack pointer (architecture-specific).
fn is_stack_pointer(reg_id: u16) -> bool {
    // x86_64: RSP = 4, ARM64: SP = 31
    reg_id == 4 || reg_id == 31
}

/// Checks if a register ID is the frame pointer (architecture-specific).
fn is_frame_pointer(reg_id: u16) -> bool {
    // x86_64: RBP = 5, ARM64: FP (x29) = 29
    reg_id == 5 || reg_id == 29
}

/// Trait for dataflow analyses that compute per-block information.
pub trait DataflowAnalysis {
    /// The type of dataflow facts being computed.
    type Fact: Clone + Eq;

    /// Initial fact for the entry block.
    fn initial_fact(&self) -> Self::Fact;

    /// Computes the meet of multiple incoming facts.
    fn meet(&self, facts: Vec<&Self::Fact>) -> Self::Fact;

    /// Transfer function: computes output fact from input fact and block.
    fn transfer(&self, block_id: BasicBlockId, input: &Self::Fact, cfg: &ControlFlowGraph) -> Self::Fact;

    /// Whether this is a forward or backward analysis.
    fn is_forward(&self) -> bool;
}

/// Generic solver for dataflow equations.
pub struct DataflowSolver;

impl DataflowSolver {
    /// Solves a forward dataflow analysis.
    pub fn solve_forward<A: DataflowAnalysis>(
        analysis: &A,
        cfg: &ControlFlowGraph,
    ) -> HashMap<BasicBlockId, (A::Fact, A::Fact)> {
        let mut facts: HashMap<BasicBlockId, (A::Fact, A::Fact)> = HashMap::new();

        // Initialize
        let initial = analysis.initial_fact();
        for block_id in cfg.block_ids() {
            facts.insert(block_id, (initial.clone(), initial.clone()));
        }

        // Set entry block
        let entry_out = analysis.transfer(cfg.entry, &initial, cfg);
        facts.insert(cfg.entry, (initial.clone(), entry_out));

        // Iterate until fixpoint
        let rpo = cfg.reverse_post_order();
        let mut changed = true;

        while changed {
            changed = false;

            for &block_id in &rpo {
                if block_id == cfg.entry {
                    continue;
                }

                // Meet incoming facts from predecessors
                let preds = cfg.predecessors(block_id);
                let incoming: Vec<&A::Fact> = preds
                    .iter()
                    .filter_map(|&p| facts.get(&p).map(|(_, out)| out))
                    .collect();

                let input = if incoming.is_empty() {
                    analysis.initial_fact()
                } else {
                    analysis.meet(incoming)
                };

                // Apply transfer function
                let output = analysis.transfer(block_id, &input, cfg);

                // Check for changes
                let (old_in, old_out) = &facts[&block_id];
                if &input != old_in || &output != old_out {
                    changed = true;
                    facts.insert(block_id, (input, output));
                }
            }
        }

        facts
    }

    /// Solves a backward dataflow analysis.
    pub fn solve_backward<A: DataflowAnalysis>(
        analysis: &A,
        cfg: &ControlFlowGraph,
    ) -> HashMap<BasicBlockId, (A::Fact, A::Fact)> {
        let mut facts: HashMap<BasicBlockId, (A::Fact, A::Fact)> = HashMap::new();

        // Initialize all blocks
        let initial = analysis.initial_fact();
        for block_id in cfg.block_ids() {
            facts.insert(block_id, (initial.clone(), initial.clone()));
        }

        // Iterate until fixpoint (reverse order for backward analysis)
        let mut rpo = cfg.reverse_post_order();
        rpo.reverse();

        let mut changed = true;

        while changed {
            changed = false;

            for &block_id in &rpo {
                // Meet outgoing facts from successors
                let succs = cfg.successors(block_id);
                let outgoing: Vec<&A::Fact> = succs
                    .iter()
                    .filter_map(|&s| facts.get(&s).map(|(inp, _)| inp))
                    .collect();

                let output = if outgoing.is_empty() {
                    analysis.initial_fact()
                } else {
                    analysis.meet(outgoing)
                };

                // Apply transfer function (backward: output -> input)
                let input = analysis.transfer(block_id, &output, cfg);

                // Check for changes
                let (old_in, old_out) = &facts[&block_id];
                if &input != old_in || &output != old_out {
                    changed = true;
                    facts.insert(block_id, (input, output));
                }
            }
        }

        facts
    }
}
