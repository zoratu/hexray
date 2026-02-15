//! Data flow analysis framework.
//!
//! This module provides:
//! - Definition-Use (def-use) chains
//! - Reaching definitions analysis
//! - Liveness analysis
//! - Generic dataflow equation solver
//! - Interactive data flow queries (backward/forward slicing)
//!
//! These analyses are fundamental for:
//! - Dead code elimination
//! - Constant propagation
//! - SSA construction
//! - Type inference
//! - Understanding data dependencies

pub mod const_prop;
pub mod def_use;
pub mod liveness;
pub mod queries;
pub mod reaching_defs;

pub use const_prop::{ConstState, ConstValue, ConstantPropagation};
pub use def_use::{DefId, DefUseChain, DefUseInfo, Definition, Use};
pub use liveness::LivenessAnalysis;
pub use queries::{DataFlowQuery, DataFlowQueryEngine, DataFlowResult, DataFlowRole, DataFlowStep};
pub use reaching_defs::ReachingDefinitions;

use hexray_core::{
    register::{arm64, riscv, x86},
    Architecture, BasicBlockId, ControlFlowGraph, Instruction, Operand, Operation, Register,
};
use std::collections::HashMap;

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
            Operation::Add
            | Operation::Sub
            | Operation::Mul
            | Operation::Div
            | Operation::And
            | Operation::Or
            | Operation::Xor
            | Operation::Shl
            | Operation::Shr
            | Operation::Sar => {
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
                for op in &inst.operands {
                    effects.add_use(op);
                }
                effects.add_call_abi_effects(inst);
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

    fn add_call_abi_effects(&mut self, inst: &Instruction) {
        let Some(arch) = infer_arch_from_operands(inst) else {
            return;
        };

        match arch {
            Architecture::X86_64 | Architecture::X86 => {
                // SysV-style integer argument registers.
                for reg in [x86::RDI, x86::RSI, x86::RDX, x86::RCX, x86::R8, x86::R9] {
                    self.uses.push(Location::Register(reg));
                }
                // Caller-saved GPRs + return register.
                for reg in [
                    x86::RAX,
                    x86::RCX,
                    x86::RDX,
                    x86::RSI,
                    x86::RDI,
                    x86::R8,
                    x86::R9,
                    x86::R10,
                    x86::R11,
                ] {
                    self.defs.push(Location::Register(reg));
                }
            }
            Architecture::Arm64 => {
                // AArch64 AAPCS argument registers x0-x7.
                for reg in arm64::X0..=7 {
                    self.uses.push(Location::Register(reg));
                }
                // Caller-saved x0-x17 (x0 is return value).
                for reg in arm64::X0..=17 {
                    self.defs.push(Location::Register(reg));
                }
            }
            Architecture::RiscV64 | Architecture::RiscV32 => {
                // RISC-V a0-a7 arguments.
                for reg in riscv::X10..=riscv::X17 {
                    self.uses.push(Location::Register(reg));
                }
                // Caller-saved: ra, t0-t6, a0-a7.
                for reg in [
                    riscv::X1,
                    riscv::X5,
                    riscv::X6,
                    riscv::X7,
                    riscv::X10,
                    riscv::X11,
                    riscv::X12,
                    riscv::X13,
                    riscv::X14,
                    riscv::X15,
                    riscv::X16,
                    riscv::X17,
                    riscv::X28,
                    riscv::X29,
                    riscv::X30,
                    riscv::X31,
                ] {
                    self.defs.push(Location::Register(reg));
                }
            }
            _ => {}
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

fn infer_arch_from_operands(inst: &Instruction) -> Option<Architecture> {
    fn arch_from_operand(op: &Operand) -> Option<Architecture> {
        match op {
            Operand::Register(r) => Some(r.arch),
            Operand::Memory(mem) => mem
                .base
                .as_ref()
                .map(|r| r.arch)
                .or_else(|| mem.index.as_ref().map(|r| r.arch)),
            _ => None,
        }
    }

    inst.operands.iter().find_map(arch_from_operand)
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
    fn transfer(
        &self,
        block_id: BasicBlockId,
        input: &Self::Fact,
        cfg: &ControlFlowGraph,
    ) -> Self::Fact;

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

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{
        Architecture, BasicBlock, BlockTerminator, Immediate, IndexMode, Instruction, MemoryRef,
        Operand, Operation, Register, RegisterClass,
    };

    // --- Location Tests ---

    #[test]
    fn test_location_from_register() {
        let reg = Register::new(Architecture::X86_64, RegisterClass::General, 0, 64);
        let loc = Location::from_register(&reg);
        assert_eq!(loc, Location::Register(0));
    }

    #[test]
    fn test_location_is_register() {
        assert!(Location::Register(0).is_register());
        assert!(!Location::Stack(0).is_register());
        assert!(!Location::Memory(0x1000).is_register());
        assert!(!Location::Flags.is_register());
    }

    #[test]
    fn test_location_equality() {
        assert_eq!(Location::Register(0), Location::Register(0));
        assert_ne!(Location::Register(0), Location::Register(1));
        assert_eq!(Location::Stack(-8), Location::Stack(-8));
        assert_ne!(Location::Stack(-8), Location::Stack(-16));
        assert_eq!(Location::Memory(0x1000), Location::Memory(0x1000));
        assert_eq!(Location::Flags, Location::Flags);
    }

    #[test]
    fn test_location_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Location::Register(0));
        set.insert(Location::Register(1));
        set.insert(Location::Stack(-8));
        set.insert(Location::Flags);

        assert!(set.contains(&Location::Register(0)));
        assert!(set.contains(&Location::Register(1)));
        assert!(set.contains(&Location::Stack(-8)));
        assert!(set.contains(&Location::Flags));
        assert!(!set.contains(&Location::Register(2)));
    }

    #[test]
    fn test_location_debug() {
        assert!(format!("{:?}", Location::Register(0)).contains("Register"));
        assert!(format!("{:?}", Location::Stack(-8)).contains("Stack"));
        assert!(format!("{:?}", Location::Memory(0x1000)).contains("Memory"));
        assert!(format!("{:?}", Location::Flags).contains("Flags"));
    }

    // --- InstructionEffects Tests ---

    fn make_register(id: u16) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    fn make_mov_reg_reg(dst_id: u16, src_id: u16) -> Instruction {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(dst_id)),
            Operand::Register(make_register(src_id)),
        ];
        inst
    }

    fn make_mov_reg_imm(dst_id: u16, value: i128) -> Instruction {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(dst_id)),
            Operand::Immediate(Immediate {
                value,
                size: 8,
                signed: false,
            }),
        ];
        inst
    }

    fn make_add_reg_reg(dst_id: u16, src_id: u16) -> Instruction {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "add");
        inst.operation = Operation::Add;
        inst.operands = vec![
            Operand::Register(make_register(dst_id)),
            Operand::Register(make_register(src_id)),
        ];
        inst
    }

    #[test]
    fn test_instruction_effects_mov_reg_reg() {
        let inst = make_mov_reg_reg(0, 1);
        let effects = InstructionEffects::from_instruction(&inst);

        assert!(effects.defs.contains(&Location::Register(0)));
        assert!(effects.uses.contains(&Location::Register(1)));
    }

    #[test]
    fn test_instruction_effects_mov_reg_imm() {
        let inst = make_mov_reg_imm(0, 42);
        let effects = InstructionEffects::from_instruction(&inst);

        assert!(effects.defs.contains(&Location::Register(0)));
        // Immediate doesn't add a use
        assert!(!effects
            .uses
            .iter()
            .any(|l| matches!(l, Location::Register(_))));
    }

    #[test]
    fn test_instruction_effects_add() {
        let inst = make_add_reg_reg(0, 1);
        let effects = InstructionEffects::from_instruction(&inst);

        // Add: dst = dst + src
        assert!(effects.defs.contains(&Location::Register(0)));
        assert!(effects.defs.contains(&Location::Flags)); // add sets flags
        assert!(effects.uses.contains(&Location::Register(0)));
        assert!(effects.uses.contains(&Location::Register(1)));
    }

    #[test]
    fn test_instruction_effects_cmp() {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "cmp");
        inst.operation = Operation::Compare;
        inst.operands = vec![
            Operand::Register(make_register(0)),
            Operand::Register(make_register(1)),
        ];

        let effects = InstructionEffects::from_instruction(&inst);

        // Compare only uses operands and defines flags
        assert!(effects.uses.contains(&Location::Register(0)));
        assert!(effects.uses.contains(&Location::Register(1)));
        assert!(effects.defs.contains(&Location::Flags));
    }

    #[test]
    fn test_instruction_effects_push() {
        let mut inst = Instruction::new(0x1000, 1, vec![0], "push");
        inst.operation = Operation::Push;
        inst.operands = vec![Operand::Register(make_register(0))];

        let effects = InstructionEffects::from_instruction(&inst);

        assert!(effects.uses.contains(&Location::Register(0)));
    }

    #[test]
    fn test_instruction_effects_pop() {
        let mut inst = Instruction::new(0x1000, 1, vec![0], "pop");
        inst.operation = Operation::Pop;
        inst.operands = vec![Operand::Register(make_register(0))];

        let effects = InstructionEffects::from_instruction(&inst);

        assert!(effects.defs.contains(&Location::Register(0)));
    }

    #[test]
    fn test_instruction_effects_store() {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst.operation = Operation::Store;
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64); // RBP
        inst.operands = vec![
            Operand::Register(make_register(0)), // source value
            Operand::Memory(MemoryRef {
                base: Some(rbp),
                index: None,
                scale: 1,
                displacement: -8,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
            }),
        ];

        let effects = InstructionEffects::from_instruction(&inst);

        // Store uses the source register
        assert!(effects.uses.contains(&Location::Register(0)));
        // Store uses the base register for address
        assert!(effects.uses.contains(&Location::Register(5)));
        // Store defines the stack slot
        assert!(effects.defs.contains(&Location::Stack(-8)));
    }

    #[test]
    fn test_instruction_effects_load() {
        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst.operation = Operation::Load;
        let rbp = Register::new(Architecture::X86_64, RegisterClass::General, 5, 64);
        inst.operands = vec![
            Operand::Register(make_register(0)), // destination
            Operand::Memory(MemoryRef {
                base: Some(rbp),
                index: None,
                scale: 1,
                displacement: -8,
                size: 8,
                segment: None,
                broadcast: false,
                index_mode: IndexMode::None,
            }),
        ];

        let effects = InstructionEffects::from_instruction(&inst);

        // Load defines the destination register
        assert!(effects.defs.contains(&Location::Register(0)));
        // Load uses the base register and memory location
        assert!(effects.uses.contains(&Location::Register(5)));
        assert!(effects.uses.contains(&Location::Stack(-8)));
    }

    #[test]
    fn test_instruction_effects_neg() {
        let mut inst = Instruction::new(0x1000, 2, vec![0; 2], "neg");
        inst.operation = Operation::Neg;
        inst.operands = vec![Operand::Register(make_register(0))];

        let effects = InstructionEffects::from_instruction(&inst);

        // Unary op: uses and defines the operand
        assert!(effects.defs.contains(&Location::Register(0)));
        assert!(effects.uses.contains(&Location::Register(0)));
        assert!(effects.defs.contains(&Location::Flags));
    }

    #[test]
    fn test_instruction_effects_call() {
        let mut inst = Instruction::new(0x1000, 5, vec![0; 5], "call");
        inst.operation = Operation::Call;
        inst.operands = vec![Operand::Immediate(Immediate {
            value: 0x2000,
            size: 8,
            signed: false,
        })];

        let effects = InstructionEffects::from_instruction(&inst);

        // Call uses the target (but immediate doesn't add Location)
        // The instruction doesn't define anything in our conservative analysis
        assert!(
            effects.uses.is_empty()
                || effects
                    .uses
                    .iter()
                    .all(|l| !matches!(l, Location::Register(_)))
        );
    }

    #[test]
    fn test_instruction_effects_call_abi_x86_64() {
        let mut inst = Instruction::new(0x1000, 2, vec![0xff, 0xd0], "call");
        inst.operation = Operation::Call;
        let target = Register::new(Architecture::X86_64, RegisterClass::General, x86::RAX, 64);
        inst.operands = vec![Operand::Register(target)];

        let effects = InstructionEffects::from_instruction(&inst);

        assert!(effects.uses.contains(&Location::Register(x86::RDI)));
        assert!(effects.uses.contains(&Location::Register(x86::RSI)));
        assert!(effects.defs.contains(&Location::Register(x86::RAX)));
        assert!(effects.defs.contains(&Location::Register(x86::R11)));
    }

    #[test]
    fn test_instruction_effects_default() {
        assert!(InstructionEffects::default().defs.is_empty());
        assert!(InstructionEffects::default().uses.is_empty());
    }

    // --- is_stack_pointer / is_frame_pointer Tests ---

    #[test]
    fn test_is_stack_pointer() {
        // x86_64 RSP = 4
        assert!(is_stack_pointer(4));
        // ARM64 SP = 31
        assert!(is_stack_pointer(31));
        // Other registers are not stack pointers
        assert!(!is_stack_pointer(0));
        assert!(!is_stack_pointer(5));
    }

    #[test]
    fn test_is_frame_pointer() {
        // x86_64 RBP = 5
        assert!(is_frame_pointer(5));
        // ARM64 FP (x29) = 29
        assert!(is_frame_pointer(29));
        // Other registers are not frame pointers
        assert!(!is_frame_pointer(0));
        assert!(!is_frame_pointer(4));
    }

    // --- DataflowSolver Tests ---

    // Simple analysis for testing: counts instructions
    #[derive(Clone, PartialEq, Eq, Debug)]
    struct CountFact(usize);

    struct CountAnalysis;

    impl DataflowAnalysis for CountAnalysis {
        type Fact = CountFact;

        fn initial_fact(&self) -> Self::Fact {
            CountFact(0)
        }

        fn meet(&self, facts: Vec<&Self::Fact>) -> Self::Fact {
            let max = facts.iter().map(|f| f.0).max().unwrap_or(0);
            CountFact(max)
        }

        fn transfer(
            &self,
            block_id: BasicBlockId,
            input: &Self::Fact,
            cfg: &ControlFlowGraph,
        ) -> Self::Fact {
            let block_count = cfg
                .block(block_id)
                .map(|b| b.instructions.len())
                .unwrap_or(0);
            CountFact(input.0 + block_count)
        }

        fn is_forward(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_dataflow_solver_forward_linear() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(make_mov_reg_imm(0, 1));
        bb0.push_instruction(make_mov_reg_imm(1, 2));
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_reg_imm(2, 3));
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let analysis = CountAnalysis;
        let results = DataflowSolver::solve_forward(&analysis, &cfg);

        // bb0: entry=0, exit=2 (2 instructions)
        let (bb0_in, bb0_out) = &results[&BasicBlockId::new(0)];
        assert_eq!(bb0_in.0, 0);
        assert_eq!(bb0_out.0, 2);

        // bb1: entry=2, exit=3 (1 instruction)
        let (bb1_in, bb1_out) = &results[&BasicBlockId::new(1)];
        assert_eq!(bb1_in.0, 2);
        assert_eq!(bb1_out.0, 3);
    }

    #[test]
    fn test_dataflow_solver_forward_diamond() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(make_mov_reg_imm(0, 1));
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_reg_imm(1, 2));
        bb1.push_instruction(make_mov_reg_imm(2, 3));
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.push_instruction(make_mov_reg_imm(1, 4));
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

        let analysis = CountAnalysis;
        let results = DataflowSolver::solve_forward(&analysis, &cfg);

        // bb3: entry should be max of (1+2=3, 1+1=2) = 3
        let (bb3_in, _) = &results[&BasicBlockId::new(3)];
        assert_eq!(bb3_in.0, 3);
    }

    // Backward analysis for testing
    struct BackwardCountAnalysis;

    impl DataflowAnalysis for BackwardCountAnalysis {
        type Fact = CountFact;

        fn initial_fact(&self) -> Self::Fact {
            CountFact(0)
        }

        fn meet(&self, facts: Vec<&Self::Fact>) -> Self::Fact {
            let max = facts.iter().map(|f| f.0).max().unwrap_or(0);
            CountFact(max)
        }

        fn transfer(
            &self,
            block_id: BasicBlockId,
            input: &Self::Fact,
            cfg: &ControlFlowGraph,
        ) -> Self::Fact {
            let block_count = cfg
                .block(block_id)
                .map(|b| b.instructions.len())
                .unwrap_or(0);
            CountFact(input.0 + block_count)
        }

        fn is_forward(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_dataflow_solver_backward() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.push_instruction(make_mov_reg_imm(0, 1));
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov_reg_imm(1, 2));
        bb1.push_instruction(make_mov_reg_imm(2, 3));
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let analysis = BackwardCountAnalysis;
        let results = DataflowSolver::solve_backward(&analysis, &cfg);

        // For backward analysis, bb1 starts with 0 (exit) and adds 2
        // bb0 gets bb1's input (2) and adds 1
        let (bb0_in, _) = &results[&BasicBlockId::new(0)];
        assert_eq!(bb0_in.0, 3); // 0 + 2 + 1
    }

    #[test]
    fn test_dataflow_solver_empty_cfg() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let analysis = CountAnalysis;
        let results = DataflowSolver::solve_forward(&analysis, &cfg);

        assert!(results.contains_key(&BasicBlockId::new(0)));
    }
}
