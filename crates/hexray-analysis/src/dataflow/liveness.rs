//! Liveness analysis.
//!
//! Liveness analysis computes, for each program point, which variables are
//! "live" - that is, may be used before being redefined.
//!
//! This is a backward dataflow analysis where:
//! - Meet: union (a variable is live if it's live on any successor path)
//! - Transfer: use ∪ (out - def)
//!
//! Liveness is fundamental for:
//! - Register allocation
//! - Dead code elimination
//! - SSA construction (placing phi nodes)

use super::{DataflowAnalysis, DataflowSolver, InstructionEffects, Location};
use hexray_core::{BasicBlockId, ControlFlowGraph};
use std::collections::{HashMap, HashSet};

/// The liveness fact: set of live locations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LivenessFact {
    /// Set of live locations at this program point.
    pub live: HashSet<Location>,
}

impl LivenessFact {
    /// Returns true if a location is live.
    pub fn is_live(&self, loc: &Location) -> bool {
        self.live.contains(loc)
    }

    /// Returns an iterator over live locations.
    pub fn iter(&self) -> impl Iterator<Item = &Location> {
        self.live.iter()
    }
}

/// Liveness analysis.
pub struct LivenessAnalysis {
    /// Use sets: locations used by each block.
    use_sets: HashMap<BasicBlockId, HashSet<Location>>,
    /// Def sets: locations defined by each block.
    def_sets: HashMap<BasicBlockId, HashSet<Location>>,
}

impl LivenessAnalysis {
    /// Creates a new liveness analysis.
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let mut use_sets: HashMap<BasicBlockId, HashSet<Location>> = HashMap::new();
        let mut def_sets: HashMap<BasicBlockId, HashSet<Location>> = HashMap::new();

        for block in cfg.blocks() {
            let mut block_use = HashSet::new();
            let mut block_def = HashSet::new();

            // Process instructions in order
            // A use is upward-exposed if not preceded by a def in the same block
            for inst in &block.instructions {
                let effects = InstructionEffects::from_instruction(inst);

                // Uses that aren't killed by a prior def in this block
                for loc in effects.uses {
                    if !block_def.contains(&loc) {
                        block_use.insert(loc);
                    }
                }

                // Add defs
                for loc in effects.defs {
                    block_def.insert(loc);
                }
            }

            use_sets.insert(block.id, block_use);
            def_sets.insert(block.id, block_def);
        }

        Self { use_sets, def_sets }
    }

    /// Runs the analysis and returns liveness at each block.
    ///
    /// Returns (live_in, live_out) for each block.
    pub fn analyze(
        cfg: &ControlFlowGraph,
    ) -> HashMap<BasicBlockId, (LivenessFact, LivenessFact)> {
        let analysis = Self::new(cfg);
        DataflowSolver::solve_backward(&analysis, cfg)
    }

    /// Returns the live variables at a specific instruction within a block.
    ///
    /// This computes liveness right before the instruction executes.
    pub fn at_instruction(
        facts: &HashMap<BasicBlockId, (LivenessFact, LivenessFact)>,
        cfg: &ControlFlowGraph,
        block_id: BasicBlockId,
        inst_index: usize,
    ) -> LivenessFact {
        let block = match cfg.block(block_id) {
            Some(b) => b,
            None => return LivenessFact::default(),
        };

        let (_, output) = match facts.get(&block_id) {
            Some(f) => f,
            None => return LivenessFact::default(),
        };

        // Start from live-out and work backwards
        let mut current = output.live.clone();

        // Process instructions from end to target
        for idx in (inst_index..block.instructions.len()).rev() {
            let inst = &block.instructions[idx];
            let effects = InstructionEffects::from_instruction(inst);

            // Remove defs (they're not live before this point)
            for loc in &effects.defs {
                current.remove(loc);
            }

            // Add uses (they are live before this point)
            for loc in effects.uses {
                current.insert(loc);
            }
        }

        LivenessFact { live: current }
    }

    /// Returns locations that are live across the entire function (never die).
    pub fn always_live(
        facts: &HashMap<BasicBlockId, (LivenessFact, LivenessFact)>,
    ) -> HashSet<Location> {
        let mut always_live: Option<HashSet<Location>> = None;

        for (_, (live_in, live_out)) in facts {
            let combined: HashSet<Location> = live_in.live
                .union(&live_out.live)
                .cloned()
                .collect();

            always_live = Some(match always_live {
                None => combined,
                Some(prev) => prev.intersection(&combined).cloned().collect(),
            });
        }

        always_live.unwrap_or_default()
    }

    /// Computes live ranges for each location.
    ///
    /// Returns a map from location to the set of (block, instruction_index) pairs
    /// where the location is live.
    pub fn live_ranges(
        facts: &HashMap<BasicBlockId, (LivenessFact, LivenessFact)>,
        cfg: &ControlFlowGraph,
    ) -> HashMap<Location, Vec<(BasicBlockId, usize)>> {
        let mut ranges: HashMap<Location, Vec<(BasicBlockId, usize)>> = HashMap::new();

        for block in cfg.blocks() {
            for (idx, _) in block.instructions.iter().enumerate() {
                let live_here = Self::at_instruction(facts, cfg, block.id, idx);

                for loc in live_here.live {
                    ranges.entry(loc)
                        .or_default()
                        .push((block.id, idx));
                }
            }
        }

        ranges
    }
}

impl DataflowAnalysis for LivenessAnalysis {
    type Fact = LivenessFact;

    fn initial_fact(&self) -> Self::Fact {
        LivenessFact::default()
    }

    fn meet(&self, facts: Vec<&Self::Fact>) -> Self::Fact {
        // Union of all live variables
        let mut result = LivenessFact::default();

        for fact in facts {
            result.live.extend(fact.live.iter().cloned());
        }

        result
    }

    fn transfer(
        &self,
        block_id: BasicBlockId,
        input: &Self::Fact,  // This is live-out for backward analysis
        _cfg: &ControlFlowGraph,
    ) -> Self::Fact {
        let mut output = input.clone();  // Output is live-in

        // Remove definitions (they're not live before the block)
        if let Some(defs) = self.def_sets.get(&block_id) {
            for loc in defs {
                output.live.remove(loc);
            }
        }

        // Add uses (they are live before the block)
        if let Some(uses) = self.use_sets.get(&block_id) {
            output.live.extend(uses.iter().cloned());
        }

        output
    }

    fn is_forward(&self) -> bool {
        false  // Backward analysis
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, ControlFlowGraph, Instruction, Operation, Operand, Register, RegisterClass, BlockTerminator, Architecture};

    fn make_register(id: u16, _name: &str) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    fn make_mov(addr: u64, dst_id: u16, dst_name: &str, src_id: u16, src_name: &str) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(dst_id, dst_name)),
            Operand::Register(make_register(src_id, src_name)),
        ];
        inst
    }

    #[allow(dead_code)]
    fn make_add(addr: u64, dst_id: u16, dst_name: &str, src_id: u16, src_name: &str) -> Instruction {
        let mut inst = Instruction::new(addr, 3, vec![0; 3], "add");
        inst.operation = Operation::Add;
        inst.operands = vec![
            Operand::Register(make_register(dst_id, dst_name)),
            Operand::Register(make_register(src_id, src_name)),
        ];
        inst
    }

    #[test]
    fn test_liveness_simple() {
        // rax = rbx      ; uses rbx
        // rcx = rax      ; uses rax, defs rcx
        // return         ; rax dead after line 1
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        bb.push_instruction(make_mov(0x1000, 0, "rax", 1, "rbx"));  // rax = rbx
        bb.push_instruction(make_mov(0x1003, 2, "rcx", 0, "rax"));  // rcx = rax
        bb.terminator = BlockTerminator::Return;

        cfg.add_block(bb);

        let facts = LivenessAnalysis::analyze(&cfg);
        let (live_in, _) = &facts[&BasicBlockId::new(0)];

        // At entry, rbx should be live (it's used before being defined)
        assert!(live_in.is_live(&Location::Register(1)));  // rbx

        // rax should not be live at entry (it's defined before use)
        assert!(!live_in.is_live(&Location::Register(0)));
    }

    #[test]
    fn test_liveness_across_blocks() {
        // bb0: rax = 1    -> bb1
        // bb1: rbx = rax  ; rax live at entry to bb1
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        let mut inst1 = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst1.operation = Operation::Move;
        inst1.operands = vec![
            Operand::Register(make_register(0, "rax")),
            Operand::Immediate(hexray_core::Immediate { value: 1, size: 8, signed: false }),
        ];
        bb0.push_instruction(inst1);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.push_instruction(make_mov(0x1010, 1, "rbx", 0, "rax"));
        bb1.terminator = BlockTerminator::Return;
        cfg.add_block(bb1);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let facts = LivenessAnalysis::analyze(&cfg);

        // rax should be live at exit of bb0 (used in bb1)
        let (_, live_out_0) = &facts[&BasicBlockId::new(0)];
        assert!(live_out_0.is_live(&Location::Register(0)));

        // rax should be live at entry to bb1
        let (live_in_1, _) = &facts[&BasicBlockId::new(1)];
        assert!(live_in_1.is_live(&Location::Register(0)));
    }

    #[test]
    fn test_dead_code_detection() {
        // rax = 1  ; rax is dead (not used)
        // return
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        let mut inst = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst.operation = Operation::Move;
        inst.operands = vec![
            Operand::Register(make_register(0, "rax")),
            Operand::Immediate(hexray_core::Immediate { value: 1, size: 8, signed: false }),
        ];
        bb.push_instruction(inst);
        bb.terminator = BlockTerminator::Return;

        cfg.add_block(bb);

        let facts = LivenessAnalysis::analyze(&cfg);

        // After the instruction, rax is dead (not used anywhere)
        let (_, live_out) = &facts[&BasicBlockId::new(0)];
        assert!(!live_out.is_live(&Location::Register(0)));
    }
}
