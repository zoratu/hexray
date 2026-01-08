//! Definition-Use (def-use) chain analysis.
//!
//! Def-use chains connect each definition of a variable to all its uses,
//! enabling optimizations like dead code elimination and constant propagation.

use super::{InstructionEffects, Location};
use hexray_core::{BasicBlockId, ControlFlowGraph};
use std::collections::{HashMap, HashSet};

/// A unique identifier for a definition point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DefId(pub u32);

/// A definition of a location at a specific program point.
#[derive(Debug, Clone)]
pub struct Definition {
    /// Unique ID for this definition.
    pub id: DefId,
    /// The block containing this definition.
    pub block: BasicBlockId,
    /// Index of the instruction within the block.
    pub inst_index: usize,
    /// Address of the defining instruction.
    pub address: u64,
    /// The location being defined.
    pub location: Location,
}

/// A use of a location at a specific program point.
#[derive(Debug, Clone)]
pub struct Use {
    /// The block containing this use.
    pub block: BasicBlockId,
    /// Index of the instruction within the block.
    pub inst_index: usize,
    /// Address of the using instruction.
    pub address: u64,
    /// The location being used.
    pub location: Location,
    /// Definitions that reach this use.
    pub reaching_defs: Vec<DefId>,
}

/// Complete def-use chain information for a CFG.
#[derive(Debug)]
pub struct DefUseChain {
    /// All definitions in the CFG.
    pub definitions: HashMap<DefId, Definition>,
    /// All uses in the CFG.
    pub uses: Vec<Use>,
    /// Maps each definition to its uses.
    pub def_to_uses: HashMap<DefId, Vec<usize>>,
    /// Maps each use index to its reaching definitions.
    pub use_to_defs: HashMap<usize, Vec<DefId>>,
    /// Definitions indexed by location.
    pub defs_by_location: HashMap<Location, Vec<DefId>>,
}

impl DefUseChain {
    /// Builds def-use chains for a CFG.
    pub fn build(cfg: &ControlFlowGraph) -> Self {
        let mut builder = DefUseChainBuilder::new();
        builder.build(cfg);
        builder.into_chain()
    }

    /// Returns all definitions that reach a specific use.
    pub fn definitions_for_use(&self, use_index: usize) -> Vec<&Definition> {
        self.use_to_defs
            .get(&use_index)
            .map(|defs| {
                defs.iter()
                    .filter_map(|id| self.definitions.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all uses of a specific definition.
    pub fn uses_of_definition(&self, def_id: DefId) -> Vec<&Use> {
        self.def_to_uses
            .get(&def_id)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&i| self.uses.get(i))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns all definitions of a location.
    pub fn definitions_of(&self, location: &Location) -> Vec<&Definition> {
        self.defs_by_location
            .get(location)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.definitions.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Returns true if a definition has any uses (is not dead).
    pub fn has_uses(&self, def_id: DefId) -> bool {
        self.def_to_uses
            .get(&def_id)
            .map(|uses| !uses.is_empty())
            .unwrap_or(false)
    }

    /// Returns dead definitions (definitions with no uses).
    pub fn dead_definitions(&self) -> Vec<&Definition> {
        self.definitions
            .iter()
            .filter(|(id, _)| !self.has_uses(**id))
            .map(|(_, def)| def)
            .collect()
    }
}

/// Per-instruction def-use information.
#[derive(Debug, Clone, Default)]
pub struct DefUseInfo {
    /// Definitions made by this instruction.
    pub defs: Vec<(Location, DefId)>,
    /// Uses made by this instruction (with reaching definitions).
    pub uses: Vec<(Location, Vec<DefId>)>,
}

/// Builder for def-use chains.
struct DefUseChainBuilder {
    next_def_id: u32,
    definitions: HashMap<DefId, Definition>,
    uses: Vec<Use>,
    def_to_uses: HashMap<DefId, Vec<usize>>,
    defs_by_location: HashMap<Location, Vec<DefId>>,
    /// Current reaching definitions at each block entry.
    reaching_at_entry: HashMap<BasicBlockId, HashMap<Location, HashSet<DefId>>>,
}

impl DefUseChainBuilder {
    fn new() -> Self {
        Self {
            next_def_id: 0,
            definitions: HashMap::new(),
            uses: Vec::new(),
            def_to_uses: HashMap::new(),
            defs_by_location: HashMap::new(),
            reaching_at_entry: HashMap::new(),
        }
    }

    fn new_def_id(&mut self) -> DefId {
        let id = DefId(self.next_def_id);
        self.next_def_id += 1;
        id
    }

    fn build(&mut self, cfg: &ControlFlowGraph) {
        // First pass: collect all definitions
        self.collect_definitions(cfg);

        // Second pass: compute reaching definitions
        self.compute_reaching_definitions(cfg);

        // Third pass: link uses to definitions
        self.link_uses_to_definitions(cfg);
    }

    fn collect_definitions(&mut self, cfg: &ControlFlowGraph) {
        for block in cfg.blocks() {
            for (inst_index, inst) in block.instructions.iter().enumerate() {
                let effects = InstructionEffects::from_instruction(inst);

                for location in effects.defs {
                    let def_id = self.new_def_id();
                    let def = Definition {
                        id: def_id,
                        block: block.id,
                        inst_index,
                        address: inst.address,
                        location: location.clone(),
                    };

                    self.definitions.insert(def_id, def);
                    self.defs_by_location
                        .entry(location)
                        .or_default()
                        .push(def_id);
                    self.def_to_uses.insert(def_id, Vec::new());
                }
            }
        }
    }

    fn compute_reaching_definitions(&mut self, cfg: &ControlFlowGraph) {
        // Initialize reaching definitions for each block
        for block_id in cfg.block_ids() {
            self.reaching_at_entry.insert(block_id, HashMap::new());
        }

        // Iterate until fixpoint
        let rpo = cfg.reverse_post_order();
        let mut changed = true;

        while changed {
            changed = false;

            for &block_id in &rpo {
                // Meet: union of reaching defs from predecessors
                let preds = cfg.predecessors(block_id);
                let mut new_reaching: HashMap<Location, HashSet<DefId>> = HashMap::new();

                for &pred_id in preds {
                    if let Some(pred_reaching) = self.compute_block_exit_reaching(cfg, pred_id) {
                        for (loc, defs) in pred_reaching {
                            new_reaching
                                .entry(loc)
                                .or_default()
                                .extend(defs);
                        }
                    }
                }

                // Check for changes
                let old = self.reaching_at_entry.get(&block_id);
                if old.map(|o| o != &new_reaching).unwrap_or(true) {
                    self.reaching_at_entry.insert(block_id, new_reaching);
                    changed = true;
                }
            }
        }
    }

    fn compute_block_exit_reaching(
        &self,
        cfg: &ControlFlowGraph,
        block_id: BasicBlockId,
    ) -> Option<HashMap<Location, HashSet<DefId>>> {
        let block = cfg.block(block_id)?;
        let mut reaching = self.reaching_at_entry
            .get(&block_id)
            .cloned()
            .unwrap_or_default();

        // Transfer: for each instruction, kill old defs and add new ones
        for (inst_index, inst) in block.instructions.iter().enumerate() {
            let effects = InstructionEffects::from_instruction(inst);

            for def_loc in effects.defs {
                // Find the definition ID for this instruction/location
                let def_id = self.definitions
                    .iter()
                    .find(|(_, d)| {
                        d.block == block_id
                            && d.inst_index == inst_index
                            && d.location == def_loc
                    })
                    .map(|(id, _)| *id);

                if let Some(def_id) = def_id {
                    // Kill all previous definitions of this location
                    reaching.insert(def_loc.clone(), HashSet::from([def_id]));
                }
            }
        }

        Some(reaching)
    }

    fn link_uses_to_definitions(&mut self, cfg: &ControlFlowGraph) {
        for block in cfg.blocks() {
            // Start with reaching definitions at block entry
            let mut current_reaching = self.reaching_at_entry
                .get(&block.id)
                .cloned()
                .unwrap_or_default();

            for (inst_index, inst) in block.instructions.iter().enumerate() {
                let effects = InstructionEffects::from_instruction(inst);

                // Record uses with their reaching definitions
                for use_loc in effects.uses {
                    let reaching_defs: Vec<DefId> = current_reaching
                        .get(&use_loc)
                        .map(|s| s.iter().copied().collect())
                        .unwrap_or_default();

                    let use_info = Use {
                        block: block.id,
                        inst_index,
                        address: inst.address,
                        location: use_loc,
                        reaching_defs: reaching_defs.clone(),
                    };

                    let use_index = self.uses.len();
                    self.uses.push(use_info);

                    // Link definitions to this use
                    for def_id in reaching_defs {
                        self.def_to_uses
                            .entry(def_id)
                            .or_default()
                            .push(use_index);
                    }
                }

                // Update reaching definitions for definitions in this instruction
                for def_loc in effects.defs {
                    let def_id = self.definitions
                        .iter()
                        .find(|(_, d)| {
                            d.block == block.id
                                && d.inst_index == inst_index
                                && d.location == def_loc
                        })
                        .map(|(id, _)| *id);

                    if let Some(def_id) = def_id {
                        current_reaching.insert(def_loc, HashSet::from([def_id]));
                    }
                }
            }
        }
    }

    fn into_chain(self) -> DefUseChain {
        let use_to_defs: HashMap<usize, Vec<DefId>> = self.uses
            .iter()
            .enumerate()
            .map(|(i, u)| (i, u.reaching_defs.clone()))
            .collect();

        DefUseChain {
            definitions: self.definitions,
            uses: self.uses,
            def_to_uses: self.def_to_uses,
            use_to_defs,
            defs_by_location: self.defs_by_location,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, ControlFlowGraph, Instruction, Operation, Operand, Register, RegisterClass, Architecture};

    fn make_register(id: u16, _name: &str) -> Register {
        Register::new(Architecture::X86_64, RegisterClass::General, id, 64)
    }

    #[test]
    fn test_simple_def_use() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);

        // mov rax, 42  (def rax)
        let rax = make_register(0, "rax");
        let mut inst1 = Instruction::new(0x1000, 3, vec![0; 3], "mov");
        inst1.operation = Operation::Move;
        inst1.operands = vec![
            Operand::Register(rax.clone()),
            Operand::Immediate(hexray_core::Immediate { value: 42, size: 8, signed: false }),
        ];
        bb.push_instruction(inst1);

        // add rax, 1  (use rax, def rax)
        let mut inst2 = Instruction::new(0x1003, 3, vec![0; 3], "add");
        inst2.operation = Operation::Add;
        inst2.operands = vec![
            Operand::Register(rax.clone()),
            Operand::Immediate(hexray_core::Immediate { value: 1, size: 8, signed: false }),
        ];
        bb.push_instruction(inst2);

        cfg.add_block(bb);

        let chains = DefUseChain::build(&cfg);

        // Should have definitions for rax (and flags)
        assert!(!chains.definitions.is_empty());

        // The first definition of rax should be used by the second instruction
        let rax_defs = chains.definitions_of(&Location::Register(0));
        assert!(rax_defs.len() >= 1);
    }
}
