//! Static Single Assignment (SSA) form construction.
//!
//! SSA form is an intermediate representation where each variable is assigned
//! exactly once. At join points where multiple definitions might reach, phi
//! nodes are inserted to select the appropriate value.
//!
//! Benefits of SSA:
//! - Simplifies many analyses (constant propagation, dead code elimination)
//! - Makes def-use relationships explicit
//! - Enables efficient register allocation
//!
//! This module uses the standard dominance-frontier based algorithm:
//! 1. Find dominance frontiers for each block
//! 2. Insert phi nodes at dominance frontiers where needed
//! 3. Rename variables to unique versions

pub mod types;
pub mod builder;

pub use types::{SsaValue, SsaInstruction, SsaBlock, SsaFunction, PhiNode, Version};
pub use builder::SsaBuilder;

use crate::dataflow::Location;
use hexray_core::{BasicBlockId, ControlFlowGraph};
use std::collections::{HashMap, HashSet};

/// Computes the dominance frontier for each block.
///
/// The dominance frontier of a block B is the set of blocks where B's
/// dominance ends - i.e., blocks that have a predecessor dominated by B
/// but are not themselves strictly dominated by B.
pub fn compute_dominance_frontiers(
    cfg: &ControlFlowGraph,
) -> HashMap<BasicBlockId, HashSet<BasicBlockId>> {
    let dom_tree = cfg.compute_dominators();
    let mut frontiers: HashMap<BasicBlockId, HashSet<BasicBlockId>> = HashMap::new();

    // Initialize empty frontiers
    for block_id in cfg.block_ids() {
        frontiers.insert(block_id, HashSet::new());
    }

    // For each join point (block with multiple predecessors)
    for block_id in cfg.block_ids() {
        let preds = cfg.predecessors(block_id);
        if preds.len() >= 2 {
            // This is a join point
            for &pred in preds {
                // Walk up the dominator tree from pred until we reach block_id's idom
                let mut runner = pred;
                while Some(runner) != dom_tree.immediate_dominator(block_id)
                    && runner != block_id
                {
                    // block_id is in runner's dominance frontier
                    frontiers.entry(runner).or_default().insert(block_id);

                    // Move up the dominator tree
                    match dom_tree.immediate_dominator(runner) {
                        Some(idom) => runner = idom,
                        None => break,
                    }
                }
            }
        }
    }

    frontiers
}

/// Finds where phi nodes are needed for a given variable.
///
/// Uses the iterated dominance frontier algorithm: phi nodes are needed
/// at the dominance frontier of each definition, and placing a phi is
/// itself a new definition requiring its own frontier.
pub fn find_phi_placements(
    _cfg: &ControlFlowGraph,
    frontiers: &HashMap<BasicBlockId, HashSet<BasicBlockId>>,
    def_blocks: &HashSet<BasicBlockId>,
) -> HashSet<BasicBlockId> {
    let mut phi_blocks = HashSet::new();
    let mut worklist: Vec<BasicBlockId> = def_blocks.iter().copied().collect();
    let mut processed = def_blocks.clone();

    while let Some(block) = worklist.pop() {
        if let Some(frontier) = frontiers.get(&block) {
            for &df_block in frontier {
                if phi_blocks.insert(df_block) {
                    // This is a new phi placement
                    if processed.insert(df_block) {
                        worklist.push(df_block);
                    }
                }
            }
        }
    }

    phi_blocks
}

/// Collects which blocks define each location.
pub fn collect_definitions(
    cfg: &ControlFlowGraph,
) -> HashMap<Location, HashSet<BasicBlockId>> {
    use crate::dataflow::InstructionEffects;

    let mut defs: HashMap<Location, HashSet<BasicBlockId>> = HashMap::new();

    for block in cfg.blocks() {
        for inst in &block.instructions {
            let effects = InstructionEffects::from_instruction(inst);
            for loc in effects.defs {
                defs.entry(loc).or_default().insert(block.id);
            }
        }
    }

    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, BlockTerminator, Condition};

    fn make_diamond_cfg() -> ControlFlowGraph {
        //     bb0
        //    /   \
        //  bb1   bb2
        //    \   /
        //     bb3
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
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

        cfg
    }

    #[test]
    fn test_dominance_frontiers() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // bb1's frontier should include bb3 (where bb1's dominance ends)
        assert!(frontiers[&BasicBlockId::new(1)].contains(&BasicBlockId::new(3)));

        // bb2's frontier should include bb3
        assert!(frontiers[&BasicBlockId::new(2)].contains(&BasicBlockId::new(3)));

        // bb0 dominates everything, so its frontier should be empty
        assert!(frontiers[&BasicBlockId::new(0)].is_empty());
    }

    #[test]
    fn test_phi_placement() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // If a variable is defined in both bb1 and bb2
        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(1), BasicBlockId::new(2)]
            .into_iter()
            .collect();

        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);

        // A phi should be placed at bb3
        assert!(phi_blocks.contains(&BasicBlockId::new(3)));
    }
}
