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

pub mod builder;
pub mod optimize;
pub mod types;

pub use builder::SsaBuilder;
pub use optimize::{OptimizationStats, SsaOptimizer};
pub use types::{PhiNode, SsaBlock, SsaFunction, SsaInstruction, SsaValue, Version};

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
                while Some(runner) != dom_tree.immediate_dominator(block_id) && runner != block_id {
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
pub fn collect_definitions(cfg: &ControlFlowGraph) -> HashMap<Location, HashSet<BasicBlockId>> {
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

    fn make_linear_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 -> bb2 -> bb3
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        for i in 0..4u32 {
            let mut bb = BasicBlock::new(BasicBlockId::new(i), 0x1000 + i as u64 * 0x10);
            if i < 3 {
                bb.terminator = BlockTerminator::Jump {
                    target: BasicBlockId::new(i + 1),
                };
                cfg.add_edge(BasicBlockId::new(i), BasicBlockId::new(i + 1));
            } else {
                bb.terminator = BlockTerminator::Return;
            }
            cfg.add_block(bb);
        }

        cfg
    }

    fn make_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (loop header)
        //        bb1 -> bb2 (loop body) -> bb1 (back edge)
        //        bb1 -> bb3 (exit)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(3),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Return;
        cfg.add_block(bb3);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1)); // back edge

        cfg
    }

    fn make_nested_loop_cfg() -> ControlFlowGraph {
        // bb0 -> bb1 (outer header) -> bb2 (inner header) -> bb3 (inner body)
        //                                                      -> bb2 (inner back)
        //                              bb2 -> bb4 (between loops) -> bb1 (outer back)
        //        bb1 -> bb5 (exit)
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));

        let mut bb0 = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb0);

        let mut bb1 = BasicBlock::new(BasicBlockId::new(1), 0x1010);
        bb1.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(2),
            false_target: BasicBlockId::new(5),
        };
        cfg.add_block(bb1);

        let mut bb2 = BasicBlock::new(BasicBlockId::new(2), 0x1020);
        bb2.terminator = BlockTerminator::ConditionalBranch {
            condition: Condition::NotEqual,
            true_target: BasicBlockId::new(3),
            false_target: BasicBlockId::new(4),
        };
        cfg.add_block(bb2);

        let mut bb3 = BasicBlock::new(BasicBlockId::new(3), 0x1030);
        bb3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(bb3);

        let mut bb4 = BasicBlock::new(BasicBlockId::new(4), 0x1040);
        bb4.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(bb4);

        let mut bb5 = BasicBlock::new(BasicBlockId::new(5), 0x1050);
        bb5.terminator = BlockTerminator::Return;
        cfg.add_block(bb5);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(5));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(1));

        cfg
    }

    // --- Dominance Frontier Tests ---

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
    fn test_dominance_frontiers_linear() {
        let cfg = make_linear_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // In a linear CFG, no block has a dominance frontier
        // (no join points)
        for block_id in cfg.block_ids() {
            assert!(
                frontiers[&block_id].is_empty(),
                "Block {} should have empty frontier",
                block_id
            );
        }
    }

    #[test]
    fn test_dominance_frontiers_loop() {
        let cfg = make_loop_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // bb2's frontier should include bb1 (the loop header)
        // because bb1 has multiple predecessors (bb0, bb2) and bb2 doesn't dominate bb1
        assert!(
            frontiers[&BasicBlockId::new(2)].contains(&BasicBlockId::new(1)),
            "bb2's frontier should contain bb1"
        );

        // bb0's frontier should be empty because bb0 dominates bb1
        // (bb0 is bb1's immediate dominator)
        assert!(
            frontiers[&BasicBlockId::new(0)].is_empty(),
            "bb0's frontier should be empty (dominates all reachable blocks)"
        );
    }

    #[test]
    fn test_dominance_frontiers_nested_loop() {
        let cfg = make_nested_loop_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // Inner loop back edge: bb3's frontier should include bb2
        assert!(
            frontiers[&BasicBlockId::new(3)].contains(&BasicBlockId::new(2)),
            "bb3's frontier should contain bb2 (inner loop header)"
        );

        // Outer loop back edge: bb4's frontier should include bb1
        assert!(
            frontiers[&BasicBlockId::new(4)].contains(&BasicBlockId::new(1)),
            "bb4's frontier should contain bb1 (outer loop header)"
        );
    }

    #[test]
    fn test_dominance_frontiers_single_block() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let frontiers = compute_dominance_frontiers(&cfg);
        assert!(frontiers[&BasicBlockId::new(0)].is_empty());
    }

    // --- Phi Placement Tests ---

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

    #[test]
    fn test_phi_placement_single_def() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // Single definition in bb0 - dominates everything, no phi needed
        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(0)].into_iter().collect();

        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);
        assert!(phi_blocks.is_empty());
    }

    #[test]
    fn test_phi_placement_loop() {
        let cfg = make_loop_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // Variable defined in bb0 (before loop) and bb2 (in loop)
        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(0), BasicBlockId::new(2)]
            .into_iter()
            .collect();

        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);

        // Phi should be placed at bb1 (loop header)
        assert!(
            phi_blocks.contains(&BasicBlockId::new(1)),
            "Phi should be placed at loop header"
        );
    }

    #[test]
    fn test_phi_placement_iterated() {
        // Test that phi placement is iterated - placing a phi creates a new def
        // which may require more phis
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // Definition only in bb1
        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(1)].into_iter().collect();

        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);

        // bb1's frontier is bb3, so phi at bb3
        assert!(phi_blocks.contains(&BasicBlockId::new(3)));
    }

    #[test]
    fn test_phi_placement_nested_loop() {
        let cfg = make_nested_loop_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // Variable defined in inner loop body
        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(3)].into_iter().collect();

        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);

        // Should need phi at bb2 (inner loop header)
        assert!(
            phi_blocks.contains(&BasicBlockId::new(2)),
            "Phi should be placed at inner loop header"
        );
    }

    #[test]
    fn test_phi_placement_empty_defs() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        let def_blocks: HashSet<BasicBlockId> = HashSet::new();
        let phi_blocks = find_phi_placements(&cfg, &frontiers, &def_blocks);

        assert!(phi_blocks.is_empty());
    }

    // --- collect_definitions Tests ---

    #[test]
    fn test_collect_definitions_empty_cfg() {
        let mut cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        let mut bb = BasicBlock::new(BasicBlockId::new(0), 0x1000);
        bb.terminator = BlockTerminator::Return;
        cfg.add_block(bb);

        let defs = collect_definitions(&cfg);
        // No instructions, so no definitions
        assert!(defs.is_empty());
    }

    // --- Integration Tests ---

    #[test]
    fn test_frontiers_and_phi_placement_consistency() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        // All frontiers should contain valid block IDs
        for (block_id, frontier) in &frontiers {
            assert!(
                cfg.block(*block_id).is_some(),
                "Block {} should exist",
                block_id
            );
            for df_block in frontier {
                assert!(
                    cfg.block(*df_block).is_some(),
                    "Frontier block {} should exist",
                    df_block
                );
            }
        }
    }

    #[test]
    fn test_phi_placement_idempotent() {
        let cfg = make_diamond_cfg();
        let frontiers = compute_dominance_frontiers(&cfg);

        let def_blocks: HashSet<BasicBlockId> = [BasicBlockId::new(1), BasicBlockId::new(2)]
            .into_iter()
            .collect();

        // Running phi placement twice should give same result
        let phi_blocks1 = find_phi_placements(&cfg, &frontiers, &def_blocks);
        let phi_blocks2 = find_phi_placements(&cfg, &frontiers, &def_blocks);

        assert_eq!(phi_blocks1, phi_blocks2);
    }
}
