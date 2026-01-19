//! Property-based tests for Control Flow Graph invariants.
//!
//! These tests verify that CFG construction and analysis maintain
//! important graph-theoretic properties:
//! - Dominator tree correctness
//! - Edge consistency (successors/predecessors are symmetric)
//! - Reachability properties
//! - Loop detection correctness

use proptest::prelude::*;
use std::collections::HashSet;

use hexray_core::{BasicBlock, BasicBlockId, ControlFlowGraph};

// =============================================================================
// CFG Generators
// =============================================================================

/// Generate a random CFG with a given number of blocks.
fn arb_cfg(max_blocks: usize) -> impl Strategy<Value = ControlFlowGraph> {
    (1..=max_blocks)
        .prop_flat_map(|num_blocks| {
            // Generate edges as (from, to) pairs
            let edge_strategy = prop::collection::vec(
                (0..num_blocks, 0..num_blocks),
                0..num_blocks * 2,
            );

            (Just(num_blocks), edge_strategy)
        })
        .prop_map(|(num_blocks, edges)| {
            let entry_id = BasicBlockId(0);
            let mut cfg = ControlFlowGraph::new(entry_id);

            // Create blocks
            for i in 0..num_blocks {
                let id = BasicBlockId(i as u32);
                let start = 0x1000u64 + (i as u64) * 0x100;
                let block = BasicBlock::new(id, start);
                cfg.add_block(block);
            }

            // Add edges
            for (from, to) in edges {
                let from_id = BasicBlockId(from as u32);
                let to_id = BasicBlockId(to as u32);
                cfg.add_edge(from_id, to_id);
            }

            cfg
        })
}

/// Generate a DAG (Directed Acyclic Graph) CFG - useful for testing without loops.
/// Edges only go from lower to higher numbered blocks to guarantee no cycles.
fn arb_dag_cfg(max_blocks: usize) -> impl Strategy<Value = ControlFlowGraph> {
    (2..=max_blocks)
        .prop_flat_map(|num_blocks| {
            // Generate potential edges: for each pair (i, j) where i < j,
            // we might add an edge with some probability
            let num_potential_edges = num_blocks * (num_blocks - 1) / 2;
            let edge_bits = prop::collection::vec(prop::bool::ANY, num_potential_edges);

            (Just(num_blocks), edge_bits)
        })
        .prop_map(|(num_blocks, edge_bits)| {
            let entry_id = BasicBlockId(0);
            let mut cfg = ControlFlowGraph::new(entry_id);

            for i in 0..num_blocks {
                let id = BasicBlockId(i as u32);
                let start = 0x1000u64 + (i as u64) * 0x100;
                cfg.add_block(BasicBlock::new(id, start));
            }

            // Add edges based on bits - only from lower to higher indices
            let mut bit_idx = 0;
            for from in 0..num_blocks {
                for to in (from + 1)..num_blocks {
                    if bit_idx < edge_bits.len() && edge_bits[bit_idx] {
                        cfg.add_edge(BasicBlockId(from as u32), BasicBlockId(to as u32));
                    }
                    bit_idx += 1;
                }
            }

            cfg
        })
}

// =============================================================================
// CFG Structure Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Successor/predecessor edges are symmetric.
    /// If B is a successor of A, then A is a predecessor of B.
    #[test]
    fn cfg_edges_are_symmetric(cfg in arb_cfg(20)) {
        for block_id in cfg.block_ids() {
            for &succ in cfg.successors(block_id) {
                prop_assert!(
                    cfg.predecessors(succ).contains(&block_id),
                    "Block {} is successor of {}, but {} is not predecessor of {}",
                    succ, block_id, block_id, succ
                );
            }

            for &pred in cfg.predecessors(block_id) {
                prop_assert!(
                    cfg.successors(pred).contains(&block_id),
                    "Block {} is predecessor of {}, but {} is not successor of {}",
                    pred, block_id, block_id, pred
                );
            }
        }
    }

    /// Entry block has no predecessors (in well-formed CFGs from entry-only traversal).
    /// Note: Our CFG allows unreachable blocks, so we check reachable predecessors.
    #[test]
    fn cfg_entry_dominates_reachable(cfg in arb_cfg(15)) {
        let reachable = compute_reachable(&cfg);

        // Entry should be reachable from itself
        prop_assert!(
            reachable.contains(&cfg.entry),
            "Entry block should be reachable"
        );

        // Every reachable block should be dominated by entry
        let dominators = cfg.compute_dominators();
        for &block in &reachable {
            prop_assert!(
                dominators.dominates(cfg.entry, block),
                "Entry should dominate all reachable blocks, but does not dominate {}",
                block
            );
        }
    }

    /// Reverse post-order visits all blocks.
    #[test]
    fn cfg_rpo_covers_all_blocks(cfg in arb_cfg(20)) {
        let rpo = cfg.reverse_post_order();
        let rpo_set: HashSet<_> = rpo.iter().copied().collect();
        let all_blocks: HashSet<_> = cfg.block_ids().collect();

        prop_assert_eq!(
            rpo_set, all_blocks,
            "RPO should cover all blocks"
        );
    }

    /// Reverse post-order has no duplicates.
    #[test]
    fn cfg_rpo_no_duplicates(cfg in arb_cfg(20)) {
        let rpo = cfg.reverse_post_order();
        let rpo_set: HashSet<_> = rpo.iter().copied().collect();

        prop_assert_eq!(
            rpo.len(), rpo_set.len(),
            "RPO should have no duplicates"
        );
    }
}

// =============================================================================
// Dominator Tree Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Dominance is reflexive: every block dominates itself.
    #[test]
    fn dominance_is_reflexive(cfg in arb_cfg(15)) {
        let dominators = cfg.compute_dominators();

        for block_id in cfg.block_ids() {
            prop_assert!(
                dominators.dominates(block_id, block_id),
                "Block {} should dominate itself",
                block_id
            );
        }
    }

    /// Dominance is transitive: if A dom B and B dom C, then A dom C.
    #[test]
    fn dominance_is_transitive(cfg in arb_dag_cfg(10)) {
        let dominators = cfg.compute_dominators();
        let blocks: Vec<_> = cfg.block_ids().collect();

        for &a in &blocks {
            for &b in &blocks {
                for &c in &blocks {
                    if dominators.dominates(a, b) && dominators.dominates(b, c) {
                        prop_assert!(
                            dominators.dominates(a, c),
                            "Dominance transitivity violated: {} dom {} and {} dom {}, but not {} dom {}",
                            a, b, b, c, a, c
                        );
                    }
                }
            }
        }
    }

    /// Dominance is antisymmetric: if A dom B and B dom A, then A == B.
    #[test]
    fn dominance_is_antisymmetric(cfg in arb_cfg(15)) {
        let dominators = cfg.compute_dominators();
        let blocks: Vec<_> = cfg.block_ids().collect();

        for &a in &blocks {
            for &b in &blocks {
                if dominators.dominates(a, b) && dominators.dominates(b, a) {
                    prop_assert_eq!(
                        a, b,
                        "Dominance antisymmetry violated: {} dom {} and {} dom {}, but they're different",
                        a, b, b, a
                    );
                }
            }
        }
    }

    /// Immediate dominator is unique and proper: idom(B) strictly dominates B.
    #[test]
    fn idom_strictly_dominates(cfg in arb_dag_cfg(10)) {
        let dominators = cfg.compute_dominators();

        for block_id in cfg.block_ids() {
            if block_id == cfg.entry {
                continue; // Entry has no idom
            }

            if let Some(idom) = dominators.immediate_dominator(block_id) {
                // idom should dominate block
                prop_assert!(
                    dominators.dominates(idom, block_id),
                    "idom({}) = {} should dominate {}",
                    block_id, idom, block_id
                );

                // idom should not equal block (strict domination)
                prop_assert_ne!(
                    idom, block_id,
                    "idom({}) should not be {} itself",
                    block_id, block_id
                );
            }
        }
    }

    /// For every path from entry to B, the dominator set of B is on that path.
    /// (Simplified: verify that idom is always on some path from entry to block)
    #[test]
    fn dominator_on_all_paths(cfg in arb_dag_cfg(8)) {
        let dominators = cfg.compute_dominators();
        let reachable = compute_reachable(&cfg);

        for &block_id in &reachable {
            if block_id == cfg.entry {
                continue;
            }

            // Collect all dominators of this block
            let mut doms = HashSet::new();
            let mut current = block_id;
            loop {
                doms.insert(current);
                match dominators.immediate_dominator(current) {
                    Some(idom) if idom != current => current = idom,
                    _ => break,
                }
            }

            // Verify: every path from entry to block passes through all dominators
            // (We verify the contrapositive: if we can reach block without going through
            // a dominator, that's a bug)
            let paths_through_dom = verify_dominator_on_paths(&cfg, cfg.entry, block_id, &doms);
            prop_assert!(
                paths_through_dom,
                "Not all dominators of {} are on all paths from entry",
                block_id
            );
        }
    }
}

// =============================================================================
// Loop Detection Properties
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// In a DAG, there should be no loops.
    #[test]
    fn dag_has_no_loops(cfg in arb_dag_cfg(15)) {
        let loops = cfg.find_loops();
        prop_assert!(
            loops.is_empty(),
            "DAG should have no loops, but found {} loops",
            loops.len()
        );
    }

    /// Loop headers dominate all reachable blocks in the loop body.
    /// Note: Loop body collection may include unreachable blocks that aren't dominated.
    #[test]
    fn loop_header_dominates_body(cfg in arb_cfg(12)) {
        let loops = cfg.find_loops();
        let dominators = cfg.compute_dominators();
        let reachable = compute_reachable(&cfg);

        for loop_info in &loops {
            for &body_block in &loop_info.body {
                // Only check reachable blocks - unreachable blocks might be
                // collected into loop body but aren't dominated by header
                if reachable.contains(&body_block) {
                    prop_assert!(
                        dominators.dominates(loop_info.header, body_block),
                        "Loop header {} should dominate reachable body block {}",
                        loop_info.header, body_block
                    );
                }
            }
        }
    }

    /// Loop body always contains the header.
    #[test]
    fn loop_body_contains_header(cfg in arb_cfg(12)) {
        let loops = cfg.find_loops();

        for loop_info in &loops {
            prop_assert!(
                loop_info.body.contains(&loop_info.header),
                "Loop body should contain header {}, but body is {:?}",
                loop_info.header, loop_info.body
            );
        }
    }

    /// Back edge source is in the loop body.
    #[test]
    fn back_edge_in_loop_body(cfg in arb_cfg(12)) {
        let loops = cfg.find_loops();

        for loop_info in &loops {
            prop_assert!(
                loop_info.body.contains(&loop_info.back_edge),
                "Back edge source {} should be in loop body {:?}",
                loop_info.back_edge, loop_info.body
            );
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute the set of blocks reachable from entry.
fn compute_reachable(cfg: &ControlFlowGraph) -> HashSet<BasicBlockId> {
    let mut reachable = HashSet::new();
    let mut worklist = vec![cfg.entry];

    while let Some(block) = worklist.pop() {
        if reachable.insert(block) {
            for &succ in cfg.successors(block) {
                worklist.push(succ);
            }
        }
    }

    reachable
}

/// Verify that all dominators are on all paths from start to end.
/// Returns true if all paths pass through all dominators.
fn verify_dominator_on_paths(
    cfg: &ControlFlowGraph,
    start: BasicBlockId,
    end: BasicBlockId,
    dominators: &HashSet<BasicBlockId>,
) -> bool {
    // BFS to find all paths and verify each passes through dominators
    // For simplicity, we verify that removing any dominator disconnects start from end
    for &dom in dominators {
        if dom == start || dom == end {
            continue;
        }

        // Check if we can reach end from start without going through dom
        let mut reachable = HashSet::new();
        let mut worklist = vec![start];

        while let Some(block) = worklist.pop() {
            if block == dom {
                continue; // Skip the dominator
            }
            if reachable.insert(block) {
                if block == end {
                    // Reached end without going through dom - not a dominator!
                    return false;
                }
                for &succ in cfg.successors(block) {
                    worklist.push(succ);
                }
            }
        }
    }

    true
}
