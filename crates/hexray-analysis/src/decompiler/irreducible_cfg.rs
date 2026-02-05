//! Dominance-based irreducible CFG detection.
//!
//! An irreducible CFG contains loops/cycles with multiple entry points,
//! making them impossible to structure using only if/else/while/for constructs.
//!
//! This module detects such regions using dominator analysis and strongly
//! connected component (SCC) detection.

use hexray_core::{BasicBlockId, ControlFlowGraph};
use std::collections::{HashMap, HashSet};

/// Information about an irreducible region in the CFG.
#[derive(Debug, Clone)]
pub struct IrreducibleRegion {
    /// All blocks in this irreducible region.
    pub blocks: HashSet<BasicBlockId>,
    /// Entry points into this region (blocks reachable from outside).
    pub entry_points: Vec<BasicBlockId>,
    /// Suggested primary header (the entry point with most predecessors from outside).
    pub suggested_header: BasicBlockId,
}

/// Result of irreducible CFG analysis.
#[derive(Debug)]
pub struct IrreducibleCfgAnalysis {
    /// Detected irreducible regions.
    pub regions: Vec<IrreducibleRegion>,
    /// Set of all blocks that are part of irreducible regions.
    pub irreducible_blocks: HashSet<BasicBlockId>,
    /// Whether the CFG is fully reducible (no irreducible regions).
    pub is_reducible: bool,
}

impl IrreducibleCfgAnalysis {
    /// Performs dominance-based irreducible CFG detection.
    pub fn analyze(cfg: &ControlFlowGraph) -> Self {
        let dominators = cfg.compute_dominators();
        let sccs = compute_sccs(cfg);

        let mut regions = Vec::new();
        let mut irreducible_blocks = HashSet::new();

        for scc in sccs {
            // Only consider non-trivial SCCs (cycles)
            if scc.len() <= 1 {
                continue;
            }

            // Find entry points into this SCC
            let entry_points = find_scc_entry_points(cfg, &scc);

            if entry_points.len() <= 1 {
                // Single entry point - this is a natural/reducible loop
                continue;
            }

            // Multiple entry points - check if one dominates all others
            let mut has_dominating_entry = false;
            for &entry in &entry_points {
                let dominates_all = entry_points
                    .iter()
                    .all(|&other| entry == other || dominators.dominates(entry, other));
                if dominates_all {
                    has_dominating_entry = true;
                    break;
                }
            }

            if has_dominating_entry {
                // One entry dominates all others - structurally reducible
                continue;
            }

            // This is an irreducible region
            let scc_set: HashSet<_> = scc.into_iter().collect();

            // Find the best suggested header (entry with most external predecessors)
            let suggested_header = find_best_header(cfg, &entry_points, &scc_set);

            irreducible_blocks.extend(&scc_set);

            regions.push(IrreducibleRegion {
                blocks: scc_set,
                entry_points,
                suggested_header,
            });
        }

        let is_reducible = regions.is_empty();

        Self {
            regions,
            irreducible_blocks,
            is_reducible,
        }
    }

    /// Checks if a specific block is part of an irreducible region.
    pub fn is_irreducible_block(&self, block: BasicBlockId) -> bool {
        self.irreducible_blocks.contains(&block)
    }

    /// Gets the irreducible region containing a block, if any.
    pub fn get_region_for_block(&self, block: BasicBlockId) -> Option<&IrreducibleRegion> {
        self.regions.iter().find(|r| r.blocks.contains(&block))
    }
}

/// Computes strongly connected components using Kosaraju's algorithm.
fn compute_sccs(cfg: &ControlFlowGraph) -> Vec<Vec<BasicBlockId>> {
    let blocks: Vec<_> = cfg.block_ids().collect();

    if blocks.is_empty() {
        return Vec::new();
    }

    // First DFS to compute finish times
    let mut visited = HashSet::new();
    let mut finish_order = Vec::new();

    for &block in &blocks {
        if !visited.contains(&block) {
            dfs_finish_order(cfg, block, &mut visited, &mut finish_order);
        }
    }

    // Build reverse graph
    let reverse_edges = build_reverse_edges(cfg, &blocks);

    // Second DFS in reverse finish order on reverse graph
    let mut visited = HashSet::new();
    let mut sccs = Vec::new();

    for &block in finish_order.iter().rev() {
        if !visited.contains(&block) {
            let mut scc = Vec::new();
            dfs_collect_scc(&reverse_edges, block, &mut visited, &mut scc);
            sccs.push(scc);
        }
    }

    sccs
}

/// DFS to compute finish order for Kosaraju's algorithm.
fn dfs_finish_order(
    cfg: &ControlFlowGraph,
    block: BasicBlockId,
    visited: &mut HashSet<BasicBlockId>,
    finish_order: &mut Vec<BasicBlockId>,
) {
    visited.insert(block);

    for &succ in cfg.successors(block) {
        if !visited.contains(&succ) {
            dfs_finish_order(cfg, succ, visited, finish_order);
        }
    }

    finish_order.push(block);
}

/// Builds reverse edges for the CFG.
fn build_reverse_edges(
    cfg: &ControlFlowGraph,
    blocks: &[BasicBlockId],
) -> HashMap<BasicBlockId, Vec<BasicBlockId>> {
    let mut reverse = HashMap::new();

    for &block in blocks {
        reverse.entry(block).or_insert_with(Vec::new);
        for &succ in cfg.successors(block) {
            reverse.entry(succ).or_insert_with(Vec::new).push(block);
        }
    }

    reverse
}

/// DFS to collect nodes in an SCC.
fn dfs_collect_scc(
    reverse_edges: &HashMap<BasicBlockId, Vec<BasicBlockId>>,
    block: BasicBlockId,
    visited: &mut HashSet<BasicBlockId>,
    scc: &mut Vec<BasicBlockId>,
) {
    visited.insert(block);
    scc.push(block);

    if let Some(preds) = reverse_edges.get(&block) {
        for &pred in preds {
            if !visited.contains(&pred) {
                dfs_collect_scc(reverse_edges, pred, visited, scc);
            }
        }
    }
}

/// Finds entry points into an SCC (blocks with predecessors outside the SCC).
fn find_scc_entry_points(cfg: &ControlFlowGraph, scc: &[BasicBlockId]) -> Vec<BasicBlockId> {
    let scc_set: HashSet<_> = scc.iter().copied().collect();
    let mut entry_points = Vec::new();

    for &block in scc {
        let has_external_pred = cfg
            .predecessors(block)
            .iter()
            .any(|pred| !scc_set.contains(pred));
        if has_external_pred {
            entry_points.push(block);
        }
    }

    // Sort by block ID for deterministic output
    entry_points.sort_by_key(|b| b.0);
    entry_points
}

/// Finds the best header for an irreducible region.
///
/// The best header is the entry point with the most predecessors from outside
/// the region, as this is most likely the "natural" entry point.
fn find_best_header(
    cfg: &ControlFlowGraph,
    entry_points: &[BasicBlockId],
    scc_set: &HashSet<BasicBlockId>,
) -> BasicBlockId {
    let mut best = entry_points[0];
    let mut best_count = 0;

    for &entry in entry_points {
        let external_pred_count = cfg
            .predecessors(entry)
            .iter()
            .filter(|pred| !scc_set.contains(pred))
            .count();

        if external_pred_count > best_count {
            best_count = external_pred_count;
            best = entry;
        }
    }

    best
}

/// Attempts to make an irreducible region reducible through node splitting.
///
/// This technique duplicates nodes to create a single-entry region.
/// Returns the set of nodes that should be duplicated.
#[allow(dead_code)]
pub fn suggest_node_splitting(
    _cfg: &ControlFlowGraph,
    region: &IrreducibleRegion,
) -> Vec<BasicBlockId> {
    // Simple heuristic: duplicate all entry points except the suggested header
    region
        .entry_points
        .iter()
        .filter(|&&e| e != region.suggested_header)
        .copied()
        .collect()
}

/// Marks irreducible regions in structured output by inserting special nodes.
///
/// This can be used by the structurer to emit appropriate goto/label pairs
/// or C-style labeled blocks for irreducible regions.
#[allow(dead_code)]
pub fn mark_irreducible_entries(
    cfg: &ControlFlowGraph,
    analysis: &IrreducibleCfgAnalysis,
) -> HashSet<BasicBlockId> {
    let mut needs_label = HashSet::new();

    for region in &analysis.regions {
        // All entry points except the primary one need labels
        for &entry in &region.entry_points {
            if entry != region.suggested_header {
                needs_label.insert(entry);
            }
        }

        // Also add labels for any block that's a back-edge target from outside
        for &block in &region.blocks {
            for &pred in cfg.predecessors(block) {
                // If predecessor is outside the region or is "after" this block,
                // this block might need a label for goto
                if !region.blocks.contains(&pred) && block != region.suggested_header {
                    needs_label.insert(block);
                }
            }
        }
    }

    needs_label
}

#[cfg(test)]
mod tests {
    use super::*;
    use hexray_core::{BasicBlock, BlockTerminator};

    fn make_block(id: u32, start: u64) -> BasicBlock {
        let mut block = BasicBlock::new(BasicBlockId::new(id), start);
        block.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(id),
        };
        block
    }

    #[test]
    fn test_reducible_cfg() {
        // Simple reducible loop:
        //   bb0 -> bb1 -> bb2
        //          ^-----|
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut b0 = make_block(0, 0x1000);
        b0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(b0);

        let mut b1 = make_block(1, 0x1010);
        b1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(b1);

        let mut b2 = make_block(2, 0x1020);
        b2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(b2);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1));

        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);

        assert!(analysis.is_reducible);
        assert!(analysis.regions.is_empty());
    }

    #[test]
    fn test_irreducible_two_entry_loop() {
        // Classic irreducible pattern:
        //     bb0
        //    /   \
        //  bb1 -> bb2
        //   ^      |
        //   |------+
        //
        // Both bb1 and bb2 are entry points to the cycle.
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut b0 = make_block(0, 0x1000);
        b0.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(b0);

        let mut b1 = make_block(1, 0x1010);
        b1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(b1);

        let mut b2 = make_block(2, 0x1020);
        b2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(b2);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1));

        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);

        assert!(!analysis.is_reducible);
        assert_eq!(analysis.regions.len(), 1);

        let region = &analysis.regions[0];
        assert!(region.blocks.contains(&BasicBlockId::new(1)));
        assert!(region.blocks.contains(&BasicBlockId::new(2)));
        assert_eq!(region.entry_points.len(), 2);
    }

    #[test]
    fn test_nested_irreducible() {
        // More complex irreducible pattern:
        //       bb0
        //      /   \
        //   bb1     bb2
        //    |  \  / |
        //    |   \/  |
        //    |   /\  |
        //    v  /  v v
        //   bb3 <-> bb4
        //
        // bb3 and bb4 form an irreducible cycle with entries from bb1 and bb2.
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut b0 = make_block(0, 0x1000);
        b0.terminator = BlockTerminator::ConditionalBranch {
            condition: hexray_core::Condition::Equal,
            true_target: BasicBlockId::new(1),
            false_target: BasicBlockId::new(2),
        };
        cfg.add_block(b0);

        let mut b1 = make_block(1, 0x1010);
        b1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(b1);

        let mut b2 = make_block(2, 0x1020);
        b2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(b2);

        let mut b3 = make_block(3, 0x1030);
        b3.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(4),
        };
        cfg.add_block(b3);

        let mut b4 = make_block(4, 0x1040);
        b4.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(3),
        };
        cfg.add_block(b4);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(4));
        cfg.add_edge(BasicBlockId::new(4), BasicBlockId::new(3));

        let analysis = IrreducibleCfgAnalysis::analyze(&cfg);

        assert!(!analysis.is_reducible);
        assert!(!analysis.regions.is_empty());

        // The region should contain bb3 and bb4
        let region = analysis
            .regions
            .iter()
            .find(|r| r.blocks.len() == 2)
            .unwrap();
        assert!(region.blocks.contains(&BasicBlockId::new(3)));
        assert!(region.blocks.contains(&BasicBlockId::new(4)));
    }

    #[test]
    fn test_scc_computation() {
        // Simple cycle: bb0 -> bb1 -> bb2 -> bb0
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut b0 = make_block(0, 0x1000);
        b0.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(1),
        };
        cfg.add_block(b0);

        let mut b1 = make_block(1, 0x1010);
        b1.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(2),
        };
        cfg.add_block(b1);

        let mut b2 = make_block(2, 0x1020);
        b2.terminator = BlockTerminator::Jump {
            target: BasicBlockId::new(0),
        };
        cfg.add_block(b2);

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(0));

        let sccs = compute_sccs(&cfg);

        // All three blocks should be in one SCC
        let large_scc = sccs.iter().find(|s| s.len() == 3);
        assert!(large_scc.is_some());
    }

    #[test]
    fn test_suggest_node_splitting() {
        // Create a region with multiple entry points
        let region = IrreducibleRegion {
            blocks: [BasicBlockId::new(1), BasicBlockId::new(2)]
                .into_iter()
                .collect(),
            entry_points: vec![BasicBlockId::new(1), BasicBlockId::new(2)],
            suggested_header: BasicBlockId::new(1),
        };

        let entry = BasicBlockId::new(0);
        let cfg = ControlFlowGraph::new(entry);

        let to_split = suggest_node_splitting(&cfg, &region);

        // Should suggest splitting bb2 (the non-header entry)
        assert_eq!(to_split.len(), 1);
        assert!(to_split.contains(&BasicBlockId::new(2)));
    }
}
