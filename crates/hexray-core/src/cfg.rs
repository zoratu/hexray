//! Control flow graph representation.

use indexmap::IndexMap;

use crate::{BasicBlock, BasicBlockId};

/// A control flow graph for a function.
///
/// The CFG represents the structure of control flow within a function,
/// with nodes being basic blocks and edges being possible control transfers.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ControlFlowGraph {
    /// Entry block ID.
    pub entry: BasicBlockId,
    /// All basic blocks, indexed by ID.
    blocks: IndexMap<BasicBlockId, BasicBlock>,
    /// Forward edges (block -> successors).
    successors: IndexMap<BasicBlockId, Vec<BasicBlockId>>,
    /// Backward edges (block -> predecessors).
    predecessors: IndexMap<BasicBlockId, Vec<BasicBlockId>>,
}

impl ControlFlowGraph {
    /// Creates a new empty CFG with the given entry block.
    pub fn new(entry: BasicBlockId) -> Self {
        Self {
            entry,
            blocks: IndexMap::new(),
            successors: IndexMap::new(),
            predecessors: IndexMap::new(),
        }
    }

    /// Adds a basic block to the CFG.
    pub fn add_block(&mut self, block: BasicBlock) {
        let id = block.id;
        self.blocks.insert(id, block);
        self.successors.entry(id).or_default();
        self.predecessors.entry(id).or_default();
    }

    /// Adds an edge from one block to another.
    pub fn add_edge(&mut self, from: BasicBlockId, to: BasicBlockId) {
        self.successors.entry(from).or_default().push(to);
        self.predecessors.entry(to).or_default().push(from);
    }

    /// Returns a reference to a block by ID.
    pub fn block(&self, id: BasicBlockId) -> Option<&BasicBlock> {
        self.blocks.get(&id)
    }

    /// Returns a mutable reference to a block by ID.
    pub fn block_mut(&mut self, id: BasicBlockId) -> Option<&mut BasicBlock> {
        self.blocks.get_mut(&id)
    }

    /// Returns the entry block.
    pub fn entry_block(&self) -> Option<&BasicBlock> {
        self.blocks.get(&self.entry)
    }

    /// Returns an iterator over all blocks.
    pub fn blocks(&self) -> impl Iterator<Item = &BasicBlock> {
        self.blocks.values()
    }

    /// Returns an iterator over all block IDs.
    pub fn block_ids(&self) -> impl Iterator<Item = BasicBlockId> + '_ {
        self.blocks.keys().copied()
    }

    /// Returns the number of blocks.
    pub fn num_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Returns the successors of a block.
    pub fn successors(&self, id: BasicBlockId) -> &[BasicBlockId] {
        self.successors
            .get(&id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the predecessors of a block.
    pub fn predecessors(&self, id: BasicBlockId) -> &[BasicBlockId] {
        self.predecessors
            .get(&id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Returns the block containing the given address.
    pub fn block_containing(&self, addr: u64) -> Option<&BasicBlock> {
        self.blocks
            .values()
            .find(|b| addr >= b.start && addr < b.end)
    }

    /// Returns blocks in reverse post-order (useful for dataflow analysis).
    ///
    /// Reverse post-order visits a node before all its successors in acyclic parts
    /// of the graph, making it ideal for forward dataflow problems.
    pub fn reverse_post_order(&self) -> Vec<BasicBlockId> {
        let mut visited = std::collections::HashSet::new();
        let mut post_order = Vec::new();

        fn dfs(
            cfg: &ControlFlowGraph,
            block: BasicBlockId,
            visited: &mut std::collections::HashSet<BasicBlockId>,
            post_order: &mut Vec<BasicBlockId>,
        ) {
            if !visited.insert(block) {
                return;
            }
            for &succ in cfg.successors(block) {
                dfs(cfg, succ, visited, post_order);
            }
            post_order.push(block);
        }

        dfs(self, self.entry, &mut visited, &mut post_order);

        // Also visit any unreachable blocks
        for id in self.blocks.keys().copied() {
            if !visited.contains(&id) {
                dfs(self, id, &mut visited, &mut post_order);
            }
        }

        post_order.reverse();
        post_order
    }

    /// Finds natural loops in the CFG.
    ///
    /// A natural loop has:
    /// - A single entry point (header)
    /// - A back edge from a node in the loop to the header
    pub fn find_loops(&self) -> Vec<Loop> {
        let mut loops = Vec::new();
        let dominators = self.compute_dominators();

        // Find back edges (edges where target dominates source)
        for &block in self.blocks.keys() {
            for &succ in self.successors(block) {
                if dominators.dominates(succ, block) {
                    // succ is the loop header, block is the back edge source
                    let body = self.collect_loop_body(succ, block);
                    loops.push(Loop {
                        header: succ,
                        back_edge: block,
                        body,
                    });
                }
            }
        }

        loops
    }

    /// Computes the dominator tree.
    pub fn compute_dominators(&self) -> DominatorTree {
        DominatorTree::compute(self)
    }

    fn collect_loop_body(
        &self,
        header: BasicBlockId,
        back_edge: BasicBlockId,
    ) -> Vec<BasicBlockId> {
        let mut body = vec![header];
        let mut worklist = vec![back_edge];
        let mut visited = std::collections::HashSet::new();
        visited.insert(header);

        while let Some(block) = worklist.pop() {
            if visited.insert(block) {
                body.push(block);
                for &pred in self.predecessors(block) {
                    worklist.push(pred);
                }
            }
        }

        body
    }
}

/// A natural loop in the CFG.
#[derive(Debug, Clone)]
pub struct Loop {
    /// The loop header (entry point).
    pub header: BasicBlockId,
    /// The source of the back edge.
    pub back_edge: BasicBlockId,
    /// All blocks in the loop body.
    pub body: Vec<BasicBlockId>,
}

/// Dominator tree for a CFG.
///
/// Block A dominates block B if every path from entry to B must go through A.
#[derive(Debug)]
pub struct DominatorTree {
    /// Immediate dominator for each block.
    idom: IndexMap<BasicBlockId, BasicBlockId>,
}

impl DominatorTree {
    /// Computes the dominator tree using the Lengauer-Tarjan algorithm.
    /// (Simplified version using dataflow for clarity.)
    pub fn compute(cfg: &ControlFlowGraph) -> Self {
        let mut idom: IndexMap<BasicBlockId, BasicBlockId> = IndexMap::new();

        // Entry block dominates itself
        idom.insert(cfg.entry, cfg.entry);

        // Iterative dominator computation
        let rpo = cfg.reverse_post_order();
        let mut changed = true;

        while changed {
            changed = false;

            for &block in &rpo {
                if block == cfg.entry {
                    continue;
                }

                let preds = cfg.predecessors(block);
                if preds.is_empty() {
                    continue;
                }

                // Find first processed predecessor
                let mut new_idom = None;
                for &pred in preds {
                    if idom.contains_key(&pred) {
                        new_idom = Some(pred);
                        break;
                    }
                }

                let Some(mut new_idom) = new_idom else {
                    continue;
                };

                // Intersect with other predecessors
                for &pred in preds {
                    if pred == new_idom || !idom.contains_key(&pred) {
                        continue;
                    }
                    new_idom = Self::intersect(&idom, &rpo, pred, new_idom);
                }

                if idom.get(&block) != Some(&new_idom) {
                    idom.insert(block, new_idom);
                    changed = true;
                }
            }
        }

        Self { idom }
    }

    fn intersect(
        idom: &IndexMap<BasicBlockId, BasicBlockId>,
        rpo: &[BasicBlockId],
        mut b1: BasicBlockId,
        mut b2: BasicBlockId,
    ) -> BasicBlockId {
        let rpo_number: IndexMap<BasicBlockId, usize> = rpo
            .iter()
            .copied()
            .enumerate()
            .map(|(i, b)| (b, i))
            .collect();

        while b1 != b2 {
            while rpo_number.get(&b1) > rpo_number.get(&b2) {
                b1 = idom[&b1];
            }
            while rpo_number.get(&b2) > rpo_number.get(&b1) {
                b2 = idom[&b2];
            }
        }

        b1
    }

    /// Returns true if `a` dominates `b`.
    pub fn dominates(&self, a: BasicBlockId, b: BasicBlockId) -> bool {
        let mut current = b;
        loop {
            if current == a {
                return true;
            }
            match self.idom.get(&current) {
                Some(&idom) if idom != current => current = idom,
                _ => return false,
            }
        }
    }

    /// Returns the immediate dominator of a block.
    pub fn immediate_dominator(&self, block: BasicBlockId) -> Option<BasicBlockId> {
        self.idom.get(&block).copied().filter(|&d| d != block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BasicBlock;

    fn make_block(id: u32, start: u64) -> BasicBlock {
        BasicBlock::new(BasicBlockId::new(id), start)
    }

    #[test]
    fn test_new_cfg_has_entry() {
        let entry = BasicBlockId::new(0);
        let cfg = ControlFlowGraph::new(entry);
        assert_eq!(cfg.entry, entry);
        assert_eq!(cfg.num_blocks(), 0);
    }

    #[test]
    fn test_add_block() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let block = make_block(0, 0x1000);
        cfg.add_block(block);

        assert_eq!(cfg.num_blocks(), 1);
        assert!(cfg.block(BasicBlockId::new(0)).is_some());
    }

    #[test]
    fn test_add_multiple_blocks() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        assert_eq!(cfg.num_blocks(), 3);
    }

    #[test]
    fn test_add_edge_creates_successor() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));

        let bb0 = BasicBlockId::new(0);
        let bb1 = BasicBlockId::new(1);
        cfg.add_edge(bb0, bb1);

        assert_eq!(cfg.successors(bb0), &[bb1]);
    }

    #[test]
    fn test_add_edge_creates_predecessor() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));

        let bb0 = BasicBlockId::new(0);
        let bb1 = BasicBlockId::new(1);
        cfg.add_edge(bb0, bb1);

        assert_eq!(cfg.predecessors(bb1), &[bb0]);
    }

    #[test]
    fn test_successor_predecessor_symmetry() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        let bb0 = BasicBlockId::new(0);
        let bb1 = BasicBlockId::new(1);
        let bb2 = BasicBlockId::new(2);

        // bb0 -> bb1, bb0 -> bb2
        cfg.add_edge(bb0, bb1);
        cfg.add_edge(bb0, bb2);

        // Check successors of bb0
        let succs = cfg.successors(bb0);
        assert!(succs.contains(&bb1));
        assert!(succs.contains(&bb2));

        // Check predecessors - should be symmetric
        assert!(cfg.predecessors(bb1).contains(&bb0));
        assert!(cfg.predecessors(bb2).contains(&bb0));
    }

    #[test]
    fn test_entry_block() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut block = make_block(0, 0x1000);
        block.end = 0x1010;
        cfg.add_block(block);

        let entry_block = cfg.entry_block().unwrap();
        assert_eq!(entry_block.id, entry);
        assert_eq!(entry_block.start, 0x1000);
    }

    #[test]
    fn test_block_not_found() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        assert!(cfg.block(BasicBlockId::new(99)).is_none());
    }

    #[test]
    fn test_block_mut() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));

        let block = cfg.block_mut(BasicBlockId::new(0)).unwrap();
        block.end = 0x2000;

        assert_eq!(cfg.block(BasicBlockId::new(0)).unwrap().end, 0x2000);
    }

    #[test]
    fn test_block_ids_iteration() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        let ids: Vec<_> = cfg.block_ids().collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn test_blocks_iteration() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));

        let blocks: Vec<_> = cfg.blocks().collect();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_block_containing_address() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut block0 = make_block(0, 0x1000);
        block0.end = 0x1010;
        let mut block1 = make_block(1, 0x1010);
        block1.end = 0x1020;

        cfg.add_block(block0);
        cfg.add_block(block1);

        // Address in first block
        let found = cfg.block_containing(0x1005).unwrap();
        assert_eq!(found.id, BasicBlockId::new(0));

        // Address in second block
        let found = cfg.block_containing(0x1015).unwrap();
        assert_eq!(found.id, BasicBlockId::new(1));

        // Address not in any block
        assert!(cfg.block_containing(0x2000).is_none());
    }

    #[test]
    fn test_block_containing_boundary() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        let mut block = make_block(0, 0x1000);
        block.end = 0x1010;
        cfg.add_block(block);

        // Start address is inclusive
        assert!(cfg.block_containing(0x1000).is_some());

        // End address is exclusive
        assert!(cfg.block_containing(0x1010).is_none());
    }

    #[test]
    fn test_successors_empty_for_unknown_block() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        assert!(cfg.successors(BasicBlockId::new(99)).is_empty());
    }

    #[test]
    fn test_predecessors_empty_for_unknown_block() {
        let cfg = ControlFlowGraph::new(BasicBlockId::new(0));
        assert!(cfg.predecessors(BasicBlockId::new(99)).is_empty());
    }

    // --- Reverse Post Order Tests ---

    #[test]
    fn test_reverse_post_order_single_block() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);
        cfg.add_block(make_block(0, 0x1000));

        let rpo = cfg.reverse_post_order();
        assert_eq!(rpo, vec![BasicBlockId::new(0)]);
    }

    #[test]
    fn test_reverse_post_order_linear() {
        // bb0 -> bb1 -> bb2
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let rpo = cfg.reverse_post_order();
        assert_eq!(rpo[0], BasicBlockId::new(0)); // Entry first
        assert_eq!(rpo[1], BasicBlockId::new(1));
        assert_eq!(rpo[2], BasicBlockId::new(2));
    }

    #[test]
    fn test_reverse_post_order_diamond() {
        //     bb0
        //    /   \
        //  bb1   bb2
        //    \   /
        //     bb3
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));
        cfg.add_block(make_block(3, 0x1030));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let rpo = cfg.reverse_post_order();
        assert_eq!(rpo[0], BasicBlockId::new(0)); // Entry first
        assert_eq!(rpo[3], BasicBlockId::new(3)); // Join point last
    }

    #[test]
    fn test_reverse_post_order_with_unreachable() {
        // bb0 -> bb1, bb2 (unreachable)
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020)); // unreachable

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));

        let rpo = cfg.reverse_post_order();
        assert_eq!(rpo.len(), 3); // Should include unreachable block
    }

    // --- Dominator Tree Tests ---

    #[test]
    fn test_dominators_single_block() {
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);
        cfg.add_block(make_block(0, 0x1000));

        let dom = cfg.compute_dominators();
        // Entry dominates itself
        assert!(dom.dominates(BasicBlockId::new(0), BasicBlockId::new(0)));
    }

    #[test]
    fn test_dominators_linear() {
        // bb0 -> bb1 -> bb2
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let dom = cfg.compute_dominators();

        // bb0 dominates all
        assert!(dom.dominates(BasicBlockId::new(0), BasicBlockId::new(0)));
        assert!(dom.dominates(BasicBlockId::new(0), BasicBlockId::new(1)));
        assert!(dom.dominates(BasicBlockId::new(0), BasicBlockId::new(2)));

        // bb1 dominates bb2
        assert!(dom.dominates(BasicBlockId::new(1), BasicBlockId::new(2)));

        // bb2 doesn't dominate bb1
        assert!(!dom.dominates(BasicBlockId::new(2), BasicBlockId::new(1)));
    }

    #[test]
    fn test_dominators_diamond() {
        //     bb0
        //    /   \
        //  bb1   bb2
        //    \   /
        //     bb3
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));
        cfg.add_block(make_block(3, 0x1030));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));

        let dom = cfg.compute_dominators();

        // bb0 dominates all
        assert!(dom.dominates(BasicBlockId::new(0), BasicBlockId::new(3)));

        // bb1 does NOT dominate bb3 (bb3 reachable via bb2)
        assert!(!dom.dominates(BasicBlockId::new(1), BasicBlockId::new(3)));
        assert!(!dom.dominates(BasicBlockId::new(2), BasicBlockId::new(3)));
    }

    #[test]
    fn test_immediate_dominator() {
        // bb0 -> bb1 -> bb2
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let dom = cfg.compute_dominators();

        // Entry has no idom (or self)
        assert!(dom.immediate_dominator(BasicBlockId::new(0)).is_none());

        // bb1's idom is bb0
        assert_eq!(
            dom.immediate_dominator(BasicBlockId::new(1)),
            Some(BasicBlockId::new(0))
        );

        // bb2's idom is bb1
        assert_eq!(
            dom.immediate_dominator(BasicBlockId::new(2)),
            Some(BasicBlockId::new(1))
        );
    }

    // --- Loop Detection Tests ---

    #[test]
    fn test_find_loops_no_loops() {
        // bb0 -> bb1 -> bb2 (no back edges)
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));

        let loops = cfg.find_loops();
        assert!(loops.is_empty());
    }

    #[test]
    fn test_find_loops_simple_loop() {
        // bb0 -> bb1 -> bb2 -> bb1 (loop header bb1)
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1)); // back edge

        let loops = cfg.find_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, BasicBlockId::new(1));
        assert_eq!(loops[0].back_edge, BasicBlockId::new(2));
        assert!(loops[0].body.contains(&BasicBlockId::new(1)));
        assert!(loops[0].body.contains(&BasicBlockId::new(2)));
    }

    #[test]
    fn test_find_loops_self_loop() {
        // bb0 -> bb1 -> bb1 (self-loop)
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(1)); // self-loop

        let loops = cfg.find_loops();
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].header, BasicBlockId::new(1));
        assert_eq!(loops[0].back_edge, BasicBlockId::new(1));
    }

    #[test]
    fn test_find_loops_nested() {
        // Outer loop: bb0 -> bb1 -> bb2 -> bb3 -> bb1
        // Inner loop: bb1 -> bb2 -> bb1
        let entry = BasicBlockId::new(0);
        let mut cfg = ControlFlowGraph::new(entry);

        cfg.add_block(make_block(0, 0x1000));
        cfg.add_block(make_block(1, 0x1010));
        cfg.add_block(make_block(2, 0x1020));
        cfg.add_block(make_block(3, 0x1030));

        cfg.add_edge(BasicBlockId::new(0), BasicBlockId::new(1));
        cfg.add_edge(BasicBlockId::new(1), BasicBlockId::new(2));
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(1)); // inner back edge
        cfg.add_edge(BasicBlockId::new(2), BasicBlockId::new(3));
        cfg.add_edge(BasicBlockId::new(3), BasicBlockId::new(1)); // outer back edge

        let loops = cfg.find_loops();
        assert_eq!(loops.len(), 2);
    }
}
