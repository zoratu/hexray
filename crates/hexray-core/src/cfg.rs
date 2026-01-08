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
        self.successors.get(&id).map(|v| v.as_slice()).unwrap_or(&[])
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

    fn collect_loop_body(&self, header: BasicBlockId, back_edge: BasicBlockId) -> Vec<BasicBlockId> {
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
        let rpo_number: IndexMap<BasicBlockId, usize> =
            rpo.iter().copied().enumerate().map(|(i, b)| (b, i)).collect();

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
