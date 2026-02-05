//! Dominance-based irreducible CFG detection and transformation.
//!
//! An irreducible CFG contains loops/cycles with multiple entry points,
//! making them impossible to structure using only if/else/while/for constructs.
//!
//! This module provides:
//! - Detection of irreducible regions using dominator analysis and SCC detection
//! - Cost estimation for different transformation strategies
//! - Node splitting transformation to make regions reducible
//! - State machine pattern detection for common irreducible patterns
//! - Integration hints for goto/label emission

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
    /// Classification of the pattern if recognizable.
    pub pattern: IrreduciblePattern,
    /// Estimated cost to make reducible via node splitting.
    pub splitting_cost: usize,
    /// Whether this looks like a state machine.
    pub is_state_machine: bool,
}

/// Classification of common irreducible patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IrreduciblePattern {
    /// Classic two-entry mutual recursion.
    TwoEntryLoop,
    /// N-way state machine (multiple entries, all interconnected).
    StateMachine,
    /// Nested irreducible loops.
    NestedIrreducible,
    /// Unclassified pattern.
    #[default]
    Unknown,
}

impl IrreduciblePattern {
    /// Returns a human-readable description of the pattern.
    pub fn description(&self) -> &'static str {
        match self {
            Self::TwoEntryLoop => "two-entry loop (simple goto)",
            Self::StateMachine => "state machine (use switch/case)",
            Self::NestedIrreducible => "nested irreducible (complex goto)",
            Self::Unknown => "unknown pattern",
        }
    }

    /// Returns the recommended handling strategy.
    pub fn recommended_strategy(&self) -> TransformStrategy {
        match self {
            Self::TwoEntryLoop => TransformStrategy::GotoLabels,
            Self::StateMachine => TransformStrategy::StateMachineSwitch,
            Self::NestedIrreducible => TransformStrategy::NodeSplitting,
            Self::Unknown => TransformStrategy::GotoLabels,
        }
    }
}

/// Strategy for transforming an irreducible region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformStrategy {
    /// Use goto/label pairs (preserves original CFG structure).
    GotoLabels,
    /// Transform to a state machine with a switch statement.
    StateMachineSwitch,
    /// Duplicate nodes to create single-entry region.
    NodeSplitting,
    /// Leave as-is (for very complex regions).
    LeaveAsIs,
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

            // Classify the pattern
            let pattern = classify_pattern(cfg, &entry_points, &scc_set);

            // Estimate splitting cost
            let splitting_cost = estimate_splitting_cost(cfg, &entry_points, &scc_set);

            // Check if this looks like a state machine
            let is_state_machine = detect_state_machine_pattern(cfg, &entry_points, &scc_set);

            irreducible_blocks.extend(&scc_set);

            regions.push(IrreducibleRegion {
                blocks: scc_set,
                entry_points,
                suggested_header,
                pattern,
                splitting_cost,
                is_state_machine,
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

    /// Returns the total splitting cost across all regions.
    pub fn total_splitting_cost(&self) -> usize {
        self.regions.iter().map(|r| r.splitting_cost).sum()
    }

    /// Returns the recommended strategy for handling all irreducible regions.
    pub fn recommended_strategy(&self) -> TransformStrategy {
        if self.is_reducible {
            return TransformStrategy::LeaveAsIs;
        }

        // If any region is a state machine, use switch
        if self.regions.iter().any(|r| r.is_state_machine) {
            return TransformStrategy::StateMachineSwitch;
        }

        // If total splitting cost is low, use node splitting
        let total_cost = self.total_splitting_cost();
        if total_cost <= 5 {
            return TransformStrategy::NodeSplitting;
        }

        // Otherwise use gotos
        TransformStrategy::GotoLabels
    }

    /// Returns all blocks that need labels for goto emission.
    pub fn blocks_needing_labels(&self) -> HashSet<BasicBlockId> {
        let mut labels = HashSet::new();
        for region in &self.regions {
            for &entry in &region.entry_points {
                if entry != region.suggested_header {
                    labels.insert(entry);
                }
            }
        }
        labels
    }

    /// Returns a summary of the irreducible regions.
    pub fn summary(&self) -> String {
        if self.is_reducible {
            return "CFG is reducible (no irreducible regions)".to_string();
        }

        let mut lines = vec![format!(
            "Found {} irreducible region(s):",
            self.regions.len()
        )];

        for (i, region) in self.regions.iter().enumerate() {
            lines.push(format!(
                "  Region {}: {} blocks, {} entries ({})",
                i + 1,
                region.blocks.len(),
                region.entry_points.len(),
                region.pattern.description()
            ));
        }

        lines.push(format!(
            "Recommended strategy: {:?}",
            self.recommended_strategy()
        ));

        lines.join("\n")
    }
}

impl IrreducibleRegion {
    /// Returns the recommended strategy for this specific region.
    pub fn recommended_strategy(&self) -> TransformStrategy {
        self.pattern.recommended_strategy()
    }

    /// Returns the blocks that would need to be duplicated for node splitting.
    pub fn blocks_to_duplicate(&self) -> Vec<BasicBlockId> {
        self.entry_points
            .iter()
            .filter(|&&e| e != self.suggested_header)
            .copied()
            .collect()
    }

    /// Checks if a block is an entry point to this region.
    pub fn is_entry_point(&self, block: BasicBlockId) -> bool {
        self.entry_points.contains(&block)
    }

    /// Checks if a block is the suggested header.
    pub fn is_header(&self, block: BasicBlockId) -> bool {
        self.suggested_header == block
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

/// Classifies the pattern of an irreducible region.
fn classify_pattern(
    cfg: &ControlFlowGraph,
    entry_points: &[BasicBlockId],
    scc_set: &HashSet<BasicBlockId>,
) -> IrreduciblePattern {
    // Two-entry loop is the simplest pattern
    if entry_points.len() == 2 && scc_set.len() == 2 {
        // Check if they form a simple mutual loop
        let e0 = entry_points[0];
        let e1 = entry_points[1];
        let e0_goes_to_e1 = cfg.successors(e0).contains(&e1);
        let e1_goes_to_e0 = cfg.successors(e1).contains(&e0);
        if e0_goes_to_e1 && e1_goes_to_e0 {
            return IrreduciblePattern::TwoEntryLoop;
        }
    }

    // State machine: all entries are heavily interconnected
    if detect_state_machine_pattern(cfg, entry_points, scc_set) {
        return IrreduciblePattern::StateMachine;
    }

    // Check for nested irreducible by looking for multiple SCCs within entries
    if entry_points.len() > 2 {
        // Count internal edges vs external edges
        let internal_edges: usize = scc_set
            .iter()
            .map(|&b| {
                cfg.successors(b)
                    .iter()
                    .filter(|s| scc_set.contains(s))
                    .count()
            })
            .sum();
        let entry_count = entry_points.len();

        // High ratio of internal edges to entries suggests nesting
        if internal_edges > entry_count * 3 {
            return IrreduciblePattern::NestedIrreducible;
        }
    }

    IrreduciblePattern::Unknown
}

/// Estimates the cost of node splitting to make the region reducible.
///
/// Cost is measured in terms of duplicated blocks.
fn estimate_splitting_cost(
    cfg: &ControlFlowGraph,
    entry_points: &[BasicBlockId],
    scc_set: &HashSet<BasicBlockId>,
) -> usize {
    // Simple heuristic: need to duplicate all non-header entries
    // plus any blocks reachable from multiple entries
    let header = find_best_header(cfg, entry_points, scc_set);

    let mut cost = 0;

    // Each non-header entry needs to be duplicated
    for &entry in entry_points {
        if entry != header {
            cost += 1;

            // Count blocks reachable only from this entry
            // that would also need duplication
            let mut reachable = HashSet::new();
            let mut stack = vec![entry];
            while let Some(b) = stack.pop() {
                if scc_set.contains(&b) && reachable.insert(b) {
                    for &succ in cfg.successors(b) {
                        if scc_set.contains(&succ) {
                            stack.push(succ);
                        }
                    }
                }
            }
            // Blocks that are only reachable from this entry (not header)
            cost += reachable.len().saturating_sub(1);
        }
    }

    cost
}

/// Detects if the region looks like a state machine.
///
/// A state machine pattern has:
/// - Multiple entries that all represent "states"
/// - Most/all states can transition to most/all other states
/// - Often has a "dispatch" block pattern
fn detect_state_machine_pattern(
    cfg: &ControlFlowGraph,
    entry_points: &[BasicBlockId],
    scc_set: &HashSet<BasicBlockId>,
) -> bool {
    if entry_points.len() < 3 {
        return false;
    }

    let entry_set: HashSet<_> = entry_points.iter().copied().collect();

    // Count how many entries each entry can reach directly
    let mut interconnection_count = 0;
    let expected_connections = entry_points.len() * (entry_points.len() - 1);

    for &entry in entry_points {
        for &succ in cfg.successors(entry) {
            if entry_set.contains(&succ) && succ != entry {
                interconnection_count += 1;
            }
            // Also check if succ reaches other entries
            if scc_set.contains(&succ) {
                for &succ2 in cfg.successors(succ) {
                    if entry_set.contains(&succ2) && succ2 != entry {
                        interconnection_count += 1;
                    }
                }
            }
        }
    }

    // If at least 50% of possible connections exist, likely a state machine
    interconnection_count * 2 >= expected_connections
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

/// Generates state machine transformation info for a region.
///
/// For state machine patterns, this generates the mapping from block IDs
/// to state numbers that can be used to generate a switch-based state machine.
#[allow(dead_code)]
pub fn generate_state_machine_mapping(region: &IrreducibleRegion) -> Option<StateMachineMapping> {
    if !region.is_state_machine && region.pattern != IrreduciblePattern::StateMachine {
        return None;
    }

    let mut state_to_block = HashMap::new();
    let mut block_to_state = HashMap::new();

    // Assign state numbers starting from 0
    // Put header first as state 0
    state_to_block.insert(0, region.suggested_header);
    block_to_state.insert(region.suggested_header, 0);

    let mut next_state = 1;
    for &entry in &region.entry_points {
        if entry != region.suggested_header {
            state_to_block.insert(next_state, entry);
            block_to_state.insert(entry, next_state);
            next_state += 1;
        }
    }

    // Add remaining blocks in the region
    for &block in &region.blocks {
        if let std::collections::hash_map::Entry::Vacant(e) = block_to_state.entry(block) {
            state_to_block.insert(next_state, block);
            e.insert(next_state);
            next_state += 1;
        }
    }

    Some(StateMachineMapping {
        state_to_block,
        block_to_state,
        initial_state: 0,
        num_states: next_state,
    })
}

/// Mapping information for state machine transformation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StateMachineMapping {
    /// State number -> BasicBlockId.
    pub state_to_block: HashMap<usize, BasicBlockId>,
    /// BasicBlockId -> state number.
    pub block_to_state: HashMap<BasicBlockId, usize>,
    /// The initial state (typically 0, corresponding to the header).
    pub initial_state: usize,
    /// Total number of states.
    pub num_states: usize,
}

#[allow(dead_code)]
impl StateMachineMapping {
    /// Gets the state number for a block.
    pub fn get_state(&self, block: BasicBlockId) -> Option<usize> {
        self.block_to_state.get(&block).copied()
    }

    /// Gets the block for a state number.
    pub fn get_block(&self, state: usize) -> Option<BasicBlockId> {
        self.state_to_block.get(&state).copied()
    }

    /// Returns the number of case labels needed for a switch.
    pub fn case_count(&self) -> usize {
        self.num_states
    }
}

/// Analyzes and provides guidance for handling irreducible control flow.
///
/// This is a higher-level interface that combines detection with
/// recommendations for how to handle each region.
#[derive(Debug)]
#[allow(dead_code)]
pub struct IrreducibleHandler {
    /// The underlying analysis.
    pub analysis: IrreducibleCfgAnalysis,
    /// State machine mappings for applicable regions.
    pub state_machines: HashMap<usize, StateMachineMapping>,
    /// Blocks that need labels.
    pub labeled_blocks: HashSet<BasicBlockId>,
}

#[allow(dead_code)]
impl IrreducibleHandler {
    /// Creates a new handler by analyzing the given CFG.
    pub fn new(cfg: &ControlFlowGraph) -> Self {
        let analysis = IrreducibleCfgAnalysis::analyze(cfg);
        let labeled_blocks = analysis.blocks_needing_labels();

        let mut state_machines = HashMap::new();
        for (i, region) in analysis.regions.iter().enumerate() {
            if let Some(mapping) = generate_state_machine_mapping(region) {
                state_machines.insert(i, mapping);
            }
        }

        Self {
            analysis,
            state_machines,
            labeled_blocks,
        }
    }

    /// Checks if the CFG is reducible.
    pub fn is_reducible(&self) -> bool {
        self.analysis.is_reducible
    }

    /// Checks if a block needs a label for goto handling.
    pub fn needs_label(&self, block: BasicBlockId) -> bool {
        self.labeled_blocks.contains(&block)
    }

    /// Gets handling guidance for a specific block.
    pub fn get_block_guidance(&self, block: BasicBlockId) -> BlockGuidance {
        if let Some(region) = self.analysis.get_region_for_block(block) {
            let region_idx = self
                .analysis
                .regions
                .iter()
                .position(|r| r.blocks.contains(&block))
                .unwrap();

            BlockGuidance {
                in_irreducible_region: true,
                is_entry_point: region.is_entry_point(block),
                is_header: region.is_header(block),
                needs_label: self.needs_label(block),
                recommended_strategy: region.recommended_strategy(),
                state_number: self
                    .state_machines
                    .get(&region_idx)
                    .and_then(|m| m.get_state(block)),
            }
        } else {
            BlockGuidance {
                in_irreducible_region: false,
                is_entry_point: false,
                is_header: false,
                needs_label: false,
                recommended_strategy: TransformStrategy::LeaveAsIs,
                state_number: None,
            }
        }
    }
}

/// Guidance for handling a specific block during code generation.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BlockGuidance {
    /// Whether this block is part of an irreducible region.
    pub in_irreducible_region: bool,
    /// Whether this block is an entry point to its region.
    pub is_entry_point: bool,
    /// Whether this block is the suggested header.
    pub is_header: bool,
    /// Whether this block needs a label.
    pub needs_label: bool,
    /// Recommended transformation strategy for this region.
    pub recommended_strategy: TransformStrategy,
    /// State number if part of a state machine transformation.
    pub state_number: Option<usize>,
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
            pattern: IrreduciblePattern::TwoEntryLoop,
            splitting_cost: 1,
            is_state_machine: false,
        };

        let entry = BasicBlockId::new(0);
        let cfg = ControlFlowGraph::new(entry);

        let to_split = suggest_node_splitting(&cfg, &region);

        // Should suggest splitting bb2 (the non-header entry)
        assert_eq!(to_split.len(), 1);
        assert!(to_split.contains(&BasicBlockId::new(2)));
    }
}
