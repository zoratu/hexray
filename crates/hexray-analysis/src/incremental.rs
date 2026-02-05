//! Incremental re-analysis for binary patches.
//!
//! This module provides efficient re-analysis when binaries are patched,
//! only recomputing analysis results for affected regions.
//!
//! # Features
//!
//! - Binary diff detection to identify changed regions
//! - Dependency tracking to propagate changes through analyses
//! - Efficient invalidation of affected cache entries
//! - Call graph-aware propagation for interprocedural analysis
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::incremental::{BinaryDiff, IncrementalAnalyzer, PatchSet};
//!
//! // Compute diff between binary versions
//! let diff = BinaryDiff::compute(&old_binary, &new_binary);
//!
//! // Create incremental analyzer
//! let mut analyzer = IncrementalAnalyzer::new(cache, call_graph);
//!
//! // Apply patches and get affected functions
//! let affected = analyzer.apply_patches(&diff.patches);
//!
//! // Re-analyze only affected functions
//! for func_addr in affected {
//!     analyzer.reanalyze_function(func_addr);
//! }
//! ```

use crate::analysis_cache::{AnalysisCache, FunctionCacheKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during incremental analysis.
#[derive(Debug, Error)]
pub enum IncrementalError {
    #[error("Failed to compute binary diff: {0}")]
    DiffFailed(String),

    #[error("Invalid address range: {start:#x} - {end:#x}")]
    InvalidRange { start: u64, end: u64 },

    #[error("Function not found: {0:#x}")]
    FunctionNotFound(u64),

    #[error("Cache error: {0}")]
    CacheError(String),
}

/// Result type for incremental analysis operations.
pub type IncrementalResult<T> = Result<T, IncrementalError>;

/// A patch representing a change to binary content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Patch {
    /// Start address of the patched region.
    pub address: u64,

    /// Original bytes (before patch).
    pub old_bytes: Vec<u8>,

    /// New bytes (after patch).
    pub new_bytes: Vec<u8>,

    /// Type of patch.
    pub patch_type: PatchType,
}

impl Patch {
    /// Create a new patch.
    pub fn new(address: u64, old_bytes: Vec<u8>, new_bytes: Vec<u8>) -> Self {
        let patch_type = if old_bytes.is_empty() {
            PatchType::Insertion
        } else if new_bytes.is_empty() {
            PatchType::Deletion
        } else if old_bytes.len() == new_bytes.len() {
            PatchType::Replacement
        } else {
            PatchType::SizeChange
        };

        Self {
            address,
            old_bytes,
            new_bytes,
            patch_type,
        }
    }

    /// Get the end address of the original region.
    pub fn old_end(&self) -> u64 {
        self.address + self.old_bytes.len() as u64
    }

    /// Get the end address of the new region.
    pub fn new_end(&self) -> u64 {
        self.address + self.new_bytes.len() as u64
    }

    /// Get the size delta (positive = expansion, negative = shrink).
    pub fn size_delta(&self) -> i64 {
        self.new_bytes.len() as i64 - self.old_bytes.len() as i64
    }

    /// Check if this patch overlaps with an address range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.address < end && self.old_end() > start
    }
}

/// Type of patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PatchType {
    /// Bytes were inserted (old_bytes is empty).
    Insertion,

    /// Bytes were deleted (new_bytes is empty).
    Deletion,

    /// Bytes were replaced with same-size content.
    Replacement,

    /// Bytes were replaced with different-size content.
    SizeChange,
}

/// A collection of patches applied to a binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PatchSet {
    /// Individual patches, sorted by address.
    pub patches: Vec<Patch>,

    /// Total size delta from all patches.
    pub total_delta: i64,
}

impl PatchSet {
    /// Create a new empty patch set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch to the set.
    pub fn add_patch(&mut self, patch: Patch) {
        self.total_delta += patch.size_delta();

        // Insert sorted by address
        let pos = self.patches.partition_point(|p| p.address < patch.address);
        self.patches.insert(pos, patch);
    }

    /// Get all patches that overlap with a given address range.
    pub fn patches_in_range(&self, start: u64, end: u64) -> Vec<&Patch> {
        self.patches
            .iter()
            .filter(|p| p.overlaps(start, end))
            .collect()
    }

    /// Check if any patches affect a given address range.
    pub fn affects_range(&self, start: u64, end: u64) -> bool {
        self.patches.iter().any(|p| p.overlaps(start, end))
    }

    /// Get the number of patches.
    pub fn len(&self) -> usize {
        self.patches.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Merge overlapping or adjacent patches.
    pub fn coalesce(&mut self) {
        if self.patches.len() < 2 {
            return;
        }

        let mut merged = Vec::with_capacity(self.patches.len());
        let mut current = self.patches[0].clone();

        for patch in self.patches.iter().skip(1) {
            // Check if patches are adjacent or overlapping
            if patch.address <= current.old_end() {
                // Merge: extend current patch
                let gap = patch.address.saturating_sub(current.old_end());
                if gap > 0 {
                    // Fill gap with zeros (or could copy from original)
                    current.old_bytes.extend(vec![0u8; gap as usize]);
                    current.new_bytes.extend(vec![0u8; gap as usize]);
                }
                current.old_bytes.extend(&patch.old_bytes);
                current.new_bytes.extend(&patch.new_bytes);
            } else {
                merged.push(current);
                current = patch.clone();
            }
        }
        merged.push(current);

        self.patches = merged;
    }
}

/// Represents a diff between two binary versions.
#[derive(Debug, Clone)]
pub struct BinaryDiff {
    /// The computed patches.
    pub patches: PatchSet,

    /// Hash of the original binary.
    pub old_hash: [u8; 32],

    /// Hash of the new binary.
    pub new_hash: [u8; 32],

    /// Statistics about the diff.
    pub stats: DiffStats,
}

/// Statistics about a binary diff.
#[derive(Debug, Clone, Default)]
pub struct DiffStats {
    /// Number of changed regions.
    pub changed_regions: usize,

    /// Total bytes changed.
    pub bytes_changed: usize,

    /// Number of inserted bytes.
    pub bytes_inserted: usize,

    /// Number of deleted bytes.
    pub bytes_deleted: usize,

    /// Similarity ratio (0.0 = completely different, 1.0 = identical).
    pub similarity: f64,
}

impl BinaryDiff {
    /// Compute the diff between two binary contents.
    pub fn compute(old_data: &[u8], new_data: &[u8]) -> Self {
        let old_hash = Self::compute_hash(old_data);
        let new_hash = Self::compute_hash(new_data);

        // If identical, return empty diff
        if old_hash == new_hash {
            return Self {
                patches: PatchSet::new(),
                old_hash,
                new_hash,
                stats: DiffStats {
                    similarity: 1.0,
                    ..Default::default()
                },
            };
        }

        let mut patches = PatchSet::new();
        let mut stats = DiffStats::default();

        // Simple byte-by-byte diff with run-length encoding
        let min_len = old_data.len().min(new_data.len());
        let mut i = 0;
        let mut same_bytes = 0;

        while i < min_len {
            if old_data[i] == new_data[i] {
                same_bytes += 1;
                i += 1;
            } else {
                // Find the extent of the difference
                let start = i;
                while i < min_len && old_data[i] != new_data[i] {
                    i += 1;
                }

                let old_bytes = old_data[start..i].to_vec();
                let new_bytes = new_data[start..i].to_vec();
                stats.bytes_changed += old_bytes.len().max(new_bytes.len());

                patches.add_patch(Patch::new(start as u64, old_bytes, new_bytes));
                stats.changed_regions += 1;
            }
        }

        // Handle size differences
        if old_data.len() > min_len {
            // Deletion at the end
            let deleted = old_data[min_len..].to_vec();
            stats.bytes_deleted += deleted.len();
            patches.add_patch(Patch::new(min_len as u64, deleted, vec![]));
            stats.changed_regions += 1;
        } else if new_data.len() > min_len {
            // Insertion at the end
            let inserted = new_data[min_len..].to_vec();
            stats.bytes_inserted += inserted.len();
            patches.add_patch(Patch::new(min_len as u64, vec![], inserted));
            stats.changed_regions += 1;
        }

        // Calculate similarity
        let total_bytes = old_data.len().max(new_data.len());
        if total_bytes > 0 {
            stats.similarity = same_bytes as f64 / total_bytes as f64;
        }

        Self {
            patches,
            old_hash,
            new_hash,
            stats,
        }
    }

    /// Compute hash of binary content.
    fn compute_hash(data: &[u8]) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let hash = hasher.finish();

        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_le_bytes());
        result[8..16].copy_from_slice(&(data.len() as u64).to_le_bytes());

        // Simple checksum for remaining bytes
        let checksum: u64 = data.iter().map(|&b| b as u64).sum();
        result[16..24].copy_from_slice(&checksum.to_le_bytes());

        result
    }
}

/// Information about a function for incremental analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionInfo {
    /// Function entry address.
    pub address: u64,

    /// Function size in bytes.
    pub size: usize,

    /// Functions that this function calls.
    pub callees: HashSet<u64>,

    /// Functions that call this function.
    pub callers: HashSet<u64>,

    /// Content hash for cache key generation.
    pub content_hash: u64,
}

impl FunctionInfo {
    /// Create new function info.
    pub fn new(address: u64, size: usize) -> Self {
        Self {
            address,
            size,
            callees: HashSet::new(),
            callers: HashSet::new(),
            content_hash: 0,
        }
    }

    /// Get the end address of the function.
    pub fn end_address(&self) -> u64 {
        self.address + self.size as u64
    }

    /// Check if this function overlaps with an address range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.address < end && self.end_address() > start
    }
}

/// Tracks analysis dependencies for incremental updates.
#[derive(Debug, Default)]
pub struct DependencyTracker {
    /// Map from function address to function info.
    functions: HashMap<u64, FunctionInfo>,

    /// Map from address ranges to function addresses.
    address_map: Vec<(u64, u64, u64)>, // (start, end, func_addr)
}

impl DependencyTracker {
    /// Create a new dependency tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a function to track.
    pub fn add_function(&mut self, info: FunctionInfo) {
        let addr = info.address;
        let start = info.address;
        let end = info.end_address();

        self.address_map.push((start, end, addr));
        self.functions.insert(addr, info);

        // Keep address map sorted for binary search
        self.address_map.sort_by_key(|(start, _, _)| *start);
    }

    /// Add a call edge between functions.
    pub fn add_call_edge(&mut self, caller: u64, callee: u64) {
        if let Some(caller_info) = self.functions.get_mut(&caller) {
            caller_info.callees.insert(callee);
        }
        if let Some(callee_info) = self.functions.get_mut(&callee) {
            callee_info.callers.insert(caller);
        }
    }

    /// Find functions affected by patches in an address range.
    pub fn functions_in_range(&self, start: u64, end: u64) -> Vec<u64> {
        self.address_map
            .iter()
            .filter(|(s, e, _)| *s < end && *e > start)
            .map(|(_, _, addr)| *addr)
            .collect()
    }

    /// Get all functions that transitively depend on a given function.
    pub fn transitive_callers(&self, func_addr: u64) -> HashSet<u64> {
        let mut result = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(info) = self.functions.get(&func_addr) {
            for &caller in &info.callers {
                queue.push_back(caller);
            }
        }

        while let Some(addr) = queue.pop_front() {
            if result.insert(addr) {
                if let Some(info) = self.functions.get(&addr) {
                    for &caller in &info.callers {
                        if !result.contains(&caller) {
                            queue.push_back(caller);
                        }
                    }
                }
            }
        }

        result
    }

    /// Get all functions that a given function transitively depends on.
    pub fn transitive_callees(&self, func_addr: u64) -> HashSet<u64> {
        let mut result = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(info) = self.functions.get(&func_addr) {
            for &callee in &info.callees {
                queue.push_back(callee);
            }
        }

        while let Some(addr) = queue.pop_front() {
            if result.insert(addr) {
                if let Some(info) = self.functions.get(&addr) {
                    for &callee in &info.callees {
                        if !result.contains(&callee) {
                            queue.push_back(callee);
                        }
                    }
                }
            }
        }

        result
    }

    /// Get function info.
    pub fn get_function(&self, addr: u64) -> Option<&FunctionInfo> {
        self.functions.get(&addr)
    }

    /// Get the number of tracked functions.
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

/// Level of analysis invalidation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InvalidationLevel {
    /// Only local analysis (disassembly, CFG) is invalid.
    Local,

    /// Data flow analysis is invalid.
    DataFlow,

    /// Type inference is invalid.
    Types,

    /// Interprocedural analysis is invalid.
    Interprocedural,

    /// Everything is invalid.
    All,
}

/// Result of analyzing which functions need re-analysis.
#[derive(Debug, Clone, Default)]
pub struct AffectedAnalysis {
    /// Functions that need full re-analysis.
    pub full_reanalysis: HashSet<u64>,

    /// Functions that need data flow re-analysis.
    pub dataflow_reanalysis: HashSet<u64>,

    /// Functions that need type re-inference.
    pub type_reanalysis: HashSet<u64>,

    /// Functions that need interprocedural re-analysis.
    pub interprocedural_reanalysis: HashSet<u64>,
}

impl AffectedAnalysis {
    /// Get all affected functions.
    pub fn all_affected(&self) -> HashSet<u64> {
        let mut result = self.full_reanalysis.clone();
        result.extend(&self.dataflow_reanalysis);
        result.extend(&self.type_reanalysis);
        result.extend(&self.interprocedural_reanalysis);
        result
    }

    /// Check if any functions are affected.
    pub fn is_empty(&self) -> bool {
        self.full_reanalysis.is_empty()
            && self.dataflow_reanalysis.is_empty()
            && self.type_reanalysis.is_empty()
            && self.interprocedural_reanalysis.is_empty()
    }

    /// Get total count of affected functions.
    pub fn total_affected(&self) -> usize {
        self.all_affected().len()
    }
}

/// Manages incremental analysis updates.
pub struct IncrementalAnalyzer {
    /// The analysis cache.
    cache: Arc<AnalysisCache>,

    /// Dependency tracker.
    dependencies: DependencyTracker,

    /// Whether to propagate changes through call graph.
    propagate_interprocedural: bool,

    /// Statistics.
    stats: IncrementalStats,
}

/// Statistics about incremental analysis.
#[derive(Debug, Clone, Default)]
pub struct IncrementalStats {
    /// Number of functions fully reanalyzed.
    pub full_reanalysis_count: usize,

    /// Number of functions with partial reanalysis.
    pub partial_reanalysis_count: usize,

    /// Number of cache entries invalidated.
    pub cache_invalidations: usize,

    /// Estimated time saved (compared to full reanalysis).
    pub estimated_time_saved_percent: f64,
}

impl IncrementalAnalyzer {
    /// Create a new incremental analyzer.
    pub fn new(cache: Arc<AnalysisCache>, dependencies: DependencyTracker) -> Self {
        Self {
            cache,
            dependencies,
            propagate_interprocedural: true,
            stats: IncrementalStats::default(),
        }
    }

    /// Set whether to propagate changes through call graph.
    pub fn set_interprocedural_propagation(&mut self, enable: bool) {
        self.propagate_interprocedural = enable;
    }

    /// Analyze which functions are affected by a patch set.
    pub fn analyze_affected(&self, patches: &PatchSet) -> AffectedAnalysis {
        let mut affected = AffectedAnalysis::default();

        // Find directly affected functions
        for patch in &patches.patches {
            let functions = self
                .dependencies
                .functions_in_range(patch.address, patch.old_end());

            for func_addr in functions {
                // Size changes require full reanalysis
                if patch.patch_type == PatchType::SizeChange
                    || patch.patch_type == PatchType::Insertion
                    || patch.patch_type == PatchType::Deletion
                {
                    affected.full_reanalysis.insert(func_addr);
                } else {
                    // Simple replacement might only need local reanalysis
                    affected.full_reanalysis.insert(func_addr);
                }
            }
        }

        // Propagate through call graph if enabled
        if self.propagate_interprocedural {
            for &func_addr in affected.full_reanalysis.clone().iter() {
                // Callers may need interprocedural reanalysis
                let callers = self.dependencies.transitive_callers(func_addr);
                affected.interprocedural_reanalysis.extend(callers);

                // If a callee changed, callers may need type reanalysis
                let callers = self.dependencies.transitive_callers(func_addr);
                affected.type_reanalysis.extend(callers);
            }
        }

        // Remove duplicates (full reanalysis supersedes partial)
        affected
            .dataflow_reanalysis
            .retain(|a| !affected.full_reanalysis.contains(a));
        affected
            .type_reanalysis
            .retain(|a| !affected.full_reanalysis.contains(a));
        affected
            .interprocedural_reanalysis
            .retain(|a| !affected.full_reanalysis.contains(a));

        affected
    }

    /// Apply patches and invalidate affected cache entries.
    pub fn apply_patches(&mut self, patches: &PatchSet) -> AffectedAnalysis {
        let affected = self.analyze_affected(patches);

        // Invalidate cache entries for affected functions
        for &func_addr in &affected.full_reanalysis {
            if let Some(info) = self.dependencies.get_function(func_addr) {
                self.cache
                    .invalidate_range(info.address, info.end_address());
                self.stats.cache_invalidations += 1;
            }
        }

        // Calculate estimated time saved
        let total_functions = self.dependencies.function_count();
        let affected_count = affected.total_affected();
        if total_functions > 0 {
            self.stats.estimated_time_saved_percent =
                (1.0 - (affected_count as f64 / total_functions as f64)) * 100.0;
        }

        self.stats.full_reanalysis_count = affected.full_reanalysis.len();
        self.stats.partial_reanalysis_count = affected.dataflow_reanalysis.len()
            + affected.type_reanalysis.len()
            + affected.interprocedural_reanalysis.len();

        affected
    }

    /// Get the cache key for a function given new binary content.
    pub fn get_cache_key(&self, func_addr: u64, new_code: &[u8]) -> FunctionCacheKey {
        FunctionCacheKey::new(func_addr, new_code)
    }

    /// Get statistics.
    pub fn stats(&self) -> &IncrementalStats {
        &self.stats
    }

    /// Get the dependency tracker.
    pub fn dependencies(&self) -> &DependencyTracker {
        &self.dependencies
    }

    /// Get the dependency tracker mutably.
    pub fn dependencies_mut(&mut self) -> &mut DependencyTracker {
        &mut self.dependencies
    }
}

/// Builder for creating an incremental analyzer from analysis results.
pub struct IncrementalAnalyzerBuilder {
    cache: Arc<AnalysisCache>,
    dependencies: DependencyTracker,
}

impl IncrementalAnalyzerBuilder {
    /// Create a new builder.
    pub fn new(cache: Arc<AnalysisCache>) -> Self {
        Self {
            cache,
            dependencies: DependencyTracker::new(),
        }
    }

    /// Add a function to track.
    pub fn add_function(mut self, address: u64, size: usize, code: &[u8]) -> Self {
        let mut info = FunctionInfo::new(address, size);
        info.content_hash = FunctionCacheKey::new(address, code).content_hash;
        self.dependencies.add_function(info);
        self
    }

    /// Add a call edge.
    pub fn add_call(mut self, caller: u64, callee: u64) -> Self {
        self.dependencies.add_call_edge(caller, callee);
        self
    }

    /// Build the incremental analyzer.
    pub fn build(self) -> IncrementalAnalyzer {
        IncrementalAnalyzer::new(self.cache, self.dependencies)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis_cache::CacheConfig;

    fn create_test_cache() -> Arc<AnalysisCache> {
        Arc::new(AnalysisCache::new(CacheConfig::default()))
    }

    #[test]
    fn test_patch_creation() {
        let patch = Patch::new(0x1000, vec![0x90], vec![0xCC]);
        assert_eq!(patch.patch_type, PatchType::Replacement);
        assert_eq!(patch.size_delta(), 0);
    }

    #[test]
    fn test_patch_insertion() {
        let patch = Patch::new(0x1000, vec![], vec![0xCC, 0xCC]);
        assert_eq!(patch.patch_type, PatchType::Insertion);
        assert_eq!(patch.size_delta(), 2);
    }

    #[test]
    fn test_patch_deletion() {
        let patch = Patch::new(0x1000, vec![0x90, 0x90], vec![]);
        assert_eq!(patch.patch_type, PatchType::Deletion);
        assert_eq!(patch.size_delta(), -2);
    }

    #[test]
    fn test_patch_size_change() {
        let patch = Patch::new(0x1000, vec![0x90], vec![0xCC, 0xCC, 0xCC]);
        assert_eq!(patch.patch_type, PatchType::SizeChange);
        assert_eq!(patch.size_delta(), 2);
    }

    #[test]
    fn test_patch_overlap() {
        let patch = Patch::new(0x1000, vec![0; 16], vec![0; 16]);

        assert!(patch.overlaps(0x1000, 0x1010)); // Exact match
        assert!(patch.overlaps(0x0FFF, 0x1001)); // Start overlap
        assert!(patch.overlaps(0x100F, 0x1020)); // End overlap
        assert!(patch.overlaps(0x1004, 0x100C)); // Inside
        assert!(patch.overlaps(0x0F00, 0x2000)); // Contains

        assert!(!patch.overlaps(0x0F00, 0x1000)); // Before
        assert!(!patch.overlaps(0x1010, 0x2000)); // After
    }

    #[test]
    fn test_patch_set_add() {
        let mut set = PatchSet::new();
        set.add_patch(Patch::new(0x2000, vec![0x90], vec![0xCC]));
        set.add_patch(Patch::new(0x1000, vec![0x90], vec![0xCC]));
        set.add_patch(Patch::new(0x3000, vec![0x90], vec![0xCC]));

        // Should be sorted by address
        assert_eq!(set.patches[0].address, 0x1000);
        assert_eq!(set.patches[1].address, 0x2000);
        assert_eq!(set.patches[2].address, 0x3000);
    }

    #[test]
    fn test_patch_set_range_query() {
        let mut set = PatchSet::new();
        set.add_patch(Patch::new(0x1000, vec![0; 16], vec![0; 16]));
        set.add_patch(Patch::new(0x2000, vec![0; 16], vec![0; 16]));
        set.add_patch(Patch::new(0x3000, vec![0; 16], vec![0; 16]));

        let in_range = set.patches_in_range(0x1500, 0x2500);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].address, 0x2000);
    }

    #[test]
    fn test_binary_diff_identical() {
        let data = b"hello world";
        let diff = BinaryDiff::compute(data, data);

        assert!(diff.patches.is_empty());
        assert!((diff.stats.similarity - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_binary_diff_single_byte() {
        let old_data = b"hello world";
        let new_data = b"hello World"; // Capital W

        let diff = BinaryDiff::compute(old_data, new_data);

        assert_eq!(diff.patches.len(), 1);
        assert_eq!(diff.patches.patches[0].address, 6);
        assert_eq!(diff.patches.patches[0].old_bytes, vec![b'w']);
        assert_eq!(diff.patches.patches[0].new_bytes, vec![b'W']);
    }

    #[test]
    fn test_binary_diff_insertion() {
        let old_data = b"hello";
        let new_data = b"hello world";

        let diff = BinaryDiff::compute(old_data, new_data);

        assert_eq!(diff.stats.bytes_inserted, 6);
    }

    #[test]
    fn test_binary_diff_deletion() {
        let old_data = b"hello world";
        let new_data = b"hello";

        let diff = BinaryDiff::compute(old_data, new_data);

        assert_eq!(diff.stats.bytes_deleted, 6);
    }

    #[test]
    fn test_dependency_tracker_add_function() {
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 200));

        assert_eq!(tracker.function_count(), 2);
    }

    #[test]
    fn test_dependency_tracker_call_edges() {
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));
        tracker.add_function(FunctionInfo::new(0x3000, 100));

        tracker.add_call_edge(0x1000, 0x2000);
        tracker.add_call_edge(0x2000, 0x3000);

        let info = tracker.get_function(0x2000).unwrap();
        assert!(info.callers.contains(&0x1000));
        assert!(info.callees.contains(&0x3000));
    }

    #[test]
    fn test_dependency_tracker_transitive_callers() {
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));
        tracker.add_function(FunctionInfo::new(0x3000, 100));

        tracker.add_call_edge(0x1000, 0x2000);
        tracker.add_call_edge(0x2000, 0x3000);

        let callers = tracker.transitive_callers(0x3000);
        assert!(callers.contains(&0x1000));
        assert!(callers.contains(&0x2000));
    }

    #[test]
    fn test_dependency_tracker_transitive_callees() {
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));
        tracker.add_function(FunctionInfo::new(0x3000, 100));

        tracker.add_call_edge(0x1000, 0x2000);
        tracker.add_call_edge(0x2000, 0x3000);

        let callees = tracker.transitive_callees(0x1000);
        assert!(callees.contains(&0x2000));
        assert!(callees.contains(&0x3000));
    }

    #[test]
    fn test_dependency_tracker_functions_in_range() {
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));
        tracker.add_function(FunctionInfo::new(0x3000, 100));

        let funcs = tracker.functions_in_range(0x1800, 0x2200);
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0], 0x2000);
    }

    #[test]
    fn test_incremental_analyzer_affected() {
        let cache = create_test_cache();
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));
        tracker.add_function(FunctionInfo::new(0x3000, 100));

        tracker.add_call_edge(0x1000, 0x2000);

        let analyzer = IncrementalAnalyzer::new(cache, tracker);

        let mut patches = PatchSet::new();
        patches.add_patch(Patch::new(0x2000, vec![0x90], vec![0xCC]));

        let affected = analyzer.analyze_affected(&patches);

        // 0x2000 should need full reanalysis
        assert!(affected.full_reanalysis.contains(&0x2000));

        // 0x1000 should need interprocedural reanalysis (it calls 0x2000)
        assert!(affected.interprocedural_reanalysis.contains(&0x1000));
    }

    #[test]
    fn test_incremental_analyzer_no_propagation() {
        let cache = create_test_cache();
        let mut tracker = DependencyTracker::new();

        tracker.add_function(FunctionInfo::new(0x1000, 100));
        tracker.add_function(FunctionInfo::new(0x2000, 100));

        tracker.add_call_edge(0x1000, 0x2000);

        let mut analyzer = IncrementalAnalyzer::new(cache, tracker);
        analyzer.set_interprocedural_propagation(false);

        let mut patches = PatchSet::new();
        patches.add_patch(Patch::new(0x2000, vec![0x90], vec![0xCC]));

        let affected = analyzer.analyze_affected(&patches);

        // Without propagation, only direct change is affected
        assert!(affected.full_reanalysis.contains(&0x2000));
        assert!(affected.interprocedural_reanalysis.is_empty());
    }

    #[test]
    fn test_incremental_analyzer_builder() {
        let cache = create_test_cache();

        let analyzer = IncrementalAnalyzerBuilder::new(cache)
            .add_function(0x1000, 100, &[0x90; 100])
            .add_function(0x2000, 100, &[0x90; 100])
            .add_call(0x1000, 0x2000)
            .build();

        assert_eq!(analyzer.dependencies().function_count(), 2);
    }

    #[test]
    fn test_affected_analysis_all_affected() {
        let mut affected = AffectedAnalysis::default();
        affected.full_reanalysis.insert(0x1000);
        affected.dataflow_reanalysis.insert(0x2000);
        affected.type_reanalysis.insert(0x3000);
        affected.interprocedural_reanalysis.insert(0x4000);

        let all = affected.all_affected();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_affected_analysis_empty() {
        let affected = AffectedAnalysis::default();
        assert!(affected.is_empty());
    }

    #[test]
    fn test_incremental_stats() {
        let cache = create_test_cache();
        let mut tracker = DependencyTracker::new();

        // Add 10 functions
        for i in 0..10 {
            tracker.add_function(FunctionInfo::new(0x1000 + i * 0x100, 100));
        }

        let mut analyzer = IncrementalAnalyzer::new(cache, tracker);

        let mut patches = PatchSet::new();
        patches.add_patch(Patch::new(0x1200, vec![0x90], vec![0xCC])); // Affects 1 function

        let _affected = analyzer.apply_patches(&patches);

        // 1 out of 10 functions affected = 90% time saved
        assert!(analyzer.stats().estimated_time_saved_percent > 80.0);
    }

    #[test]
    fn test_patch_set_coalesce() {
        let mut set = PatchSet::new();
        set.add_patch(Patch::new(0x1000, vec![0x90], vec![0xCC]));
        set.add_patch(Patch::new(0x1001, vec![0x90], vec![0xCC]));
        set.add_patch(Patch::new(0x1002, vec![0x90], vec![0xCC]));

        assert_eq!(set.len(), 3);

        set.coalesce();

        // Should merge into single patch
        assert_eq!(set.len(), 1);
        assert_eq!(set.patches[0].old_bytes.len(), 3);
    }

    #[test]
    fn test_function_info_overlaps() {
        let info = FunctionInfo::new(0x1000, 100);

        assert!(info.overlaps(0x1000, 0x1064)); // Exact match
        assert!(info.overlaps(0x0FFF, 0x1001)); // Start overlap
        assert!(info.overlaps(0x1063, 0x1100)); // End overlap
        assert!(!info.overlaps(0x0F00, 0x1000)); // Before
        assert!(!info.overlaps(0x1064, 0x2000)); // After
    }

    #[test]
    fn test_diff_stats() {
        let old_data = b"hello world";
        let new_data = b"HELLO World";

        let diff = BinaryDiff::compute(old_data, new_data);

        assert!(diff.stats.changed_regions > 0);
        assert!(diff.stats.similarity > 0.0);
        assert!(diff.stats.similarity < 1.0);
    }

    #[test]
    fn test_incremental_error_display() {
        let err = IncrementalError::DiffFailed("test".to_string());
        assert!(err.to_string().contains("diff"));

        let err = IncrementalError::InvalidRange {
            start: 0x1000,
            end: 0x2000,
        };
        assert!(err.to_string().contains("1000"));

        let err = IncrementalError::FunctionNotFound(0x1000);
        assert!(err.to_string().contains("1000"));

        let err = IncrementalError::CacheError("test".to_string());
        assert!(err.to_string().contains("test"));
    }
}
