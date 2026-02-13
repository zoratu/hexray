# Incremental Analysis Examples

This guide covers `hexray_analysis::incremental` primitives for patch-aware reanalysis.

## 1) Compute binary diffs and patch sets

```rust
use hexray_analysis::{BinaryDiff, PatchSet};

let old_bytes = std::fs::read("original.bin")?;
let new_bytes = std::fs::read("patched.bin")?;

let diff = BinaryDiff::compute(&old_bytes, &new_bytes);
println!("changed ranges: {}", diff.patches.len());

let mut patch_set = PatchSet::new();
for patch in diff.patches {
    patch_set.add_patch(patch);
}
patch_set.coalesce();
# Ok::<(), Box<dyn std::error::Error>>(())
```

## 2) Build dependency graph once, reuse many times

```rust
use hexray_analysis::{DependencyTracker, FunctionInfo};

let mut deps = DependencyTracker::new();

deps.add_function(FunctionInfo::new(0x401000, 0x80));
deps.add_function(FunctionInfo::new(0x401200, 0x50));

// caller -> callee
 deps.add_call_edge(0x401000, 0x401200);

let impacted_callers = deps.transitive_callers(0x401200);
println!("transitive callers: {}", impacted_callers.len());
```

Populate this from discovered functions/callgraph, then keep it in memory for repeated patch application.

## 3) Analyze affected functions with propagation

```rust
use hexray_analysis::{AnalysisCache, CacheConfig, IncrementalAnalyzerBuilder, Patch, PatchSet};
use std::sync::Arc;

let cache = Arc::new(AnalysisCache::new(CacheConfig::default()));

let mut analyzer = IncrementalAnalyzerBuilder::new(cache)
    .add_function(0x401000, 0x80, b"\x55\x48\x89\xe5")
    .add_function(0x401200, 0x50, b"\x55\x48\x89\xe5")
    .add_call(0x401000, 0x401200)
    .build();

analyzer.set_interprocedural_propagation(true);

let mut patches = PatchSet::new();
patches.add_patch(Patch::new(
    0x401210,
    vec![0x90, 0x90],
    vec![0x31, 0xC0],
));

let affected = analyzer.apply_patches(&patches);
println!("total affected: {}", affected.total_affected());
```

## 4) Cache key generation after patch update

```rust
use hexray_analysis::IncrementalAnalyzer;

fn cache_key_after_patch(analyzer: &IncrementalAnalyzer, addr: u64, code: &[u8]) {
    let key = analyzer.get_cache_key(addr, code);
    println!("cache key: {}", key.to_disk_key());
}
```

Use `get_cache_key` for stable lookup of recomputed function analyses after patching.

## 5) Operational recommendations

- Keep `DependencyTracker` warm between patch runs.
- Coalesce `PatchSet` before analysis to reduce duplicate invalidation.
- Enable inter-procedural propagation for release/validation runs.
- Disable propagation for very fast local edit/test loops where false negatives are acceptable.
