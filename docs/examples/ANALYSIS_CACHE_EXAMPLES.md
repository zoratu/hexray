# Analysis Cache Examples

This guide shows practical usage of `hexray_analysis::analysis_cache` for decompiler and analysis pipelines.

## 1) Memory-only cache for single-process runs

```rust
use hexray_analysis::{AnalysisCache, CacheConfig, FunctionCacheKey};

let config = CacheConfig::default()
    .with_max_memory_size(256 * 1024 * 1024)
    .with_compression(true);
let cache = AnalysisCache::new(config);

let key = FunctionCacheKey::new(0x401000, b"\x55\x48\x89\xe5");
if let Some(cfg) = cache.get_cfg(&key) {
    println!("cache hit with {} blocks", cfg.blocks.len());
}
```

Use this mode when running repeated analyses in one process and you do not need persistence across runs.

## 2) Disk-backed cache for repeatable local workflows

```rust
use hexray_analysis::{AnalysisCache, CacheConfig};
use std::time::Duration;

let cache = AnalysisCache::new(
    CacheConfig::default()
        .with_disk_path(".hexray-cache")
        .with_max_memory_size(512 * 1024 * 1024)
        .with_max_age(Duration::from_secs(24 * 60 * 60))
        .with_compression(true),
);

// Persist in-memory state to disk at stable checkpoints.
cache.flush()?;
# Ok::<(), hexray_analysis::CacheError>(())
```

Use disk cache when iterating on the same binaries across multiple runs.

## 3) Cache invalidation after patching bytes

```rust
use hexray_analysis::AnalysisCache;

fn invalidate_patch_range(cache: &AnalysisCache, start: u64, end: u64) {
    cache.invalidate_range(start, end);
    cache.clear_expired();
}
```

`invalidate_range` is the critical step when binary bytes changed for affected functions.

## 4) Cache observability and guardrails

```rust
use hexray_analysis::AnalysisCache;

fn report(cache: &AnalysisCache) {
    let stats = cache.stats();
    println!(
        "hits={} misses={} evictions={} hit_rate={:.2}% entries={} mem={}B",
        stats.hits,
        stats.misses,
        stats.evictions,
        stats.hit_rate() * 100.0,
        cache.entry_count(),
        cache.memory_usage(),
    );
}
```

Recommended alert thresholds in CI/local automation:
- Hit rate drop larger than 20% from baseline.
- Sustained eviction growth with stable workload.
- Memory usage repeatedly reaching configured cap.

## 5) Shared cache handle for parallel analyzers

```rust
use hexray_analysis::{create_shared_cache, CacheConfig};

let shared = create_shared_cache(CacheConfig::default());
let cache_a = shared.clone();
let cache_b = shared.clone();

// Use cache_a/cache_b across worker threads or pipeline stages.
```

This pattern keeps cache state consistent across parallel decompilation workers.
