//! Analysis result caching for improved performance across runs.
//!
//! This module provides caching infrastructure for:
//! - Disassembly results
//! - CFG analysis
//! - Data flow analysis
//! - Type inference results
//! - Call graph construction
//!
//! The cache uses content-based hashing to detect when cached results
//! are stale and need recomputation.
//!
//! # Example
//!
//! ```ignore
//! use hexray_analysis::analysis_cache::{AnalysisCache, CacheConfig, FunctionCacheKey};
//!
//! // Create a cache with disk persistence
//! let config = CacheConfig::default().with_disk_path("/tmp/hexray_cache");
//! let cache = AnalysisCache::new(config);
//!
//! // Check for cached disassembly
//! let key = FunctionCacheKey::new(0x1000, &code_bytes);
//! if let Some(cached) = cache.get_disassembly(&key) {
//!     // Use cached result
//! } else {
//!     // Disassemble and cache
//!     let result = disassemble(code_bytes);
//!     cache.store_disassembly(&key, &result);
//! }
//!
//! // Persist to disk
//! cache.flush()?;
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Cache file format version (reserved for future compatibility checks).
#[allow(dead_code)]
const CACHE_VERSION: u32 = 1;

/// Default maximum memory cache size in bytes (100 MB).
const DEFAULT_MAX_MEMORY_SIZE: usize = 100 * 1024 * 1024;

/// Default maximum cache age in seconds (7 days).
const DEFAULT_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Errors that can occur during cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Cache entry not found")]
    NotFound,

    #[error("Cache entry expired")]
    Expired,

    #[error("Cache version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Cache corrupted: {0}")]
    Corrupted(String),
}

/// Result type for cache operations.
pub type CacheResult<T> = Result<T, CacheError>;

/// Configuration for the analysis cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Path to disk cache directory (None for memory-only).
    pub disk_path: Option<PathBuf>,

    /// Maximum memory cache size in bytes.
    pub max_memory_size: usize,

    /// Maximum age for cache entries.
    pub max_age: Duration,

    /// Whether to compress cached data.
    pub compress: bool,

    /// Whether to enable LRU eviction.
    pub enable_lru: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            disk_path: None,
            max_memory_size: DEFAULT_MAX_MEMORY_SIZE,
            max_age: Duration::from_secs(DEFAULT_MAX_AGE_SECS),
            compress: false,
            enable_lru: true,
        }
    }
}

impl CacheConfig {
    /// Set the disk cache path.
    pub fn with_disk_path<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.disk_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set the maximum memory size.
    pub fn with_max_memory_size(mut self, size: usize) -> Self {
        self.max_memory_size = size;
        self
    }

    /// Set the maximum cache age.
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Enable compression.
    pub fn with_compression(mut self, enable: bool) -> Self {
        self.compress = enable;
        self
    }
}

/// A cache key based on function address and content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FunctionCacheKey {
    /// Function entry address.
    pub address: u64,

    /// Hash of the function's binary content.
    pub content_hash: u64,

    /// Size of the function in bytes.
    pub size: usize,
}

impl FunctionCacheKey {
    /// Create a new cache key from function address and code bytes.
    pub fn new(address: u64, code: &[u8]) -> Self {
        Self {
            address,
            content_hash: Self::compute_hash(code),
            size: code.len(),
        }
    }

    /// Compute a fast hash of code bytes.
    fn compute_hash(data: &[u8]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }

    /// Convert to a string key for disk storage.
    pub fn to_disk_key(&self) -> String {
        format!(
            "{:016x}_{:016x}_{}",
            self.address, self.content_hash, self.size
        )
    }
}

/// A cache key for binary-level analysis (call graph, vtables, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BinaryCacheKey {
    /// Hash of the entire binary.
    pub binary_hash: [u8; 32],

    /// Analysis type identifier.
    pub analysis_type: String,
}

impl BinaryCacheKey {
    /// Create a new binary cache key.
    pub fn new(binary_hash: [u8; 32], analysis_type: impl Into<String>) -> Self {
        Self {
            binary_hash,
            analysis_type: analysis_type.into(),
        }
    }

    /// Convert to a string key for disk storage.
    pub fn to_disk_key(&self) -> String {
        let hash_str: String = self
            .binary_hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        format!("{}_{}", hash_str, self.analysis_type)
    }
}

/// Metadata for a cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntryMeta {
    /// When the entry was created.
    pub created_at: u64,

    /// When the entry was last accessed.
    pub last_accessed: u64,

    /// Number of times accessed.
    pub access_count: u64,

    /// Size in bytes.
    pub size: usize,
}

impl CacheEntryMeta {
    fn new(size: usize) -> Self {
        let now = current_timestamp();
        Self {
            created_at: now,
            last_accessed: now,
            access_count: 0,
            size,
        }
    }

    fn touch(&mut self) {
        self.last_accessed = current_timestamp();
        self.access_count += 1;
    }

    fn is_expired(&self, max_age: Duration) -> bool {
        let now = current_timestamp();
        now.saturating_sub(self.created_at) > max_age.as_secs()
    }
}

/// Cached disassembly result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDisassembly {
    /// Disassembled instructions as serializable representation.
    pub instructions: Vec<CachedInstruction>,

    /// Total instruction count.
    pub instruction_count: usize,

    /// Whether disassembly completed successfully.
    pub success: bool,

    /// Error message if any.
    pub error: Option<String>,
}

/// Serializable instruction representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedInstruction {
    pub address: u64,
    pub size: usize,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
}

/// Cached CFG analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCfg {
    /// Number of basic blocks.
    pub block_count: usize,

    /// Number of edges.
    pub edge_count: usize,

    /// Entry block ID.
    pub entry_block: u32,

    /// Serialized block data.
    pub blocks: Vec<CachedBasicBlock>,

    /// Edges as (from, to) pairs.
    pub edges: Vec<(u32, u32)>,
}

/// Serializable basic block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedBasicBlock {
    pub id: u32,
    pub start_address: u64,
    pub end_address: u64,
    pub instruction_count: usize,
    pub terminator: String,
}

/// Cached data flow analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDataFlow {
    /// Def-use chains.
    pub def_use_chains: Vec<CachedDefUse>,

    /// Live variables at each block entry.
    pub live_in: HashMap<u32, Vec<String>>,

    /// Live variables at each block exit.
    pub live_out: HashMap<u32, Vec<String>>,
}

/// Serializable def-use chain entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedDefUse {
    pub variable: String,
    pub def_address: u64,
    pub use_addresses: Vec<u64>,
}

/// Cached type inference result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedTypes {
    /// Variable types.
    pub variable_types: HashMap<String, String>,

    /// Parameter types.
    pub parameter_types: Vec<String>,

    /// Return type.
    pub return_type: Option<String>,

    /// Confidence score.
    pub confidence: f64,
}

/// Cached call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedCallGraph {
    /// Function entries.
    pub functions: Vec<CachedFunction>,

    /// Call edges as (caller, callee) address pairs.
    pub calls: Vec<(u64, u64)>,

    /// Indirect call sites.
    pub indirect_calls: Vec<u64>,
}

/// Serializable function entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFunction {
    pub address: u64,
    pub size: usize,
    pub name: Option<String>,
    pub is_thunk: bool,
}

/// In-memory cache entry.
struct MemoryCacheEntry {
    data: Vec<u8>,
    meta: CacheEntryMeta,
}

/// The main analysis cache.
pub struct AnalysisCache {
    config: CacheConfig,

    /// In-memory cache for disassembly.
    disasm_cache: RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,

    /// In-memory cache for CFGs.
    cfg_cache: RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,

    /// In-memory cache for data flow.
    dataflow_cache: RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,

    /// In-memory cache for types.
    types_cache: RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,

    /// In-memory cache for binary-level analysis.
    binary_cache: RwLock<HashMap<BinaryCacheKey, MemoryCacheEntry>>,

    /// Current memory usage.
    memory_usage: RwLock<usize>,

    /// Statistics.
    stats: RwLock<CacheStats>,
}

/// Cache statistics.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stores: u64,
    pub evictions: u64,
    pub disk_reads: u64,
    pub disk_writes: u64,
}

impl CacheStats {
    /// Get the cache hit rate.
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

impl AnalysisCache {
    /// Create a new analysis cache.
    pub fn new(config: CacheConfig) -> Self {
        // Create disk cache directory if specified
        if let Some(ref path) = config.disk_path {
            let _ = fs::create_dir_all(path);
        }

        Self {
            config,
            disasm_cache: RwLock::new(HashMap::new()),
            cfg_cache: RwLock::new(HashMap::new()),
            dataflow_cache: RwLock::new(HashMap::new()),
            types_cache: RwLock::new(HashMap::new()),
            binary_cache: RwLock::new(HashMap::new()),
            memory_usage: RwLock::new(0),
            stats: RwLock::new(CacheStats::default()),
        }
    }

    /// Create a new memory-only cache.
    pub fn memory_only() -> Self {
        Self::new(CacheConfig::default())
    }

    /// Create a cache with disk persistence.
    pub fn with_disk<P: AsRef<Path>>(path: P) -> Self {
        Self::new(CacheConfig::default().with_disk_path(path))
    }

    // ==================== Disassembly Cache ====================

    /// Get cached disassembly result.
    pub fn get_disassembly(&self, key: &FunctionCacheKey) -> Option<CachedDisassembly> {
        self.get_entry(&self.disasm_cache, key, "disasm")
    }

    /// Store disassembly result.
    pub fn store_disassembly(&self, key: &FunctionCacheKey, value: &CachedDisassembly) {
        self.store_entry(&self.disasm_cache, key, value, "disasm");
    }

    // ==================== CFG Cache ====================

    /// Get cached CFG.
    pub fn get_cfg(&self, key: &FunctionCacheKey) -> Option<CachedCfg> {
        self.get_entry(&self.cfg_cache, key, "cfg")
    }

    /// Store CFG.
    pub fn store_cfg(&self, key: &FunctionCacheKey, value: &CachedCfg) {
        self.store_entry(&self.cfg_cache, key, value, "cfg");
    }

    // ==================== Data Flow Cache ====================

    /// Get cached data flow analysis.
    pub fn get_dataflow(&self, key: &FunctionCacheKey) -> Option<CachedDataFlow> {
        self.get_entry(&self.dataflow_cache, key, "dataflow")
    }

    /// Store data flow analysis.
    pub fn store_dataflow(&self, key: &FunctionCacheKey, value: &CachedDataFlow) {
        self.store_entry(&self.dataflow_cache, key, value, "dataflow");
    }

    // ==================== Type Cache ====================

    /// Get cached type inference.
    pub fn get_types(&self, key: &FunctionCacheKey) -> Option<CachedTypes> {
        self.get_entry(&self.types_cache, key, "types")
    }

    /// Store type inference.
    pub fn store_types(&self, key: &FunctionCacheKey, value: &CachedTypes) {
        self.store_entry(&self.types_cache, key, value, "types");
    }

    // ==================== Binary-Level Cache ====================

    /// Get cached call graph.
    pub fn get_call_graph(&self, key: &BinaryCacheKey) -> Option<CachedCallGraph> {
        self.get_binary_entry(key)
    }

    /// Store call graph.
    pub fn store_call_graph(&self, key: &BinaryCacheKey, value: &CachedCallGraph) {
        self.store_binary_entry(key, value);
    }

    // ==================== Generic Entry Methods ====================

    fn get_entry<V: for<'de> Deserialize<'de> + Serialize>(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        key: &FunctionCacheKey,
        category: &str,
    ) -> Option<V> {
        // Try memory cache first
        {
            let mut cache_guard = cache.write().ok()?;
            if let Some(entry) = cache_guard.get_mut(key) {
                if !entry.meta.is_expired(self.config.max_age) {
                    entry.meta.touch();
                    if let Ok(mut stats) = self.stats.write() {
                        stats.hits += 1;
                    }
                    return serde_json::from_slice(&entry.data).ok();
                }
            }
        }

        // Try disk cache
        if let Some(ref disk_path) = self.config.disk_path {
            if let Some(value) = self.load_from_disk::<V>(disk_path, &key.to_disk_key(), category) {
                if let Ok(mut stats) = self.stats.write() {
                    stats.disk_reads += 1;
                }
                // Promote to memory cache
                if let Ok(data) = serde_json::to_vec(&value) {
                    self.insert_memory_entry(cache, key.clone(), data);
                }
                return Some(value);
            }
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
        None
    }

    fn store_entry<V: Serialize>(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        key: &FunctionCacheKey,
        value: &V,
        category: &str,
    ) {
        if let Ok(data) = serde_json::to_vec(value) {
            // Store in memory
            self.insert_memory_entry(cache, key.clone(), data.clone());

            // Store on disk
            if let Some(ref disk_path) = self.config.disk_path {
                self.save_to_disk(disk_path, &key.to_disk_key(), category, &data);
                if let Ok(mut stats) = self.stats.write() {
                    stats.disk_writes += 1;
                }
            }

            if let Ok(mut stats) = self.stats.write() {
                stats.stores += 1;
            }
        }
    }

    fn get_binary_entry<V: for<'de> Deserialize<'de> + Serialize>(
        &self,
        key: &BinaryCacheKey,
    ) -> Option<V> {
        // Try memory cache first
        {
            let mut cache_guard = self.binary_cache.write().ok()?;
            if let Some(entry) = cache_guard.get_mut(key) {
                if !entry.meta.is_expired(self.config.max_age) {
                    entry.meta.touch();
                    if let Ok(mut stats) = self.stats.write() {
                        stats.hits += 1;
                    }
                    return serde_json::from_slice(&entry.data).ok();
                }
            }
        }

        // Try disk cache
        if let Some(ref disk_path) = self.config.disk_path {
            if let Some(value) = self.load_from_disk::<V>(disk_path, &key.to_disk_key(), "binary") {
                if let Ok(mut stats) = self.stats.write() {
                    stats.disk_reads += 1;
                }
                return Some(value);
            }
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.misses += 1;
        }
        None
    }

    fn store_binary_entry<V: Serialize>(&self, key: &BinaryCacheKey, value: &V) {
        if let Ok(data) = serde_json::to_vec(value) {
            // Store in memory
            if let Ok(mut cache) = self.binary_cache.write() {
                let entry = MemoryCacheEntry {
                    data: data.clone(),
                    meta: CacheEntryMeta::new(data.len()),
                };
                cache.insert(key.clone(), entry);
            }

            // Store on disk
            if let Some(ref disk_path) = self.config.disk_path {
                self.save_to_disk(disk_path, &key.to_disk_key(), "binary", &data);
                if let Ok(mut stats) = self.stats.write() {
                    stats.disk_writes += 1;
                }
            }

            if let Ok(mut stats) = self.stats.write() {
                stats.stores += 1;
            }
        }
    }

    fn insert_memory_entry(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        key: FunctionCacheKey,
        data: Vec<u8>,
    ) {
        let size = data.len();

        // Check if we need to evict
        if self.config.enable_lru {
            self.maybe_evict(size);
        }

        if let Ok(mut cache_guard) = cache.write() {
            let entry = MemoryCacheEntry {
                data,
                meta: CacheEntryMeta::new(size),
            };
            cache_guard.insert(key, entry);
        }

        if let Ok(mut usage) = self.memory_usage.write() {
            *usage += size;
        }
    }

    fn maybe_evict(&self, needed_size: usize) {
        let current_usage = self.memory_usage.read().map(|u| *u).unwrap_or(0);
        if current_usage + needed_size <= self.config.max_memory_size {
            return;
        }

        // Evict oldest entries from each cache
        let to_free = (current_usage + needed_size).saturating_sub(self.config.max_memory_size);
        let mut freed = 0;

        // Evict from disasm cache
        freed += self.evict_lru(&self.disasm_cache, to_free - freed);
        if freed >= to_free {
            return;
        }

        // Evict from cfg cache
        freed += self.evict_lru(&self.cfg_cache, to_free - freed);
        if freed >= to_free {
            return;
        }

        // Evict from dataflow cache
        freed += self.evict_lru(&self.dataflow_cache, to_free - freed);
        if freed >= to_free {
            return;
        }

        // Evict from types cache
        self.evict_lru(&self.types_cache, to_free - freed);
    }

    fn evict_lru(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        target_free: usize,
    ) -> usize {
        let mut freed = 0;
        if let Ok(mut cache_guard) = cache.write() {
            // Find oldest entries
            let mut entries: Vec<_> = cache_guard
                .iter()
                .map(|(k, v)| (k.clone(), v.meta.last_accessed, v.meta.size))
                .collect();
            entries.sort_by_key(|(_, accessed, _)| *accessed);

            for (key, _, size) in entries {
                if freed >= target_free {
                    break;
                }
                cache_guard.remove(&key);
                freed += size;
                if let Ok(mut stats) = self.stats.write() {
                    stats.evictions += 1;
                }
            }
        }

        if let Ok(mut usage) = self.memory_usage.write() {
            *usage = usage.saturating_sub(freed);
        }

        freed
    }

    // ==================== Disk Operations ====================

    fn load_from_disk<V: for<'de> Deserialize<'de>>(
        &self,
        base_path: &Path,
        key: &str,
        category: &str,
    ) -> Option<V> {
        let path = base_path.join(category).join(format!("{}.json", key));
        let data = fs::read(&path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    fn save_to_disk(&self, base_path: &Path, key: &str, category: &str, data: &[u8]) {
        let dir = base_path.join(category);
        let _ = fs::create_dir_all(&dir);
        let path = dir.join(format!("{}.json", key));
        let _ = fs::write(&path, data);
    }

    // ==================== Cache Management ====================

    /// Flush all caches to disk.
    pub fn flush(&self) -> CacheResult<()> {
        let Some(ref disk_path) = self.config.disk_path else {
            return Ok(());
        };

        // Flush each cache type
        self.flush_cache(&self.disasm_cache, disk_path, "disasm")?;
        self.flush_cache(&self.cfg_cache, disk_path, "cfg")?;
        self.flush_cache(&self.dataflow_cache, disk_path, "dataflow")?;
        self.flush_cache(&self.types_cache, disk_path, "types")?;

        Ok(())
    }

    fn flush_cache(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        base_path: &Path,
        category: &str,
    ) -> CacheResult<()> {
        let cache_guard = cache
            .read()
            .map_err(|_| CacheError::Corrupted("Failed to acquire read lock".to_string()))?;

        for (key, entry) in cache_guard.iter() {
            self.save_to_disk(base_path, &key.to_disk_key(), category, &entry.data);
        }

        Ok(())
    }

    /// Clear all caches.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.disasm_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.cfg_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.dataflow_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.types_cache.write() {
            cache.clear();
        }
        if let Ok(mut cache) = self.binary_cache.write() {
            cache.clear();
        }
        if let Ok(mut usage) = self.memory_usage.write() {
            *usage = 0;
        }
    }

    /// Clear expired entries.
    pub fn clear_expired(&self) {
        self.clear_expired_from(&self.disasm_cache);
        self.clear_expired_from(&self.cfg_cache);
        self.clear_expired_from(&self.dataflow_cache);
        self.clear_expired_from(&self.types_cache);
    }

    fn clear_expired_from(&self, cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>) {
        if let Ok(mut cache_guard) = cache.write() {
            let max_age = self.config.max_age;
            let mut freed = 0;
            cache_guard.retain(|_, entry| {
                if entry.meta.is_expired(max_age) {
                    freed += entry.meta.size;
                    false
                } else {
                    true
                }
            });
            if let Ok(mut usage) = self.memory_usage.write() {
                *usage = usage.saturating_sub(freed);
            }
        }
    }

    /// Get cache statistics.
    pub fn stats(&self) -> CacheStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Get current memory usage in bytes.
    pub fn memory_usage(&self) -> usize {
        self.memory_usage.read().map(|u| *u).unwrap_or(0)
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        let disasm = self.disasm_cache.read().map(|c| c.len()).unwrap_or(0);
        let cfg = self.cfg_cache.read().map(|c| c.len()).unwrap_or(0);
        let dataflow = self.dataflow_cache.read().map(|c| c.len()).unwrap_or(0);
        let types = self.types_cache.read().map(|c| c.len()).unwrap_or(0);
        let binary = self.binary_cache.read().map(|c| c.len()).unwrap_or(0);
        disasm + cfg + dataflow + types + binary
    }

    /// Invalidate cache entries for a specific address range.
    pub fn invalidate_range(&self, start: u64, end: u64) {
        self.invalidate_range_in(&self.disasm_cache, start, end);
        self.invalidate_range_in(&self.cfg_cache, start, end);
        self.invalidate_range_in(&self.dataflow_cache, start, end);
        self.invalidate_range_in(&self.types_cache, start, end);
    }

    fn invalidate_range_in(
        &self,
        cache: &RwLock<HashMap<FunctionCacheKey, MemoryCacheEntry>>,
        start: u64,
        end: u64,
    ) {
        if let Ok(mut cache_guard) = cache.write() {
            let mut freed = 0;
            cache_guard.retain(|key, entry| {
                let key_end = key.address + key.size as u64;
                let overlaps = key.address < end && key_end > start;
                if overlaps {
                    freed += entry.meta.size;
                }
                !overlaps
            });
            if let Ok(mut usage) = self.memory_usage.write() {
                *usage = usage.saturating_sub(freed);
            }
        }
    }
}

/// Thread-safe shared cache.
pub type SharedAnalysisCache = Arc<AnalysisCache>;

/// Create a shared analysis cache.
pub fn create_shared_cache(config: CacheConfig) -> SharedAnalysisCache {
    Arc::new(AnalysisCache::new(config))
}

/// Get current Unix timestamp.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_key() {
        let code = b"hello world";
        let key = FunctionCacheKey::new(0x1000, code);

        assert_eq!(key.address, 0x1000);
        assert_eq!(key.size, 11);
        assert!(!key.to_disk_key().is_empty());
    }

    #[test]
    fn test_cache_key_different_content() {
        let key1 = FunctionCacheKey::new(0x1000, b"content1");
        let key2 = FunctionCacheKey::new(0x1000, b"content2");

        assert_ne!(key1.content_hash, key2.content_hash);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_memory_cache_basic() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"test code");
        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 0,
            success: true,
            error: None,
        };

        cache.store_disassembly(&key, &disasm);
        let retrieved = cache.get_disassembly(&key);

        assert!(retrieved.is_some());
        assert!(retrieved.unwrap().success);
    }

    #[test]
    fn test_cache_miss() {
        let cache = AnalysisCache::memory_only();
        let key = FunctionCacheKey::new(0x1000, b"test");

        let result = cache.get_disassembly(&key);
        assert!(result.is_none());

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);
    }

    #[test]
    fn test_cache_hit() {
        let cache = AnalysisCache::memory_only();
        let key = FunctionCacheKey::new(0x1000, b"test");

        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 5,
            success: true,
            error: None,
        };

        cache.store_disassembly(&key, &disasm);
        let _ = cache.get_disassembly(&key);

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.stores, 1);
    }

    #[test]
    fn test_disk_cache() {
        let temp_dir = TempDir::new().unwrap();
        let cache = AnalysisCache::with_disk(temp_dir.path());

        let key = FunctionCacheKey::new(0x2000, b"disk test");
        let cfg = CachedCfg {
            block_count: 5,
            edge_count: 4,
            entry_block: 0,
            blocks: vec![],
            edges: vec![],
        };

        cache.store_cfg(&key, &cfg);
        cache.clear(); // Clear memory cache

        // Should load from disk
        let retrieved = cache.get_cfg(&key);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().block_count, 5);
    }

    #[test]
    fn test_cache_invalidation() {
        let cache = AnalysisCache::memory_only();

        // Store entries at different addresses
        for addr in [0x1000u64, 0x2000, 0x3000] {
            let key = FunctionCacheKey::new(addr, &addr.to_le_bytes());
            let disasm = CachedDisassembly {
                instructions: vec![],
                instruction_count: 0,
                success: true,
                error: None,
            };
            cache.store_disassembly(&key, &disasm);
        }

        assert_eq!(cache.entry_count(), 3);

        // Invalidate range covering 0x2000
        cache.invalidate_range(0x1800, 0x2800);

        // Entry at 0x2000 should be gone
        let key = FunctionCacheKey::new(0x2000, &0x2000u64.to_le_bytes());
        assert!(cache.get_disassembly(&key).is_none());
    }

    #[test]
    fn test_clear_cache() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"test");
        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 0,
            success: true,
            error: None,
        };

        cache.store_disassembly(&key, &disasm);
        assert_eq!(cache.entry_count(), 1);

        cache.clear();
        assert_eq!(cache.entry_count(), 0);
    }

    #[test]
    fn test_cfg_cache() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"cfg test");
        let cfg = CachedCfg {
            block_count: 10,
            edge_count: 15,
            entry_block: 0,
            blocks: vec![CachedBasicBlock {
                id: 0,
                start_address: 0x1000,
                end_address: 0x1020,
                instruction_count: 5,
                terminator: "Return".to_string(),
            }],
            edges: vec![(0, 1), (1, 2)],
        };

        cache.store_cfg(&key, &cfg);
        let retrieved = cache.get_cfg(&key).unwrap();

        assert_eq!(retrieved.block_count, 10);
        assert_eq!(retrieved.edge_count, 15);
        assert_eq!(retrieved.blocks.len(), 1);
    }

    #[test]
    fn test_dataflow_cache() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"dataflow test");
        let dataflow = CachedDataFlow {
            def_use_chains: vec![CachedDefUse {
                variable: "rax".to_string(),
                def_address: 0x1000,
                use_addresses: vec![0x1010, 0x1020],
            }],
            live_in: HashMap::from([(0, vec!["rdi".to_string()])]),
            live_out: HashMap::from([(0, vec!["rax".to_string()])]),
        };

        cache.store_dataflow(&key, &dataflow);
        let retrieved = cache.get_dataflow(&key).unwrap();

        assert_eq!(retrieved.def_use_chains.len(), 1);
        assert_eq!(retrieved.def_use_chains[0].use_addresses.len(), 2);
    }

    #[test]
    fn test_types_cache() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"types test");
        let types = CachedTypes {
            variable_types: HashMap::from([
                ("var1".to_string(), "int".to_string()),
                ("var2".to_string(), "char *".to_string()),
            ]),
            parameter_types: vec!["int".to_string(), "char *".to_string()],
            return_type: Some("void".to_string()),
            confidence: 0.85,
        };

        cache.store_types(&key, &types);
        let retrieved = cache.get_types(&key).unwrap();

        assert_eq!(retrieved.variable_types.len(), 2);
        assert_eq!(retrieved.return_type, Some("void".to_string()));
        assert!((retrieved.confidence - 0.85).abs() < 0.01);
    }

    #[test]
    fn test_binary_cache() {
        let cache = AnalysisCache::memory_only();

        let hash = [0u8; 32];
        let key = BinaryCacheKey::new(hash, "callgraph");
        let callgraph = CachedCallGraph {
            functions: vec![CachedFunction {
                address: 0x1000,
                size: 100,
                name: Some("main".to_string()),
                is_thunk: false,
            }],
            calls: vec![(0x1000, 0x2000)],
            indirect_calls: vec![0x1050],
        };

        cache.store_call_graph(&key, &callgraph);
        let retrieved = cache.get_call_graph(&key).unwrap();

        assert_eq!(retrieved.functions.len(), 1);
        assert_eq!(retrieved.calls.len(), 1);
    }

    #[test]
    fn test_cache_stats() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"stats test");
        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 0,
            success: true,
            error: None,
        };

        // Miss
        let _ = cache.get_disassembly(&key);

        // Store
        cache.store_disassembly(&key, &disasm);

        // Hit
        let _ = cache.get_disassembly(&key);

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.stores, 1);
        assert_eq!(stats.hits, 1);
        assert!((stats.hit_rate() - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_shared_cache() {
        let cache = create_shared_cache(CacheConfig::default());

        let key = FunctionCacheKey::new(0x1000, b"shared test");
        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 0,
            success: true,
            error: None,
        };

        cache.store_disassembly(&key, &disasm);

        // Clone the Arc and access from "another thread"
        let cache2 = cache.clone();
        let retrieved = cache2.get_disassembly(&key);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_cache_config() {
        let config = CacheConfig::default()
            .with_disk_path("/tmp/test_cache")
            .with_max_memory_size(50 * 1024 * 1024)
            .with_max_age(Duration::from_secs(3600))
            .with_compression(true);

        assert_eq!(config.disk_path, Some(PathBuf::from("/tmp/test_cache")));
        assert_eq!(config.max_memory_size, 50 * 1024 * 1024);
        assert_eq!(config.max_age, Duration::from_secs(3600));
        assert!(config.compress);
    }

    #[test]
    fn test_entry_meta_expiration() {
        let meta = CacheEntryMeta::new(100);

        // Should not be expired with default max age
        assert!(!meta.is_expired(Duration::from_secs(DEFAULT_MAX_AGE_SECS)));

        // A freshly created entry with 0 max age is technically at the boundary
        // (age == 0, max_age == 0, so age > max_age is false)
        // This is correct behavior - 0 means "expire after 0 seconds have passed"
        assert!(!meta.is_expired(Duration::from_secs(0)));

        // Should be expired with 1 second max age if we simulate an old entry
        let mut old_meta = CacheEntryMeta::new(100);
        old_meta.created_at = current_timestamp().saturating_sub(10);
        assert!(old_meta.is_expired(Duration::from_secs(5)));
    }

    #[test]
    fn test_cache_error_display() {
        let err = CacheError::NotFound;
        assert!(err.to_string().contains("not found"));

        let err = CacheError::Expired;
        assert!(err.to_string().contains("expired"));

        let err = CacheError::VersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("1"));
        assert!(err.to_string().contains("2"));

        let err = CacheError::Corrupted("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_binary_cache_key() {
        let hash = [0xABu8; 32];
        let key = BinaryCacheKey::new(hash, "test_analysis");

        assert_eq!(key.analysis_type, "test_analysis");
        let disk_key = key.to_disk_key();
        assert!(disk_key.contains("abab")); // Hex representation
        assert!(disk_key.contains("test_analysis"));
    }

    #[test]
    fn test_memory_tracking() {
        let cache = AnalysisCache::memory_only();

        let key = FunctionCacheKey::new(0x1000, b"memory test");
        let disasm = CachedDisassembly {
            instructions: vec![],
            instruction_count: 0,
            success: true,
            error: None,
        };

        assert_eq!(cache.memory_usage(), 0);
        cache.store_disassembly(&key, &disasm);
        assert!(cache.memory_usage() > 0);

        cache.clear();
        assert_eq!(cache.memory_usage(), 0);
    }
}
