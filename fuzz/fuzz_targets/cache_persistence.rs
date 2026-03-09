#![no_main]

use hexray_analysis::{AnalysisCache, BinaryCacheKey, FunctionCacheKey};
use libfuzzer_sys::fuzz_target;
use std::fs;
use tempfile::tempdir;

fn file_path(base: &std::path::Path, category: &str, key: &str) -> std::path::PathBuf {
    base.join(category).join(format!("{}.json", key))
}

fuzz_target!(|data: &[u8]| {
    let Ok(temp_dir) = tempdir() else {
        return;
    };

    let cache = AnalysisCache::with_disk(temp_dir.path());
    let key_bytes = &data[..data.len().min(16)];
    let payload = &data[data.len().min(16)..];
    let key = FunctionCacheKey::new(0x1000, key_bytes);

    for category in ["disasm", "cfg", "dataflow", "types"] {
        let path = file_path(temp_dir.path(), category, &key.to_disk_key());
        let _ = fs::create_dir_all(path.parent().unwrap_or(temp_dir.path()));
        let _ = fs::write(&path, payload);

        match category {
            "disasm" => {
                let _ = cache.get_disassembly(&key);
            }
            "cfg" => {
                let _ = cache.get_cfg(&key);
            }
            "dataflow" => {
                let _ = cache.get_dataflow(&key);
            }
            "types" => {
                let _ = cache.get_types(&key);
            }
            _ => unreachable!(),
        }
    }

    let mut binary_hash = [0u8; 32];
    for (idx, byte) in data.iter().take(32).enumerate() {
        binary_hash[idx] = *byte;
    }
    let binary_key = BinaryCacheKey::new(binary_hash, "callgraph");
    let binary_path = file_path(temp_dir.path(), "binary", &binary_key.to_disk_key());
    let _ = fs::create_dir_all(binary_path.parent().unwrap_or(temp_dir.path()));
    let _ = fs::write(&binary_path, payload);
    let _ = cache.get_call_graph(&binary_key);
});
