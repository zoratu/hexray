#![no_main]

use arbitrary::Unstructured;
use hexray_analysis::{
    AnalysisCache, CachedDisassembly, DependencyTracker, FunctionCacheKey, IncrementalAnalyzer,
    IncrementalFunctionInfo, Patch, PatchSet,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

fn cached_disassembly() -> CachedDisassembly {
    CachedDisassembly {
        instructions: vec![],
        instruction_count: 0,
        success: true,
        error: None,
    }
}

fn expected_affects(start: u64, size: usize, patch: &Patch) -> bool {
    if patch.size_delta() != 0 {
        start + size as u64 > patch.address
    } else {
        start < patch.old_end() && start + size as u64 > patch.address
    }
}

fuzz_target!(|data: &[u8]| {
    let mut input = Unstructured::new(data);
    let function_count = input.int_in_range::<u8>(1..=6).unwrap_or(1) as usize;

    let cache = Arc::new(AnalysisCache::memory_only());
    let mut tracker = DependencyTracker::new();
    let mut cached = Vec::new();
    let mut next_address = 0x1000u64;

    for idx in 0..function_count {
        let gap = input.int_in_range::<u8>(0..=16).unwrap_or(0) as u64;
        let size = input.int_in_range::<u8>(1..=32).unwrap_or(1) as usize;
        next_address = next_address.saturating_add(gap);

        tracker.add_function(IncrementalFunctionInfo::new(next_address, size));
        let key = FunctionCacheKey::new(next_address, &[idx as u8; 8]);
        cache.store_disassembly(&key, &cached_disassembly());
        cached.push((next_address, size, key));

        next_address = next_address.saturating_add(size as u64).saturating_add(4);
    }

    for pair in cached.windows(2) {
        tracker.add_call_edge(pair[0].0, pair[1].0);
    }

    let patch_offset = input.int_in_range::<u16>(0..=0x200).unwrap_or(0) as u64;
    let patch_address = 0x0f80u64.saturating_add(patch_offset);
    let old_len = input.int_in_range::<u8>(0..=12).unwrap_or(0) as usize;
    let new_len = input.int_in_range::<u8>(0..=12).unwrap_or(0) as usize;
    if old_len == 0 && new_len == 0 {
        return;
    }

    let patch = Patch::new(patch_address, vec![0xAA; old_len], vec![0xBB; new_len]);
    let mut patches = PatchSet::new();
    patches.add_patch(patch.clone());

    let mut analyzer = IncrementalAnalyzer::new(cache.clone(), tracker);
    let affected = analyzer.apply_patches(&patches);

    for (address, size, key) in &cached {
        if expected_affects(*address, *size, &patch) {
            assert!(cache.get_disassembly(key).is_none());
        }
    }

    let _ = affected.total_affected();
});
