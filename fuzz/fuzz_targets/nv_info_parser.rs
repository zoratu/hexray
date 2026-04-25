#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::elf::cuda::parse_nv_info;

fuzz_target!(|data: &[u8]| {
    let blob = parse_nv_info(data);
    // Every entry's payload range must stay strictly inside the input.
    for entry in &blob.entries {
        let start = entry.payload_offset as usize;
        let end = start.saturating_add(entry.payload_size as usize);
        assert!(
            end <= data.len(),
            "nv_info entry payload {start}..{end} out of bounds (input len {})",
            data.len()
        );
        // payload() must agree with the entry's recorded span.
        assert_eq!(blob.payload(entry).len(), entry.payload_size as usize);
    }
});
