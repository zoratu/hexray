#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::FatbinWrapper;

fuzz_target!(|data: &[u8]| {
    let Ok(w) = FatbinWrapper::parse(data) else { return };

    let buffer_start = data.as_ptr() as usize;
    let buffer_end = buffer_start + data.len();

    for entry in &w.entries {
        // Payload slices must lie strictly inside the input buffer.
        let p = entry.payload.as_ptr() as usize;
        assert!(
            p >= buffer_start && p + entry.payload.len() <= buffer_end,
            "fatbin entry payload escaped buffer"
        );
        // Convenience accessors must agree with the underlying slice.
        assert_eq!(entry.data().len(), entry.payload.len());
    }
});
