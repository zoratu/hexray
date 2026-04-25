#![no_main]

use libfuzzer_sys::fuzz_target;
use hexray_formats::PtxIndex;

fuzz_target!(|data: &[u8]| {
    // Two entry points: the UTF-8 path used for plain `.ptx` files, and
    // the NUL-delimited path used for CUBIN-embedded `.nv_debug_ptx_txt`.
    if let Ok(text) = std::str::from_utf8(data) {
        let idx = PtxIndex::parse(text);
        let len = idx.raw.len();
        for f in &idx.functions {
            assert!(f.body_start <= f.body_end);
            assert!(f.body_end <= len);
            assert!(f.header.start <= f.header.end);
            assert!(f.header.end <= len);
        }
    }

    if let Some(idx) = PtxIndex::from_nul_delimited_bytes(data) {
        let len = idx.raw.len();
        for f in &idx.functions {
            assert!(f.body_start <= f.body_end);
            assert!(f.body_end <= len);
        }
    }
});
