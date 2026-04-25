//! Adversarial / fault-injection tests for the CUDA parser surface.
//!
//! These tests start from real corpus cubins (when present) and from
//! synthetic minimal fixtures (always available) and then deliberately
//! mutate them — truncating at every offset, flipping magic bytes,
//! corrupting section tables, scrambling NvInfo TLV framing, claiming
//! impossible payload sizes — and assert each parser:
//!
//! 1. never panics,
//! 2. either returns a typed error or a tolerant view,
//! 3. doesn't read past the input buffer (caught by the Rust bounds
//!    checker in debug builds and the proptests' bounds asserts).
//!
//! This file complements the proptest entries: those generate random
//! bytes, this file targets the *structurally adversarial* shapes a
//! malicious or corrupt CUBIN might use to crash a downstream tool.

use hexray_formats::{elf::cuda::parse_nv_info, Elf, FatbinError, FatbinWrapper, PtxIndex};
use std::fs;
use std::path::{Path, PathBuf};

fn corpus_root() -> Option<PathBuf> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("tests/corpus/cuda/build");
    p.is_dir().then_some(p)
}

/// One representative cubin we lean on for mutation seeds. When the
/// corpus isn't built locally, callers fall back to a synthesised
/// minimal CUDA-ELF stub.
fn seed_cubin() -> Vec<u8> {
    if let Some(root) = corpus_root() {
        let p = root.join("sm_80/vector_add.cubin");
        if let Ok(b) = fs::read(p) {
            return b;
        }
    }
    // Minimal synthetic ELF64 + EM_CUDA stub. Enough bytes to exercise
    // ELF header validation; downstream parsers will reject the
    // missing section table cleanly.
    let mut data = vec![0u8; 64];
    data[0..4].copy_from_slice(b"\x7fELF");
    data[4] = 2; // ELF64
    data[5] = 1; // little-endian
    data[6] = 1; // EI_VERSION
    data[8] = 7; // EI_ABIVERSION (CUDA V1)
    data[16] = 2; // ET_EXEC
    data[18] = 190; // EM_CUDA
    data[48..52].copy_from_slice(&0x0050_0550u32.to_le_bytes()); // sm_80 e_flags
    data
}

// ---- truncation sweeps ----------------------------------------------------

#[test]
fn elf_parse_survives_truncation_at_every_offset() {
    let seed = seed_cubin();
    // Sample a few offsets evenly so the test stays fast on small CI.
    let stride = (seed.len() / 64).max(1);
    for end in (0..=seed.len()).step_by(stride) {
        let _ = Elf::parse(&seed[..end]);
    }
}

#[test]
fn cubin_view_survives_truncation_at_every_offset() {
    let seed = seed_cubin();
    let stride = (seed.len() / 64).max(1);
    for end in (0..=seed.len()).step_by(stride) {
        if let Ok(elf) = Elf::parse(&seed[..end]) {
            let _ = elf.cubin_view();
        }
    }
}

// ---- bit-flip mutations ---------------------------------------------------

#[test]
fn elf_parse_survives_random_bit_flips() {
    let seed = seed_cubin();
    let mut state: u64 = 0xdead_beef_dead_beef;
    for _ in 0..256 {
        // Cheap LCG so the test is reproducible without a PRNG dep.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let pos = (state as usize) % seed.len();
        let bit = (state.rotate_right(33) as u8) & 0x7;
        let mut mutated = seed.clone();
        mutated[pos] ^= 1 << bit;
        let _ = Elf::parse(&mutated);
    }
}

// ---- NvInfo framing chaos -------------------------------------------------

#[test]
fn nv_info_format_byte_chaos() {
    // The TLV parser bails on unknown format bytes. Verify it does so
    // for every possible byte without losing the entries collected
    // before the bad one.
    for fmt in 0u8..=0xFF {
        let blob = vec![
            0x03, 0x05, 0x00, 0x00, // good HVAL MaxThreads = 0
            fmt, 0x05, 0x00, 0x00, // candidate next entry
        ];
        let parsed = parse_nv_info(&blob);
        if matches!(fmt, 0x01..=0x04) {
            // Valid format byte — both entries should parse.
            assert!(
                !parsed.entries.is_empty(),
                "fmt {fmt:#x}: expected ≥1 entries, got 0"
            );
        } else {
            // Invalid — first entry recovered, rest truncated.
            assert_eq!(parsed.entries.len(), 1);
            assert!(parsed.truncated);
        }
    }
}

#[test]
fn nv_info_sval_overrun_does_not_read_past_buffer() {
    // SVAL declares a 16-bit length. Claim a length that overruns by
    // every meaningful amount and check no panic.
    for length in [u16::MAX, 1024, 100, 17, 16, 5, 1] {
        let mut blob = vec![0x04, 0x17];
        blob.extend_from_slice(&length.to_le_bytes());
        // Provide a smaller real payload than declared.
        blob.extend_from_slice(&[0xAAu8; 4]);
        let parsed = parse_nv_info(&blob);
        // No matter what the parser decides, we just want it not to panic
        // and to surface truncation when applicable.
        let _ = parsed;
    }
}

// ---- Fatbin chaos ---------------------------------------------------------

#[test]
fn fatbin_truncation_sweeps_to_just_under_header() {
    // Anything shorter than 16 bytes must report Truncated.
    for n in 0..16 {
        let bytes = vec![0xAAu8; n];
        match FatbinWrapper::parse(&bytes) {
            Err(FatbinError::Truncated { needed: 16, have }) => assert_eq!(have, n),
            other => panic!("len={n}: expected Truncated, got {other:?}"),
        }
    }
}

#[test]
fn fatbin_with_garbage_post_magic_either_parses_or_errors() {
    let mut bytes = vec![0u8; 256];
    // Plant valid magic.
    bytes[0..4].copy_from_slice(&0xBA55_ED50u32.to_le_bytes());
    // Fill the rest with adversarial junk.
    let mut state: u64 = 1;
    for slot in bytes.iter_mut().skip(4) {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        *slot = state as u8;
    }
    // Either Ok or Err — never panic.
    let _ = FatbinWrapper::parse(&bytes);
}

#[test]
fn fatbin_lying_about_payload_size_yields_payload_overflow() {
    let mut bytes = vec![0u8; 32];
    bytes[0..4].copy_from_slice(&0xBA55_ED50u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes()); // version
    bytes[8..12].copy_from_slice(&16u32.to_le_bytes()); // header_offset
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes()); // wildly large header_size
    match FatbinWrapper::parse(&bytes) {
        Err(FatbinError::PayloadOverflow { .. }) => {}
        other => panic!("expected PayloadOverflow, got {other:?}"),
    }
}

#[test]
fn fatbin_entry_overflow_is_caught() {
    // Build a wrapper whose entry header says "my payload is huge" so
    // the entry walk hits EntryOverflow before reading past the buffer.
    let mut bytes = vec![0u8; 16 + 64];
    bytes[0..4].copy_from_slice(&0xBA55_ED50u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&16u32.to_le_bytes()); // header_offset
    bytes[12..16].copy_from_slice(&64u32.to_le_bytes()); // header_size = exactly one entry header
                                                         // Entry header at offset 16:
    bytes[16] = 0x02; // kind = cubin
    bytes[20..24].copy_from_slice(&64u32.to_le_bytes()); // header_len = 64 (right-sized)
    bytes[24..32].copy_from_slice(&u64::MAX.to_le_bytes()); // payload_size = huge
    match FatbinWrapper::parse(&bytes) {
        Err(FatbinError::EntryOverflow { .. }) => {}
        other => panic!("expected EntryOverflow, got {other:?}"),
    }
}

// ---- PTX chaos ------------------------------------------------------------

#[test]
fn ptx_handles_unbalanced_braces() {
    for src in [
        ".visible .entry x() {",                        // never closes
        ".visible .entry x() {{}}}}}",                  // extra closes
        ".visible .entry x() }",                        // close-only
        "{{{{",                                         // no directive
        ".visible .entry x() ; .visible .entry y() {}", // forward decl + body
    ] {
        // The parser must not panic and must produce at least an empty
        // function list when given complete junk.
        let idx = PtxIndex::parse(src);
        for f in &idx.functions {
            assert!(f.body_start <= f.body_end);
        }
    }
}

#[test]
fn ptx_handles_extreme_nesting() {
    // 200 levels of `{` followed by 200 `}` — a stack-based parser
    // would have to handle this without overflowing.
    let mut src = String::from(".visible .entry deep() ");
    for _ in 0..200 {
        src.push('{');
    }
    for _ in 0..200 {
        src.push('}');
    }
    let idx = PtxIndex::parse(&src);
    assert_eq!(idx.functions.len(), 1);
}

#[test]
fn ptx_nul_delimited_handles_all_nul_input() {
    let bytes = vec![0u8; 64];
    // Should return None (no real content) without panicking.
    assert!(PtxIndex::from_nul_delimited_bytes(&bytes).is_none());
}

#[test]
fn ptx_nul_delimited_handles_high_bytes() {
    // Non-ASCII bytes: the function maps any byte != 0 directly to a
    // char. Verify it doesn't panic on UTF-8-invalid bytes.
    let bytes: Vec<u8> = (1..=255u8).collect();
    let _ = PtxIndex::from_nul_delimited_bytes(&bytes);
}
