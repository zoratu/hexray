//! End-to-end tests for the HIP / Clang offload bundle parser.
//!
//! These tests exercise the public re-exports from `hexray_formats`
//! (`HipBundleWrapper` & friends) and a small synthetic-bundle builder
//! that mirrors what `clang-offload-bundler` writes. They complement
//! the inline unit tests in `cuda::hip_fatbin::tests` by going through
//! the public crate surface.
//!
//! No real HIP fatbin is involved: we don't have `hipcc` on CI, and
//! constructing a real one would buy us very little over the synthetic
//! shape because the parser is structural.

use hexray_core::GfxArchitecture;
use hexray_formats::{HipBundleEntryKind, HipBundleError, HipBundleWrapper};

const HIP_BUNDLE_MAGIC: &[u8; 24] = b"__CLANG_OFFLOAD_BUNDLE__";
const HIP_BUNDLE_HEADER_SIZE: usize = 32;
const HIP_BUNDLE_ENTRY_FIXED_SIZE: usize = 24;

/// Minimal builder for a Clang offload bundle. Produces the same
/// layout as the one in `cuda::hip_fatbin::tests`, but lives here so
/// the integration test stays self-contained.
fn build_bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut entry_table_size = 0usize;
    for (triple, _) in entries {
        entry_table_size += HIP_BUNDLE_ENTRY_FIXED_SIZE + triple.len();
    }
    let payload_region_start = HIP_BUNDLE_HEADER_SIZE + entry_table_size;

    let mut out = Vec::new();
    out.extend_from_slice(HIP_BUNDLE_MAGIC);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());

    let mut payload_offsets: Vec<usize> = Vec::with_capacity(entries.len());
    let mut running = payload_region_start;
    for (_, payload) in entries {
        payload_offsets.push(running);
        running += payload.len();
    }
    for (i, (triple, payload)) in entries.iter().enumerate() {
        out.extend_from_slice(&(payload_offsets[i] as u64).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend_from_slice(&(triple.len() as u64).to_le_bytes());
        out.extend_from_slice(triple.as_bytes());
    }
    for (_, payload) in entries {
        out.extend_from_slice(payload);
    }
    out
}

#[test]
fn parses_synthetic_bundle_with_host_and_two_amdgpu_entries() {
    let host = b"HOST_OBJECT_PLACEHOLDER";
    let gfx906 = b"\x7fELF__amdgpu_gfx906_codeobj__";
    let gfx1030 = b"\x7fELF__amdgpu_gfx1030_codeobj__";

    let blob = build_bundle(&[
        ("host-x86_64-unknown-linux-gnu", host),
        ("hipv4-amdgcn-amd-amdhsa--gfx906", gfx906),
        ("hipv4-amdgcn-amd-amdhsa-unknown-gfx1030", gfx1030),
    ]);

    let w = HipBundleWrapper::parse(&blob).expect("valid bundle parses");
    assert_eq!(w.entries.len(), 3);
    assert_eq!(w.amdgpu_objects().count(), 2);
    assert_eq!(w.cubins().count(), 2); // alias

    let arches: Vec<_> = w.amdgpu_objects().filter_map(|e| e.gfx()).collect();
    assert_eq!(arches[0], GfxArchitecture::new(9, 0, 6));
    assert_eq!(arches[1], GfxArchitecture::new(10, 3, 0));

    assert_eq!(w.host_payload(), Some(host.as_slice()));
}

#[test]
fn rejects_obviously_corrupt_bundle() {
    // Truncated header.
    assert!(matches!(
        HipBundleWrapper::parse(&[0u8; 4]),
        Err(HipBundleError::Truncated { .. })
    ));

    // Bad magic.
    let mut blob = build_bundle(&[("host-x", b"H")]);
    blob[0] = 0;
    assert!(matches!(
        HipBundleWrapper::parse(&blob),
        Err(HipBundleError::BadMagic)
    ));
}

#[test]
fn unknown_triple_kept_as_other_for_forward_compat() {
    let blob = build_bundle(&[
        ("host-x86_64-foo", b"H"),
        ("openmp-amdgcn-amd-amdhsa--gfx906", b"OBJ"),
    ]);
    let w = HipBundleWrapper::parse(&blob).unwrap();
    assert!(matches!(w.entries[1].kind, HipBundleEntryKind::Other(_)));
    assert_eq!(w.amdgpu_objects().count(), 0);
}
