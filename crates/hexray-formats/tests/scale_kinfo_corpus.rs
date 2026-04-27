//! Real-binary regression test for the SCALE-free `.AMDGPU.kinfo`
//! fallback parser. The two fixtures under `tests/corpus/scale-lang/`
//! were emitted by `scale-free` 1.4.2 and ship in-repo (~2 KB each),
//! so this test runs everywhere `cargo test` runs.
//!
//! Without the fallback path the per-arg cmp rows in `hexray cmp`
//! never render — see `crates/hexray/tests/scale_lang_cmp.rs` for the
//! end-to-end check on the CLI side.

use hexray_formats::{Elf, ScaleKinfo};
use std::fs;
use std::path::{Path, PathBuf};

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/corpus/scale-lang")
        .join(name)
}

#[test]
fn parses_scale_lang_vector_add_kinfo() {
    let path = corpus("vector_add.gfx1030.co");
    if !path.exists() {
        eprintln!("scale-lang corpus missing, skipping");
        return;
    }
    let bytes = fs::read(&path).expect("read fixture");
    let elf = Elf::parse(&bytes).expect("parse ELF");

    // Pull the `.AMDGPU.kinfo` section bytes out and decode directly.
    // (The CodeObjectView wiring is exercised by the cmp integration
    // test in the `hexray` crate; here we want a low-level assertion.)
    let kinfo_section = elf
        .sections
        .iter()
        .find(|s| elf.section_name(s) == Some(".AMDGPU.kinfo"))
        .expect("real SCALE-free binary always carries .AMDGPU.kinfo");
    let kinfo_bytes = elf.section_data(kinfo_section).expect("section data");
    assert_eq!(kinfo_bytes.len(), 44, "vector_add kinfo is 44 bytes");

    let info = ScaleKinfo::parse(kinfo_bytes).expect("valid kinfo blob");
    assert_eq!(
        info.flags, 0x400,
        "flags u32 was 0x400 in the v1.4.2 corpus"
    );
    assert_eq!(info.reserved, 0);
    assert_eq!(info.args.len(), 4);
    let sizes: Vec<u32> = info.args.iter().map(|a| a.size).collect();
    let offsets: Vec<u32> = info.args.iter().map(|a| a.offset).collect();
    assert_eq!(sizes, vec![8, 8, 8, 4]);
    assert_eq!(offsets, vec![0, 8, 16, 24]);
}

#[test]
fn code_object_view_attaches_synthesised_metadata() {
    let path = corpus("vector_add.gfx1030.co");
    if !path.exists() {
        eprintln!("scale-lang corpus missing, skipping");
        return;
    }
    let bytes = fs::read(&path).expect("read fixture");
    let elf = Elf::parse(&bytes).expect("parse ELF");
    let view = elf.code_object_view().expect("AMDGPU view");

    // SCALE-free 1.4.x emits no `NT_AMDGPU_METADATA` note.
    assert!(view.metadata.is_none());
    assert_eq!(view.kernels.len(), 1);
    let k = &view.kernels[0];
    assert_eq!(k.name, "vector_add");
    let m = k
        .metadata
        .as_ref()
        .expect("kinfo fallback should have populated metadata");
    assert_eq!(m.args.len(), 4);
    let sizes: Vec<Option<u32>> = m.args.iter().map(|a| a.size).collect();
    assert_eq!(sizes, vec![Some(8), Some(8), Some(8), Some(4)]);
}
