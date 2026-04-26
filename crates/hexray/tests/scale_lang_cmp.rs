//! Integration test for the scale-lang interop demo.
//!
//! The two committed code objects under
//! `tests/corpus/scale-lang/vector_add.gfxNNNN.co` were produced by
//! SCALE 1.4.2 (`scale-free` package) compiling the same
//! `vector_add.cu` for two different AMD targets:
//!
//! - `vector_add.gfx1030.co` — RDNA2 (Navi 21).
//! - `vector_add.gfx1100.co` — RDNA3 (Navi 31).
//!
//! `hexray cmp` between them should report:
//! - Matching primary VGPR count (target-independent on this kernel).
//! - Matching kernarg total (the kernel-arg layout is target-
//!   independent).
//! - Differing scalar SGPR count (RDNA3 codegen reserves more sgprs
//!   for the implicit kernarg pointer / queue ptr than RDNA2 — that's
//!   *expected* codegen drift, marked `differ` rather than MISMATCH).
//!
//! The fixtures live in the repo (small — ~2KB each), so this test
//! runs everywhere `cargo test` runs. The walkthrough in
//! `docs/SCALE_INTEROP.md` documents how to regenerate them.

use std::path::PathBuf;
use std::process::Command;

fn corpus_path(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/corpus/scale-lang");
    p.push(name);
    p
}

fn fixtures_present() -> bool {
    corpus_path("vector_add.gfx1030.co").exists() && corpus_path("vector_add.gfx1100.co").exists()
}

fn hexray_bin() -> String {
    env!("CARGO_BIN_EXE_hexray").to_string()
}

#[test]
fn cmp_reports_kernel_equivalence_across_amd_targets() {
    if !fixtures_present() {
        eprintln!("scale-lang corpus not present, skipping");
        return;
    }
    let a = corpus_path("vector_add.gfx1030.co");
    let b = corpus_path("vector_add.gfx1100.co");
    let output = Command::new(hexray_bin())
        .arg(a.to_str().unwrap())
        .arg("cmp")
        .arg(b.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(output.status.success(), "hexray cmp failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Architecture lines: gfx1030 vs gfx1100.
    assert!(stdout.contains("amdgpu (gfx1030"), "got {stdout}");
    assert!(stdout.contains("amdgpu (gfx1100"), "got {stdout}");

    // Same kernel name on both sides.
    assert!(stdout.contains("Kernel: vector_add"), "got {stdout}");

    // Structural agreement: same kernarg total.
    assert!(stdout.contains("kernarg/param"), "got {stdout}");
    assert!(stdout.contains("a=88B          b=88B"), "got {stdout}");

    // VGPR matches (8 vs 8 for this kernel — the float-add inner loop
    // is sgpr-bound, so vgpr pressure stays the same across RDNA2
    // and RDNA3 codegen).
    assert!(stdout.contains("primary regs    a=8"), "got {stdout}");

    // Matched at least one kernel cleanly.
    assert!(stdout.contains("Matched 1 kernel(s)."), "got {stdout}");
}

#[test]
fn info_decodes_real_amdgpu_kernel() {
    if !corpus_path("vector_add.gfx1030.co").exists() {
        eprintln!("scale-lang corpus not present, skipping");
        return;
    }
    let path = corpus_path("vector_add.gfx1030.co");
    let output = Command::new(hexray_bin())
        .arg(path.to_str().unwrap())
        .arg("info")
        .output()
        .expect("hexray runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("amdgpu (gfx1030, family=Rdna2)"));
    assert!(stdout.contains("vector_add"));
    assert!(stdout.contains("vgprs=8"));
    assert!(stdout.contains("kernarg=88B"));
    assert!(stdout.contains("wave32"));
}

#[test]
fn disasm_renders_real_operands() {
    if !corpus_path("vector_add.gfx1030.co").exists() {
        eprintln!("scale-lang corpus not present, skipping");
        return;
    }
    let path = corpus_path("vector_add.gfx1030.co");
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg("vector_add")
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Real kernel: must end with s_endpgm.
    assert!(
        stdout.contains("s_endpgm"),
        "expected 's_endpgm' terminator, got:\n{stdout}"
    );
    // Must show real load instructions with operands.
    assert!(
        stdout.contains("s_load_dword"),
        "expected 's_load_dword' instruction, got:\n{stdout}"
    );
}
