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

#[test]
fn disasm_decodes_sopp_simm16_subfields() {
    // gfx1100 fixture exercises s_clause, s_waitcnt, s_delay_alu —
    // each with non-trivial SIMM16 sub-fields.
    if !corpus_path("vector_add.gfx1100.co").exists() {
        eprintln!("gfx1100 fixture not present, skipping");
        return;
    }
    let path = corpus_path("vector_add.gfx1100.co");
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg("vector_add")
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // s_clause renders the count.
    assert!(
        stdout.contains("s_clause 0x2"),
        "expected `s_clause 0x2`, got:\n{stdout}"
    );
    // s_waitcnt with GFX11 layout: lgkmcnt(0) (vmcnt + expcnt at max).
    assert!(
        stdout.contains("s_waitcnt lgkmcnt(0)"),
        "expected `s_waitcnt lgkmcnt(0)`, got:\n{stdout}"
    );
    // s_delay_alu — RDNA3 scheduling hint with full sub-field decode.
    assert!(
        stdout
            .contains("s_delay_alu instid0(SALU_CYCLE_1) | instskip(SKIP_1) | instid1(VALU_DEP_1)"),
        "expected s_delay_alu sub-field decode, got:\n{stdout}"
    );

    // Verify the gfx1030 (RDNA2) layout still works:
    let path = corpus_path("vector_add.gfx1030.co");
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg("vector_add")
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("s_waitcnt lgkmcnt(0)"),
        "GFX10 s_waitcnt regression: {stdout}"
    );
}

#[test]
fn disasm_renders_register_pairs_and_null() {
    if !corpus_path("vector_add.gfx1100.co").exists() {
        eprintln!("gfx1100 fixture not present, skipping");
        return;
    }
    let path = corpus_path("vector_add.gfx1100.co");
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg("vector_add")
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // SMEM with SBASE register pair `s[0:1]`.
    assert!(
        stdout.contains("s_load_b32 s2, s[0:1], 0x38"),
        "expected `s_load_b32 s2, s[0:1], 0x38`, got:\n{stdout}"
    );
    // SMEM 128-bit destination (4-dword pair).
    assert!(
        stdout.contains("s_load_b128 s[4:7], s[0:1], null"),
        "expected `s_load_b128 s[4:7], s[0:1], null`, got:\n{stdout}"
    );
    // VOP3 v_mad_u64_u32 with VDST pair, SDST=null, SRC2 pair.
    assert!(
        stdout.contains("v_mad_u64_u32 v[1:2], null, s2, s3, v[0:1]"),
        "expected v_mad_u64_u32 with v[1:2]/null/v[0:1], got:\n{stdout}"
    );
    // VOPC e64 — VDST is implicit EXEC, no explicit dst rendered.
    assert!(
        stdout.contains("v_cmpx_gt_i32_e64 s4, v1"),
        "expected `v_cmpx_gt_i32_e64 s4, v1` (no implicit VDST), got:\n{stdout}"
    );
    // VOP3B — `v_add_co_u32` shows the `vcc_lo` SDST.
    assert!(
        stdout.contains("v_add_co_u32 v2, vcc_lo, s4, v0"),
        "expected v_add_co_u32 with vcc_lo SDST, got:\n{stdout}"
    );
    // FLAT — global_load_b32 v2, v[2:3], off (saddr=null/off).
    assert!(
        stdout.contains("global_load_b32 v2, v[2:3], off"),
        "expected `global_load_b32 v2, v[2:3], off`, got:\n{stdout}"
    );
    assert!(
        stdout.contains("global_store_b32 v[0:1], v2, off"),
        "expected `global_store_b32 v[0:1], v2, off`, got:\n{stdout}"
    );
    // 2-source VOP3 (v_lshlrev_b64) does NOT render a phantom src2.
    assert!(
        stdout.contains("v_lshlrev_b64 v[0:1], 2, v[1:2]"),
        "expected v_lshlrev_b64 with 2 sources only, got:\n{stdout}"
    );
}

#[test]
fn disasm_handles_rdna3_opcode_renumbering() {
    if !corpus_path("vector_add.gfx1100.co").exists() {
        eprintln!("gfx1100 fixture not present, skipping");
        return;
    }
    let path = corpus_path("vector_add.gfx1100.co");
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg("vector_add")
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);

    // RDNA3 SOPP: s_endpgm shifted from OP=0x01 (RDNA2) to OP=0x30
    // (RDNA3). The v1.3.3 single-band tables would have rendered
    // this as `sopp.op0x30`.
    assert!(
        stdout.contains("s_endpgm"),
        "RDNA3 s_endpgm should resolve, got:\n{stdout}"
    );
    // RDNA3 SOPP scheduling hints not present in RDNA2.
    assert!(
        stdout.contains("s_clause") && stdout.contains("s_delay_alu"),
        "expected RDNA3 SOPP hints (s_clause + s_delay_alu), got:\n{stdout}"
    );
    // RDNA3 SMEM rename: _dword → _b32.
    assert!(
        stdout.contains("s_load_b32"),
        "expected RDNA3 SMEM rename s_load_b32, got:\n{stdout}"
    );
    // RDNA3 FLAT rename: _dword → _b32 + distinct global_/scratch_/flat_ OPs.
    assert!(
        stdout.contains("global_load_b32"),
        "expected RDNA3 global_load_b32, got:\n{stdout}"
    );
    // RDNA3 VOP3 renumbering: v_mad_u64_u32 shifted to OP=0x2fe.
    assert!(
        stdout.contains("v_mad_u64_u32"),
        "expected RDNA3 v_mad_u64_u32 to resolve, got:\n{stdout}"
    );
}
