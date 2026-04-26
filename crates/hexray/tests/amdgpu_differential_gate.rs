//! Differential gate against committed `llvm-objdump` sidecars.
//!
//! For every `vector_add.gfxNNNN.co` and `multi_kernel.gfxNNNN.co`
//! fixture under `tests/corpus/scale-lang/`, this test compares
//! hexray's disassembly to a frozen `*.expected_disasm.txt` produced
//! by `llvm-objdump --triple=amdgcn-amd-amdhsa --mcpu=gfxNNNN`.
//!
//! Two kinds of regression are gated:
//!
//! 1. **Unknown-opcode placeholders.** Any `xxx.op0x...` mnemonic in
//!    hexray's output means the family-band table is missing an entry
//!    that `llvm-objdump` resolves. Zero is the only acceptable count.
//!
//! 2. **Mnemonic-frequency drift.** For every distinct mnemonic in
//!    the llvm-objdump sidecar, hexray must emit the same count, ±1
//!    (the ±1 tolerates the trailing block of `s_nop 0` / `.long`
//!    padding `llvm-objdump` decodes past `s_endpgm` but hexray's
//!    walker stops at).
//!
//! When a fixture's sidecar is missing the test skips it (so adding
//! a new corpus binary doesn't fail CI before the sidecar lands).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

fn corpus_dir() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../tests/corpus/scale-lang");
    p
}

fn hexray_bin() -> String {
    env!("CARGO_BIN_EXE_hexray").to_string()
}

/// Extract the mnemonic (first whitespace-delimited token after the
/// hex-byte column) from a hexray disasm line. Returns `None` for
/// header / blank / address-only lines.
fn hexray_mnemonic(line: &str) -> Option<&str> {
    // Hexray lines look like:
    //   "0x00000100:  02 00 02 c0 38 00 00 00  s_load_dword s0, ..."
    // Past the `:` and the hex column, the first token is the mnemonic.
    let after_colon = line.split_once(':')?.1.trim_start();
    for tok in after_colon.split_whitespace() {
        let is_hex_byte = tok.len() == 2 && tok.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_hex_byte {
            return Some(tok);
        }
    }
    None
}

/// Extract the mnemonic from a llvm-objdump line. Lines look like:
///   "\ts_load_dword s0, s[4:5], 0x38   // 000000000000: C0020002..."
/// Skip header/blank/section/symbol/comment lines. Drop the optional
/// `.long 0x...` form (data, not code).
fn objdump_mnemonic(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.is_empty()
        || trimmed.starts_with("//")
        || trimmed.starts_with('<')
        || trimmed.starts_with("Disassembly")
        || trimmed.starts_with("0000")
        || trimmed.contains("file format")
        || trimmed.starts_with(".long")
        || trimmed.starts_with(".byte")
        || trimmed.starts_with(".short")
        || trimmed.starts_with(".word")
    {
        return None;
    }
    // Skip lines that are just an address+colon (symbol labels are
    // already filtered above; this catches the edge-case `0x...:` on
    // its own).
    if trimmed.ends_with(':') && !trimmed.contains(' ') {
        return None;
    }
    let mut iter = trimmed.split_whitespace();
    iter.next()
}

fn count_mnemonics<F>(text: &str, mut extract: F) -> HashMap<String, usize>
where
    F: FnMut(&str) -> Option<String>,
{
    // For llvm-objdump output, treat the file as a sequence of
    // "kernel blocks" — each starts at a `<NAME$local>:` line and
    // runs through the first `s_endpgm` that follows. Padding past
    // that (`s_nop`, `s_code_end`, `v_illegal`, `.long`) is dropped
    // because hexray's walker stops at the kernel-symbol boundary.
    //
    // For hexray output, the stream has no kernel headers but also
    // no padding — we accept every mnemonic in it.
    let has_kernel_header = text.contains("$local>:");
    let mut tally = HashMap::new();
    let mut in_kernel = !has_kernel_header;
    for line in text.lines() {
        if has_kernel_header {
            if line.contains("$local>:") {
                in_kernel = true;
                continue;
            }
            if !in_kernel {
                continue;
            }
        }
        if let Some(m) = extract(line) {
            *tally.entry(m.clone()).or_insert(0) += 1;
            if has_kernel_header && m == "s_endpgm" {
                in_kernel = false;
            }
        }
    }
    tally
}

fn run_hexray_disasm(path: &PathBuf, kernel: &str) -> String {
    let output = Command::new(hexray_bin())
        .arg("-s")
        .arg(kernel)
        .arg(path.to_str().unwrap())
        .output()
        .expect("hexray runs");
    assert!(
        output.status.success(),
        "hexray failed for {}: {:?}",
        path.display(),
        output
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn no_unknown_opcode_placeholders_in_corpus() {
    // Collect every (binary, kernel-name) we know about. Pulling
    // kernel names directly avoids any surprise from synthesised
    // kernel symbols.
    let cases: &[(&str, &[&str])] = &[
        ("vector_add.gfx900.co", &["vector_add"]),
        ("vector_add.gfx1010.co", &["vector_add"]),
        ("vector_add.gfx1030.co", &["vector_add"]),
        ("vector_add.gfx1100.co", &["vector_add"]),
        ("vector_add.gfx1101.co", &["vector_add"]),
        ("vector_add.gfx1102.co", &["vector_add"]),
        ("multi_kernel.gfx1030.co", &["scale_kernel", "clamp_kernel"]),
        ("multi_kernel.gfx1100.co", &["scale_kernel", "clamp_kernel"]),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (fixture, kernels) in cases {
        let path = corpus_dir().join(fixture);
        if !path.exists() {
            eprintln!("skipping {fixture}: not present");
            continue;
        }
        for kernel in *kernels {
            let stdout = run_hexray_disasm(&path, kernel);
            // Look for any token of the form `<class>.op0x<hex>` —
            // those are the unresolved-opcode placeholders.
            let mut unresolved: Vec<String> = Vec::new();
            for line in stdout.lines() {
                for tok in line.split_whitespace() {
                    // The `.op0x...` substring is what `render_mnemonic`
                    // emits when the family-band lookup misses.
                    if tok.contains(".op0x") {
                        unresolved.push(format!("{tok}  (in {fixture}::{kernel})"));
                    }
                }
            }
            if !unresolved.is_empty() {
                failures.push(format!(
                    "{fixture}::{kernel} has {} unresolved opcodes:\n  {}",
                    unresolved.len(),
                    unresolved.join("\n  ")
                ));
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} fixture(s) had unresolved opcode placeholders:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
}

#[test]
fn mnemonic_frequencies_match_llvm_objdump() {
    let cases: &[(&str, &str, &[&str])] = &[
        ("vector_add.gfx900.co", "gfx900", &["vector_add"]),
        ("vector_add.gfx1010.co", "gfx1010", &["vector_add"]),
        ("vector_add.gfx1030.co", "gfx1030", &["vector_add"]),
        ("vector_add.gfx1100.co", "gfx1100", &["vector_add"]),
        ("vector_add.gfx1101.co", "gfx1101", &["vector_add"]),
        ("vector_add.gfx1102.co", "gfx1102", &["vector_add"]),
        (
            "multi_kernel.gfx1030.co",
            "gfx1030",
            &["scale_kernel", "clamp_kernel"],
        ),
        (
            "multi_kernel.gfx1100.co",
            "gfx1100",
            &["scale_kernel", "clamp_kernel"],
        ),
    ];

    let mut failures: Vec<String> = Vec::new();
    for (fixture, _arch, kernels) in cases {
        let path = corpus_dir().join(fixture);
        let sidecar_name = fixture.replace(".co", ".expected_disasm.txt");
        let sidecar_path = corpus_dir().join(&sidecar_name);
        if !path.exists() || !sidecar_path.exists() {
            eprintln!("skipping {fixture}: fixture or sidecar missing");
            continue;
        }
        let sidecar = std::fs::read_to_string(&sidecar_path).expect("sidecar reads");
        let llvm_tally = count_mnemonics(&sidecar, |line| {
            objdump_mnemonic(line).map(|s| s.to_string())
        });

        // Pool every kernel's hexray output: `llvm-objdump` dumps the
        // whole `.text` section and includes both kernels in the
        // multi-kernel fixtures. We mirror that by concatenating.
        let mut pooled_hexray = String::new();
        for kernel in *kernels {
            pooled_hexray.push_str(&run_hexray_disasm(&path, kernel));
        }
        let hexray_tally = count_mnemonics(&pooled_hexray, |line| {
            hexray_mnemonic(line).map(|s| s.to_string())
        });

        // Build the diff: for every llvm mnemonic, check hexray emits
        // it within ±1.
        let mut drift: Vec<String> = Vec::new();
        for (mnem, &llvm_count) in &llvm_tally {
            let hexray_count = hexray_tally.get(mnem).copied().unwrap_or(0);
            let delta = (llvm_count as i64 - hexray_count as i64).abs();
            if delta > 1 {
                drift.push(format!(
                    "  {mnem}: llvm={llvm_count} hexray={hexray_count} (Δ={delta})"
                ));
            }
        }
        if !drift.is_empty() {
            failures.push(format!(
                "{fixture}: {} mnemonics drifted >±1:\n{}",
                drift.len(),
                drift.join("\n")
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} fixture(s) drifted from llvm-objdump:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );
    }
}
