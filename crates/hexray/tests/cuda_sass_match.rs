//! End-to-end mnemonic match-rate gate for the SASS decoder.
//!
//! Walks every `.cubin` under `tests/corpus/cuda/build/`, decodes each
//! kernel's `.text.<kernel>` bytes through `SassDisassembler`, and
//! compares the recovered base mnemonic against the ground-truth
//! `nvdisasm -json` output (`*.sass.json`). Reports an overall
//! match-rate per SM and asserts the M4 success criterion
//! (≥ 70% base-mnemonic match on sm_80).
//!
//! The corpus is gitignored and regenerated via
//! `scripts/build-cuda-corpus.sh`; when it's absent the test no-ops so
//! CI (without a CUDA toolkit) stays green.

use hexray_disasm::cuda::SassDisassembler;
use hexray_disasm::Disassembler;
use hexray_formats::{Elf, Section};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const BASE_MNEMONIC_THRESHOLD_PCT: f64 = 70.0;

fn corpus_root() -> Option<PathBuf> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    let p = repo.join("tests/corpus/cuda/build");
    p.is_dir().then_some(p)
}

fn enumerate_corpus() -> Vec<(String, String, PathBuf)> {
    let Some(root) = corpus_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for sm in fs::read_dir(&root).into_iter().flatten().flatten() {
        let Some(sm_name) = sm.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !sm_name.starts_with("sm_") {
            continue;
        }
        for k in fs::read_dir(sm.path()).into_iter().flatten().flatten() {
            let p = k.path();
            if p.extension().and_then(|s| s.to_str()) != Some("cubin") {
                continue;
            }
            let name = p
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            out.push((sm_name.clone(), name, p));
        }
    }
    out.sort();
    out
}

/// Strip variant suffixes (`.GE.AND`, `.WIDE`, `.E.CONSTANT`, …) so
/// `ISETP.GE.AND` and `ISETP` compare equal at the base level M4
/// targets.
fn base_mnemonic(full: &str) -> &str {
    full.split('.').next().unwrap_or("")
}

fn load_ground_truth(json_path: &Path) -> Vec<(Option<String>, String)> {
    let raw = fs::read_to_string(json_path).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    // Shape: [ meta-dict, [ { "function-name": ..., "sass-instructions": [ ... ] }, ... ] ]
    let functions = v
        .get(1)
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let mut out = Vec::new();
    for f in functions {
        let instrs = f
            .get("sass-instructions")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default();
        for ins in instrs {
            let predicate = ins
                .get("predicate")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            let opcode = ins
                .get("opcode")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            out.push((predicate, opcode));
        }
    }
    out
}

/// Find `.text.<kernel>` bytes inside a parsed Elf by section name.
fn kernel_text_bytes<'a>(elf: &'a Elf<'_>, kernel: &str) -> Option<&'a [u8]> {
    let want = format!(".text.{kernel}");
    for s in &elf.sections {
        if s.name() == want {
            return Some(s.data());
        }
    }
    None
}

struct PerSmStats {
    kernels: usize,
    instructions: usize,
    matched: usize,
    mismatches: Vec<(String, usize, String, String)>, // (kernel, idx, expected, got)
}

impl PerSmStats {
    fn new() -> Self {
        Self {
            kernels: 0,
            instructions: 0,
            matched: 0,
            mismatches: Vec::new(),
        }
    }
    fn pct(&self) -> f64 {
        if self.instructions == 0 {
            100.0
        } else {
            (self.matched as f64) * 100.0 / (self.instructions as f64)
        }
    }
}

#[test]
fn sass_decoder_hits_base_mnemonic_threshold() {
    let cubins = enumerate_corpus();
    if cubins.is_empty() {
        eprintln!("SKIP: no CUDA corpus at tests/corpus/cuda/build/");
        return;
    }

    let mut by_sm: std::collections::BTreeMap<String, PerSmStats> =
        std::collections::BTreeMap::new();

    for (sm, kname, cubin_path) in &cubins {
        let bytes = fs::read(cubin_path).unwrap();
        let elf = Elf::parse(&bytes).expect("real cubin parses");
        let Some(text) = kernel_text_bytes(&elf, kname) else {
            panic!("{sm}/{kname}: missing .text.<kernel> section");
        };

        let json_path = cubin_path.with_extension("sass.json");
        let truth = load_ground_truth(&json_path);

        // The SASS decoder: sm band must match the cubin.
        let sm_arch = match elf.header.architecture() {
            hexray_core::Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => sm,
            other => panic!("unexpected arch {other:?}"),
        };
        let d = SassDisassembler::for_sm(sm_arch);

        let results = d.disassemble_block(text, 0);
        let stats = by_sm.entry(sm.clone()).or_insert_with(PerSmStats::new);
        stats.kernels += 1;

        let n = results.len().min(truth.len());
        for i in 0..n {
            let expected = base_mnemonic(&truth[i].1);
            let got = results[i]
                .as_ref()
                .map(|ins| base_mnemonic(&ins.mnemonic))
                .unwrap_or("?");
            stats.instructions += 1;
            if !expected.is_empty() && expected == got {
                stats.matched += 1;
            } else if stats.mismatches.len() < 5 {
                stats
                    .mismatches
                    .push((kname.clone(), i, expected.to_string(), got.to_string()));
            }
        }
    }

    eprintln!("\nM4 mnemonic match-rate report:");
    for (sm, s) in &by_sm {
        eprintln!(
            "  {sm}: {}/{} = {:.1}%  across {} kernels",
            s.matched,
            s.instructions,
            s.pct(),
            s.kernels
        );
        for (k, i, exp, got) in s.mismatches.iter().take(3) {
            eprintln!("      miss  {k}[{i}]: expected {exp}  got {got}");
        }
    }

    // Gate on sm_80 specifically — that's the M4 success criterion.
    let sm80 = by_sm.get("sm_80").expect("sm_80 present in corpus");
    assert!(
        sm80.pct() >= BASE_MNEMONIC_THRESHOLD_PCT,
        "sm_80 base-mnemonic match rate {:.1}% < {}% threshold",
        sm80.pct(),
        BASE_MNEMONIC_THRESHOLD_PCT
    );
}

#[test]
fn every_decoded_instruction_is_16_bytes_and_never_desyncs() {
    let cubins = enumerate_corpus();
    if cubins.is_empty() {
        return;
    }
    for (sm, kname, cubin_path) in &cubins {
        let bytes = fs::read(cubin_path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let text = kernel_text_bytes(&elf, kname).unwrap();
        let sm_arch = match elf.header.architecture() {
            hexray_core::Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => sm,
            _ => continue,
        };
        let d = SassDisassembler::for_sm(sm_arch);
        let results = d.disassemble_block(text, 0);
        assert_eq!(
            results.len() * 16,
            text.len(),
            "{sm}/{kname}: decoded {} slots × 16 != {} bytes",
            results.len(),
            text.len()
        );
        for (i, r) in results.iter().enumerate() {
            if let Ok(ins) = r {
                assert_eq!(ins.size, 16, "{sm}/{kname}[{i}]: size={}", ins.size);
                assert_eq!(ins.address, (i * 16) as u64);
            }
        }
    }
}

#[test]
fn predicate_guards_render_on_known_instruction() {
    // vector_add's "@P0 EXIT" (instruction 5) should come out with a
    // non-None guard; the trailing unconditional EXIT (instruction 15)
    // should not.
    let Some(root) = corpus_root() else {
        return;
    };
    let cubin = root.join("sm_80/vector_add.cubin");
    if !cubin.exists() {
        return;
    }
    let bytes = fs::read(cubin).unwrap();
    let elf = Elf::parse(&bytes).unwrap();
    let text = kernel_text_bytes(&elf, "vector_add").unwrap();
    let d = SassDisassembler::ampere();
    let results = d.disassemble_block(text, 0);
    let guarded_exit = results[5].as_ref().unwrap();
    assert_eq!(guarded_exit.mnemonic, "EXIT");
    let g = guarded_exit.guard.expect("@P0 guard");
    assert!(!g.negate, "guard should be positive @P0 not @!P0");

    let bare_exit = results[15].as_ref().unwrap();
    assert_eq!(bare_exit.mnemonic, "EXIT");
    assert!(
        bare_exit.guard.is_none(),
        "unconditional EXIT must have no guard"
    );
}
