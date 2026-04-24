//! SASS disassembly comparison tests against `nvdisasm -json` ground truth.
//!
//! The reference isn't `objdump` here — NVIDIA's own `nvdisasm` emits a
//! schema-versioned JSON shape that we diff against. The corpus lives at
//! `tests/corpus/cuda/build/` and is regenerated off-tree via
//! `scripts/build-cuda-corpus.sh` (the CUDA toolkit isn't a CI
//! dependency). When the corpus is absent, every test in this module
//! no-ops with a `SKIP` message so contributors without a GPU toolkit
//! still get a green build.
//!
//! The harness reports match rates at three tightening levels so we can
//! track progress milestone-by-milestone:
//!
//! - **Base mnemonic** — `ISETP.GE.AND` vs `ISETP.GT.AND` both reduce
//!   to `ISETP`. Gate for M4.
//! - **Full mnemonic** — variant suffixes included (`LDG.E.CONSTANT`).
//!   M7's target.
//! - **Predicate guard** — did we recover `@P0` / `@!P0` correctly?
//!   M4's guard decoder already satisfies this.
//!
//! Operand-level match is intentionally *not* gated yet — that's the
//! later half of M7 once per-opcode field tables land.

#![allow(dead_code)]

use hexray_disasm::cuda::SassDisassembler;
use hexray_disasm::Disassembler;
use hexray_formats::{Elf, Section};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Per-kernel diff summary, serialisable so CI can diff two runs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SassDiffResult {
    pub sm: String,
    pub kernel: String,
    pub total_instructions: usize,
    pub base_mnemonic_matches: usize,
    pub full_mnemonic_matches: usize,
    pub guard_matches: usize,
    pub first_mismatches: Vec<SassMismatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SassMismatch {
    pub index: usize,
    pub address: u64,
    pub expected_mnemonic: String,
    pub got_mnemonic: String,
    pub expected_guard: Option<String>,
    pub got_guard: Option<String>,
}

impl SassDiffResult {
    pub fn base_rate(&self) -> f64 {
        pct(self.base_mnemonic_matches, self.total_instructions)
    }
    pub fn full_rate(&self) -> f64 {
        pct(self.full_mnemonic_matches, self.total_instructions)
    }
    pub fn guard_rate(&self) -> f64 {
        pct(self.guard_matches, self.total_instructions)
    }
}

fn pct(num: usize, denom: usize) -> f64 {
    if denom == 0 {
        100.0
    } else {
        (num as f64) * 100.0 / (denom as f64)
    }
}

/// Aggregate across a set of kernels (usually all kernels for one SM).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SassDiffAggregate {
    pub total_instructions: usize,
    pub base_mnemonic_matches: usize,
    pub full_mnemonic_matches: usize,
    pub guard_matches: usize,
    pub kernel_count: usize,
}

impl SassDiffAggregate {
    pub fn add(&mut self, k: &SassDiffResult) {
        self.total_instructions += k.total_instructions;
        self.base_mnemonic_matches += k.base_mnemonic_matches;
        self.full_mnemonic_matches += k.full_mnemonic_matches;
        self.guard_matches += k.guard_matches;
        self.kernel_count += 1;
    }
    pub fn base_rate(&self) -> f64 {
        pct(self.base_mnemonic_matches, self.total_instructions)
    }
    pub fn full_rate(&self) -> f64 {
        pct(self.full_mnemonic_matches, self.total_instructions)
    }
    pub fn guard_rate(&self) -> f64 {
        pct(self.guard_matches, self.total_instructions)
    }
}

// ---- Corpus discovery ------------------------------------------------------

/// Absolute path to the corpus build directory, if it exists.
pub fn corpus_root() -> Option<PathBuf> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).parent()?.parent()?;
    let p = repo.join("tests/corpus/cuda/build");
    p.is_dir().then_some(p)
}

/// `(sm_name, kernel_name, cubin_path)` for every corpus cubin.
pub fn enumerate_corpus() -> Vec<(String, String, PathBuf)> {
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

// ---- nvdisasm JSON loader --------------------------------------------------

/// One instruction parsed out of `nvdisasm -json`. `opcode` is the full
/// mnemonic including `.` suffixes; `predicate` is the raw rendering
/// (`@P0`, `@!P3`, or `None` for unguarded).
#[derive(Debug, Clone)]
pub struct ReferenceInstruction {
    pub opcode: String,
    pub predicate: Option<String>,
}

/// Walk the nvdisasm JSON shape and return the concatenated instruction
/// list across every function in the file. The corpus only has one
/// function per file today, but we collect them all anyway so we don't
/// silently lose cubins with multiple `.text.<kernel>` sections later.
pub fn load_nvdisasm_reference(json_path: &Path) -> Vec<ReferenceInstruction> {
    let raw = match fs::read_to_string(json_path) {
        Ok(x) => x,
        Err(_) => return Vec::new(),
    };
    let Ok(v): Result<Value, _> = serde_json::from_str(&raw) else {
        return Vec::new();
    };
    // Layout: [ meta-dict, [ { function-name, sass-instructions: [...] }, ... ] ]
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
            out.push(ReferenceInstruction {
                opcode: ins
                    .get("opcode")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
                predicate: ins
                    .get("predicate")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            });
        }
    }
    out
}

// ---- Normalization ---------------------------------------------------------

/// Strip `.` suffixes so `ISETP.GE.AND` collapses to `ISETP`.
pub fn base_mnemonic(full: &str) -> &str {
    full.split('.').next().unwrap_or("")
}

/// Render our `Instruction.guard` in `nvdisasm` textual form (`@P0`,
/// `@!P3`) for comparison.
pub fn render_guard(guard: &Option<hexray_core::PredicateGuard>) -> Option<String> {
    guard.as_ref().map(|g| {
        let idx = g.register.id & 0x7;
        if g.negate {
            format!("@!P{idx}")
        } else {
            format!("@P{idx}")
        }
    })
}

// ---- Core comparison -------------------------------------------------------

/// Find `.text.<kernel>` bytes inside a parsed ELF by section name.
pub fn kernel_text_bytes<'a>(elf: &'a Elf<'_>, kernel: &str) -> Option<&'a [u8]> {
    let want = format!(".text.{kernel}");
    elf.sections
        .iter()
        .find(|s| s.name() == want)
        .map(|s| s.data())
}

/// Diff one cubin's `.text.<kernel>` against its paired `.sass.json`.
pub fn compare_kernel(sm: &str, kernel: &str, cubin_path: &Path) -> Result<SassDiffResult, String> {
    let bytes = fs::read(cubin_path).map_err(|e| format!("read: {e}"))?;
    let elf = Elf::parse(&bytes).map_err(|e| format!("parse: {e:?}"))?;
    let text = kernel_text_bytes(&elf, kernel).ok_or("missing .text section")?;

    let json_path = cubin_path.with_extension("sass.json");
    let truth = load_nvdisasm_reference(&json_path);

    let sm_arch = match elf.header.architecture() {
        hexray_core::Architecture::Cuda(hexray_core::CudaArchitecture::Sass(sm)) => sm,
        other => return Err(format!("unexpected arch {other:?}")),
    };
    let d = SassDisassembler::for_sm(sm_arch);
    let results = d.disassemble_block(text, 0);

    let mut out = SassDiffResult {
        sm: sm.to_string(),
        kernel: kernel.to_string(),
        ..Default::default()
    };

    let n = results.len().min(truth.len());
    for i in 0..n {
        let ref_ins = &truth[i];
        let expected_base = base_mnemonic(&ref_ins.opcode);
        let got_mnemonic = results[i]
            .as_ref()
            .map(|ins| ins.mnemonic.as_str())
            .unwrap_or("?");
        let got_guard = results[i]
            .as_ref()
            .ok()
            .and_then(|ins| render_guard(&ins.guard));

        out.total_instructions += 1;

        if !expected_base.is_empty() && expected_base == base_mnemonic(got_mnemonic) {
            out.base_mnemonic_matches += 1;
        }
        if !ref_ins.opcode.is_empty() && ref_ins.opcode == got_mnemonic {
            out.full_mnemonic_matches += 1;
        }
        if ref_ins.predicate == got_guard {
            out.guard_matches += 1;
        }

        // Record first few mismatches at either level so the CI artefact
        // has regression breadcrumbs.
        let base_miss = expected_base != base_mnemonic(got_mnemonic);
        let full_miss = !ref_ins.opcode.is_empty() && ref_ins.opcode != got_mnemonic;
        if (base_miss || full_miss) && out.first_mismatches.len() < 16 {
            out.first_mismatches.push(SassMismatch {
                index: i,
                address: (i * 16) as u64,
                expected_mnemonic: ref_ins.opcode.clone(),
                got_mnemonic: got_mnemonic.to_string(),
                expected_guard: ref_ins.predicate.clone(),
                got_guard,
            });
        }
    }
    Ok(out)
}

/// Render a multi-line human-readable report for a set of per-SM
/// aggregates plus per-kernel details.
pub fn format_report(
    per_kernel: &[SassDiffResult],
    per_sm: &std::collections::BTreeMap<String, SassDiffAggregate>,
) -> String {
    let mut s = String::new();
    s.push_str("SASS differential report\n");
    s.push_str("========================\n\n");
    for (sm, agg) in per_sm {
        s.push_str(&format!(
            "{sm}  kernels={}  insts={}  base={:.1}%  full={:.1}%  guard={:.1}%\n",
            agg.kernel_count,
            agg.total_instructions,
            agg.base_rate(),
            agg.full_rate(),
            agg.guard_rate(),
        ));
    }
    s.push('\n');
    for k in per_kernel {
        if !k.first_mismatches.is_empty() {
            s.push_str(&format!("--- {}/{} ---\n", k.sm, k.kernel));
            for m in &k.first_mismatches {
                let eg = m.expected_guard.as_deref().unwrap_or("-");
                let gg = m.got_guard.as_deref().unwrap_or("-");
                s.push_str(&format!(
                    "  [{:>3}] @{:#06x}  expected {:<20} {}  got {:<20} {}\n",
                    m.index, m.address, m.expected_mnemonic, eg, m.got_mnemonic, gg
                ));
            }
        }
    }
    s
}

/// Run the full corpus pipeline. Returns `None` when the corpus isn't
/// built; callers should treat that as a skip.
pub fn run_corpus() -> Option<(
    Vec<SassDiffResult>,
    std::collections::BTreeMap<String, SassDiffAggregate>,
)> {
    let cubins = enumerate_corpus();
    if cubins.is_empty() {
        return None;
    }
    let mut per_kernel: Vec<SassDiffResult> = Vec::with_capacity(cubins.len());
    let mut per_sm: std::collections::BTreeMap<String, SassDiffAggregate> = Default::default();
    for (sm, kname, cubin_path) in &cubins {
        match compare_kernel(sm, kname, cubin_path) {
            Ok(r) => {
                per_sm.entry(sm.clone()).or_default().add(&r);
                per_kernel.push(r);
            }
            Err(e) => {
                eprintln!("FAIL {sm}/{kname}: {e}");
            }
        }
    }
    Some((per_kernel, per_sm))
}

// ---- Thresholds tracked for CI --------------------------------------------

/// Match-rate thresholds the CI gate enforces. These are the *floors*:
/// actual rates can be higher and usually are.
pub mod threshold {
    /// M4 success criterion on sm_80 (base mnemonic only).
    pub const BASE_MNEMONIC_SM80: f64 = 70.0;
    /// Predicate guards should decode reliably today.
    pub const GUARD_ALL_SMS: f64 = 95.0;
    /// Full-mnemonic (with variant suffixes) — M7 success criterion.
    /// Measured 95.8% on ptxas 13.2 sm_80/86/89 at commit time; set
    /// floor at 92% so normal drift doesn't break the build while a
    /// real regression still trips.
    pub const FULL_MNEMONIC_ALL_SMS: f64 = 92.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_mnemonic_splits_on_dot() {
        assert_eq!(base_mnemonic("ISETP.GE.AND"), "ISETP");
        assert_eq!(base_mnemonic("NOP"), "NOP");
        assert_eq!(base_mnemonic(""), "");
    }

    #[test]
    fn pct_handles_zero_denominator() {
        assert_eq!(pct(0, 0), 100.0);
        assert_eq!(pct(5, 10), 50.0);
    }

    #[test]
    fn render_guard_formats_positive_and_negated() {
        use hexray_core::{
            Architecture, CudaArchitecture, PredicateGuard, Register, RegisterClass,
            SmArchitecture, SmVariant,
        };
        let sm = SmArchitecture::new(8, 0, SmVariant::Base);
        let arch = Architecture::Cuda(CudaArchitecture::Sass(sm));
        let reg = Register::new(arch, RegisterClass::Predicate, 2, 1);
        let g = Some(PredicateGuard::positive(reg));
        assert_eq!(render_guard(&g), Some("@P2".to_string()));
        let g = Some(PredicateGuard::negated(reg));
        assert_eq!(render_guard(&g), Some("@!P2".to_string()));
        assert_eq!(render_guard(&None), None);
    }
}
