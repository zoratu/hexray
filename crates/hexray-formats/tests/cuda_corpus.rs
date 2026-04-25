//! Corpus-driven regression tests for the CUDA CUBIN view.
//!
//! These tests walk every `.cubin` under `tests/corpus/cuda/build/` and
//! assert that hexray recovers the same kernel / resource picture that
//! `nvdisasm` records in the paired `.sass.json`. The corpus is
//! gitignored and regenerated via `scripts/build-cuda-corpus.sh`; when
//! the artifacts are missing these tests become silent no-ops so CI
//! (which doesn't ship a CUDA toolkit) stays green.
//!
//! The tests live here rather than as inline unit tests because they
//! need the full `tests/` fixture tree, which unit tests can't reach
//! without `CARGO_MANIFEST_DIR`-relative paths.

use hexray_formats::{CubinError, Elf, KernelConfidence, KernelResourceUsage, MemorySpace};
use std::fs;
use std::path::{Path, PathBuf};

/// Absolute path to the corpus build directory, or `None` when the
/// corpus hasn't been built on this box.
fn corpus_root() -> Option<PathBuf> {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()? // crates/
        .parent()?; // repo root
    let p = repo_root.join("tests/corpus/cuda/build");
    if p.is_dir() {
        Some(p)
    } else {
        None
    }
}

/// Walk every cubin under `build/sm_*/*.cubin`. Returns `(sm, kernel_name, path)`.
fn enumerate_cubins() -> Vec<(String, String, PathBuf)> {
    let Some(root) = corpus_root() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let Ok(sm_dirs) = fs::read_dir(&root) else {
        return out;
    };
    for sm_entry in sm_dirs.flatten() {
        let Some(sm_name) = sm_entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !sm_name.starts_with("sm_") {
            continue;
        }
        let Ok(kernels) = fs::read_dir(sm_entry.path()) else {
            continue;
        };
        for k_entry in kernels.flatten() {
            let path = k_entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("cubin") {
                continue;
            }
            let kname = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            out.push((sm_name.clone(), kname, path));
        }
    }
    out.sort();
    out
}

#[test]
fn every_cubin_parses_and_classifies_its_kernel() {
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        eprintln!("SKIP: no corpus at tests/corpus/cuda/build/ (run scripts/build-cuda-corpus.sh)");
        return;
    }

    let mut failures: Vec<String> = Vec::new();
    for (sm, expected_kernel, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = match Elf::parse(&bytes) {
            Ok(e) => e,
            Err(e) => {
                failures.push(format!("{sm}/{expected_kernel}: ELF parse error: {e:?}"));
                continue;
            }
        };
        let view = match elf.cubin_view() {
            Ok(v) => v,
            Err(CubinError::NotCuda) => {
                failures.push(format!("{sm}/{expected_kernel}: not recognised as CUDA"));
                continue;
            }
        };
        let entry_names: Vec<&str> = view.entry_kernels().map(|k| k.name).collect();
        if !entry_names.iter().any(|n| *n == expected_kernel) {
            failures.push(format!(
                "{sm}/{expected_kernel}: expected among entry kernels, got {entry_names:?}"
            ));
        }
        // No MalformedNvInfo should fire on any real ptxas-13.2 cubin.
        let malformed: Vec<_> = view
            .diagnostics()
            .iter()
            .filter(|d| matches!(d.kind, hexray_formats::CubinDiagnosticKind::MalformedNvInfo))
            .collect();
        if !malformed.is_empty() {
            failures.push(format!(
                "{sm}/{expected_kernel}: MalformedNvInfo diagnostics: {malformed:?}"
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn kernel_confidence_is_always_entry_marker_on_current_toolchain() {
    // ptxas 13.2 unconditionally sets STO_CUDA_ENTRY on kernel symbols.
    // If a future toolkit stops emitting it we want to notice loudly.
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    for (sm, kname, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let k = view
            .kernel_by_name(kname)
            .unwrap_or_else(|| panic!("{sm}/{kname} missing from view"));
        assert_eq!(
            k.confidence,
            KernelConfidence::EntryMarker,
            "{sm}/{kname} should be a strong entry match on ptxas 13.2"
        );
    }
}

#[test]
fn every_kernel_has_a_param_cbank_or_is_empty() {
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    for (sm, kname, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let k = view.kernel_by_name(kname).unwrap();
        let Some(usage) = k.resource_usage() else {
            panic!("{sm}/{kname} missing .nv.info sidecar");
        };
        // Every test kernel in the corpus takes at least one argument,
        // so the param_cbank attribute must be present.
        assert!(
            usage.param_cbank.is_some(),
            "{sm}/{kname} missing ParamCbank: {:?}",
            usage
        );
    }
}

#[test]
fn cbank_size_matches_sum_of_params_plus_cbank_offset() {
    // Consistency check: the param block size recorded in
    // PARAM_CBANK should accommodate every KPARAM_INFO record (size ≥
    // last_offset + last_size). Catches drift if the trailing u32
    // decomposition goes wrong.
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    let mut failures: Vec<String> = Vec::new();
    for (sm, kname, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let k = view.kernel_by_name(kname).unwrap();
        let usage = k.resource_usage().unwrap();
        let Some(cb) = usage.param_cbank else {
            continue;
        };
        let max_end = usage
            .params
            .iter()
            .map(|p| p.offset as u32 + p.size_bytes())
            .max()
            .unwrap_or(0);
        if max_end > cb.size {
            failures.push(format!(
                "{sm}/{kname}: params end at {max_end}, but PARAM_CBANK size is {}",
                cb.size
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn max_reg_count_is_plausible() {
    // Every handwritten kernel in the corpus fits well under 255 regs;
    // MaxRegCount should always be present and non-zero.
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    let mut failures: Vec<String> = Vec::new();
    for (sm, kname, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let usage = view
            .kernel_by_name(kname)
            .unwrap()
            .resource_usage()
            .unwrap();
        match usage.max_reg_count {
            None => failures.push(format!("{sm}/{kname}: MaxRegCount missing")),
            Some(0) => failures.push(format!("{sm}/{kname}: MaxRegCount=0 is implausible")),
            Some(_) => {}
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

#[test]
fn exit_offsets_fall_on_16_byte_boundaries() {
    // Every EXIT offset must land on a SASS instruction boundary
    // (multiple of 16 on Volta+). Cross-validates EXIT_INSTR_OFFSETS
    // decoding against our own SASS_INSTRUCTION_SIZE.
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    for (sm, kname, path) in &cubins {
        let bytes = fs::read(path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let usage = view
            .kernel_by_name(kname)
            .unwrap()
            .resource_usage()
            .unwrap();
        for off in &usage.exit_offsets {
            assert_eq!(
                off % 16,
                0,
                "{sm}/{kname}: EXIT offset {:#x} is not 16-byte aligned",
                off
            );
        }
    }
}

#[test]
fn shared_transpose_has_static_shared_region() {
    // shared_transpose is the only kernel in the corpus that declares
    // static __shared__ memory; if its region ever disappears from the
    // memory_regions list we want to know.
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    for sm in &["sm_80", "sm_86", "sm_89"] {
        let path = corpus_root()
            .unwrap()
            .join(sm)
            .join("shared_transpose.cubin");
        if !path.exists() {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let shared: Vec<_> = view
            .memory_regions()
            .iter()
            .filter(|r| matches!(r.space, MemorySpace::Shared))
            .collect();
        assert!(
            !shared.is_empty(),
            "{sm}/shared_transpose missing shared region"
        );
        assert_eq!(shared[0].owner_kernel, Some("shared_transpose"));
        assert!(
            shared[0].size > 0,
            "{sm}/shared_transpose shared region size is 0"
        );
    }
}

#[test]
fn constant_bias_uses_constant_bank_3() {
    // constant_bias reads from __constant__ memory. That user-declared
    // constant bank gets emitted as .nv.constant3 (bank number).
    let cubins = enumerate_cubins();
    if cubins.is_empty() {
        return;
    }
    for sm in &["sm_80", "sm_86", "sm_89"] {
        let path = corpus_root().unwrap().join(sm).join("constant_bias.cubin");
        if !path.exists() {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let banks: Vec<u8> = view
            .memory_regions()
            .iter()
            .filter_map(|r| match r.space {
                MemorySpace::Constant { bank } => Some(bank),
                _ => None,
            })
            .collect();
        assert!(
            banks.contains(&3),
            "{sm}/constant_bias should expose constant bank 3 (got {banks:?})"
        );
    }
}

fn _witness(_: KernelResourceUsage) {}

#[test]
fn every_cubin_exposes_ptx_sidecar_matching_the_kernel() {
    use hexray_formats::PtxFunctionKind;
    let Some(_) = corpus_root() else {
        return;
    };
    for (sm, kname, path) in enumerate_cubins() {
        let bytes = fs::read(&path).unwrap();
        let elf = Elf::parse(&bytes).unwrap();
        let view = elf.cubin_view().unwrap();
        let Some(ptx) = view.ptx_sidecar() else {
            panic!("{sm}/{kname}: missing .nv_debug_ptx_txt sidecar on nvcc -lineinfo build");
        };
        // Module header populated.
        assert!(
            ptx.header.version.is_some(),
            "{sm}/{kname}: PTX .version missing"
        );
        assert!(
            ptx.header
                .target
                .as_deref()
                .map(|t| t.starts_with("sm_"))
                .unwrap_or(false),
            "{sm}/{kname}: PTX .target missing or malformed"
        );
        assert_eq!(
            ptx.header.address_size,
            Some(64),
            "{sm}/{kname}: PTX address_size should be 64"
        );
        // The kernel we decoded from SASS should appear as a .entry
        // directive in the PTX side.
        let f = ptx
            .function_by_name(&kname)
            .unwrap_or_else(|| panic!("{sm}/{kname}: PTX entry for this kernel name missing"));
        assert_eq!(f.kind, PtxFunctionKind::Entry);
        assert!(f.visible, "{sm}/{kname}: PTX entry should be .visible");
        let body = ptx.function_body(f);
        assert!(!body.is_empty(), "{sm}/{kname}: PTX body span empty");
    }
}
