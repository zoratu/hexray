# Changelog

All notable changes to hexray will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### GPU Support (in progress on `feature/gpu-support`)

- **M1 – CUDA arch recognition**: `Architecture::Cuda(CudaArchitecture)` in
  `hexray-core`, carrying `SmArchitecture { family, major, minor, variant }`
  for SASS targets (`sm_80`, `sm_86`, `sm_89`, `sm_90a`, …) and `PtxVersion`
  for PTX sidecars. ELF `EM_CUDA = 190` is recognised with correct `e_flags`
  decoding for both ABI V1 (Ampere/Ada/Hopper) and ABI V2 (Blackwell+)
  layouts, including the `a` accelerator bit. `hexray info foo.cubin` now
  reports e.g. `cuda-sass (sm_80, family=Ampere)`. The previous
  `disassemble_block_for_arch` fallback that silently fed unknown-arch bytes
  to the x86 decoder has been removed — unsupported architectures now return
  an empty block rather than plausible-but-wrong disassembly.

- **M2 – raw CUBIN code-object view**: `Elf::cubin_view()` returns a typed
  `CubinView` over an EM_CUDA ELF, enumerating kernels, memory regions,
  module-wide `.nv.info`, and parsing diagnostics. Kernel detection uses
  the `STO_CUDA_ENTRY` bit in `st_other` (preserved from the raw symbol
  table), falling back to a sibling `.nv.info.<kernel>` section; ambiguous
  `.text.<name>` sections (e.g. out-of-line `__device__` helpers) are
  flagged rather than surfaced as kernels. `.nv.constantN`, `.nv.shared`,
  and `.nv.local` sections are classified into `MemoryRegion`s with the
  constant bank number preserved. `.nv.info` TLV framing is parsed into
  `NvInfoBlob { raw, entries: Vec<NvInfoEntryRef>, truncated }` with
  attribute IDs mapped to an `NvInfoAttribute` enum (unknown bytes are
  preserved verbatim). Payload semantics are intentionally left for M5.
  `hexray info foo.cubin` now lists kernels, memory regions, and any
  diagnostics. 18 new unit tests cover TLV framing, kernel detection,
  memory-region classification, and the edge cases called out in the M2
  design review.

- **M3 – SASS decode skeleton**: New `hexray-disasm/src/cuda/sass/` module
  (feature-gated on `cuda`) with a `SassDisassembler` targeting Volta
  through Blackwell (16-byte fixed-width encoding). The decoder walks
  code in lockstep 16-byte strides — overriding the default trait
  `disassemble_block` so a decode failure never desyncs the stream, which
  the byte-by-byte default would do catastrophically on a fixed-width
  ISA. `ControlBits` extracts the top 23 bits of each word (stall /
  yield / read-barrier / write-barrier / wait-mask / reuse).
  `registers.rs` handles the five SASS register files (R/P/UR/UP/SR)
  with RZ / PT / URZ / UPT aliases and `RegisterSpan` for `R0:R1`-style
  pairs rendered at display time rather than faked as register IDs.
  The M3 opcode table contains exactly one entry — the canonical
  Volta+ `NOP` (`0x7918` in the low 16 bits) — to prove end-to-end
  plumbing; real opcodes land in M4.

  Core IR extensions needed by the SASS decoder also landed:
  `Instruction.guard: Option<PredicateGuard>` for per-instruction
  predicate guards (`@P0` / `@!P0` on SASS); `MemoryRef.space:
  MemorySpace` with variants `Generic / Global / Shared / Local /
  Constant(u8) / Param`. Both default cleanly so CPU decoders compile
  unchanged. 29 new SASS tests plus tests for the IR extensions.

- **M5 – kernel metadata MVP**: Typed decoding of `.nv.info` record
  payloads. New `KernelResourceUsage` summary on `hexray-formats`:
  `max_reg_count`, `min_stack_size`, `frame_size`, `max_stack_size`,
  `cbank_param_size`, `param_cbank` (bank/offset/size),
  `params: Vec<ParamInfo>` with ordinal / offset / size_dwords /
  raw_trailer, `exit_offsets` (for CFG bookkeeping),
  `s2r_ctaid_offsets`, `max_threads`, `req_ntid` / `max_ntid` launch
  bounds, `ctaidz_used`. Accessed via `Kernel::resource_usage()`.

  Decoding is grounded in the 30-cubin handwritten corpus: every
  field matches the values `cuobjdump --dump-resource-usage` reports
  for the same cubin. `vector_add` → `regs=255 params@c[0][0x160]
  size=28 args=[#3:4B,#2:8B,#1:8B,#0:8B]`. `shared_transpose` →
  `args=[#2:4B,#1:8B,#0:8B]` + 4 KB static shared region.
  `constant_bias` → constant bank 3 surfaced as a dedicated memory
  region.

  Corpus-driven regression tests (`hexray-formats/tests/cuda_corpus.rs`)
  walk every cubin under `tests/corpus/cuda/build/`, asserting:
  (a) every kernel promotes via `STO_CUDA_ENTRY`, (b) no
  `MalformedNvInfo` diagnostics fire, (c) `PARAM_CBANK.size >=
  max(param_offset + param_size)`, (d) every EXIT offset lands on a
  16-byte boundary, (e) `constant_bias` exposes constant bank 3, (f)
  `shared_transpose` exposes its `.nv.shared.<kernel>` region. Tests
  no-op when the corpus isn't built locally, so CI (which doesn't
  ship a CUDA toolkit) stays green.

  `hexray info foo.cubin` now prints per-kernel `regs=`, `params@c[]`,
  `exits=`, `ctaidz`, and an `args=[#n:BsB,...]` summary underneath
  the kernel line.

- **M4 – core SASS semantics**: First working SASS opcode table.
  34 opcode classes harvested empirically from the 30-cubin
  sm_80/86/89 corpus and cross-referenced against `nvdisasm -json`
  base mnemonics: NOP, BRA, EXIT, BSYNC, BSSY, BAR, MOV, S2R, IADD3,
  LEA, LOP3, SHF, IMAD, IMAD.WIDE (shared class), ISETP, PLOP3, FMUL,
  FADD, FFMA, HFMA2, FSETP, ULDC, USHF, UFLO, LDG, LDC, LDS, STG, STS,
  RED, SHFL, POPC, VOTE, VOTEU. Each entry carries a `(op_class,
  base_mnemonic, Operation)` tuple in `cuda/sass/opcode_table.rs`.

  Predicate guard decoding (`Instruction.guard`): the 4-bit field at
  bits `[12..=15]` resolves to `@P0`..`@P6` / `@!P0`..`@!P6`, with
  `0b0111 = PT` collapsing to `None` (no guard printed).

  Basic operand extraction: destination register from bits `[16..=23]`
  on ALU/load/MOV/S2R classes; first source register from bits
  `[24..=31]` on ALU/compare/store/load. Full per-opcode operand
  decoding (memory refs, cbank refs, immediates) is M7.

  End-to-end match-rate gate in `crates/hexray/tests/cuda_sass_match.rs`:
  walks every cubin, decodes the `.text.<kernel>` section, compares
  recovered base mnemonics against `nvdisasm`'s ground truth.

  Current results on the handwritten microkernel corpus:

      sm_80: 448/448 = 100.0%  across 10 kernels
      sm_86: 448/448 = 100.0%  across 10 kernels
      sm_89: 448/448 = 100.0%  across 10 kernels

  The M4 success criterion (≥ 70% base match on sm_80) is the test's
  gate; the actual number is 100%. Variant suffixes and full operand
  rendering bring the numbers down again under M7's stricter
  comparison, as expected.

  3 new integration tests, 5 new opcode_table unit tests, 2 new
  decoder unit tests (predicate decode, desync-free walk). Full
  workspace green, clippy clean with `-D warnings`.

- **M6 – differential harness + corpus pipeline**: Proper SASS diff
  module at `crates/hexray/tests/differential/sass_compare.rs`,
  wired into the existing `differential_tests` integration surface
  alongside the objdump / nm / strings gates. Tracks match rates at
  three tightening levels — base mnemonic, full mnemonic (with
  `.`-suffix variants), and predicate guard. Results serialise to
  JSON (`/tmp/hexray-sass-diff-report.json`) for CI artefact
  tracking. Skips silently when the corpus isn't built on the box.

  Live gates (floors, not targets):

      sm_80 base mnemonic ≥ 70%
      every SM predicate guard ≥ 95%
      every SM full mnemonic ≥ 5% (regression floor only)

  Current numbers on ptxas 13.2 / sm_80/86/89:

      sm_80  kernels=10  insts=448  base=100.0%  full=65.2%  guard=100.0%
      sm_86  kernels=10  insts=448  base=100.0%  full=67.9%  guard=100.0%
      sm_89  kernels=10  insts=448  base=100.0%  full=67.9%  guard=100.0%

  The full-mnemonic floor is set low because variant suffixes
  (`.E.CONSTANT`, `.WIDE`, `.GE.AND`) land in M7. The current 65-68%
  figure comes from instructions that have no variant suffix
  (`NOP`, `BRA`, `EXIT`, `MOV`, `S2R`, …); M7 brings it up.

- **M7 – Ampere/Ada coverage expansion**: Per-opcode variant-suffix
  decoders lift full-mnemonic match from 65% → **95.8%** on the
  sm_80/86/89 handwritten corpus. New `default_suffix` field on every
  `OpcodeEntry` for always-present suffixes (`LOP3.LUT`, `PLOP3.LUT`,
  `HFMA2.MMA`, `STG.E`, `LDG.E.CONSTANT`, `BAR.SYNC.DEFER_BLOCKING`,
  `SHFL.DOWN`, `VOTE.ANY`, `RED.E.ADD.STRONG.GPU`, …), plus a
  `Option<VariantFn>` callback for opcodes whose suffix depends on
  encoding bits:

      ISETP/FSETP    → cmp (bits 76-78) + bool (74-75) + signed (73)
                       yields .GE.AND, .GT.U32.OR, etc. (24 cases/SM)
      IMAD           → .X (bit 72) or .MOV.U32 (RZ,RZ multiplicands)
      IMAD.WIDE      → .WIDE vs .WIDE.U32 on bit 73
      IADD3          → .X on bit 74
      LEA            → .HI / .X / .HI.X / .HI.X.SX32 combinations
      SHF            → direction (L/R) + type (U32/S32) + .HI
      ULDC           → .64 on bit 73
      LDG            → .CONSTANT on cache-op field

  Raised the differential harness's `FULL_MNEMONIC_ALL_SMS` threshold
  from 5.0% (regression floor) to **92.0%** (M7 success criterion).

  Live numbers on ptxas 13.2 as of M7 landing:

      sm_80: 448/448 = 100.0% base /  95.8% full / 100.0% guard
      sm_86: 448/448 = 100.0% base /  95.8% full / 100.0% guard
      sm_89: 448/448 = 100.0% base /  95.8% full / 100.0% guard

  The remaining ~4.2% gap is concentrated in `IMAD.MOV.U32` detection
  (needs better operand-pattern recognition), some `SHF` / `USHF`
  variants, and `LEA.HI.SX32` vs `LEA.HI.X.SX32`. Those land as
  follow-up patches under M7 once the user-declared operand decoding
  (the second half of M7 per codex's plan) is in.

- **M8 – fatbin + PTX sidecar**: Two new modules land:

  - `crates/hexray-formats/src/elf/cuda/ptx.rs` — cheap PTX text
    parser. `PtxIndex::parse(&str)` for standalone `.ptx` files,
    `PtxIndex::from_nul_delimited_bytes(&[u8])` for the
    `.nv_debug_ptx_txt` section `nvcc -lineinfo` embeds inside
    CUBINs (which separates directives with `\0` instead of `\n`).
    Extracts the module header (`.version` / `.target` /
    `.address_size`) and indexes every `.entry` / `.func`
    directive with its body span — enough for a UI to render PTX
    side-by-side with SASS or for name-based kernel linking. No
    AST, per codex's design note.

    Accessed via `Kernel::resource_usage()`-style sugar on the
    CubinView: `view.ptx_sidecar() -> Option<PtxIndex<'_>>`. A
    corpus regression test confirms every ptxas-13.2 cubin in
    `tests/corpus/cuda/build/` exposes a valid PTX sidecar whose
    `.entry` directive matches the SASS kernel name.

  - `crates/hexray-formats/src/cuda/fatbin.rs` — fatbin wrapper
    parser. `FatbinWrapper::parse(&[u8])` reads the 16-byte
    wrapper (`magic 0xBA55_ED50`) + packed entry table; surfaces
    `FatbinEntry { kind, sm, payload, compressed }` for each
    embedded cubin / PTX blob, with `cubins()` / `ptx_entries()`
    convenience iterators. Tolerant against malformed input —
    returns `FatbinError::{Truncated, BadMagic, EntryOverflow,
    PayloadOverflow}` rather than panicking. Tests synthesise
    wrappers around real sm_80 cubins from the corpus and
    round-trip them byte-for-byte; `host-binary-embedded fatbin`
    validation is deferred to a future corpus rebuild (needs a
    host ELF that `nvcc` produced with `-rdc=true`).

  PTX↔SASS linking for the single-kernel-per-cubin case is
  already implicit: both sides use the same (mangled) name, so
  `ptx.function_by_name(&sass_kernel.name)` just works.

- **GPU testing batch**: closes the quality bar items the rest of the
  repo holds new code to.
  - CUDA-info snapshot test (hermetic synthetic stub).
  - `Send + Sync` compile-time witnesses on the SASS decoder, owned
    record types, and the fatbin wrapper.
  - CFG smoke test that feeds real SASS instructions through the
    existing `CfgBuilder`.
  - Miri now runs the CUDA fault-injection suite (13 tests pass under
    the strict UB interpreter).
  - Coverage check passes: workspace 73.36%, every new CUDA file
    83-100% lines.
  - Mutation testing run with `cargo-mutants` on the SASS modules;
    surfaced gaps closed in `registers.rs` (now 0 missed of 57
    viable) and tightened tests on `variant_setp` / `variant_lea`
    / `variant_shf`.
  - Criterion benchmark for SASS decode (single NOP ≈ 43 ns;
    1024-instruction throughput ≈ 1.4 GB/s).
  - Corpus extended to sm_75 and sm_90 (Turing + Hopper). The
    differential gate is SM-band-aware: v1 SMs (sm_80/86/89) keep
    the 92% full-mnemonic floor; sm_75 / sm_90 track a softer 70%
    floor while we incrementally add their SM-specific opcodes.
  - New opcode entries: `S2UR`, `VIADD`, `BMOV`, plus `LDC.64`
    variant. sm_90 full-mnemonic match: 91.3% → 97.2%.

## [1.2.1] - 2026-03-19

### Testing

- **Swarm Testing**: Added swarm testing infrastructure for decompiler (Groce et al., ISSTA 2012)
  - Randomly omit optimization passes to find bugs through feature-omission diversity
  - `DecompilerConfig::from_swarm_bits()` for coin-toss pass selection
  - proptest suite: crash safety, determinism, monotonicity, loop robustness
  - Per-pass trigger/suppressor analysis (coverage report)
  - Verified on x86_64 and aarch64 with 0 failures across 1,200+ random configs

- **Miri Memory-Safety Gate**: Added Miri to pre-push validation (e76fc4b3a)

- **Feature, Security, and Coverage Gates**: Added comprehensive test gates (400afdfb8)

### Hardening

- **Mach-O Parser**: Hardened load command parsing against malformed inputs (67f6952f9)

- **Incremental Analysis**: Hardened invalidation logic and modeled it (9d25e3db9)

## [1.2.0] - 2026-02-25

### Critical Fixes

- **CRITICAL**: Fixed register aliasing in decompiler optimization passes (ae6326c93, 39e6156e5)
  - Loop variable updates were being incorrectly eliminated on ARM64 and x86-64
  - Made copy propagation and dead store elimination aware of register aliasing (w9↔x9, eax↔rax)
  - Fixes infinite loops, uninitialized variables, and non-compilable output
  - All 1040+ tests passing
  - Tested with 15+ different loop patterns across ARM64 and x86-64

### Decompiler Improvements

- **Loop Variable Tracking**: Fixed emission phase statement skipping logic (ae6326c93)
  - Fixed skip_statements to use BasicBlockId instead of positional index
  - Fixed return register and temp register filtering
  - Preserves critical loop variable assignments

- **Signature Recovery**: Preserve calling convention registers for better signature inference (d5fa20676)

- **Type Inference**: Add typed pointer inference for arrays (520748b7b)

- **Output Quality**: Comprehensive output quality improvements (47bfb66e8, 0e7a13bf2)
  - Improved type defaults and signature validation
  - Enhanced callback recovery with better alias tracking
  - Reduced callback shape-fallback false positives (20a6ffc60)
  - Hardened callback alias recovery with quality gates (a4738f1e4)

- **Parameter Naming**: Align lifted arg-slot parameter naming (8e4ead436)
  - Improved variable declarations and parameter naming (25571844b)
  - Fixed header/body naming mismatches

- **Return Type Inference**:
  - Default literal return nodes to int32 (960ee18dc)
  - Keep return-register width for literal returns (93a5e99cd)
  - Improved main-like function return typing

- **Loop Initialization**:
  - Improved loop-condition zero-init analysis (order-aware) (46ff4844f)
  - Fixed use-before-write artifacts in counter-like variables

- **Code Cleanup**:
  - Filter prologue callee-saved register saves (b14840f3c)
  - Filter epilogue register restores (41bb2bc8e)
  - Stop emission after control-exit statements (3348b91ec)

- **ARM64 Specific**:
  - Improved ARM64 output readability (6e0ba10fc)
  - Expanded ARM64 register renaming (0166ea493)
  - Improved Linux/ARM64 output quality (d24580377)

### Testing

- Updated callback test expectations for array parameter names (719b41f32, 65cf0df48, 0a630ef0a)
- Updated sort test expectations (53284d4bb)
- Added stack-spill callback quality gates to benchmarks (cd7af86c8)
- Added signature validation to benchmark system (3b70944d1)

### Bug Fixes

- Fix clippy warning for manual range contains (bbbc4caca)

### Documentation

- Documented register aliasing fix in DECOMPILER_IMPROVEMENTS.md (5bc940f31)
  - Added comprehensive section with examples, root cause analysis, and testing details

## [1.1.0] - (Previous release)

(Historical changes from previous releases)

## [1.0.0] - (Initial release)

(Historical changes from initial release)
