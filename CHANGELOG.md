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
