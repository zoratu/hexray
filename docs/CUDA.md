# CUDA / NVIDIA GPU Support

hexray supports NVIDIA CUDA binaries (CUBINs) and the SASS instruction
set (Volta and newer) end-to-end: ELF recognition → kernel and resource
metadata → SASS disassembly → PTX sidecar → fatbin extraction.

This document covers the architecture, what's currently decoded, the
testing surface, and how to extend coverage.

## Quick start

```bash
# Compile a CUDA kernel for sm_80:
nvcc --cubin -arch=sm_80 my_kernel.cu -o my_kernel.cubin

# Inspect with hexray:
hexray my_kernel.cubin info
```

Sample output on a real `vector_add` cubin:

```
Binary Information
==================
Format:        ELF
Architecture:  cuda-sass (sm_80, family=Ampere)
Endianness:    Little
Bitness:       Bits64
Type:          Executable
Machine:       Cuda

Sections:      19
Segments:      3

CUDA CUBIN View
---------------
Kernels:       1 (1 entry, 0 candidate)
  [entry] vector_add  size=512  section=#18 (+nv_info)
      regs=255  params@c[0][0x160] size=28  exits=2
      args=[#3:4B,#2:8B,#1:8B,#0:8B]
Memory Regions: 1
  - constant[0] (vector_add)  .nv.constant0.vector_add  size=380
Module .nv.info: 3 entries
```

## Supported targets

| Family    | Compute capability | Status        |
|-----------|--------------------|---------------|
| Volta     | sm_70 / sm_72      | Decoder runs  |
| Turing    | sm_75              | Decoder runs  |
| Ampere    | sm_80 / sm_86 / sm_87 | **Tested in corpus** |
| Ada       | sm_89              | **Tested in corpus** |
| Hopper    | sm_90 / sm_90a     | Decoder runs (no corpus) |
| Blackwell | sm_10x             | Recognised; `e_flags` V2 layout |
| Maxwell / Pascal | sm_5x / sm_6x | Rejected: 8-byte encoding not supported |

Ampere/Ada is the v1 differential gate. Hopper/Blackwell decode
without errors but variant-suffix coverage hasn't been measured yet
because `nvcc` builds for those targets need a different test box.

## Architecture

### Crate layout

```
hexray-core
   └── arch.rs       Architecture::Cuda(CudaArchitecture::{Sass, Ptx})
                     SmArchitecture, SmFamily, SmVariant, PtxVersion
   └── instruction.rs PredicateGuard (Instruction.guard)
   └── operand.rs    MemorySpace (MemoryRef.space)

hexray-formats
   └── elf/
   │   └── header.rs Machine::Cuda + sm_from_cuda_elf (V1/V2)
   │   └── cuda/
   │       ├── mod.rs      CubinView, Kernel, KernelConfidence
   │       ├── info.rs     .nv.info TLV parser (NvInfoBlob)
   │       ├── ptx.rs      .nv_debug_ptx_txt PTX sidecar
   │       └── schema.rs   Typed payload decode (KernelResourceUsage)
   └── cuda/
       └── fatbin.rs        FatbinWrapper for host-binary extraction

hexray-disasm
   └── cuda/sass/    SassDisassembler (feature `cuda`)
       ├── bits.rs       SassWord, bit_range
       ├── control.rs    ControlBits (top 23 bits)
       ├── opcode_table.rs 34 opcode classes + variant decoders
       └── registers.rs  R/P/UR/UP/SR + RegisterSpan
```

### Kernel detection heuristic

Surfacing a `.text.<name>` section as a kernel is non-trivial — out-of-line
`__device__` functions also live in their own `.text.*` sections.
`CubinView` uses a priority-ordered classification:

1. **`STO_CUDA_ENTRY` bit set in `st_other`** of a defining symbol →
   `KernelConfidence::EntryMarker`. Highest confidence; this is the
   signal `nvdisasm` itself uses.
2. **A sibling `.nv.info.<name>` section** but no entry bit →
   `KernelConfidence::SiblingInfoOnly`. Surfaced for inspection, but
   strict consumers should filter to entry-marker kernels via
   `view.entry_kernels()`.
3. **Neither signal** → not surfaced; an `AmbiguousTextSection`
   diagnostic is emitted instead.

### Memory-space tagging

`MemoryRef.space: MemorySpace` was added to the core IR so GPU
operands carry their address space:

```
MemorySpace::Generic       // CPU default; PTX implicit-cast loads
MemorySpace::Global        // device DRAM
MemorySpace::Shared        // on-chip workgroup memory
MemorySpace::Local         // per-thread stack/spill
MemorySpace::Constant(u8)  // .nv.constantN bank N (0 = params)
MemorySpace::Param         // PTX .param (aliased to .const[0])
```

CPU decoders default to `Generic`; SASS decoders set the right space
when LD/ST decoding lands fully (M7 follow-up).

### `Instruction.guard`

Every `Instruction` now carries an optional `PredicateGuard { register,
negate }` so SASS `@P0` / `@!P3` round-trips through the IR. CPU
decoders emit `None`. `@PT` (the always-true alias) collapses to
`None` so it doesn't show in normal rendering.

## Testing

### Test corpus

`tests/corpus/cuda/sources/` contains 10 handwritten CUDA microkernels
under BSD-3-Clause:

| Kernel | What it exercises |
|--------|-------------------|
| `vector_add` | thread-index addressing, FP32 add |
| `scalar_mul` | load-modify-store, scalar broadcast |
| `memcpy_kernel` | global load/store pair |
| `reduction_warp` | `SHFL.DOWN`, warp-synchronous reduction |
| `shared_transpose` | `STS`/`LDS`, `__syncthreads`, bank-conflict pad |
| `predicate_set` | `VOTE.BALLOT`, predicate regs, `POPC` |
| `atomic_incr` | `ATOM.ADD` (global) |
| `constant_bias` | `LDC` (constant-bank load) |
| `loop_accumulator` | unrollable loop, register accumulator, `FFMA` |
| `branching` | divergent branches, `BSSY`/`BSYNC` convergence |

Each gets compiled against `sm_80`, `sm_86`, and `sm_89`, producing
30 cubins and 30 paired `nvdisasm -json` ground-truth files.

Build the corpus on a CUDA-equipped Linux box:

```bash
./scripts/build-cuda-corpus.sh   # CUDA 13.2 toolkit pinned
```

The corpus directory (`tests/corpus/cuda/build/`) is gitignored —
nothing is checked in. CI without CUDA stays green; tests that need
the corpus no-op silently with a `SKIP` line.

### Test layers

| Layer | What it covers | When it runs |
|-------|----------------|--------------|
| Unit tests (75+) | Per-module invariants — TLV framing, opcode table, register encoding, control-bit roundtrips, fatbin/PTX parsing | Every `cargo test` |
| Property-based tests (19 new) | Decoder/parser totality, determinism, bounds preservation, no-desync block walk | `cargo test --features cuda` |
| Fault-injection tests (13 new) | Truncation sweeps, bit-flip mutations, malformed TLV chaos, fatbin overflow attempts, PTX edge cases | Every `cargo test` |
| Differential harness | Per-kernel diff vs `nvdisasm -json` at three levels (base mnemonic, full mnemonic, predicate guard); writes JSON artefact | `cargo test --test differential_tests sass_corpus` |
| Corpus regressions | Real-cubin invariants — every kernel detected, every resource consistent, every EXIT 16-byte aligned | `cargo test --test cuda_corpus` |
| Fuzz targets (5 new) | `sass_decoder`, `cubin_view`, `nv_info_parser`, `ptx_parser`, `fatbin_parser` under `fuzz/fuzz_targets/` | `cargo +nightly fuzz run <name>` |

### Match-rate gates

The differential harness has CI floors that block regressions:

| Gate | Floor | Current |
|------|-------|---------|
| sm_80 base mnemonic | 70.0% | **100.0%** |
| every SM predicate guard | 95.0% | **100.0%** |
| every SM full mnemonic | 92.0% | **95.8%** |

Floors live in `crates/hexray-formats/.../sass_compare.rs::threshold`.
Lift them when raising the bar; lower them only with explicit
justification in the commit message.

## Extending the decoder

### Adding a new SASS opcode

Edit `crates/hexray-disasm/src/cuda/sass/opcode_table.rs`. The pattern:

```rust
OpcodeEntry {
    op_class: 0x_NEW,
    mnemonic: "BASE",
    default_suffix: ".ALWAYS_PRESENT", // or ""
    variant: Some(variant_decoder),    // or None
    operation: Operation::Other(0x_NEW),
}
```

Variant decoders are pure functions on a `SassWord`:

```rust
fn variant_my_op(word: &SassWord) -> &'static str {
    if word.bit(73) { ".SUFFIX_A" } else { ".SUFFIX_B" }
}
```

When you add an opcode, the differential harness will surface
mismatches if your decode is wrong. Run:

```bash
cargo test --test differential_tests sass_corpus_differential_gate -- --nocapture
```

to see the per-SM match-rate report before/after.

### Adding a new SM family

1. Add a variant to `SmFamily` in `hexray-core/src/arch.rs` and update
   `from_major_minor`.
2. If the family changes the `e_flags` ABI version, add a branch to
   `sm_from_cuda_elf` in `hexray-formats/src/elf/header.rs`.
3. Add `SassDisassembler::is_volta_or_newer` if the encoding still
   fits the 16-byte word layout; otherwise this is a separate
   decoder (Maxwell/Pascal use 8-byte encoding — not in scope for v1).

### Adding a new attribute decoder

`.nv.info` attributes (`EIATTR_*`) are decoded in
`hexray-formats/src/elf/cuda/schema.rs::KernelResourceUsage::from_nv_info`.
Most are simple HVAL/SVAL reads — add a match arm and a field on
`KernelResourceUsage`.

## Known gaps

- **Operand decoding is minimal.** M4 emits `Rd` from bits 16-23 and
  `Ra` from bits 24-31; full memory-ref / cbank-ref decoding is M7
  follow-up work.
- **No host-binary fatbin samples.** The fatbin parser is unit-tested
  end-to-end but hasn't been validated against a real `nvcc`-produced
  host binary with `__nv_fatbin`. Synthetic fixtures cover the format
  layout exhaustively; a future corpus rebuild with `-rdc=true` will
  add real samples.
- **Compressed fatbin entries** are flagged but the payload isn't
  decompressed yet (uses LZ4 in current ptxas).
- **PTX is parsed at the sidecar level only**, not as an AST. That's
  intentional — see `crates/hexray-formats/src/elf/cuda/ptx.rs` module
  docs.

## References

- NVIDIA CUDA Binary Utilities (cuobjdump / nvdisasm), pinned to CUDA 13.2.
- CuAssembler `CuAsm/CuNVInfo.py` for `.nv.info` attribute IDs.
- LLVM `llvm/include/llvm/BinaryFormat/ELF.h` for `EF_CUDA_*` constants.
- "Dissecting the NVIDIA Volta GPU Architecture via Microbenchmarking"
  (Jia et al., 2018) for control-bit field positions.
