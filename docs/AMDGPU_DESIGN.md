# AMDGPU Support — Design (M10)

This is the planning RFC for the v1.4.0 AMDGPU work. It covers the
binary-format recognition, the disassembler, the metadata layer, the
test strategy, and the cross-vendor `hexray cmp` subcommand that makes
the [scale-lang](https://scale-lang.com/) interop story real.

The shape of the work mirrors the v1.3.0 CUDA effort (M1–M9). Where a
decision in M10 has a direct analogue in M1–M9, we lean on what
already worked.

---

## Why now

Two motivations, in priority order:

1. **scale-lang interop.** SCALE is a clean-room nvcc replacement that
   accepts unmodified CUDA source and produces native binaries for
   *both* NVIDIA (cubin, `EM_CUDA = 190`) and AMD targets (AMDGPU code
   objects, `EM_AMDGPU = 224`). Without AMDGPU support in hexray, the
   only interop demo we can run is "nvcc cubin vs SCALE cubin" — same
   format, different compiler, useful as a sanity check but not the
   point of SCALE. The point is the cross-vendor case: same CUDA
   source, two completely different ISAs, hexray showing they
   implement the same kernel. That requires reading both sides.

2. **AMDGPU is independently interesting.** ROCm-targeted HIP code,
   raw `clang -target amdgcn-amd-amdhsa` output, MIOpen / rocBLAS
   kernels, `hipcc --genco` outputs — none of these are reachable
   today. AMDGPU is the second-largest GPU compute target in the
   world; supporting only NVIDIA gives an asymmetric tool.

## Scope

In:

- ELF recognition: `EM_AMDGPU = 224` machine type, `e_flags` decode
  for the GFX target (mach + xnack + sramecc), kernel-name extraction
  from the `.kd`/symbol pair convention.
- Code-object view: the 64-byte amdhsa kernel descriptor block
  parsed into typed fields (vgpr/sgpr/lds/scratch usage, kernarg
  size, COMPUTE_PGM_RSRC bitfields).
- AMDGPU metadata note: the `NT_AMDGPU_METADATA` (type 32) MessagePack
  blob giving kernel name, symbol, arg layout, register footprints.
  Decoded into the same `KernelResourceUsage` shape we use for CUDA
  so consumers can stay vendor-agnostic.
- Disassembler (feature `amdgpu`, opt-in like `cuda`): variable-length
  encoding walker covering GFX9 (Vega / CDNA1) and GFX10/11 (RDNA1/2/3).
  GCN/RDNA opcodes for the core classes (VOP1/2/3, SOP1/2, SMEM,
  MUBUF, DS, FLAT, EXP). Predicate awareness (EXEC mask),
  scalar-vector lane semantics, abs/neg/sext modifiers.
- `hexray cmp a b` cross-vendor comparator: kernel-signature equivalence,
  CFG-shape diff, register-pressure envelope, memory-region usage diff.
- Differential harness against `llvm-objdump --triple=amdgcn-amd-amdhsa`,
  same shape as the cuda-vs-nvdisasm harness.

Out (deferred to M11+ or later):

- HIP host code analysis (the host-side ELF wrapping a fatbin of
  AMDGPU code objects). M10 reads the AMDGPU object directly; HIP
  fatbin extraction is the cross-cutting follow-up.
- Compressed code objects (LZ4 / zstd in fatbin entries — flagged but
  not decompressed, mirroring CUDA M9).
- DPP / SDWA / VOP3P operand modifiers (decoded as opaque suffix in
  M10, full operand rendering deferred).
- CDNA-specific MFMA / WMMA matrix opcodes (acknowledged in opcode
  table, full decode deferred).

## Milestone breakdown

| Milestone | Deliverable | Test gate |
|---|---|---|
| **M10.1** | `Machine::Amdgpu`, `Architecture::Amdgpu(GfxArchitecture)`, `e_flags` decode | Unit tests on synthetic ELF headers across gfx900/906/908/90a/940/1010/1030/1100/1151 |
| **M10.2** | `CodeObjectView`, kernel descriptor decode, `NT_AMDGPU_METADATA` MessagePack parse | Round-trip a synthetic AMDGPU object through `cubin_view`-style API; metadata names match `.kd` symbols |
| **M10.3** | Disassembler skeleton: lockstep variable-length walker, single-mnemonic end-to-end (`s_endpgm` + `v_mov_b32`) | One real corpus kernel decodes without desync; `Send + Sync` witnesses |
| **M10.4** | Real opcode table: VOP1/2/3, SOP1/2, SMEM, MUBUF, DS, FLAT, EXP, plus a GFX9 vs GFX10+ family split | ≥ 70% base mnemonic match against `llvm-objdump` on the gfx906 corpus (M4-style floor) |
| **M10.5** | Differential harness + corpus pipeline | ≥ 90% base / ≥ 60% full mnemonic on gfx906/gfx1030; predicate-mask handling across kernels |
| **M10.6** | Quality bar: proptest, fuzz, Miri, mutation, coverage | Match the v1.3.0 CUDA bar — 100+ unit tests, 5 fuzz targets, Miri pass on fault-injection, ≥ 80% coverage on new files |
| **M10.7** | `docs/AMDGPU.md`, INSTRUCTIONS.md AMDGPU section, CHANGELOG Highlights | Docs review only |
| **M11** | `hexray cmp` subcommand | End-to-end demo: same CUDA source, nvcc-cubin and SCALE-amdgpu, hexray cmp shows kernel equivalence |

Each milestone is its own commit (or commit pair: `M10.X feat` +
`M10.X tests`); the M-series lives on `feature/amdgpu-support` and
merges to main as the v1.4.0 cut, mirroring v1.3.0.

## Architecture

### Crate-level placement

```
hexray-core            Architecture::Amdgpu(GfxArchitecture)
                       GfxFamily { Gfx9, Gfx10, Gfx11, Gfx12 }
                       (existing PredicateGuard / MemorySpace reused)

hexray-formats/elf/    Machine::Amdgpu, e_flags decode (header.rs)
hexray-formats/elf/amdgpu/   CodeObjectView, KernelDescriptor,
                             AmdMetadata (MessagePack), helpers

hexray-disasm/amdgpu/  AmdgpuDisassembler (feature `amdgpu`)
                       encoding.rs   — instruction-class dispatch
                       opcode_table.rs — per-class tables
                       operands.rs   — VGPR/SGPR/SRC/IMM/literal
                       gfx9.rs / gfx10.rs — family-specific tables
```

No new crate. The split mirrors `hexray-formats/elf/cuda/` and
`hexray-disasm/cuda/sass/`.

### `GfxArchitecture` shape

```rust
pub struct GfxArchitecture {
    pub family: GfxFamily,    // Gfx9 / Gfx10 / Gfx11 / Gfx12
    pub major: u8,            // 9, 10, 11, 12
    pub minor: u8,            // 0, 1, 3, ...
    pub stepping: u8,         // 0, 6, 8, 'a', ...
    pub xnack: TriState,      // Any / Off / On
    pub sramecc: TriState,
}
```

Renders as `gfx906`, `gfx1030`, `gfx1100`, `gfx90a:xnack+`, etc.,
matching `llvm-objdump`'s target-id format.

### `CodeObjectView` shape

```rust
pub struct CodeObjectView<'a> {
    pub elf: &'a Elf<'a>,
    pub kernels: Vec<Kernel<'a>>,
    pub metadata: Option<AmdMetadata<'a>>,
    pub diagnostics: Vec<Diagnostic>,
}

pub struct Kernel<'a> {
    pub name: &'a str,
    pub symbol_addr: u64,        // .text symbol (entry)
    pub kd_addr: u64,            // .kd symbol (descriptor)
    pub descriptor: KernelDescriptor,
    pub resource_usage: KernelResourceUsage,  // shared vocab w/ CUDA
}
```

The 64-byte descriptor lives as `.text`-section bytes pointed at by
the `<kernel>.kd` symbol. `KernelResourceUsage` is reused from
hexray-formats so any vendor-agnostic consumer (the cmp subcommand,
future CFG-builder integrations) sees a uniform shape.

### Disassembler dispatch

AMDGPU instructions are 32-bit or 64-bit on the wire, distinguished
by a few high bits of the first dword. The decoder reads one dword,
pattern-matches the encoding class on its high bits, then either
consumes a second dword (VOP3, SMEM, MUBUF, etc.) or emits the
single-dword instruction (VOP1, SOP1, etc.).

Rough class dispatch (GFX9; GFX10+ adjusted in `gfx10.rs`):

```
0b1011_1110 ........        SOP1
0b1011_1111 ........        SOPK / SOPP   (further bit at [22..23])
0b1000 .... ........        SOPK
0b101 _ .... ........        SOP2 / SOPC
0b0111 1110 ........        VOP1
0b0 .........               VOP2
0b1101_0 ...                VOP3 (64-bit)
0b1100_0 ...                SMEM (64-bit)
0b1110_0 ...                MUBUF (64-bit)
0b1101_1 ...                DS (64-bit)
0b1101_11_..                FLAT / GLOBAL / SCRATCH (64-bit)
```

Like SASS, we walk the buffer in lockstep: read dword, classify,
advance by 32 or 64 bits. A bad classification doesn't desync —
a single instruction may be marked unknown; the walker still finds
the next valid 32-bit boundary on the next iteration.

### EXEC mask + predicate semantics

AMDGPU's per-instruction predicate is an *implicit* mask
(`EXEC[63:0]`), not a per-instruction guard like SASS's `@P0`. We
reuse `Instruction.guard: Option<PredicateGuard>` only when an
instruction takes an explicit `vcc`/`sgpr_pair` mask (e.g.
`v_cndmask_b32_e64`), and otherwise leave guard as `None`. Lane-mask
semantics show up in the resource-usage summary and in the cmp
report (kernel uses divergent control flow vs straight-line).

## Test strategy

Three layers, mirroring v1.3.0:

1. **Synthetic fixtures.** Hand-crafted bytes for ELF headers, kernel
   descriptors, and individual instruction encodings. No external
   tooling needed; tests stay green on CI without ROCm.

2. **Built corpus** (Linux + ROCm box). `scripts/build-amdgpu-corpus.sh`
   compiles ten microkernels via `clang -target
   amdgcn-amd-amdhsa --offload-arch=gfx906` (and similar for
   gfx1030, gfx1100). Drops `.co`/`.o` files into
   `tests/corpus/amdgpu/build/<gfx>/`. Build artefacts gitignored —
   CI without ROCm no-ops the corpus tests, same as the CUDA path.

3. **Differential gate** (`crates/hexray/tests/amdgpu_diff_match.rs`).
   For every corpus kernel, compares hexray's mnemonic output against
   `llvm-objdump --triple=amdgcn-amd-amdhsa
   --disassemble --mcpu=gfx906`. Tracks base-mnemonic /
   full-mnemonic / operand-count match rates. Floors:

   ```
   gfx906   base ≥ 90%   full ≥ 60%
   gfx1030  base ≥ 80%   full ≥ 50%   (RDNA-specific opcodes lag)
   gfx1100  base ≥ 70%   full ≥ 40%   (RDNA3 newer)
   ```

   Floors lift over time as we add opcodes; gates sit below the
   actual numbers so they catch regressions without being targets.

## Cross-vendor comparator (M11)

The point of the whole milestone series. New CLI subcommand:

```bash
hexray cmp nvcc.cubin scale.cubin           # NVIDIA-vs-NVIDIA
hexray cmp nvcc.cubin scale_amd.co          # NVIDIA-vs-AMD (the demo)
hexray cmp scale_amd.co rocm_native.co      # AMD-vs-AMD
```

Output: tabular kernel-by-kernel diff. For each matching kernel name:

```
Kernel: vector_add
                       a (sm_80)       b (gfx1030)     status
parameters             4 × {4,8,8,8}   4 × {4,8,8,8}   ✓
basic blocks           12              14              differ
exits                  2               2               ✓
register pressure      ≤24 R           ≤32 V, ≤16 S    differ
shared / LDS           0 B             0 B             ✓
constant cbank         c[0] 28 B       —               differ
```

`✓` = match. `differ` = same shape, different codegen detail
(informational). `MISMATCH` = a structural inconsistency (different
arg count, different exit count, etc.) that suggests a real
vendor-side bug. `differ` lines never fail the cmp; `MISMATCH`
lines exit non-zero, suitable for CI.

The comparator itself is small once the underlying parsers are in
place — it just queries `KernelResourceUsage` and the (vendor-agnostic)
CFG builder for both sides.

## Practical limitations / open questions

- **No local AMD hardware.** Development will use synthetic fixtures
  + `llvm-objdump` outputs captured from a ROCm-equipped box. The
  disassembler doesn't need GPU hardware to decode bytes; the corpus
  build does (or a Linux container with a HIP/clang AMDGPU
  toolchain). I'll set up a build script that runs in a `rocm/dev`
  container so the corpus is reproducible.
- **GFX9 vs GFX10/11/12 split.** RDNA1 (gfx10) changed several
  encoding details (VOPC encoding, dual-issue VOPD on GFX11). The
  family enum + per-family opcode tables let us share the bulk and
  override where needed.
- **CDNA opcodes.** Matrix instructions (MFMA, WMMA, SMFMAC) are
  high-impact for AI workloads but encoding-heavy and seldom in the
  corpus we're likely to assemble first. They're flagged as opaque
  in M10 and lifted in a follow-up.
- **Fatbin / HIP host extraction.** A HIP host binary embeds a
  fatbin-style wrapper containing AMDGPU code objects. We don't
  extract it in M10. The cmp subcommand operates on the AMDGPU
  object directly; HIP host extraction is M11+.

## Versioning

This work targets **v1.4.0**. The CHANGELOG cut follows the v1.3.0
shape: a Highlights block at the top of the Unreleased section, then
M10-by-M10 detail underneath, then the M11 cmp section.

If M10 lands but M11 slips, M10 alone is still a release-worthy
milestone (AMDGPU disasm support is independently valuable). Plan B:
ship M10 as v1.4.0 and M11 as v1.4.1.
