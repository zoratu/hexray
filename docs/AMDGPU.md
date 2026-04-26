# AMDGPU / AMD GPU Support

hexray reads AMDGPU code objects (the ELF format produced by `clang
-target=amdgcn-amd-amdhsa`, `hipcc --genco`, and tools like SCALE)
and disassembles GCN / CDNA / RDNA instructions.

## Quick start

```bash
clang -target=amdgcn-amd-amdhsa --offload-arch=gfx906 -c kernel.cu -o kernel.co
hexray kernel.co info
```

```
Architecture:  amdgpu (gfx906:xnack+:sramecc-, family=Gcn5)
AMDGPU Code Object View
-----------------------
Target:        gfx906:xnack+:sramecc-
Kernels:       1
  vector_add
    entry=0x40  kd=0x48  wave64  vgprs=12  sgprs=16
    kernarg=24B  lds=768B  scratch=0B  user_sgprs=0
```

Disassemble a kernel by name with `-s`:

```bash
hexray -s vector_add kernel.co
```

```
<vector_add>:
0x00000040:  01 03 00 7e   v_mov_b32_e32
0x00000044:  00 00 81 bf   s_endpgm
```

## Supported targets

| Family    | Examples            | Status                              |
|-----------|---------------------|-------------------------------------|
| GCN5 / Vega | gfx900, gfx902, gfx906, gfx90c | ELF + descriptor + decoder skeleton |
| CDNA1/2/3   | gfx908, gfx90a, gfx940, gfx942 | ELF + descriptor; MFMA opcodes deferred |
| RDNA1/2     | gfx1010, gfx1030, gfx1031 | ELF + descriptor + decoder skeleton |
| RDNA3/4     | gfx1100, gfx1150, gfx1200 | ELF + descriptor + decoder skeleton |
| GCN3/4      | gfx803, gfx810      | ELF recognition only                |

## What's decoded

- **ELF recognition**: `EM_AMDGPU = 224`, V3 + V4 ABI layouts of
  `e_flags`, `xnack` and `sramecc` TriState. Renders the canonical
  LLVM target id (`gfx90a:xnack+:sramecc-`).
- **Code-object view**: walks the symbol table for `<kernel>.kd`
  STT_OBJECT entries and pairs them with their `<kernel>` STT_FUNC
  entries. Surfaces orphan descriptors / orphan entries as soft
  diagnostics.
- **Kernel descriptor**: parses the 64-byte `amdhsa_kernel_descriptor_t`
  block (per LLVM `AMDHSAKernelDescriptor.h`) into typed fields:
  `vgpr_count` (with wave32 granule split), `sgpr_count`,
  `user_sgpr_count`, `lds_bytes` (static + dynamic),
  `scratch_bytes`, `kernarg_size`, `is_wave32`. Both decoded fields
  and raw `compute_pgm_rsrc1/2/3` words are exposed.
- **Disassembler**: variable-length 32/64-bit walker covering
  VOP1/VOP2/VOPC, VOP3A/B, SOP1/SOP2/SOPC/SOPK/SOPP, SMEM, MUBUF,
  MTBUF, MIMG, DS, FLAT, EXP encoding classes. Family-aware: GFX9
  (Vega/CDNA) and GFX10+ (RDNA1+) prefix layouts both supported.
  First-pass opcode tables for the most common opcodes per class
  (`v_mov_b32`, `v_add_*`, `v_cmp_*`, `s_mov_b32`, `s_add_u32`,
  `s_endpgm`, `s_branch`, `s_load_dword*`, …).

## Architecture

```
hexray-core              arch.rs              Architecture::Amdgpu(GfxArchitecture)
                                              GfxFamily, TriState

hexray-formats/elf/      header.rs            Machine::Amdgpu, gfx_from_amdgpu_elf
hexray-formats/elf/amdgpu/  CodeObjectView, KernelDescriptor,
                            AmdKernelResourceUsage

hexray-disasm/amdgpu/    AmdgpuDisassembler (feature `amdgpu`)
                         encoding.rs   — class dispatch (GFX9 vs GFX10+)
                         opcode_table.rs — per-family opcode tables
                         registers.rs  — operand id naming
```

CLI surface: `hexray info <code-object>`, `hexray <code-object>
sections`, `hexray <code-object> symbols`, `hexray -s <kernel>
<code-object>`.

## scale-lang interop

[SCALE](https://scale-lang.com/) is a clean-room nvcc replacement
that compiles unmodified CUDA source to either NVIDIA cubins
(`-arch=sm_XX`) or AMDGPU code objects (`-arch=gfxNNN`). hexray reads
both formats — the NVIDIA path through `Elf::cubin_view()` (v1.3.0),
the AMD path through `Elf::code_object_view()` (this milestone).

The point of the AMDGPU support is to make cross-vendor equivalence
demoable: same CUDA source, two different ISAs, one tool that shows
the kernel signatures match. The `hexray cmp` subcommand (M11) is
the user-facing entry point; this milestone is the parser /
disassembler infrastructure underneath it.

## Known gaps

- Operand decoding for the disassembler is class-dispatch + mnemonic
  only; SRC0 / VDST register-name rendering is follow-up work.
- The opcode tables ship the dozen-ish OPs per class that show up
  in every realistic kernel. Filling in the tail (CDNA MFMA / WMMA
  matrix instructions, VOP3P packed math, DPP / SDWA modifiers) is
  driven by the differential gate against `llvm-objdump` once a
  ROCm-built corpus exists.
- `NT_AMDGPU_METADATA` MessagePack notes (kernel arg layout, max
  workgroup size) are not decoded yet — the descriptor block is the
  only metadata source. The arg layout sidecar is a follow-up that
  doesn't change anything user-visible for the cmp use case.
- HIP host binaries embed AMDGPU code objects in a fatbin-style
  wrapper. `hexray` reads the AMDGPU object directly today; HIP
  fatbin extraction is M11+ work.
