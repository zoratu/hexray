# CUDA / NVIDIA GPU Support

hexray reads NVIDIA CUBINs and disassembles SASS instructions for
Volta and newer.

## Quick start

```bash
nvcc --cubin -arch=sm_80 my_kernel.cu -o my_kernel.cubin
hexray my_kernel.cubin info
```

```
Architecture:  cuda-sass (sm_80, family=Ampere)
CUDA CUBIN View
---------------
Kernels:       1 (1 entry, 0 candidate)
  [entry] vector_add  size=512  section=#18 (+nv_info)
      regs=255  params@c[0][0x160] size=28  exits=2
      args=[#3:4B,#2:8B,#1:8B,#0:8B]
```

Disassemble a single kernel by name with `-s`:

```bash
hexray -s vector_add my_kernel.cubin
```

```
<.text.vector_add>:
0x00000d00:  02 7a 01 00 …  MOV R1
0x00000d10:  19 79 06 00 …  S2R R6
0x00000d20:  19 79 03 00 …  S2R R3
0x00000d30:  24 7a 06 06 …  IMAD R6, R6
0x00000d40:  0c 7a 00 06 …  ISETP.GE.AND R0, R6
0x00000d50:  4d 09 00 00 …  EXIT
```

## Supported targets

| Family    | Compute capability | Status        |
|-----------|--------------------|---------------|
| Ampere    | sm_80 / sm_86 / sm_87 | Tested in corpus |
| Ada       | sm_89              | Tested in corpus |
| Volta / Turing / Hopper / Blackwell | sm_70..sm_12x | Decoder runs; corpus coverage limited |
| Maxwell / Pascal | sm_5x / sm_6x | Rejected: 8-byte encoding not supported |

Match rates on the handwritten corpus (sm_80/86/89, ptxas 13.2):

| | base mnemonic | full mnemonic | predicate guard |
|---|:---:|:---:|:---:|
| Each SM (10 kernels, 448 instructions) | 100.0% | 95.8% | 100.0% |

CI gates lock these at 70% / 92% / 95% respectively.

## What's decoded

- **CUBIN view**: kernel detection (`STO_CUDA_ENTRY`), `.nv.constantN`,
  `.nv.shared`, `.nv.local` memory regions
- **`.nv.info`**: typed payloads — register count, frame size, param
  layout, EXIT offsets, launch bounds (`__launch_bounds__`)
- **SASS**: 34 opcode classes (NOP, MOV, S2R, IADD3, IMAD, ISETP,
  LDG/STG, BRA, EXIT, FFMA, ULDC, …) with variant-suffix decoding
  (`ISETP.GE.AND`, `IMAD.WIDE`, `LDG.E.CONSTANT`, …) and predicate
  guards (`@P0` / `@!P3`)
- **PTX sidecar**: `.version` / `.target` / `.address_size` plus an
  index of every `.entry` / `.func` directive (sidecar only — no AST)
- **Fatbin**: wrapper extraction (`magic 0xBA55_ED50`) into per-SM
  cubin / PTX entries

## Architecture

```
hexray-core            arch.rs       Architecture::Cuda(...)
                       instruction.rs PredicateGuard
                       operand.rs    MemorySpace

hexray-formats/elf/cuda/  CubinView, NvInfoBlob, KernelResourceUsage,
                          PtxIndex
hexray-formats/cuda/      FatbinWrapper

hexray-disasm/cuda/sass/  SassDisassembler (feature `cuda`)
```

Public CLI surface: `hexray <cubin> info`, `hexray <cubin> sections`,
`hexray <cubin> symbols`, `hexray -s <kernel> <cubin>`.

## Test corpus

`tests/corpus/cuda/sources/` ships 10 BSD-3 microkernels.
`scripts/build-cuda-corpus.sh` compiles them on a Linux box with the
CUDA 13.2 component packages (`cuda-nvcc-13-2`, `cuda-nvdisasm-13-2`,
`cuda-cuobjdump-13-2`). The build artefacts are gitignored — CI
without CUDA stays green; corpus-dependent tests no-op silently.

## Known gaps

- Operand decoding emits `Rd` and `Ra` only; full memory-ref / cbank-ref
  rendering is follow-up work.
- Fatbin parser is unit-tested against synthetic fixtures but not yet
  validated against an `nvcc -rdc=true` host binary.
- Compressed fatbin entries (LZ4) are flagged but not decompressed.
- PTX is parsed at the sidecar level only, no AST.
