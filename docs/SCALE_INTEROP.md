# scale-lang Interop Walkthrough

[SCALE](https://scale-lang.com/) (Spectral Compute) is a clean-room
nvcc replacement that compiles unmodified CUDA source to AMDGPU
code objects. With v1.3.0 (CUDA reading), v1.3.1 (AMDGPU reading),
and v1.3.2 (operand decoding + the `cmp` subcommand), `hexray`
parses both vendor formats and can compare kernel signatures across
them.

This walkthrough uses a real `vector_add.cu` source compiled by
SCALE 1.4.2 (`scale-free` package) for two different AMD targets.
The produced binaries live in `tests/corpus/scale-lang/` and drive
the integration test `crates/hexray/tests/scale_lang_cmp.rs`.

## Compile the same source for two AMD targets

```cuda
// vector_add.cu
extern "C" __global__ void vector_add(const float* a,
                                      const float* b,
                                      float* c,
                                      int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) {
        c[i] = a[i] + b[i];
    }
}
```

```bash
# RDNA2 (Navi 21) target — gfx1030.
/opt/scale/targets/gfx1030/bin/nvcc --cuda-device-only -O2 \
    -c vector_add.cu -o vector_add.gfx1030.co

# RDNA3 (Navi 31) target — gfx1100.
/opt/scale/targets/gfx1100/bin/nvcc --cuda-device-only -O2 \
    -c vector_add.cu -o vector_add.gfx1100.co
```

Both outputs are ELF code objects with `EM_AMDGPU = 224` but target
different RDNA generations. They share the same kernel signature but
diverge at the instruction-stream level.

## Inspect each side individually

```bash
hexray vector_add.gfx1030.co info
```

```
Architecture:  amdgpu (gfx1030, family=Rdna2)
AMDGPU Code Object View
-----------------------
Target:        gfx1030
Kernels:       1
  vector_add
    entry=0x100  kd=0x2c0  wave32  vgprs=8  sgprs=16
    kernarg=88B  lds=0B  scratch=0B  user_sgprs=6
```

The kernarg total comes out to 88B because SCALE preserves the
`extern "C" __global__` ABI, packing the four user args plus the
hidden args (block-dim, grid-dim) the AMDGPU runtime expects.

```bash
hexray -s vector_add vector_add.gfx1030.co
```

```
<vector_add$local>:
0x00000100:  02 00 a1 bf              sopp.op0x21
0x00000104:  02 00 00 f4 38 00 00 fa  s_load_dword
...
0x00000120:  00 06 00 81              s_add_i32 s0, s0, s6
0x00000124:  00 7d 76 d5 00 02 00 04  vop3
0x0000012c:  7e 03 80 be              sop1.op0x3 s0, exec_lo
...
0x00000138:  19 00 88 bf              s_cbranch_execz 0x1a0
...
0x000001a0:  00 00 81 bf              s_endpgm
```

Real disasm with operand decoding: `s_add_i32 s0, s0, s6` shows the
SDST + SSRC0 + SSRC1 fields decoded; `s_cbranch_execz 0x1a0` shows
the SOPP branch target rendered PC-relative; `s_endpgm` terminates
the kernel. Opcodes the v1.3.2 first-pass tables don't yet recognise
fall through as `<class>.op0xNN` (e.g. `vop3` for V_FMAC), but the
walker stays in lockstep — every dword advances the right amount.

## Cross-target cmp

The committed fixtures power the integration test that drives
`hexray cmp` against the two AMD targets. Captured output (also at
`tests/corpus/scale-lang/cmp.txt`):

```
hexray cmp
==========
a: amdgpu (gfx1030, family=Rdna2)
b: amdgpu (gfx1100, family=Rdna3)

Kernel: vector_add
  primary regs    a=8            b=8            ✓
  scalar regs     a=16           b=24           differ
  kernarg/param   a=88B          b=88B          ✓
  shared/LDS     a=0B            b=0B           ✓
  exit count      a=—            b=—            ✓

Matched 1 kernel(s).
```

What the report tells you:

- **Structural fields agree.** The two binaries describe a kernel
  with the same kernarg total (88B), same VGPR pressure (8 each),
  and matching LDS/shared usage. SCALE's two RDNA codegen paths
  produce the same user-visible signature.
- **SGPR drift is informational.** RDNA3 reserves more scalar
  registers for the implicit kernarg pointer / queue ptr setup
  than RDNA2; that's expected codegen drift between the
  generations, not a real signature break. The comparator marks
  it `differ` rather than `MISMATCH` so it doesn't fail CI.

If a SCALE update accidentally changed the kernarg layout on one
target but not the other, `kernarg/param` would flip to
`MISMATCH` and `hexray cmp` would exit non-zero — exactly the kind
of regression you want CI to catch.

## Cross-vendor cmp (NVIDIA + AMD)

`scale-free` only ships the AMD compiler; the full `scale` package
(commercial) ships the NVIDIA target alongside the AMD one and
produces real cubins for `-arch=sm_80`. The cross-vendor flow with
both targets installed:

```bash
scale --cubin -arch=sm_80 vector_add.cu -o vector_add.sm_80.cubin
hexray vector_add.sm_80.cubin cmp vector_add.gfx1030.co
```

The expected output mirrors the same-vendor cmp above except the
architecture lines say `cuda-sass (sm_80, family=Ampere)` vs
`amdgpu (gfx1030, family=Rdna2)`. Argument-by-argument breakdown
(`arg count`, `arg [0] size`, …) appears when both binaries carry
the per-arg metadata — the CUDA side via the `.nv.info`
`KPARAM_INFO` records (always present in cubins from `ptxas`) and
the AMDGPU side via the `NT_AMDGPU_METADATA` MessagePack note (which
clang's amdgcn target and `hipcc` emit; SCALE-free emits a
SCALE-specific `.AMDGPU.kinfo` section instead, so the arg-by-arg
rows render only when both binaries use the standard format).

## What this proves

The whole point of SCALE is "same CUDA source, two ISAs." Before
v1.3.2 you could only validate this informally by running both
binaries and checking that they computed the same outputs. With
`hexray cmp` you can now do *static* signature equivalence on the
binaries themselves — no runtime, no GPU, no test data — and have
that check fail loudly when the signatures drift.

The same machinery works for SCALE-vs-nvcc (both produce cubins,
should agree on signature) and for SCALE-vs-clang-amdgpu (the AMD
path against any AMDGPU-targeting compiler).

## Reproducing

The committed fixtures under `tests/corpus/scale-lang/` are the
exact binaries SCALE produced when `vector_add.cu` was last
regenerated. The integration test
`crates/hexray/tests/scale_lang_cmp.rs` runs `hexray cmp` against
them on every workspace test.

To regenerate (Linux + SCALE required):

```bash
sudo apt-get install scale-free                       # or `scale` (paid)
cd tests/corpus/scale-lang
/opt/scale/targets/gfx1030/bin/nvcc --cuda-device-only -O2 \
    -c vector_add.cu -o vector_add.gfx1030.co
/opt/scale/targets/gfx1100/bin/nvcc --cuda-device-only -O2 \
    -c vector_add.cu -o vector_add.gfx1100.co
hexray vector_add.gfx1030.co cmp vector_add.gfx1100.co > cmp.txt
```

The committed bytes were produced by SCALE 1.4.2 (`scale-free`
1.4.2-1noble1) on Ubuntu 25.10 (which the noble package installs on
cleanly even though it's tagged for 24.04).
