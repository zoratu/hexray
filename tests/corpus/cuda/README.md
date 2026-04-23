# CUDA microkernel corpus

A compact set of handwritten CUDA microkernels used as decode-coverage targets
for hexray's GPU support work (M2/M3 differential testing against
`nvdisasm -json` ground truth).

## What's here

- `sources/*.cu` - 10 small handwritten kernels, each under 40 lines. Every
  kernel is annotated with the SASS features it is meant to exercise.
- `Makefile` - builds each source against `sm_80`, `sm_86`, `sm_89` with
  `nvcc --cubin`, then runs `nvdisasm -json` to produce ground-truth SASS.
- `.gitignore` - excludes `build/`, `*.cubin`, `*.ptx`, `*.sass.json`. Only
  the sources + scaffolding are checked in; artifacts are regenerated per box.

Current kernels:

| Kernel              | SASS features exercised                          |
|---------------------|--------------------------------------------------|
| `vector_add`        | thread-index addressing, FP32 add                |
| `scalar_mul`        | load-modify-store, scalar broadcast              |
| `memcpy_kernel`     | straight global load/store pair                  |
| `reduction_warp`    | `SHFL.DOWN`, warp-synchronous reduction          |
| `shared_transpose`  | `STS`/`LDS`, `__syncthreads`, bank-conflict pad  |
| `predicate_set`     | `VOTE.BALLOT`, predicate regs, `POPC`            |
| `atomic_incr`       | `ATOM.ADD` (global)                              |
| `constant_bias`     | `LDC` (constant-bank load)                       |
| `loop_accumulator`  | unrollable loop, register accumulator, `FFMA`    |
| `branching`         | divergent branches, `BSSY`/`BSYNC` convergence   |

> TODO(sm_90a): Hopper target is not yet wired; add once decode paths land.

## License

All sources here are BSD-3-Clause, written fresh by this project. **Nothing is
copied from `cuda-samples` or any other NVIDIA distribution.** The BSD-3 header
is intentional so the corpus can be reused and redistributed alongside the rest
of the project without dragging in an incompatible sample-code license.

## Reproducibility: pin the toolkit

Ground truth is pinned to **CUDA Toolkit 13.2**. Outputs from other toolkit
versions will differ (nvdisasm formatting + instruction encoding can change
between minor releases) and must not be used for differential-testing gates.

## Setting up CUDA 13.2 on Ubuntu 22.04 / 24.04

The cloud box does not need a GPU - we only compile and disassemble. Install
the **component packages only**, not the `cuda-toolkit` meta (which pulls in
driver + runtime bloat we don't need).

### x86_64

```bash
# Pick the distro line that matches the box:
DISTRO=ubuntu2204   # or ubuntu2404

wget https://developer.download.nvidia.com/compute/cuda/repos/${DISTRO}/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install -y \
    cuda-nvcc-13-2 \
    cuda-nvdisasm-13-2 \
    cuda-cuobjdump-13-2

export PATH=/usr/local/cuda-13.2/bin:$PATH
nvcc --version   # expect: release 13.2
```

### aarch64 (sbsa, e.g. Grace / Graviton)

```bash
DISTRO=ubuntu2204   # or ubuntu2404

wget https://developer.download.nvidia.com/compute/cuda/repos/${DISTRO}/sbsa/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
sudo apt-get update
sudo apt-get install -y \
    cuda-nvcc-13-2 \
    cuda-nvdisasm-13-2 \
    cuda-cuobjdump-13-2

export PATH=/usr/local/cuda-13.2/bin:$PATH
```

## Building the corpus

```bash
cd tests/corpus/cuda
make all        # compile + disassemble everything
make check      # verify each (kernel, sm) pair produced non-empty artifacts
make clean      # wipe build/
```

Default SM set is `80 86 89`. Override with:

```bash
make SM_ARCHS="80 86" all
```

## Regenerating ground truth end-to-end

Use the top-level wrapper, which pins the toolkit version and runs a
determinism check (two builds, diffed):

```bash
./scripts/build-cuda-corpus.sh
```
