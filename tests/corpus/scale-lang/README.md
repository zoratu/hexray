# scale-lang interop fixtures

This directory holds the artefacts of the v1.3.2 scale-lang interop
demo: a single `vector_add.cu` source compiled by SCALE into both an
NVIDIA cubin and an AMDGPU code object, plus the captured
`hexray cmp` output that proves the two binaries describe the same
kernel.

## Files

- `vector_add.cu` — source kernel.
- `vector_add.sm_80.cubin` — SCALE → NVIDIA cubin (`-arch=sm_80`).
- `vector_add.gfx906.co` — SCALE → AMDGPU code object (`-arch=gfx906`).
- `cmp.txt` — captured output of
  `hexray vector_add.sm_80.cubin cmp vector_add.gfx906.co`.

## Reproducing

The fixtures here are committed bytes-for-bytes; the integration test
just feeds them to `hexray cmp` and snapshots the output. To
regenerate from source on a Linux box with SCALE installed:

```bash
scale --cubin -arch=sm_80 vector_add.cu -o vector_add.sm_80.cubin
scale --hsaco -arch=gfx906 vector_add.cu -o vector_add.gfx906.co
hexray vector_add.sm_80.cubin cmp vector_add.gfx906.co > cmp.txt
```

The exact SCALE version used to generate the committed fixtures is
recorded in the test that consumes them
(`crates/hexray/tests/scale_lang_cmp.rs`).
