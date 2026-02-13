# Performance and Determinism Guide

This guide defines a repeatable workflow for fast local iteration and stable benchmark comparisons.

## Goals

- Keep normal development fast.
- Keep benchmark runs comparable over time.
- Avoid false regressions caused by machine variance.

## Parallelism Knobs

Rust and Cargo already parallelize heavily. Use explicit knobs when you need control:

```bash
# Build/test parallelism (default is logical CPU count)
export CARGO_BUILD_JOBS=8

# Test runner thread count (set to 1 for deterministic ordering/debugging)
export RUST_TEST_THREADS=1
```

Recommended defaults:

- Day-to-day local development: leave defaults or set `CARGO_BUILD_JOBS` to physical cores.
- Deterministic troubleshooting: set `RUST_TEST_THREADS=1`.

## Stable Benchmark Procedure

Use the same machine profile, command line, and baseline naming for all comparisons.

```bash
# 1) Warm caches and ensure code is formatted/compiles
scripts/ci-local --tier fast

# 2) Capture baseline on the mainline commit
cargo bench --workspace -- --save-baseline main

# 3) Run your branch benchmark with identical options
cargo bench --workspace -- --save-baseline change

# 4) Compare (install once: cargo install critcmp)
critcmp main change
```

For lower noise:

- Close heavy background workloads.
- Keep power mode consistent (avoid switching between battery and plugged-in runs).
- Re-run suspect benchmarks at least twice before calling a regression.

## Tiered Workflow Mapping

Use the tier that matches the decision you are making:

- `scripts/ci-local --tier fast`: pre-commit speed checks.
- `scripts/ci-local --tier medium`: pre-push confidence checks.
- `scripts/ci-local --tier full`: release-grade local validation.

This keeps routine commits lightweight while preserving a consistent full-check path.
