# Performance Tuning Guide

This guide complements `docs/PERFORMANCE.md` with practical tuning steps.

## Goals

- Keep developer feedback loops fast.
- Preserve deterministic benchmark comparisons.
- Avoid noisy regressions from environment drift.

## 1) Choose the right CI tier

- `scripts/ci-local --tier fast`: formatting, compile, lint, targeted checks.
- `scripts/ci-local --tier medium`: pre-push default, includes decompiler quality smoke.
- `scripts/ci-local --tier full`: release-candidate confidence.

## 2) Rust parallelism knobs

For faster local builds/tests on capable machines:

```bash
export CARGO_BUILD_JOBS=$(sysctl -n hw.ncpu)
export RUSTFLAGS="-Ccodegen-units=16"
```

For stable benchmark runs, reduce variability:

```bash
export CARGO_BUILD_JOBS=1
export RUSTFLAGS="-Ccodegen-units=1"
```

## 3) Deterministic benchmark procedure

```bash
scripts/bench-deterministic --save-baseline
scripts/bench-deterministic --compare
```

Recommended procedure:
- Close heavy background workloads.
- Keep thermal/power conditions consistent.
- Run at least 3 comparisons for borderline regressions.

## 4) What to run by change type

- Decoder/decompiler logic change: `medium`, then deterministic benchmark compare.
- Docs/tests-only change: `fast` is usually enough.
- Performance-focused change: `full --perf` plus benchmark baseline update.

## 5) Troubleshooting slow runs

- Verify Docker-backed hooks are using warm images/layers.
- Check whether `--cross` or `--perf` was unintentionally enabled.
- Ensure debug assertions or sanitizer flags are not globally forced.
- For iterative dev, disable expensive optional steps and re-enable before push.
