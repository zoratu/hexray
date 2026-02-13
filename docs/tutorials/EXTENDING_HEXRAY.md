# Extending hexray

This tutorial outlines the lowest-friction path for adding a new analysis/decompiler pass.

## 1) Choose insertion point

Common extension points in `crates/hexray-analysis/src/decompiler/`:
- expression simplification
- control-flow structuring
- post-structure optimization pass
- emission-time naming/type hints

## 2) Implement pass logic

- Keep transform deterministic.
- Prefer pure transforms over global mutable state.
- Add clear guardrails for architecture-specific behavior.

## 3) Wire pass into configuration

Expose the pass via `DecompilerConfig`/`OptimizationPass` so callers can enable, disable, and benchmark it.

## 4) Add tests at three layers

- Unit tests near pass implementation.
- Decompiler regression tests for behavior.
- Benchmark quality checks if pass affects switch/goto/structure metrics.

## 5) Keep CI tiers fast

Run during development:

```bash
scripts/ci-local --tier fast
```

Before push:

```bash
scripts/ci-local --tier medium --no-cross --no-perf
scripts/quality-smoke
```

Use full tier and perf gate only for milestone/performance changes.

## 6) Update docs and roadmap

Whenever adding a new pass:
- document it in `docs/DECOMPILER.md`
- add examples if API surface changed
- update roadmap status if a planned item is now complete
