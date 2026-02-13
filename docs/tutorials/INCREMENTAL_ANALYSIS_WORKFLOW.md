# Incremental Analysis Workflow

This tutorial shows a patch-driven workflow for fast, repeatable re-analysis.

## 1) Capture baseline artifacts

```bash
./target/release/hexray ./original.bin symbols --functions > baseline.functions.txt
./target/release/hexray ./original.bin callgraph --format json > baseline.callgraph.json
```

## 2) Produce patched binary and diff it

```bash
./target/release/hexray diff ./original.bin ./patched.bin --json > diff.json
```

Use this diff as the source of changed byte ranges.

## 3) Run incremental analyzer (API)

Core flow:
- Build `DependencyTracker` from discovered functions and call edges.
- Convert diff ranges to `PatchSet`.
- Run `IncrementalAnalyzer::apply_patches`.
- Recompute analysis only for `AffectedAnalysis::all_affected()`.

## 4) Invalidate stale cache ranges

When patches overlap a function range, invalidate cached entries for that range before recomputing.

```rust
cache.invalidate_range(changed_start, changed_end);
```

## 5) Validate impact and quality

```bash
scripts/ci-local --tier medium --no-cross --no-perf
scripts/quality-smoke
```

If patch touches control-flow-heavy code, compare benchmark quality counters before/after.

## 6) Recommended policy

- Local inner loop: no cross, no perf.
- Pre-push: medium tier defaults.
- Release candidate: full tier + deterministic perf gate.
