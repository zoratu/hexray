# Proposal: Antithesis deterministic-simulation testing for the incremental cache

## Summary

Run hexray's **incremental analysis cache** — and only that — under
[Antithesis](https://antithesis.com), the deterministic-simulation platform from the
Hypothesis/Hegel authors. Antithesis explores sequences of operations against a
containerized system while **autonomously injecting faults**, and gives **perfect
deterministic replay** of any failure it finds. That is a strong fit for the one
genuinely *stateful* component in an otherwise pure pipeline, and it targets the
named invariant our current tests cover least adversarially:

> **Invariant #8 — Incremental-cache soundness.** Modeled in TLA+ and kept in
> lockstep with the implementation (`specs/tla/IncrementalInvalidation.tla` +
> `scripts/check-tla`).

## Why the cache, and not the whole decompiler

The decode path (bytes → pseudo-C) is **stateless and already heavily fuzzed**: 23
libFuzzer targets, structure-aware fuzzing, the proptest swarm, and the property
batteries added in this campaign. Antithesis would mostly duplicate that at real
setup cost.

The incremental cache is different in kind:

- It carries **state across operations** (populate → edit input → invalidate →
  recompute → read back), which is exactly the shape Antithesis explores well and
  example/property tests explore poorly.
- Its correctness depends on **I/O and ordering** (cache files on disk, partial
  writes, reordered or dropped writes) — precisely the faults Antithesis injects
  and a plain proptest cannot.
- We already have a **formal spec** (`IncrementalInvalidation.tla`). The TLA
  conformance test checks *model ↔ implementation lockstep on modeled
  transitions*; it does **not** drive the real on-disk cache through adversarial
  operation sequences under injected faults. That gap is what this fills.

**The soundness property, in one line:** an incremental recompute must yield a
result **observationally equal to a from-scratch analysis** of the same final
input — no stale entry ever survives an input change. That is the headline
`assert_always`.

## Scope (deliberately small)

A time-boxed spike, not a platform migration:

1. A minimal container that drives `hexray-analysis`'s cache (`analysis_cache.rs`
   + the incremental layer) through a workload: load binary → mutate bytes/sections
   → re-run analysis incrementally → compare against a non-incremental baseline.
2. The **`antithesis-sdk` Rust crate** for assertions and guided randomness:
   - `assert_always!` — incremental result ≡ from-scratch result (soundness).
   - `assert_always!` — no panic / no unbounded memory on any operation (invariants
     #1, #4 under fault injection).
   - `assert_sometimes!` — the interesting states are actually reached: a cache
     *hit* after an edit, an *invalidation* cascade, a recompute after a dropped
     write (a reachability witness, matching our existing anti-vacuity discipline).
   - `antithesis_sdk::random` for the operation sequence, so Antithesis steers
     coverage and can replay.
3. Fault injection: partial/dropped cache-file writes, reordered writes, truncated
   cache, concurrent readers — the failure modes the TLA model abstracts away.

## What success looks like

- Zero `assert_always` violations across an Antithesis run → strong, replayable
  evidence for invariant #8 beyond the model-conformance test.
- Any violation ships with a **deterministic reproducer**, which we fold back in as
  a committed regression (and, if it contradicts the model, a TLA fix — the model
  and code change together per the file-scope guardrail).

## Cost / risk

- **Setup:** a container + a workload harness + SDK wiring. Hours, not days, because
  the scope is one component.
- **Account:** Antithesis is a hosted service; needs access. Confirm availability
  before committing.
- **Not a replacement:** this augments the TLA conformance test and the fuzz/
  proptest suite; it does not replace them. Keep `scripts/check-tla` as the gate.
- **Guardrail:** `specs/tla/*` and the conformance test change together or not at
  all — any model-level finding is a joint model+code change, human-owned.

## Recommendation

Worth a scoped spike **targeting the incremental cache specifically**. Skip it for
the decode path. Gate the spike on confirming Antithesis account access and on the
`antithesis-sdk` crate fitting the `hexray-analysis` cache surface without
contorting the data model (human-owned).
