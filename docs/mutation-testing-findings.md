# Mutation testing — first-pass findings

Mutation testing (`cargo-mutants`, wired via `scripts/check-mutants`) measures
test-suite *strength*: it injects small behavioural changes and checks whether the
suite catches them. A **surviving** ("missed") mutant is a behaviour nothing
asserts — a concrete, named test gap.

This is the Examplar / "conceptual-chaff" idea (Brown PLT) applied with a tool:
we already verify the *code* continuously (proptest + differential + fuzz); this
is the missing layer that verifies the *test suite*.

## Scope and status of this first pass

- **Target:** `crates/hexray-analysis/src/decompiler/switch_recovery.rs`
  (158 mutants) — chosen as an un-swept hot-path module tied to invariant #4
  (bounded dispatch) and the recent PIC jump-table / coroutine work.
- **Test scope:** `hexray-analysis` crate tests only (`cargo-mutants` default).
  **Survivors here are gaps in the owning crate's own tests.** Some may still be
  caught by the top-level `hexray` integration/differential/swarm/e2e suites —
  re-run survivors with `--test-workspace true` to separate crate-local gaps from
  true end-to-end gaps.
- **Completion:** partial — the run was reaped at **63/158 mutants** because the
  shared build box ran critically low on memory. Per CLAUDE.md, the full campaign
  belongs on a fresh aarch64 spot. Per-mutant cost observed: ~20s build + ~4s test.

## Partial result (63/158 completed)

| outcome  | count |
|----------|-------|
| missed (surviving) | 38 |
| caught             | 25 |
| unviable           | 14 |

~60% of *completed, viable* mutants survived the crate's own tests — a strong
signal that `switch_recovery.rs` is under-tested at the unit level.

## Gap clusters (surviving mutants)

1. **Whole-function stubs survive.** `try_detect_jump_table` → `None` (L195) and
   `try_recover_switch` → `None` (L116) are not caught by crate-local tests —
   nothing in `hexray-analysis` asserts that switch recovery recovers anything.
   (Contrast: `analyze_jump_table_block` → `None` at L244 *is* caught.)

2. **Per-register index→argN naming is untested.** Deleting any arm of the
   index-register map (L379–387: `edi/rdi→arg0`, `esi/rsi→arg1`, … `r9d/r9→arg5`,
   ARM `w0/x0→arg0`, `w1/x1→arg1`) survives. Nothing asserts a jump table indexed
   through a given register yields the right `switch(argN)` — directly a
   readability-of-output gap.

3. **Table-base heuristic boundary + guard unpinned.** In
   `extract_absolute_table_base` (L485–487): `displacement > 0x1000` → `>=` and
   `displacement < i64::MAX` → `<=` survive (no boundary test), and the `&&`
   conjunction → `||` survives (the "base.is_none AND index.is_some AND
   displacement in range" gate is not pinned — `||` would wrongly accept many
   memory refs as table bases).

4. **PIC path + stride arithmetic unpinned.** `Operand::PcRelative` (L265) and
   `Operand::Memory` (L270) match arms delete without detection — the position-
   independent jump-table path (the recent reloc-aware win) has no crate-local
   guard. Case-value arithmetic `min_value + i` / table-stride `+` → `-`/`*`
   (L218, L277) also survives.

## Next steps

1. **Finish the campaign on a spot** (full 158 + the other curated hot-path files
   in `scripts/check-mutants`), `--test-workspace true` on survivors to confirm
   true end-to-end gaps.
2. **Close confirmed gaps** by adding targeted unit tests (each new test should
   flip exactly one surviving mutant from missed → caught). Highest-value first:
   clusters 2 and 3 (self-contained, clearly correctness/readability relevant).
3. **Adopt `--in-diff origin/main` as a CI gate** so new code must come with tests
   that catch its mutants, without re-sweeping the whole tree each run.
