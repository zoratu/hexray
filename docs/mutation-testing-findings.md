# Mutation testing — findings

Mutation testing (`cargo-mutants`, wired via `scripts/check-mutants`) measures
test-suite *strength*: it injects small behavioural changes ("mutants") and checks
whether the suite catches them. A **surviving** ("missed") mutant is a behaviour
nothing asserts — a concrete, named test gap.

This is the Examplar / "conceptual-chaff" idea (Brown PLT) applied with a tool:
we already verify the *code* continuously (proptest + differential + fuzz); this
is the missing layer that verifies the *test suite* itself.

## Campaign 1 — crate-scoped sweep of the decompiler hot path

- **Targets:** `switch_recovery.rs`, `structurer/condition.rs`, `array_detection.rs`,
  `short_circuit.rs` (the deep untrusted-byte → pseudo-C transforms in
  `hexray-analysis`).
- **Test scope:** `hexray-analysis` crate tests only (cargo-mutants default).
  **Survivors here are gaps in the owning crate's own unit tests**; some may still
  be caught end-to-end by the top-level `hexray` integration/differential/swarm/e2e
  suites. Campaign 2 (below) calibrates that.
- **Run:** c7g.4xlarge aarch64 spot, `cargo-mutants 27.1.0`, `-j 6`, ~39 min.
  854/855 mutants completed (one lost to a transient `-j 6` ENOSPC peak near the
  end — reduce to `-j 4` next time; disk recovered to 77 G on exit).

### Result

| outcome            | count |
|--------------------|------:|
| caught             |  240  |
| **missed (gaps)**  |**372**|
| unviable           |  242  |
| timeout            |    0  |

**61% of viable mutants (372 / 612) survived the crate's own unit tests.** The
owning crate under-asserts its own decompiler logic; today most of it is validated
only end-to-end.

### Survivors by file

| file | missed |
|------|-------:|
| `structurer/condition.rs` | 223 |
| `array_detection.rs`      |  77 |
| `switch_recovery.rs`      |  69 |
| `short_circuit.rs`        |   3 |

### Survivors by function (top clusters)

The dominant theme is **condition / flag lifting** — the mnemonic→operator and
condition→operator mappings, where a mutant swaps `>=`↔`<` or `==`↔`!=`, i.e. a
*wrong comparison operator in the emitted pseudo-C*:

| function | missed | nature of gap |
|----------|-------:|---------------|
| `SwitchRecovery<…>` methods | 63 | jump-table detection, PIC/stride arithmetic, per-register `argN` index naming, table-base boundary heuristic |
| `condition_to_expr_before_address_with_fallback` | 48 | condition→operator mapping unpinned |
| `negate_condition` | 28 | **pure involution, zero tests** — any operator-pair arm can be swapped/deleted undetected |
| `parse_condition_from_mnemonic` | 16 | mnemonic→condition table unpinned |
| `condition_to_expr` | 16 | condition→operator table unpinned |
| `try_detect_struct_array_access` | 15 | struct/array access shape detection |
| `parse_arm64_condition` | 14 | AArch64 condition-code table unpinned |
| `expr_known_bit_width` | 14 | width inference |
| `lift_setcc_with_context` | 12 | `setcc` lifting (no direct unit test) |
| `x86_float_compare_binop` | 11 | float predicate mapping |

Smaller clusters: `register_aliases` (8), `is_flag_setting_instruction` (8),
`extract_mul_by_constant` (7), `try_detect_scaled_access` (6),
`generate_writeback_expr` (6), `collect_bounds_from_node` (6),
`lift_cmovcc_with_context` (3).

### Confirmed exemplar

`negate_condition` (condition.rs:970) maps each comparison op to its logical
complement (`Eq→Ne`, `Lt→Ge`, `ULt→UGe`, …) across ~14 arms plus a comment-string
table — and has **no test**. Deleting any arm silently falls through to a
`LogicalNot(...)` wrapper; swapping any pair emits the wrong operator. Both evade
the whole suite. It has an obvious pinning property: `negate(negate(c)) ≡ c` for
comparison ops, plus an exhaustive op→complement table test.

## Campaign 2 — end-to-end calibration (switch_recovery.rs)

Re-ran `switch_recovery.rs` with `--test-workspace true` so a mutant counts as
caught only if **some** test anywhere in the workspace (incl. the top-level
`hexray` integration / differential / swarm / e2e suites) notices it — separating
true end-to-end gaps from merely-crate-local ones. `-j 4`, 156/158 completed (the
last 2 lost to ENOSPC again — `--test-workspace` copies the *full* workspace build
per worker, so use `-j 2` and/or a bigger root volume for workspace-scoped runs).

### Result

| scope | caught | **missed** | unviable |
|-------|-------:|-----------:|---------:|
| crate-only (Campaign 1) | ~56 | **69** | 33 |
| **full workspace (Campaign 2)** | 59 | **64** | 33 |

**The entire top-level test machinery flips only ~5 crate-local survivors to
caught.** ~41% of `switch_recovery.rs` mutants (64 / 156) survive the *whole* test
suite — these are real, suite-wide gaps, not an artifact of crate scoping.

### What survives end-to-end (the serious part)

- **Whole-function stubs**: `try_detect_binary_search → None`,
  `collect_comparisons → None`/`Some(vec![])`, `find_switch_candidates → vec![]`,
  `extract_comparison → None`. Switch recovery could return "no switches found"
  and no test anywhere notices.
- **Binary-search comparison→operator table fully unpinned**: deleting any of
  `Condition::{Equal,Less,LessOrEqual,Greater,GreaterOrEqual,Below,BelowOrEqual,
  Above,AboveOrEqual}` arms in `extract_comparison` survives — wrong case
  predicate, undetected.
- **Jump-table stride/base arithmetic**: `read_jump_table` entry-size arms
  `(4,true)`/`(1,true)` delete and `+`→`-`/`*` survive; `extract_absolute_table_base`
  boundary (`> 0x1000`, `< i64::MAX`) and `&&` guard survive.
- **PIC path**: `analyze_jump_table_block` `LoadEffectiveAddress` and
  `Operand::PcRelative` arms delete undetected (the recent reloc-aware work).
- **Per-register `argN` index naming**: deleting any of `edi/rdi…r9d/r9`, `w0/x0`,
  `w1/x1` survives — `switch(argN)` readability unguarded.

This promotes switch-recovery guards from "nice to have" to a **confirmed
suite-wide blind spot**. `condition.rs`'s 223 crate-local survivors were not
workspace-calibrated (would need `-j 2`, ~3 h); given the tiny uplift observed
here, expect most to be real too, though condition lifting is more heavily
exercised by e2e decompile tests so its uplift may be larger.

## Recommendations (ranked)

1. **Pin the condition/flag-lifting tables first** — highest value, lowest effort.
   `negate_condition`, `condition_to_expr`, `parse_condition_from_mnemonic`,
   `parse_arm64_condition`, `x86_float_compare_binop` are pure, table-shaped, and
   correctness-critical (a wrong operator is a wrong decompile). Add exhaustive
   op→expr table tests + the `negate∘negate = id` property test. Each test should
   flip specific survivors missed→caught; re-run `scripts/check-mutants -f
   crates/hexray-analysis/src/decompiler/structurer/condition.rs` to confirm.
2. **Switch-recovery guards — CONFIRMED suite-wide gap (Campaign 2).** The
   binary-search path (`try_detect_binary_search`, `collect_comparisons`,
   `extract_comparison`'s `Condition::*` table), jump-table stride/base arithmetic
   (`read_jump_table`, `extract_absolute_table_base` `> 0x1000`/`&&` guard), the PIC
   path, and per-register `argN` naming survive the *entire* suite. Tied to
   invariant #4 and the recent reloc-aware PIC work — highest-confidence gap.
3. **Array-detection shape tests** — `try_detect_struct_array_access`,
   `try_detect_scaled_access`, `extract_mul_by_constant`.
4. **Adopt `scripts/check-mutants --in-diff origin/main` as a CI gate** so new code
   must ship with tests that catch its mutants, without re-sweeping the whole tree.
