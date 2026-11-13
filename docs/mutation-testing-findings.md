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

## Gap-closing progress

### ✅ Done — condition/flag-lifting tables (`condition.rs`)
Commit `aa228e68b`. Added exhaustive table tests for `negate_condition`,
`condition_to_expr`, `parse_condition_from_mnemonic` (x86) and `parse_arm64_condition`,
plus the `negate(negate(c)) == c` involution property. **Verified biting** by
injection: a `Lt→Gt` swap fails the table + involution tests; deleting the arm64
`hi` arm fails the arm64 table test (both previously surviving mutants).

### ✅ Done — binary-search comparison table (`switch_recovery.rs`)
Commit `b1223c6a3`. Added an exhaustive `extract_comparison` `Condition →
ComparisonType` table test (signed + unsigned-folded arms) + a register/register
decline guard. **Verified biting**: dropping `Condition::Less` and swapping
`Above→Greater` both fail (both were *suite-wide* survivors in Campaign 2).

### ✅ Done — switch_recovery.rs jump-table internals (COMPLETE: 69 → 3 equivalent)
Commits `b77af689e`, `70f6762e3`, `57b9324ff`, `034d66202`, `66c9e61e2`,
`6ff07fae1`. Six batches of fixtures + tests closing the entire jump-table /
binary-search survivor set:
- table-base heuristic (`extract_absolute_table_base` 4 guard conditions + both
  displacement boundaries) and entry decoding (`read_jump_table` 4-byte / 1-byte /
  stride / out-of-range decline)
- index-register `argN` naming (all 8 argument-register arms + fallback)
- binary-search detection (`try_detect_binary_search` / `collect_comparisons` /
  `find_switch_candidates` stubs, len bounds, default, case sorting, Sub-compare,
  `get_stack_slot_key` Var arm)
- `analyze_jump_table_block` PIC path (LEA / PC-relative / `inst_end + disp` / scale,
  incl. scale-1 keeps default) and the comparison-register traceback (eax/rax
  aliasing, incl. negative cases)
- `try_detect_jump_table` possible-targets fallback (`min_value + i` arithmetic)

**Spot-measured (c7g.4xlarge aarch64, package-scoped, 158 mutants): 69 → 11 → 3.**
Final run: `158 mutants tested: 3 missed, 131 caught, 24 unviable` — all 3 missed
are the equivalent-mutant cluster below.
The final 3 survivors are **equivalent mutants**: `base.name()=="rip"` and
`base.id==16` (lines 273–274) always agree for x86-64 (the name is derived from the
id), so no input can distinguish the original from the mutant. Correctly unkillable.

> Verification method: every test was checked by hand-injecting a representative
> mutant and confirming it goes red, then reverting; and the whole file was
> re-measured end-to-end with `cargo-mutants` on a spot (69 → 11 after batches 1–5,
> → 3 equivalent after batch 6).

### ✅ Done — array_detection.rs (COMPLETE: 77 → 3 equivalent)
Commits `7704c2489`, `378422a1e`, `062b4bbe1`. Four batches of fixtures + tests
across the whole file:
- detection helpers (`extract_mul_by_constant` / `extract_shift_left_by_constant`
  bounds, `is_likely_array_base` arms, scaled / shift / constant-offset / struct-array
  detectors with exact base/index/element-size, size gates, commutativity, alignment
  and zero/unaligned rejection, struct field-offset math incl. const-first/shift paths)
- bounds inference (`infer_array_bounds` for `<` / `<=` / constant-index / non-unit
  stride; `is_simple_increment_for_inference` Assign + CompoundAssign arms;
  `expr_to_bound` IntLit/Product/Sum; `expr_uses_var` recursion incl. Cast)
- the loop-bound tree walkers (`collect_bounds_from_node`,
  `collect_array_accesses_in_loop`, `collect_array_accesses_from_expr`,
  `scan_expr_for_constant_indices`) across every container/expr arm

**Spot-measured (c7g.4xlarge aarch64, package-scoped): 213 mutants, 77 → 35 → 3.**
Final run: `213 mutants tested: 3 missed, 187 caught, 23 unviable`. The 3 survivors
are **equivalent mutants**: `element_size > 0` at lines 131/143/249, where the
element size comes from `extract_mul_by_constant` / `infer_element_size` /
`expected_size>0` and is provably always ≥ 1, so `> 0` and `>= 0` can never differ.

### ✅ Done — condition.rs (148 → 28; 91% of viable caught)
Commits `6cdfef955`, `c1676443c`, `449e7857b`, `6e49000e3`, `3e9fb547e`. Six batches
(beyond the earlier table batch `aa228e68b`). First full measure found **333 mutants,
148 missed** — the earlier batch had covered only 4 of ~22 functions. The batches
closed the pure helpers (`x86_float_compare_binop`, `is_flag_setting_instruction`,
`binop_for_register_update`, `register_aliases`, `substitute_register_in_expr`,
`expr_known_bit_width`, `expr_is_boolean_wrapper`, `expr_requires_single_evaluation`),
the big `condition_to_expr_before_address_with_fallback` lowering (operator table +
neg/inc/dec/test/xor/sub/add instruction shapes) and setcc/cmovcc, the lock/cmpxchg
+ ARM64 branch (CBZ/TBZ/TBNZ) + ARM64 writeback + ALU-update tracking, the fallback
placeholder table, logical-op compares, the ARM64 conditional-select family
(csel/cinc/cinv/cneg/cset/csetm) and rdtsc/rdtscp.

**Spot-measured (c7g.4xlarge aarch64, package-scoped): 333 mutants, 148 → 70 → 31 →
28.** Final: `333 mutants tested: 28 missed, 280 caught, 25 unviable` (91% of the 308
viable). The remaining **28 are the intricate internal-dataflow tail** — deferred as
below-the-value-line, not equivalent:
- `build_register_value_map_with_options` (9): multi-instruction register tracking,
  each mutant needs a bespoke dataflow fixture
- `condition_to_expr_before_address_with_fallback` (6): deep edge cases
- `try_lift_lock_prefixed_zero_flag_condition` (5): the lock-atomic exchange lifter
- `lift_setcc_with_context` (3): internal `&&` guard conjunctions
- `generate_writeback_expr` (2) and `find_flag_setting_instruction` (1) are
  near-equivalent (a var `size` field / a before-address filter not reflected in
  rendered output); `expr_requires_single_evaluation` (2)

### ✅ Done — CI gate (`scripts/check-mutants --in-diff` + `ci-local --mutants`)
Commit `f9392e8f2`. `check-mutants --in-diff <ref>` now resolves a git ref to a
merge-base diff of the working tree (uncommitted changes included) and feeds it to
cargo-mutants; a ready-made `.diff` file still works. `ci-local --tier full
--mutants` runs the gate over only the lines changed vs `--mutants-base` (default
`origin/main`), requiring every mutant on new code be caught — off by default since
it is heavy. Verified: `--in-diff origin/main` lists exactly the mutants of a changed
source line and nothing else.

## Remaining work (optional)

1. **condition.rs deep tail (28)** — the internal-dataflow functions above. Needs
   bespoke multi-instruction fixtures; low ROI vs the 48%→91% already gained.
2. **Other hot-path files** — `emitter/mod.rs`, `structurer/simplify.rs`,
   `signature/mod.rs` are large and unmeasured; `short_circuit.rs` had only 3
   crate-local survivors.
