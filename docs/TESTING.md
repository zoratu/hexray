# Hexray Testing Plan

This document outlines the testing gaps and prioritized work for improving test coverage across the hexray codebase.

## Current State

**Test Infrastructure:**
- 819 total unit tests across codebase
- 83 files contain test functions
- 13 integration test files
- 5 property-based test files using proptest
- 7 fuzz targets (x86_64, arm64, riscv decoders; ELF/Mach-O parsers; structured parsers)
- Snapshot tests for CLI output validation
- Differential tests comparing against objdump, nm, strings

**Coverage by Crate:**
| Crate | Test Files | Unit Tests | Status |
|-------|------------|------------|--------|
| hexray-analysis | 34 | 352 | Good coverage (+86 SSA tests) |
| hexray-disasm | 7 | 231 | Good coverage |
| hexray-types | 8 | 26 | Moderate |
| hexray-signatures | 6 | 25 | Inline only, no integration |
| hexray-emulate | 6 | 24 | Moderate |
| hexray-formats | 7 | 26 | Moderate |
| hexray-core | 1 | 141 | Good coverage (+137 tests) |
| hexray-demangle | 1 | 11 | Light |
| hexray (CLI) | 0 | 0 | Integration tests only |

---

## Critical Priority

### 1. hexray-core (3,007 lines, 141 tests) ✅ COMPLETE

The core crate defines foundational types used everywhere. **Phase 1 complete: 137 tests added.**

**Modules with NO tests:**

| Module | Lines | Description |
|--------|-------|-------------|
| `cfg.rs` | 313 | Control flow graph implementation |
| `instruction.rs` | 855 | Core instruction representation |
| `basic_block.rs` | 162 | Basic block representation |
| `operand.rs` | 223 | Operand handling |
| `symbol.rs` | 91 | Symbol representation |
| `arch.rs` | 66 | Architecture definitions |
| `output.rs` | ~200 | Output formatting |

**Specific tests needed:**

```
cfg.rs:
- test_add_block_returns_unique_id
- test_add_edge_creates_successor_predecessor_link
- test_successors_predecessors_symmetry
- test_entry_block_has_no_predecessors
- test_exit_blocks_have_no_successors
- test_dominance_frontier_computation
- test_reverse_post_order_traversal
- test_loop_detection_simple
- test_loop_detection_nested
- test_loop_detection_irreducible
- test_cfg_from_empty_function
- test_cfg_serialization_roundtrip

instruction.rs:
- test_instruction_construction
- test_is_branch_for_all_branch_types
- test_is_call_for_direct_and_indirect
- test_is_return_detection
- test_is_conditional_vs_unconditional
- test_branch_target_extraction
- test_instruction_size_consistency
- test_operand_count_matches_mnemonic
- test_memory_operand_detection
- test_register_operand_detection

basic_block.rs:
- test_block_address_range
- test_block_contains_address
- test_block_instruction_iteration
- test_block_terminator_instruction
- test_block_fall_through_detection
- test_empty_block_handling

operand.rs:
- test_register_operand_parsing
- test_immediate_operand_parsing
- test_memory_operand_base_index_scale
- test_rip_relative_addressing
- test_operand_size_detection
- test_operand_equality
- test_operand_display_format

register.rs (has 4 tests, needs more):
- test_register_lookup_x86_64_all
- test_register_lookup_arm64_all
- test_register_lookup_riscv_all
- test_register_aliases (rax/eax/ax/al)
- test_register_size_queries
- test_register_class_membership
- test_sub_register_relationships
```

**Estimated effort:** 50-80 tests, 2-3 days

---

### 2. SSA Construction (1,250 lines, 93 tests) ✅ COMPLETE

SSA form is fundamental to all analysis passes. **Phase 2 complete: 86 tests added.**

**Files:**
- `ssa/builder.rs` (359 lines) - SSA construction with phi placement
- `ssa/mod.rs` (193 lines) - SSA operations
- `ssa/types.rs` (288 lines) - SSA type definitions
- `ssa/optimize.rs` (410 lines) - SSA optimizations

**Property-based tests needed:**

```
SSA Construction Invariants:
- prop_every_use_has_exactly_one_reaching_definition
- prop_phi_nodes_placed_at_dominance_frontier
- prop_phi_node_operand_count_equals_predecessor_count
- prop_version_numbers_are_unique_per_variable
- prop_ssa_form_is_acyclic_for_definitions
- prop_original_semantics_preserved

Dominator Tree:
- prop_dominator_tree_is_tree (no cycles)
- prop_entry_dominates_all_blocks
- prop_strict_dominance_is_transitive
- prop_immediate_dominator_is_unique

Phi Placement:
- test_phi_at_join_point_two_predecessors
- test_phi_at_loop_header
- test_no_phi_for_single_definition
- test_phi_for_conditional_definitions
- test_nested_loop_phi_placement

SSA Optimizations:
- test_dead_phi_elimination
- test_copy_propagation
- test_constant_folding_in_ssa
- test_redundant_phi_removal
```

**Estimated effort:** 40-60 tests, 2 days

---

### 3. Structurer (3,605 lines, 0 tests)

The largest untested module. Transforms CFG to structured control flow.

**Key functions to test:**

```
Control Flow Recovery:
- test_if_then_detection
- test_if_then_else_detection
- test_nested_if_detection
- test_switch_case_recovery
- test_switch_with_fallthrough
- test_switch_with_default

Loop Detection:
- test_while_loop_detection
- test_do_while_loop_detection
- test_for_loop_detection
- test_infinite_loop_detection
- test_nested_loop_detection
- test_loop_with_break
- test_loop_with_continue
- test_loop_with_multiple_exits

Complex Patterns:
- test_short_circuit_and_detection
- test_short_circuit_or_detection
- test_ternary_expression_detection
- test_goto_reduction_simple
- test_goto_reduction_irreducible
- test_early_return_handling

Property Tests:
- prop_structured_output_is_acyclic
- prop_all_blocks_reachable_in_output
- prop_no_critical_edges_remain
- prop_loop_headers_dominate_loop_body
- prop_switch_cases_are_disjoint
```

**Estimated effort:** 80-120 tests, 3-4 days

---

## High Priority

### 4. Dataflow Passes

**Files needing tests:**
- `dataflow/reaching_defs.rs` - Reaching definitions analysis
- `dataflow/liveness.rs` - Live variable analysis
- `dataflow/const_prop.rs` - Constant propagation
- `dataflow/def_use.rs` - Definition-use chains
- `dataflow/queries.rs` - Slicing queries

**Tests needed:**

```
Reaching Definitions:
- test_single_definition_reaches_all_uses
- test_multiple_definitions_at_join
- test_definition_killed_by_redefinition
- test_loop_carried_definitions
- test_reaching_defs_through_call

Liveness:
- test_variable_live_at_use
- test_variable_dead_after_last_use
- test_live_range_across_blocks
- test_phi_operands_are_live
- test_call_clobbers_affect_liveness

Constant Propagation:
- test_constant_assignment_propagates
- test_constant_arithmetic
- test_conditional_constant_propagation
- test_loop_prevents_propagation
- test_unknown_call_result

Def-Use Chains:
- test_single_def_multiple_uses
- test_phi_def_uses
- test_use_def_chain_consistency
- test_transitive_dependencies
```

**Estimated effort:** 60-80 tests, 2-3 days

---

### 5. Signature Integration Tests

**Current state:** 25 inline unit tests, no integration tests

**Missing test directory:** `crates/hexray-signatures/tests/`

**Tests needed:**

```
Pattern Matching:
- test_match_libc_strlen
- test_match_libc_memcpy
- test_match_libc_malloc
- test_match_with_wildcard_bytes
- test_no_false_positive_on_similar_code

Database Operations:
- test_load_builtin_signatures
- test_signature_database_merge
- test_signature_serialization_roundtrip
- test_duplicate_signature_handling

Integration:
- test_recognize_functions_in_elf_binary
- test_recognize_functions_in_macho_binary
- test_signature_match_with_relocations
- test_signature_match_stripped_binary
```

**Estimated effort:** 30-50 tests, 1-2 days

---

### 6. Decompiler Error Paths

**Problem:** 312 instances of `unwrap`/`panic`/`expect` in hexray-analysis

**Approach:** Add tests that exercise error conditions

```
Error Handling Tests:
- test_decompile_empty_function
- test_decompile_single_instruction
- test_decompile_unreachable_code
- test_decompile_malformed_cfg
- test_decompile_with_unknown_instruction
- test_decompile_recursive_function
- test_decompile_very_large_function
- test_expression_simplify_deep_nesting
- test_type_inference_conflicting_constraints
```

**Estimated effort:** 30-50 tests, 1-2 days

---

## Medium Priority

### 7. C Header Parsing Integration

**Files:**
- `hexray-types/src/parser.rs` (25,158 lines)
- `hexray-types/src/types.rs` (20,331 lines)

**Tests needed:**

```
Real Header Parsing:
- test_parse_stdio_h_subset
- test_parse_stdint_h
- test_parse_struct_with_bitfields
- test_parse_nested_structs
- test_parse_function_pointers
- test_parse_typedef_chains
- test_parse_anonymous_unions
- test_parse_flexible_array_member
- test_parse_attributes_packed
- test_parse_forward_declarations
```

**Estimated effort:** 30-40 tests, 1-2 days

---

### 8. Output Format Tests

**Files:**
- Various output modules for JSON, HTML, DOT

**Tests needed:**

```
JSON Output:
- test_json_cfg_valid_structure
- test_json_decompile_valid_structure
- test_json_special_character_escaping

DOT Output:
- test_dot_graph_syntax_valid
- test_dot_node_labels_escaped
- test_dot_edge_attributes

HTML Output:
- test_html_syntax_highlighting
- test_html_xss_prevention
```

**Estimated effort:** 20-30 tests, 1 day

---

### 9. Cross-Crate Integration Tests

**Tests that exercise the full pipeline:**

```
End-to-End:
- test_elf_to_decompiled_c_x86_64
- test_elf_to_decompiled_c_arm64
- test_macho_to_decompiled_c
- test_pe_to_decompiled_c
- test_stripped_binary_analysis
- test_binary_with_debug_info
- test_static_linked_binary
- test_dynamic_linked_binary
```

**Estimated effort:** 20-30 tests, 1-2 days

---

## Testing Infrastructure Improvements

### Current Strengths
- Fuzzing with Docker (7 targets)
- Property-based testing with proptest
- Differential testing against binutils
- Snapshot testing with insta
- Proptest regression files committed

### Future Improvements
1. **Coverage reporting** - Add `cargo-tarpaulin` or `llvm-cov` to CI
2. **Benchmarking** - Add `criterion` benchmarks for hot paths
3. **Regression tests** - Create tests for each bug fix
4. **Real-world corpus** - Build collection of test binaries

---

## Execution Order

| Phase | Focus | Tests | Status |
|-------|-------|-------|--------|
| 1 | hexray-core | 137 | ✅ Complete |
| 2 | SSA construction | 86 | ✅ Complete |
| 3 | Structurer | 80-120 | Pending |
| 4 | Dataflow passes | 60-80 | Pending |
| 5 | Signatures integration | 30-50 | Pending |
| 6 | Error paths | 30-50 | Pending |
| 7 | C header parsing | 30-40 | Pending |
| 8 | Output formats | 20-30 | Pending |
| 9 | Cross-crate integration | 20-30 | Pending |

**Progress:** 223 tests added (Phase 1-2 complete)

---

## Quick Wins

Tests that can be added quickly with high value:

1. **CFG successor/predecessor symmetry** - Simple property test
2. **SSA single-definition property** - Core invariant
3. **Register lookup exhaustive test** - Catch missing registers
4. **Signature database load test** - Verify builtins work
5. **Empty function edge cases** - Common crash source
