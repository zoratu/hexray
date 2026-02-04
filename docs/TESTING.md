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
| hexray-analysis | 34 | 553 | Good coverage (+86 SSA, +59 structurer, +42 dataflow, +100 error paths tests) |
| hexray-disasm | 7 | 231 | Good coverage |
| hexray-types | 8 | 173 | Good coverage (+147 tests) |
| hexray-signatures | 6 | 141 | Good coverage (+116 tests) |
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

### 3. Structurer (3,605 lines, 59 tests) ✅ COMPLETE

The largest module. Transforms CFG to structured control flow. **Phase 3 complete: 59 tests added.**

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

### 4. Dataflow Passes ✅ COMPLETE

**Phase 4 complete: 42 tests added across dataflow modules.**

- `dataflow/mod.rs` - 22 tests for Location, InstructionEffects, DataflowSolver
- `dataflow/const_prop.rs` - 20 tests for ConstValue, ConstState, ConstantPropagation

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

### 5. Signature Integration Tests ✅ COMPLETE

**Phase 5 complete: 116 tests added across all signature modules.**

- `pattern.rs` - 31 tests for PatternByte, BytePattern parsing, matching, wildcards
- `signature.rs` - 24 tests for CallingConvention, ParameterType, Parameter, FunctionSignature
- `database.rs` - 31 tests for SignatureDatabase CRUD, merge, filtering, JSON serialization
- `matcher.rs` - 30 tests for SignatureMatcher prefix indexing, confidence, scanning
- `builtin/mod.rs` - 26 tests for builtin signature loading, architecture aliases

**Estimated effort:** 30-50 tests, 1-2 days

---

### 6. Error Paths and Edge Cases ✅ COMPLETE

**Phase 6 complete: 100 tests added across error handling and edge cases.**

- `project.rs` - Tests for BinaryNotFound, InvalidJson, UnsupportedVersion, NothingToUndo/Redo, HashMismatch, unicode handling
- `cpp_special.rs` - Tests for malformed symbols, C++ ABI edge cases, all constructor/destructor variants, database operations
- `dataflow/queries.rs` - Tests for DataFlowRole, DataFlowStep, DataFlowResult, nonexistent addresses, truncation handling
- `dataflow/liveness.rs` - Tests for LivenessFact methods, at_instruction edge cases, always_live, live_ranges
- `decompiler/naming.rs` - Tests for helper functions, TypeHint variants, register renaming, DWARF integration

**Estimated effort:** 30-50 tests, 1-2 days

---

## Medium Priority

### 7. C Header Parsing Integration ✅ COMPLETE

**Phase 7 complete: 147 tests added across hexray-types crate.**

- `parser.rs` - 43 tests for typedef variants, struct/union/enum parsing, functions, comments, error handling
- `types.rs` - 68 tests for IntType, FloatType, CType methods, size/alignment, to_c_string, ArrayType, StructType, UnionType, EnumType, FunctionType, FunctionPrototype
- `database.rs` - 39 tests for ArchInfo, type lookup, iterators, field access, merge, JSON serialization, format_type

**Estimated effort:** 30-40 tests, 1-2 days

---

### 8. Output Format Tests ✅ COMPLETE

**Phase 8 complete: 110 tests added across output format modules.**

- `hexray-core/src/output/dot.rs` - 27 tests for escape_dot_string, DotConfig, format_node, format_edge, format_edge_labeled, integration
- `hexray-analysis/src/output/dot.rs` - 20 tests for CfgDotExporter and CallGraphDotExporter (config, empty, escaping, branching, external)
- `hexray-analysis/src/output/json.rs` - 22 tests for CfgJsonExporter and CallGraphJsonExporter (valid JSON, pretty/compact, addresses, call types)
- `hexray-analysis/src/output/html.rs` - 41 tests for CfgHtmlExporter and CallGraphHtmlExporter (structure, XSS prevention, escaping, styling)

**Tests cover:**
- DOT format escaping (backslash, quotes, angle brackets)
- DOT graph structure and configuration
- JSON validity and serialization
- HTML structure and XSS prevention
- Empty input handling
- Special character escaping
- Entry/exit block styling
- External function display

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
| 3 | Structurer | 59 | ✅ Complete |
| 4 | Dataflow passes | 42 | ✅ Complete |
| 5 | Signatures integration | 116 | ✅ Complete |
| 6 | Error paths & edge cases | 100 | ✅ Complete |
| 7 | C header parsing | 147 | ✅ Complete |
| 8 | Output formats | 110 | ✅ Complete |
| 9 | Cross-crate integration | 20-30 | Pending |

**Progress:** 797 tests added (Phase 1-8 complete)

---

## Quick Wins

Tests that can be added quickly with high value:

1. **CFG successor/predecessor symmetry** - Simple property test
2. **SSA single-definition property** - Core invariant
3. **Register lookup exhaustive test** - Catch missing registers
4. **Signature database load test** - Verify builtins work
5. **Empty function edge cases** - Common crash source
