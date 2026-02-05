# Hexray Testing Infrastructure

This document describes the comprehensive testing infrastructure for hexray, including ground truth benchmarks, multi-language test fixtures, regression tests, and fuzz testing.

## Overview

Hexray uses a multi-layered testing approach:

| Layer | Purpose | Location |
|-------|---------|----------|
| Unit Tests | Component correctness | `crates/*/src/**/*.rs` |
| Integration Tests | Cross-crate functionality | `crates/hexray/tests/` |
| Differential Tests | Compare with system tools | `tests/differential_tests.rs` |
| Snapshot Tests | CLI output stability | `tests/snapshot_tests.rs` |
| Regression Tests | Decompiler stability | `tests/decompiler_regression.rs` |
| Benchmark Suite | Ground truth validation | `hexray-analysis/src/decompiler/benchmark.rs` |
| Fuzz Tests | Crash resistance | `fuzz/fuzz_targets/` |

## Ground Truth Benchmark Suite

The benchmark suite provides automated quality assessment of decompiled output against expected patterns.

### Location

```
crates/hexray-analysis/src/decompiler/benchmark.rs
```

### Benchmark Categories

#### Loop Patterns
| Pattern | Description | Expected Output |
|---------|-------------|-----------------|
| `simple_for_loop` | Basic counting loop | `for` or `while` with increment |
| `while_loop` | Condition-controlled loop | `while` keyword |
| `do_while_loop` | Post-test loop | `do { } while` |
| `nested_loops` | Multi-level iteration | Nested loop constructs |
| `loop_with_break` | Early exit pattern | `break` statement |
| `loop_with_continue` | Skip iteration | `continue` statement |

#### Conditional Patterns
| Pattern | Description | Expected Output |
|---------|-------------|-----------------|
| `simple_if_else` | Basic conditional | `if` / `else` |
| `nested_conditionals` | Multi-level branching | Nested `if` statements |
| `short_circuit_and` | Lazy AND evaluation | `&&` operator |
| `short_circuit_or` | Lazy OR evaluation | `||` operator |
| `ternary_operator` | Conditional expression | `? :` operator |

#### Arithmetic Patterns
| Pattern | Description | Expected Output |
|---------|-------------|-----------------|
| `bit_test` | Test specific bit | `& (1 <<` or bitfield |
| `bit_set` | Set specific bit | `|= (1 <<` |
| `bit_clear` | Clear specific bit | `&= ~(1 <<` |
| `is_power_of_two` | Power-of-2 check | `(n & (n-1)) == 0` |
| `compound_add` | In-place addition | `+=` operator |
| `increment` | Counter increment | `++` or `+= 1` |
| `clamp_pattern` | Value clamping | `min` / `max` or conditional |

#### Algorithm Patterns
| Pattern | Description | Expected Output |
|---------|-------------|-----------------|
| `bubble_sort` | Sorting algorithm | Nested loops with swap |
| `factorial_iterative` | Factorial computation | Loop with multiplication |

### Quality Metrics

The benchmark suite evaluates decompiled output against:

1. **Expected Patterns**: Keywords/constructs that MUST appear
2. **Forbidden Patterns**: Constructs that MUST NOT appear (e.g., `goto`)
3. **Structural Metrics**:
   - Nesting depth (target: ≤3 levels)
   - Label count (target: 0 for structured code)
   - Variable naming quality

### Running Benchmarks

```rust
use hexray_analysis::decompiler::benchmark::{BenchmarkSuite, create_standard_suite};

let suite = create_standard_suite();
let results = suite.run_all(&decompiler);

for result in &results {
    println!("{}: {:.1}% ({})",
        result.name,
        result.score * 100.0,
        if result.passed { "PASS" } else { "FAIL" }
    );
}
```

## Multi-Language Test Fixtures

Different compilers generate different code patterns. The test fixtures cover multiple source languages to ensure the decompiler handles various compilation strategies.

### Location

```
tests/fixtures/
```

### C Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_loops.c` | for, while, do-while, nested, break, continue |
| `test_conditionals.c` | if-else, switch, ternary, short-circuit |
| `test_structs.c` | Field access, nested structs, arrays of structs |
| `test_arithmetic.c` | Bit manipulation, overflow, division |

### C++ Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_cpp_classes.cpp` | Classes, constructors, destructors, virtual functions |
| | Multiple inheritance, vtables, RTTI |
| | IntStack (template-like expanded), dynamic allocation |
| `test_cpp_exceptions.cpp` | try-catch, multiple catch blocks, nested handlers |
| | RAII pattern, noexcept, function try blocks |

### Rust Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_rust_patterns.rs` | Enums with variants, Option<T>, Result<T, E> |
| | Trait implementations, closures, iterators |
| | Box allocation, Vec operations, generics |
| | Slice patterns, panic/assert |

### D Language Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_d_patterns.d` | Structs with methods, classes with inheritance |
| | Templates (generic functions), contracts (in/out/invariant) |
| | Scope guards (scope(exit/success/failure)) |
| | Compile-time function evaluation (CTFE), mixins |
| | Nullable types, associative arrays |

### Go Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_go_patterns.go` | Structs with methods, interfaces |
| | Multiple return values, defer pattern |
| | Panic/recover, goroutines, channels |
| | Slices vs arrays, maps, type assertions |
| | Closures, variadic functions |

### Swift Test Fixtures

| File | Patterns Covered |
|------|------------------|
| `test_swift_patterns.swift` | Structs (value types), classes (reference types) |
| | Protocols, extensions, optionals |
| | Enums with associated values, closures |
| | Guard statements, switch with pattern matching |
| | Property observers, computed properties |

### Compiling Test Fixtures

```bash
# C
gcc -O2 -o test_loops tests/fixtures/test_loops.c

# C++
clang++ -O2 -fexceptions -o test_cpp_exceptions tests/fixtures/test_cpp_exceptions.cpp

# Rust
rustc -O -o test_rust_patterns tests/fixtures/test_rust_patterns.rs

# D (requires dmd or ldc2)
dmd -O -of=test_d_patterns tests/fixtures/test_d_patterns.d

# Go
go build -o test_go_patterns tests/fixtures/test_go_patterns.go

# Swift (macOS)
swiftc -O -o test_swift_patterns tests/fixtures/test_swift_patterns.swift
```

## Decompiler Regression Tests

Regression tests ensure the decompiler produces consistent, valid output across versions.

### Location

```
crates/hexray/tests/decompiler_regression.rs
```

### Test Categories

#### Structure Validation
```rust
test_macos_binary_decompilation_structure
```
Decompiles system binaries (/bin/ls, /bin/cat, /bin/echo) and validates:
- Function header present (parentheses)
- Braces present
- Return statement present
- Variables assigned
- No goto statements (quality indicator)

#### Crash Resistance
```rust
test_decompiler_no_crash_on_various_patterns
```
Tests edge cases that should not crash:
- Empty function (just `ret`)
- Simple function with push/pop
- Function with conditional branches

#### Determinism
```rust
test_decompiler_stability_on_repeated_runs
```
Verifies that decompiling the same code multiple times produces identical output.

#### Loop Detection
```rust
test_decompiler_handles_loop_patterns
```
Validates that loop constructs are detected in decompiled output.

### Running Regression Tests

```bash
cargo test --package hexray --test decompiler_regression
```

## Fuzz Testing

Fuzz testing ensures robustness against malformed or adversarial inputs.

### Location

```
fuzz/fuzz_targets/
```

### Decoder Fuzz Targets

| Target | Description |
|--------|-------------|
| `x86_64_decoder` | Random byte sequences to x86-64 decoder |
| `arm64_decoder` | Random byte sequences to ARM64 decoder |
| `riscv_decoder` | Random byte sequences to RISC-V decoder |

### Parser Fuzz Targets

| Target | Description |
|--------|-------------|
| `elf_parser` | Malformed ELF files |
| `macho_parser` | Malformed Mach-O files |
| `elf_structured` | Structure-aware ELF fuzzing |
| `macho_structured` | Structure-aware Mach-O fuzzing |

### Analysis Fuzz Targets

| Target | Description |
|--------|-------------|
| `cfg_builder` | CFG construction from instruction sequences |
| `decompiler` | Full decompilation pipeline |

### Running Fuzz Tests

```bash
cd fuzz

# Run specific target
cargo +nightly fuzz run x86_64_decoder

# Run with time limit
cargo +nightly fuzz run cfg_builder -- -max_total_time=300

# Run all targets via Docker
./run-fuzzers.sh --hours 2
```

## Differential Testing

Compares hexray output against system tools to ensure accuracy.

### Location

```
crates/hexray/tests/differential_tests.rs
```

### Comparisons

| Component | System Tool | What's Compared |
|-----------|-------------|-----------------|
| Disassembly | `objdump -d` | Instruction mnemonics, operands |
| Symbols | `nm` | Symbol names, addresses, types |
| Strings | `strings` | Detected string content |

### Running Differential Tests

```bash
cargo test --package hexray --test differential_tests
```

## Test Counts

As of the latest release:

| Crate | Test Count |
|-------|------------|
| hexray-analysis | 837+ |
| hexray-disasm | 224+ |
| hexray-formats | 43+ |
| hexray-demangle | 24+ |
| hexray-emulate | 45+ |
| hexray (CLI) | 139+ |
| **Total** | **1300+** |

## Continuous Integration

Tests run automatically on every push and pull request via GitHub Actions:

1. **Build Matrix**: Ubuntu + macOS
2. **Rust Versions**: Stable + MSRV (1.70)
3. **Checks**: clippy, rustfmt, tests, benchmarks
4. **Coverage**: cargo-llvm-cov with Codecov upload

## Adding New Tests

### Adding a Benchmark Case

```rust
// In benchmark.rs
BenchmarkCase::new("my_pattern", my_bytes.to_vec(), 0x1000)
    .expect_pattern("while")
    .expect_pattern("break")
    .forbid_pattern("goto")
```

### Adding a Test Fixture

1. Create the source file in `tests/fixtures/`
2. Document the patterns it covers
3. Add compilation instructions in comments

### Adding a Fuzz Target

1. Create `fuzz/fuzz_targets/my_target.rs`
2. Add entry to `fuzz/Cargo.toml`
3. Document in `fuzz/README.md`
