# hexray

A professional-grade multi-architecture disassembler and decompiler written entirely in Rust. No external disassembler libraries - every instruction decoder, binary parser, and analysis pass is implemented from scratch.

## Why hexray?

| Feature | IDA Pro | Ghidra | Binary Ninja | hexray |
|---------|:-------:|:------:|:------------:|:------:|
| **Formats** |
| ELF / Mach-O / PE | ✅ | ✅ | ✅ | ✅ |
| DWARF Debug Info | ✅ | ✅ | ✅ | ✅ |
| **Architectures** |
| x86_64 (incl. AVX-512) | ✅ | ✅ | ✅ | ✅ |
| ARM64 (incl. SVE/SVE2) | ✅ | ✅ | ✅ | ✅ |
| RISC-V (RV32/64 + extensions) | ✅ | ✅ | ✅ | ✅ |
| **Analysis** |
| CFG / Call Graph | ✅ | ✅ | ✅ | ✅ |
| SSA-based Decompiler | ✅ | ✅ | ✅ | ✅ |
| Type Inference | ✅ | ✅ | ✅ | ✅ |
| Data Flow Queries | ✅ | ✅ | ✅ | ✅ |
| Function Signatures | ✅ | ✅ | ✅ | ✅ |
| Static Emulation | ✅ | ✅ | ✅ | ✅ |
| Interactive Sessions | ✅ | ✅ | ✅ | ✅ |
| **Unique to hexray** |
| 100% Rust | ❌ | ❌ | ❌ | ✅ |
| No Dependencies* | ❌ | ❌ | ❌ | ✅ |
| Single Binary CLI | ❌ | ❌ | ❌ | ✅ |
| Open Source | ❌ | ✅ | ❌ | ✅ |

*No capstone, no LLVM, no external disassemblers - pure Rust from the ground up.

## Key Strengths

### Complete From-Scratch Implementation
Every component is hand-written in Rust for full transparency and hackability:
- **Instruction decoders**: x86_64 (1500+ opcodes), ARM64 (NEON, SVE, crypto), RISC-V (RV32/64IMAC)
- **Binary parsers**: ELF, Mach-O (including fat/universal), PE/COFF
- **Debug info**: Full DWARF4 parser with line numbers and variable names
- **Analysis**: CFG, SSA, data flow, type inference, decompilation

### Advanced x86_64 Support
- Full VEX prefix decoding (SSE, AVX, AVX2, FMA)
- EVEX/AVX-512 with masking and broadcast
- BMI1/BMI2 bit manipulation (PDEP, PEXT, etc.)
- AES-NI and SHA extensions

### Comprehensive ARM64 Support
- NEON SIMD (128-bit vectors)
- SVE/SVE2 scalable vectors (Z0-Z31, P0-P15)
- Crypto extensions (AES, SHA, SM4)
- Atomics (LDXR/STXR, CAS, LDADD, SWP)

### Professional Decompiler
- SSA-based intermediate representation
- Control flow structuring (if/else, while, do-while, for, switch)
- Short-circuit boolean optimization (`a && b`, `a || b`)
- Compound assignment detection (`x += 1`)
- Array and struct field access recovery
- Constant propagation and dead code elimination

### Analysis Capabilities
- **Data flow queries**: Trace values forward/backward through code
- **Function signatures**: FLIRT-like pattern matching for library identification
- **Type libraries**: C type definitions for POSIX, Linux, macOS
- **Static emulation**: Resolve indirect jumps and virtual calls
- **Cross-references**: Code and data xref database

### Interactive Sessions
- **Persistent REPL**: SQLite-backed sessions with command history
- **Annotations**: Rename functions/variables, add comments, bookmarks
- **Session management**: Detach and resume sessions later
- **Binary verification**: SHA256 hash ensures session matches binary

## Installation

```bash
git clone https://github.com/zoratu/hexray.git
cd hexray
cargo build --release
# Binary at target/release/hexray
```

## Quick Start

```bash
# Show binary info
hexray ./binary info

# List functions
hexray ./binary symbols --functions

# Disassemble a function
hexray ./binary -s main

# Decompile to pseudo-code
hexray ./binary decompile main

# Show control flow graph
hexray ./binary cfg main

# Cross-references
hexray ./binary xrefs 0x401000

# Detected strings
hexray ./binary strings

# Compare two binaries (incremental analysis)
hexray diff original.bin patched.bin --json

# Interactive session (persistent annotations)
hexray session new ./binary --output project.hrp
hexray session resume project.hrp
```

## Example Output

### Decompilation
```c
void process_input(char *input)
{
    int len = strlen(input);

    if (len > 0 && input[0] != '#') {
        for (int i = 0; i < len; i++) {
            buffer[i] = input[i] ^ 0x42;
        }
        send_data(buffer, len);
    }
}
```

### Disassembly
```
0x00401000  push    rbp
0x00401001  mov     rbp, rsp
0x00401004  sub     rsp, 0x20
0x00401008  mov     qword ptr [rbp-0x8], rdi
0x0040100c  mov     rax, qword ptr [rbp-0x8]
0x00401010  mov     rdi, rax
0x00401013  call    strlen
```

## Supported Targets

### Architectures

| Architecture | Disassembly | Decompilation | Extensions |
|--------------|:-----------:|:-------------:|------------|
| x86_64 | ✅ | ✅ | SSE, AVX, AVX-512, BMI, AES-NI, SHA |
| ARM64 | ✅ | ✅ | NEON, SVE/SVE2, Crypto, Atomics |
| RISC-V 64 | ✅ | ✅ | M, A, C extensions |
| RISC-V 32 | ✅ | ✅ | M, A, C extensions |

### Binary Formats

| Format | Parsing | Symbols | Debug Info |
|--------|:-------:|:-------:|:----------:|
| ELF | ✅ | ✅ | DWARF |
| Mach-O | ✅ | ✅ | DWARF |
| Fat/Universal | ✅ | ✅ | DWARF |
| PE/COFF | ✅ | ✅ | - |

## Project Structure

```
hexray/
├── crates/
│   ├── hexray/              # CLI application
│   ├── hexray-core/         # Core types (Instruction, CFG, etc.)
│   ├── hexray-formats/      # ELF, Mach-O, PE parsers + DWARF
│   ├── hexray-disasm/       # Instruction decoders
│   ├── hexray-analysis/     # CFG, SSA, decompiler, data flow
│   ├── hexray-demangle/     # C++/Rust symbol demangling
│   ├── hexray-signatures/   # Function signature matching
│   ├── hexray-types/        # C type libraries
│   └── hexray-emulate/      # Static emulation engine
├── fuzz/                    # Fuzz testing targets
└── docs/                    # Architecture documentation
```

## Documentation

- [Architecture Overview](docs/ARCHITECTURE.md) - Crate structure and data flow
- [Decompiler Guide](docs/DECOMPILER.md) - Decompilation pipeline details
- [Supported Instructions](docs/INSTRUCTIONS.md) - Complete instruction reference
- [Testing Infrastructure](docs/TESTING.md) - Ground truth benchmarks, test fixtures, fuzzing
- [Performance and Determinism](docs/PERFORMANCE.md) - Parallelism knobs and stable benchmark workflow
- [Performance Tuning Guide](docs/PERFORMANCE_TUNING.md) - Fast/medium/full tier usage and benchmark stability
- [Module Dependency Diagrams](docs/MODULE_DEPENDENCIES.md) - Crate and analysis-layer dependency maps
- [Tutorials](docs/tutorials/GETTING_STARTED.md) - Getting started, API usage, incremental workflow, and extension guide
- [API Examples](docs/examples/ANALYSIS_CACHE_EXAMPLES.md) - Analysis cache, incremental analysis, C++/EH/devirtualization examples
- [Architecture Decision Records](docs/adr/README.md) - Decision log for CI/process and architecture choices
- [Development Roadmap](docs/ROADMAP.md) - Feature status and plans

## Development

```bash
# Run tests (1300+ tests across all crates)
cargo test --workspace

# Tiered local CI (hook-aligned)
scripts/ci-local --tier fast
scripts/ci-local --tier medium
scripts/ci-local --tier full
scripts/ci-local --tier full --perf   # optional deterministic perf gate

# Fast decompiler control-flow quality smoke (fixture-backed)
scripts/quality-smoke

# Run with debug output
RUST_LOG=debug cargo run -- ./binary decompile main

# Run benchmarks
cargo bench --workspace

# Benchmark regression testing
./scripts/bench-regression.sh baseline  # Save baseline
./scripts/bench-regression.sh compare   # Compare to baseline

# Fuzz testing (decoders, parsers, and decompiler)
cd fuzz && cargo +nightly fuzz run x86_64_decoder
cd fuzz && cargo +nightly fuzz run decompiler

# Run all fuzzers via Docker
cd fuzz && ./run-fuzzers.sh --hours 2
```

### Ground Truth Testing

The decompiler includes a benchmark suite with 20+ test patterns validated against expected output:

```bash
# Run decompiler regression tests
cargo test --package hexray --test decompiler_regression

# Multi-language test fixtures available in tests/fixtures/
# C, C++, Rust, D, Go, Swift patterns for cross-compiler validation
```

### Local Benchmarking

For reliable performance comparisons, run benchmarks locally on consistent hardware:

```bash
# Save baseline (e.g., before changes)
cargo bench --workspace -- --save-baseline main

# Make changes, then compare
cargo bench --workspace -- --save-baseline pr

# Compare results (install with: cargo install critcmp)
critcmp main pr

# Deterministic benchmark workflow helper
scripts/bench-deterministic --main-label main --change-label pr --jobs 8 --test-threads 1
```

See `/Volumes/OWC 1M2/Users/isaiah/src/hexray/docs/PERFORMANCE.md` for deterministic benchmark and parallelism guidance.

## Use Cases

- **Reverse Engineering**: Analyze malware, understand proprietary software
- **Security Research**: Vulnerability discovery, exploit development
- **CTF Competitions**: Quick binary analysis with scriptable CLI
- **Education**: Learn how disassemblers and decompilers work
- **Tooling Integration**: JSON output for programmatic analysis

## License

GNU GPLv3

## Acknowledgments

Built to deeply understand binary analysis from first principles:
- Instruction set architectures and encoding formats
- Binary file formats and linking
- Control flow analysis and decompilation theory
- Data flow analysis and type recovery
