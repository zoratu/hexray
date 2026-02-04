# Hexray Roadmap

This document outlines the development roadmap, competitive analysis, and feature status for hexray.

## Competitive Analysis

### Feature Comparison Matrix

| Feature | IDA Pro | Ghidra | Binary Ninja | Hexray |
|---------|:-------:|:------:|:------------:|:------:|
| **Formats** |
| ELF | ✅ | ✅ | ✅ | ✅ |
| Mach-O | ✅ | ✅ | ✅ | ✅ |
| PE/COFF | ✅ | ✅ | ✅ | ✅ |
| **Architectures** |
| x86/x64 | ✅ | ✅ | ✅ | ✅ |
| ARM64 | ✅ | ✅ | ✅ | ✅ |
| RISC-V | ✅ | ✅ | ✅ | ✅ |
| **Analysis** |
| CFG construction | ✅ | ✅ | ✅ | ✅ |
| Call graph | ✅ | ✅ | ✅ | ✅ |
| Cross-references | ✅ | ✅ | ✅ | ✅ |
| String detection | ✅ | ✅ | ✅ | ✅ |
| Decompiler | ✅ | ✅ | ✅ | ✅ |
| SSA form | ✅ | ✅ | ✅ | ✅ |
| Type inference | ✅ | ✅ | ✅ | ✅ |
| **Advanced Features** |
| FLIRT/signatures | ✅ | ✅ | ✅ | ✅ |
| Type libraries | ✅ | ✅ | ✅ | ✅ |
| DWARF debug info | ✅ | ✅ | ✅ | ✅ |
| Data flow queries | ✅ | ✅ | ✅ | ✅ |
| Emulation | ✅ | ✅ | ✅ | ✅ |
| **Interactive** |
| Annotations/comments | ✅ | ✅ | ✅ | ✅ |
| Undo/redo | ✅ | ✅ | ✅ | ✅ |
| Session/Project files | ✅ | ✅ | ✅ | ✅ |
| Scripting/plugins | ✅ | ✅ | ✅ | ❌ Future |
| GUI | ✅ | ✅ | ✅ | ❌ Future |

### Competitor Strengths

**IDA Pro** ($$$)
- Gold standard for professional RE
- FLIRT signatures with massive database
- Lumina cloud-based function identification
- Excellent debugger integration
- Fastest disassembly engine

**Ghidra** (Free, NSA)
- Best-in-class decompiler (especially C++)
- P-code intermediate language
- Collaborative analysis (shared projects)
- Undo/redo everything
- Extensive scripting (Java, Python)

**Binary Ninja** ($$)
- Modern, clean architecture
- BNIL intermediate language (4 levels)
- Best UI for patching
- Fast iteration on features
- Rust plugin support

### Hexray Differentiators
- **Educational focus** - Built from scratch, every component understandable
- **Rust ecosystem** - Memory safe, modern tooling, easy to extend
- **Minimal dependencies** - No goblin, no capstone, no external disassemblers
- **CLI-first** - Fast, scriptable, Unix-philosophy
- **Open source** - Full transparency, community contributions

---

## Current Status

### Completed Phases

#### Phase 1-9: Foundation ✅
- Multi-architecture disassembly (x86_64, ARM64, RISC-V)
- Multiple binary formats (ELF, Mach-O)
- Control flow graph construction
- SSA-based decompiler with control flow structuring
- Cross-reference analysis
- String detection and annotation
- Type inference (integers, pointers, floats, structs)
- Symbol demangling (C++, Rust)
- Multiple output formats (text, JSON, DOT, HTML)
- Parallel disassembly

#### Phase 10: Debug Info & Extended Coverage ✅

**10.1 DWARF Debug Info** ✅
- Location: `crates/hexray-formats/src/dwarf/`
- Full DWARF4 parser with compilation units, DIEs
- Line number lookup (address → source location)
- Function discovery with parameters and local variables
- Variable name extraction with stack offsets

**10.2 Extended Instruction Coverage** ✅
- x86_64: EVEX/AVX-512, VEX 0F38/0F3A, BMI1/BMI2, POPCNT/LZCNT/TZCNT
- ARM64: SVE/SVE2 (Z0-Z31, P0-P15), atomics (LDXR, STXR, CAS, LDADD)
- ARM64: SIMD/FP load/store with V=1 flag, advanced NEON

**10.4 Fuzz Testing** ✅
- Location: `fuzz/`
- Fuzz targets for x86_64, ARM64, RISC-V decoders
- Fuzz targets for ELF and Mach-O parsers

#### Phase 11: Competitive Feature Parity ✅

**11.1 Function Signatures (FLIRT-like)** ✅
- Location: `crates/hexray-signatures/`
- Byte pattern matching with wildcards
- Signature database with libc patterns
- Builtin signatures for x86_64 and AArch64

**11.2 Type Libraries** ✅
- Location: `crates/hexray-types/`
- C type representation (structs, unions, enums, typedefs)
- Type database with lookup
- Builtin types for POSIX, Linux, macOS

**11.3 Data Flow Queries** ✅
- Location: `crates/hexray-analysis/src/dataflow/queries.rs`
- Backward tracing: "where does this value come from?"
- Forward tracing: "where does this value go?"
- Find all uses/definitions of a value

**11.4 Static Emulation** ✅
- Location: `crates/hexray-emulate/`
- Concrete execution with x86_64 semantics
- Register and memory state tracking
- Indirect jump/call resolution
- Value types: Concrete, Symbolic, Unknown

#### Phase 12: Advanced Decompilation ✅

**12.1 Control Flow Improvements** ✅
- Switch statement reconstruction (jump table detection)
- Loop canonicalization (while, do-while, for loops)
- Short-circuit boolean optimization (`a && b`, `a || b`)

**12.2 Expression Quality** ✅
- Compound assignment detection (`x += 1`)
- Array access detection (`arr[i]` from pointer math)
- Struct field access inference

**12.3 C++ Decompilation** ✅
- [x] Virtual function table reconstruction
- [x] Constructor/destructor identification
  - Location: `crates/hexray-analysis/src/cpp_special.rs`
  - Symbol name analysis for Itanium C++ ABI (C1, C2, C3, D0, D1, D2)
  - Vtable pointer assignment detection
  - Base class constructor/destructor call tracking
- [x] Exception handling (try/catch)
  - Location: `crates/hexray-formats/src/dwarf/lsda.rs`
  - LSDA (Language Specific Data Area) parsing
  - Call site tables, action tables, type tables
  - Try block and catch handler reconstruction
- [x] RTTI parsing
  - Location: `crates/hexray-analysis/src/rtti.rs`
  - Itanium C++ ABI typeinfo structure parsing
  - Single and virtual multiple inheritance support
  - Class hierarchy reconstruction

#### Phase 13: Platform Expansion ✅

**13.1 PE/COFF Format** ✅
- Location: `crates/hexray-formats/src/pe/`
- PE32 and PE32+ (64-bit) support
- Import and export table parsing
- Section handling with RVA conversion
- Architecture detection (x86, x64, ARM64)

#### Phase 13.5: Testing Infrastructure ✅

**CI/CD Pipeline** ✅
- Location: `.github/workflows/`
- GitHub Actions with multi-OS testing (Ubuntu, macOS)
- MSRV verification (Rust 1.70)
- Code coverage with cargo-llvm-cov and Codecov
- Clippy linting and format checking

**Benchmarking** ✅
- Location: `crates/*/benches/`
- Criterion benchmarks for disassembly throughput
- CFG construction and decompilation benchmarks
- Regression detection with `scripts/bench-regression.sh`
- PR benchmark comparison workflow

**Test Coverage** ✅
- Unit tests across all crates (800+ tests)
- Property-based testing with proptest
- Differential testing against system tools (objdump, nm, strings)
- Snapshot testing for CLI output stability
- Cross-crate integration tests

#### Phase 11.5: Interactive Analysis Database ✅

**Location:** `crates/hexray/src/session.rs`

**Features implemented:**
- Interactive REPL with rustyline (readline support, history navigation)
- SQLite-based session persistence (.hrp files)
- Binary hash verification (SHA256)
- Command history with outputs saved between sessions
- Annotations: function/variable renaming, comments, bookmarks, tags
- Undo/redo for all annotation changes
- Pager integration (`less`) for long outputs
- Session management (create, resume, list, info, export)

**REPL commands:**
- `help` - Show available commands
- `disasm <addr> [count]` - Disassemble instructions
- `func <addr|name>` - Analyze function
- `xrefs <addr>` - Show cross-references
- `strings [min_len]` - Detect strings
- `rename <addr> <name>` - Rename function/variable
- `comment <addr> <text>` - Add comment
- `bookmark <addr> [name]` - Add bookmark
- `delete <kind> <addr>` - Delete annotation (rename, comment, bookmark)
- `bookmarks`, `renames`, `comments` - List annotations
- `undo` - Undo last annotation change
- `redo` - Redo last undone change
- `history [n]` - Show command history
- `recall <n>` - Recall output from history
- `stats` - Session statistics

**CLI commands:**
```bash
hexray session new <binary> --output project.hrp
hexray session resume project.hrp
hexray session list <directory>
hexray session info project.hrp
hexray session export project.hrp --format json
```

---

## Remaining Work

### Phase 14: User Interface
**Status:** Future

- GUI/TUI interface (ratatui for TUI, egui for GUI)
- Plugin system (dynamic loading, Lua/Python scripting)
- Remote debugging protocol integration
- Collaborative analysis (server mode)

---

## Project Structure

```
hexray/
├── crates/
│   ├── hexray/              # CLI application
│   ├── hexray-core/         # Core types (Instruction, CFG, etc.)
│   ├── hexray-formats/      # ELF, Mach-O, PE parsers + DWARF
│   ├── hexray-disasm/       # Architecture decoders (x86_64, ARM64, RISC-V)
│   ├── hexray-analysis/     # CFG, decompiler, data flow, xrefs
│   ├── hexray-demangle/     # C++/Rust symbol demangling
│   ├── hexray-signatures/   # Function signature matching
│   ├── hexray-types/        # C type libraries
│   └── hexray-emulate/      # Static emulation
├── fuzz/                    # Fuzz testing targets
└── docs/                    # Documentation
```

---

## Contributing

When contributing to hexray, please:

1. Check this roadmap for planned features before starting new work
2. Open an issue to discuss significant changes
3. Follow the existing code style and architecture patterns
4. Add tests for new functionality
5. Update relevant documentation

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).
