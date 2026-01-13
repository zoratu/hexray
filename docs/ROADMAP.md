# Hexray Roadmap

This document outlines the development roadmap, competitive analysis, and planned features for hexray.

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
| FLIRT/signatures | ✅ | ✅ | ✅ | ❌ Planned |
| Type libraries | ✅ | ✅ | ✅ | ❌ Planned |
| DWARF debug info | ✅ | ✅ | ✅ | ❌ Planned |
| Data flow queries | ✅ | ✅ | ✅ | ❌ Planned |
| Emulation | ✅ | ✅ | ✅ | ❌ Planned |
| **Interactive** |
| Annotations/comments | ✅ | ✅ | ✅ | ❌ Planned |
| Undo/redo | ✅ | ✅ | ✅ | ❌ Planned |
| Project files | ✅ | ✅ | ✅ | ❌ Planned |
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

### Completed Features

- Multi-architecture disassembly (x86_64, ARM64, RISC-V)
- Multiple binary formats (ELF, Mach-O, PE)
- Control flow graph construction
- SSA-based decompiler with control flow structuring
- Cross-reference analysis
- String detection and annotation
- Type inference (integers, pointers, floats, structs)
- Symbol demangling (C++, Rust)
- Multiple output formats (text, JSON, DOT, HTML)
- Parallel disassembly

---

## Planned Features

### Phase 1: Debug Info & Extended Coverage

#### DWARF Debug Info Parsing

**New files:**
```
crates/hexray-formats/src/dwarf/
    mod.rs           - Module root, public API
    leb128.rs        - LEB128 encoding/decoding
    abbrev.rs        - Abbreviation table parsing (.debug_abbrev)
    die.rs           - Debug Information Entry parsing
    line.rs          - Line number program (.debug_line)
    info.rs          - Compilation units (.debug_info)
    types.rs         - DWARF type representation
```

**Key structures:**
- `DebugInfo` - Parsed DWARF data
- `LineNumberTable` - Address → source location mapping
- `DebugInfoTable` - Bridge to decompiler for variable names

**Files to modify:**
- `crates/hexray-formats/src/elf/mod.rs` - Add debug_info() method
- `crates/hexray-analysis/src/decompiler/emitter.rs` - Use DWARF variable names

---

### Phase 2: Competitive Feature Parity

#### Function Signature Recognition (FLIRT-like)

**Goal:** Automatically identify standard library functions without symbols.

**New crate:** `hexray-signatures`
```
crates/hexray-signatures/
    Cargo.toml
    src/
        lib.rs           - Public API
        pattern.rs       - Byte pattern with wildcards
        matcher.rs       - Pattern matching engine
        database.rs      - Signature database format
        generators/
            mod.rs
            libc.rs      - Generate signatures from libc
            libcxx.rs    - Generate signatures from libstdc++
```

**Key structures:**
```rust
pub struct FunctionSignature {
    pub name: String,
    pub pattern: BytePattern,       // First N bytes with wildcards
    pub size_hint: Option<usize>,
    pub calling_convention: CallingConvention,
    pub return_type: Option<Type>,
    pub parameters: Vec<Parameter>,
    pub library: String,            // "glibc-2.31", "musl-1.2"
}

pub struct BytePattern {
    bytes: Vec<PatternByte>,  // Concrete(u8) | Wildcard | MaskedWildcard
}
```

**Implementation steps:**
1. Define byte pattern format with wildcards
2. Build pattern matcher (prefix tree for efficiency)
3. Create signature database format (YAML, optimize to binary later)
4. Generate initial signatures for common libc functions
5. Integrate into analysis pipeline
6. CLI: `hexray signatures <binary>`

---

#### Type Libraries & Header Parsing

**Goal:** Load C/C++ type definitions for accurate struct layouts.

**New crate:** `hexray-types`
```
crates/hexray-types/
    Cargo.toml
    src/
        lib.rs           - Public API
        parser.rs        - C header parser (simplified)
        types.rs         - Type representation
        database.rs      - Type database with lookup
        builtin/
            mod.rs
            posix.rs     - POSIX types
            linux.rs     - Linux-specific
            darwin.rs    - macOS-specific
```

**Key structures:**
```rust
pub enum CType {
    Void,
    Int { signed: bool, bits: u8 },
    Float { bits: u8 },
    Pointer(Box<CType>),
    Array { element: Box<CType>, size: Option<usize> },
    Struct(StructType),
    Union(UnionType),
    Enum(EnumType),
    Function(FunctionType),
    Typedef { name: String, target: Box<CType> },
}

pub struct FunctionPrototype {
    pub name: String,
    pub return_type: CType,
    pub parameters: Vec<(String, CType)>,
    pub variadic: bool,
}
```

**Builtin types to include:**
- Standard C: `size_t`, `ptrdiff_t`, `FILE`
- POSIX: `pid_t`, `uid_t`, `struct stat`, `struct sockaddr`
- Linux syscalls: `struct iovec`, `struct pollfd`

---

#### Data Flow Queries (Watchpoint-style Analysis)

**Goal:** Answer "where does this value come from?" and "where does this value go?"

**New module:** `hexray-analysis/src/dataflow/queries.rs`

**Key structures:**
```rust
pub enum DataFlowQuery {
    TraceBackward { address: u64, operand_index: usize },
    TraceForward { address: u64, operand_index: usize },
    FindUses { def_address: u64, register: Register },
    FindDefs { use_address: u64, register: Register },
}

pub struct DataFlowResult {
    pub query: DataFlowQuery,
    pub chain: Vec<DataFlowStep>,
}
```

**Implementation steps:**
1. Build on existing def-use chains and reaching definitions
2. Implement backward slice: find all contributing definitions
3. Implement forward slice: find all uses of a definition
4. Handle inter-procedural flow
5. CLI: `hexray trace --backward 0x1234:0`
6. CLI: `hexray trace --forward 0x1234:rax`

---

#### Static Emulation / Symbolic Execution

**Goal:** Resolve indirect calls/jumps without running.

**New crate:** `hexray-emulate`
```
crates/hexray-emulate/
    Cargo.toml
    src/
        lib.rs           - Public API
        state.rs         - Machine state (registers, memory, flags)
        executor.rs      - Instruction interpreter
        symbolic.rs      - Symbolic values and constraints
        solver.rs        - Constraint solver
        x86_64.rs        - x86_64 semantics
        arm64.rs         - ARM64 semantics
```

**Use cases:**
- Resolve jump tables: `jmp [rax*8 + table]`
- Resolve virtual calls: `call [rax + vtable_offset]`
- Trace string construction

**Complexity notes:**
- Start with concrete execution only
- Add symbolic execution incrementally
- Focus on common patterns first

---

#### Interactive Analysis Database

**Goal:** Persist user annotations and type overrides.

**New module:** `hexray-analysis/src/project.rs`

**Key structures:**
```rust
pub struct AnalysisProject {
    pub binary_path: PathBuf,
    pub binary_hash: [u8; 32],
    pub annotations: HashMap<u64, Annotation>,
    pub function_overrides: HashMap<u64, FunctionOverride>,
    pub type_overrides: HashMap<u64, TypeOverride>,
    pub comments: HashMap<u64, String>,
    pub bookmarks: Vec<Bookmark>,
    pub history: Vec<HistoryEntry>,  // For undo/redo
}
```

**CLI commands:**
- `hexray project create <binary> --output project.hrp`
- `hexray project annotate 0x1234 --name "process_input"`
- `hexray project comment 0x1234 "Validates user input"`

---

### Priority Order

```
                    ┌─────────────────────┐
                    │  Project Database   │ (can start anytime)
                    └─────────────────────┘
                              │
    ┌─────────────────────────┼─────────────────────────┐
    │                         │                         │
    v                         v                         v
┌───────────┐         ┌───────────────┐         ┌───────────────┐
│ Signatures│         │ Type Libraries│         │ Data Flow     │
└───────────┘         └───────────────┘         └───────────────┘
    │                         │                         │
    └────────────┬────────────┘                         │
                 │                                      │
                 v                                      │
         ┌───────────────┐                             │
         │  Decompiler   │◄────────────────────────────┘
         │  Integration  │
         └───────────────┘
                 │
                 v
         ┌───────────────┐
         │  Emulation    │ (uses all above)
         └───────────────┘
```

**Recommended order:**
1. **Project DB** - Enables iterative analysis, no dependencies
2. **Type Libraries** - High impact on decompiler output
3. **Signatures** - Identifies unknown functions
4. **Data Flow Queries** - Builds on existing analysis
5. **Emulation** - Most complex, benefits from all above

---

### Phase 3: Advanced Decompilation

#### Control Flow Improvements
- Switch statement reconstruction (jump table detection)
- Loop canonicalization (do-while, for-loop detection)
- Short-circuit boolean optimization

#### Expression Quality
- Cast elimination where type is obvious
- Compound assignment detection (`x += 1`)
- Array access detection (`arr[i]` from pointer math)
- Struct field access (`s.field` from offset)

#### C++ Decompilation
- Virtual function table reconstruction
- Constructor/destructor identification
- Exception handling (try/catch from landing pads)
- RTTI parsing for class names

---

### Phase 4: Platform Expansion

#### PE/COFF Format (Windows)
```
crates/hexray-formats/src/pe/
    mod.rs           - PE parser
    header.rs        - DOS/PE/optional headers
    sections.rs      - Section table
    imports.rs       - Import directory
    exports.rs       - Export directory
    resources.rs     - Resource directory
    relocations.rs   - Base relocations
```

#### Windows Type Libraries
- Win32 API prototypes
- Windows structures (HANDLE, HWND, etc.)
- COM interface definitions

---

### Future Work

- GUI/TUI interface (ratatui for TUI, egui for GUI)
- Plugin system (dynamic loading, Lua/Python scripting)
- Remote debugging protocol integration
- Collaborative analysis (server mode)

---

## Contributing

When contributing to hexray, please:

1. Check this roadmap for planned features before starting new work
2. Open an issue to discuss significant changes
3. Follow the existing code style and architecture patterns
4. Add tests for new functionality
5. Update relevant documentation

For architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).
