# Architecture Overview

hexray is organized as a Cargo workspace with multiple crates, each handling a specific responsibility.

## Crate Dependency Graph

```
hexray (CLI)
    ├── hexray-analysis
    │   └── hexray-core
    ├── hexray-formats
    │   └── hexray-core
    ├── hexray-disasm
    │   └── hexray-core
    └── hexray-demangle
```

## Crates

### hexray-core

Core abstractions shared across all crates.

**Key Types:**
- `Instruction` - Architecture-agnostic instruction representation
- `Operand` - Instruction operands (registers, immediates, memory)
- `Operation` - Semantic operation type (Add, Sub, Move, Call, etc.)
- `BasicBlock` - A sequence of instructions with single entry/exit
- `ControlFlowGraph` - Graph of basic blocks with edges
- `Symbol` - Binary symbol with name, address, type

```rust
pub struct Instruction {
    pub address: u64,
    pub size: usize,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: Vec<Operand>,
    pub operation: Operation,
    pub control_flow: ControlFlow,
}
```

### hexray-formats

Binary format parsers (ELF, Mach-O).

**Key Traits:**
```rust
pub trait BinaryFormat {
    fn architecture(&self) -> Architecture;
    fn entry_point(&self) -> Option<u64>;
    fn symbols(&self) -> Box<dyn Iterator<Item = &Symbol>>;
    fn sections(&self) -> Box<dyn Iterator<Item = &dyn Section>>;
    fn bytes_at(&self, addr: u64, len: usize) -> Option<&[u8]>;
}
```

**Supported Formats:**
- ELF (32/64-bit, little/big endian)
- Mach-O (32/64-bit, universal/fat binaries)
- PE (Windows PE32/PE32+, executables and DLLs)

### hexray-disasm

Architecture-specific instruction decoders.

**Key Trait:**
```rust
pub trait Disassembler {
    fn decode(&self, bytes: &[u8], address: u64) -> Result<Instruction, DecodeError>;
    fn min_instruction_size(&self) -> usize;
    fn max_instruction_size(&self) -> usize;
}
```

**Supported Architectures:**
- x86_64 (variable length, 1-15 bytes)
- ARM64 (fixed 32-bit instructions)
- RISC-V (32-bit base, 16-bit compressed)

### hexray-analysis

Analysis passes and decompilation.

**Components:**
- `CfgBuilder` - Constructs CFG from linear instruction stream
- `FunctionFinder` - Identifies function boundaries
- `Decompiler` - Transforms CFG to pseudo-code
- `Structurer` - Recovers high-level control flow (if/else, loops)

**Data Flow Analysis (`dataflow` module):**
- `Location` - Represents registers, stack slots, memory locations
- `ReachingDefinitions` - Forward analysis: which defs reach each point
- `LivenessAnalysis` - Backward analysis: which values are live
- `DefUseChain` - Links definitions to their uses

**SSA Form (`ssa` module):**
- `SsaBuilder` - Converts CFG to SSA form
- `SsaValue` - Versioned value (e.g., `rax_1`, `rax_2`)
- `PhiNode` - Merges values at control flow join points
- `SsaFunction` - SSA representation of a function

**Type Inference (`types` module):**
- `Type` - Type representation (int, pointer, struct, etc.)
- `TypeInference` - Constraint-based type recovery engine
- `FunctionSignatures` - Known function prototypes

**Decompilation Pipeline:**
```
Instructions → CFG → SSA → Data Flow → Type Inference → Structured CFG → Expressions → Pseudo-code
```

### hexray-demangle

Symbol name demangling.

**Supported Schemes:**
- Itanium C++ ABI (GCC, Clang)
- Rust v0 mangling scheme

## Data Flow

```
Binary File (ELF/Mach-O/PE)
    ↓
┌─────────────────────────────────────┐
│         hexray-formats              │
│  (ELF/Mach-O/PE parsing, symbols)   │
└─────────────────────────────────────┘
    ↓ bytes, symbols
┌─────────────────────────────────────┐
│         hexray-disasm               │
│  (x86_64/ARM64/RISC-V decoding)     │
└─────────────────────────────────────┘
    ↓ Instructions
┌─────────────────────────────────────┐
│         hexray-analysis             │
│  ┌─────────────────────────────┐    │
│  │ CFG Construction            │    │
│  └─────────────────────────────┘    │
│              ↓                      │
│  ┌─────────────────────────────┐    │
│  │ SSA Conversion (phi nodes)  │    │
│  └─────────────────────────────┘    │
│              ↓                      │
│  ┌─────────────────────────────┐    │
│  │ Data Flow Analysis          │    │
│  │ (reaching defs, liveness)   │    │
│  └─────────────────────────────┘    │
│              ↓                      │
│  ┌─────────────────────────────┐    │
│  │ Type Inference              │    │
│  └─────────────────────────────┘    │
│              ↓                      │
│  ┌─────────────────────────────┐    │
│  │ Structuring & Decompilation │    │
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
    ↓ Pseudo-code
┌─────────────────────────────────────┐
│         hexray (CLI)                │
│  (user interface, output)           │
└─────────────────────────────────────┘
```

## Adding a New Architecture

1. Create a new module in `hexray-disasm/src/`
2. Implement the `Disassembler` trait
3. Add architecture detection in `hexray-formats`
4. Register in the CLI dispatcher

Example decoder structure:
```rust
pub struct MyArchDisassembler;

impl Disassembler for MyArchDisassembler {
    fn decode(&self, bytes: &[u8], address: u64) -> Result<Instruction, DecodeError> {
        // Decode bytes into Instruction
    }

    fn min_instruction_size(&self) -> usize { 2 }
    fn max_instruction_size(&self) -> usize { 4 }
}
```

## Adding a New Binary Format

1. Create a new module in `hexray-formats/src/`
2. Implement the `BinaryFormat` trait
3. Add format detection in `detect_format()`
4. Export from `lib.rs`
