# hexray

A multi-architecture disassembler and decompiler written in Rust from scratch by GenAI for educational purposes.

## Features

- **Multi-architecture support**: x86_64, ARM64, RISC-V (32/64-bit)
- **Multiple binary formats**: ELF (Linux), Mach-O (macOS/iOS), PE (Windows)
- **Decompilation**: Generates readable pseudo-code from machine code
- **Control flow analysis**: Basic block detection, CFG construction
- **Data flow analysis**: Reaching definitions, liveness analysis, def-use chains
- **SSA form**: Static Single Assignment conversion with phi nodes
- **Type inference**: Constraint-based type recovery for integers, pointers, and structures
- **Symbol resolution**: Function names displayed in disassembly and decompiled output
- **String detection**: Automatically resolves string literals in decompiled code
- **Built from scratch**: No external disassembler libraries - pure Rust implementation

## Installation

### From Source

```bash
git clone https://github.com/zoratu/hexray.git
cd hexray
cargo build --release
```

The binary will be at `target/release/hexray`.

### Development Build

```bash
cargo build
cargo run -- <binary> [command]
```

## Usage

### Basic Disassembly

Disassemble a function by symbol name:

```bash
hexray ./binary -s main
```

Disassemble at a specific address:

```bash
hexray ./binary -a 0x401000
```

Control the number of instructions:

```bash
hexray ./binary -s main -c 50
```

### Commands

#### `info` - Show Binary Information

Display header information about the binary:

```bash
hexray ./binary info
```

Output:
```
Binary Information
==================
Format:        ELF
Architecture:  X86_64
Endianness:    Little
Bitness:       Bits64
Type:          Executable
Entry Point:   0x401000
Sections:      5
Segments:      1
Symbols:       4
```

#### `sections` - List Sections

Show all sections in the binary:

```bash
hexray ./binary sections
```

Output:
```
Idx  Name                     Address          Size             Flags
---------------------------------------------------------------------------
0                             0x00000000000000 0x00000000000000 ---
1    .text                    0x00000000401000 0x00000000000028 A-X
2    .symtab                  0x00000000000000 0x00000000000060 ---
3    .strtab                  0x00000000000000 0x00000000000014 ---
```

#### `symbols` - List Symbols

Show all symbols:

```bash
hexray ./binary symbols
```

Show only function symbols:

```bash
hexray ./binary symbols --functions
```

Output:
```
Address          Size     Type     Bind     Name
----------------------------------------------------------------------
0x00000000401000 15       FUNC     GLOBAL   _start
0x0000000040100f 14       FUNC     GLOBAL   main
0x0000000040101d 11       FUNC     GLOBAL   helper
```

#### `cfg` - Control Flow Graph

Disassemble a function and show its control flow graph:

```bash
hexray ./binary cfg main
```

#### `decompile` - Decompile to Pseudo-code

Decompile a function to readable pseudo-code:

```bash
hexray ./binary decompile main
```

Output:
```
Decompiling main at 0x40100f

void main()
{
    // bb0 [0x40100f - 0x401018]
    push(rbp);
    rbp = rsp;
    helper();
    // bb1 [0x401018 - 0x40101d]
    eax = eax + 0xa;
    pop(rbp);
    return;
}
```

Hide address comments:

```bash
hexray ./binary decompile main --no-addresses
```

Decompile by address:

```bash
hexray ./binary decompile 0x401000
```

## Examples

### Disassemble an x86_64 ELF Binary

```bash
# Show binary info
hexray /usr/bin/ls info

# List functions
hexray /usr/bin/ls symbols --functions

# Disassemble main
hexray /usr/bin/ls -s main

# Decompile main
hexray /usr/bin/ls decompile main
```

### Disassemble a macOS Mach-O Binary

```bash
# Show binary info
hexray /bin/echo info

# List functions
hexray /bin/echo symbols --functions

# Decompile a function
hexray /bin/echo decompile _main
```

### Analyze an ARM64 Binary

```bash
# Disassemble
hexray ./arm64_binary -s main

# Decompile
hexray ./arm64_binary decompile main
```

### Analyze a Windows PE Binary

```bash
# Show binary info
hexray ./program.exe info

# List exports
hexray ./program.exe symbols --functions

# Decompile
hexray ./program.exe decompile main
```

## Supported Architectures

| Architecture | Disassembly | Decompilation | Notes |
|--------------|-------------|---------------|-------|
| x86_64       | ✅          | ✅            | Full support |
| ARM64        | ✅          | ✅            | AArch64 |
| RISC-V 64    | ✅          | ✅            | RV64I |
| RISC-V 32    | ✅          | ✅            | RV32I |
| x86 (32-bit) | Partial     | Partial       | Basic support |

## Supported Formats

| Format | Read | Symbols | Notes |
|--------|------|---------|-------|
| ELF    | ✅   | ✅      | Linux executables, shared libraries |
| Mach-O | ✅   | ✅      | macOS/iOS executables |
| Fat/Universal | ✅ | ✅   | Multi-arch Mach-O binaries |
| PE     | ✅   | ✅      | Windows executables and DLLs (PE32/PE32+) |

## Project Structure

```
hexray/
├── Cargo.toml                 # Workspace configuration
├── crates/
│   ├── hexray/                # CLI application
│   ├── hexray-core/           # Core types (Instruction, BasicBlock, CFG)
│   ├── hexray-formats/        # Binary format parsers (ELF, Mach-O)
│   ├── hexray-disasm/         # Architecture decoders (x86_64, ARM64, RISC-V)
│   ├── hexray-analysis/       # CFG builder, decompiler, data flow, SSA, types
│   └── hexray-demangle/       # C++/Rust symbol demangling
└── tests/fixtures/            # Test binaries
```

## Building Test Binaries

Create test ELF binaries:

```bash
python3 tests/fixtures/elf/create_elf_with_symbols.py
```

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

## Limitations

- Decompiler output is pseudo-code, not valid C
- Complex control flow (goto, switch statements) may not structure perfectly
- Type inference is basic (integers, pointers, simple structs)
- No switch statement recovery yet

## License

MIT License

## Acknowledgments

Built as an educational project to understand:
- Binary file formats (ELF, Mach-O)
- Instruction set architectures (x86_64, ARM64, RISC-V)
- Control flow analysis and decompilation techniques
