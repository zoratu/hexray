# Getting Started with hexray

This tutorial covers the basic CLI flow from first build to first decompilation.

## Prerequisites

- Rust toolchain (`cargo` available)
- A sample ELF, Mach-O, or PE binary

## 1) Build

```bash
git clone https://github.com/zoratu/hexray.git
cd hexray
cargo build --release
```

Binary path: `target/release/hexray`.

## 2) Inspect file metadata

```bash
./target/release/hexray ./sample.bin info
./target/release/hexray ./sample.bin sections
```

Use this to confirm architecture and section layout before deeper analysis.

## 3) Enumerate symbols and functions

```bash
./target/release/hexray ./sample.bin symbols --functions
```

If the binary is stripped, you can still use addresses with most commands.

## 4) Disassemble and decompile a target

```bash
./target/release/hexray ./sample.bin -s main
./target/release/hexray ./sample.bin decompile main
./target/release/hexray ./sample.bin decompile 0x401000
```

## 5) Explore CFG, callgraph, strings, xrefs

```bash
./target/release/hexray ./sample.bin cfg main
./target/release/hexray ./sample.bin callgraph --format dot
./target/release/hexray ./sample.bin strings
./target/release/hexray ./sample.bin xrefs 0x401000
```

## 6) Validate local changes quickly

```bash
scripts/ci-local --tier fast
scripts/quality-smoke
```

## Next tutorial

Proceed to [Analyzing a C++ Binary](ANALYZING_CPP_BINARY.md).
