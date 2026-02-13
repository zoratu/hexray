# Analyzing a C++ Binary

This tutorial walks through a C++-focused workflow with vtables, RTTI, and exception metadata.

## 1) Start with symbols and demangled names

```bash
./target/release/hexray ./app_cpp.bin symbols
```

Look for constructors/destructors (`::ClassName`, `~ClassName`) and vtable/typeinfo symbols.

## 2) Find class-like call patterns

```bash
./target/release/hexray ./app_cpp.bin decompile 0x401000
```

Signals to look for:
- writes of a vtable pointer into `this`
- indirect calls through table slots
- `this` propagation across wrapper functions

## 3) Inspect callgraph around constructors/destructors

```bash
./target/release/hexray ./app_cpp.bin callgraph --format json > callgraph.json
```

Filter around ctor/dtor nodes to identify initialization/finalization chains.

## 4) Recover exception-related behavior

If binary has EH data (`.eh_frame`, `.gcc_except_table`), decompiled output may include try/catch annotations when exception info is wired into the decompiler API.

Use API-level extraction from `hexray_analysis::ExceptionExtractor` to map:
- try ranges
- landing pads
- catch type names (RTTI-enhanced when available)

## 5) Reconstruct class layouts (API)

Use:
- `ClassReconstructor` for class model inference
- `ReconstructedClassDatabase::to_cpp_header()` for a header-style snapshot
- `DevirtualizationAnalysis` for virtual-call target candidates

## 6) Regression checks for C++ analysis work

```bash
scripts/ci-local --tier medium --no-cross
cargo test -p hexray-analysis class_reconstruction -- --nocapture
cargo test -p hexray-analysis devirtualization -- --nocapture
```

## Practical caveats

- Stripped binaries reduce naming quality but not structural detection.
- RTTI availability strongly affects devirtualization confidence.
- Multiple inheritance introduces `this` adjustment thunks; verify these paths explicitly.
