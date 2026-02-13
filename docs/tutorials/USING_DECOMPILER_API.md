# Using the Decompiler API

This tutorial shows a minimal programmatic decompilation pipeline.

## 1) Add dependencies

```toml
[dependencies]
hexray-analysis = { path = "../crates/hexray-analysis" }
hexray-formats = { path = "../crates/hexray-formats" }
```

## 2) Build CFG and decompile

```rust
use hexray_analysis::{CfgBuilder, Decompiler, DecompilerConfig, OptimizationLevel};
use hexray_formats::elf::ElfFile;

let data = std::fs::read("sample.bin")?;
let _elf = ElfFile::parse(&data)?;

// Example function bytes/range selection is application-specific.
let func_addr = 0x401000;
let instructions = vec![]; // decoded instructions for target function

let cfg = CfgBuilder::new().build(&instructions, func_addr);

let config = DecompilerConfig::new(OptimizationLevel::Standard);
let decompiler = Decompiler::new().with_config(config).with_addresses(true);

let pseudocode = decompiler.decompile(&cfg, "sub_401000");
println!("{pseudocode}");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## 3) Improve output quality with optional context

Common enrichments:
- `.with_type_database(...)`
- `.with_summary_database(...)`
- `.with_dwarf_names(...)`
- `.with_string_table(...)`
- `.with_symbol_table(...)`
- `.with_exception_info(...)`

## 4) Quality scoring and regression checks

For structured-output quality checks, run benchmark harnesses in `hexray_analysis::decompiler::benchmark` and keep fixture-backed checks in CI (`scripts/quality-smoke`).

## 5) API-level debugging checklist

- Confirm decoded instruction count and addresses.
- Confirm CFG entry node and outgoing edges.
- Compare output with and without aggressive optimization.
- Keep deterministic inputs for regression snapshots.
