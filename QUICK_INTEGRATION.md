# Quick Integration Guide

## TL;DR

Add unreachable block removal to the decompiler in 2 steps:

### Step 1: Add Functions

In `crates/hexray-analysis/src/decompiler/structurer.rs`, find the line:
```rust
#[cfg(test)]
mod tests {
```

**Right before that line**, paste the 6 functions from `unreachable_block_removal.rs` or `UNREACHABLE_BLOCKS_PATCH.md`.

### Step 2: Call the Function

In the same file, find:
```rust
pub fn from_cfg_with_config(
    cfg: &ControlFlowGraph,
    config: &super::config::DecompilerConfig,
) -> Self {
    use super::config::OptimizationPass;

    let mut structurer = Structurer::new(cfg);
    let mut body = structurer.structure();
```

**Add this line right after** `structurer.structure()`:
```rust
    body = remove_unreachable_blocks(body);
```

### Step 3: Build and Test

```bash
cargo build --workspace
cargo test --package hexray-analysis --lib decompiler::structurer
```

## What This Does

Removes unreachable blocks like:
```c
return x;
bb4:
    goto bb2;  // ← These disappear
bb7:
    goto bb5;  // ← These disappear
```

## Files to Use

- **`unreachable_block_removal.rs`** - Contains all 6 functions
- **`UNREACHABLE_BLOCKS_PATCH.md`** - Complete patch with full context
- **`IMPLEMENTATION_SUMMARY.md`** - Detailed explanation of how it works

## If You Get Errors

1. Make sure `HashSet` is imported at the top:
   ```rust
   use std::collections::{HashMap, HashSet};
   ```

2. The functions use these existing functions (already in the file):
   - `body_terminates()`
   - `is_noreturn_call()`

3. If compilation fails, check that the function signatures match the existing `StructuredNode` enum

## Expected Result

**Before**: Cluttered output with unreachable labels
```c
return result;
bb10:
    goto bb8;
bb14:
    goto bb12;
```

**After**: Clean, readable code
```c
return result;
```

Done! 🎉
