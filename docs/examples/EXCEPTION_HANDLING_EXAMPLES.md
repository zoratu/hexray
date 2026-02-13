# Exception Handling Extraction Examples

This guide covers `ExceptionExtractor` and high-level helpers for EH metadata.

## 1) Build extractor from parsed sections

```rust
use hexray_analysis::ExceptionExtractor;

let eh_frame = std::fs::read("fixtures/eh_frame.bin")?;
let eh_frame_hdr = std::fs::read("fixtures/eh_frame_hdr.bin")?;
let gcc_except_table = std::fs::read("fixtures/gcc_except_table.bin")?;

let extractor = ExceptionExtractor::from_sections(
    &eh_frame,
    Some(&eh_frame_hdr),
    Some(&gcc_except_table),
)?;
# Ok::<(), hexray_analysis::ExceptionError>(())
```

## 2) Query exception info for a function range

```rust
fn query(extractor: &hexray_analysis::ExceptionExtractor, start: u64, end: u64) {
    if let Some(info) = extractor.get_exception_info(start, end) {
        println!(
            "try_blocks={} cleanups={}",
            info.try_blocks.len(),
            info.cleanup_handlers.len()
        );
    }
}
```

## 3) Use RTTI-aware extraction when available

```rust
use hexray_analysis::{ExceptionExtractor, RttiDatabase};

fn query_with_rtti(
    extractor: &ExceptionExtractor,
    rtti: &RttiDatabase,
    start: u64,
    end: u64,
) {
    if let Some(info) = extractor.get_exception_info_with_rtti(start, end, rtti) {
        for tb in info.try_blocks {
            for handler in tb.handlers {
                if let Some(ty) = handler.catch_type {
                    println!("catch type: {ty}");
                }
            }
        }
    }
}
```

## 4) Batch extract across binary

```rust
use hexray_analysis::extract_all_exception_info;

fn batch<B: hexray_formats::BinaryFormat>(bin: &B) {
    if let Ok(all) = extract_all_exception_info(bin) {
        println!("functions with EH: {}", all.len());
    }
}
```

## 5) Integration with decompiler

Use extracted `ExceptionInfo` with decompiler:

```rust
use hexray_analysis::Decompiler;

fn attach_eh(info: hexray_analysis::ExceptionInfo) -> Decompiler {
    Decompiler::new().with_exception_info(info)
}
```
