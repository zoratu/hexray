# Devirtualization Examples

This guide shows how to resolve virtual call targets with `DevirtualizationAnalysis`.

## 1) Create analysis context

```rust
use hexray_analysis::{DevirtualizationAnalysis, RttiDatabase, VtableDatabase};
use std::sync::Arc;

let vtables = Arc::new(VtableDatabase::new());
let rtti: Option<Arc<RttiDatabase>> = None;

let mut devirt = DevirtualizationAnalysis::new(vtables, rtti)
    .with_pointer_size(8);
```

## 2) Analyze a call site

```rust
use hexray_analysis::{DevirtualizationAnalysis, ObjectLocation, VirtualCallSite};
use hexray_core::BasicBlockId;

fn analyze_site(devirt: &mut DevirtualizationAnalysis) {
    let call = VirtualCallSite {
        address: 0x401234,
        block_id: BasicBlockId(3),
        object_location: ObjectLocation::Register("rdi".into()),
        object_type: Some("Derived".into()),
        vtable_addr: None,
        possible_implementations: vec![],
        method_offset: 0x10,
        method_index: 2,
        confidence: hexray_analysis::DevirtConfidence::Medium,
    };

    if let Some(result) = devirt.analyze_call(&call) {
        println!("resolved methods: {}", result.possible_methods.len());
    }
}
```

## 3) Reuse the database for reporting

```rust
use hexray_analysis::DevirtualizationDatabase;

let mut db = DevirtualizationDatabase::new();

if let Some(result) = devirt.analyze_call(&call_site) {
    db.add_result(&result);
}

println!("tracked call sites: {}", db.call_count());
```

## 4) Query methods for a class+slot

```rust
fn methods_for_slot(db: &hexray_analysis::DevirtualizationDatabase) {
    let methods = db.get_methods("Derived", 2);
    for m in methods {
        println!("{} @ {:#x}", m.name.clone().unwrap_or_default(), m.address);
    }
}
```

## 5) Operational notes

- Prefer RTTI-enabled runs when available for tighter confidence.
- Cache method-slot lookups if processing many call sites.
- Emit confidence into output so downstream tools can gate low-confidence devirtualizations.
