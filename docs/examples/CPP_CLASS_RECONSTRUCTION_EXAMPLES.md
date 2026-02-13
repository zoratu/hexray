# C++ Class Reconstruction Examples

This guide covers `ClassReconstructor` usage to rebuild class layouts from vtables/RTTI.

## 1) Construct reconstructor with optional RTTI

```rust
use hexray_analysis::{ClassReconstructor, RttiDatabase, VtableDatabase};
use std::sync::Arc;

let vtables = Arc::new(VtableDatabase::new());
let rtti: Option<Arc<RttiDatabase>> = None;

let reconstructor = ClassReconstructor::new(vtables, rtti)
    .with_pointer_size(8)
    .with_symbols(vec![
        (0x1000, "_ZN4Base3fooEv".to_string()),
        (0x2000, "_ZN7Derived3barEv".to_string()),
    ]);
```

## 2) Reconstruct all classes and compute stats

```rust
use hexray_analysis::{ClassReconstructor, ReconstructionStats};

fn summarize(reconstructor: &ClassReconstructor) -> ReconstructionStats {
    let classes = reconstructor.reconstruct_all();
    reconstructor.compute_stats(&classes)
}
```

## 3) Export reconstructed model as headers

```rust
use hexray_analysis::{ReconstructedClassDatabase};

fn export_header(classes: Vec<hexray_analysis::ReconstructedClass>) -> String {
    let db = ReconstructedClassDatabase::from_classes(classes);
    db.to_cpp_header()
}
```

## 4) Lookups by vtable/typeinfo/name

```rust
use hexray_analysis::ReconstructedClassDatabase;

fn inspect(db: &ReconstructedClassDatabase) {
    if let Some(cls) = db.get_by_vtable(0x404000) {
        println!("class by vtable: {}", cls.name);
    }
    if let Some(cls) = db.get_by_typeinfo(0x406000) {
        println!("class by RTTI: {}", cls.name);
    }
    if let Some(cls) = db.get_by_name("Derived") {
        println!("methods: {}", cls.methods.len());
    }
}
```

## 5) Practical notes

- `with_symbols` materially improves method naming quality.
- RTTI is optional but increases confidence in inheritance links.
- `to_cpp_header()` is the fastest way to snapshot reconstruction quality in tests.
