# Module Dependency Diagrams

This page summarizes crate-level and analysis-layer dependencies.

## Crate-level overview

```mermaid
graph TD
  A[hexray CLI] --> B[hexray-analysis]
  A --> C[hexray-disasm]
  A --> D[hexray-formats]
  A --> E[hexray-core]
  A --> F[hexray-signatures]
  A --> G[hexray-types]
  A --> H[hexray-emulate]
  B --> C
  B --> D
  B --> E
  B --> F
  B --> G
  H --> E
  C --> E
  D --> E
```

## `hexray-analysis` internals (high-level)

```mermaid
graph LR
  A[cfg_builder] --> B[dataflow]
  B --> C[ssa]
  C --> D[decompiler]
  D --> E[output]
  F[vtable] --> G[class_reconstruction]
  H[rtti] --> G
  F --> I[devirtualization]
  H --> I
  J[analysis_cache] --> D
  K[incremental] --> J
  K --> A
  K --> L[callgraph]
  M[exception_handling] --> D
```

## Notes

- `analysis_cache` and `incremental` are cross-cutting and intentionally reused by multiple workflows.
- `devirtualization`, `class_reconstruction`, and `exception_handling` feed decompiler quality for C++ targets.
- Dependency direction is logical usage, not exhaustive Rust import graph detail.
