# Incremental Invalidation Model

`IncrementalInvalidation.tla` models the conservative policy used for size-changing
patches in the incremental analyzer:

- same-size replacements invalidate only overlapping functions
- insertions, deletions, and size changes invalidate the containing function and
  every later function because addresses may shift
- after invalidation, the dependency tracker rewrites function intervals with a
  conservative interval transform

`scripts/check-tla` runs TLC on this model and then executes the matching Rust
conformance test in `hexray-analysis`.
