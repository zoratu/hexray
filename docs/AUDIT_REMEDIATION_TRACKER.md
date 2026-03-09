# Audit Remediation Tracker

This tracker records the issues found during the March 2026 audit and the branch
used to address each one. An item stays open until code, tests, and the relevant
verification command all pass.

| Finding | Status | Branch |
|---------|--------|--------|
| Feature matrix is not enforced for `hexray-disasm` non-default architectures | Resolved | `pr/feature-gates-security` |
| Missing explicit coverage/security gate in local CI | Resolved | `pr/feature-gates-security` |
| Missing explicit fuzz-target compile gate in local CI | Resolved | `pr/feature-gates-security` |
| Missing property-based coverage in `hexray-types` and `hexray-signatures` | Resolved | `pr/feature-gates-security` |
| Missing fuzz targets for `pe`, `dwarf`, `hexray-types`, and `hexray-signatures` | Resolved | `pr/feature-gates-security` |
| Missing cache-persistence failure injection outside the emulator | Resolved | `pr/feature-gates-security` |
| Missing crate-level `unsafe` policy despite no first-party `unsafe` usage | Resolved | `pr/feature-gates-security` |
| Mach-O parser accepts load commands beyond declared `sizeofcmds` and tests mask panics | Open | `pr/macho-hardening` |
| Missing parser truncation/fault-injection coverage for Mach-O load command bounds | Open | `pr/macho-hardening` |
| Incremental invalidation is unsound for insertions/size shifts and lacks a formal model | Open | `pr/incremental-tla` |
| Missing incremental adversarial coverage for shifted-layout patches | Open | `pr/incremental-tla` |
| Missing formal model artifact and code-to-model check step | Open | `pr/incremental-tla` |

## Verification Loop

Each branch follows the same closeout loop:

1. Reproduce the issue or the missing gate.
2. Patch code and tests.
3. Run the branch-local verification commands.
4. Review the diff as a PR.
5. Merge only when the item can be marked resolved.

## Latest Verification

- `scripts/ci-local --tier medium --no-quality-smoke`: passed
- `scripts/check-security`: passed
- `scripts/check-coverage`: passed with `TOTAL` line coverage `71.68%`
