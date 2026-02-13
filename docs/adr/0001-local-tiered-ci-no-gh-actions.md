# ADR 0001: Local Tiered CI Without GitHub Actions

- Status: Accepted
- Date: 2026-02-13

## Context

The project requires strong pre-commit/pre-push quality gates while avoiding recurring GitHub Actions costs. The team also wants predictable behavior across developer machines and containerized runners.

## Decision

Adopt local, script-driven tiers as the canonical workflow:

- `pre-commit` hook runs fast checks.
- `pre-push` hook runs medium checks (including decompiler quality smoke).
- `scripts/ci-local --tier full` runs full validation, optionally with deterministic perf checks.

No hosted CI workflow files are required for baseline repository quality enforcement.

## Consequences

Positive:
- No GH Actions spend for regular development.
- Single source of truth in repo (`scripts/ci-local`, hooks).
- Developers can reproduce checks locally before push.

Tradeoffs:
- Enforcement depends on local hook installation policy.
- Long-running checks still consume local compute.
- External branch protection must rely on alternate runner infrastructure if required later.
