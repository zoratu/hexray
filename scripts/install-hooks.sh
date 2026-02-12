#!/bin/bash
# Install git hooks for tiered local CI workflows.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ ! -d "$REPO_ROOT/.git/hooks" ]]; then
    echo "ERROR: .git/hooks not found. Run this script from a git checkout." >&2
    exit 1
fi

echo "Installing git hooks..."

cp "$SCRIPT_DIR/pre-commit" "$REPO_ROOT/.git/hooks/pre-commit"
chmod +x "$REPO_ROOT/.git/hooks/pre-commit"
echo "  - pre-commit: scripts/ci-local --tier fast"

cp "$SCRIPT_DIR/pre-push" "$REPO_ROOT/.git/hooks/pre-push"
chmod +x "$REPO_ROOT/.git/hooks/pre-push"
echo "  - pre-push: scripts/ci-local --tier medium"

echo ""
echo "Done. Tiered local workflows:"
echo "  - Fast:   scripts/ci-local --tier fast"
echo "  - Medium: scripts/ci-local --tier medium"
echo "  - Full:   scripts/ci-local --tier full"
echo ""
echo "Docker cross-arch matrix is run only in full tier."
echo "It auto-builds missing images (hexray-test:amd64, hexray-test:arm64)."
