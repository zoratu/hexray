#!/bin/bash
# Install git hooks for local CI

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Installing git hooks..."

# Pre-commit hook (fast checks: fmt, clippy, build, test, property tests)
cp "$SCRIPT_DIR/pre-commit" "$REPO_ROOT/.git/hooks/pre-commit"
chmod +x "$REPO_ROOT/.git/hooks/pre-commit"
echo "  - pre-commit: format, clippy, build, test, property tests"

# Pre-push hook (Docker cross-platform tests)
cp "$SCRIPT_DIR/pre-push" "$REPO_ROOT/.git/hooks/pre-push"
chmod +x "$REPO_ROOT/.git/hooks/pre-push"
echo "  - pre-push: Docker tests on linux/amd64 and linux/arm64"

echo ""
echo "Building Docker images for pre-push hook..."
docker build --platform linux/amd64 -t hexray-test:amd64 "$REPO_ROOT"
docker build --platform linux/arm64 -t hexray-test:arm64 "$REPO_ROOT"

echo ""
echo "Done! Hooks installed:"
echo "  - Pre-commit: runs on every 'git commit'"
echo "  - Pre-push: runs on every 'git push'"
echo ""
echo "Additional test scripts:"
echo "  - scripts/test-analysis-modules.sh: comprehensive analysis module tests"
echo "  - scripts/bench-regression.sh: benchmark regression testing"
