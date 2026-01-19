#!/bin/bash
# Install git hooks for local CI

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Installing git hooks..."
cp "$SCRIPT_DIR/pre-push" "$REPO_ROOT/.git/hooks/pre-push"
chmod +x "$REPO_ROOT/.git/hooks/pre-push"

echo "Building Docker images..."
docker build --platform linux/amd64 -t hexray-test:amd64 "$REPO_ROOT"
docker build --platform linux/arm64 -t hexray-test:arm64 "$REPO_ROOT"

echo ""
echo "Done! Pre-push hook installed. Tests will run on every 'git push'."
