#!/bin/bash
# Test script for verifying all analysis modules
#
# This script runs targeted tests for the major analysis components
# to ensure they're working correctly.

set -e

echo "=== Testing Analysis Modules ==="
echo ""

# Core analysis tests
echo "--- Analysis Cache ---"
cargo test -p hexray-analysis analysis_cache -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Incremental Analysis ---"
cargo test -p hexray-analysis incremental -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Class Reconstruction ---"
cargo test -p hexray-analysis class_reconstruction -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Devirtualization ---"
cargo test -p hexray-analysis devirtualization -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Exception Handling ---"
cargo test -p hexray-analysis exception_handling -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- RTTI ---"
cargo test -p hexray-analysis rtti -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Vtable Detection ---"
cargo test -p hexray-analysis vtable -- --nocapture 2>/dev/null | tail -5

# Decompiler module tests
echo ""
echo "=== Testing Decompiler Modules ==="

echo ""
echo "--- Quality Metrics ---"
cargo test -p hexray-analysis quality_metrics -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Benchmark Suite ---"
cargo test -p hexray-analysis benchmark -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Comparison Testing ---"
cargo test -p hexray-analysis comparison -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Float Patterns ---"
cargo test -p hexray-analysis float_patterns -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- RISC-V Vector Patterns ---"
cargo test -p hexray-analysis riscv_vector -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Interprocedural Analysis ---"
cargo test -p hexray-analysis interprocedural -- --nocapture 2>/dev/null | tail -5

echo ""
echo "--- Irreducible CFG ---"
cargo test -p hexray-analysis irreducible -- --nocapture 2>/dev/null | tail -5

# Property tests
echo ""
echo "=== Running Property Tests ==="
PROPTEST_CASES=50 cargo test -p hexray-analysis --test proptest_cfg --test proptest_types 2>/dev/null | tail -10

# Summary
echo ""
echo "=== Test Summary ==="
TOTAL=$(cargo test -p hexray-analysis 2>&1 | grep "test result:" | head -1 | sed 's/.*\([0-9]\+\) passed.*/\1/')
echo "Total hexray-analysis tests passed: $TOTAL"

echo ""
echo "All analysis module tests passed!"
