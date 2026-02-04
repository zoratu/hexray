#!/bin/bash
# Regression testing script for benchmark comparisons
# Usage:
#   ./scripts/bench-regression.sh baseline    # Save current results as baseline
#   ./scripts/bench-regression.sh compare     # Compare current results to baseline
#   ./scripts/bench-regression.sh run         # Just run benchmarks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BENCH_DIR="$PROJECT_DIR/target/bench-results"
BASELINE_FILE="$BENCH_DIR/baseline.json"
CURRENT_FILE="$BENCH_DIR/current.json"

# Threshold for regression detection (percentage)
REGRESSION_THRESHOLD=10

mkdir -p "$BENCH_DIR"

run_benchmarks() {
    echo "Running benchmarks..."
    cd "$PROJECT_DIR"

    # Run benchmarks and capture output in JSON format
    cargo bench --workspace -- --noplot --save-baseline current 2>&1 | tee "$BENCH_DIR/bench-output.txt"

    # Parse criterion results into a simpler format
    extract_results
}

extract_results() {
    local output_file="$1"
    if [ -z "$output_file" ]; then
        output_file="$CURRENT_FILE"
    fi

    echo "Extracting results to $output_file..."

    # Parse the benchmark output for timing information
    # Criterion outputs lines like: "test_name   time:   [123.45 us 125.67 us 127.89 us]"
    python3 - "$BENCH_DIR/bench-output.txt" "$output_file" << 'PYTHON'
import sys
import re
import json
from pathlib import Path

input_file = sys.argv[1]
output_file = sys.argv[2]

results = {}
current_group = ""

with open(input_file, 'r') as f:
    for line in f:
        # Match benchmark group header
        group_match = re.match(r'^(\w+)/(\w+)', line)
        if group_match:
            current_group = f"{group_match.group(1)}/{group_match.group(2)}"

        # Match timing line: "time:   [123.45 us 125.67 us 127.89 us]"
        time_match = re.search(r'time:\s*\[([0-9.]+)\s*(\w+)\s+([0-9.]+)\s*(\w+)\s+([0-9.]+)\s*(\w+)\]', line)
        if time_match and current_group:
            low = float(time_match.group(1))
            unit = time_match.group(2)
            median = float(time_match.group(3))
            high = float(time_match.group(5))

            # Convert to nanoseconds for consistent comparison
            multiplier = {'ns': 1, 'µs': 1000, 'us': 1000, 'ms': 1000000, 's': 1000000000}
            median_ns = median * multiplier.get(unit, 1)

            results[current_group] = {
                'low': low,
                'median': median,
                'high': high,
                'unit': unit,
                'median_ns': median_ns
            }

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"Extracted {len(results)} benchmark results")
PYTHON
}

save_baseline() {
    run_benchmarks
    cp "$CURRENT_FILE" "$BASELINE_FILE"
    echo "Baseline saved to $BASELINE_FILE"
}

compare_results() {
    if [ ! -f "$BASELINE_FILE" ]; then
        echo "Error: No baseline found. Run '$0 baseline' first."
        exit 1
    fi

    run_benchmarks

    echo ""
    echo "Comparing to baseline..."
    echo "========================"

    python3 - "$BASELINE_FILE" "$CURRENT_FILE" "$REGRESSION_THRESHOLD" << 'PYTHON'
import sys
import json

baseline_file = sys.argv[1]
current_file = sys.argv[2]
threshold = float(sys.argv[3])

with open(baseline_file, 'r') as f:
    baseline = json.load(f)

with open(current_file, 'r') as f:
    current = json.load(f)

regressions = []
improvements = []

for name, curr_data in current.items():
    if name not in baseline:
        print(f"  NEW: {name}: {curr_data['median']:.2f} {curr_data['unit']}")
        continue

    base_data = baseline[name]
    base_ns = base_data['median_ns']
    curr_ns = curr_data['median_ns']

    if base_ns > 0:
        change = ((curr_ns - base_ns) / base_ns) * 100
    else:
        change = 0

    if change > threshold:
        regressions.append((name, change, base_data, curr_data))
        status = "REGRESSION"
        color = "\033[91m"  # Red
    elif change < -threshold:
        improvements.append((name, change, base_data, curr_data))
        status = "IMPROVED"
        color = "\033[92m"  # Green
    else:
        status = "OK"
        color = "\033[0m"

    print(f"{color}  {status}: {name}: {base_data['median']:.2f} -> {curr_data['median']:.2f} {curr_data['unit']} ({change:+.1f}%)\033[0m")

# Summary
print("\n" + "=" * 60)
if regressions:
    print(f"\033[91mFOUND {len(regressions)} REGRESSIONS (>{threshold}% slower)\033[0m")
    for name, change, _, curr in regressions:
        print(f"  - {name}: {change:+.1f}%")
    sys.exit(1)
elif improvements:
    print(f"\033[92mNo regressions. {len(improvements)} improvements found.\033[0m")
else:
    print("\033[92mNo significant changes detected.\033[0m")
PYTHON
}

case "${1:-run}" in
    baseline)
        save_baseline
        ;;
    compare)
        compare_results
        ;;
    run)
        run_benchmarks
        ;;
    *)
        echo "Usage: $0 {baseline|compare|run}"
        echo "  baseline - Run benchmarks and save as baseline"
        echo "  compare  - Run benchmarks and compare to baseline"
        echo "  run      - Just run benchmarks"
        exit 1
        ;;
esac
