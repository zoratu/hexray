#!/bin/bash
# Run hexray fuzzers in Docker containers
#
# Usage:
#   ./run-fuzzers.sh              # Run all fuzzers for 1 hour each
#   ./run-fuzzers.sh x86_64       # Run only x86_64 decoder fuzzer
#   ./run-fuzzers.sh --hours 8    # Run all fuzzers for 8 hours each

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

HOURS=1
TARGET=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --hours|-h)
            HOURS="$2"
            shift 2
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

SECONDS=$((HOURS * 3600))

# Create corpus directories
mkdir -p corpus/{x86_64_decoder,arm64_decoder,riscv_decoder,elf_parser,macho_parser}
mkdir -p artifacts

echo "Building Docker image..."
docker build -t hexray-fuzz -f Dockerfile ..

run_fuzzer() {
    local name=$1
    local target=$2
    echo "Starting $name fuzzer for $HOURS hour(s)..."
    docker run --rm -d \
        --name "hexray-fuzz-$name" \
        --cpus 1 \
        --memory 2g \
        -v "$SCRIPT_DIR/corpus/$target:/hexray/fuzz/corpus/$target" \
        -v "$SCRIPT_DIR/artifacts:/hexray/fuzz/artifacts" \
        hexray-fuzz \
        cargo fuzz run "$target" -- -max_total_time=$SECONDS
}

if [ -n "$TARGET" ]; then
    # Run single fuzzer
    run_fuzzer "$TARGET" "${TARGET}_decoder"
else
    # Run all fuzzers
    run_fuzzer "x86_64" "x86_64_decoder"
    run_fuzzer "arm64" "arm64_decoder"
    run_fuzzer "riscv" "riscv_decoder"
    run_fuzzer "elf" "elf_parser"
    run_fuzzer "macho" "macho_parser"
fi

echo ""
echo "Fuzzers running in background. Monitor with:"
echo "  docker logs -f hexray-fuzz-x86_64"
echo "  docker ps | grep hexray-fuzz"
echo ""
echo "Stop all fuzzers with:"
echo "  docker stop \$(docker ps -q --filter name=hexray-fuzz)"
