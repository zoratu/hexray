#!/bin/bash
# Analyze a binary and capture issues
HEXRAY="/Volumes/OWC 1M2/Users/isaiah/src/hexray/target/release/hexray"
BINARY="$1"
OUTPUT_DIR="/Volumes/OWC 1M2/Users/isaiah/src/hexray/analysis_results"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found: $BINARY"
    exit 1
fi

BASENAME=$(basename "$BINARY")
echo "=== Analyzing: $BINARY ==="

# Get symbols
"$HEXRAY" "$BINARY" symbols 2>/dev/null | head -50 > "$OUTPUT_DIR/${BASENAME}_symbols.txt"

# Get first 10 function symbols
FUNCS=$("$HEXRAY" "$BINARY" symbols 2>/dev/null | grep "FUNC" | head -10 | awk '{print $5}')

for FUNC in $FUNCS; do
    echo "  Decompiling: $FUNC"
    timeout 10 "$HEXRAY" "$BINARY" decompile "$FUNC" 2>&1 | head -100 >> "$OUTPUT_DIR/${BASENAME}_decompile.txt"
    echo "---" >> "$OUTPUT_DIR/${BASENAME}_decompile.txt"
done
