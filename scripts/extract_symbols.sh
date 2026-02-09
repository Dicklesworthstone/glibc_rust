#!/usr/bin/env bash
# Extract exported symbols from host libc for baseline comparison.
set -euo pipefail

LIBC_PATH="${1:-/usr/lib/x86_64-linux-gnu/libc.so.6}"

echo "=== Extracting symbols from: ${LIBC_PATH} ==="
echo ""

# Count total dynamic symbols
total=$(nm -D --defined-only "${LIBC_PATH}" 2>/dev/null | wc -l)
echo "Total defined dynamic symbols: ${total}"
echo ""

# Extract versioned symbols sorted by version tag
echo "=== Versioned symbols (first 50) ==="
nm -D --defined-only "${LIBC_PATH}" 2>/dev/null | head -50

echo ""
echo "=== Symbol version tags ==="
objdump -T "${LIBC_PATH}" 2>/dev/null | grep -oP 'GLIBC_\d+\.\d+(\.\d+)?' | sort -u
