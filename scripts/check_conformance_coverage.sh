#!/usr/bin/env bash
# check_conformance_coverage.sh — CI gate for bd-15n.3
# Detects fixture coverage regressions: removed fixtures, decreased case counts,
# or module coverage drops.
# Exit 0 = no regression, 1 = regression found, 2 = baseline created (first run).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="${1:-check}"

echo "=== Conformance Coverage Gate (bd-15n.3) ==="
echo "Mode: $MODE"
echo ""

cd "$REPO_ROOT"

rc=0
python3 scripts/conformance_coverage_gate.py "$MODE" || rc=$?

if [ "$rc" -eq 0 ]; then
    echo ""
    echo "PASS: No coverage regressions detected."
elif [ "$rc" -eq 1 ]; then
    echo ""
    echo "FAIL: Coverage regression detected. See report above."
elif [ "$rc" -eq 2 ]; then
    echo ""
    echo "INFO: Initial baseline created. Commit tests/conformance/conformance_coverage_baseline.v1.json"
fi

exit "$rc"
