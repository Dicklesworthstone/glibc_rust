#!/usr/bin/env bash
# check_closure_sweep.sh — CI gate for bd-w2c3.10.3
# Runs the closure sweep engine and validates the report structure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Closure Sweep Gate (bd-w2c3.10.3) ==="

python3 "$SCRIPT_DIR/closure_sweep.py"
rc=$?

REPORT="$REPO_ROOT/tests/conformance/closure_sweep_report.v1.json"
if [ ! -f "$REPORT" ]; then
    echo "FAIL: closure sweep report not generated"
    exit 2
fi

# Validate report structure
python3 - "$REPORT" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)
required = ["schema_version", "bead", "status", "summary", "findings",
            "coverage_gaps", "callthrough_gaps", "non_closure_reasons",
            "drift_gates_status", "open_gap_beads"]
missing = [k for k in required if k not in report]
if missing:
    print(f"FAIL: report missing keys: {missing}")
    sys.exit(1)
s = report["summary"]
print(f"PASS: closure sweep complete")
print(f"  Status: {report['status']}")
print(f"  Coverage: {s.get('coverage_pct', 0)}%")
print(f"  CallThrough remaining: {s.get('callthrough_remaining', 0)}")
print(f"  Open gap beads: {s.get('open_gap_beads', 0)}")
print(f"  Closure ready: {s.get('closure_ready', False)}")
print(f"  Drift gates: {report.get('drift_gates_status', 'unknown')}")
print(f"  Non-closure reasons: {len(report.get('non_closure_reasons', []))}")
PY
rc2=$?

if [ "$rc" -ne 0 ]; then
    echo "FAIL: closure sweep found errors"
    exit 1
fi
if [ "$rc2" -ne 0 ]; then
    echo "FAIL: report validation failed"
    exit 1
fi

echo "check_closure_sweep: PASS"
