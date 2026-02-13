#!/usr/bin/env bash
# check_release_dry_run.sh — CI gate for bd-w2c3.10.2
# Validates that the release dry-run DAG executes successfully in dry-run mode
# and produces a valid dossier with all required fields.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Release Dry-Run DAG Gate (bd-w2c3.10.2) ==="

# Run dry-run and capture dossier
DOSSIER_PATH="${1:-/data/tmp/frankenlibc_release_dry_run_dossier.json}"
"$SCRIPT_DIR/release_dry_run.sh" --mode dry-run --dossier-path "$DOSSIER_PATH"
rc=$?

if [ "$rc" -ne 0 ]; then
    echo "FAIL: release dry-run failed with exit code $rc"
    exit 1
fi

# Validate dossier structure
python3 - "$DOSSIER_PATH" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path) as f:
    dossier = json.load(f)

errors = []
required_top = ["schema_version", "trace_id", "mode", "prereq_hash", "gate_count",
                "generated_at_utc", "summary", "gates", "artifact_index"]
for key in required_top:
    if key not in dossier:
        errors.append(f"missing top-level key: {key}")

summary = dossier.get("summary", {})
for key in ["total", "passed", "failed", "verdict"]:
    if key not in summary:
        errors.append(f"missing summary key: {key}")

if summary.get("verdict") != "PASS":
    errors.append(f"verdict is {summary.get('verdict')}, expected PASS")

gates = dossier.get("gates", [])
required_gate_fields = ["trace_id", "gate_name", "status", "duration_ms",
                        "gate_index", "rationale", "critical"]
for gate in gates:
    for key in required_gate_fields:
        if key not in gate:
            errors.append(f"gate {gate.get('gate_name','?')}: missing field {key}")

if errors:
    print(f"FAIL: dossier validation has {len(errors)} error(s)")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)

print(f"PASS: dossier validated ({len(gates)} gates, verdict={summary.get('verdict')})")
PY
