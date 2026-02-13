#!/usr/bin/env bash
# check_release_dossier.sh — CI gate for bd-5fw.3
# Validates release artifact dossier: completeness, integrity, schema.
# NOTE: In non-release CI, exits 0 with warnings for known-incomplete artifacts.
# For release gating, run with --strict to enforce all-valid.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STRICT="${1:-}"

echo "=== Release Dossier Validation Gate (bd-5fw.3) ==="

python3 "$SCRIPT_DIR/release_dossier_validator.py" || true

REPORT="$REPO_ROOT/tests/release/dossier_validation_report.v1.json"
if [ ! -f "$REPORT" ]; then
    echo "FAIL: dossier validation report not generated"
    exit 2
fi

# Validate report structure
python3 - "$REPORT" "$STRICT" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    report = json.load(f)
strict = len(sys.argv) > 2 and sys.argv[2] == "--strict"

required = ["schema_version", "bead", "status", "verdict", "summary",
            "artifact_results", "integrity_index", "findings",
            "compatibility_policy"]
missing = [k for k in required if k not in report]
if missing:
    print(f"FAIL: report missing keys: {missing}")
    sys.exit(1)

s = report["summary"]
print(f"Dossier validation: {report['verdict']}")
print(f"  Total artifacts: {s.get('total_artifacts', 0)}")
print(f"  Valid: {s.get('valid', 0)}")
print(f"  Present with issues: {s.get('present_with_issues', 0)}")
print(f"  Missing: {s.get('missing', 0)} (critical: {s.get('critical_missing', 0)})")
print(f"  Integrity entries: {len(report.get('integrity_index', {}))}")

if strict:
    if report["verdict"] != "PASS":
        print(f"FAIL: strict mode requires PASS verdict, got {report['verdict']}")
        sys.exit(1)
else:
    # Non-strict: only fail on critical missing
    if s.get("critical_missing", 0) > 0:
        print(f"FAIL: {s['critical_missing']} critical artifacts missing")
        sys.exit(1)
PY
rc2=$?

if [ "$rc2" -ne 0 ]; then
    echo "FAIL: dossier validation failed"
    exit 1
fi

echo "check_release_dossier: PASS"
