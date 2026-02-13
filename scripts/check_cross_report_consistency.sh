#!/usr/bin/env bash
# check_cross_report_consistency.sh — CI gate for bd-2vv.11
# Validates cross-report consistency for support/reality/replacement claims.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/cross_report_consistency.v1.json"

echo "=== Cross-Report Consistency Gate (bd-2vv.11) ==="

echo "--- Generating consistency report ---"
python3 "$SCRIPT_DIR/generate_cross_report_consistency.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: consistency report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
findings = report.get("findings", [])
reports_loaded = report.get("reports_loaded", {})

total = summary.get("total_findings", 0)
by_severity = summary.get("by_severity", {})
by_verdict = summary.get("by_verdict", {})
loaded = summary.get("reports_loaded", 0)
total_reports = summary.get("reports_total", 0)

print(f"Findings:                {total}")
print(f"  Critical:              {by_severity.get('critical', 0)}")
print(f"  Error:                 {by_severity.get('error', 0)}")
print(f"  Warning:               {by_severity.get('warning', 0)}")
print(f"  Info:                  {by_severity.get('info', 0)}")
print(f"  Reports loaded:        {loaded}/{total_reports}")
print()

# Must load at least support_matrix
if not reports_loaded.get("support_matrix"):
    print("FAIL: support_matrix.json not loaded")
    errors += 1
else:
    print("PASS: support_matrix.json loaded")

# Must load at least 3 reports
if loaded < 3:
    print(f"FAIL: Only {loaded} reports loaded (need >= 3)")
    errors += 1
else:
    print(f"PASS: {loaded} reports loaded for cross-checking")

# No critical findings
critical = by_severity.get("critical", 0)
if critical > 0:
    print(f"FAIL: {critical} critical findings")
    errors += 1
else:
    print("PASS: No critical findings")

# Symbol count checks should pass
count_findings = [f for f in findings if f.get("rule", "").startswith("symbol_count")]
count_fails = [f for f in count_findings if f.get("verdict") == "fail"]
if count_fails:
    print(f"FAIL: {len(count_fails)} symbol count mismatches")
    errors += 1
else:
    print("PASS: Symbol counts consistent")

# No unknown symbols
unknown_findings = [f for f in findings if f.get("rule") == "no_unknown_status"]
unknown_fails = [f for f in unknown_findings if f.get("verdict") == "fail"]
if unknown_fails:
    print(f"FAIL: Symbols with unknown status found")
    errors += 1
else:
    print("PASS: No unknown symbol statuses")

# Report must have consistency rules documented
rules = report.get("consistency_rules", {})
if len(rules) < 3:
    print(f"FAIL: Only {len(rules)} consistency rules (need >= 3)")
    errors += 1
else:
    print(f"PASS: {len(rules)} consistency rules defined")

# Report all drift and inconsistencies (informational, not blocking)
drift_count = by_verdict.get("drift", 0) + by_verdict.get("inconsistent", 0)
error_count = by_severity.get("error", 0)
if drift_count > 0:
    print(f"INFO: {drift_count} drift/inconsistency findings detected "
          f"({error_count} errors, tracked for resolution)")

if errors > 0:
    print(f"\nFAIL: {errors} gate errors")
    sys.exit(1)

print(f"\ncheck_cross_report_consistency: PASS")
PY
