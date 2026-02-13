#!/usr/bin/env bash
# check_support_matrix_maintenance.sh — CI gate for bd-3g4p
# Runs the automated support matrix maintenance validator, checks report
# structure, and reports status/conformance drift.
#
# Default mode: warns on drift findings but does not fail unless the
# maintenance report itself is malformed or status validation drops
# below 80%.
#
# --strict: requires >= 95% status validation to pass.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/support_matrix_maintenance_report.v1.json"

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

echo "=== Support Matrix Maintenance Gate (bd-3g4p) ==="

# 1. Run the maintenance validator
echo "--- Generating maintenance report ---"
python3 "$SCRIPT_DIR/generate_support_matrix_maintenance.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: maintenance report not generated"
    exit 1
fi

# 2. Validate report structure and check thresholds
python3 - "$REPORT" "$STRICT" <<'PY'
import json, sys

report_path = sys.argv[1]
strict = sys.argv[2] == "True"
errors = 0

with open(report_path) as f:
    report = json.load(f)

# Check required fields
summary = report.get("summary", {})
required = [
    "total_symbols", "status_validated", "status_invalid",
    "fixture_linked", "fixture_unlinked", "fixture_coverage_pct",
    "status_valid_pct",
]
for key in required:
    if key not in summary:
        print(f"FAIL: missing summary field '{key}'")
        errors += 1

total = summary.get("total_symbols", 0)
valid = summary.get("status_validated", 0)
invalid = summary.get("status_invalid", 0)
linked = summary.get("fixture_linked", 0)
unlinked = summary.get("fixture_unlinked", 0)
valid_pct = summary.get("status_valid_pct", 0)
cov_pct = summary.get("fixture_coverage_pct", 0)

print(f"Total symbols: {total}")
print(f"Status validated: {valid}/{total} ({valid_pct}%)")
print(f"  Invalid: {invalid}")
print(f"Fixture linked: {linked}/{total} ({cov_pct}%)")
print(f"  Unlinked: {unlinked}")

# Status distribution
dist = report.get("status_distribution", {})
if dist:
    print("\nStatus distribution:")
    for st, info in sorted(dist.items()):
        count = info.get("count", 0)
        fix = info.get("fixture_linked", 0)
        print(f"  {st:25s} {count:3d} symbols ({fix} with fixtures)")

# Module coverage
mod_cov = report.get("module_coverage", {})
if mod_cov:
    print(f"\nModule coverage ({len(mod_cov)} modules):")
    for mod_name, info in sorted(mod_cov.items()):
        t = info.get("total", 0)
        l = info.get("linked", 0)
        pct = info.get("coverage_pct", 0)
        bar = "█" * int(pct / 10) + "░" * (10 - int(pct / 10))
        print(f"  {mod_name:20s} {l:3d}/{t:3d} {bar} {pct}%")

# Show findings
issues = report.get("status_validation_issues", [])
if issues:
    print(f"\nStatus validation findings ({len(issues)}):")
    for iss in issues[:15]:
        findings_str = "; ".join(iss.get("findings", []))
        print(f"  {iss['symbol']:30s} ({iss['status']}) {findings_str}")

# Threshold checks
threshold = 95.0 if strict else 80.0
if valid_pct < threshold:
    print(f"\nFAIL: status validation {valid_pct}% below {threshold}% threshold")
    errors += 1

if total == 0:
    print("\nFAIL: no symbols in matrix")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

mode = "strict" if strict else "default"
print(f"\ncheck_support_matrix_maintenance ({mode}): PASS")
PY
