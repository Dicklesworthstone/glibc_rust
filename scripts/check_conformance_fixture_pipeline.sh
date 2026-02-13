#!/usr/bin/env bash
# check_conformance_fixture_pipeline.sh — CI gate for bd-2hh.1
# Validates the conformance fixture capture pipeline.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fixture_pipeline.v1.json"

echo "=== Conformance Fixture Pipeline Gate (bd-2hh.1) ==="

echo "--- Generating fixture pipeline report ---"
python3 "$SCRIPT_DIR/generate_conformance_fixture_pipeline.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: fixture pipeline report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
modules = report.get("module_summary", [])

total_files = summary.get("total_fixture_files", 0)
total_cases = summary.get("total_fixture_cases", 0)
unique_syms = summary.get("unique_symbols_in_fixtures", 0)
impl_syms = summary.get("implemented_symbols", 0)
with_fixtures = summary.get("symbols_with_fixtures", 0)
at_threshold = summary.get("symbols_at_threshold", 0)
below_threshold = summary.get("symbols_below_threshold", 0)
zero_fixtures = summary.get("symbols_with_zero_fixtures", 0)
coverage_pct = summary.get("coverage_pct", 0)
threshold = summary.get("min_cases_threshold", 10)
format_issues = summary.get("fixture_format_issues", 0)

print(f"Fixture files:            {total_files}")
print(f"Total fixture cases:      {total_cases}")
print(f"Unique symbols tested:    {unique_syms}")
print(f"Implemented symbols:      {impl_syms}")
print(f"  With fixtures:          {with_fixtures}/{impl_syms} ({coverage_pct}%)")
print(f"  At threshold (>={threshold}):  {at_threshold}/{impl_syms}")
print(f"  Below threshold:        {below_threshold}/{impl_syms}")
print(f"  Zero fixtures:          {zero_fixtures}/{impl_syms}")
print(f"Format issues:            {format_issues}")

print(f"\nModule summary:")
for m in sorted(modules, key=lambda x: -x["total_cases"]):
    print(f"  {m['module']:20s}  symbols={m['covered_symbols']}/{m['total_symbols']:>3}  cases={m['total_cases']:>3}  coverage={m['coverage_pct']:>5.1f}%")

print("")

# Must have fixture files
if total_files == 0:
    print("FAIL: No fixture files found")
    errors += 1
else:
    print(f"PASS: {total_files} fixture files found")

# Must have fixture cases
if total_cases < 100:
    print(f"FAIL: Only {total_cases} fixture cases (need >= 100)")
    errors += 1
else:
    print(f"PASS: {total_cases} fixture cases")

# Coverage must be >= 50%
if coverage_pct < 50:
    print(f"FAIL: Symbol coverage {coverage_pct}% (need >= 50%)")
    errors += 1
else:
    print(f"PASS: Symbol coverage {coverage_pct}%")

# No format issues
if format_issues > 0:
    print(f"FAIL: {format_issues} fixture format issues")
    errors += 1
else:
    print(f"PASS: All fixture files valid format")

# At least 5 modules covered
covered_modules = sum(1 for m in modules if m["covered_symbols"] > 0)
if covered_modules < 5:
    print(f"FAIL: Only {covered_modules} modules covered (need >= 5)")
    errors += 1
else:
    print(f"PASS: {covered_modules} modules have fixtures")

# Report threshold gap for visibility (informational, not blocking)
if at_threshold < impl_syms:
    gap = impl_syms - at_threshold
    print(f"INFO: {gap} symbols below {threshold}-case threshold (not blocking)")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_conformance_fixture_pipeline: PASS")
PY
