#!/usr/bin/env bash
# check_conformance_fixture_unit_tests.sh — CI gate for bd-2hh.5
# Validates conformance fixture format, loading, and regression baseline.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fixture_unit_tests.v1.json"

echo "=== Conformance Fixture Unit Tests Gate (bd-2hh.5) ==="

echo "--- Generating fixture unit test report ---"
python3 "$SCRIPT_DIR/generate_conformance_fixture_unit_tests.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: fixture unit test report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
fixtures = report.get("fixture_results", [])
baseline = report.get("regression_baseline", {})

total_files = summary.get("total_fixture_files", 0)
valid_files = summary.get("valid_fixture_files", 0)
total_cases = summary.get("total_cases", 0)
total_issues = summary.get("total_issues", 0)
total_warnings = summary.get("total_warnings", 0)
unique_families = summary.get("unique_families", 0)
unique_symbols = summary.get("unique_symbols", 0)
determinism = summary.get("determinism_verified", False)

print(f"Fixture files:           {total_files}")
print(f"  Valid:                 {valid_files}/{total_files}")
print(f"  Total cases:           {total_cases}")
print(f"  Issues:                {total_issues}")
print(f"  Warnings:              {total_warnings}")
print(f"  Unique families:       {unique_families}")
print(f"  Unique symbols:        {unique_symbols}")
print(f"  Determinism verified:  {determinism}")

# Show any invalid fixtures
invalid = [f for f in fixtures if not f["valid"]]
if invalid:
    print(f"\nInvalid fixtures:")
    for f in invalid:
        print(f"  {f['file']}: {', '.join(f['issues'])}")

print(f"\nRegression baseline: {baseline.get('symbol_count', 0)} symbols, {baseline.get('total_cases', 0)} cases")

print("")

# All fixtures must be valid
if valid_files < total_files:
    print(f"FAIL: {total_files - valid_files} invalid fixture file(s)")
    errors += 1
else:
    print(f"PASS: All {total_files} fixture files valid")

# No format issues
if total_issues > 0:
    print(f"FAIL: {total_issues} format issues")
    errors += 1
else:
    print(f"PASS: No format issues")

# Determinism must be verified
if not determinism:
    print("FAIL: Fixture parsing not deterministic")
    errors += 1
else:
    print("PASS: Fixture parsing is deterministic")

# Must have fixture cases
if total_cases < 100:
    print(f"FAIL: Only {total_cases} total cases (need >= 100)")
    errors += 1
else:
    print(f"PASS: {total_cases} fixture cases")

# Must have regression baseline
baseline_symbols = baseline.get("symbol_count", 0)
if baseline_symbols < 50:
    print(f"FAIL: Only {baseline_symbols} symbols in regression baseline (need >= 50)")
    errors += 1
else:
    print(f"PASS: {baseline_symbols} symbols in regression baseline")

# Every fixture must have a hash
missing_hash = [f for f in fixtures if not f.get("fixture_hash")]
if missing_hash:
    print(f"FAIL: {len(missing_hash)} fixtures missing content hash")
    errors += 1
else:
    print(f"PASS: All {total_files} fixtures have content hashes")

if total_files == 0:
    print("FAIL: No fixture files found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_conformance_fixture_unit_tests: PASS")
PY
