#!/usr/bin/env bash
# check_cve_hardened_assertions.sh — CI gate for bd-1m5.6
# Validates the hardened CVE prevention/healing assertion suite.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/hardened_assertions.v1.json"

echo "=== CVE Hardened Assertions Gate (bd-1m5.6) ==="

echo "--- Generating hardened assertions report ---"
python3 "$SCRIPT_DIR/generate_cve_hardened_assertions.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: hardened assertions report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
assertions = report.get("assertion_matrix", [])
healing_map = report.get("healing_expectation_map", {})
val_issues = report.get("validation_issues", [])

total = summary.get("total_assertions", 0)
no_crash = summary.get("no_crash_in_hardened", 0)
with_healing = summary.get("with_healing_actions", 0)
strategies = summary.get("prevention_strategies", {})
val_errors = summary.get("validation_errors", 0)
val_warnings = summary.get("validation_warnings", 0)

print(f"Hardened assertions:     {total}")
print(f"  No crash in hardened:  {no_crash}/{total}")
print(f"  With healing actions:  {with_healing}/{total}")
print(f"  Prevention strategies: {strategies}")
print(f"  Validation errors:     {val_errors}")
print(f"  Validation warnings:   {val_warnings}")

print("\nAssertion matrix:")
for a in assertions:
    strat = a["prevention_strategy"]
    healing = ", ".join(a["hardened_expectations"]["healing_actions_required"])
    crash = "NO CRASH" if not a["hardened_expectations"]["crashes"] else "CRASHES"
    print(f"  {a['cve_id']:35s} CVSS={a.get('cvss_score', '?'):>4}  {crash}  strategy={strat:12s}  healing=[{healing}]")

print(f"\nHealing expectation map:")
for action, info in sorted(healing_map.items()):
    cves = ", ".join(info["cve_ids"])
    print(f"  {action:25s} strategy={info['strategy']:12s}  count={info['count']}  cves=[{cves}]")

if val_issues:
    print(f"\nValidation issues:")
    for issue in val_issues:
        print(f"  [{issue['severity']}] {issue['cve_id']}: {issue['issue']}")

print("")

# All CVEs must not crash in hardened mode
if no_crash < total:
    crashing = [a["cve_id"] for a in assertions if a["hardened_expectations"]["crashes"]]
    print(f"FAIL: {total - no_crash} CVE(s) crash in hardened mode: {', '.join(crashing)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs prevent crashes in hardened mode")

# All CVEs must have healing actions
if with_healing < total:
    missing = [a["cve_id"] for a in assertions if not a["hardened_expectations"]["healing_actions_required"]]
    print(f"FAIL: {total - with_healing} CVE(s) missing healing actions: {', '.join(missing)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs have healing actions defined")

# No validation errors
if val_errors > 0:
    print(f"FAIL: {val_errors} validation error(s)")
    errors += 1
else:
    print(f"PASS: No validation errors")

# Must have at least 2 prevention strategies
if len(strategies) < 2:
    print(f"FAIL: Only {len(strategies)} prevention strategy (need >= 2)")
    errors += 1
else:
    print(f"PASS: {len(strategies)} prevention strategies covered")

# Must have at least 4 unique healing actions
unique_healing = len(healing_map)
if unique_healing < 4:
    print(f"FAIL: Only {unique_healing} unique healing actions (need >= 4)")
    errors += 1
else:
    print(f"PASS: {unique_healing} unique healing actions in expectation map")

# Regression: every assertion must have no_uncontrolled_unsafety = true
unsafe = [a["cve_id"] for a in assertions if not a["hardened_expectations"].get("no_uncontrolled_unsafety", False)]
if unsafe:
    print(f"FAIL: {len(unsafe)} CVE(s) with uncontrolled unsafety: {', '.join(unsafe)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs have no uncontrolled memory unsafety")

if total == 0:
    print("FAIL: No assertions found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_hardened_assertions: PASS")
PY
