#!/usr/bin/env bash
# check_reverse_round_contracts.sh — CI gate for bd-2a2.4
# Validates reverse-round math-to-subsystem contract verification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/reverse_round_contracts.v1.json"

echo "=== Reverse-Round Contract Verification Gate (bd-2a2.4) ==="

echo "--- Generating reverse-round contract report ---"
python3 "$SCRIPT_DIR/generate_reverse_round_contracts.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: reverse-round contract report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
rounds = report.get("round_results", {})

total_families = summary.get("total_math_families", 0)
found = summary.get("modules_found", 0)
coverage = summary.get("module_coverage_pct", 0)
invariants = summary.get("invariants_specified", 0)
inv_total = summary.get("invariants_total", 0)
classes = summary.get("math_class_count", 0)
diverse = summary.get("all_rounds_diverse", False)

print(f"Rounds:                  {len(rounds)}")
print(f"  Math families:         {total_families}")
print(f"  Modules found:         {found}/{total_families} ({coverage}%)")
print(f"  Invariants:            {invariants}/{inv_total}")
print(f"  Math classes:          {classes}")
print(f"  All diverse:           {diverse}")
print()

# Must have R7-R11
if len(rounds) < 5:
    print(f"FAIL: Only {len(rounds)} rounds verified (need >= 5)")
    errors += 1
else:
    print(f"PASS: {len(rounds)} rounds verified (R7-R11)")

# All modules must exist
if found < total_families:
    missing = total_families - found
    print(f"FAIL: {missing} math modules not found")
    errors += 1
else:
    print(f"PASS: All {total_families} math modules exist")

# All invariants must be specified
if invariants < inv_total:
    print(f"FAIL: {inv_total - invariants} invariants not specified")
    errors += 1
else:
    print(f"PASS: All {inv_total} mathematical invariants specified")

# Branch diversity: all rounds >= 3 classes
if not diverse:
    for rid, rr in rounds.items():
        if not rr["branch_diversity"]["passes_diversity"]:
            print(f"FAIL: {rid} ({rr['name']}) has < 3 math classes")
    errors += 1
else:
    print("PASS: All rounds satisfy branch-diversity (>= 3 classes)")

# Must have >= 5 distinct math classes overall
if classes < 5:
    print(f"FAIL: Only {classes} math classes (need >= 5)")
    errors += 1
else:
    print(f"PASS: {classes} distinct math classes across rounds")

# Golden output hash must be stable
golden = report.get("golden_output", {})
if not golden.get("hash"):
    print("FAIL: Golden output hash missing")
    errors += 1
else:
    print(f"PASS: Golden output hash: {golden['hash']}")

# Each round must have legacy surface anchors
for rid, rr in sorted(rounds.items()):
    if not rr.get("legacy_surfaces"):
        print(f"FAIL: {rid} has no legacy surface anchors")
        errors += 1

if errors == 0:
    print("PASS: All rounds have legacy surface anchors")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_reverse_round_contracts: PASS")
PY
