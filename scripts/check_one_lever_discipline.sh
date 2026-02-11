#!/usr/bin/env bash
# One-lever discipline guard (bd-22p)
#
# Validates that every optimization opportunity in the opportunity_matrix
# has exactly one lever_category and that the category is valid.
#
# Usage: bash scripts/check_one_lever_discipline.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

DISCIPLINE_SPEC="$ROOT_DIR/tests/conformance/one_lever_discipline.json"
OPP_MATRIX="$ROOT_DIR/tests/conformance/opportunity_matrix.json"

FAILURES=0

echo "=== One-Lever Discipline Guard (bd-22p) ==="
echo

# --- Check 1: Discipline spec exists and is valid JSON ---
echo "--- Check 1: Discipline spec exists ---"
if [ ! -f "$DISCIPLINE_SPEC" ]; then
    echo "FAIL: $DISCIPLINE_SPEC not found"
    FAILURES=$((FAILURES + 1))
else
    if python3 -c "import json; json.load(open('$DISCIPLINE_SPEC'))" 2>/dev/null; then
        echo "PASS: Discipline spec is valid JSON"
    else
        echo "FAIL: Discipline spec is not valid JSON"
        FAILURES=$((FAILURES + 1))
    fi
fi

# --- Check 2: Opportunity matrix exists ---
echo
echo "--- Check 2: Opportunity matrix exists ---"
if [ ! -f "$OPP_MATRIX" ]; then
    echo "FAIL: $OPP_MATRIX not found"
    FAILURES=$((FAILURES + 1))
else
    echo "PASS: Opportunity matrix exists"
fi

# --- Check 3: All entries have lever_category ---
echo
echo "--- Check 3: All entries have lever_category ---"
python3 - "$DISCIPLINE_SPEC" "$OPP_MATRIX" << 'PYTHON' || FAILURES=$((FAILURES + 1))
import json, sys

spec_path, matrix_path = sys.argv[1], sys.argv[2]
with open(spec_path) as f:
    spec = json.load(f)
with open(matrix_path) as f:
    matrix = json.load(f)

valid_categories = set(spec["lever_categories"]["categories"].keys())
entries = matrix.get("entries", [])
missing = []
invalid = []

for entry in entries:
    eid = entry.get("id", "?")
    lever = entry.get("lever_category")
    if lever is None:
        missing.append(eid)
    elif lever not in valid_categories:
        invalid.append(f"{eid}: '{lever}'")

if missing:
    print(f"FAIL: Entries missing lever_category: {', '.join(missing)}")
    sys.exit(1)
elif invalid:
    print(f"FAIL: Entries with invalid lever_category: {', '.join(invalid)}")
    sys.exit(1)
else:
    print(f"PASS: All {len(entries)} entries have valid lever_category")
PYTHON

# --- Check 4: No multi-lever beads without waiver ---
echo
echo "--- Check 4: No multi-lever beads ---"
python3 - "$OPP_MATRIX" << 'PYTHON' || FAILURES=$((FAILURES + 1))
import json, sys
from collections import defaultdict

with open(sys.argv[1]) as f:
    matrix = json.load(f)

bead_levers = defaultdict(set)
for entry in matrix.get("entries", []):
    bead = entry.get("bead_id")
    lever = entry.get("lever_category")
    if bead and lever:
        bead_levers[bead].add(lever)

multi = {b: sorted(ls) for b, ls in bead_levers.items() if len(ls) > 1}
if multi:
    for bead, levers in multi.items():
        waiver = any(
            e.get("bead_id") == bead and e.get("justification_waiver")
            for e in matrix.get("entries", [])
        )
        if not waiver:
            print(f"FAIL: Bead {bead} references multiple levers: {levers}")
            sys.exit(1)
        else:
            print(f"WARN: Bead {bead} multi-lever (waivered): {levers}")
    print("PASS: All multi-lever beads have waivers")
else:
    beads_with_levers = len(bead_levers)
    print(f"PASS: All {beads_with_levers} beads reference exactly one lever category")
PYTHON

# --- Summary ---
echo
echo "=== Summary ==="
echo "Failures: $FAILURES"
echo
if [ "$FAILURES" -eq 0 ]; then
    echo "check_one_lever_discipline: PASS"
    exit 0
else
    echo "check_one_lever_discipline: FAIL"
    exit 1
fi
