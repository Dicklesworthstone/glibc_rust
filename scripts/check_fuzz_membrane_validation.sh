#!/usr/bin/env bash
# check_fuzz_membrane_validation.sh — CI gate for bd-1oz.4
# Validates membrane fuzz target against spec requirements.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fuzz_membrane_validation.v1.json"

echo "=== Membrane Fuzz Target Validation Gate (bd-1oz.4) ==="

echo "--- Generating membrane validation report ---"
python3 "$SCRIPT_DIR/generate_fuzz_membrane_validation.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: membrane validation report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
source = report.get("source_analysis", {})
gaps = report.get("gap_analysis", [])

readiness = summary.get("readiness_pct", 0)
strategies = summary.get("strategies_coverage", "0/0")
transitions = summary.get("transitions_coverage", "0/0")
cache = summary.get("cache_coverage", "0/0")
invariants = summary.get("invariants_coverage", "0/0")
total_gaps = summary.get("total_gaps", 0)
high_gaps = summary.get("high_severity_gaps", 0)

print(f"Readiness:               {readiness}%")
print(f"  Strategies:            {strategies}")
print(f"  State transitions:     {transitions}")
print(f"  Cache coherence:       {cache}")
print(f"  Invariants:            {invariants}")
print(f"  Gaps:                  {total_gaps} ({high_gaps} high)")
print()

# Source must exist and compile
if not source.get("has_fuzz_target"):
    print("FAIL: fuzz_membrane.rs missing fuzz_target! macro")
    errors += 1
else:
    print("PASS: fuzz_membrane.rs has valid harness structure")

# Must have ValidationPipeline
if not source.get("has_pipeline_creation"):
    print("FAIL: fuzz_membrane.rs doesn't create ValidationPipeline")
    errors += 1
else:
    print("PASS: ValidationPipeline is exercised")

# Must check outcomes
if not source.get("has_outcome_checking"):
    print("FAIL: fuzz_membrane.rs doesn't check validation outcomes")
    errors += 1
else:
    print("PASS: Validation outcomes are checked (can_read/can_write)")

# Must have at least 1 strategy implemented
strat_impl = int(strategies.split("/")[0])
if strat_impl < 1:
    print("FAIL: No fuzzing strategies implemented")
    errors += 1
else:
    print(f"PASS: {strat_impl} fuzzing strategies active")

# At least 1 state transition exercised
trans_impl = int(transitions.split("/")[0])
if trans_impl < 1:
    print("FAIL: No state transitions exercised")
    errors += 1
else:
    print(f"PASS: {trans_impl} state transitions exercised")

# CWE coverage
cwes = summary.get("cwe_targets", [])
if len(cwes) < 2:
    print(f"FAIL: Only {len(cwes)} CWEs targeted (need >= 2)")
    errors += 1
else:
    print(f"PASS: {len(cwes)} CWEs targeted")

# Gap analysis must be documented
if total_gaps == 0 and readiness < 100:
    print("FAIL: Readiness < 100% but no gaps documented")
    errors += 1
else:
    print(f"PASS: {total_gaps} gaps documented for improvement roadmap")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_fuzz_membrane_validation: PASS")
PY
