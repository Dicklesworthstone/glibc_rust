#!/usr/bin/env bash
# check_fuzz_phase1_targets.sh — CI gate for bd-1oz.6
# Validates phase-1 fuzz target readiness, crash triage policy, and coverage.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fuzz_phase1_targets.v1.json"

echo "=== Fuzz Phase-1 Targets Gate (bd-1oz.6) ==="

echo "--- Generating phase-1 fuzz target report ---"
python3 "$SCRIPT_DIR/generate_fuzz_phase1_targets.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: phase-1 fuzz target report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
targets = report.get("target_assessments", [])
triage = report.get("crash_triage_policy", {})

total = summary.get("total_targets", 0)
functional = summary.get("functional_targets", 0)
smoke_viable = summary.get("smoke_viable_targets", 0)
avg_score = summary.get("average_readiness_score", 0)
symbols = summary.get("total_symbols_covered", 0)
cwes = summary.get("total_cwes_targeted", 0)
triage_steps = summary.get("triage_steps", 0)

print(f"Phase-1 targets:         {total}")
print(f"  Functional:            {functional}")
print(f"  Smoke-viable:          {smoke_viable}")
print(f"  Avg readiness score:   {avg_score}")
print(f"  Symbols covered:       {symbols}")
print(f"  CWEs targeted:         {cwes}")
print(f"  Triage steps:          {triage_steps}")
print()

# Must have phase-1 targets
if total == 0:
    print("FAIL: No phase-1 targets found")
    errors += 1
else:
    print(f"PASS: {total} phase-1 targets found")

# At least 2 functional targets
if functional < 2:
    print(f"FAIL: Only {functional} functional targets (need >= 2)")
    errors += 1
else:
    print(f"PASS: {functional} functional targets")

# All targets smoke-viable
if smoke_viable < total:
    print(f"FAIL: Only {smoke_viable}/{total} targets are smoke-viable")
    errors += 1
else:
    print(f"PASS: All {total} targets are smoke-viable")

# Average readiness >= 50
if avg_score < 50:
    print(f"FAIL: Average readiness {avg_score} < 50")
    errors += 1
else:
    print(f"PASS: Average readiness score {avg_score}")

# Must cover >= 20 symbols
if symbols < 20:
    print(f"FAIL: Only {symbols} symbols covered (need >= 20)")
    errors += 1
else:
    print(f"PASS: {symbols} symbols covered")

# Must have crash triage flow
triage_flow = triage.get("triage_flow", [])
if len(triage_flow) < 4:
    print(f"FAIL: Only {len(triage_flow)} triage steps (need >= 4)")
    errors += 1
else:
    print(f"PASS: {len(triage_flow)}-step crash triage flow defined")

# Must have dedup policy
dedup = triage.get("dedup", {})
if not dedup.get("method"):
    print("FAIL: No crash dedup method defined")
    errors += 1
else:
    print(f"PASS: Crash dedup policy: {dedup['method']}")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_fuzz_phase1_targets: PASS")
PY
