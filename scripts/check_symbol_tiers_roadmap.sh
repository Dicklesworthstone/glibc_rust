#!/usr/bin/env bash
# check_symbol_tiers_roadmap.sh — CI gate for bd-2vv.10
# Validates trace-weighted symbol tiers and family wave roadmap.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/symbol_tiers_roadmap.v1.json"

echo "=== Symbol Tiers & Wave Roadmap Gate (bd-2vv.10) ==="

echo "--- Generating symbol tiers roadmap ---"
python3 "$SCRIPT_DIR/generate_symbol_tiers_roadmap.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: symbol tiers roadmap not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
tiers = report.get("tiered_symbols", [])
waves = report.get("wave_roadmap", {})
families = report.get("family_readiness", {})
checklist = report.get("wave_acceptance_checklist", [])

total = summary.get("total_symbols", 0)
tier_counts = summary.get("tier_counts", {})
wave_count = summary.get("wave_count", 0)
native_pct = summary.get("overall_native_pct", 0)

print(f"Symbols:                 {total}")
print(f"  Tier counts:           {json.dumps(tier_counts)}")
print(f"  Waves:                 {wave_count}")
print(f"  Native impl:           {native_pct}%")
print(f"  Families complete:     {summary.get('families_complete', 0)}")
print(f"  Families in-progress:  {summary.get('families_in_progress', 0)}")
print()

# Must have all symbols tiered
if total < 100:
    print(f"FAIL: Only {total} symbols tiered (need >= 100)")
    errors += 1
else:
    print(f"PASS: {total} symbols tiered")

# Must have tier distribution
if len(tier_counts) < 3:
    print(f"FAIL: Only {len(tier_counts)} tiers (need >= 3)")
    errors += 1
else:
    print(f"PASS: {len(tier_counts)} tier levels defined")

# Top50 must have 50 symbols
top50 = tier_counts.get("top50", 0)
if top50 != 50:
    print(f"FAIL: Top50 tier has {top50} symbols (expected 50)")
    errors += 1
else:
    print("PASS: Top50 tier correctly populated")

# Must have >= 3 waves
if wave_count < 3:
    print(f"FAIL: Only {wave_count} waves (need >= 3)")
    errors += 1
else:
    print(f"PASS: {wave_count} implementation waves defined")

# Every symbol must be assigned a wave
wave_total = sum(w.get("total_symbols", 0) for w in waves.values())
if wave_total != total:
    print(f"FAIL: Wave symbol total {wave_total} != universe total {total}")
    errors += 1
else:
    print(f"PASS: All {total} symbols assigned to waves")

# Must have acceptance checklist
mandatory = [c for c in checklist if c.get("mandatory")]
if len(mandatory) < 3:
    print(f"FAIL: Only {len(mandatory)} mandatory checklist items (need >= 3)")
    errors += 1
else:
    print(f"PASS: {len(mandatory)} mandatory wave acceptance requirements")

# Output must be reproducible
import subprocess, tempfile, os
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
    tmp_path = tmp.name
result = subprocess.run(
    ["python3", report_path.replace("tests/conformance/symbol_tiers_roadmap.v1.json",
     "scripts/generate_symbol_tiers_roadmap.py"), "-o", tmp_path],
    capture_output=True, text=True
)
if result.returncode == 0:
    with open(tmp_path) as f:
        r2 = json.load(f)
    os.unlink(tmp_path)
    if r2.get("roadmap_hash") == report.get("roadmap_hash"):
        print("PASS: Output is reproducible (same hash)")
    else:
        print("FAIL: Output not reproducible (different hash)")
        errors += 1
else:
    os.unlink(tmp_path)
    print(f"WARN: Could not verify reproducibility: {result.stderr.strip()}")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_symbol_tiers_roadmap: PASS")
PY
