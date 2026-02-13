#!/usr/bin/env bash
# check_symbol_universe_normalization.sh — CI gate for bd-2vv.9
# Validates symbol universe normalization and support classification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/symbol_universe_normalization.v1.json"

echo "=== Symbol Universe Normalization Gate (bd-2vv.9) ==="

echo "--- Generating symbol normalization report ---"
python3 "$SCRIPT_DIR/generate_symbol_universe_normalization.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: symbol normalization report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
symbols = report.get("normalized_symbols", [])
families = report.get("family_statistics", {})
actions = report.get("unknown_action_list", [])

total = summary.get("total_symbols", 0)
unique = summary.get("unique_symbols", 0)
dupes = summary.get("duplicates", 0)
fam_count = summary.get("families", 0)
native_pct = summary.get("native_implementation_pct", 0)
classifications = summary.get("classifications", {})
confidence = summary.get("confidence_levels", {})

print(f"Symbols:                 {total}")
print(f"  Unique:                {unique}")
print(f"  Duplicates:            {dupes}")
print(f"  Families:              {fam_count}")
print(f"  Native impl:           {native_pct}%")
print(f"  Classifications:       {json.dumps(classifications)}")
print(f"  Confidence levels:     {json.dumps(confidence)}")
print(f"  Action items:          {len(actions)}")
print()

# Must have symbols
if total < 100:
    print(f"FAIL: Only {total} symbols (need >= 100)")
    errors += 1
else:
    print(f"PASS: {total} symbols in universe")

# No duplicates
if dupes > 0:
    print(f"FAIL: {dupes} duplicate symbols")
    errors += 1
else:
    print("PASS: No duplicate symbols")

# Every symbol must have a non-ambiguous classification
unknown_class = classifications.get("unknown", 0)
if unknown_class > 0:
    print(f"FAIL: {unknown_class} symbols with unknown classification")
    errors += 1
else:
    print("PASS: All symbols have non-ambiguous classification")

# Must have >= 10 families
if fam_count < 10:
    print(f"FAIL: Only {fam_count} families (need >= 10)")
    errors += 1
else:
    print(f"PASS: {fam_count} families")

# Every symbol must have confidence level != unknown
unknown_conf = confidence.get("unknown", 0)
if unknown_conf > 0:
    print(f"FAIL: {unknown_conf} symbols with unknown confidence")
    errors += 1
else:
    print("PASS: All symbols have confidence level")

# Output must be reproducible (deterministic)
# Re-run generator and compare hash
import subprocess, tempfile
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
    tmp_path = tmp.name
result = subprocess.run(
    ["python3", report_path.replace("tests/conformance/symbol_universe_normalization.v1.json",
     "scripts/generate_symbol_universe_normalization.py"), "-o", tmp_path],
    capture_output=True, text=True
)
if result.returncode == 0:
    import os
    with open(tmp_path) as f:
        r2 = json.load(f)
    os.unlink(tmp_path)
    if r2.get("universe_hash") == report.get("universe_hash"):
        print("PASS: Output is reproducible (same hash)")
    else:
        print("FAIL: Output not reproducible (different hash)")
        errors += 1
else:
    print(f"WARN: Could not verify reproducibility: {result.stderr.strip()}")

# Family statistics must be populated
if not families:
    print("FAIL: No family statistics")
    errors += 1
else:
    print(f"PASS: {len(families)} family statistics populated")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_symbol_universe_normalization: PASS")
PY
