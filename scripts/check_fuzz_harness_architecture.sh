#!/usr/bin/env bash
# check_fuzz_harness_architecture.sh — CI gate for bd-1oz.5
# Validates fuzz harness architecture spec and corpus seeding strategy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fuzz_harness_architecture.v1.json"

echo "=== Fuzz Harness Architecture Gate (bd-1oz.5) ==="

echo "--- Generating fuzz architecture report ---"
python3 "$SCRIPT_DIR/generate_fuzz_harness_architecture.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: fuzz architecture report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
targets = report.get("target_analyses", [])
corpus = report.get("corpus_strategy", {})
dicts = report.get("dictionary_strategy", {})

total = summary.get("total_targets", 0)
functional = summary.get("functional_targets", 0)
checks_passed = summary.get("checks_passed", 0)
checks_total = summary.get("checks_total", 0)
total_seeds = summary.get("total_seed_corpus", 0)
total_dict = summary.get("total_dict_entries", 0)
unique_cwes = summary.get("unique_cwes", 0)

print(f"Fuzz targets:            {total}")
print(f"  Functional:            {functional}")
print(f"  Stubs:                 {total - functional}")
print(f"  Convention checks:     {checks_passed}/{checks_total}")
print(f"  Seed corpus entries:   {total_seeds}")
print(f"  Dictionary entries:    {total_dict}")
print(f"  CWEs covered:          {unique_cwes}")
print()

# Must have fuzz targets
if total == 0:
    print("FAIL: No fuzz targets found")
    errors += 1
else:
    print(f"PASS: {total} fuzz targets found")

# Must have at least 1 functional target
if functional < 1:
    print("FAIL: No functional fuzz targets")
    errors += 1
else:
    print(f"PASS: {functional} functional targets")

# All convention checks must pass
if checks_passed < checks_total:
    print(f"FAIL: {checks_total - checks_passed} convention check failures")
    errors += 1
else:
    print(f"PASS: All {checks_total} convention checks passed")

# Must have seed corpus for each target
corpus_manifests = corpus.get("manifests", [])
seeded = sum(1 for m in corpus_manifests if m.get("count", 0) > 0)
if seeded < total:
    print(f"FAIL: Only {seeded}/{total} targets have seed corpus")
    errors += 1
else:
    print(f"PASS: All {total} targets have seed corpus")

# Must have dictionaries for each target
dict_manifests = dicts.get("manifests", [])
dict_count = sum(1 for m in dict_manifests if m.get("count", 0) > 0)
if dict_count < total:
    print(f"FAIL: Only {dict_count}/{total} targets have dictionaries")
    errors += 1
else:
    print(f"PASS: All {total} targets have dictionaries")

# Must cover at least 5 CWEs
if unique_cwes < 5:
    print(f"FAIL: Only {unique_cwes} CWEs covered (need >= 5)")
    errors += 1
else:
    print(f"PASS: {unique_cwes} CWEs covered")

# Corpus must be deterministic
for m in corpus_manifests:
    if not m.get("reproducible", False):
        print(f"FAIL: Corpus for {m['target']} is not reproducible")
        errors += 1
        break
else:
    print("PASS: All corpora are deterministic/reproducible")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_fuzz_harness_architecture: PASS")
PY
