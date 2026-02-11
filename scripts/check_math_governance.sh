#!/usr/bin/env bash
# check_math_governance.sh — CI gate for bd-2yx
#
# Validates that:
#   1. Math governance classification exists and is valid.
#   2. Every classified module exists in the production manifest.
#   3. No module is unclassified (manifest coverage).
#   4. No module appears in multiple tiers.
#   5. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"
MANIFEST="${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json"

failures=0

echo "=== Math Governance Gate (bd-2yx) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Governance file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Governance file exists ---"

if [[ ! -f "${GOVERNANCE}" ]]; then
    echo "FAIL: tests/conformance/math_governance.json not found"
    echo ""
    echo "check_math_governance: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${GOVERNANCE}') as f:
        gov = json.load(f)
    v = gov.get('schema_version', 0)
    tiers = gov.get('tiers', {})
    cls = gov.get('classifications', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not tiers:
        print('INVALID: empty tiers')
    elif not cls:
        print('INVALID: empty classifications')
    else:
        total = sum(len(cls.get(t, [])) for t in cls)
        print(f'VALID version={v} tiers={len(tiers)} classified={total}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: All classified modules exist in manifest
# ---------------------------------------------------------------------------
echo "--- Check 2: Classified modules exist in manifest ---"

manifest_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

manifest_modules = set(manifest.get('production_modules', []))
classifications = gov.get('classifications', {})
errors = []

for tier, entries in classifications.items():
    for entry in entries:
        module = entry.get('module', '')
        if module not in manifest_modules:
            errors.append(f'{module} (tier={tier}): not in production manifest')

print(f'MANIFEST_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

manifest_errs=$(echo "${manifest_check}" | grep '^MANIFEST_ERRORS=' | cut -d= -f2)

if [[ "${manifest_errs}" -gt 0 ]]; then
    echo "FAIL: ${manifest_errs} classified module(s) not in manifest:"
    echo "${manifest_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All classified modules exist in manifest"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Manifest coverage (no unclassified modules)
# ---------------------------------------------------------------------------
echo "--- Check 3: Manifest coverage ---"

coverage_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

manifest_modules = set(manifest.get('production_modules', []))
classifications = gov.get('classifications', {})

classified = set()
for tier, entries in classifications.items():
    for entry in entries:
        classified.add(entry.get('module', ''))

unclassified = manifest_modules - classified
extra = classified - manifest_modules

print(f'MANIFEST_MODULES={len(manifest_modules)}')
print(f'CLASSIFIED={len(classified)}')
print(f'UNCLASSIFIED={len(unclassified)}')
print(f'EXTRA={len(extra)}')

for m in sorted(unclassified):
    print(f'  UNCLASSIFIED: {m}')
for m in sorted(extra):
    print(f'  EXTRA: {m}')
")

unclassified=$(echo "${coverage_check}" | grep '^UNCLASSIFIED=' | cut -d= -f2)
extra=$(echo "${coverage_check}" | grep '^EXTRA=' | cut -d= -f2)

if [[ "${unclassified}" -gt 0 ]]; then
    echo "FAIL: ${unclassified} manifest module(s) not classified:"
    echo "${coverage_check}" | grep '  UNCLASSIFIED:'
    failures=$((failures + 1))
else
    echo "PASS: All manifest modules are classified"
fi

if [[ "${extra}" -gt 0 ]]; then
    echo "WARNING: ${extra} classified module(s) not in manifest:"
    echo "${coverage_check}" | grep '  EXTRA:'
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: No duplicate classifications
# ---------------------------------------------------------------------------
echo "--- Check 4: No duplicate classifications ---"

dup_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)

classifications = gov.get('classifications', {})
seen = {}
dups = []

for tier, entries in classifications.items():
    for entry in entries:
        module = entry.get('module', '')
        if module in seen:
            dups.append(f'{module}: in both {seen[module]} and {tier}')
        seen[module] = tier

print(f'DUPLICATES={len(dups)}')
for d in dups:
    print(f'  {d}')
")

dup_count=$(echo "${dup_check}" | grep '^DUPLICATES=' | cut -d= -f2)

if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} module(s) in multiple tiers:"
    echo "${dup_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: No duplicate classifications"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

summary_check=$(python3 -c "
import json

with open('${GOVERNANCE}') as f:
    gov = json.load(f)

classifications = gov.get('classifications', {})
summary = gov.get('summary', {})
errors = []

actual_counts = {}
total = 0
for tier, entries in classifications.items():
    actual_counts[tier] = len(entries)
    total += len(entries)

claimed_total = summary.get('total_modules', 0)
if claimed_total != total:
    errors.append(f'total_modules: claimed={claimed_total} actual={total}')

for tier in ['production_core', 'production_monitor', 'research']:
    claimed = summary.get(tier, 0)
    actual = actual_counts.get(tier, 0)
    if claimed != actual:
        errors.append(f'{tier}: claimed={claimed} actual={actual}')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution report
print()
for tier in ['production_core', 'production_monitor', 'research']:
    count = actual_counts.get(tier, 0)
    pct = round(count * 100 / total) if total > 0 else 0
    print(f'{tier}: {count} modules ({pct}%)')
")

summary_errs=$(echo "${summary_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${summary_errs}" -gt 0 ]]; then
    echo "FAIL: ${summary_errs} summary inconsistency(ies):"
    echo "${summary_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${summary_check}" | grep -E '^(production_|research:)'
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_math_governance: FAILED"
    exit 1
fi

echo ""
echo "check_math_governance: PASS"
