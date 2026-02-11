#!/usr/bin/env bash
# check_math_value_proof.sh — CI gate for bd-3tp
#
# Validates that:
#   1. Math value proof JSON exists and is valid.
#   2. All production_core modules in governance have assessments.
#   3. All production_monitor modules in governance have assessments.
#   4. All retained modules meet the opportunity score threshold.
#   5. Score formula is consistent (impact * confidence / effort).
#   6. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/math_value_proof.json"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"

failures=0

echo "=== Math Value Proof Gate (bd-3tp) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/math_value_proof.json not found"
    echo ""
    echo "check_math_value_proof: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    core = s.get('production_core_assessments', [])
    monitor = s.get('production_monitor_assessments', [])
    scoring = s.get('scoring_methodology', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not core:
        print('INVALID: empty production_core_assessments')
    elif not monitor:
        print('INVALID: empty production_monitor_assessments')
    elif not scoring:
        print('INVALID: missing scoring_methodology')
    else:
        print(f'VALID version={v} core={len(core)} monitor={len(monitor)}')
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
# Check 2: Core modules match governance
# ---------------------------------------------------------------------------
echo "--- Check 2: Core modules match governance ---"

core_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${GOVERNANCE}') as f:
    gov = json.load(f)

errors = []

spec_core = set(a['module'] for a in spec.get('production_core_assessments', []))
gov_core = set(m['module'] for m in gov.get('classifications', {}).get('production_core', []))

missing = gov_core - spec_core
extra = spec_core - gov_core

for m in missing:
    errors.append(f'Core module in governance but not assessed: {m}')
for m in extra:
    errors.append(f'Core module assessed but not in governance: {m}')

print(f'CORE_ERRORS={len(errors)}')
print(f'SPEC_CORE={len(spec_core)} GOV_CORE={len(gov_core)}')
for e in errors:
    print(f'  {e}')
")

core_errs=$(echo "${core_check}" | grep '^CORE_ERRORS=' | cut -d= -f2)

if [[ "${core_errs}" -gt 0 ]]; then
    echo "FAIL: ${core_errs} core module error(s):"
    echo "${core_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All core modules assessed"
fi
echo "${core_check}" | grep -E '^SPEC' || true
echo ""

# ---------------------------------------------------------------------------
# Check 3: Monitor modules match governance
# ---------------------------------------------------------------------------
echo "--- Check 3: Monitor modules match governance ---"

mon_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${GOVERNANCE}') as f:
    gov = json.load(f)

errors = []

spec_mon = set(a['module'] for a in spec.get('production_monitor_assessments', []))
gov_mon = set(m['module'] for m in gov.get('classifications', {}).get('production_monitor', []))

missing = gov_mon - spec_mon
extra = spec_mon - gov_mon

for m in missing:
    errors.append(f'Monitor module in governance but not assessed: {m}')
for m in extra:
    errors.append(f'Monitor module assessed but not in governance: {m}')

print(f'MON_ERRORS={len(errors)}')
print(f'SPEC_MON={len(spec_mon)} GOV_MON={len(gov_mon)}')
for e in errors:
    print(f'  {e}')
")

mon_errs=$(echo "${mon_check}" | grep '^MON_ERRORS=' | cut -d= -f2)

if [[ "${mon_errs}" -gt 0 ]]; then
    echo "FAIL: ${mon_errs} monitor module error(s):"
    echo "${mon_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All monitor modules assessed"
fi
echo "${mon_check}" | grep -E '^SPEC' || true
echo ""

# ---------------------------------------------------------------------------
# Check 4: Retained modules meet threshold
# ---------------------------------------------------------------------------
echo "--- Check 4: Retention threshold ---"

threshold_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
threshold = spec.get('scoring_methodology', {}).get('retention_threshold', 2.0)

all_assessments = spec.get('production_core_assessments', []) + spec.get('production_monitor_assessments', [])

for a in all_assessments:
    module = a.get('module', '?')
    score = a.get('score', 0)
    verdict = a.get('verdict', '?')

    if verdict == 'retain' and score < threshold:
        errors.append(f'{module}: score={score} < threshold={threshold} but verdict=retain')
    if verdict == 'retire' and score >= threshold:
        errors.append(f'{module}: score={score} >= threshold={threshold} but verdict=retire')

print(f'THRESHOLD_ERRORS={len(errors)}')
print(f'ASSESSMENTS={len(all_assessments)} THRESHOLD={threshold}')
for e in errors:
    print(f'  {e}')
")

threshold_errs=$(echo "${threshold_check}" | grep '^THRESHOLD_ERRORS=' | cut -d= -f2)

if [[ "${threshold_errs}" -gt 0 ]]; then
    echo "FAIL: ${threshold_errs} threshold error(s):"
    echo "${threshold_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All retained modules meet score threshold"
fi
echo "${threshold_check}" | grep -E '^ASSESSMENTS' || true
echo ""

# ---------------------------------------------------------------------------
# Check 5: Score formula consistent
# ---------------------------------------------------------------------------
echo "--- Check 5: Score formula consistency ---"

formula_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
all_assessments = spec.get('production_core_assessments', []) + spec.get('production_monitor_assessments', [])

for a in all_assessments:
    module = a.get('module', '?')
    impact = a.get('impact', 0)
    confidence = a.get('confidence', 0)
    effort = a.get('effort', 1)
    claimed_score = a.get('score', 0)

    if effort == 0:
        errors.append(f'{module}: effort must be > 0')
        continue

    computed = round((impact * confidence) / effort, 1)
    if abs(computed - claimed_score) > 0.15:
        errors.append(f'{module}: claimed score={claimed_score} but computed={computed} (impact={impact} * confidence={confidence} / effort={effort})')

    # Check ranges
    for field, val in [('impact', impact), ('confidence', confidence), ('effort', effort)]:
        if not (1 <= val <= 5):
            errors.append(f'{module}: {field}={val} out of range [1,5]')

    # Required fields
    for field in ['value_category', 'baseline_alternative', 'measurable_benefit', 'evidence']:
        if not a.get(field):
            errors.append(f'{module}: missing {field}')

print(f'FORMULA_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

formula_errs=$(echo "${formula_check}" | grep '^FORMULA_ERRORS=' | cut -d= -f2)

if [[ "${formula_errs}" -gt 0 ]]; then
    echo "FAIL: ${formula_errs} formula error(s):"
    echo "${formula_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Score formula consistent for all assessments"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 6: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
summary = spec.get('summary', {})
core = spec.get('production_core_assessments', [])
monitor = spec.get('production_monitor_assessments', [])
all_a = core + monitor
threshold = spec.get('scoring_methodology', {}).get('retention_threshold', 2.0)

scores = [a.get('score', 0) for a in all_a]
min_score = min(scores) if scores else 0

if summary.get('total_modules_assessed', 0) != len(all_a):
    errors.append(f'total_modules_assessed: claimed={summary.get(\"total_modules_assessed\")} actual={len(all_a)}')
if summary.get('core_assessments', 0) != len(core):
    errors.append(f'core_assessments: claimed={summary.get(\"core_assessments\")} actual={len(core)}')
if summary.get('monitor_assessments', 0) != len(monitor):
    errors.append(f'monitor_assessments: claimed={summary.get(\"monitor_assessments\")} actual={len(monitor)}')
if summary.get('retention_threshold', 0) != threshold:
    errors.append(f'retention_threshold mismatch')

all_retained = all(a.get('verdict') == 'retain' for a in all_a)
if summary.get('all_retained', False) != all_retained:
    errors.append(f'all_retained: claimed={summary.get(\"all_retained\")} actual={all_retained}')

if abs(summary.get('min_score', 0) - min_score) > 0.15:
    errors.append(f'min_score: claimed={summary.get(\"min_score\")} actual={min_score}')

research_count = spec.get('research_assessment', {}).get('module_count', 0)
if summary.get('research_modules_excluded', 0) != research_count:
    errors.append(f'research_modules_excluded: claimed={summary.get(\"research_modules_excluded\")} actual={research_count}')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Core: {len(core)} | Monitor: {len(monitor)} | Min score: {min_score} | All retained: {all_retained} | Research: {research_count}')
for e in errors:
    print(f'  {e}')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary error(s):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${sum_check}" | grep -E '^Core' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_math_value_proof: FAILED"
    exit 1
fi

echo ""
echo "check_math_value_proof: PASS"
