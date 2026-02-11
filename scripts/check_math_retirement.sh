#!/usr/bin/env bash
# check_math_retirement.sh — CI gate for bd-545
#
# Validates that:
#   1. Math retirement policy JSON exists and is valid.
#   2. RC-1 candidates match governance research modules vs production manifest.
#   3. Production-compliant modules match governance production_core + production_monitor.
#   4. Active waivers cover all retirement candidates (no unwaived RC-1 violations).
#   5. Migration wave modules account for all RC-1 candidates.
#   6. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/math_retirement_policy.json"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"
MANIFEST="${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json"
LINKAGE="${ROOT}/tests/runtime_math/runtime_math_linkage.v1.json"

failures=0

echo "=== Math Retirement Gate (bd-545) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: File exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Retirement policy exists and is valid ---"

if [[ ! -f "${POLICY}" ]]; then
    echo "FAIL: tests/conformance/math_retirement_policy.json not found"
    echo ""
    echo "check_math_retirement: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${POLICY}') as f:
        p = json.load(f)
    v = p.get('schema_version', 0)
    rules = p.get('retirement_criteria', {}).get('rules', [])
    stages = p.get('deprecation_stages', {}).get('stages', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not rules:
        print('INVALID: empty retirement_criteria.rules')
    elif not stages:
        print('INVALID: empty deprecation_stages.stages')
    else:
        print(f'VALID version={v} rules={len(rules)} stages={len(stages)}')
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
# Check 2: RC-1 candidates match governance research vs manifest
# ---------------------------------------------------------------------------
echo "--- Check 2: RC-1 governance/manifest cross-reference ---"

rc1_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    policy = json.load(f)
with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

errors = []

# Get research modules from governance
research_modules = set(m['module'] for m in gov.get('classifications', {}).get('research', []))
# Get production manifest modules
manifest_modules = set(manifest.get('production_modules', []))

# Actual RC-1: research modules that are in production manifest
actual_rc1 = research_modules & manifest_modules

# Policy-claimed RC-1
claimed_rc1 = set(policy.get('current_assessment', {}).get('rc1_candidates', {}).get('modules', []))
claimed_count = policy.get('current_assessment', {}).get('rc1_candidates', {}).get('count', 0)

if claimed_rc1 != actual_rc1:
    missing = actual_rc1 - claimed_rc1
    extra = claimed_rc1 - actual_rc1
    if missing:
        errors.append(f'RC-1 missing modules: {sorted(missing)}')
    if extra:
        errors.append(f'RC-1 extra modules: {sorted(extra)}')

if claimed_count != len(actual_rc1):
    errors.append(f'RC-1 count: claimed={claimed_count} actual={len(actual_rc1)}')

print(f'RC1_ERRORS={len(errors)}')
print(f'RC1_ACTUAL={len(actual_rc1)}')
print(f'RESEARCH_TOTAL={len(research_modules)}')
print(f'MANIFEST_TOTAL={len(manifest_modules)}')
for e in errors:
    print(f'  {e}')
")

rc1_errs=$(echo "${rc1_check}" | grep '^RC1_ERRORS=' | cut -d= -f2)

if [[ "${rc1_errs}" -gt 0 ]]; then
    echo "FAIL: ${rc1_errs} RC-1 cross-reference error(s):"
    echo "${rc1_check}" | grep '  '
    failures=$((failures + 1))
else
    rc1_actual=$(echo "${rc1_check}" | grep '^RC1_ACTUAL=' | cut -d= -f2)
    echo "PASS: ${rc1_actual} RC-1 candidates match governance research vs manifest"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Production-compliant modules match governance
# ---------------------------------------------------------------------------
echo "--- Check 3: Production-compliant module cross-reference ---"

prod_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    policy = json.load(f)
with open('${GOVERNANCE}') as f:
    gov = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

errors = []

# Get production modules from governance
prod_core = set(m['module'] for m in gov.get('classifications', {}).get('production_core', []))
prod_monitor = set(m['module'] for m in gov.get('classifications', {}).get('production_monitor', []))
prod_all = prod_core | prod_monitor
manifest_modules = set(manifest.get('production_modules', []))

# Actual compliant: production governance modules that are in manifest
actual_compliant = prod_all & manifest_modules

# Policy-claimed compliant
claimed = policy.get('current_assessment', {}).get('production_compliant', {})
claimed_core = set(claimed.get('production_core', []))
claimed_monitor = set(claimed.get('production_monitor', []))
claimed_count = claimed.get('count', 0)

if claimed_core != prod_core:
    errors.append(f'production_core mismatch: claimed={sorted(claimed_core)} actual={sorted(prod_core)}')
if claimed_monitor != prod_monitor:
    errors.append(f'production_monitor mismatch: claimed={sorted(claimed_monitor)} actual={sorted(prod_monitor)}')
if claimed_count != len(actual_compliant):
    errors.append(f'compliant count: claimed={claimed_count} actual={len(actual_compliant)}')

# All production-compliant modules must be in manifest
not_in_manifest = prod_all - manifest_modules
if not_in_manifest:
    errors.append(f'Production modules missing from manifest: {sorted(not_in_manifest)}')

print(f'PROD_ERRORS={len(errors)}')
print(f'COMPLIANT={len(actual_compliant)}')
for e in errors:
    print(f'  {e}')
")

prod_errs=$(echo "${prod_check}" | grep '^PROD_ERRORS=' | cut -d= -f2)

if [[ "${prod_errs}" -gt 0 ]]; then
    echo "FAIL: ${prod_errs} production-compliant error(s):"
    echo "${prod_check}" | grep '  '
    failures=$((failures + 1))
else
    compliant=$(echo "${prod_check}" | grep '^COMPLIANT=' | cut -d= -f2)
    echo "PASS: ${compliant} production-compliant modules match governance"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Waiver coverage for RC-1 candidates
# ---------------------------------------------------------------------------
echo "--- Check 4: Waiver coverage for retirement candidates ---"

waiver_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    policy = json.load(f)

errors = []

rc1_modules = set(policy.get('current_assessment', {}).get('rc1_candidates', {}).get('modules', []))
rc1_count = len(rc1_modules)
waivers = policy.get('active_waivers', [])

# Check waiver fields
required_fields = policy.get('waiver_policy', {}).get('required_fields', [])
for w in waivers:
    for field in required_fields:
        if field not in w:
            errors.append(f'Waiver for {w.get(\"module\", \"?\")} missing field \"{field}\"')

# Check waiver coverage: every RC-1 module must be covered
covered_modules = set()
for w in waivers:
    if w.get('module') == 'ALL_RESEARCH':
        covered_modules = rc1_modules.copy()
    else:
        covered_modules.add(w.get('module', ''))

unwaived = rc1_modules - covered_modules
if unwaived:
    errors.append(f'{len(unwaived)} RC-1 modules without waiver: {sorted(unwaived)[:5]}...')

print(f'WAIVER_ERRORS={len(errors)}')
print(f'RC1_TOTAL={rc1_count}')
print(f'COVERED={len(covered_modules)}')
print(f'WAIVERS={len(waivers)}')
for e in errors:
    print(f'  {e}')
")

waiver_errs=$(echo "${waiver_check}" | grep '^WAIVER_ERRORS=' | cut -d= -f2)

if [[ "${waiver_errs}" -gt 0 ]]; then
    echo "FAIL: ${waiver_errs} waiver error(s):"
    echo "${waiver_check}" | grep '  '
    failures=$((failures + 1))
else
    covered=$(echo "${waiver_check}" | grep '^COVERED=' | cut -d= -f2)
    waivers=$(echo "${waiver_check}" | grep '^WAIVERS=' | cut -d= -f2)
    echo "PASS: ${covered} RC-1 candidates covered by ${waivers} waiver(s)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Migration waves account for all RC-1 candidates
# ---------------------------------------------------------------------------
echo "--- Check 5: Migration wave completeness ---"

wave_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    policy = json.load(f)

errors = []

rc1_modules = set(policy.get('current_assessment', {}).get('rc1_candidates', {}).get('modules', []))
migration = policy.get('migration_notes', {})
waves = migration.get('waves', [])

wave_modules = set()
wave_module_count = 0
for w in waves:
    mods = w.get('modules', [])
    wave_module_count += w.get('count', 0)
    for m in mods:
        if m in wave_modules:
            errors.append(f'Duplicate module in waves: {m}')
        wave_modules.add(m)
    if len(mods) != w.get('count', 0):
        errors.append(f'Wave {w.get(\"wave\")}: count={w.get(\"count\")} but {len(mods)} modules listed')

# All RC-1 must appear in some wave
missing = rc1_modules - wave_modules
extra = wave_modules - rc1_modules
if missing:
    errors.append(f'RC-1 modules not in any wave: {sorted(missing)}')
if extra:
    errors.append(f'Wave modules not in RC-1: {sorted(extra)}')

claimed_total = migration.get('total_modules_to_migrate', 0)
if claimed_total != len(wave_modules):
    errors.append(f'total_modules_to_migrate: claimed={claimed_total} actual={len(wave_modules)}')

claimed_waves = migration.get('total_waves', 0)
if claimed_waves != len(waves):
    errors.append(f'total_waves: claimed={claimed_waves} actual={len(waves)}')

print(f'WAVE_ERRORS={len(errors)}')
print(f'WAVES={len(waves)}')
print(f'WAVE_MODULES={len(wave_modules)}')
for e in errors:
    print(f'  {e}')
")

wave_errs=$(echo "${wave_check}" | grep '^WAVE_ERRORS=' | cut -d= -f2)

if [[ "${wave_errs}" -gt 0 ]]; then
    echo "FAIL: ${wave_errs} migration wave error(s):"
    echo "${wave_check}" | grep '  '
    failures=$((failures + 1))
else
    waves=$(echo "${wave_check}" | grep '^WAVES=' | cut -d= -f2)
    wmods=$(echo "${wave_check}" | grep '^WAVE_MODULES=' | cut -d= -f2)
    echo "PASS: ${wmods} modules across ${waves} migration waves cover all RC-1 candidates"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 6: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    policy = json.load(f)
with open('${MANIFEST}') as f:
    manifest = json.load(f)

errors = []
summary = policy.get('summary', {})
assessment = policy.get('current_assessment', {})

manifest_count = len(manifest.get('production_modules', []))
rc1_count = len(assessment.get('rc1_candidates', {}).get('modules', []))
compliant_count = assessment.get('production_compliant', {}).get('count', 0)

if summary.get('total_modules_in_manifest', 0) != manifest_count:
    errors.append(f'total_modules_in_manifest: claimed={summary.get(\"total_modules_in_manifest\")} actual={manifest_count}')
if summary.get('production_compliant', 0) != compliant_count:
    errors.append(f'production_compliant: claimed={summary.get(\"production_compliant\")} actual={compliant_count}')
if summary.get('retirement_candidates_rc1', 0) != rc1_count:
    errors.append(f'retirement_candidates_rc1: claimed={summary.get(\"retirement_candidates_rc1\")} actual={rc1_count}')

waivers = policy.get('active_waivers', [])
if summary.get('active_waivers', 0) != len(waivers):
    errors.append(f'active_waivers: claimed={summary.get(\"active_waivers\")} actual={len(waivers)}')

waves = policy.get('migration_notes', {}).get('waves', [])
if summary.get('migration_waves', 0) != len(waves):
    errors.append(f'migration_waves: claimed={summary.get(\"migration_waves\")} actual={len(waves)}')

# Manifest count should equal compliant + rc1
if manifest_count != compliant_count + rc1_count:
    errors.append(f'manifest_count({manifest_count}) != compliant({compliant_count}) + rc1({rc1_count})')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Manifest: {manifest_count} modules')
print(f'Compliant: {compliant_count} | RC-1 candidates: {rc1_count}')
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
echo "${sum_check}" | grep -E '^(Manifest|Compliant)' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_math_retirement: FAILED"
    exit 1
fi

echo ""
echo "check_math_retirement: PASS"
