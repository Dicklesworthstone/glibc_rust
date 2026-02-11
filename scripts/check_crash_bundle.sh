#!/usr/bin/env bash
# check_crash_bundle.sh — CI gate for bd-6yd
#
# Validates that:
#   1. Crash bundle spec JSON exists and is valid.
#   2. All required artifacts are declared with max_size_bytes.
#   3. Determinism rules are complete and referenced.
#   4. Reproduction checklist covers command + env + mode.
#   5. Runner integration status is tracked.
#   6. Summary statistics are consistent.
#
# This gate validates the crash bundle specification structure.
# It does NOT generate or inspect actual crash bundles (that's the runners' job).
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/crash_bundle_spec.json"

failures=0

echo "=== Crash Bundle Gate (bd-6yd) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Crash bundle spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/crash_bundle_spec.json not found"
    echo ""
    echo "check_crash_bundle: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    fmt = s.get('bundle_format', {})
    required = fmt.get('required_artifacts', [])
    optional = fmt.get('optional_artifacts', [])
    det = s.get('determinism_requirements', {})
    repro = s.get('reproduction_requirements', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not required:
        print('INVALID: empty required_artifacts')
    elif not det:
        print('INVALID: missing determinism_requirements')
    elif not repro:
        print('INVALID: missing reproduction_requirements')
    else:
        print(f'VALID version={v} required={len(required)} optional={len(optional)}')
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
# Check 2: All required artifacts have max_size_bytes
# ---------------------------------------------------------------------------
echo "--- Check 2: Required artifacts have size bounds ---"

bounds_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
required = spec.get('bundle_format', {}).get('required_artifacts', [])

for art in required:
    name = art.get('filename', '?')
    if 'max_size_bytes' not in art:
        errors.append(f'{name}: missing max_size_bytes')
    elif not isinstance(art['max_size_bytes'], int) or art['max_size_bytes'] <= 0:
        errors.append(f'{name}: invalid max_size_bytes={art.get(\"max_size_bytes\")}')
    if 'description' not in art or not art['description']:
        errors.append(f'{name}: missing description')
    if 'format' not in art or not art['format']:
        errors.append(f'{name}: missing format')

print(f'BOUNDS_ERRORS={len(errors)}')
print(f'ARTIFACTS={len(required)}')
for e in errors:
    print(f'  {e}')
")

bounds_errs=$(echo "${bounds_check}" | grep '^BOUNDS_ERRORS=' | cut -d= -f2)

if [[ "${bounds_errs}" -gt 0 ]]; then
    echo "FAIL: ${bounds_errs} size bound error(s):"
    echo "${bounds_check}" | grep '  '
    failures=$((failures + 1))
else
    count=$(echo "${bounds_check}" | grep '^ARTIFACTS=' | cut -d= -f2)
    echo "PASS: All ${count} required artifacts have valid size bounds"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Determinism rules are complete
# ---------------------------------------------------------------------------
echo "--- Check 3: Determinism rules ---"

det_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
rules = spec.get('determinism_requirements', {}).get('rules', [])

if len(rules) < 3:
    errors.append(f'Too few determinism rules: {len(rules)} (need >= 3)')

seen_ids = set()
for rule in rules:
    rid = rule.get('id', '?')
    if rid in seen_ids:
        errors.append(f'Duplicate rule ID: {rid}')
    seen_ids.add(rid)
    if 'rule' not in rule or not rule['rule']:
        errors.append(f'{rid}: missing rule text')
    if 'rationale' not in rule or not rule['rationale']:
        errors.append(f'{rid}: missing rationale')

# Verify max_bundle_size rule exists
has_bundle_limit = any('bundle' in r.get('rule', '').lower() and 'size' in r.get('rule', '').lower() for r in rules)
if not has_bundle_limit:
    errors.append('No rule constraining total bundle size')

# Verify truncation rule exists
has_truncation = any('truncat' in r.get('rule', '').lower() for r in rules)
if not has_truncation:
    errors.append('No rule for output truncation')

print(f'DET_ERRORS={len(errors)}')
print(f'RULES={len(rules)}')
for e in errors:
    print(f'  {e}')
")

det_errs=$(echo "${det_check}" | grep '^DET_ERRORS=' | cut -d= -f2)

if [[ "${det_errs}" -gt 0 ]]; then
    echo "FAIL: ${det_errs} determinism rule error(s):"
    echo "${det_check}" | grep '  '
    failures=$((failures + 1))
else
    rcount=$(echo "${det_check}" | grep '^RULES=' | cut -d= -f2)
    echo "PASS: ${rcount} determinism rules validated (bundle size limit + truncation present)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Reproduction checklist covers essentials
# ---------------------------------------------------------------------------
echo "--- Check 4: Reproduction checklist ---"

repro_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
checklist = spec.get('reproduction_requirements', {}).get('checklist', [])

if len(checklist) < 3:
    errors.append(f'Too few reproduction checklist items: {len(checklist)} (need >= 3)')

# Must mention command, env, and mode
checklist_text = ' '.join(checklist).lower()
required_concepts = {
    'command': ['command', 'shline', 're-run'],
    'environment': ['env', 'environment'],
    'mode': ['mode'],
}

for concept, keywords in required_concepts.items():
    if not any(kw in checklist_text for kw in keywords):
        errors.append(f'Reproduction checklist missing concept: {concept}')

print(f'REPRO_ERRORS={len(errors)}')
print(f'CHECKLIST_ITEMS={len(checklist)}')
for e in errors:
    print(f'  {e}')
")

repro_errs=$(echo "${repro_check}" | grep '^REPRO_ERRORS=' | cut -d= -f2)

if [[ "${repro_errs}" -gt 0 ]]; then
    echo "FAIL: ${repro_errs} reproduction checklist error(s):"
    echo "${repro_check}" | grep '  '
    failures=$((failures + 1))
else
    items=$(echo "${repro_check}" | grep '^CHECKLIST_ITEMS=' | cut -d= -f2)
    echo "PASS: ${items} reproduction checklist items (command + env + mode covered)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Runner integration status tracked
# ---------------------------------------------------------------------------
echo "--- Check 5: Runner integration status ---"

runner_check=$(python3 -c "
import json, os

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
runners = spec.get('integration', {}).get('runners', [])

if not runners:
    errors.append('No runners listed in integration section')

for runner in runners:
    script = runner.get('script', '?')
    status = runner.get('status', '?')

    # Script must exist on disk
    path = os.path.join('${ROOT}', script)
    if not os.path.isfile(path):
        errors.append(f'{script}: script not found')

    # Status must be one of known values
    if status not in ('full', 'partial', 'none'):
        errors.append(f'{script}: invalid status \"{status}\" (must be full/partial/none)')

    # If partial, must list missing artifacts
    if status == 'partial':
        missing = runner.get('missing', [])
        if not missing:
            errors.append(f'{script}: status=partial but no missing artifacts listed')

print(f'RUNNER_ERRORS={len(errors)}')
print(f'RUNNERS={len(runners)}')
for e in errors:
    print(f'  {e}')
")

runner_errs=$(echo "${runner_check}" | grep '^RUNNER_ERRORS=' | cut -d= -f2)

if [[ "${runner_errs}" -gt 0 ]]; then
    echo "FAIL: ${runner_errs} runner integration error(s):"
    echo "${runner_check}" | grep '  '
    failures=$((failures + 1))
else
    rcount=$(echo "${runner_check}" | grep '^RUNNERS=' | cut -d= -f2)
    echo "PASS: ${rcount} runner(s) tracked with valid integration status"
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
fmt = spec.get('bundle_format', {})
required = fmt.get('required_artifacts', [])
optional = fmt.get('optional_artifacts', [])
det_rules = spec.get('determinism_requirements', {}).get('rules', [])
repro_items = spec.get('reproduction_requirements', {}).get('checklist', [])
runners = spec.get('integration', {}).get('runners', [])

if summary.get('required_artifacts', 0) != len(required):
    errors.append(f'required_artifacts: claimed={summary.get(\"required_artifacts\")} actual={len(required)}')
if summary.get('optional_artifacts', 0) != len(optional):
    errors.append(f'optional_artifacts: claimed={summary.get(\"optional_artifacts\")} actual={len(optional)}')
if summary.get('determinism_rules', 0) != len(det_rules):
    errors.append(f'determinism_rules: claimed={summary.get(\"determinism_rules\")} actual={len(det_rules)}')
if summary.get('reproduction_checklist_items', 0) != len(repro_items):
    errors.append(f'reproduction_checklist_items: claimed={summary.get(\"reproduction_checklist_items\")} actual={len(repro_items)}')
if summary.get('runners_integrated', 0) != len(runners):
    errors.append(f'runners_integrated: claimed={summary.get(\"runners_integrated\")} actual={len(runners)}')

# max_bundle_size should be 4MB
claimed_max = summary.get('max_bundle_size_bytes', 0)
if claimed_max != 4194304:
    errors.append(f'max_bundle_size_bytes: claimed={claimed_max} expected=4194304')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Required: {len(required)} | Optional: {len(optional)} | Rules: {len(det_rules)} | Checklist: {len(repro_items)} | Runners: {len(runners)}')
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
echo "${sum_check}" | grep -E '^Required' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_crash_bundle: FAILED"
    exit 1
fi

echo ""
echo "check_crash_bundle: PASS"
