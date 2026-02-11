#!/usr/bin/env bash
# check_isomorphism_proof.sh — CI gate for bd-2bd
#
# Validates that:
#   1. Isomorphism proof protocol JSON exists and is valid.
#   2. All proof categories are defined with required checks.
#   3. Proof template has required fields.
#   4. Applicable modules reference valid ABI modules.
#   5. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROTOCOL="${ROOT}/tests/conformance/isomorphism_proof_protocol.json"
MATRIX="${ROOT}/support_matrix.json"

failures=0

echo "=== Isomorphism Proof Gate (bd-2bd) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Protocol file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Protocol file exists and is valid ---"

if [[ ! -f "${PROTOCOL}" ]]; then
    echo "FAIL: tests/conformance/isomorphism_proof_protocol.json not found"
    echo ""
    echo "check_isomorphism_proof: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${PROTOCOL}') as f:
        proto = json.load(f)
    v = proto.get('schema_version', 0)
    cats = proto.get('proof_categories', {})
    template = proto.get('proof_template', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not cats:
        print('INVALID: empty proof_categories')
    elif not template:
        print('INVALID: empty proof_template')
    else:
        print(f'VALID version={v} categories={len(cats)}')
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
# Check 2: All proof categories defined with required checks
# ---------------------------------------------------------------------------
echo "--- Check 2: Proof category definitions ---"

cat_check=$(python3 -c "
import json

with open('${PROTOCOL}') as f:
    proto = json.load(f)

cats = proto.get('proof_categories', {})
errors = []

expected_cats = ['ordering', 'tie_breaking', 'fp_behavior', 'rng_behavior', 'side_effects', 'memory_semantics']

for cat_name in expected_cats:
    if cat_name not in cats:
        errors.append(f'Missing category: {cat_name}')
        continue
    cat = cats[cat_name]
    if not cat.get('description'):
        errors.append(f'{cat_name}: missing description')
    checks = cat.get('required_checks', [])
    if not checks:
        errors.append(f'{cat_name}: empty required_checks')
    if not cat.get('golden_format'):
        errors.append(f'{cat_name}: missing golden_format')

print(f'CATEGORY_ERRORS={len(errors)}')
print(f'CATEGORIES={len(cats)}')
for e in errors:
    print(f'  {e}')
")

cat_errs=$(echo "${cat_check}" | grep '^CATEGORY_ERRORS=' | cut -d= -f2)

if [[ "${cat_errs}" -gt 0 ]]; then
    echo "FAIL: ${cat_errs} category definition error(s):"
    echo "${cat_check}" | grep '  '
    failures=$((failures + 1))
else
    cat_count=$(echo "${cat_check}" | grep '^CATEGORIES=' | cut -d= -f2)
    echo "PASS: All ${cat_count} proof categories defined with checks and golden formats"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Proof template has required fields
# ---------------------------------------------------------------------------
echo "--- Check 3: Proof template ---"

tmpl_check=$(python3 -c "
import json

with open('${PROTOCOL}') as f:
    proto = json.load(f)

template = proto.get('proof_template', {})
errors = []

required = template.get('required_fields', [])
expected_required = ['lever_id', 'bead_id', 'functions', 'categories', 'golden_commands', 'golden_hash', 'proof_status']

for field in expected_required:
    if field not in required:
        errors.append(f'required_fields missing: {field}')

statuses = template.get('proof_statuses', [])
expected_statuses = ['pending', 'verified', 'failed', 'waived']
for st in expected_statuses:
    if st not in statuses:
        errors.append(f'proof_statuses missing: {st}')

example = template.get('example', {})
if not example:
    errors.append('Missing example proof')
else:
    for field in expected_required:
        if field not in example:
            errors.append(f'Example missing required field: {field}')

print(f'TEMPLATE_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

tmpl_errs=$(echo "${tmpl_check}" | grep '^TEMPLATE_ERRORS=' | cut -d= -f2)

if [[ "${tmpl_errs}" -gt 0 ]]; then
    echo "FAIL: ${tmpl_errs} template error(s):"
    echo "${tmpl_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Proof template complete with required fields, statuses, and example"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Applicable modules reference valid ABI modules
# ---------------------------------------------------------------------------
echo "--- Check 4: Applicable modules ---"

mod_check=$(python3 -c "
import json

with open('${PROTOCOL}') as f:
    proto = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []

# Get valid modules from matrix
valid_modules = set()
for sym in matrix.get('symbols', []):
    valid_modules.add(sym.get('module', ''))

applicable = proto.get('applicable_modules', {})
all_entries = []
for priority in ['high_priority', 'medium_priority', 'low_priority']:
    entries = applicable.get(priority, [])
    for entry in entries:
        mod_name = entry.get('module', '')
        all_entries.append(mod_name)
        if mod_name not in valid_modules:
            errors.append(f'{mod_name} ({priority}): not a valid ABI module')
        if not entry.get('reason'):
            errors.append(f'{mod_name} ({priority}): missing reason')

# Check for duplicates
seen = set()
for m in all_entries:
    if m in seen:
        errors.append(f'{m}: duplicate entry in applicable_modules')
    seen.add(m)

print(f'MODULE_ERRORS={len(errors)}')
print(f'TOTAL_MODULES={len(all_entries)}')
for e in errors:
    print(f'  {e}')
")

mod_errs=$(echo "${mod_check}" | grep '^MODULE_ERRORS=' | cut -d= -f2)

if [[ "${mod_errs}" -gt 0 ]]; then
    echo "FAIL: ${mod_errs} module reference error(s):"
    echo "${mod_check}" | grep '  '
    failures=$((failures + 1))
else
    mod_total=$(echo "${mod_check}" | grep '^TOTAL_MODULES=' | cut -d= -f2)
    echo "PASS: All ${mod_total} applicable modules reference valid ABI modules"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${PROTOCOL}') as f:
    proto = json.load(f)

errors = []
summary = proto.get('summary', {})
cats = proto.get('proof_categories', {})
applicable = proto.get('applicable_modules', {})
proofs = proto.get('existing_proofs', [])

if summary.get('total_categories', 0) != len(cats):
    errors.append(f'total_categories: claimed={summary.get(\"total_categories\")} actual={len(cats)}')

for priority in ['high_priority', 'medium_priority', 'low_priority']:
    key = priority + '_modules'
    claimed = summary.get(key, 0)
    actual = len(applicable.get(priority, []))
    if claimed != actual:
        errors.append(f'{key}: claimed={claimed} actual={actual}')

if summary.get('existing_proof_count', -1) != len(proofs):
    errors.append(f'existing_proof_count: claimed={summary.get(\"existing_proof_count\")} actual={len(proofs)}')

print(f'SUMMARY_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary inconsistency(ies):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_isomorphism_proof: FAILED"
    exit 1
fi

echo ""
echo "check_isomorphism_proof: PASS"
