#!/usr/bin/env bash
# check_perf_budget.sh — CI gate for bd-2r0
#
# Validates that:
#   1. Perf budget policy JSON exists and is valid.
#   2. Hotpath symbol list matches support_matrix.json perf_class assignments.
#   3. Budget thresholds are consistent with replacement_levels.json.
#   4. Active waivers reference valid beads.
#   5. Assessment counts match support_matrix.json.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/perf_budget_policy.json"
MATRIX="${ROOT}/support_matrix.json"
LEVELS="${ROOT}/tests/conformance/replacement_levels.json"
BEADS="${ROOT}/.beads/issues.jsonl"

failures=0

echo "=== Perf Budget Gate (bd-2r0) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Policy file exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Policy file exists and is valid ---"

if [[ ! -f "${POLICY}" ]]; then
    echo "FAIL: tests/conformance/perf_budget_policy.json not found"
    echo ""
    echo "check_perf_budget: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${POLICY}') as f:
        pol = json.load(f)
    v = pol.get('schema_version', 0)
    budgets = pol.get('budgets', {})
    hotpath = pol.get('hotpath_symbols', {})
    assessment = pol.get('current_assessment', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not budgets:
        print('INVALID: empty budgets')
    elif not hotpath:
        print('INVALID: empty hotpath_symbols')
    elif not assessment:
        print('INVALID: empty current_assessment')
    else:
        strict_count = len(hotpath.get('strict_hotpath', []))
        print(f'VALID version={v} budgets={len(budgets)} hotpath_symbols={strict_count}')
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
# Check 2: Hotpath symbols match support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 2: Hotpath symbols match support_matrix ---"

hotpath_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []

# Build set of strict_hotpath symbols from matrix
matrix_strict = set()
for sym in matrix.get('symbols', []):
    if sym.get('perf_class') == 'strict_hotpath':
        matrix_strict.add(sym['symbol'])

# Build set from policy
policy_strict = set()
for entry in pol.get('hotpath_symbols', {}).get('strict_hotpath', []):
    policy_strict.add(entry['symbol'])

missing = matrix_strict - policy_strict
extra = policy_strict - matrix_strict

if missing:
    for s in sorted(missing):
        errors.append(f'MISSING from policy: {s} (in matrix as strict_hotpath)')
if extra:
    for s in sorted(extra):
        errors.append(f'EXTRA in policy: {s} (not strict_hotpath in matrix)')

# Verify module/status match for shared symbols
for entry in pol.get('hotpath_symbols', {}).get('strict_hotpath', []):
    sym_name = entry['symbol']
    if sym_name not in matrix_strict:
        continue
    matrix_sym = next((s for s in matrix['symbols'] if s['symbol'] == sym_name), None)
    if matrix_sym:
        if entry.get('module') != matrix_sym.get('module'):
            errors.append(f'{sym_name}: module mismatch policy={entry.get(\"module\")} matrix={matrix_sym.get(\"module\")}')
        if entry.get('status') != matrix_sym.get('status'):
            errors.append(f'{sym_name}: status mismatch policy={entry.get(\"status\")} matrix={matrix_sym.get(\"status\")}')

print(f'HOTPATH_ERRORS={len(errors)}')
print(f'MATRIX_STRICT={len(matrix_strict)}')
print(f'POLICY_STRICT={len(policy_strict)}')
for e in errors:
    print(f'  {e}')
")

hotpath_errs=$(echo "${hotpath_check}" | grep '^HOTPATH_ERRORS=' | cut -d= -f2)

if [[ "${hotpath_errs}" -gt 0 ]]; then
    echo "FAIL: ${hotpath_errs} hotpath symbol mismatch(es):"
    echo "${hotpath_check}" | grep '  '
    failures=$((failures + 1))
else
    matrix_ct=$(echo "${hotpath_check}" | grep '^MATRIX_STRICT=' | cut -d= -f2)
    policy_ct=$(echo "${hotpath_check}" | grep '^POLICY_STRICT=' | cut -d= -f2)
    echo "PASS: ${policy_ct} policy symbols match ${matrix_ct} matrix strict_hotpath symbols"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Budget thresholds consistent with replacement_levels.json
# ---------------------------------------------------------------------------
echo "--- Check 3: Budget thresholds vs replacement levels ---"

budget_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)

errors = []
budgets = pol.get('budgets', {})

# Check replacement levels if available
try:
    with open('${LEVELS}') as f:
        lvl = json.load(f)

    for entry in lvl.get('levels', []):
        gc = entry.get('gate_criteria', {})
        lid = entry.get('level', '?')
        strict_ns = gc.get('perf_budget_strict_ns')
        hardened_ns = gc.get('perf_budget_hardened_ns')

        pol_strict = budgets.get('strict_hotpath', {}).get('strict_mode_ns')
        pol_hardened = budgets.get('strict_hotpath', {}).get('hardened_mode_ns')

        if strict_ns is not None and pol_strict is not None:
            if pol_strict != strict_ns:
                errors.append(f'{lid}: strict budget policy={pol_strict}ns levels={strict_ns}ns')
        if hardened_ns is not None and pol_hardened is not None:
            if pol_hardened != hardened_ns:
                errors.append(f'{lid}: hardened budget policy={pol_hardened}ns levels={hardened_ns}ns')
except FileNotFoundError:
    errors.append('replacement_levels.json not found (skipping cross-check)')

print(f'BUDGET_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

budget_errs=$(echo "${budget_check}" | grep '^BUDGET_ERRORS=' | cut -d= -f2)

if [[ "${budget_errs}" -gt 0 ]]; then
    echo "FAIL: ${budget_errs} budget threshold inconsistency(ies):"
    echo "${budget_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Budget thresholds consistent with replacement levels"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Active waivers reference tracked beads
# ---------------------------------------------------------------------------
echo "--- Check 4: Waiver bead references ---"

waiver_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)

errors = []
waivers = pol.get('active_waivers', [])

# Load beads
bead_ids = set()
try:
    with open('${BEADS}') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            bead_ids.add(obj.get('id', ''))
except FileNotFoundError:
    pass

for w in waivers:
    bid = w.get('bead_id', '')
    if not bid:
        errors.append('Waiver missing bead_id')
        continue
    if bid not in bead_ids:
        errors.append(f'Waiver bead {bid} not found in issues.jsonl')

    for req in ['symbols', 'justification', 'expires_at']:
        if not w.get(req):
            errors.append(f'Waiver {bid}: missing required field \"{req}\"')

print(f'WAIVER_ERRORS={len(errors)}')
print(f'ACTIVE_WAIVERS={len(waivers)}')
for e in errors:
    print(f'  {e}')
")

waiver_errs=$(echo "${waiver_check}" | grep '^WAIVER_ERRORS=' | cut -d= -f2)
waiver_count=$(echo "${waiver_check}" | grep '^ACTIVE_WAIVERS=' | cut -d= -f2)

if [[ "${waiver_errs}" -gt 0 ]]; then
    echo "FAIL: ${waiver_errs} waiver error(s):"
    echo "${waiver_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: ${waiver_count} active waiver(s), all reference tracked beads"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Assessment counts match support_matrix.json
# ---------------------------------------------------------------------------
echo "--- Check 5: Assessment counts ---"

assess_check=$(python3 -c "
import json

with open('${POLICY}') as f:
    pol = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
assessment = pol.get('current_assessment', {})
symbols = matrix.get('symbols', [])

# Count perf_class from matrix
class_counts = {}
for sym in symbols:
    pc = sym.get('perf_class', 'coldpath')
    class_counts[pc] = class_counts.get(pc, 0) + 1

# Total
if assessment.get('total_symbols', 0) != len(symbols):
    errors.append(f'total_symbols: policy={assessment.get(\"total_symbols\")} matrix={len(symbols)}')

for pc, json_key in [('strict_hotpath', 'strict_hotpath_count'),
                      ('hardened_hotpath', 'hardened_hotpath_count'),
                      ('coldpath', 'coldpath_count')]:
    actual = class_counts.get(pc, 0)
    claimed = assessment.get(json_key, 0)
    if claimed != actual:
        errors.append(f'{json_key}: policy={claimed} matrix={actual}')

# Check by_module breakdown
by_mod = assessment.get('strict_hotpath_by_module', {})
mod_counts = {}
for sym in symbols:
    if sym.get('perf_class') == 'strict_hotpath':
        m = sym.get('module', 'unknown')
        mod_counts[m] = mod_counts.get(m, 0) + 1

for m, claimed in by_mod.items():
    actual = mod_counts.get(m, 0)
    if claimed != actual:
        errors.append(f'strict_hotpath_by_module.{m}: policy={claimed} matrix={actual}')

for m, actual in mod_counts.items():
    if m not in by_mod:
        errors.append(f'strict_hotpath_by_module missing {m} ({actual} symbols)')

# Check by_status breakdown
by_status = assessment.get('strict_hotpath_by_status', {})
status_counts = {}
for sym in symbols:
    if sym.get('perf_class') == 'strict_hotpath':
        s = sym.get('status', 'Unknown')
        status_counts[s] = status_counts.get(s, 0) + 1

for s, claimed in by_status.items():
    actual = status_counts.get(s, 0)
    if claimed != actual:
        errors.append(f'strict_hotpath_by_status.{s}: policy={claimed} matrix={actual}')

print(f'ASSESS_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')

# Distribution
total = len(symbols)
for pc in ['strict_hotpath', 'hardened_hotpath', 'coldpath']:
    c = class_counts.get(pc, 0)
    pct = round(c * 100 / total) if total > 0 else 0
    print(f'{pc}: {c} ({pct}%)')
")

assess_errs=$(echo "${assess_check}" | grep '^ASSESS_ERRORS=' | cut -d= -f2)

if [[ "${assess_errs}" -gt 0 ]]; then
    echo "FAIL: ${assess_errs} assessment mismatch(es):"
    echo "${assess_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Assessment counts match support_matrix.json"
fi
echo "${assess_check}" | grep -E '^(strict_hotpath|hardened_hotpath|coldpath):' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_perf_budget: FAILED"
    exit 1
fi

echo ""
echo "check_perf_budget: PASS"
