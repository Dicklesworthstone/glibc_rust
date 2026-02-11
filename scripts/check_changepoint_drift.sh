#!/usr/bin/env bash
# check_changepoint_drift.sh — CI gate for bd-3tc
#
# Validates that:
#   1. Changepoint drift policy JSON exists and is valid.
#   2. BOCPD parameters are internally consistent.
#   3. Routing policies cover all detector states.
#   4. Monitor integration references valid specs.
#   5. False positive control targets are defined.
#   6. Summary statistics are consistent.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/changepoint_drift_policy.json"
MONITOR_SPEC="${ROOT}/tests/conformance/anytime_valid_monitor_spec.json"

failures=0

echo "=== Changepoint Drift Policy Gate (bd-3tc) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/changepoint_drift_policy.json not found"
    echo ""
    echo "check_changepoint_drift: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    bocpd = s.get('bocpd_parameters', {})
    routing = s.get('routing_policy', {})
    integ = s.get('integration_with_monitors', {})
    fpc = s.get('false_positive_control', {})
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not bocpd:
        print('INVALID: missing bocpd_parameters')
    elif not routing:
        print('INVALID: missing routing_policy')
    elif not integ:
        print('INVALID: missing integration_with_monitors')
    elif not fpc:
        print('INVALID: missing false_positive_control')
    else:
        print(f'VALID version={v}')
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
# Check 2: BOCPD parameters internally consistent
# ---------------------------------------------------------------------------
echo "--- Check 2: BOCPD parameters ---"

bocpd_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
params = spec.get('bocpd_parameters', {}).get('parameters', {})

required = ['warmup_count', 'hazard_lambda', 'short_window', 'drift_threshold', 'changepoint_threshold', 'max_run_length', 'ewma_alpha', 'beta_prior']
for p in required:
    if p not in params:
        errors.append(f'Missing parameter: {p}')

if not errors:
    warmup = params['warmup_count']['value']
    drift_t = params['drift_threshold']['value']
    cp_t = params['changepoint_threshold']['value']
    max_rl = params['max_run_length']['value']
    short_w = params['short_window']['value']
    hazard = params['hazard_lambda']['value']

    if warmup < 1:
        errors.append(f'warmup_count must be >= 1, got {warmup}')
    if not (0 < drift_t < cp_t <= 1.0):
        errors.append(f'Must have 0 < drift_threshold ({drift_t}) < changepoint_threshold ({cp_t}) <= 1.0')
    if short_w < 1 or short_w > max_rl:
        errors.append(f'short_window ({short_w}) must be in [1, max_run_length ({max_rl})]')
    if hazard <= 0:
        errors.append(f'hazard_lambda must be > 0, got {hazard}')

# Check states
states = spec.get('bocpd_parameters', {}).get('states', [])
state_names = [s['state'] for s in states]
expected = ['Calibrating', 'Stable', 'Drift', 'ChangePoint']
for es in expected:
    if es not in state_names:
        errors.append(f'Missing BOCPD state: {es}')

print(f'BOCPD_ERRORS={len(errors)}')
print(f'PARAMS={len(required)} STATES={len(states)}')
for e in errors:
    print(f'  {e}')
")

bocpd_errs=$(echo "${bocpd_check}" | grep '^BOCPD_ERRORS=' | cut -d= -f2)

if [[ "${bocpd_errs}" -gt 0 ]]; then
    echo "FAIL: ${bocpd_errs} BOCPD parameter error(s):"
    echo "${bocpd_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: BOCPD parameters validated"
fi
echo "${bocpd_check}" | grep -E '^PARAMS' || true
echo ""

# ---------------------------------------------------------------------------
# Check 3: Routing policies cover all states
# ---------------------------------------------------------------------------
echo "--- Check 3: Routing policies ---"

routing_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
policies = spec.get('routing_policy', {}).get('policies', [])

if len(policies) < 3:
    errors.append(f'Too few routing policies: {len(policies)} (need >= 3)')

# Check each policy has required fields
seen_ids = set()
for p in policies:
    pid = p.get('id', '?')
    if pid in seen_ids:
        errors.append(f'Duplicate policy ID: {pid}')
    seen_ids.add(pid)
    if not p.get('state'):
        errors.append(f'{pid}: missing state')
    if not p.get('action'):
        errors.append(f'{pid}: missing action')
    if not p.get('description'):
        errors.append(f'{pid}: missing description')
    if 'escalation_level' not in p:
        errors.append(f'{pid}: missing escalation_level')

# Must cover Stable, Drift, ChangePoint
policy_states = set(p.get('state', '') for p in policies)
for required_state in ['Stable', 'Drift', 'ChangePoint']:
    if required_state not in policy_states:
        errors.append(f'No routing policy for state: {required_state}')

# Escalation levels must increase
stable_level = [p for p in policies if p.get('state') == 'Stable']
drift_level = [p for p in policies if p.get('state') == 'Drift']
cp_level = [p for p in policies if p.get('state') == 'ChangePoint']
if stable_level and drift_level:
    if stable_level[0].get('escalation_level', 0) >= drift_level[0].get('escalation_level', 0):
        errors.append('Stable escalation_level must be < Drift')
if drift_level and cp_level:
    if drift_level[0].get('escalation_level', 0) >= cp_level[0].get('escalation_level', 0):
        errors.append('Drift escalation_level must be < ChangePoint')

print(f'ROUTING_ERRORS={len(errors)}')
print(f'POLICIES={len(policies)}')
for e in errors:
    print(f'  {e}')
")

routing_errs=$(echo "${routing_check}" | grep '^ROUTING_ERRORS=' | cut -d= -f2)

if [[ "${routing_errs}" -gt 0 ]]; then
    echo "FAIL: ${routing_errs} routing policy error(s):"
    echo "${routing_check}" | grep '  '
    failures=$((failures + 1))
else
    pcount=$(echo "${routing_check}" | grep '^POLICIES=' | cut -d= -f2)
    echo "PASS: ${pcount} routing policies cover Stable/Drift/ChangePoint with increasing escalation"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Monitor integration references valid specs
# ---------------------------------------------------------------------------
echo "--- Check 4: Monitor integration ---"

integ_check=$(python3 -c "
import json, os

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
integ = spec.get('integration_with_monitors', {})

upstream = integ.get('upstream_feeds', [])
downstream = integ.get('downstream_consumers', [])

if not upstream:
    errors.append('No upstream feeds defined')
if not downstream:
    errors.append('No downstream consumers defined')

# Check upstream sources reference known monitors
valid_sources = {'eprocess', 'alpha_investing', 'changepoint', 'cvar', 'azuma_hoeffding'}
for feed in upstream:
    src = feed.get('source', '?')
    if src not in valid_sources:
        errors.append(f'Unknown upstream source: {src}')

# Check monitor_spec_ref exists
monitor_ref = integ.get('monitor_spec_ref', '')
if monitor_ref:
    ref_path = os.path.join('${ROOT}', monitor_ref)
    if not os.path.isfile(ref_path):
        errors.append(f'monitor_spec_ref not found: {monitor_ref}')

crash_ref = integ.get('crash_bundle_ref', '')
if crash_ref:
    ref_path = os.path.join('${ROOT}', crash_ref)
    if not os.path.isfile(ref_path):
        errors.append(f'crash_bundle_ref not found: {crash_ref}')

print(f'INTEG_ERRORS={len(errors)}')
print(f'UPSTREAM={len(upstream)} DOWNSTREAM={len(downstream)}')
for e in errors:
    print(f'  {e}')
")

integ_errs=$(echo "${integ_check}" | grep '^INTEG_ERRORS=' | cut -d= -f2)

if [[ "${integ_errs}" -gt 0 ]]; then
    echo "FAIL: ${integ_errs} integration error(s):"
    echo "${integ_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Monitor integration validated"
fi
echo "${integ_check}" | grep -E '^UPSTREAM' || true
echo ""

# ---------------------------------------------------------------------------
# Check 5: False positive control targets defined
# ---------------------------------------------------------------------------
echo "--- Check 5: False positive control ---"

fpc_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
fpc = spec.get('false_positive_control', {})
targets = fpc.get('targets', {})

if not targets:
    errors.append('No false positive control targets defined')

# Must have stable traffic FP rate target
if 'stable_traffic_fp_rate' not in targets:
    errors.append('Missing stable_traffic_fp_rate target')
elif 'target' not in targets['stable_traffic_fp_rate']:
    errors.append('stable_traffic_fp_rate missing target value')

# Must have recovery time target
if 'recovery_time' not in targets:
    errors.append('Missing recovery_time target')

# Check unit test coverage
test_coverage = fpc.get('unit_test_coverage', {})
tests = test_coverage.get('tests', [])
if len(tests) < 5:
    errors.append(f'Too few unit tests listed: {len(tests)} (need >= 5)')

print(f'FPC_ERRORS={len(errors)}')
print(f'TARGETS={len(targets)} UNIT_TESTS={len(tests)}')
for e in errors:
    print(f'  {e}')
")

fpc_errs=$(echo "${fpc_check}" | grep '^FPC_ERRORS=' | cut -d= -f2)

if [[ "${fpc_errs}" -gt 0 ]]; then
    echo "FAIL: ${fpc_errs} false positive control error(s):"
    echo "${fpc_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: False positive control targets defined"
fi
echo "${fpc_check}" | grep -E '^TARGETS' || true
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

bocpd_params = len(spec.get('bocpd_parameters', {}).get('parameters', {}))
bocpd_states = len(spec.get('bocpd_parameters', {}).get('states', []))
routing = len(spec.get('routing_policy', {}).get('policies', []))
upstream = len(spec.get('integration_with_monitors', {}).get('upstream_feeds', []))
downstream = len(spec.get('integration_with_monitors', {}).get('downstream_consumers', []))
fp_targets = len(spec.get('false_positive_control', {}).get('targets', {}))
unit_tests = len(spec.get('false_positive_control', {}).get('unit_test_coverage', {}).get('tests', []))

if summary.get('bocpd_parameters', 0) != bocpd_params:
    errors.append(f'bocpd_parameters: claimed={summary.get(\"bocpd_parameters\")} actual={bocpd_params}')
if summary.get('bocpd_states', 0) != bocpd_states:
    errors.append(f'bocpd_states: claimed={summary.get(\"bocpd_states\")} actual={bocpd_states}')
if summary.get('routing_policies', 0) != routing:
    errors.append(f'routing_policies: claimed={summary.get(\"routing_policies\")} actual={routing}')
if summary.get('upstream_feeds', 0) != upstream:
    errors.append(f'upstream_feeds: claimed={summary.get(\"upstream_feeds\")} actual={upstream}')
if summary.get('downstream_consumers', 0) != downstream:
    errors.append(f'downstream_consumers: claimed={summary.get(\"downstream_consumers\")} actual={downstream}')
if summary.get('false_positive_targets', 0) != fp_targets:
    errors.append(f'false_positive_targets: claimed={summary.get(\"false_positive_targets\")} actual={fp_targets}')
if summary.get('unit_tests', 0) != unit_tests:
    errors.append(f'unit_tests: claimed={summary.get(\"unit_tests\")} actual={unit_tests}')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'BOCPD: {bocpd_params} params, {bocpd_states} states | Routing: {routing} | Integration: {upstream}+{downstream} | FP: {fp_targets} | Tests: {unit_tests}')
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
echo "${sum_check}" | grep -E '^BOCPD' || true
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_changepoint_drift: FAILED"
    exit 1
fi

echo ""
echo "check_changepoint_drift: PASS"
