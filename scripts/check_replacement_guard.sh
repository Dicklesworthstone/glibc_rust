#!/usr/bin/env bash
# check_replacement_guard.sh — CI gate for bd-130
#
# Enforces the replacement profile guard: no glibc call-through permitted
# outside the interpose allowlist. In replacement mode (L2/L3), ALL modules
# must be free of host glibc function calls.
#
# Modes:
#   interpose  — allowlisted modules may call through (default)
#   replacement — zero call-through permitted anywhere
#
# Usage:
#   bash scripts/check_replacement_guard.sh [interpose|replacement]
#
# Exit codes:
#   0 — guard passes
#   1 — forbidden call-through detected
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"
PROFILE_DEF="${ROOT}/tests/conformance/replacement_profile.json"
MODE="${1:-interpose}"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/replacement_guard.log.jsonl"
REPORT_PATH="${OUT_DIR}/replacement_guard.report.json"

failures=0

echo "=== Replacement Profile Guard (bd-130) ==="
echo "mode=${MODE}"
echo ""
mkdir -p "${OUT_DIR}"

# ---------------------------------------------------------------------------
# Check 1: Profile definition exists
# ---------------------------------------------------------------------------
echo "--- Check 1: Profile definition ---"

if [[ ! -f "${PROFILE_DEF}" ]]; then
    echo "FAIL: tests/conformance/replacement_profile.json not found"
    failures=$((failures + 1))
else
    echo "PASS: Profile definition exists"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Scan ABI source for call-through patterns
# ---------------------------------------------------------------------------
echo "--- Check 2: Call-through scan (mode=${MODE}) ---"

scan_result=$(python3 -c "
import json, re, os
from datetime import datetime, timezone

abi_src = '${ABI_SRC}'
profile_path = '${PROFILE_DEF}'
mode = '${MODE}'
root = '${ROOT}'
log_path = '${LOG_PATH}'
report_path = '${REPORT_PATH}'

with open(profile_path) as f:
    profile = json.load(f)

allowlist = set(profile['interpose_allowlist']['modules'])
mutex_symbols = set(profile.get('replacement_forbidden', {}).get('mutex_symbols', []))

call_through_re = re.compile(r'libc::([a-z_][a-z0-9_]*)\s*\(')
host_pthread_re = re.compile(r'host_pthread_([a-z_][a-z0-9_]*)\s*\(')

violations = []
mutex_violations = []
module_counts = {}
events = []
timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('_abi.rs'):
        continue
    module = fname.replace('.rs', '')
    filepath = os.path.join(abi_src, fname)

    with open(filepath) as f:
        lines = f.readlines()

    module_calls = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        for m in call_through_re.finditer(line):
            func_name = m.group(1)
            if func_name == 'syscall':
                continue
            module_calls.append({
                'line': lineno,
                'function': func_name,
                'source': 'libc',
                'context': stripped[:120]
            })
        if 'fn host_pthread_' in stripped:
            continue
        for m in host_pthread_re.finditer(line):
            wrapped = m.group(1)
            if wrapped.endswith('_sym'):
                continue
            module_calls.append({
                'line': lineno,
                'function': f'pthread_{wrapped}',
                'source': 'host_pthread',
                'context': stripped[:120]
            })

    if module_calls:
        module_counts[module] = len(module_calls)
        is_forbidden = False
        if mode == 'replacement':
            is_forbidden = True
        elif mode == 'interpose' and module not in allowlist:
            is_forbidden = True
        if is_forbidden:
            for call in module_calls:
                violations.append({
                    'module': module,
                    'line': call['line'],
                    'function': call['function'],
                    'source': call['source'],
                    'context': call['context']
                })
        for call in module_calls:
            if call['function'] in mutex_symbols:
                mutex_violations.append({
                    'module': module,
                    'line': call['line'],
                    'function': call['function'],
                    'source': call['source'],
                    'context': call['context'],
                })
        for call in module_calls:
            allowed = (mode == 'interpose' and module in allowlist)
            outcome = 'allowed' if allowed else 'forbidden'
            events.append({
                'timestamp': timestamp,
                'trace_id': f'replacement-guard:{mode}:{module}:{call[\"line\"]}:{call[\"function\"]}',
                'mode': mode,
                'gate_name': 'replacement_guard',
                'module': module,
                'line': call['line'],
                'symbol': call['function'],
                'source_pattern': call['source'],
                'status': outcome,
                'reason': (
                    'module is allowlisted in interpose mode'
                    if allowed
                    else 'replacement forbids all host call-through'
                    if mode == 'replacement'
                    else 'module not in interpose allowlist'
                ),
                'artifact_ref': os.path.relpath(filepath, root),
                'context': call['context'],
            })

total_ct = sum(module_counts.values())

with open(log_path, 'w', encoding='utf-8') as f:
    for event in sorted(events, key=lambda e: (e['module'], e['line'], e['symbol'])):
        f.write(json.dumps(event, separators=(',', ':')))
        f.write('\n')

report = {
    'ok': len(violations) == 0,
    'mode': mode,
    'total_call_throughs': total_ct,
    'modules_with_call_throughs': len(module_counts),
    'violations': len(violations),
    'module_counts': dict(sorted(module_counts.items())),
    'log_jsonl': os.path.relpath(log_path, root),
    'violations_detail': violations,
    'mutex_forbidden_symbols': sorted(mutex_symbols),
    'mutex_forbidden_count': len(mutex_violations),
    'mutex_violations_detail': mutex_violations,
}
with open(report_path, 'w', encoding='utf-8') as f:
    json.dump(report, f, indent=2)
    f.write('\n')

print(f'TOTAL_CALL_THROUGHS={total_ct}')
print(f'MODULES_WITH_CT={len(module_counts)}')
print(f'VIOLATIONS={len(violations)}')
print(f'MUTEX_FORBIDDEN={len(mutex_violations)}')
print(f'LOG_PATH={os.path.relpath(log_path, root)}')
print(f'REPORT_PATH={os.path.relpath(report_path, root)}')

for mod, count in sorted(module_counts.items()):
    allowed = 'ALLOWED' if (mode == 'interpose' and mod in allowlist) else 'FORBIDDEN'
    print(f'  MODULE: {mod} calls={count} [{allowed}]')

if violations:
    print('')
    print('VIOLATION DETAILS:')
    for v in violations:
        source_prefix = 'libc::' if v['source'] == 'libc' else 'host_pthread::'
        print(f\"  {v['module']}.rs:{v['line']} {source_prefix}{v['function']}() -- {v['context']}\")
if mutex_violations:
    print('')
    print('MUTEX VIOLATION DETAILS:')
    for v in mutex_violations:
        source_prefix = 'libc::' if v['source'] == 'libc' else 'host_pthread::'
        print(f\"  {v['module']}.rs:{v['line']} {source_prefix}{v['function']}() -- {v['context']}\")
")

total_ct=$(echo "${scan_result}" | grep '^TOTAL_CALL_THROUGHS=' | cut -d= -f2)
violation_count=$(echo "${scan_result}" | grep '^VIOLATIONS=' | cut -d= -f2)
mutex_forbidden_count=$(echo "${scan_result}" | grep '^MUTEX_FORBIDDEN=' | cut -d= -f2)
modules_ct=$(echo "${scan_result}" | grep '^MODULES_WITH_CT=' | cut -d= -f2)
log_path_rel=$(echo "${scan_result}" | grep '^LOG_PATH=' | cut -d= -f2)
report_path_rel=$(echo "${scan_result}" | grep '^REPORT_PATH=' | cut -d= -f2)

echo "Total call-throughs found: ${total_ct} across ${modules_ct} modules"
echo "${scan_result}" | grep '  MODULE:'
echo ""

if [[ "${violation_count}" -gt 0 ]]; then
    echo "FAIL: ${violation_count} forbidden call-through(s) in ${MODE} mode:"
    echo "${scan_result}" | grep -A1000 'VIOLATION DETAILS:' | tail -n +2
    failures=$((failures + 1))
else
    echo "PASS: No forbidden call-throughs in ${MODE} mode"
fi
if [[ "${mutex_forbidden_count}" -gt 0 ]]; then
    echo "FAIL: ${mutex_forbidden_count} forbidden pthread_mutex_* call-through(s) detected:"
    echo "${scan_result}" | grep -A1000 'MUTEX VIOLATION DETAILS:' | tail -n +2
    failures=$((failures + 1))
else
    echo "PASS: No forbidden pthread_mutex_* call-throughs detected"
fi
echo "Structured logs: ${log_path_rel}"
echo "Report: ${report_path_rel}"
echo ""

# ---------------------------------------------------------------------------
# Check 3: Verify no pthread/syscall call-through outside allowlist
# ---------------------------------------------------------------------------
echo "--- Check 3: Pthread/syscall isolation ---"

pthread_check=$(python3 -c "
import os, re

abi_src = '${ABI_SRC}'
libc_call_re = re.compile(r'libc::pthread_[a-z_]+\s*\(')
host_call_re = re.compile(r'host_pthread_[a-z_][a-z0-9_]*\s*\(')
violations = []

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('.rs') or fname == 'pthread_abi.rs':
        continue
    filepath = os.path.join(abi_src, fname)
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            if line.strip().startswith('//'):
                continue
            for m in libc_call_re.finditer(line):
                violations.append(f'{fname}:{lineno} {m.group(0).strip()}')
            if 'fn host_pthread_' in line:
                continue
            for m in host_call_re.finditer(line):
                token = m.group(0).strip()
                if '_sym' in token:
                    continue
                violations.append(f'{fname}:{lineno} {token}')

print(f'PTHREAD_VIOLATIONS={len(violations)}')
for v in violations:
    print(f'  {v}')
")

pthread_violations=$(echo "${pthread_check}" | grep '^PTHREAD_VIOLATIONS=' | cut -d= -f2)

if [[ "${pthread_violations}" -gt 0 ]]; then
    echo "FAIL: pthread call-through found outside pthread_abi.rs:"
    echo "${pthread_check}" | grep -v 'PTHREAD_VIOLATIONS='
    failures=$((failures + 1))
else
    echo "PASS: All pthread calls confined to pthread_abi.rs"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Raw syscall audit — verify syscall usage is correct
# ---------------------------------------------------------------------------
echo "--- Check 4: Raw syscall audit ---"

syscall_check=$(python3 -c "
import os, re

abi_src = '${ABI_SRC}'
syscall_re = re.compile(r'libc::syscall\s*\(\s*libc::SYS_([a-z_0-9]+)')
syscalls_by_module = {}

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('.rs'):
        continue
    module = fname.replace('.rs', '')
    filepath = os.path.join(abi_src, fname)
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            if line.strip().startswith('//'):
                continue
            for m in syscall_re.finditer(line):
                syscalls_by_module.setdefault(module, []).append(m.group(1))

total = sum(len(v) for v in syscalls_by_module.values())
print(f'RAW_SYSCALLS={total}')
for mod, calls in sorted(syscalls_by_module.items()):
    unique = sorted(set(calls))
    print(f'  {mod}: {\", \".join(unique)}')
")

raw_syscalls=$(echo "${syscall_check}" | grep '^RAW_SYSCALLS=' | cut -d= -f2)
echo "Raw syscalls found: ${raw_syscalls} (these are safe)"
echo "${syscall_check}" | grep '  '
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Mode: ${MODE}"
echo "Total call-throughs: ${total_ct}"
echo "Violations: ${violation_count}"
echo "Failures: ${failures}"
echo "Structured logs: ${log_path_rel}"
echo "Report: ${report_path_rel}"

if [[ "${MODE}" == "interpose" ]]; then
    echo ""
    echo "Note: In interpose mode, allowlisted modules may call through to host glibc."
    echo "Run with 'replacement' argument to enforce zero call-through."
fi

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_replacement_guard: FAILED"
    exit 1
fi

echo ""
echo "check_replacement_guard: PASS"
