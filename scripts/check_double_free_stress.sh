#!/usr/bin/env bash
# check_double_free_stress.sh — deterministic concurrent double-free stress gate (bd-18qq.5)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/double_free_stress"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

TEST_NAME="allocator_membrane_invariants_sequences_test"
FILTER="concurrent_double_free_detection_"

for mode in strict hardened; do
  LOG_PATH="${RUN_DIR}/${mode}.log"
  echo "=== mode=${mode} ==="
  set +e
  FRANKENLIBC_MODE="${mode}" \
    cargo test -p frankenlibc-membrane --release --test "${TEST_NAME}" "${FILTER}" -- --nocapture \
    >"${LOG_PATH}" 2>&1
  rc=$?
  set -e
  if [[ ${rc} -ne 0 ]]; then
    echo "mode=${mode} test run failed (rc=${rc}); see ${LOG_PATH}" >&2
    exit ${rc}
  fi
  echo "mode=${mode} log=${LOG_PATH}"
done

REPORT_PATH="${RUN_DIR}/double_free_report.json"
RUN_DIR_ARG="${RUN_DIR}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
python3 - <<'PY'
import json
import os
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])

summary = {
    "schema_version": "v1",
    "bead": "bd-18qq.5",
    "run_dir": str(run_dir),
    "modes": {},
    "overall_ok": True,
}

for mode in ("strict", "hardened"):
    log_path = run_dir / f"{mode}.log"
    reports = []
    for line in log_path.read_text(errors="replace").splitlines():
        if line.startswith("DOUBLE_FREE_REPORT "):
            payload = line[len("DOUBLE_FREE_REPORT "):]
            reports.append(json.loads(payload))

    by_scenario = {r.get("scenario"): r for r in reports}
    mode_ok = True
    reasons = []

    for scenario in ("basic", "stress"):
        if scenario not in by_scenario:
            mode_ok = False
            reasons.append(f"missing_scenario:{scenario}")
            continue
        r = by_scenario[scenario]
        if r.get("false_negatives") != 0:
            mode_ok = False
            reasons.append(f"{scenario}:false_negatives={r.get('false_negatives')}")
        if r.get("false_positives") != 0:
            mode_ok = False
            reasons.append(f"{scenario}:false_positives={r.get('false_positives')}")
        if r.get("heap_integrity_failures") != 0:
            mode_ok = False
            reasons.append(f"{scenario}:heap_integrity_failures={r.get('heap_integrity_failures')}")
        if not r.get("no_deadlock", False):
            mode_ok = False
            reasons.append(f"{scenario}:deadlock")
        if r.get("detected_double_frees") != r.get("double_free_attempts"):
            mode_ok = False
            reasons.append(
                f"{scenario}:detected({r.get('detected_double_frees')})!=attempts({r.get('double_free_attempts')})"
            )
        latency_ns = int(r.get("uncontended_avg_latency_ns", 10**9))
        if latency_ns >= 100:
            mode_ok = False
            reasons.append(f"{scenario}:uncontended_avg_latency_ns={latency_ns}>=100")

    summary["modes"][mode] = {
        "ok": mode_ok,
        "reasons": reasons,
        "reports": reports,
        "log": str(log_path),
    }
    if not mode_ok:
        summary["overall_ok"] = False

report_path.write_text(json.dumps(summary, indent=2) + "\n")

for mode in ("strict", "hardened"):
    mode_summary = summary["modes"].get(mode, {})
    status = "PASS" if mode_summary.get("ok") else "FAIL"
    print(f"[{status}] mode={mode} reasons={','.join(mode_summary.get('reasons', [])) or 'none'}")

if not summary["overall_ok"]:
    raise SystemExit(1)
PY

echo "report=${REPORT_PATH}"
echo "check_double_free_stress: PASS"
