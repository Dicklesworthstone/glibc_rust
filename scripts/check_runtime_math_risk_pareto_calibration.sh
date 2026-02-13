#!/usr/bin/env bash
# check_runtime_math_risk_pareto_calibration.sh — CI gate for bd-w2c3.5.1
#
# Validates:
# 1) deterministic risk+pareto calibration artifact is up-to-date,
# 2) regret-cap and risk-calibration regression tests pass,
# 3) real-workload divergence guard remains green.
#
# Emits:
# - target/conformance/runtime_math_risk_pareto_calibration.report.json
# - target/conformance/runtime_math_risk_pareto_calibration.log.jsonl

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
REPORT_PATH="${OUT_DIR}/runtime_math_risk_pareto_calibration.report.json"
LOG_PATH="${OUT_DIR}/runtime_math_risk_pareto_calibration.log.jsonl"
ARTIFACT_PATH="${FRANKENLIBC_RISK_PARETO_CALIBRATION_PATH:-${ROOT}/tests/runtime_math/risk_pareto_calibration.v1.json}"

mkdir -p "${OUT_DIR}"

export FLC_ROOT="${ROOT}"
export FLC_ARTIFACT_PATH="${ARTIFACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
artifact_path = Path(os.environ["FLC_ARTIFACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])

trace_id = f"bd-w2c3.5.1::run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}::{os.getpid()}"
start_ns = time.time_ns()

checks = [
    {
        "id": "calibration_baseline_match",
        "cmd": f"python3 scripts/generate_runtime_math_risk_pareto_calibration.py --check --artifact {artifact_path}",
    },
    {
        "id": "pareto_regret_saturates_at_cap",
        "cmd": "cargo test -p frankenlibc-membrane runtime_math::pareto::tests::regret_saturates_at_cap -- --nocapture",
    },
    {
        "id": "pareto_budget_enforcement_counter",
        "cmd": "cargo test -p frankenlibc-membrane runtime_math::pareto::tests::budget_enforcement_count_increases_when_saturated -- --nocapture",
    },
    {
        "id": "risk_family_isolation",
        "cmd": "cargo test -p frankenlibc-membrane runtime_math::risk::tests::family_counters_are_isolated -- --nocapture",
    },
    {
        "id": "risk_adverse_rate_monotonicity",
        "cmd": "cargo test -p frankenlibc-membrane runtime_math::risk::tests::higher_adverse_rate_yields_higher_bound_for_same_volume -- --nocapture",
    },
    {
        "id": "real_workload_divergence_guard",
        "cmd": "scripts/check_runtime_math_divergence_bounds.sh",
    },
]

results: list[dict[str, Any]] = []
violations: list[str] = []

for check in checks:
    proc = subprocess.run(
        check["cmd"],
        shell=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    ok = proc.returncode == 0
    if not ok:
        violations.append(check["id"])

    stdout_tail = ""
    stderr_tail = ""
    if proc.stdout.strip():
        stdout_tail = proc.stdout.strip().splitlines()[-1]
    if proc.stderr.strip():
        stderr_tail = proc.stderr.strip().splitlines()[-1]

    results.append(
        {
            "id": check["id"],
            "cmd": check["cmd"],
            "outcome": "pass" if ok else "fail",
            "exit_code": proc.returncode,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
        }
    )

report = {
    "schema_version": "v1",
    "bead": "bd-w2c3.5.1",
    "artifact": str(artifact_path.relative_to(root) if artifact_path.is_relative_to(root) else artifact_path),
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "checks": {row["id"]: row["outcome"] for row in results},
    "results": results,
    "summary": {
        "total": len(results),
        "failed": len(violations),
        "passed": len(results) - len(violations),
        "violations": violations,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

log_event = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "trace_id": trace_id,
    "level": "error" if violations else "info",
    "event": "runtime_math_risk_pareto_calibration_gate",
    "bead_id": "bd-w2c3.5.1",
    "mode": "strict",
    "api_family": "runtime_math",
    "symbol": "risk_upper_bound_ppm|pareto_regret_cap",
    "decision_path": "kernel_regression_mode+regression_tests+divergence_guard",
    "healing_action": "None",
    "outcome": "fail" if violations else "pass",
    "errno": 1 if violations else 0,
    "latency_ns": time.time_ns() - start_ns,
    "artifact_refs": [
        str(report_path.relative_to(root)),
        str(log_path.relative_to(root)),
        str(artifact_path.relative_to(root) if artifact_path.is_relative_to(root) else artifact_path),
    ],
    "details": {
        "failed_checks": violations,
        "total_checks": len(results),
        "results": results,
    },
}
log_path.write_text(json.dumps(log_event, separators=(",", ":")) + "\n", encoding="utf-8")

if violations:
    print("FAIL: runtime-math risk/pareto calibration guard failed")
    for row in results:
        if row["outcome"] == "fail":
            print(f"  - {row['id']} (exit={row['exit_code']})")
    raise SystemExit(1)

print("PASS: runtime-math risk/pareto calibration guard passed")
print(f"- {report_path}")
print(f"- {log_path}")
PY
