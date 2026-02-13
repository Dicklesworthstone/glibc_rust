#!/usr/bin/env bash
# check_math_value_ablations.sh — CI gate for bd-1rxj
#
# Validates controller A/B value-proof ablation artifact and emits:
# - target/conformance/math_value_ablations.log.jsonl
# - target/conformance/math_value_ablations.report.json
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ABLATIONS="${ROOT}/tests/conformance/math_value_ablations.v1.json"
VALUE_PROOF="${ROOT}/tests/conformance/math_value_proof.json"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/math_value_ablations.log.jsonl"
REPORT_PATH="${OUT_DIR}/math_value_ablations.report.json"

mkdir -p "${OUT_DIR}"

if [[ ! -f "${ABLATIONS}" ]]; then
    echo "FAIL: ${ABLATIONS} missing"
    exit 1
fi
if [[ ! -f "${VALUE_PROOF}" ]]; then
    echo "FAIL: ${VALUE_PROOF} missing"
    exit 1
fi

export FLC_ROOT="${ROOT}"
export FLC_ABLATIONS="${ABLATIONS}"
export FLC_VALUE_PROOF="${VALUE_PROOF}"
export FLC_LOG_PATH="${LOG_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["FLC_ROOT"])
ABLATIONS = Path(os.environ["FLC_ABLATIONS"])
VALUE_PROOF = Path(os.environ["FLC_VALUE_PROOF"])
LOG_PATH = Path(os.environ["FLC_LOG_PATH"])
REPORT_PATH = Path(os.environ["FLC_REPORT_PATH"])

ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


abl = load_json(ABLATIONS)
vp = load_json(VALUE_PROOF)

failures: list[str] = []
events: list[dict] = []


def fail(msg: str) -> None:
    failures.append(msg)


if abl.get("schema_version") != 1:
    fail(f"schema_version must be 1, got {abl.get('schema_version')!r}")
if abl.get("bead") != "bd-1rxj":
    fail(f"bead must be bd-1rxj, got {abl.get('bead')!r}")

policy = abl.get("evaluation_policy", {})
strict_budget = float(policy.get("strict_budget_ns_max", 20))
hardened_budget = float(policy.get("hardened_budget_ns_max", 200))
min_conf = float(policy.get("min_confidence", 0.8))
min_risk = float(policy.get("min_risk_reduction_ppm", 5))
min_quality = float(policy.get("min_quality_gain", 0.003))
min_latency = float(policy.get("min_latency_improvement_pct", 2.0))

vp_modules = set()
for key in ("production_core_assessments", "production_monitor_assessments"):
    for row in vp.get(key, []):
        module = row.get("module")
        if isinstance(module, str):
            vp_modules.add(module)

experiments = abl.get("experiments", [])
if not isinstance(experiments, list):
    fail("experiments must be an array")
    experiments = []

seen: set[str] = set()
retain = 0
retire = 0
max_strict_with = 0.0
max_hardened_with = 0.0
min_conf_observed = 1.0

for exp in experiments:
    start_ns = time.perf_counter_ns()
    module = exp.get("module")
    decision = exp.get("decision")
    confidence = float(exp.get("statistics", {}).get("confidence", 0.0))
    tier = exp.get("tier")
    module_reasons: list[str] = []

    if not isinstance(module, str) or not module:
        fail(f"invalid module entry: {exp!r}")
        continue
    if module in seen:
        module_reasons.append("duplicate_module")
    seen.add(module)
    if module not in vp_modules:
        module_reasons.append("module_not_in_math_value_proof")
    if tier not in {"production_core", "production_monitor"}:
        module_reasons.append("invalid_tier")
    if decision not in {"retain", "retire"}:
        module_reasons.append("invalid_decision")

    if decision == "retain":
        retain += 1
    elif decision == "retire":
        retire += 1

    min_conf_observed = min(min_conf_observed, confidence)
    if decision == "retain" and confidence < min_conf:
        module_reasons.append("confidence_below_min_for_retain")

    exp_reasons: set[str] = set()
    for mode in ("strict", "hardened"):
        mode_reasons = list(module_reasons)
        section = exp.get(mode, {})
        with_ctl = section.get("with", {})
        without_ctl = section.get("without", {})

        try:
            with_latency = float(with_ctl["latency_ns"])
            without_latency = float(without_ctl["latency_ns"])
            with_risk = float(with_ctl["risk_ppm"])
            without_risk = float(without_ctl["risk_ppm"])
            with_quality = float(with_ctl["decision_quality"])
            without_quality = float(without_ctl["decision_quality"])
        except Exception:
            mode_reasons.append(f"{mode}_missing_metric")
            exp_reasons.update(mode_reasons)
            continue

        if with_latency <= 0 or without_latency <= 0:
            mode_reasons.append(f"{mode}_latency_non_positive")
            exp_reasons.update(mode_reasons)
            continue

        if mode == "strict":
            max_strict_with = max(max_strict_with, with_latency)
            if with_latency > strict_budget:
                mode_reasons.append("strict_budget_exceeded")
        else:
            max_hardened_with = max(max_hardened_with, with_latency)
            if with_latency > hardened_budget:
                mode_reasons.append("hardened_budget_exceeded")

        risk_reduction = without_risk - with_risk
        quality_gain = with_quality - without_quality
        latency_improvement_pct = ((without_latency - with_latency) / without_latency) * 100.0

        meets_retain_signal = (
            risk_reduction >= min_risk
            or quality_gain >= min_quality
            or latency_improvement_pct >= min_latency
        )

        if decision == "retain" and confidence >= min_conf and not meets_retain_signal:
            mode_reasons.append(f"{mode}_retain_without_signal")
        if decision == "retire" and confidence >= min_conf and meets_retain_signal:
            mode_reasons.append(f"{mode}_retire_with_signal")

        elapsed_ns = time.perf_counter_ns() - start_ns
        exp_reasons.update(mode_reasons)
        events.append(
            {
                "timestamp": ts,
                "trace_id": f"bd-1rxj-{module}-{mode}",
                "mode": mode,
                "symbol": module,
                "event": "runtime_math.value_ablation",
                "outcome": "pass" if not mode_reasons else "fail",
                "errno": 0 if not mode_reasons else 22,
                "timing_ns": elapsed_ns,
                "tier": tier,
                "decision": decision,
                "confidence": confidence,
                "risk_reduction_ppm": round(risk_reduction, 3),
                "quality_gain": round(quality_gain, 6),
                "latency_improvement_pct": round(latency_improvement_pct, 3),
                "reasons": mode_reasons,
            }
        )

    for r in sorted(exp_reasons):
        fail(f"{module}: {r}")

missing_in_ablations = sorted(vp_modules - seen)
extra_in_ablations = sorted(seen - vp_modules)
if missing_in_ablations:
    fail("missing modules in ablations: " + ", ".join(missing_in_ablations))
if extra_in_ablations:
    fail("unexpected modules in ablations: " + ", ".join(extra_in_ablations))

summary = abl.get("summary", {})
expected_summary = {
    "total_modules": len(seen),
    "retain": retain,
    "retire": retire,
    "min_confidence": round(min_conf_observed, 2),
    "max_strict_with_latency_ns": int(round(max_strict_with)),
    "max_hardened_with_latency_ns": int(round(max_hardened_with)),
}
for key, value in expected_summary.items():
    if summary.get(key) != value:
        fail(f"summary.{key} mismatch: claimed={summary.get(key)!r} actual={value!r}")

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
with LOG_PATH.open("w", encoding="utf-8") as f:
    for row in events:
        f.write(json.dumps(row, sort_keys=True))
        f.write("\n")

report = {
    "schema_version": "v1",
    "bead": "bd-1rxj",
    "generated_at": ts,
    "ok": len(failures) == 0,
    "summary": expected_summary,
    "failure_count": len(failures),
    "failures": failures,
    "artifacts": {
        "log_jsonl": str(LOG_PATH.relative_to(ROOT)),
        "report_json": str(REPORT_PATH.relative_to(ROOT)),
        "ablations_json": str(ABLATIONS.relative_to(ROOT)),
    },
}
REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if failures:
    print("FAIL: math value ablation gate detected issues:")
    for item in failures[:20]:
        print(f"  - {item}")
    if len(failures) > 20:
        print(f"  - ... {len(failures) - 20} more")
    print(f"Structured logs: {LOG_PATH}")
    print(f"Report: {REPORT_PATH}")
    raise SystemExit(1)

print(
    "PASS: math value ablation gate validated "
    f"{len(seen)} modules (retain={retain}, retire={retire})."
)
print(f"Structured logs: {LOG_PATH}")
print(f"Report: {REPORT_PATH}")
PY
