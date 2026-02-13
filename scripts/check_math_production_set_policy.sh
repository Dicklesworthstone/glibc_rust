#!/usr/bin/env bash
# check_math_production_set_policy.sh — CI gate for bd-25pf
#
# Validates that every runtime_math production-manifest module has the required
# admission/retirement evidence package:
# - classification evidence (math_governance),
# - linkage evidence (runtime_math_linkage),
# - value-proof evidence for production tiers (math_value_proof),
# - waiver+migration evidence for research-tier modules still in production.
#
# Also enforces a production-set digest lock in
# tests/conformance/math_production_set_policy.v1.json so any manifest set
# change must update policy metadata and re-pass evidence checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${ROOT}/tests/conformance/math_production_set_policy.v1.json"
MANIFEST="${ROOT}/tests/runtime_math/production_kernel_manifest.v1.json"
GOVERNANCE="${ROOT}/tests/conformance/math_governance.json"
LINKAGE="${ROOT}/tests/runtime_math/runtime_math_linkage.v1.json"
VALUE_PROOF="${ROOT}/tests/conformance/math_value_proof.json"
RETIREMENT="${ROOT}/tests/conformance/math_retirement_policy.json"

OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/math_production_set_policy.log.jsonl"
REPORT_PATH="${OUT_DIR}/math_production_set_policy.report.json"

mkdir -p "${OUT_DIR}"

for req in \
    "${POLICY}" \
    "${MANIFEST}" \
    "${GOVERNANCE}" \
    "${LINKAGE}" \
    "${VALUE_PROOF}" \
    "${RETIREMENT}"; do
    if [[ ! -f "${req}" ]]; then
        echo "FAIL: required file missing: ${req}"
        exit 1
    fi
done

export FLC_ROOT="${ROOT}"
export FLC_POLICY="${POLICY}"
export FLC_MANIFEST="${MANIFEST}"
export FLC_GOVERNANCE="${GOVERNANCE}"
export FLC_LINKAGE="${LINKAGE}"
export FLC_VALUE_PROOF="${VALUE_PROOF}"
export FLC_RETIREMENT="${RETIREMENT}"
export FLC_LOG_PATH="${LOG_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"

python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(os.environ["FLC_ROOT"])
POLICY = Path(os.environ["FLC_POLICY"])
MANIFEST = Path(os.environ["FLC_MANIFEST"])
GOV = Path(os.environ["FLC_GOVERNANCE"])
LINK = Path(os.environ["FLC_LINKAGE"])
VALUE = Path(os.environ["FLC_VALUE_PROOF"])
RETIRE = Path(os.environ["FLC_RETIREMENT"])
LOG_PATH = Path(os.environ["FLC_LOG_PATH"])
REPORT_PATH = Path(os.environ["FLC_REPORT_PATH"])

ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def canonical_set_sha256(modules: list[str]) -> str:
    blob = "\n".join(sorted(modules)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


policy = load_json(POLICY)
manifest = load_json(MANIFEST)
gov = load_json(GOV)
link = load_json(LINK)
value = load_json(VALUE)
retire = load_json(RETIRE)

failures: list[str] = []
events: list[dict] = []
reason_counts = {
    "missing_classification": 0,
    "missing_linkage": 0,
    "missing_value_proof": 0,
    "missing_retirement_waiver": 0,
    "missing_retirement_migration_entry": 0,
}


def fail(msg: str) -> None:
    failures.append(msg)


if policy.get("schema_version") != 1:
    fail(f"policy.schema_version must be 1 (got {policy.get('schema_version')!r})")
if policy.get("bead") != "bd-25pf":
    fail(f"policy.bead must be 'bd-25pf' (got {policy.get('bead')!r})")

manifest_modules = manifest.get("production_modules", [])
if not isinstance(manifest_modules, list):
    fail("manifest.production_modules must be an array")
    manifest_modules = []
manifest_modules = sorted(
    [m for m in manifest_modules if isinstance(m, str) and m]
)
manifest_set = set(manifest_modules)

change_gate = policy.get("policy", {}).get("change_gate", {})
expected_sha = change_gate.get("manifest_sha256")
actual_sha = canonical_set_sha256(manifest_modules)
if expected_sha != actual_sha:
    fail(
        "policy change_gate manifest_sha256 mismatch: "
        f"policy={expected_sha!r} actual={actual_sha!r}"
    )

expected_count = change_gate.get("module_count")
if expected_count != len(manifest_modules):
    fail(
        "policy change_gate module_count mismatch: "
        f"policy={expected_count!r} actual={len(manifest_modules)}"
    )

retention_threshold_policy = change_gate.get("retention_threshold")
retention_threshold_value = (
    value.get("scoring_methodology", {}).get("retention_threshold")
)
if retention_threshold_policy != retention_threshold_value:
    fail(
        "retention threshold mismatch between policy and value proof: "
        f"policy={retention_threshold_policy!r} value_proof={retention_threshold_value!r}"
    )

expected_sources = {
    "production_manifest": "tests/runtime_math/production_kernel_manifest.v1.json",
    "governance": "tests/conformance/math_governance.json",
    "linkage": "tests/runtime_math/runtime_math_linkage.v1.json",
    "value_proof": "tests/conformance/math_value_proof.json",
    "retirement_policy": "tests/conformance/math_retirement_policy.json",
}
if policy.get("sources") != expected_sources:
    fail("policy.sources must match canonical source artifact paths")

tier_by_module: dict[str, str] = {}
classifications = gov.get("classifications", {})
for tier, entries in classifications.items():
    if not isinstance(entries, list):
        continue
    for entry in entries:
        module = entry.get("module")
        if isinstance(module, str) and module:
            tier_by_module[module] = tier

linkage_modules = link.get("modules", {})
if not isinstance(linkage_modules, dict):
    fail("linkage.modules must be an object")
    linkage_modules = {}

value_proof_modules = set()
for key in ("production_core_assessments", "production_monitor_assessments"):
    entries = value.get(key, [])
    if isinstance(entries, list):
        for entry in entries:
            module = entry.get("module")
            if isinstance(module, str) and module:
                value_proof_modules.add(module)

waived_modules: set[str] = set()
retirement_waivers = retire.get("active_waivers", [])
if isinstance(retirement_waivers, list):
    for waiver in retirement_waivers:
        module = waiver.get("module")
        if module == "ALL_RESEARCH":
            waived_modules.update(
                m for m in manifest_modules if tier_by_module.get(m) == "research"
            )
        elif isinstance(module, str) and module:
            waived_modules.add(module)

migration_modules: set[str] = set()
waves = retire.get("migration_notes", {}).get("waves", [])
if isinstance(waves, list):
    for wave in waves:
        modules = wave.get("modules", [])
        if isinstance(modules, list):
            migration_modules.update(m for m in modules if isinstance(m, str) and m)

production_tier_modules = 0
research_tier_modules = 0

for module in manifest_modules:
    start = time.perf_counter_ns()
    reasons: list[str] = []
    tier = tier_by_module.get(module)
    linkage_status = None

    if tier is None:
        reasons.append("missing_classification")
    elif tier in {"production_core", "production_monitor"}:
        production_tier_modules += 1
        if module not in value_proof_modules:
            reasons.append("missing_value_proof")
    elif tier == "research":
        research_tier_modules += 1
        if module not in waived_modules:
            reasons.append("missing_retirement_waiver")
        if module not in migration_modules:
            reasons.append("missing_retirement_migration_entry")
    else:
        reasons.append(f"invalid_classification:{tier}")

    linkage = linkage_modules.get(module)
    if not isinstance(linkage, dict):
        reasons.append("missing_linkage")
    else:
        linkage_status = linkage.get("linkage_status")
        if linkage_status not in {"Production", "ResearchOnly"}:
            reasons.append(f"invalid_linkage_status:{linkage_status}")
        if not linkage.get("decision_target"):
            reasons.append("missing_decision_target")

    for r in reasons:
        if r in reason_counts:
            reason_counts[r] += 1
        fail(f"{module}: {r}")

    elapsed_ns = time.perf_counter_ns() - start
    events.append(
        {
            "timestamp": ts,
            "trace_id": f"bd-25pf-{module}",
            "mode": "policy",
            "symbol": module,
            "outcome": "pass" if not reasons else "fail",
            "errno": 0 if not reasons else 22,
            "timing_ns": elapsed_ns,
            "gate": "math_production_set_policy",
            "classification": tier,
            "linkage_status": linkage_status,
            "reasons": reasons,
        }
    )

waived_research_modules = sum(
    1
    for m in manifest_modules
    if tier_by_module.get(m) == "research" and m in waived_modules
)

actual_summary = {
    "total_production_modules": len(manifest_modules),
    "production_tier_modules": production_tier_modules,
    "research_tier_modules": research_tier_modules,
    "waived_research_modules": waived_research_modules,
    "missing_classification": reason_counts["missing_classification"],
    "missing_linkage": reason_counts["missing_linkage"],
    "missing_value_proof": reason_counts["missing_value_proof"],
    "missing_retirement_waiver": reason_counts["missing_retirement_waiver"],
    "missing_retirement_migration_entry": reason_counts["missing_retirement_migration_entry"],
}

for key, actual_value in actual_summary.items():
    claimed = policy.get("summary", {}).get(key)
    if claimed != actual_value:
        fail(f"policy.summary.{key} mismatch: claimed={claimed!r} actual={actual_value!r}")

LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
with LOG_PATH.open("w", encoding="utf-8") as f:
    for row in events:
        f.write(json.dumps(row, sort_keys=True))
        f.write("\n")

report = {
    "schema_version": "v1",
    "bead": "bd-25pf",
    "generated_at": ts,
    "ok": len(failures) == 0,
    "summary": actual_summary,
    "failure_count": len(failures),
    "failures": failures,
    "artifacts": {
        "log_jsonl": str(LOG_PATH.relative_to(ROOT)),
        "report_json": str(REPORT_PATH.relative_to(ROOT)),
        "policy_json": str(POLICY.relative_to(ROOT)),
    },
}
REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if failures:
    print("FAIL: math production-set policy gate detected evidence gaps:")
    for msg in failures[:20]:
        print(f"  - {msg}")
    if len(failures) > 20:
        print(f"  - ... {len(failures) - 20} more")
    print(f"Structured logs: {LOG_PATH}")
    print(f"Report: {REPORT_PATH}")
    raise SystemExit(1)

print(
    "PASS: production-set policy gate validated "
    f"{len(manifest_modules)} modules "
    f"(production-tier={production_tier_modules}, research-tier={research_tier_modules})."
)
print(f"Structured logs: {LOG_PATH}")
print(f"Report: {REPORT_PATH}")
PY
