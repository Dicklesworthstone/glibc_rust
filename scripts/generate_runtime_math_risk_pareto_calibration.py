#!/usr/bin/env python3
"""generate_runtime_math_risk_pareto_calibration.py — bd-w2c3.5.1

Builds a deterministic risk+pareto calibration artifact from harness runtime-math
mode runs (strict + hardened).

Usage:
  python3 scripts/generate_runtime_math_risk_pareto_calibration.py --write
  python3 scripts/generate_runtime_math_risk_pareto_calibration.py --check
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

CONFIG = {
    "seed": "0xDEADBEEF",
    "steps": 256,
    "warmup_iters": 128,
    "samples": 2,
    "iters": 2000,
    "trend_stride": 32,
}


def run_mode(repo_root: Path, mode: str) -> dict[str, Any]:
    cmd = [
        "cargo",
        "run",
        "-p",
        "frankenlibc-harness",
        "--bin",
        "harness",
        "--",
        "kernel-regression-mode",
        "--mode",
        mode,
        "--seed",
        str(CONFIG["seed"]),
        "--steps",
        str(CONFIG["steps"]),
        "--warmup-iters",
        str(CONFIG["warmup_iters"]),
        "--samples",
        str(CONFIG["samples"]),
        "--iters",
        str(CONFIG["iters"]),
        "--trend-stride",
        str(CONFIG["trend_stride"]),
    ]
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        env={**dict(os.environ), "FRANKENLIBC_MODE": mode},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"kernel-regression-mode failed for mode={mode}\n"
            f"cmd: {' '.join(cmd)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}\n"
        )
        raise SystemExit(proc.returncode)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.stderr.write(
            f"Failed to parse harness JSON for mode={mode}: {exc}\n"
            f"stdout tail:\n{proc.stdout[-1000:]}\n"
        )
        raise SystemExit(1) from exc


def normalize_mode_payload(payload: dict[str, Any]) -> dict[str, Any]:
    families = payload.get("family_diagnostics", [])
    if not isinstance(families, list):
        families = []

    normalized_families = []
    for row in families:
        if not isinstance(row, dict):
            continue
        normalized_families.append(
            {
                "family": row.get("family"),
                "decisions": int(row.get("decisions", 0)),
                "adverse_events": int(row.get("adverse_events", 0)),
                "adverse_rate_ppm": int(row.get("adverse_rate_ppm", 0)),
                "mean_risk_ppm": int(row.get("mean_risk_ppm", 0)),
                "p95_risk_ppm": int(row.get("p95_risk_ppm", 0)),
                "mean_decision_latency_ns": int(row.get("mean_decision_latency_ns", 0)),
                "full_profile_rate_ppm": int(row.get("full_profile_rate_ppm", 0)),
            }
        )

    normalized_families.sort(key=lambda row: str(row.get("family", "")))

    snapshot = payload.get("snapshot", {}) if isinstance(payload.get("snapshot"), dict) else {}
    actions = payload.get("actions", {}) if isinstance(payload.get("actions"), dict) else {}
    risk = payload.get("risk", {}) if isinstance(payload.get("risk"), dict) else {}

    return {
        "mode": payload.get("mode"),
        "seed": payload.get("seed"),
        "steps": payload.get("steps"),
        "family_diagnostics": normalized_families,
        "snapshot": {
            "full_validation_trigger_ppm": int(snapshot.get("full_validation_trigger_ppm", 0)),
            "repair_trigger_ppm": int(snapshot.get("repair_trigger_ppm", 0)),
            "sampled_risk_bonus_ppm": int(snapshot.get("sampled_risk_bonus_ppm", 0)),
            "pareto_cumulative_regret_milli": int(
                snapshot.get("pareto_cumulative_regret_milli", 0)
            ),
            "pareto_cap_enforcements": int(snapshot.get("pareto_cap_enforcements", 0)),
            "pareto_exhausted_families": int(snapshot.get("pareto_exhausted_families", 0)),
        },
        "action_summary": {
            "decisions": int(actions.get("decisions", 0)),
            "profile_fast": int(actions.get("profile_fast", 0)),
            "profile_full": int(actions.get("profile_full", 0)),
            "action_allow": int(actions.get("action_allow", 0)),
            "action_full_validate": int(actions.get("action_full_validate", 0)),
            "action_repair": int(actions.get("action_repair", 0)),
            "action_deny": int(actions.get("action_deny", 0)),
        },
        "risk_summary": {
            "mean_risk_ppm": float(risk.get("mean_risk_ppm", 0.0)),
            "p95_risk_ppm": int(risk.get("p95_risk_ppm", 0)),
            "p99_risk_ppm": int(risk.get("p99_risk_ppm", 0)),
        },
    }


def build_artifact(repo_root: Path) -> dict[str, Any]:
    strict = normalize_mode_payload(run_mode(repo_root, "strict"))
    hardened = normalize_mode_payload(run_mode(repo_root, "hardened"))
    return {
        "schema_version": "v1",
        "bead": "bd-w2c3.5.1",
        "generator": "scripts/generate_runtime_math_risk_pareto_calibration.py",
        "config": CONFIG,
        "strict": strict,
        "hardened": hardened,
    }


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="Write artifact to disk")
    parser.add_argument("--check", action="store_true", help="Check artifact against generated")
    parser.add_argument(
        "--artifact",
        default="tests/runtime_math/risk_pareto_calibration.v1.json",
        help="Artifact path (default: tests/runtime_math/risk_pareto_calibration.v1.json)",
    )
    args = parser.parse_args()

    if not args.write and not args.check:
        parser.error("must pass --write or --check")

    repo_root = Path(__file__).resolve().parents[1]
    artifact_path = (repo_root / args.artifact).resolve()

    generated = build_artifact(repo_root)
    generated_body = json.dumps(generated, indent=2, sort_keys=True) + "\n"

    if args.write:
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(generated_body, encoding="utf-8")
        print(f"Wrote calibration artifact: {artifact_path}")
        return 0

    current = load_json(artifact_path)
    current_body = json.dumps(current, indent=2, sort_keys=True) + "\n"
    if current == generated:
        print(f"PASS: calibration artifact matches generated output ({artifact_path})")
        return 0

    diff = "".join(
        difflib.unified_diff(
            current_body.splitlines(keepends=True),
            generated_body.splitlines(keepends=True),
            fromfile=str(artifact_path),
            tofile="<generated>",
        )
    )
    sys.stderr.write("FAIL: calibration artifact drift detected\n")
    sys.stderr.write(diff)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
