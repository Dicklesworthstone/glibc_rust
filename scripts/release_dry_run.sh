#!/usr/bin/env bash
# release_dry_run.sh — deterministic release gate DAG runner (bd-5fw.2)
#
# Supports:
# - fixed, audited gate order from tests/conformance/release_gate_dag.v1.json
# - fail-fast behavior
# - deterministic resume token + partial rerun semantics
# - structured JSONL logs for each gate decision
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$ROOT" "$@" <<'PY'
import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


def default_tmp_root() -> str:
    # Prefer explicit overrides, then /data/tmp if present in this workspace,
    # then fall back to /tmp for portability.
    for key in ("FRANKENLIBC_TMPDIR", "TMPDIR"):
        val = os.environ.get(key, "").strip()
        if val and os.path.isdir(val) and os.access(val, os.W_OK):
            return val
    if os.path.isdir("/data/tmp") and os.access("/data/tmp", os.W_OK):
        return "/data/tmp"
    return "/tmp"


def load_json(path: pathlib.Path) -> Any:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def ensure_parent(path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def validate_dag(dag: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if dag.get("schema_version") != 1:
        errors.append("schema_version must be 1")

    gates = dag.get("gates")
    if not isinstance(gates, list) or not gates:
        errors.append("gates must be a non-empty array")
        return errors

    names: list[str] = []
    for idx, gate in enumerate(gates):
        if not isinstance(gate, dict):
            errors.append(f"gate[{idx}] must be an object")
            continue
        name = gate.get("gate_name")
        if not isinstance(name, str) or not name:
            errors.append(f"gate[{idx}] missing gate_name")
            continue
        names.append(name)
        if not isinstance(gate.get("depends_on"), list):
            errors.append(f"{name}: depends_on must be an array")
        if not isinstance(gate.get("command"), str) or not gate.get("command"):
            errors.append(f"{name}: command must be non-empty string")

    if len(set(names)) != len(names):
        errors.append("gate_name values must be unique")

    known = set(names)
    seen: set[str] = set()
    for gate in gates:
        name = gate.get("gate_name")
        if not isinstance(name, str):
            continue
        deps = gate.get("depends_on", [])
        for dep in deps:
            if dep not in known:
                errors.append(f"{name}: unknown dependency '{dep}'")
            if dep not in seen:
                errors.append(
                    f"{name}: dependency '{dep}' appears after gate in declared order"
                )
        seen.add(name)

    return errors


def compute_prereq_hash(dag: dict[str, Any], mode: str) -> str:
    payload = {
        "schema_version": dag.get("schema_version"),
        "mode": mode,
        "gates": dag.get("gates"),
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def parse_resume_token(token: str, prereq_hash: str, gate_count: int) -> int:
    m = re.fullmatch(r"v1:([0-9a-f]{12}):([0-9]+)", token)
    if not m:
        raise ValueError("invalid resume token format; expected v1:<hash12>:<start_index>")
    hash_prefix, start_idx_raw = m.groups()
    if hash_prefix != prereq_hash[:12]:
        raise ValueError(
            "resume token hash prefix does not match current DAG/mode prereq hash"
        )
    start_idx = int(start_idx_raw)
    if start_idx < 0 or start_idx > gate_count:
        raise ValueError("resume token start_index out of bounds")
    return start_idx


def resolve_artifact(root: pathlib.Path, gate: dict[str, Any]) -> str | None:
    art = gate.get("report_artifact")
    if not art:
        return None
    p = root / art if not pathlib.Path(art).is_absolute() else pathlib.Path(art)
    return str(p) if p.exists() else None


def build_blocker_chain(gates: list[dict[str, Any]], failed_idx: int) -> list[str]:
    chain: list[str] = []
    failed_name = gates[failed_idx]["gate_name"]
    chain.append(f"{failed_name} (FAILED)")
    for gate in gates[failed_idx + 1:]:
        deps = gate.get("depends_on", [])
        if any(d in [g for g in [r.split(" ")[0] for r in chain]] for d in deps):
            chain.append(f"{gate['gate_name']} (BLOCKED by {failed_name})")
    return chain


def run_gate(root: pathlib.Path, command: str, mode: str, gate_name: str) -> tuple[bool, int, str]:
    if mode == "dry-run":
        simulated_fail_gate = os.environ.get("FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE", "").strip()
        if simulated_fail_gate and simulated_fail_gate == gate_name:
            return False, 1, f"simulated failure for gate '{gate_name}'"
        return True, 0, "dry-run simulated pass"

    proc = subprocess.run(  # noqa: S602
        command,
        shell=True,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    ok = proc.returncode == 0
    if ok:
        return True, 0, "command_exit=0"

    tail = proc.stderr.strip().splitlines()[-1] if proc.stderr.strip() else ""
    if not tail and proc.stdout.strip():
        tail = proc.stdout.strip().splitlines()[-1]
    detail = f"command_exit={proc.returncode}"
    if tail:
        detail = f"{detail}, tail={tail}"
    return False, proc.returncode, detail


def write_json(path: pathlib.Path, payload: Any) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True))
            f.write("\n")


def main() -> int:
    tmp_root = default_tmp_root()
    parser = argparse.ArgumentParser(description="Deterministic release dry-run gate runner")
    parser.add_argument(
        "--dag",
        default="tests/conformance/release_gate_dag.v1.json",
        help="Path to gate DAG artifact (workspace-relative by default)",
    )
    parser.add_argument(
        "--mode",
        choices=["dry-run", "run"],
        default="dry-run",
        help="dry-run simulates gate commands; run executes them",
    )
    parser.add_argument(
        "--log-path",
        default=os.path.join(tmp_root, "frankenlibc_release_gate_dry_run.log.jsonl"),
        help="JSONL log output path",
    )
    parser.add_argument(
        "--state-path",
        default=os.path.join(tmp_root, "frankenlibc_release_resume_state.json"),
        help="Resume state output path",
    )
    parser.add_argument(
        "--dossier-path",
        default=os.path.join(tmp_root, "frankenlibc_release_dry_run_dossier.json"),
        help="Dossier summary output path",
    )
    parser.add_argument(
        "--resume-token",
        default="",
        help="Resume token emitted by a previous failed run",
    )
    parser.add_argument(
        "--trace-id",
        default="",
        help="Optional explicit trace ID for deterministic replay bookkeeping",
    )
    args = parser.parse_args(sys.argv[2:])

    root = pathlib.Path(sys.argv[1]).resolve()
    dag_path = (root / args.dag).resolve() if not pathlib.Path(args.dag).is_absolute() else pathlib.Path(args.dag)
    log_path = pathlib.Path(args.log_path)
    state_path = pathlib.Path(args.state_path)
    dossier_path = pathlib.Path(args.dossier_path)

    print("=== Release Dry-Run Gate Runner (bd-5fw.2) ===")
    print(f"DAG: {dag_path}")
    print(f"Mode: {args.mode}")

    if not dag_path.exists():
        print(f"FAIL: DAG file not found: {dag_path}")
        return 1

    dag = load_json(dag_path)
    schema_errors = validate_dag(dag)
    if schema_errors:
        print(f"FAIL: DAG schema has {len(schema_errors)} error(s)")
        for err in schema_errors:
            print(f"  - {err}")
        return 1

    gates = dag["gates"]
    prereq_hash = compute_prereq_hash(dag, args.mode)
    trace_id = args.trace_id or (
        f"release-dry-run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{os.getpid()}"
    )

    start_index = 0
    if args.resume_token:
        try:
            start_index = parse_resume_token(args.resume_token, prereq_hash, len(gates))
        except ValueError as exc:
            print(f"FAIL: {exc}")
            return 1
        print(f"Resume token accepted; starting from gate index {start_index}")

    rows: list[dict[str, Any]] = []
    run_started = time.perf_counter()

    for idx, gate in enumerate(gates):
        gate_name = gate["gate_name"]
        gate_cmd = gate["command"]
        gate_started = time.perf_counter()

        if idx < start_index:
            duration_ms = 0
            status = "resume_skip"
            exit_code = 0
            detail = f"skipped due to resume start_index={start_index}"
        else:
            ok, exit_code, detail = run_gate(root, gate_cmd, args.mode, gate_name)
            duration_ms = int((time.perf_counter() - gate_started) * 1000)
            status = "pass" if ok else "fail"

        artifact_path = resolve_artifact(root, gate)
        row = {
            "trace_id": trace_id,
            "gate_name": gate_name,
            "prereq_hash": prereq_hash,
            "status": status,
            "duration_ms": duration_ms,
            "resume_token": args.resume_token or "",
            "gate_index": idx,
            "depends_on": gate.get("depends_on", []),
            "detail": detail,
            "exit_code": exit_code,
            "artifact_path": artifact_path,
            "critical": gate.get("critical", True),
            "rationale": f"gate '{gate_name}' {'passed all checks' if status == 'pass' else 'failed: ' + detail}" if status not in ("resume_skip",) else "skipped (resume)",
        }
        rows.append(row)
        print(f"{status.upper()}: {gate_name} ({detail})")

        if status == "fail":
            next_token = f"v1:{prereq_hash[:12]}:{idx}"
            blocker_chain = build_blocker_chain(gates, idx)
            state = {
                "schema_version": 1,
                "trace_id": trace_id,
                "mode": args.mode,
                "failed_gate": gate_name,
                "failed_gate_index": idx,
                "prereq_hash": prereq_hash,
                "resume_token": next_token,
                "generated_at_utc": now_utc(),
                "log_path": str(log_path),
                "blocker_chain": blocker_chain,
                "diagnostics": detail,
            }
            write_json(state_path, state)
            write_jsonl(log_path, rows)
            print("")
            print(f"FAIL-FAST: stopped at gate '{gate_name}'")
            print(f"Blocker chain: {' -> '.join(blocker_chain)}")
            print(f"Resume token: {next_token}")
            print(f"State file: {state_path}")
            print(f"Log file: {log_path}")
            print("release_dry_run: FAILED")
            return 1

    total_duration_ms = int((time.perf_counter() - run_started) * 1000)
    passed = sum(1 for r in rows if r["status"] == "pass")
    skipped = sum(1 for r in rows if r["status"] == "resume_skip")
    artifact_index = {
        r["gate_name"]: r["artifact_path"]
        for r in rows
        if r.get("artifact_path")
    }
    dossier = {
        "schema_version": 2,
        "bead": "bd-w2c3.10.2",
        "trace_id": trace_id,
        "mode": args.mode,
        "prereq_hash": prereq_hash,
        "gate_count": len(gates),
        "start_index": start_index,
        "total_duration_ms": total_duration_ms,
        "generated_at_utc": now_utc(),
        "summary": {
            "total": len(gates),
            "passed": passed,
            "skipped": skipped,
            "failed": 0,
            "verdict": "PASS",
        },
        "artifact_index": artifact_index,
        "gates": rows,
    }

    write_json(dossier_path, dossier)
    write_jsonl(log_path, rows)

    success_state = {
        "schema_version": 1,
        "trace_id": trace_id,
        "mode": args.mode,
        "status": "success",
        "prereq_hash": prereq_hash,
        "resume_token": "",
        "generated_at_utc": now_utc(),
        "log_path": str(log_path),
        "dossier_path": str(dossier_path),
    }
    write_json(state_path, success_state)

    print("")
    print(f"PASS: executed {len(gates)} gate(s) in deterministic order")
    print(f"Dossier: {dossier_path}")
    print(f"State: {state_path}")
    print(f"Log: {log_path}")
    print("release_dry_run: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY
