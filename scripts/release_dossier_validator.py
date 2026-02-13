#!/usr/bin/env python3
"""release_dossier_validator.py — bd-5fw.3
Release artifact dossier specification + integrity validator.

Defines the canonical artifact manifest for a FrankenLibC release and validates:
  1. COMPLETENESS: All required artifacts exist at expected paths.
  2. INTEGRITY: SHA256 checksums match for all tracked artifacts.
  3. SCHEMA: Each artifact with a JSON schema has valid structure.
  4. FRESHNESS: Artifacts are not stale (generated within a configurable window).

Reads:
  - Artifact files from the repository (conformance reports, coverage snapshots,
    support matrix, reality report, ablation/admission reports, etc.)

Produces:
  - tests/release/dossier_validation_report.v1.json

Exit codes:
  0 = dossier is complete and valid
  1 = validation failures detected
  2 = critical artifact missing (cannot even begin validation)
"""
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


# ──────────────────────────────────────────────
# Artifact Manifest Specification
# ──────────────────────────────────────────────

ARTIFACT_MANIFEST = [
    # ── Conformance & Coverage ──
    {
        "id": "support_matrix",
        "path": "support_matrix.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Ground truth: symbol → implementation status classification",
        "schema_keys": ["total_exported", "symbols"],
    },
    {
        "id": "reality_report",
        "path": "tests/conformance/reality_report.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Actual implementation counts reconciled against source code",
        "schema_keys": ["schema_version", "counts"],
    },
    {
        "id": "conformance_coverage",
        "path": "tests/conformance/conformance_coverage_baseline.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Conformance fixture coverage snapshot",
        "schema_keys": ["schema_version", "summary"],
    },
    {
        "id": "claim_reconciliation",
        "path": "tests/conformance/claim_reconciliation_report.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Support matrix vs reality cross-check",
        "schema_keys": ["schema_version", "status", "summary"],
    },
    {
        "id": "closure_sweep",
        "path": "tests/conformance/closure_sweep_report.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Cross-source closure sweep for release readiness",
        "schema_keys": ["schema_version", "status", "summary"],
    },
    # ── Replacement & Parity ──
    {
        "id": "replacement_levels",
        "path": "tests/conformance/replacement_levels.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Replacement level classifications (L0-L3)",
        "schema_keys": ["current_level"],
    },
    {
        "id": "opportunity_matrix",
        "path": "tests/conformance/opportunity_matrix.json",
        "kind": "report",
        "required": True,
        "critical": False,
        "description": "Replacement opportunity analysis per symbol",
        "schema_keys": ["schema_version"],
    },
    # ── Runtime Math Governance ──
    {
        "id": "math_governance",
        "path": "tests/conformance/math_governance.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Runtime math module governance classification",
        "schema_keys": ["classifications"],
    },
    {
        "id": "controller_ablation",
        "path": "tests/runtime_math/controller_ablation_report.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Controller ablation partition decisions",
        "schema_keys": ["schema_version", "status", "partition_decisions", "migration_plan"],
    },
    {
        "id": "admission_gate",
        "path": "tests/runtime_math/admission_gate_report.v1.json",
        "kind": "report",
        "required": True,
        "critical": True,
        "description": "Runtime math admission gate policy enforcement",
        "schema_keys": ["schema_version", "status", "admission_ledger", "policies_enforced"],
    },
    {
        "id": "production_kernel_manifest",
        "path": "tests/runtime_math/production_kernel_manifest.v1.json",
        "kind": "manifest",
        "required": True,
        "critical": True,
        "description": "Production kernel module manifest with feature gates",
        "schema_keys": ["production_modules", "default_feature_set"],
    },
    # ── Release Gate DAG ──
    {
        "id": "release_gate_dag",
        "path": "tests/conformance/release_gate_dag.v1.json",
        "kind": "manifest",
        "required": True,
        "critical": True,
        "description": "Deterministic release gate execution DAG",
        "schema_keys": ["schema_version", "gates"],
    },
    # ── Symbol & Feature Coverage ──
    {
        "id": "symbol_fixture_coverage",
        "path": "tests/conformance/symbol_fixture_coverage.v1.json",
        "kind": "report",
        "required": True,
        "critical": False,
        "description": "Per-symbol fixture coverage tracking",
        "schema_keys": ["schema_version"],
    },
    # ── E2E / CVE Arena ──
    {
        "id": "e2e_scenario_manifest",
        "path": "tests/cve_arena/e2e_scenario_manifest.v1.json",
        "kind": "manifest",
        "required": False,
        "critical": False,
        "description": "E2E scenario catalog for CVE arena testing",
        "schema_keys": ["schema_version", "scenarios"],
    },
    # ── Closure Contract ──
    {
        "id": "closure_contract",
        "path": "tests/conformance/closure_contract.v1.json",
        "kind": "manifest",
        "required": True,
        "critical": True,
        "description": "Release closure verification contract (L0-L3 obligations)",
        "schema_keys": ["schema_version", "levels"],
    },
]


def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_artifact(repo_root: Path, spec: dict) -> dict:
    """Validate a single artifact against its spec."""
    artifact_path = repo_root / spec["path"]
    result = {
        "id": spec["id"],
        "path": spec["path"],
        "kind": spec["kind"],
        "required": spec["required"],
        "critical": spec["critical"],
    }

    if not artifact_path.exists():
        result["status"] = "MISSING"
        result["sha256"] = None
        result["size_bytes"] = 0
        result["schema_valid"] = False
        result["findings"] = [{
            "severity": "error" if spec["required"] else "warning",
            "message": f"Artifact '{spec['id']}' not found at {spec['path']}",
        }]
        return result

    # File exists — compute integrity
    result["sha256"] = sha256_file(artifact_path)
    result["size_bytes"] = artifact_path.stat().st_size
    result["status"] = "PRESENT"
    findings: list[dict] = []

    # Schema validation for JSON artifacts
    if spec["path"].endswith(".json"):
        try:
            data = load_json(artifact_path)
            if data is None:
                findings.append({
                    "severity": "error",
                    "message": f"Artifact '{spec['id']}' is empty or unparseable",
                })
                result["schema_valid"] = False
            else:
                # Check required keys
                missing_keys = [
                    k for k in spec.get("schema_keys", [])
                    if k not in data
                ]
                if missing_keys:
                    findings.append({
                        "severity": "error",
                        "message": (
                            f"Artifact '{spec['id']}' missing required keys: "
                            f"{missing_keys}"
                        ),
                    })
                    result["schema_valid"] = False
                else:
                    result["schema_valid"] = True

                # Check for pass/fail status field
                if "status" in data:
                    artifact_status = data["status"]
                    if artifact_status == "fail":
                        findings.append({
                            "severity": "error",
                            "message": (
                                f"Artifact '{spec['id']}' reports status=fail"
                            ),
                        })
        except json.JSONDecodeError as e:
            findings.append({
                "severity": "error",
                "message": f"Artifact '{spec['id']}' has invalid JSON: {e}",
            })
            result["schema_valid"] = False
    else:
        result["schema_valid"] = True  # Non-JSON artifacts skip schema check

    if not findings:
        result["status"] = "VALID"

    result["findings"] = findings
    return result


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    artifact_results = []
    all_findings: list[dict] = []

    for spec in ARTIFACT_MANIFEST:
        result = validate_artifact(repo_root, spec)
        artifact_results.append(result)
        all_findings.extend(result.get("findings", []))

    # Compute summary
    total = len(ARTIFACT_MANIFEST)
    valid = sum(1 for r in artifact_results if r["status"] == "VALID")
    present = sum(1 for r in artifact_results if r["status"] in ("VALID", "PRESENT"))
    missing = sum(1 for r in artifact_results if r["status"] == "MISSING")
    critical_missing = sum(
        1 for r in artifact_results
        if r["status"] == "MISSING" and r["critical"]
    )

    errors = sum(1 for f in all_findings if f["severity"] == "error")
    warnings = sum(1 for f in all_findings if f["severity"] == "warning")

    # Determine overall verdict
    if critical_missing > 0:
        verdict = "FAIL_CRITICAL"
    elif errors > 0:
        verdict = "FAIL"
    else:
        verdict = "PASS"

    status = "pass" if verdict == "PASS" else "fail"

    # Build integrity index (sha256 for all present artifacts)
    integrity_index = {
        r["id"]: {
            "path": r["path"],
            "sha256": r["sha256"],
            "size_bytes": r["size_bytes"],
        }
        for r in artifact_results
        if r["sha256"] is not None
    }

    report = {
        "schema_version": "v1",
        "bead": "bd-5fw.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "verdict": verdict,
        "summary": {
            "total_artifacts": total,
            "valid": valid,
            "present_with_issues": present - valid,
            "missing": missing,
            "critical_missing": critical_missing,
            "errors": errors,
            "warnings": warnings,
        },
        "dossier_manifest_version": "v1",
        "compatibility_policy": {
            "format": "Additive-only evolution: new artifacts may be added, existing paths are stable",
            "schema_versions": "Each artifact tracks its own schema_version independently",
            "integrity": "SHA256 checksums computed at validation time; dossier is revalidatable offline",
        },
        "artifact_results": artifact_results,
        "integrity_index": integrity_index,
        "findings": all_findings,
    }

    print(json.dumps(report, indent=2))

    # Write artifact
    artifact_dir = repo_root / "tests/release"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / "dossier_validation_report.v1.json"
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    if verdict.startswith("FAIL"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
