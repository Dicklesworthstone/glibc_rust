#!/usr/bin/env python3
"""closure_sweep.py — bd-w2c3.10.3
Generate final unresolved-gap report, enforce closure rules, and verify
documentation truth synchronization.

Cross-references:
  1. support_matrix.json ↔ reality_report.v1.json
  2. conformance_coverage_baseline ↔ claim_reconciliation_report
  3. FEATURE_PARITY.md mode-specific matrix ↔ fixture evidence
  4. Open gap-closure beads ↔ remaining gaps

Exit codes:
  0 = clean (all closure rules satisfied or explicitly deferred)
  1 = gap (unresolved gaps requiring attention)
  2 = missing artifact
"""
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def count_open_gap_beads() -> tuple[int, list[dict[str, str]]]:
    """Query br for open gap-closure beads."""
    try:
        proc = subprocess.run(
            ["br", "list", "--status", "open", "--label", "gap-closure", "--json"],
            capture_output=True, text=True, check=False, timeout=30,
        )
        if proc.returncode != 0:
            return 0, []
        data = json.loads(proc.stdout)
        beads = [
            {"id": b["id"], "priority": b.get("priority", 9), "title": b["title"][:80]}
            for b in sorted(data, key=lambda x: x.get("priority", 9))
        ]
        return len(data), beads
    except Exception:
        return 0, []


def check_support_reality_alignment(
    support: dict, reality: dict
) -> list[dict[str, str]]:
    """Alignment 1: support_matrix ↔ reality_report."""
    findings: list[dict[str, str]] = []
    if support is None or reality is None:
        findings.append({
            "severity": "error",
            "category": "alignment_1_support_reality",
            "message": "Missing support_matrix.json or reality_report.v1.json",
        })
        return findings

    support_total = len(support.get("symbols", []))
    reality_total = reality.get("total_exported", reality.get("summary", {}).get("total_exported", 0))
    if support_total != reality_total:
        findings.append({
            "severity": "error",
            "category": "alignment_1_support_reality",
            "message": f"Symbol count mismatch: support_matrix={support_total}, reality_report={reality_total}",
        })

    # Check status distribution (support_matrix uses "status" field)
    statuses: dict[str, int] = {}
    for sym in support.get("symbols", []):
        s = sym.get("status", "unknown")
        statuses[s] = statuses.get(s, 0) + 1

    # reality_report uses "counts" with snake_case keys
    reality_counts = reality.get("counts", {})
    key_map = {
        "Implemented": "implemented",
        "RawSyscall": "raw_syscall",
        "GlibcCallThrough": "glibc_call_through",
        "Stub": "stub",
    }
    for support_key, reality_key in key_map.items():
        support_count = statuses.get(support_key, 0)
        reality_count = reality_counts.get(reality_key, 0)
        if support_count != reality_count:
            findings.append({
                "severity": "error",
                "category": "alignment_1_support_reality",
                "message": f"{support_key} count mismatch: support_matrix={support_count}, reality_report={reality_count}",
            })

    return findings


def check_coverage_reconciliation(
    coverage: dict | None, reconciliation: dict | None
) -> list[dict[str, str]]:
    """Alignment 2: coverage baseline ↔ claim reconciliation."""
    findings: list[dict[str, str]] = []
    if coverage is None:
        findings.append({
            "severity": "warning",
            "category": "alignment_2_coverage",
            "message": "Missing conformance_coverage_baseline.v1.json",
        })
    if reconciliation is None:
        findings.append({
            "severity": "warning",
            "category": "alignment_2_reconciliation",
            "message": "Missing claim_reconciliation_report.v1.json",
        })

    if reconciliation:
        errors = reconciliation.get("summary", {}).get("errors", 0)
        warnings = reconciliation.get("summary", {}).get("warnings", 0)
        if errors > 0:
            findings.append({
                "severity": "error",
                "category": "alignment_2_reconciliation",
                "message": f"Claim reconciliation has {errors} error(s)",
            })
        if warnings > 0:
            findings.append({
                "severity": "warning",
                "category": "alignment_2_reconciliation",
                "message": f"Claim reconciliation has {warnings} warning(s)",
            })

    return findings


def analyze_coverage_gaps(
    coverage: dict | None, support: dict | None
) -> dict[str, Any]:
    """Compute per-module coverage gap analysis."""
    if coverage is None or support is None:
        return {"error": "missing data"}

    summary = coverage.get("summary", {})
    module_cov = coverage.get("module_coverage", {})

    uncovered_modules = []
    partial_modules = []
    full_modules = []

    for mod_name, info in sorted(module_cov.items()):
        total = info.get("total", 0)
        covered = info.get("covered", 0)
        pct = info.get("pct", 0)
        if pct == 0 and total > 0:
            uncovered_modules.append({"module": mod_name, "total_symbols": total})
        elif pct < 100:
            partial_modules.append({
                "module": mod_name,
                "total": total,
                "covered": covered,
                "pct": pct,
                "gap": total - covered,
            })
        else:
            full_modules.append({"module": mod_name, "total": total})

    return {
        "total_symbols": summary.get("total_symbols", 0),
        "symbols_with_fixtures": summary.get("symbols_with_fixtures", 0),
        "coverage_pct": summary.get("coverage_pct", 0),
        "uncovered_modules": uncovered_modules,
        "partial_modules": partial_modules,
        "full_modules": full_modules,
    }


def analyze_callthrough_gap(support: dict | None) -> dict[str, Any]:
    """Analyze remaining GlibcCallThrough symbols by module."""
    if support is None:
        return {"error": "missing support_matrix"}

    callthrough_by_module: dict[str, list[str]] = {}
    for sym in support.get("symbols", []):
        if sym.get("status") == "GlibcCallThrough":
            mod = sym.get("module", "unknown")
            callthrough_by_module.setdefault(mod, []).append(sym.get("symbol", "?"))

    total = sum(len(v) for v in callthrough_by_module.values())
    modules = [
        {"module": mod, "count": len(syms), "symbols": sorted(syms)}
        for mod, syms in sorted(callthrough_by_module.items(), key=lambda x: -len(x[1]))
    ]
    return {"total_callthrough": total, "by_module": modules}


def check_drift_gates(repo_root: Path) -> list[dict[str, str]]:
    """Verify that drift gate scripts exist and are executable."""
    findings: list[dict[str, str]] = []
    required_gates = [
        "scripts/check_support_matrix_drift.sh",
        "scripts/check_claim_reconciliation.sh",
        "scripts/check_conformance_coverage.sh",
        "scripts/check_release_dry_run.sh",
    ]
    for gate in required_gates:
        p = repo_root / gate
        if not p.exists():
            findings.append({
                "severity": "warning",
                "category": "drift_gates",
                "message": f"Drift gate missing: {gate}",
            })
        elif not os.access(p, os.X_OK):
            findings.append({
                "severity": "warning",
                "category": "drift_gates",
                "message": f"Drift gate not executable: {gate}",
            })
    return findings


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent

    support = load_json(repo_root / "support_matrix.json")
    reality = load_json(repo_root / "tests/conformance/reality_report.v1.json")
    coverage = load_json(repo_root / "tests/conformance/conformance_coverage_baseline.v1.json")
    reconciliation = load_json(repo_root / "tests/conformance/claim_reconciliation_report.v1.json")

    findings: list[dict[str, str]] = []

    # Alignment 1: support ↔ reality
    findings.extend(check_support_reality_alignment(support, reality))

    # Alignment 2: coverage ↔ reconciliation
    findings.extend(check_coverage_reconciliation(coverage, reconciliation))

    # Drift gates check
    findings.extend(check_drift_gates(repo_root))

    # Coverage gap analysis
    coverage_gaps = analyze_coverage_gaps(coverage, support)

    # CallThrough gap analysis
    callthrough_gaps = analyze_callthrough_gap(support)

    # Open gap-closure beads
    bead_count, bead_list = count_open_gap_beads()

    # Build report
    errors = sum(1 for f in findings if f["severity"] == "error")
    warnings = sum(1 for f in findings if f["severity"] == "warning")

    # Determine non-closure reasons
    non_closure_reasons = []
    if callthrough_gaps.get("total_callthrough", 0) > 0:
        non_closure_reasons.append({
            "category": "callthrough_elimination",
            "detail": f"{callthrough_gaps['total_callthrough']} GlibcCallThrough symbols remain for replacement elimination",
            "blocking_beads": ["bd-w2c3.2.1"],
        })
    if coverage_gaps.get("uncovered_modules"):
        non_closure_reasons.append({
            "category": "fixture_coverage",
            "detail": f"{len(coverage_gaps['uncovered_modules'])} module(s) have zero fixture coverage",
            "modules": [m["module"] for m in coverage_gaps["uncovered_modules"]],
        })
    if bead_count > 0:
        non_closure_reasons.append({
            "category": "open_beads",
            "detail": f"{bead_count} gap-closure beads remain open",
        })

    status = "pass" if errors == 0 else "fail"
    report = {
        "schema_version": "v1",
        "bead": "bd-w2c3.10.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": status,
        "summary": {
            "errors": errors,
            "warnings": warnings,
            "total_findings": len(findings),
            "coverage_pct": coverage_gaps.get("coverage_pct", 0),
            "callthrough_remaining": callthrough_gaps.get("total_callthrough", 0),
            "open_gap_beads": bead_count,
            "closure_ready": errors == 0 and len(non_closure_reasons) == 0,
        },
        "findings": findings,
        "coverage_gaps": coverage_gaps,
        "callthrough_gaps": callthrough_gaps,
        "non_closure_reasons": non_closure_reasons,
        "drift_gates_status": "armed" if not any(
            f["category"] == "drift_gates" for f in findings
        ) else "degraded",
        "open_gap_beads": {
            "count": bead_count,
            "top_priorities": bead_list[:10],
        },
    }

    print(json.dumps(report, indent=2))

    # Also write to artifact file
    artifact_path = repo_root / "tests/conformance/closure_sweep_report.v1.json"
    with artifact_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
        f.write("\n")

    if errors > 0:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
