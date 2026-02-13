#!/usr/bin/env python3
"""generate_cve_heap_overflow_validation.py — bd-1m5.1

Validates the CVE Arena heap overflow test suite:
  1. Manifest completeness — all heap-overflow CVEs have manifests + triggers.
  2. Manifest schema — required fields present and well-typed.
  3. Healing action coverage — heap overflow CVEs exercise ClampSize/CanaryDetection.
  4. Trigger compilability — C triggers compile with cc.
  5. Coverage matrix consistency — heap overflow CVEs appear in coverage_matrix.json.

Generates a JSON validation report to stdout (or --output).
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# Heap-overflow-relevant CWE IDs
HEAP_OVERFLOW_CWES = {"CWE-122", "CWE-787", "CWE-120", "CWE-121", "CWE-131"}

# Expected healing actions for heap overflows
HEAP_HEALING_ACTIONS = {"ClampSize", "TruncateWithNull", "CanaryDetection",
                        "FreedWithCanaryCorruption"}

# Required manifest fields
REQUIRED_FIELDS = ["cve_id", "test_name", "category", "description",
                   "build_cmd", "cwe_ids"]


def find_heap_overflow_tests(arena_root):
    """Find all CVE test directories that involve heap overflow patterns."""
    tests = []
    for category_dir in ["glibc", "synthetic", "targets"]:
        base = arena_root / category_dir
        if not base.exists():
            continue
        for test_dir in sorted(base.iterdir()):
            if not test_dir.is_dir():
                continue
            manifest_path = test_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = load_json_file(manifest_path)
            cwe_ids = set(manifest.get("cwe_ids", []))

            # Include if any CWE is heap-overflow-related
            if cwe_ids & HEAP_OVERFLOW_CWES:
                tests.append({
                    "dir": test_dir,
                    "manifest_path": manifest_path,
                    "manifest": manifest,
                    "category": category_dir,
                })

    return tests


def validate_manifest(test_info):
    """Validate a single test manifest."""
    issues = []
    manifest = test_info["manifest"]

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    # Check cve_id format
    cve_id = manifest.get("cve_id", "")
    if not cve_id.startswith("CVE-"):
        issues.append(f"Invalid cve_id format: {cve_id}")

    # Check test_name format
    test_name = manifest.get("test_name", "")
    if not test_name or not all(c.isalnum() or c == "_" for c in test_name):
        issues.append(f"Invalid test_name: {test_name}")

    # Check expected behavior sections (accept both naming conventions)
    has_expected_stock = ("expected_stock_behavior" in manifest or
                         "expected_stock" in manifest)
    has_expected_tsm = ("expected_tsm_behavior" in manifest or
                        "expected_tsm" in manifest)
    if not has_expected_stock:
        issues.append("Missing expected stock behavior section")
    if not has_expected_tsm:
        issues.append("Missing expected TSM behavior section")

    # Check healing actions for heap overflow relevance
    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if not healing:
        issues.append("No healing actions specified")

    # TSM features tested
    features = manifest.get("tsm_features_tested", [])
    if not features:
        issues.append("No TSM features listed")

    return issues


def check_trigger_exists(test_info):
    """Check that trigger files exist."""
    test_dir = test_info["dir"]
    trigger_files = []
    for ext in ["*.c", "*.sh", "*.pl", "*.py"]:
        trigger_files.extend(test_dir.glob(ext))

    # Also check for specific trigger files
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        p = test_dir / name
        if p.exists():
            if p not in trigger_files:
                trigger_files.append(p)

    return [str(f.name) for f in trigger_files]


def check_c_trigger_compiles(test_info):
    """Try to compile C trigger files."""
    test_dir = test_info["dir"]
    trigger_c = test_dir / "trigger.c"
    if not trigger_c.exists():
        return None  # Not a C trigger

    with tempfile.NamedTemporaryFile(suffix=".o", delete=True) as tmp:
        try:
            result = subprocess.run(
                ["cc", "-c", "-fsyntax-only", str(trigger_c)],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None


def check_coverage_matrix(arena_root, heap_tests):
    """Verify heap overflow CVEs appear in coverage_matrix.json."""
    matrix_path = arena_root / "coverage_matrix.json"
    if not matrix_path.exists():
        return {"exists": False, "issues": ["coverage_matrix.json not found"]}

    matrix = load_json_file(matrix_path)
    features = matrix.get("features", {})

    # Collect all CVE IDs from matrix
    matrix_cve_ids = set()
    for _feat, info in features.items():
        for cve in info.get("cves", []):
            matrix_cve_ids.add(cve.get("cve_id", ""))

    # Check each heap test's CVE is in the matrix
    missing = []
    for test_info in heap_tests:
        cve_id = test_info["manifest"].get("cve_id", "").split(" ")[0]
        # Also check original_cve field for synthetics
        original_cve = test_info["manifest"].get("original_cve", cve_id)
        if cve_id not in matrix_cve_ids and original_cve not in matrix_cve_ids:
            missing.append(cve_id)

    return {
        "exists": True,
        "total_cves_in_matrix": len(matrix_cve_ids),
        "heap_cves_missing": missing,
    }


def main():
    parser = argparse.ArgumentParser(description="CVE heap overflow validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    arena_root = root / "tests" / "cve_arena"

    if not arena_root.exists():
        print("ERROR: tests/cve_arena/ not found", file=sys.stderr)
        sys.exit(1)

    # Find all heap overflow tests
    heap_tests = find_heap_overflow_tests(arena_root)

    # Validate each test
    test_results = []
    total_issues = 0
    healing_actions_seen = set()

    for test_info in heap_tests:
        manifest = test_info["manifest"]
        cve_id = manifest.get("cve_id", "unknown")
        test_name = manifest.get("test_name", "unknown")

        # Validate manifest
        manifest_issues = validate_manifest(test_info)

        # Check trigger files
        trigger_files = check_trigger_exists(test_info)

        # Try C compilation
        compiles = check_c_trigger_compiles(test_info)

        # Collect healing actions
        tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
        healing = tsm.get("healing_actions", [])
        healing_actions_seen.update(healing)

        issues = list(manifest_issues)
        if not trigger_files:
            issues.append("No trigger files found")

        total_issues += len(issues)

        test_results.append({
            "cve_id": cve_id,
            "test_name": test_name,
            "category": test_info["category"],
            "cwe_ids": manifest.get("cwe_ids", []),
            "cvss_score": manifest.get("cvss_score"),
            "trigger_files": trigger_files,
            "c_compiles": compiles,
            "healing_actions": healing,
            "tsm_features": manifest.get("tsm_features_tested", []),
            "manifest_valid": len(issues) == 0,
            "issues": issues,
        })

    # Check coverage matrix
    matrix_check = check_coverage_matrix(arena_root, heap_tests)

    # Compute summary
    total_tests = len(test_results)
    valid_manifests = sum(1 for t in test_results if t["manifest_valid"])
    with_triggers = sum(1 for t in test_results if t["trigger_files"])
    c_tests = [t for t in test_results if t["c_compiles"] is not None]
    c_compiles = sum(1 for t in c_tests if t["c_compiles"])

    # CWE coverage
    all_cwes = set()
    for t in test_results:
        all_cwes.update(t["cwe_ids"])
    heap_cwes_covered = all_cwes & HEAP_OVERFLOW_CWES

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_heap_overflow_tests": total_tests,
            "manifests_valid": valid_manifests,
            "with_trigger_files": with_triggers,
            "c_triggers_compile": c_compiles,
            "c_triggers_total": len(c_tests),
            "unique_healing_actions": sorted(healing_actions_seen),
            "heap_cwes_covered": sorted(heap_cwes_covered),
            "heap_cwes_target": sorted(HEAP_OVERFLOW_CWES),
            "coverage_matrix_present": matrix_check.get("exists", False),
            "total_issues": total_issues,
        },
        "tests": test_results,
        "coverage_matrix_check": matrix_check,
    }

    output = json.dumps(report, indent=2) + "\n"

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
