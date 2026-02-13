#!/usr/bin/env python3
"""generate_cve_uaf_validation.py — bd-1m5.3

Validates the CVE Arena use-after-free test suite:
  1. Manifest completeness — UAF/double-free CVEs have manifests + triggers.
  2. Manifest schema — required fields present and well-typed.
  3. Healing action coverage — GenerationalArena, IgnoreDoubleFree exercised.
  4. UAF pattern coverage — simple UAF, double-free, type confusion patterns.
  5. Coverage matrix consistency.

Generates a JSON validation report to stdout (or --output).
"""
import argparse
import json
import subprocess
import sys
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


# UAF-relevant CWE IDs
UAF_CWES = {"CWE-416", "CWE-415"}

REQUIRED_FIELDS = ["cve_id", "test_name", "category", "description",
                   "build_cmd", "cwe_ids"]

# Key healing actions for UAF
UAF_HEALING_ACTIONS = {"IgnoreDoubleFree", "IgnoreForeignFree",
                       "GenerationalArena", "ReallocAsMalloc"}


def find_uaf_tests(arena_root):
    """Find all CVE test directories involving UAF/double-free patterns."""
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

            is_uaf = bool(cwe_ids & UAF_CWES)
            if not is_uaf and "uaf" in test_dir.name.lower():
                is_uaf = True
            if is_uaf:
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

    for field in REQUIRED_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    cve_id = manifest.get("cve_id", "")
    if not cve_id.startswith("CVE-"):
        issues.append(f"Invalid cve_id format: {cve_id}")

    has_expected_stock = ("expected_stock_behavior" in manifest or
                         "expected_stock" in manifest)
    has_expected_tsm = ("expected_tsm_behavior" in manifest or
                        "expected_tsm" in manifest)
    if not has_expected_stock:
        issues.append("Missing expected stock behavior section")
    if not has_expected_tsm:
        issues.append("Missing expected TSM behavior section")

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if not healing:
        issues.append("No healing actions specified")

    return issues


def check_trigger_exists(test_info):
    test_dir = test_info["dir"]
    trigger_files = []
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        if (test_dir / name).exists():
            trigger_files.append(name)
    return trigger_files


def check_c_trigger_compiles(test_info):
    trigger_c = test_info["dir"] / "trigger.c"
    if not trigger_c.exists():
        return None
    try:
        result = subprocess.run(
            ["cc", "-c", "-fsyntax-only", str(trigger_c)],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None


def classify_uaf_pattern(manifest):
    """Classify the UAF pattern type from manifest metadata."""
    cwe_ids = set(manifest.get("cwe_ids", []))
    test_name = manifest.get("test_name", "").lower()
    desc = manifest.get("description", "").lower()

    patterns = []
    if "CWE-415" in cwe_ids or "double" in desc or "double_free" in test_name:
        patterns.append("double_free")
    if "CWE-416" in cwe_ids:
        patterns.append("use_after_free")
    if "type confusion" in desc or "type_confusion" in test_name:
        patterns.append("type_confusion")
    if "realloc" in desc or "realloc" in test_name:
        patterns.append("realloc_uaf")
    if "generation" in desc:
        patterns.append("generation_mismatch")

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    healing = set(tsm.get("healing_actions", []))
    if "IgnoreDoubleFree" in healing:
        if "double_free" not in patterns:
            patterns.append("double_free")
    if "IgnoreForeignFree" in healing:
        patterns.append("foreign_free")

    return patterns if patterns else ["use_after_free"]


def check_coverage_matrix(arena_root, uaf_tests):
    matrix_path = arena_root / "coverage_matrix.json"
    if not matrix_path.exists():
        return {"exists": False, "issues": ["coverage_matrix.json not found"]}

    matrix = load_json_file(matrix_path)
    features = matrix.get("features", {})

    matrix_cve_ids = set()
    for _feat, info in features.items():
        for cve in info.get("cves", []):
            matrix_cve_ids.add(cve.get("cve_id", ""))

    missing = []
    for test_info in uaf_tests:
        cve_id = test_info["manifest"].get("cve_id", "").split(" ")[0]
        original_cve = test_info["manifest"].get("original_cve", cve_id)
        if cve_id not in matrix_cve_ids and original_cve not in matrix_cve_ids:
            missing.append(cve_id)

    return {
        "exists": True,
        "total_cves_in_matrix": len(matrix_cve_ids),
        "uaf_cves_missing": missing,
    }


def main():
    parser = argparse.ArgumentParser(description="CVE UAF validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    arena_root = root / "tests" / "cve_arena"

    if not arena_root.exists():
        print("ERROR: tests/cve_arena/ not found", file=sys.stderr)
        sys.exit(1)

    uaf_tests = find_uaf_tests(arena_root)

    test_results = []
    total_issues = 0
    healing_actions_seen = set()
    all_patterns = set()

    for test_info in uaf_tests:
        manifest = test_info["manifest"]
        cve_id = manifest.get("cve_id", "unknown")
        test_name = manifest.get("test_name", "unknown")

        manifest_issues = validate_manifest(test_info)
        trigger_files = check_trigger_exists(test_info)
        compiles = check_c_trigger_compiles(test_info)
        patterns = classify_uaf_pattern(manifest)

        tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
        healing = tsm.get("healing_actions", [])
        healing_actions_seen.update(healing)
        all_patterns.update(patterns)

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
            "uaf_patterns": patterns,
            "manifest_valid": len(issues) == 0,
            "issues": issues,
        })

    matrix_check = check_coverage_matrix(arena_root, uaf_tests)

    total_tests = len(test_results)
    valid_manifests = sum(1 for t in test_results if t["manifest_valid"])
    with_triggers = sum(1 for t in test_results if t["trigger_files"])
    c_tests = [t for t in test_results if t["c_compiles"] is not None]
    c_compiles = sum(1 for t in c_tests if t["c_compiles"])

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.3",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_uaf_tests": total_tests,
            "manifests_valid": valid_manifests,
            "with_trigger_files": with_triggers,
            "c_triggers_compile": c_compiles,
            "c_triggers_total": len(c_tests),
            "unique_healing_actions": sorted(healing_actions_seen),
            "uaf_patterns_covered": sorted(all_patterns),
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
