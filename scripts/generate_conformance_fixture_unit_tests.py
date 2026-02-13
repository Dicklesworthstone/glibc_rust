#!/usr/bin/env python3
"""generate_conformance_fixture_unit_tests.py — bd-2hh.5

Conformance fixture verification and regression detection:
  1. Fixture loading — every fixture file can be parsed into FixtureSet.
  2. Format validation — all cases have required fields with valid values.
  3. Per-symbol regression — tracks case counts per symbol for regression.
  4. Deterministic output — fixture parsing is deterministic (same input = same output).
  5. Coverage baseline — captures current state for regression detection.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import sys
from collections import defaultdict
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


REQUIRED_TOP_LEVEL = ["version", "family", "cases"]
REQUIRED_CASE_FIELDS = ["name", "function", "inputs", "expected_output", "mode"]
VALID_MODES = {"strict", "hardened", "both"}


def compute_fixture_hash(data):
    """Compute deterministic hash of fixture content."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def validate_fixture(fixture_path):
    """Validate a fixture file thoroughly."""
    issues = []
    warnings = []

    try:
        data = load_json_file(fixture_path)
    except json.JSONDecodeError as e:
        return None, [f"JSON parse error: {e}"], []
    except OSError as e:
        return None, [f"File read error: {e}"], []

    # Top-level fields
    for field in REQUIRED_TOP_LEVEL:
        if field not in data:
            issues.append(f"Missing top-level field: {field}")

    version = data.get("version", "")
    if version != "v1":
        warnings.append(f"Unexpected version: {version}")

    family = data.get("family", "")
    if not family:
        issues.append("Empty family field")

    cases = data.get("cases", [])
    if not isinstance(cases, list):
        issues.append("'cases' is not an array")
        return data, issues, warnings

    if len(cases) == 0:
        warnings.append("Empty cases array")

    # Validate each case
    case_names = set()
    for i, case in enumerate(cases):
        prefix = f"Case {i}"
        if not isinstance(case, dict):
            issues.append(f"{prefix}: not an object")
            continue

        name = case.get("name", "")
        if name:
            prefix = f"Case '{name}'"
            if name in case_names:
                issues.append(f"{prefix}: duplicate case name")
            case_names.add(name)
        else:
            issues.append(f"{prefix}: missing name")

        for field in REQUIRED_CASE_FIELDS:
            if field not in case:
                issues.append(f"{prefix}: missing field '{field}'")

        mode = case.get("mode", "")
        if mode and mode not in VALID_MODES:
            issues.append(f"{prefix}: invalid mode '{mode}'")

        fn = case.get("function", "")
        if not fn:
            issues.append(f"{prefix}: empty function name")

        # Validate expected_output is present and non-null
        if "expected_output" in case and case["expected_output"] is None:
            warnings.append(f"{prefix}: expected_output is null")

    return data, issues, warnings


def build_regression_baseline(all_fixtures):
    """Build a regression baseline: per-symbol case counts and fixture hashes."""
    symbol_cases = defaultdict(lambda: {"count": 0, "fixtures": []})

    for finfo in all_fixtures:
        data = finfo.get("data")
        if not data:
            continue
        fixture_file = finfo["file"]
        for case in data.get("cases", []):
            fn = case.get("function", "")
            if fn:
                symbol_cases[fn]["count"] += 1
                if fixture_file not in symbol_cases[fn]["fixtures"]:
                    symbol_cases[fn]["fixtures"].append(fixture_file)

    return dict(symbol_cases)


def main():
    parser = argparse.ArgumentParser(
        description="Conformance fixture unit test validation")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fixtures_dir = root / "tests" / "conformance" / "fixtures"

    if not fixtures_dir.exists():
        print("ERROR: tests/conformance/fixtures/ not found", file=sys.stderr)
        sys.exit(1)

    fixture_files = sorted(fixtures_dir.glob("*.json"))

    all_fixtures = []
    total_issues = 0
    total_warnings = 0
    total_cases = 0
    all_hashes = {}

    for fp in fixture_files:
        data, issues, warnings = validate_fixture(fp)
        total_issues += len(issues)
        total_warnings += len(warnings)

        case_count = len(data.get("cases", [])) if data else 0
        total_cases += case_count

        fixture_hash = compute_fixture_hash(data) if data else None
        if fixture_hash:
            all_hashes[fp.name] = fixture_hash

        all_fixtures.append({
            "file": fp.name,
            "version": data.get("version", "") if data else "",
            "family": data.get("family", "") if data else "",
            "case_count": case_count,
            "fixture_hash": fixture_hash,
            "valid": len(issues) == 0,
            "issues": issues,
            "warnings": warnings,
            "data": data,
        })

    # Build regression baseline
    regression_baseline = build_regression_baseline(all_fixtures)

    # Check determinism: same file should hash the same
    determinism_ok = True
    for fp in fixture_files[:5]:
        data1 = load_json_file(fp)
        data2 = load_json_file(fp)
        if compute_fixture_hash(data1) != compute_fixture_hash(data2):
            determinism_ok = False
            break

    # Summary
    valid_files = sum(1 for f in all_fixtures if f["valid"])
    unique_families = len(set(f["family"] for f in all_fixtures if f["family"]))
    unique_symbols = len(regression_baseline)

    # Strip internal data field from output
    fixture_results = []
    for f in all_fixtures:
        fixture_results.append({
            "file": f["file"],
            "version": f["version"],
            "family": f["family"],
            "case_count": f["case_count"],
            "fixture_hash": f["fixture_hash"],
            "valid": f["valid"],
            "issues": f["issues"],
            "warnings": f["warnings"],
        })

    report = {
        "schema_version": "v1",
        "bead": "bd-2hh.5",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_fixture_files": len(fixture_files),
            "valid_fixture_files": valid_files,
            "total_cases": total_cases,
            "total_issues": total_issues,
            "total_warnings": total_warnings,
            "unique_families": unique_families,
            "unique_symbols": unique_symbols,
            "determinism_verified": determinism_ok,
        },
        "fixture_results": fixture_results,
        "regression_baseline": {
            "symbol_count": unique_symbols,
            "total_cases": total_cases,
            "symbols": {k: v for k, v in sorted(regression_baseline.items())},
        },
        "fixture_hashes": all_hashes,
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
