#!/usr/bin/env python3
"""generate_cve_hardened_assertions.py — bd-1m5.6

Hardened CVE prevention/healing assertion suite:
  1. Hardened assertion matrix — per-CVE expected hardened-mode behavior.
  2. Healing action expectation map — which healing actions each CVE requires.
  3. Regression checker — validates that no CVE triggers crash in hardened mode.
  4. Prevention strategy classification — prevent, quarantine, safe-default, deny.

Uses the corpus normalization index (bd-1m5.5) as input.
Generates a JSON report to stdout (or --output).
"""
import argparse
import json
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


# Healing action → prevention strategy mapping
HEALING_STRATEGY = {
    "ClampSize": "prevent",
    "TruncateWithNull": "prevent",
    "IgnoreDoubleFree": "quarantine",
    "IgnoreForeignFree": "quarantine",
    "ReallocAsMalloc": "safe-default",
    "ReturnSafeDefault": "safe-default",
    "UpgradeToSafeVariant": "prevent",
    "FreedWithCanaryCorruption": "deny",
}

# CWE → expected prevention behavior
CWE_PREVENTION = {
    "CWE-122": {"strategy": "prevent", "description": "Heap overflow clamped/bounded"},
    "CWE-787": {"strategy": "prevent", "description": "Out-of-bounds write prevented"},
    "CWE-120": {"strategy": "prevent", "description": "Buffer overflow bounded"},
    "CWE-121": {"strategy": "prevent", "description": "Stack overflow detected"},
    "CWE-131": {"strategy": "prevent", "description": "Size miscalculation clamped"},
    "CWE-190": {"strategy": "prevent", "description": "Integer overflow clamped"},
    "CWE-191": {"strategy": "prevent", "description": "Integer underflow clamped"},
    "CWE-680": {"strategy": "prevent", "description": "Integer-to-buffer overflow prevented"},
    "CWE-134": {"strategy": "prevent", "description": "Format string upgraded to safe variant"},
    "CWE-416": {"strategy": "quarantine", "description": "Use-after-free detected via generation check"},
    "CWE-415": {"strategy": "quarantine", "description": "Double-free silently ignored"},
    "CWE-825": {"strategy": "quarantine", "description": "Expired pointer detected"},
    "CWE-476": {"strategy": "safe-default", "description": "Null dereference returns safe default"},
    "CWE-908": {"strategy": "safe-default", "description": "Uninitialized memory zeroed"},
}


def classify_prevention_strategy(healing_actions):
    """Classify the overall prevention strategy from healing actions."""
    strategies = set()
    for action in healing_actions:
        if action in HEALING_STRATEGY:
            strategies.add(HEALING_STRATEGY[action])
    if not strategies:
        return "unknown"
    # Priority: deny > prevent > quarantine > safe-default
    for s in ["deny", "prevent", "quarantine", "safe-default"]:
        if s in strategies:
            return s
    return "unknown"


def build_assertion(entry):
    """Build a hardened-mode assertion for a single CVE corpus entry."""
    replay = entry.get("replay", {})
    hardened = replay.get("expected_hardened", {})
    healing_actions = hardened.get("healing_actions", [])
    cwe_ids = entry.get("cwe_ids", [])

    # Determine prevention strategy
    strategy = classify_prevention_strategy(healing_actions)

    # Build CWE-specific prevention expectations
    cwe_expectations = []
    for cwe in cwe_ids:
        if cwe in CWE_PREVENTION:
            cwe_expectations.append({
                "cwe_id": cwe,
                "strategy": CWE_PREVENTION[cwe]["strategy"],
                "description": CWE_PREVENTION[cwe]["description"],
            })
        else:
            cwe_expectations.append({
                "cwe_id": cwe,
                "strategy": "unknown",
                "description": f"No prevention expectation defined for {cwe}",
            })

    # Determine if this CVE should be fully prevented
    crashes_hardened = hardened.get("crashes", False)
    exit_code = hardened.get("exit_code", 0)

    assertion = {
        "cve_id": entry["cve_id"],
        "test_name": entry["test_name"],
        "cvss_score": entry.get("cvss_score"),
        "vulnerability_classes": entry.get("vulnerability_classes", []),
        "prevention_strategy": strategy,
        "hardened_expectations": {
            "crashes": crashes_hardened,
            "exit_code": exit_code,
            "healing_actions_required": healing_actions,
            "no_uncontrolled_unsafety": not crashes_hardened,
        },
        "cwe_prevention": cwe_expectations,
        "regression_checks": {
            "no_crash": not crashes_hardened,
            "expected_exit_code": exit_code,
            "healing_actions_emitted": len(healing_actions) > 0,
            "healing_actions_list": healing_actions,
        },
    }

    return assertion


def build_healing_expectation_map(assertions):
    """Build a map: healing_action → list of CVEs that require it."""
    healing_map = {}
    for a in assertions:
        for action in a["hardened_expectations"]["healing_actions_required"]:
            if action not in healing_map:
                healing_map[action] = {
                    "strategy": HEALING_STRATEGY.get(action, "unknown"),
                    "cve_ids": [],
                    "count": 0,
                }
            healing_map[action]["cve_ids"].append(a["cve_id"])
            healing_map[action]["count"] += 1
    return healing_map


def validate_assertions(assertions):
    """Validate the assertion suite for completeness and consistency."""
    issues = []

    for a in assertions:
        cve_id = a["cve_id"]

        # Every CVE must not crash in hardened mode
        if a["hardened_expectations"]["crashes"]:
            issues.append({
                "cve_id": cve_id,
                "issue": "CVE expected to crash in hardened mode",
                "severity": "error",
            })

        # Every CVE must have at least one healing action
        if not a["hardened_expectations"]["healing_actions_required"]:
            issues.append({
                "cve_id": cve_id,
                "issue": "No healing actions required",
                "severity": "warning",
            })

        # Prevention strategy must not be unknown
        if a["prevention_strategy"] == "unknown":
            issues.append({
                "cve_id": cve_id,
                "issue": "Unknown prevention strategy",
                "severity": "warning",
            })

    return issues


def main():
    parser = argparse.ArgumentParser(
        description="CVE hardened assertion suite generator")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    corpus_path = root / "tests" / "cve_arena" / "results" / "corpus_normalization.v1.json"

    if not corpus_path.exists():
        print("ERROR: corpus_normalization.v1.json not found. Run bd-1m5.5 first.",
              file=sys.stderr)
        sys.exit(1)

    corpus = load_json_file(corpus_path)
    entries = corpus.get("corpus_index", [])

    assertions = []
    for entry in entries:
        assertions.append(build_assertion(entry))

    healing_map = build_healing_expectation_map(assertions)
    validation_issues = validate_assertions(assertions)

    # Summary statistics
    no_crash_count = sum(1 for a in assertions
                        if not a["hardened_expectations"]["crashes"])
    with_healing = sum(1 for a in assertions
                       if a["hardened_expectations"]["healing_actions_required"])
    strategies = {}
    for a in assertions:
        s = a["prevention_strategy"]
        strategies[s] = strategies.get(s, 0) + 1

    error_count = sum(1 for i in validation_issues if i["severity"] == "error")
    warning_count = sum(1 for i in validation_issues if i["severity"] == "warning")

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.6",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_assertions": len(assertions),
            "no_crash_in_hardened": no_crash_count,
            "with_healing_actions": with_healing,
            "prevention_strategies": strategies,
            "unique_healing_actions": sorted(healing_map.keys()),
            "validation_errors": error_count,
            "validation_warnings": warning_count,
        },
        "assertion_matrix": assertions,
        "healing_expectation_map": healing_map,
        "validation_issues": validation_issues,
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
