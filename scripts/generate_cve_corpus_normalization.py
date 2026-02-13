#!/usr/bin/env python3
"""generate_cve_corpus_normalization.py — bd-1m5.5

CVE corpus normalization and deterministic scenario metadata:
  1. Scans all CVE test directories for manifest.json files.
  2. Validates each manifest against the updated schema (field presence, types).
  3. Normalizes field names (run_cmd → run_cmd_stock/run_cmd_tsm, etc.).
  4. Classifies vulnerability class per CWE.
  5. Generates deterministic replay metadata (replay_key, preconditions).
  6. Builds a canonical corpus index with normalized entries.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# CWE → vulnerability class mapping
CWE_CLASSES = {
    "CWE-122": "heap_overflow",
    "CWE-787": "heap_overflow",
    "CWE-120": "buffer_overflow",
    "CWE-121": "stack_overflow",
    "CWE-131": "size_miscalculation",
    "CWE-190": "integer_overflow",
    "CWE-191": "integer_underflow",
    "CWE-680": "integer_to_buffer_overflow",
    "CWE-134": "format_string",
    "CWE-416": "use_after_free",
    "CWE-415": "double_free",
    "CWE-825": "expired_pointer",
    "CWE-476": "null_dereference",
    "CWE-908": "uninitialized_memory",
}

REQUIRED_FIELDS = ["cve_id", "test_name", "category", "description",
                   "build_cmd", "cwe_ids", "tsm_features_tested"]

# Category normalization: directory name → canonical category
CATEGORY_MAP = {
    "glibc": "glibc-internal",
    "glibc-internal": "glibc-internal",
    "targets": "external",
    "external": "external",
    "synthetic": "synthetic",
}


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def compute_replay_key(manifest, test_dir):
    """Compute a deterministic replay key from manifest content."""
    key_parts = [
        manifest.get("cve_id", ""),
        manifest.get("test_name", ""),
        manifest.get("build_cmd") or "",
        manifest.get("run_cmd") or manifest.get("run_cmd_stock", ""),
    ]
    raw = "|".join(key_parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def classify_vulnerability(manifest):
    """Classify vulnerability class from CWE IDs."""
    cwe_ids = manifest.get("cwe_ids", [])
    classes = set()
    for cwe in cwe_ids:
        if cwe in CWE_CLASSES:
            classes.add(CWE_CLASSES[cwe])
    return sorted(classes) if classes else ["unknown"]


def normalize_category(raw_category, dir_name):
    """Normalize category to canonical form."""
    if raw_category in CATEGORY_MAP:
        return CATEGORY_MAP[raw_category]
    if dir_name in CATEGORY_MAP:
        return CATEGORY_MAP[dir_name]
    return raw_category


def extract_base_cve_id(cve_id):
    """Extract base CVE ID, stripping '(synthetic)' suffix."""
    return re.sub(r"\s*\(synthetic\)$", "", cve_id).strip()


def normalize_manifest(manifest, dir_name):
    """Normalize a manifest to canonical field names."""
    normalized = {}

    # Copy base fields directly
    for field in ["cve_id", "test_name", "description", "build_cmd",
                  "cwe_ids", "tsm_features_tested", "cvss_score",
                  "references", "requires_root", "requires_network",
                  "min_glibc_version", "max_glibc_version",
                  "architecture", "timeout_seconds",
                  "software", "software_version", "ld_preload_mode",
                  "original_cve", "related_cves",
                  "attack_vectors", "packet_structure", "uaf_sequence"]:
        if field in manifest:
            normalized[field] = manifest[field]

    # Normalize category
    raw_cat = manifest.get("category", dir_name)
    normalized["category"] = normalize_category(raw_cat, dir_name)

    # Normalize run commands: run_cmd → run_cmd_stock + run_cmd_tsm
    if "run_cmd_stock" in manifest and "run_cmd_tsm" in manifest:
        normalized["run_cmd_stock"] = manifest["run_cmd_stock"]
        normalized["run_cmd_tsm"] = manifest["run_cmd_tsm"]
    elif "run_cmd" in manifest:
        normalized["run_cmd_stock"] = manifest["run_cmd"]
        normalized["run_cmd_tsm"] = manifest["run_cmd"]
    else:
        normalized["run_cmd_stock"] = None
        normalized["run_cmd_tsm"] = None

    # Normalize expected behavior: expected_stock → expected_stock_behavior
    stock = manifest.get("expected_stock_behavior") or manifest.get("expected_stock", {})
    normalized["expected_stock_behavior"] = stock

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    normalized["expected_tsm_behavior"] = tsm

    return normalized


def validate_manifest(manifest, test_dir):
    """Validate manifest fields and return issues list."""
    issues = []

    for field in REQUIRED_FIELDS:
        if field not in manifest:
            issues.append(f"Missing required field: {field}")

    cve_id = manifest.get("cve_id", "")
    if not re.match(r"^CVE-\d{4}-\d{4,}", cve_id):
        issues.append(f"Invalid cve_id format: {cve_id}")

    has_run = ("run_cmd" in manifest or
               ("run_cmd_stock" in manifest and "run_cmd_tsm" in manifest))
    if not has_run:
        issues.append("Missing run command (run_cmd or run_cmd_stock+run_cmd_tsm)")

    has_stock = ("expected_stock_behavior" in manifest or
                 "expected_stock" in manifest)
    has_tsm = ("expected_tsm_behavior" in manifest or
               "expected_tsm" in manifest)
    if not has_stock:
        issues.append("Missing expected stock behavior")
    if not has_tsm:
        issues.append("Missing expected TSM behavior")

    tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
    if "crashes" not in tsm:
        issues.append("Missing crashes field in TSM behavior")
    if "exit_code" not in tsm:
        issues.append("Missing exit_code field in TSM behavior")

    # Check trigger files exist
    trigger_found = False
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        if (test_dir / name).exists():
            trigger_found = True
            break
    if not trigger_found:
        issues.append("No trigger files found")

    return issues


def find_all_tests(arena_root):
    """Find all CVE test directories with manifest.json."""
    tests = []
    for dir_name in ["glibc", "synthetic", "targets"]:
        base = arena_root / dir_name
        if not base.exists():
            continue
        for test_dir in sorted(base.iterdir()):
            if not test_dir.is_dir():
                continue
            manifest_path = test_dir / "manifest.json"
            if not manifest_path.exists():
                continue
            manifest = load_json_file(manifest_path)
            tests.append({
                "dir": test_dir,
                "dir_name": dir_name,
                "manifest_path": manifest_path,
                "manifest": manifest,
            })
    return tests


def get_trigger_files(test_dir):
    """List trigger files in a test directory."""
    triggers = []
    for name in ["trigger.c", "trigger.sh", "trigger.pl", "trigger.py"]:
        if (test_dir / name).exists():
            triggers.append(name)
    return triggers


def build_replay_metadata(manifest, test_dir, normalized):
    """Build deterministic replay metadata for a CVE scenario."""
    replay_key = compute_replay_key(manifest, test_dir)
    stock_behavior = normalized.get("expected_stock_behavior", {})
    tsm_behavior = normalized.get("expected_tsm_behavior", {})

    preconditions = []
    if manifest.get("requires_root"):
        preconditions.append("root_privileges")
    if manifest.get("requires_network"):
        preconditions.append("network_access")
    if manifest.get("build_cmd"):
        preconditions.append("c_compiler")
    if manifest.get("software"):
        preconditions.append(f"software:{manifest['software']}")

    return {
        "replay_key": replay_key,
        "preconditions": preconditions,
        "expected_strict": {
            "crashes": stock_behavior.get("crashes", True),
            "signal": stock_behavior.get("signal"),
            "detection_expected": True,
        },
        "expected_hardened": {
            "crashes": tsm_behavior.get("crashes", False),
            "exit_code": tsm_behavior.get("exit_code", 0),
            "healing_actions": tsm_behavior.get("healing_actions", []),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="CVE corpus normalization + deterministic scenario metadata")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    arena_root = root / "tests" / "cve_arena"

    if not arena_root.exists():
        print("ERROR: tests/cve_arena/ not found", file=sys.stderr)
        sys.exit(1)

    all_tests = find_all_tests(arena_root)

    corpus_entries = []
    total_issues = 0
    normalization_changes = []
    vuln_classes = set()
    all_healing = set()
    cwe_set = set()

    for test_info in all_tests:
        manifest = test_info["manifest"]
        test_dir = test_info["dir"]
        dir_name = test_info["dir_name"]
        cve_id = manifest.get("cve_id", "unknown")
        test_name = manifest.get("test_name", "unknown")

        # Validate
        issues = validate_manifest(manifest, test_dir)
        total_issues += len(issues)

        # Normalize
        normalized = normalize_manifest(manifest, dir_name)

        # Track normalization changes
        changes = []
        if "run_cmd" in manifest and "run_cmd_stock" not in manifest:
            changes.append("run_cmd → run_cmd_stock/run_cmd_tsm")
        if "expected_stock" in manifest and "expected_stock_behavior" not in manifest:
            changes.append("expected_stock → expected_stock_behavior")
        if "expected_tsm" in manifest and "expected_tsm_behavior" not in manifest:
            changes.append("expected_tsm → expected_tsm_behavior")
        raw_cat = manifest.get("category", dir_name)
        canon_cat = normalize_category(raw_cat, dir_name)
        if raw_cat != canon_cat:
            changes.append(f"category: {raw_cat} → {canon_cat}")
        if changes:
            normalization_changes.append({
                "cve_id": cve_id,
                "changes": changes,
            })

        # Classify
        classes = classify_vulnerability(manifest)
        vuln_classes.update(classes)
        cwe_set.update(manifest.get("cwe_ids", []))

        # Healing actions
        tsm = manifest.get("expected_tsm_behavior") or manifest.get("expected_tsm", {})
        healing = tsm.get("healing_actions", [])
        all_healing.update(healing)

        # Replay metadata
        replay = build_replay_metadata(manifest, test_dir, normalized)

        # Triggers
        triggers = get_trigger_files(test_dir)

        base_cve = extract_base_cve_id(cve_id)

        corpus_entries.append({
            "cve_id": cve_id,
            "base_cve_id": base_cve,
            "test_name": test_name,
            "category_raw": manifest.get("category", dir_name),
            "category_canonical": canon_cat,
            "vulnerability_classes": classes,
            "cwe_ids": manifest.get("cwe_ids", []),
            "cvss_score": manifest.get("cvss_score"),
            "trigger_files": triggers,
            "healing_actions": healing,
            "tsm_features": manifest.get("tsm_features_tested", []),
            "manifest_valid": len(issues) == 0,
            "issues": issues,
            "normalization_changes": changes,
            "replay": replay,
            "manifest_path": str(test_info["manifest_path"].relative_to(root)),
        })

    # Build summary
    valid_count = sum(1 for e in corpus_entries if e["manifest_valid"])
    with_triggers = sum(1 for e in corpus_entries if e["trigger_files"])
    categories = {}
    for e in corpus_entries:
        cat = e["category_canonical"]
        categories[cat] = categories.get(cat, 0) + 1
    manifests_needing_normalization = sum(
        1 for e in corpus_entries if e["normalization_changes"])

    report = {
        "schema_version": "v1",
        "bead": "bd-1m5.5",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "total_cve_tests": len(corpus_entries),
            "manifests_valid": valid_count,
            "with_trigger_files": with_triggers,
            "total_issues": total_issues,
            "manifests_needing_normalization": manifests_needing_normalization,
            "unique_cwe_ids": sorted(cwe_set),
            "vulnerability_classes": sorted(vuln_classes),
            "unique_healing_actions": sorted(all_healing),
            "categories": categories,
        },
        "normalization_changes": normalization_changes,
        "corpus_index": corpus_entries,
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
