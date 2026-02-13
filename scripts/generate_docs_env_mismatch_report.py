#!/usr/bin/env python3
"""Generate docs env inventory and docs<->code mismatch classification."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

KEY_RE = re.compile(r"\b(FRANKENLIBC_[A-Z0-9_]+)\b")

DOC_FILES = (
    "README.md",
    "AGENTS.md",
    "FEATURE_PARITY.md",
    "PLAN_TO_PORT_GLIBC_TO_RUST.md",
    "PROPOSED_ARCHITECTURE.md",
    "EXISTING_GLIBC_STRUCTURE.md",
)


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def collect_docs_mentions(root: Path) -> dict[str, list[dict[str, Any]]]:
    findings: dict[str, list[dict[str, Any]]] = {}
    for rel in DOC_FILES:
        path = root / rel
        if not path.exists():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            keys = sorted(set(KEY_RE.findall(line)))
            if not keys:
                continue
            snippet = line.strip()
            for key in keys:
                findings.setdefault(key, []).append(
                    {"path": rel, "line": idx, "snippet": snippet}
                )
    return findings


def build_docs_inventory(mentions: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    keys: list[dict[str, Any]] = []
    total_mentions = 0
    for key in sorted(mentions):
        rows = sorted(mentions[key], key=lambda row: (row["path"], row["line"]))
        total_mentions += len(rows)
        keys.append(
            {
                "env_key": key,
                "mention_count": len(rows),
                "mentions": rows,
            }
        )

    return {
        "schema_version": "v1",
        "generator": "scripts/generate_docs_env_mismatch_report.py",
        "docs_files": [rel for rel in DOC_FILES],
        "keys": keys,
        "summary": {
            "total_keys": len(keys),
            "total_mentions": total_mentions,
        },
    }


def load_code_inventory(path: Path) -> tuple[set[str], dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    keys = {
        row["env_key"]
        for row in payload.get("inventory", [])
        if isinstance(row, dict) and "env_key" in row
    }
    return keys, payload


def classify_mismatches(
    docs_mentions: dict[str, list[dict[str, Any]]],
    docs_inventory_path: str,
    code_inventory_path: str,
    code_keys: set[str],
) -> dict[str, Any]:
    docs_keys = set(docs_mentions.keys())

    missing_in_docs = sorted(code_keys - docs_keys)
    missing_in_code = sorted(docs_keys - code_keys)
    semantic_drift: list[dict[str, Any]] = []

    mode_mentions = docs_mentions.get("FRANKENLIBC_MODE", [])
    if mode_mentions and not any(
        "strict|hardened" in row["snippet"] or "strict" in row["snippet"]
        for row in mode_mentions
    ):
        semantic_drift.append(
            {
                "env_key": "FRANKENLIBC_MODE",
                "mismatch_class": "semantic_drift",
                "evidence": mode_mentions,
                "details": "docs mention FRANKENLIBC_MODE but strict/hardened contract phrasing was not found",
                "remediation_action": "clarify_strict_hardened_contract_in_docs",
            }
        )

    classifications: list[dict[str, Any]] = []

    for key in missing_in_docs:
        classifications.append(
            {
                "env_key": key,
                "mismatch_class": "missing_in_docs",
                "evidence": [{"path": code_inventory_path, "source": "code_inventory"}],
                "details": "key appears in code inventory but not in selected docs",
                "remediation_action": "document_knob_or_mark_internal_only",
            }
        )

    for key in missing_in_code:
        classifications.append(
            {
                "env_key": key,
                "mismatch_class": "missing_in_code",
                "evidence": docs_mentions.get(key, []),
                "details": "key appears in docs but no code inventory entry exists",
                "remediation_action": "implement_knob_or_mark_deprecated_in_docs",
            }
        )

    classifications.extend(semantic_drift)
    classifications = sorted(
        classifications, key=lambda row: (row["mismatch_class"], row["env_key"])
    )

    unresolved = [
        row
        for row in classifications
        if not row.get("remediation_action")
        or row.get("remediation_action") == "unknown"
    ]

    summary = {
        "docs_keys": len(docs_keys),
        "code_keys": len(code_keys),
        "missing_in_docs_count": len(missing_in_docs),
        "missing_in_code_count": len(missing_in_code),
        "semantic_drift_count": len(semantic_drift),
        "total_classifications": len(classifications),
        "unresolved_ambiguous_count": len(unresolved),
    }

    return {
        "schema_version": "v1",
        "generator": "scripts/generate_docs_env_mismatch_report.py",
        "docs_inventory_path": docs_inventory_path,
        "code_inventory_path": code_inventory_path,
        "classifications": classifications,
        "summary": summary,
        "unresolved_ambiguous": unresolved,
    }


def compare_or_write(path: Path, rendered: str, check: bool) -> int:
    if check:
        if not path.exists():
            print(f"FAIL: missing file: {path}", file=sys.stderr)
            return 1
        current = path.read_text(encoding="utf-8")
        if current != rendered:
            print(f"FAIL: drift detected for {path}", file=sys.stderr)
            return 1
        return 0

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(rendered, encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate docs env inventory and mismatch classifications."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Workspace root",
    )
    parser.add_argument(
        "--code-inventory",
        type=Path,
        default=Path("tests/conformance/runtime_env_inventory.v1.json"),
        help="Code inventory JSON path relative to --root",
    )
    parser.add_argument(
        "--docs-output",
        type=Path,
        default=Path("tests/conformance/docs_env_inventory.v1.json"),
        help="Docs inventory output path relative to --root",
    )
    parser.add_argument(
        "--report-output",
        type=Path,
        default=Path("tests/conformance/env_docs_code_mismatch_report.v1.json"),
        help="Mismatch report output path relative to --root",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when checked files differ from generated output",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    code_inventory_path = (root / args.code_inventory).resolve()
    docs_output = (root / args.docs_output).resolve()
    report_output = (root / args.report_output).resolve()

    if not code_inventory_path.exists():
        print(f"FAIL: missing code inventory file: {code_inventory_path}", file=sys.stderr)
        return 1

    docs_mentions = collect_docs_mentions(root)
    docs_inventory = build_docs_inventory(docs_mentions)
    code_keys, _ = load_code_inventory(code_inventory_path)
    report = classify_mismatches(
        docs_mentions=docs_mentions,
        docs_inventory_path=args.docs_output.as_posix(),
        code_inventory_path=args.code_inventory.as_posix(),
        code_keys=code_keys,
    )

    rc = 0
    rc |= compare_or_write(docs_output, canonical_json(docs_inventory), args.check)
    rc |= compare_or_write(report_output, canonical_json(report), args.check)
    if rc != 0:
        return 1

    if args.check:
        print(
            "PASS: docs env inventory + mismatch report are up-to-date "
            f"(classifications={report['summary']['total_classifications']})"
        )
    else:
        print(
            "Wrote docs env artifacts: "
            f"{docs_output.relative_to(root)} and {report_output.relative_to(root)}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
