#!/usr/bin/env python3
"""Validate Gentoo exclusion policy artifact against the curated top100 list."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def read_top100(path: Path) -> set[str]:
    atoms = {line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()}
    if len(atoms) != 100:
        raise ValueError(f"top100 package set must have 100 entries, found {len(atoms)}")
    return atoms


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    root = repo_root()
    parser = argparse.ArgumentParser(description="Validate Gentoo exclusions JSON.")
    parser.add_argument(
        "--top100",
        type=Path,
        default=root / "configs/gentoo/top100-packages.txt",
        help="Path to top100 package list",
    )
    parser.add_argument(
        "--exclusions",
        type=Path,
        default=root / "configs/gentoo/exclusions.json",
        help="Path to exclusions JSON",
    )
    args = parser.parse_args()

    top100 = read_top100(args.top100)
    doc = load_json(args.exclusions)

    failures: list[str] = []

    if doc.get("schema_version") != "v1":
        failures.append(f"schema_version must be 'v1', got {doc.get('schema_version')!r}")
    if doc.get("bead") != "bd-2icq.15":
        failures.append(f"bead must be 'bd-2icq.15', got {doc.get('bead')!r}")

    policy = doc.get("policy", {})
    max_rate = float(policy.get("max_exclusion_rate_percent", 10.0))
    required_fields = policy.get("required_fields", [])
    allowed_types = set(policy.get("allowed_types", []))

    exclusions = doc.get("exclusions", [])
    if not isinstance(exclusions, list):
        failures.append("exclusions must be an array")
        exclusions = []

    seen: set[str] = set()
    type_counter: Counter[str] = Counter()

    for row in exclusions:
        pkg = row.get("package")
        if not isinstance(pkg, str) or "/" not in pkg:
            failures.append(f"invalid package atom in exclusion row: {row!r}")
            continue
        if pkg in seen:
            failures.append(f"duplicate exclusion package: {pkg}")
        seen.add(pkg)

        for field in required_fields:
            if field not in row:
                failures.append(f"{pkg}: missing required field '{field}'")

        row_type = row.get("type")
        if row_type not in allowed_types:
            failures.append(f"{pkg}: invalid type '{row_type}'")
        else:
            type_counter[row_type] += 1

        if pkg not in top100:
            failures.append(f"{pkg}: not present in top100 package set")

    total = len(top100)
    excluded = len(exclusions)
    rate = round((excluded / total) * 100.0, 2)
    if rate > max_rate:
        failures.append(
            f"exclusion rate {rate}% exceeds max_exclusion_rate_percent {max_rate}%"
        )

    stats = doc.get("statistics", {})
    expected_by_type = {k: type_counter.get(k, 0) for k in allowed_types}
    checks = {
        "top100_total": total,
        "excluded_total": excluded,
        "exclusion_rate_percent": rate,
    }
    for key, expected in checks.items():
        if stats.get(key) != expected:
            failures.append(f"statistics.{key} mismatch: claimed={stats.get(key)!r} actual={expected!r}")

    claimed_by_type = stats.get("by_type", {})
    if claimed_by_type != expected_by_type:
        failures.append(
            "statistics.by_type mismatch: "
            f"claimed={claimed_by_type!r} actual={expected_by_type!r}"
        )

    if failures:
        print("FAIL: exclusion policy validation failed:")
        for msg in failures:
            print(f"  - {msg}")
        return 1

    print(
        "PASS: exclusions validated "
        f"(excluded={excluded}/{total}, rate={rate}%, types={dict(type_counter)})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
