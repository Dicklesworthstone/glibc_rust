#!/usr/bin/env python3
"""Detect statically linked ELF binaries in a target directory tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any


def inspect_file(path: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["file", "-b", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    desc = proc.stdout.strip() if proc.stdout else ""
    is_elf = "ELF" in desc
    is_static = is_elf and "statically linked" in desc
    is_dynamic = is_elf and "dynamically linked" in desc
    return {
        "path": str(path),
        "description": desc,
        "is_elf": is_elf,
        "is_static": is_static,
        "is_dynamic": is_dynamic,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect static ELF binaries under a path.")
    parser.add_argument("--root", type=Path, required=True, help="Root directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON report")
    parser.add_argument(
        "--max-files",
        type=int,
        default=10000,
        help="Safety cap on scanned files (default: 10000)",
    )
    args = parser.parse_args()

    if not args.root.exists():
        raise SystemExit(f"root does not exist: {args.root}")

    scanned = 0
    findings: list[dict[str, Any]] = []
    static_hits: list[dict[str, Any]] = []

    for base, _, files in os.walk(args.root):
        for filename in files:
            path = Path(base) / filename
            scanned += 1
            if scanned > args.max_files:
                break
            try:
                if not path.is_file():
                    continue
                # skip obvious text/config files quickly
                if path.suffix in {".json", ".md", ".txt", ".toml", ".yaml", ".yml", ".sh", ".py", ".rs"}:
                    continue
                row = inspect_file(path)
                if row["is_elf"]:
                    findings.append(row)
                    if row["is_static"]:
                        static_hits.append(row)
            except Exception:
                continue
        if scanned > args.max_files:
            break

    report = {
        "root": str(args.root),
        "scanned_files": scanned,
        "elf_count": len(findings),
        "static_elf_count": len(static_hits),
        "static_elf_paths": [r["path"] for r in static_hits],
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"Scanned={report['scanned_files']} ELF={report['elf_count']} "
            f"static={report['static_elf_count']}"
        )
        for p in report["static_elf_paths"]:
            print(f"STATIC: {p}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
