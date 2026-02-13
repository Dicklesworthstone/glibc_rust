#!/usr/bin/env python3
"""Analyze FrankenLibC healing-action logs."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple


def iter_log_lines(path: Path) -> Iterable[Tuple[Path, str]]:
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            yield path, line
        return
    for file_path in sorted(path.rglob("*.jsonl")):
        for line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
            yield file_path, line


def analyze(path: Path, top_n: int = 20) -> Dict[str, Any]:
    action_counts: Counter[str] = Counter()
    package_counts: Dict[str, Counter[str]] = defaultdict(Counter)
    package_call_counts: Counter[str] = Counter()
    call_site_counts: Counter[Tuple[str, str]] = Counter()
    call_site_size_sums: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(lambda: {"original": 0.0, "clamped": 0.0, "n": 0.0})

    parse_errors = 0
    total_entries = 0
    total_actions = 0

    for _, line in iter_log_lines(path):
        line = line.strip()
        if not line:
            continue
        total_entries += 1
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            parse_errors += 1
            continue

        package = str(payload.get("package") or payload.get("atom") or "unknown")
        call = str(payload.get("call") or payload.get("event") or "unknown")
        package_call_counts[package] += 1 if call else 0

        action = payload.get("action")
        if not action:
            continue
        action = str(action)
        total_actions += 1
        action_counts[action] += 1
        package_counts[package][action] += 1

        call_site = str(payload.get("call_site") or payload.get("function") or call)
        key = (call_site, action)
        call_site_counts[key] += 1

        details = payload.get("action_details") if isinstance(payload.get("action_details"), dict) else {}
        if isinstance(details, dict):
            original = details.get("original_size")
            clamped = details.get("clamped_size")
            if isinstance(original, (int, float)):
                call_site_size_sums[key]["original"] += float(original)
            if isinstance(clamped, (int, float)):
                call_site_size_sums[key]["clamped"] += float(clamped)
            call_site_size_sums[key]["n"] += 1.0

    by_package = {}
    for package, breakdown in sorted(package_counts.items()):
        calls = package_call_counts.get(package, 0)
        total = sum(breakdown.values())
        by_package[package] = {
            "total_healing_actions": total,
            "actions_per_1000_calls": round((total / calls) * 1000.0, 2) if calls else None,
            "breakdown": dict(breakdown),
        }

    top_call_sites = []
    for (call_site, action), frequency in call_site_counts.most_common(top_n):
        sums = call_site_size_sums[(call_site, action)]
        n = sums["n"] or 0.0
        top_call_sites.append(
            {
                "call_site": call_site,
                "healing_action": action,
                "frequency": frequency,
                "original_size_avg": round(sums["original"] / n, 2) if n else None,
                "clamped_size_avg": round(sums["clamped"] / n, 2) if n else None,
            }
        )

    return {
        "source": str(path),
        "total_entries": total_entries,
        "total_healing_actions": total_actions,
        "actions_per_1000_calls": round((total_actions / sum(package_call_counts.values())) * 1000.0, 2)
        if sum(package_call_counts.values())
        else None,
        "breakdown": dict(action_counts),
        "by_package": by_package,
        "top_call_sites": top_call_sites,
        "parse_errors": parse_errors,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze healing action JSONL logs.")
    parser.add_argument("source", help="Path to .jsonl file or root directory")
    parser.add_argument("--output", help="Write summary JSON to this file")
    parser.add_argument("--top", type=int, default=20, help="Top call-site/action rows")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = Path(args.source)
    if not source.exists():
        raise SystemExit(f"missing source path: {source}")

    summary = analyze(source, top_n=args.top)
    rendered = json.dumps(summary, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
