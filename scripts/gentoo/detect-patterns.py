#!/usr/bin/env python3
"""Detect high-level healing patterns from analyzed healing summaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


PATTERN_MAP = {
    "ClampSize": {
        "pattern": "oversized allocation requests",
        "potential_cve_prevention": True,
    },
    "TruncateWithNull": {
        "pattern": "unterminated string boundary handling",
        "potential_cve_prevention": True,
    },
    "IgnoreDoubleFree": {
        "pattern": "double free cleanup/retry patterns",
        "potential_cve_prevention": True,
    },
    "IgnoreForeignFree": {
        "pattern": "foreign allocator ownership mismatches",
        "potential_cve_prevention": True,
    },
    "ReallocAsMalloc": {
        "pattern": "realloc(NULL, n) legacy compatibility flows",
        "potential_cve_prevention": False,
    },
    "ReturnSafeDefault": {
        "pattern": "error fallback and sentinel returns",
        "potential_cve_prevention": False,
    },
    "UpgradeToSafeVariant": {
        "pattern": "unsafe call-site upgraded to safer API variant",
        "potential_cve_prevention": True,
    },
}


def detect_patterns(summary: Dict[str, Any], top_n: int = 20) -> List[Dict[str, Any]]:
    breakdown = summary.get("breakdown", {})
    by_package = summary.get("by_package", {})
    patterns: List[Dict[str, Any]] = []

    for action, total in sorted(breakdown.items(), key=lambda kv: kv[1], reverse=True)[:top_n]:
        meta = PATTERN_MAP.get(action, {"pattern": "unclassified healing behavior", "potential_cve_prevention": False})
        packages = [pkg for pkg, pkg_data in by_package.items() if action in pkg_data.get("breakdown", {})]
        patterns.append(
            {
                "healing_action": action,
                "pattern": meta["pattern"],
                "total_occurrences": total,
                "packages_affected": sorted(packages),
                "potential_cve_prevention": bool(meta["potential_cve_prevention"]),
            }
        )

    return patterns


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect healing patterns from analyze-healing output.")
    parser.add_argument("summary_json", help="JSON output from scripts/gentoo/analyze-healing.py")
    parser.add_argument("--output", help="Write patterns JSON to file")
    parser.add_argument("--top", type=int, default=20, help="Top-N actions to classify")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    patterns = detect_patterns(summary, top_n=args.top)
    payload = {
        "source": args.summary_json,
        "pattern_count": len(patterns),
        "patterns": patterns,
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
