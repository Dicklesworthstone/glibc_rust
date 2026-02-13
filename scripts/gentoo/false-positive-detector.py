#!/usr/bin/env python3
"""Heuristic false-positive detector for healing actions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def detect_false_positives(
    summary: Dict[str, Any],
    max_action_rate_per_1000: float,
    clamp_margin: float,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []

    by_package = summary.get("by_package", {})
    for package, pkg in by_package.items():
        rate = pkg.get("actions_per_1000_calls")
        if isinstance(rate, (int, float)) and rate > max_action_rate_per_1000:
            candidates.append(
                {
                    "kind": "high_action_rate",
                    "package": package,
                    "actions_per_1000_calls": rate,
                    "reason": f"action rate exceeds threshold {max_action_rate_per_1000}",
                }
            )

    for row in summary.get("top_call_sites", []):
        if row.get("healing_action") != "ClampSize":
            continue
        orig = row.get("original_size_avg")
        clamped = row.get("clamped_size_avg")
        if not isinstance(orig, (int, float)) or not isinstance(clamped, (int, float)):
            continue
        if orig <= clamped * (1.0 + clamp_margin):
            candidates.append(
                {
                    "kind": "possible_unnecessary_clamp",
                    "call_site": row.get("call_site"),
                    "frequency": row.get("frequency"),
                    "original_size_avg": orig,
                    "clamped_size_avg": clamped,
                    "reason": "original size near/equal clamped size",
                }
            )

    breakdown = summary.get("breakdown", {})
    total = max(1, int(summary.get("total_healing_actions", 0)))
    for action in ("TruncateWithNull", "IgnoreDoubleFree"):
        count = int(breakdown.get(action, 0))
        ratio = (count / total) * 100.0
        if ratio > 40.0:
            candidates.append(
                {
                    "kind": "dominant_action_ratio",
                    "action": action,
                    "ratio_percent": round(ratio, 2),
                    "reason": "single action dominates total healing; review for over-triggering",
                }
            )

    return candidates


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Detect potential false-positive healing patterns.")
    parser.add_argument("summary_json", help="JSON output from scripts/gentoo/analyze-healing.py")
    parser.add_argument("--output", help="Write false-positive candidates to file")
    parser.add_argument("--max-action-rate-per-1000", type=float, default=50.0)
    parser.add_argument("--clamp-margin", type=float, default=0.05, help="Fractional margin for clamp suspiciousness")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summary = json.loads(Path(args.summary_json).read_text(encoding="utf-8"))
    candidates = detect_false_positives(
        summary=summary,
        max_action_rate_per_1000=args.max_action_rate_per_1000,
        clamp_margin=args.clamp_margin,
    )
    payload = {
        "source": args.summary_json,
        "candidate_count": len(candidates),
        "candidates": candidates,
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
