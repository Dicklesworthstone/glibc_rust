#!/usr/bin/env python3
"""Compare baseline and instrumented Gentoo test results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List


def compare_results(baseline: Dict[str, Any], instrumented: Dict[str, Any]) -> Dict[str, Any]:
    base_failed = set(baseline.get("failed_tests", []))
    inst_failed = set(instrumented.get("failed_tests", []))

    new_failures = sorted(inst_failed - base_failed)
    new_passes = sorted(base_failed - inst_failed)

    base_duration = float(baseline.get("duration_seconds", 0.0))
    inst_duration = float(instrumented.get("duration_seconds", 0.0))
    overhead = 0.0
    if base_duration > 0.0:
        overhead = ((inst_duration - base_duration) / base_duration) * 100.0

    verdict = "PASS"
    if new_failures:
        verdict = "REGRESSION"
    elif new_passes:
        verdict = "IMPROVEMENT"
    elif base_failed == inst_failed:
        verdict = "NEUTRAL"

    return {
        "new_failures": new_failures,
        "new_passes": new_passes,
        "overhead_percent": round(overhead, 2),
        "verdict": verdict,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Gentoo baseline vs instrumented test result JSON files.")
    parser.add_argument("baseline", help="Baseline result JSON file")
    parser.add_argument("instrumented", help="Instrumented result JSON file")
    parser.add_argument("--output", help="Write comparison JSON to this path")
    parser.add_argument("--fail-on-regression", action="store_true", help="Exit with code 1 on regression verdict")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    instrumented = json.loads(Path(args.instrumented).read_text(encoding="utf-8"))
    comparison = compare_results(baseline, instrumented)

    rendered = json.dumps(comparison, indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")

    print(rendered)
    if args.fail_on_regression and comparison["verdict"] == "REGRESSION":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
