#!/usr/bin/env python3
"""Summarize FrankenLibC Portage JSONL logs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable


def _record_from_line(line: str) -> Dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None

    if line.startswith("{"):
        try:
            payload = json.loads(line)
            if isinstance(payload, dict):
                return payload
        except json.JSONDecodeError:
            return None

    # Backward-compatible fallback for old text hook logs:
    # "timestamp atom=x phase=y msg=z".
    record: Dict[str, Any] = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        record[key] = value
    if record:
        if "atom" in record:
            record.setdefault("atom", record["atom"])
        if "phase" in record:
            record.setdefault("phase", record["phase"])
        if "msg" in record:
            record.setdefault("message", record["msg"])
            record.setdefault("event", "legacy")
        return record
    return None


def _iter_log_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in {".jsonl", ".log"}:
            yield path


def analyze(root: Path, top_n: int) -> Dict[str, Any]:
    event_counts: Counter[str] = Counter()
    phase_counts: Counter[str] = Counter()
    atom_counts: Counter[str] = Counter()
    call_counts: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()

    files_scanned = 0
    lines_total = 0
    records_total = 0
    parse_errors = 0
    latency_values: list[int] = []

    for log_file in _iter_log_files(root):
        files_scanned += 1
        with log_file.open("r", encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                lines_total += 1
                record = _record_from_line(raw_line)
                if record is None:
                    parse_errors += 1
                    continue
                records_total += 1

                event = str(record.get("event", "unknown"))
                phase = str(record.get("phase", "unknown"))
                atom = str(record.get("atom") or record.get("package") or "unknown")
                call = str(record.get("call", "unknown"))
                action = str(record.get("action", "unknown"))

                event_counts[event] += 1
                phase_counts[phase] += 1
                atom_counts[atom] += 1
                call_counts[call] += 1
                action_counts[action] += 1

                latency = record.get("latency_ns")
                if isinstance(latency, int):
                    latency_values.append(latency)

    latency_summary: Dict[str, Any]
    if latency_values:
        latency_summary = {
            "count": len(latency_values),
            "min": min(latency_values),
            "max": max(latency_values),
            "avg": int(sum(latency_values) / len(latency_values)),
        }
    else:
        latency_summary = {"count": 0}

    return {
        "root": str(root),
        "files_scanned": files_scanned,
        "lines_total": lines_total,
        "records_total": records_total,
        "parse_errors": parse_errors,
        "events": dict(event_counts),
        "phases": dict(phase_counts),
        "top_atoms": atom_counts.most_common(top_n),
        "top_calls": call_counts.most_common(top_n),
        "top_actions": action_counts.most_common(top_n),
        "latency_ns": latency_summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze FrankenLibC Portage log trees.")
    parser.add_argument("root", nargs="?", default="/var/log/frankenlibc", help="Log root directory")
    parser.add_argument("--output", help="Write JSON summary to file")
    parser.add_argument("--top", type=int, default=10, help="Top-N list size")
    parser.add_argument("--json-only", action="store_true", help="Print only JSON summary")
    args = parser.parse_args()

    root = Path(args.root)
    if not root.exists():
        raise SystemExit(f"Log root does not exist: {root}")

    summary = analyze(root, args.top)
    payload = json.dumps(summary, indent=2, sort_keys=True)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload + "\n", encoding="utf-8")

    if args.json_only:
        print(payload)
    else:
        print(f"root={summary['root']}")
        print(f"files_scanned={summary['files_scanned']}")
        print(f"records_total={summary['records_total']}")
        print(f"parse_errors={summary['parse_errors']}")
        print(payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
