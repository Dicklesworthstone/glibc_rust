#!/usr/bin/env python3
"""
Ingest measured latency samples into symbol latency baseline artifact (bd-3h1u.1).

This script applies deterministic benchmark-log observations (mapped by
`tests/conformance/symbol_latency_capture_map.v1.json`) onto
`tests/conformance/symbol_latency_baseline.v1.json`.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import defaultdict
from typing import Any

MODES = ("raw", "strict", "hardened")
PERCENTILES = ("p50", "p95", "p99")
TRACE_ID = "bd-3h1u.1-symbol-latency-ingest-v1"


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _parse_kv_line(line: str) -> tuple[str, dict[str, str]] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    tokens = line.split()
    if not tokens:
        return None

    prefix = tokens[0]
    kv: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        if key:
            kv[key] = value

    return prefix, kv


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_mode_row(mode_row: dict[str, Any]) -> None:
    measured = [mode_row.get("p50_ns"), mode_row.get("p95_ns"), mode_row.get("p99_ns")]
    present = [v is not None for v in measured]

    if all(present):
        mode_row["capture_state"] = "measured"
    elif any(present):
        mode_row["capture_state"] = "partial"
    else:
        mode_row["capture_state"] = "pending_symbol_benchmark"
        mode_row["source"] = None


def _recompute_summary(doc: dict[str, Any]) -> None:
    symbols = doc.get("symbols", [])
    total = len(symbols)

    target_statuses = doc.get("summary", {}).get("target_statuses")
    if not isinstance(target_statuses, list) or not all(
        isinstance(item, str) for item in target_statuses
    ):
        target_statuses = ["GlibcCallThrough", "Implemented", "RawSyscall"]

    target_set = set(target_statuses)

    fixture_covered = sum(1 for row in symbols if bool(row.get("fixture_covered", False)))
    strict_hotpath = sum(1 for row in symbols if row.get("perf_class") == "strict_hotpath")
    target_symbols = sum(1 for row in symbols if str(row.get("status")) in target_set)

    measured_counts: dict[str, dict[str, int]] = {
        mode: {pct: 0 for pct in PERCENTILES} for mode in MODES
    }

    for row in symbols:
        baseline = row.get("baseline", {})
        if not isinstance(baseline, dict):
            continue
        for mode in MODES:
            mode_row = baseline.get(mode, {})
            if not isinstance(mode_row, dict):
                continue
            if mode_row.get("p50_ns") is not None:
                measured_counts[mode]["p50"] += 1
            if mode_row.get("p95_ns") is not None:
                measured_counts[mode]["p95"] += 1
            if mode_row.get("p99_ns") is not None:
                measured_counts[mode]["p99"] += 1

    pending_counts: dict[str, dict[str, int]] = {
        mode: {
            pct: total - measured_counts[mode][pct] for pct in PERCENTILES
        }
        for mode in MODES
    }

    summary = doc.setdefault("summary", {})
    summary["total_symbols"] = total
    summary["target_statuses"] = sorted(target_set)
    summary["target_symbols"] = target_symbols
    summary["fixture_covered_symbols"] = fixture_covered
    summary["fixture_uncovered_symbols"] = total - fixture_covered
    summary["mode_percentile_measured_counts"] = measured_counts
    summary["mode_percentile_pending_counts"] = pending_counts
    summary["strict_hotpath_symbols"] = strict_hotpath
    summary["capture_queue_size"] = len(doc.get("capture_queue", []))


def ingest(
    artifact_path: str,
    capture_map_path: str,
    logs: list[str],
) -> dict[str, Any]:
    doc = _load_json(artifact_path)
    capture_map = _load_json(capture_map_path)

    symbol_rows = doc.get("symbols", [])
    symbol_lookup: dict[str, dict[str, Any]] = {}
    for row in symbol_rows:
        symbol = row.get("symbol")
        if isinstance(symbol, str):
            symbol_lookup[symbol] = row

    sources = capture_map.get("sources", [])
    if not isinstance(sources, list):
        raise ValueError("capture map: sources must be an array")

    observations: dict[tuple[str, str, str], list[float]] = defaultdict(list)
    obs_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    applied_lines = 0

    for log_path in logs:
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                parsed = _parse_kv_line(line)
                if parsed is None:
                    continue
                prefix, kv = parsed

                for source in sources:
                    if not isinstance(source, dict):
                        continue
                    line_prefix = source.get("line_prefix")
                    if prefix != line_prefix:
                        continue

                    source_id = str(source.get("id", "unknown_source"))
                    mode_key = str(source.get("mode_key", "mode"))
                    bench_key = str(source.get("bench_key", "bench"))
                    pct_keys = source.get("percentile_keys", {})
                    bench_symbol_map = source.get("bench_symbol_map", [])

                    if not isinstance(pct_keys, dict) or not isinstance(bench_symbol_map, list):
                        continue

                    mode = kv.get(mode_key)
                    bench = kv.get(bench_key)
                    if mode not in MODES or not bench:
                        continue

                    mapped_symbols: list[str] = []
                    for mapping in bench_symbol_map:
                        if not isinstance(mapping, dict):
                            continue
                        if mapping.get("bench") != bench:
                            continue
                        symbols = mapping.get("symbols", [])
                        if not isinstance(symbols, list):
                            continue
                        mapped_symbols.extend([s for s in symbols if isinstance(s, str)])

                    if not mapped_symbols:
                        continue

                    file_tag = os.path.basename(log_path)
                    source_ref = f"{source_id}:{file_tag}:{bench}"

                    for symbol in mapped_symbols:
                        row = symbol_lookup.get(symbol)
                        if row is None:
                            continue
                        for pct in PERCENTILES:
                            field_name = pct_keys.get(pct)
                            if not isinstance(field_name, str):
                                continue
                            value = _to_float(kv.get(field_name))
                            if value is None:
                                continue
                            observations[(symbol, mode, pct)].append(value)
                            obs_sources[(symbol, mode)].add(source_ref)
                            applied_lines += 1

    updated_symbols: set[str] = set()
    updated_modes = 0

    for symbol, row in symbol_lookup.items():
        baseline = row.get("baseline")
        if not isinstance(baseline, dict):
            continue

        for mode in MODES:
            mode_row = baseline.get(mode)
            if not isinstance(mode_row, dict):
                continue

            changed = False
            for pct in PERCENTILES:
                values = observations.get((symbol, mode, pct), [])
                if not values:
                    continue
                mode_row[f"{pct}_ns"] = round(_median(values), 3)
                changed = True

            if changed:
                srcs = sorted(obs_sources.get((symbol, mode), set()))
                mode_row["source"] = ",".join(srcs) if srcs else mode_row.get("source")
                updated_symbols.add(symbol)
                updated_modes += 1

            _normalize_mode_row(mode_row)

    _recompute_summary(doc)

    doc["ingestion"] = {
        "schema_version": 1,
        "trace_id": TRACE_ID,
        "capture_map": capture_map_path,
        "logs": sorted(logs),
        "applied_observations": applied_lines,
        "updated_symbols": len(updated_symbols),
        "updated_modes": updated_modes,
    }

    return doc


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest benchmark samples into symbol latency baseline artifact."
    )
    parser.add_argument(
        "--artifact",
        default="tests/conformance/symbol_latency_baseline.v1.json",
        help="Base symbol latency baseline artifact",
    )
    parser.add_argument(
        "--capture-map",
        default="tests/conformance/symbol_latency_capture_map.v1.json",
        help="Capture map JSON",
    )
    parser.add_argument(
        "--log",
        action="append",
        default=[],
        help="Benchmark log file (repeatable)",
    )
    parser.add_argument(
        "--output",
        default="tests/conformance/symbol_latency_baseline.v1.json",
        help="Output artifact path",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress completion line",
    )
    args = parser.parse_args()

    if not args.log:
        args.log = ["tests/conformance/symbol_latency_samples.v1.log"]

    doc = ingest(
        artifact_path=args.artifact,
        capture_map_path=args.capture_map,
        logs=args.log,
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, sort_keys=True)
        handle.write("\n")

    if not args.quiet:
        print(
            json.dumps(
                {
                    "trace_id": TRACE_ID,
                    "mode": "symbol_latency_ingestion",
                    "artifact_ref": args.output,
                    "updated_symbols": doc.get("ingestion", {}).get("updated_symbols", 0),
                },
                separators=(",", ":"),
            )
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
