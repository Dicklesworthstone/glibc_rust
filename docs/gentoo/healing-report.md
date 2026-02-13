# Gentoo Healing Action Report

This report summarizes the analysis workflow for membrane healing actions.

## Inputs and Tools

- Input log corpus: `data/gentoo/healing-analysis/sample-healing.jsonl`
- Analyzer: `scripts/gentoo/analyze-healing.py`
- Pattern detector: `scripts/gentoo/detect-patterns.py`
- False-positive detector: `scripts/gentoo/false-positive-detector.py`

## Current Snapshot (Sample Dataset)

- Total log entries: `5`
- Total healing actions: `5`
- Action breakdown:
  - `ClampSize`: `2`
  - `TruncateWithNull`: `1`
  - `IgnoreDoubleFree`: `1`
  - `ReallocAsMalloc`: `1`

Derived artifacts:

- `data/gentoo/healing-analysis/summary.json`
- `data/gentoo/healing-analysis/patterns.json`
- `data/gentoo/healing-analysis/false-positives.json`

## Pattern Highlights

- Oversized allocation requests (`ClampSize`) observed in:
  - `dev-db/redis`
  - `net-misc/curl`
- Unterminated string boundary handling (`TruncateWithNull`) observed in:
  - `dev-db/redis`
- Double-free cleanup pattern (`IgnoreDoubleFree`) observed in:
  - `net-misc/curl`

## False-Positive Heuristics

Current detector flags:

1. High package-level healing rates (`actions_per_1000_calls` threshold).
2. Potentially unnecessary `ClampSize` where original and clamped sizes are near-equal.
3. Dominant single-action ratios for selected action classes.

## Reproduction

```bash
python3 scripts/gentoo/analyze-healing.py \
  data/gentoo/healing-analysis/sample-healing.jsonl \
  --output data/gentoo/healing-analysis/summary.json

python3 scripts/gentoo/detect-patterns.py \
  data/gentoo/healing-analysis/summary.json \
  --output data/gentoo/healing-analysis/patterns.json

python3 scripts/gentoo/false-positive-detector.py \
  data/gentoo/healing-analysis/summary.json \
  --output data/gentoo/healing-analysis/false-positives.json
```
