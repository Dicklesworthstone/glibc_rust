# Gentoo Test Analysis

This workflow compares package test suites in two modes:

1. Baseline (`FRANKENLIBC_PORTAGE_ENABLE=0`)
2. Instrumented (`FRANKENLIBC_PORTAGE_ENABLE=1`, `FRANKENLIBC_MODE=hardened|strict`)

## Artifacts

- `scripts/gentoo/test-runner.py`
- `scripts/gentoo/compare-results.py`
- `scripts/gentoo/analyze-healing.py`
- `data/gentoo/test-baselines/`

## Dry-Run Validation

```bash
python3 scripts/gentoo/test-runner.py \
  --dry-run \
  --package sys-apps/coreutils \
  --output artifacts/gentoo-tests
```

## Baseline + Instrumented Comparison

`test-runner.py` writes per-package `result.json` plus aggregate `summary.json`.

Comparison output includes:

- `new_failures`
- `new_passes`
- `overhead_percent`
- `verdict` (`PASS|NEUTRAL|IMPROVEMENT|REGRESSION`)

## Standalone Comparison

```bash
python3 scripts/gentoo/compare-results.py \
  baseline.json instrumented.json \
  --output comparison.json
```

## Healing Action Breakdown

```bash
python3 scripts/gentoo/analyze-healing.py \
  /path/to/frankenlibc.jsonl \
  --output healing-summary.json
```
