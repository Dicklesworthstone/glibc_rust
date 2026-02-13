# Gentoo Test Baselines

This directory stores baseline (non-instrumented) test result JSON files
produced by:

```bash
python3 scripts/gentoo/test-runner.py --write-baseline --dry-run
```

File naming convention:

- `<category>__<package>.json`

Example:

- `sys-apps__coreutils.json`
