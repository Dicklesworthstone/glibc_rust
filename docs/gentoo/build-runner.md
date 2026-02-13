# Gentoo Build Runner

Automated package build orchestration with FrankenLibC instrumentation.

## Artifacts

- `configs/gentoo/build-config.toml`
- `scripts/gentoo/build-runner.py`
- `scripts/gentoo/build-package.sh`
- `scripts/gentoo/collect-artifacts.sh`
- `tests/gentoo/test-build-runner.py`

## Dry Run

```bash
python3 scripts/gentoo/build-runner.py \
  --config configs/gentoo/build-config.toml \
  --dry-run
```

## Targeted Dry Run

```bash
python3 scripts/gentoo/build-runner.py \
  --config configs/gentoo/build-config.toml \
  --dry-run \
  --package sys-devel/binutils \
  --package sys-devel/gcc
```

## Real Run

```bash
python3 scripts/gentoo/build-runner.py \
  --config configs/gentoo/build-config.toml
```

## Results

- State file: `artifacts/gentoo-builds/state.json`
- Per-package attempts: `artifacts/gentoo-builds/packages/<atom>/attempt-N/`
- Export artifacts:

```bash
scripts/gentoo/collect-artifacts.sh --source artifacts/gentoo-builds
```
