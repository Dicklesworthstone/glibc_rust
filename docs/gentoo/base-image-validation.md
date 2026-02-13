# Gentoo Stage 3 Base Image Validation

This document defines the deterministic validation workflow for `bd-2icq.3`.

## Artifacts

- `docker/gentoo/Dockerfile.stage3`
- `docker/gentoo/Dockerfile.builder`
- `configs/gentoo/make.conf`
- `scripts/gentoo/build-base-image.sh`
- `tests/gentoo/test-base-image.sh`

## Build

```bash
scripts/gentoo/build-base-image.sh
```

Optional overrides:

```bash
STAGE3_SOURCE_IMAGE=gentoo/stage3:latest \
STAGE3_IMAGE=frankenlibc/gentoo-stage3:latest \
BUILDER_IMAGE=frankenlibc/gentoo-builder:latest \
scripts/gentoo/build-base-image.sh
```

## Validate

```bash
tests/gentoo/test-base-image.sh
```

Optional slow full package build:

```bash
FLC_GENTOO_TEST_FULL_EMERGE=1 tests/gentoo/test-base-image.sh
```

## What the Validation Script Checks

1. `docker` exists and required images are present.
2. `emerge --info` succeeds in stage3 image.
3. `/etc/portage/make.conf` exists with expected baseline knobs.
4. Stage3 baseline toolchain binaries (`gcc`, `ld`, `make`) are present.
5. Builder image includes `/etc/portage/bashrc` and executable hook script.
6. `emerge -p sys-apps/coreutils` dependency plan succeeds.
7. Optional: `emerge -1v sys-apps/coreutils` full build succeeds.

## CI Notes

- For fast CI: run `tests/gentoo/test-base-image.sh` with default `FLC_GENTOO_TEST_FULL_EMERGE=0`.
- For nightly/deep validation: enable `FLC_GENTOO_TEST_FULL_EMERGE=1`.
