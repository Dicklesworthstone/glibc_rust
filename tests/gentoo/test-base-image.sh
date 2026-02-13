#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE3_IMAGE="${STAGE3_IMAGE:-frankenlibc/gentoo-stage3:latest}"
BUILDER_IMAGE="${BUILDER_IMAGE:-frankenlibc/gentoo-builder:latest}"
RUN_FULL_EMERGE="${FLC_GENTOO_TEST_FULL_EMERGE:-0}"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not installed"
    exit 0
fi

echo "=== Gentoo Base Image Validation ==="
echo "ROOT=${ROOT}"
echo "STAGE3_IMAGE=${STAGE3_IMAGE}"
echo "BUILDER_IMAGE=${BUILDER_IMAGE}"
echo "RUN_FULL_EMERGE=${RUN_FULL_EMERGE}"

if ! docker image inspect "${STAGE3_IMAGE}" >/dev/null 2>&1; then
    echo "FAIL: missing image ${STAGE3_IMAGE}"
    echo "Hint: run scripts/gentoo/build-base-image.sh"
    exit 1
fi
if ! docker image inspect "${BUILDER_IMAGE}" >/dev/null 2>&1; then
    echo "FAIL: missing image ${BUILDER_IMAGE}"
    echo "Hint: run scripts/gentoo/build-base-image.sh"
    exit 1
fi

echo "--- check: emerge --info works ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge --info >/tmp/emerge-info.txt && test -s /tmp/emerge-info.txt"

echo "--- check: make.conf copied ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "test -f /etc/portage/make.conf && grep -q 'FEATURES=\"parallel-fetch test\"' /etc/portage/make.conf"

echo "--- check: stage3 toolchain baseline exists ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "command -v gcc && command -v ld && command -v make"

echo "--- check: builder has hook files ---"
docker run --rm "${BUILDER_IMAGE}" bash -lc "test -f /etc/portage/bashrc && test -x /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh"

echo "--- check: coreutils dependency plan resolves ---"
docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge -p sys-apps/coreutils >/tmp/coreutils-plan.txt && test -s /tmp/coreutils-plan.txt"

if [[ "${RUN_FULL_EMERGE}" == "1" ]]; then
    echo "--- check: full coreutils emerge (slow) ---"
    docker run --rm "${STAGE3_IMAGE}" bash -lc "emerge -1v sys-apps/coreutils"
else
    echo "INFO: skipped full emerge build (set FLC_GENTOO_TEST_FULL_EMERGE=1 to enable)"
fi

echo "PASS: gentoo base image validation completed"
