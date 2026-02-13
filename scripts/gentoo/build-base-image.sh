#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "FAIL: docker is required"
    exit 1
fi

STAGE3_IMAGE="${STAGE3_IMAGE:-frankenlibc/gentoo-stage3:latest}"
BUILDER_IMAGE="${BUILDER_IMAGE:-frankenlibc/gentoo-builder:latest}"
STAGE3_SOURCE_IMAGE="${STAGE3_SOURCE_IMAGE:-gentoo/stage3:latest}"

echo "=== FrankenLibC Gentoo Image Build ==="
echo "ROOT=${ROOT}"
echo "STAGE3_SOURCE_IMAGE=${STAGE3_SOURCE_IMAGE}"
echo "STAGE3_IMAGE=${STAGE3_IMAGE}"
echo "BUILDER_IMAGE=${BUILDER_IMAGE}"

docker build \
  --build-arg "GENTOO_STAGE3_IMAGE=${STAGE3_SOURCE_IMAGE}" \
  -f "${ROOT}/docker/gentoo/Dockerfile.stage3" \
  -t "${STAGE3_IMAGE}" \
  "${ROOT}"

docker build \
  --build-arg "BASE_IMAGE=${STAGE3_IMAGE}" \
  -f "${ROOT}/docker/gentoo/Dockerfile.builder" \
  -t "${BUILDER_IMAGE}" \
  "${ROOT}"

echo "=== Build Complete ==="
docker image inspect "${STAGE3_IMAGE}" "${BUILDER_IMAGE}" \
  --format '{{index .RepoTags 0}} {{.Size}}' | \
  awk 'BEGIN { print "IMAGE SIZE_BYTES" } { print $1, $2 }'
