#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_IMAGE="${BASE_IMAGE:-frankenlibc/gentoo-builder:latest}"
INTEGRATION_IMAGE="${INTEGRATION_IMAGE:-frankenlibc/gentoo-frankenlibc:latest}"

if ! command -v docker >/dev/null 2>&1; then
    echo "SKIP: docker not installed"
    exit 0
fi

echo "=== Gentoo FrankenLibC Integration Validation ==="
echo "ROOT=${ROOT}"
echo "BASE_IMAGE=${BASE_IMAGE}"
echo "INTEGRATION_IMAGE=${INTEGRATION_IMAGE}"

if ! docker image inspect "${BASE_IMAGE}" >/dev/null 2>&1; then
    echo "INFO: base image missing, building base images first"
    "${ROOT}/scripts/gentoo/build-base-image.sh"
fi

docker build \
  --build-arg "BASE_IMAGE=${BASE_IMAGE}" \
  -f "${ROOT}/docker/gentoo/Dockerfile.frankenlibc" \
  -t "${INTEGRATION_IMAGE}" \
  "${ROOT}" >/tmp/frankenlibc-integration-build.log

echo "--- check: integration artifacts exist ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc \
  "test -f /etc/portage/bashrc && \
   test -f /opt/frankenlibc/etc/frankenlibc.toml && \
   test -x /opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/build-package.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/collect-artifacts.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/collect-logs.sh && \
   test -x /opt/frankenlibc/scripts/gentoo/analyze-logs.py && \
   test -f /etc/portage/env/no-frankenlibc.conf"

echo "--- check: preload activates for allowed phase ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /opt/frankenlibc/lib
  : > /opt/frankenlibc/lib/libfrankenlibc_abi.so
  export CATEGORY=sys-apps PN=coreutils PF=coreutils-9.9-r1 EBUILD_PHASE=src_test USE=""
  source /etc/portage/bashrc
  pre_src_test
  [[ "${LD_PRELOAD:-}" == *"/opt/frankenlibc/lib/libfrankenlibc_abi.so"* ]]
  [[ -n "${FRANKENLIBC_LOG_FILE:-}" ]]
  [[ "${FRANKENLIBC_LOG_FILE}" == */src_test.jsonl ]]
  post_src_test
  [[ -z "${LD_PRELOAD:-}" ]]
'

echo "--- check: blocklisted package disables preload ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /opt/frankenlibc/lib
  : > /opt/frankenlibc/lib/libfrankenlibc_abi.so
  export CATEGORY=sys-libs PN=glibc PF=glibc-2.39 EBUILD_PHASE=src_test USE=""
  source /etc/portage/bashrc
  pre_src_test
  [[ -z "${LD_PRELOAD:-}" ]]
'

echo "--- check: log collection + analysis tooling ---"
docker run --rm "${INTEGRATION_IMAGE}" bash -lc '
  set -euo pipefail
  mkdir -p /var/log/frankenlibc/portage
  printf "%s\n" "{\"timestamp\":\"2026-02-13T00:00:00Z\",\"event\":\"enable\",\"atom\":\"sys-apps/coreutils-9.9-r1\",\"phase\":\"src_test\",\"pid\":123,\"message\":\"sample\"}" > /var/log/frankenlibc/portage/hooks.jsonl
  /opt/frankenlibc/scripts/gentoo/collect-logs.sh --log-root /var/log/frankenlibc --output /tmp/frankenlibc-collected --no-tar
  python3 /opt/frankenlibc/scripts/gentoo/analyze-logs.py /tmp/frankenlibc-collected --output /tmp/summary.json --json-only >/dev/null
  test -s /tmp/summary.json
'

echo "PASS: gentoo frankenlibc integration validation completed"
