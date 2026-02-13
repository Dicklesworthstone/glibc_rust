#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: build-package.sh <package-atom> <output-dir>"
    exit 2
fi

PACKAGE="$1"
OUT_DIR="$2"

mkdir -p "${OUT_DIR}"

BUILD_LOG="${OUT_DIR}/build.log"
FRANKEN_LOG="${OUT_DIR}/frankenlibc.jsonl"
METADATA="${OUT_DIR}/metadata.json"

START_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
START_EPOCH="$(date +%s)"

export FRANKENLIBC_MODE="${FRANKENLIBC_MODE:-hardened}"
export FRANKENLIBC_LOG_FILE="${FRANKENLIBC_LOG_FILE:-${FRANKEN_LOG}}"
export FRANKENLIBC_LOG="${FRANKENLIBC_LOG_FILE}"

EMERGE_CMD=(emerge --verbose --buildpkg "${PACKAGE}")
if [[ -n "${FLC_EMERGE_EXTRA_ARGS:-}" ]]; then
    # shellcheck disable=SC2206
    EXTRA_ARGS=( ${FLC_EMERGE_EXTRA_ARGS} )
    EMERGE_CMD+=("${EXTRA_ARGS[@]}")
fi

set +e
if [[ "${FLC_BUILD_TIMEOUT_SECONDS:-0}" =~ ^[0-9]+$ ]] && [[ "${FLC_BUILD_TIMEOUT_SECONDS:-0}" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout --signal=TERM --kill-after=30 "${FLC_BUILD_TIMEOUT_SECONDS}" "${EMERGE_CMD[@]}" >"${BUILD_LOG}" 2>&1
    EXIT_CODE=$?
else
    "${EMERGE_CMD[@]}" >"${BUILD_LOG}" 2>&1
    EXIT_CODE=$?
fi
set -e

END_EPOCH="$(date +%s)"
END_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
BUILD_TIME="$((END_EPOCH - START_EPOCH))"

RESULT="failed"
if [[ "${EXIT_CODE}" -eq 0 ]]; then
    RESULT="success"
elif [[ "${EXIT_CODE}" -eq 124 ]]; then
    RESULT="timeout"
fi

if grep -Eqi '(cannot allocate memory|out of memory|oom)' "${BUILD_LOG}" 2>/dev/null; then
    RESULT="oom"
fi

HEAL_COUNT=0
if [[ -f "${FRANKEN_LOG}" ]]; then
    HEAL_COUNT="$(grep -Eci '"action"\s*:' "${FRANKEN_LOG}" || true)"
fi

cat >"${METADATA}" <<EOF
{
  "package": "${PACKAGE}",
  "result": "${RESULT}",
  "build_time_seconds": ${BUILD_TIME},
  "frankenlibc_healing_actions": ${HEAL_COUNT},
  "frankenlibc_mode": "${FRANKENLIBC_MODE}",
  "log_file": "${BUILD_LOG}",
  "frankenlibc_log": "${FRANKEN_LOG}",
  "binary_package": "",
  "exit_code": ${EXIT_CODE},
  "started_at": "${START_TS}",
  "timestamp": "${END_TS}"
}
EOF

if [[ "${RESULT}" == "success" ]]; then
    exit 0
fi
exit 1
