#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: collect-logs.sh [--log-root PATH] [--output PATH] [--no-tar] [--no-summary]

Collect FrankenLibC Portage logs into a timestamped directory and optionally:
- emit analyzer summary JSON,
- create a .tar.gz archive.
USAGE
}

LOG_ROOT="${FLC_LOG_ROOT:-/var/log/frankenlibc}"
OUTPUT="${FLC_OUTPUT_DIR:-}"
CREATE_TAR=1
CREATE_SUMMARY=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-root)
            LOG_ROOT="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --no-tar)
            CREATE_TAR=0
            shift
            ;;
        --no-summary)
            CREATE_SUMMARY=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "FAIL: unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ -z "${OUTPUT}" ]]; then
    OUTPUT="${PWD}/frankenlibc-logs-$(date -u +%Y%m%dT%H%M%SZ)"
fi

if [[ ! -d "${LOG_ROOT}" ]]; then
    echo "FAIL: log root does not exist: ${LOG_ROOT}"
    exit 1
fi

mkdir -p "${OUTPUT}"

if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete-excluded --exclude='*.tmp' "${LOG_ROOT}/" "${OUTPUT}/"
else
    cp -a "${LOG_ROOT}/." "${OUTPUT}/"
fi

ANALYZER_DEFAULT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/analyze-logs.py"
ANALYZER="${FLC_ANALYZER:-${ANALYZER_DEFAULT}}"
SUMMARY_PATH="${OUTPUT}/summary.json"

if [[ "${CREATE_SUMMARY}" == "1" ]] && command -v python3 >/dev/null 2>&1 && [[ -f "${ANALYZER}" ]]; then
    python3 "${ANALYZER}" "${OUTPUT}" --output "${SUMMARY_PATH}" --json-only
    echo "INFO: wrote summary ${SUMMARY_PATH}"
else
    echo "INFO: skipped summary generation"
fi

if [[ "${CREATE_TAR}" == "1" ]]; then
    TAR_PATH="${OUTPUT}.tar.gz"
    tar -C "$(dirname "${OUTPUT}")" -czf "${TAR_PATH}" "$(basename "${OUTPUT}")"
    echo "INFO: wrote archive ${TAR_PATH}"
fi

echo "PASS: collected logs into ${OUTPUT}"
