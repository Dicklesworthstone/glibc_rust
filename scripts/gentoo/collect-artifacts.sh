#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: collect-artifacts.sh [--source PATH] [--output PATH] [--no-tar]

Collect Gentoo build artifacts and state into a single export directory.
USAGE
}

SOURCE="${FLC_ARTIFACT_SOURCE:-artifacts/gentoo-builds}"
OUTPUT="${FLC_ARTIFACT_OUTPUT:-}"
MAKE_TAR=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --source)
            SOURCE="$2"
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --no-tar)
            MAKE_TAR=0
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
    OUTPUT="${SOURCE%/}-export-$(date -u +%Y%m%dT%H%M%SZ)"
fi

if [[ ! -d "${SOURCE}" ]]; then
    echo "FAIL: source does not exist: ${SOURCE}"
    exit 1
fi

mkdir -p "${OUTPUT}"

if command -v rsync >/dev/null 2>&1; then
    rsync -a "${SOURCE}/" "${OUTPUT}/"
else
    cp -a "${SOURCE}/." "${OUTPUT}/"
fi

STATE_FILE="${OUTPUT}/state.json"
SUMMARY_FILE="${OUTPUT}/summary.json"

if [[ -f "${STATE_FILE}" ]]; then
    python3 - <<'PY' "${STATE_FILE}" "${SUMMARY_FILE}"
import json
import sys
from collections import Counter
from pathlib import Path

state_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
payload = json.loads(state_path.read_text(encoding="utf-8"))
results = payload.get("results", {})

counter = Counter()
for record in results.values():
    counter[record.get("result", "unknown")] += 1

summary = {
    "package_count": len(results),
    "by_result": dict(counter),
    "generated_at": payload.get("updated_at"),
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(f"INFO: wrote summary {summary_path}")
PY
fi

if [[ "${MAKE_TAR}" == "1" ]]; then
    TAR_PATH="${OUTPUT}.tar.gz"
    tar -C "$(dirname "${OUTPUT}")" -czf "${TAR_PATH}" "$(basename "${OUTPUT}")"
    echo "INFO: wrote archive ${TAR_PATH}"
fi

echo "PASS: collected artifacts into ${OUTPUT}"
