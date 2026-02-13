#!/usr/bin/env bash
# check_runtime_env_inventory.sh — CI gate for bd-29b.1
#
# Validates that:
#   1) runtime_env_inventory.v1.json is reproducible from source.
#   2) every discovered FRANKENLIBC_* key has semantic metadata.
#   3) unknown/ambiguous key list is empty.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_runtime_env_inventory.py"
OUT="${ROOT}/tests/conformance/runtime_env_inventory.v1.json"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}"
  exit 1
fi

if [[ ! -f "${OUT}" ]]; then
  echo "FAIL: missing inventory file ${OUT}"
  exit 1
fi

echo "=== Runtime Env Inventory Gate (bd-29b.1) ==="
python3 "${GEN}" --root "${ROOT}" --check

unknown_count="$(python3 - "${OUT}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    payload = json.load(f)
print(len(payload.get("unknown_or_ambiguous", [])))
PY
)"

if [[ "${unknown_count}" != "0" ]]; then
  echo "FAIL: unknown_or_ambiguous_count=${unknown_count} (must be 0)"
  python3 - "${OUT}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    payload = json.load(f)
for row in payload.get("unknown_or_ambiguous", []):
    print(f"  - {row.get('env_key')}: {row.get('reason')}")
PY
  exit 1
fi

echo "PASS: runtime env inventory gate"
