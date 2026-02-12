#!/usr/bin/env bash
# check_runtime_math_linkage_proofs.sh — Prove runtime_math production controllers are decision-linked.
#
# Bead: bd-7dw2
#
# This gate runs a dedicated harness subcommand which:
# - loads the production module set from tests/runtime_math/production_kernel_manifest.v1.json,
# - loads the linkage ledger from tests/runtime_math/runtime_math_linkage.v1.json,
# - proves wiring against crates/frankenlibc-membrane/src/runtime_math/mod.rs,
# - emits structured JSONL logs and a machine-readable JSON report.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/runtime_math_linkage_proofs.log.jsonl"
REPORT_PATH="${OUT_DIR}/runtime_math_linkage_proofs.report.json"

mkdir -p "${OUT_DIR}"

cargo run -p frankenlibc-harness --bin harness -- runtime-math-linkage-proofs \
  --workspace-root "${ROOT}" \
  --log "${LOG_PATH}" \
  --report "${REPORT_PATH}"

echo "OK: runtime_math linkage proofs emitted:"
echo "- ${LOG_PATH}"
echo "- ${REPORT_PATH}"

