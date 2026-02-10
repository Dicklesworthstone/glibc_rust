#!/usr/bin/env bash
# CI quality gates for glibc_rust.
set -euo pipefail

echo "=== glibc_rust CI ==="
echo ""

echo "--- cargo fmt --check ---"
cargo fmt --check
echo "PASS"
echo ""

echo "--- cargo check --all-targets ---"
cargo check --all-targets
echo "PASS"
echo ""

echo "--- cargo clippy --all-targets -- -D warnings ---"
cargo clippy --all-targets -- -D warnings
echo "PASS"
echo ""

echo "--- cargo test --all-targets ---"
cargo test --all-targets
echo "PASS"
echo ""

echo "--- perf gate (runtime_math + membrane) ---"
scripts/perf_gate.sh
echo "PASS"
echo ""

echo "=== All gates passed ==="
