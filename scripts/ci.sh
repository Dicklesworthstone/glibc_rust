#!/usr/bin/env bash
# CI quality gates for glibc_rust.
set -euo pipefail

echo "=== glibc_rust CI ==="
echo ""

echo "--- cargo fmt --check ---"
cargo fmt --check
echo "PASS"
echo ""

echo "--- cargo check --workspace --all-targets ---"
cargo check --workspace --all-targets
echo "PASS"
echo ""

echo "--- cargo clippy --workspace --all-targets -- -D warnings ---"
cargo clippy --workspace --all-targets -- -D warnings
echo "PASS"
echo ""

echo "--- cargo test --workspace ---"
cargo test --workspace
echo "PASS"
echo ""

echo "--- cargo build -p glibc-rs-abi --release ---"
cargo build -p glibc-rs-abi --release
echo "PASS"
echo ""

if [[ "${GLIBC_RUST_EXTENDED_GATES:-0}" == "1" ]]; then
    echo "--- hard rule audit (no forbidden math on strict fast path) ---"
    scripts/hard_rule_audit.sh
    echo "PASS"
    echo ""

    echo "--- module inventory drift check ---"
    scripts/check_module_inventory.sh
    echo "PASS"
    echo ""

    echo "--- module wiring checklist ---"
    scripts/check_module_wiring.sh || echo "WARN: wiring gaps found (non-blocking)"
    echo ""

    echo "--- snapshot+test coverage matrix ---"
    scripts/check_snapshot_coverage.sh
    echo "PASS"
    echo ""

    echo "--- conformance golden gate (strict+hardened fixture verify) ---"
    scripts/conformance_golden_gate.sh
    echo "PASS"
    echo ""

    echo "--- snapshot gate (runtime_math golden) ---"
    scripts/snapshot_gate.sh
    echo "PASS"
    echo ""

    echo "--- perf gate (runtime_math + membrane) ---"
    scripts/perf_gate.sh
    echo "PASS"
    echo ""

    echo "--- CVE Arena regression gate ---"
    if [ -f scripts/cve_arena_gate.sh ]; then
        scripts/cve_arena_gate.sh
        echo "PASS"
    else
        echo "SKIP (cve_arena_gate.sh not found)"
    fi
    echo ""
else
    echo "SKIP extended gates (set GLIBC_RUST_EXTENDED_GATES=1 to run full policy/perf/snapshot checks)"
    echo ""
fi

echo "=== All gates passed ==="
