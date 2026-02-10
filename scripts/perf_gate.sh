#!/usr/bin/env bash
# Performance regression gate for runtime_math + membrane hot paths.
#
# This script is intentionally simple and deterministic:
# - runs a small set of Criterion benches (strict + hardened)
# - parses machine-readable p50 ns/op lines emitted by benches
# - compares against scripts/perf_baseline.json and fails on regressions
set -euo pipefail

BASELINE_FILE="${BASELINE_FILE:-scripts/perf_baseline.json}"
# Default to a tolerant bound to avoid flakiness on shared/dev machines.
# Tighten locally by setting GLIBC_RUST_PERF_MAX_REGRESSION_PCT.
MAX_REGRESSION_PCT="${GLIBC_RUST_PERF_MAX_REGRESSION_PCT:-15}"
ALLOW_TARGET_VIOLATION="${GLIBC_RUST_PERF_ALLOW_TARGET_VIOLATION:-1}"

if [[ ! -f "${BASELINE_FILE}" ]]; then
  echo "perf_gate: missing baseline file: ${BASELINE_FILE}" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "perf_gate: jq is required" >&2
  exit 2
fi

extract_p50() {
  local prefix="$1" mode="$2" bench="$3"
  awk -v prefix="$prefix" -v mode="$mode" -v bench="$bench" '
    $1==prefix {
      have_mode=0; have_bench=0; p50="";
      for (i=2; i<=NF; i++) {
        if ($i=="mode="mode) have_mode=1;
        if ($i=="bench="bench) have_bench=1;
        if ($i ~ /^p50_ns_op=/) { split($i,a,"="); p50=a[2]; }
      }
      if (have_mode && have_bench && p50!="") { print p50; exit 0; }
    }
  '
}

check_metric() {
  local label="$1" mode="$2" prefix="$3" bench="$4" baseline="$5" target="$6" current="$7"
  local delta_pct ok_reg ok_target

  # Compute delta% with awk (portable, no bc dependency).
  delta_pct="$(awk -v c="$current" -v b="$baseline" 'BEGIN { if (b==0) { print "inf"; exit } printf "%.2f", ((c-b)/b)*100.0 }')"

  ok_reg="$(awk -v c="$current" -v b="$baseline" -v pct="$MAX_REGRESSION_PCT" 'BEGIN { print (c <= b*(1.0 + pct/100.0)) ? "1" : "0" }')"
  ok_target="$(awk -v c="$current" -v t="$target" 'BEGIN { print (c <= t) ? "1" : "0" }')"

  printf "%-18s %-8s %-16s baseline=%9.3f current=%9.3f delta=%7s%% target=%7.0f " \
    "$label" "$mode" "$bench" "$baseline" "$current" "$delta_pct" "$target"

  if [[ "$ok_reg" != "1" ]]; then
    echo "REGRESSION"
    return 1
  fi

  if [[ "$ok_target" != "1" ]]; then
    if [[ "$ALLOW_TARGET_VIOLATION" == "1" ]]; then
      echo "TARGET_VIOLATION (allowed)"
      return 0
    fi
    echo "TARGET_VIOLATION"
    return 2
  fi

  echo "OK"
  return 0
}

run_mode() {
  local mode="$1"
  local out_rt out_mem

  echo ""
  echo "=== perf_gate: mode=${mode} ==="

  # Pin if supported by bench binaries (best-effort).
  out_rt="$(
    GLIBC_RUST_BENCH_PIN=1 GLIBC_RUST_MODE="$mode" \
      cargo bench -p glibc-rs-bench --bench runtime_math_bench 2>/dev/null \
      | rg '^RUNTIME_MATH_BENCH ' || true
  )"

  out_mem="$(
    GLIBC_RUST_BENCH_PIN=1 GLIBC_RUST_MODE="$mode" \
      cargo bench -p glibc-rs-bench --bench membrane_bench 2>/dev/null \
      | rg '^MEMBRANE_BENCH ' || true
  )"

  if [[ -z "${out_rt}" ]]; then
    echo "perf_gate: failed to collect RUNTIME_MATH_BENCH lines for mode=${mode}" >&2
    exit 2
  fi
  if [[ -z "${out_mem}" ]]; then
    echo "perf_gate: failed to collect MEMBRANE_BENCH lines for mode=${mode}" >&2
    exit 2
  fi

  local rt_decide rt_observe rt_decide_observe mem_validate_known
  rt_decide="$(printf "%s\n" "$out_rt" | extract_p50 "RUNTIME_MATH_BENCH" "$mode" "decide")"
  rt_observe="$(printf "%s\n" "$out_rt" | extract_p50 "RUNTIME_MATH_BENCH" "$mode" "observe_fast")"
  rt_decide_observe="$(printf "%s\n" "$out_rt" | extract_p50 "RUNTIME_MATH_BENCH" "$mode" "decide_observe")"
  mem_validate_known="$(printf "%s\n" "$out_mem" | extract_p50 "MEMBRANE_BENCH" "$mode" "validate_known")"

  if [[ -z "$rt_decide" || -z "$rt_observe" || -z "$rt_decide_observe" || -z "$mem_validate_known" ]]; then
    echo "perf_gate: missing parsed values for mode=${mode}" >&2
    echo "--- runtime_math lines ---" >&2
    printf "%s\n" "$out_rt" >&2
    echo "--- membrane lines ---" >&2
    printf "%s\n" "$out_mem" >&2
    exit 2
  fi

  local b_decide b_observe b_decide_observe b_validate_known
  local t_decide t_observe t_decide_observe t_validate_known

  b_decide="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.decide" "$BASELINE_FILE")"
  b_observe="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.observe_fast" "$BASELINE_FILE")"
  b_decide_observe="$(jq -r ".baseline_p50_ns_op.runtime_math.${mode}.decide_observe" "$BASELINE_FILE")"
  b_validate_known="$(jq -r ".baseline_p50_ns_op.membrane.${mode}.validate_known" "$BASELINE_FILE")"

  t_decide="$(jq -r ".targets_ns_op.${mode}.decide" "$BASELINE_FILE")"
  t_observe="$(jq -r ".targets_ns_op.${mode}.observe_fast" "$BASELINE_FILE")"
  t_decide_observe="$(jq -r ".targets_ns_op.${mode}.decide_observe" "$BASELINE_FILE")"
  t_validate_known="$(jq -r ".targets_ns_op.${mode}.validate_known" "$BASELINE_FILE")"

  local failures=0 target_failures=0

  check_metric "runtime_math" "$mode" "RUNTIME_MATH_BENCH" "decide" "$b_decide" "$t_decide" "$rt_decide" || {
    rc=$?
    if [[ "$rc" == "1" ]]; then failures=$((failures+1)); else target_failures=$((target_failures+1)); fi
  }
  check_metric "runtime_math" "$mode" "RUNTIME_MATH_BENCH" "observe_fast" "$b_observe" "$t_observe" "$rt_observe" || {
    rc=$?
    if [[ "$rc" == "1" ]]; then failures=$((failures+1)); else target_failures=$((target_failures+1)); fi
  }
  check_metric "runtime_math" "$mode" "RUNTIME_MATH_BENCH" "decide_observe" "$b_decide_observe" "$t_decide_observe" "$rt_decide_observe" || {
    rc=$?
    if [[ "$rc" == "1" ]]; then failures=$((failures+1)); else target_failures=$((target_failures+1)); fi
  }
  check_metric "membrane" "$mode" "MEMBRANE_BENCH" "validate_known" "$b_validate_known" "$t_validate_known" "$mem_validate_known" || {
    rc=$?
    if [[ "$rc" == "1" ]]; then failures=$((failures+1)); else target_failures=$((target_failures+1)); fi
  }

  if [[ "$failures" -gt 0 ]]; then
    echo "perf_gate: ${failures} regression failure(s) in mode=${mode}" >&2
    return 1
  fi

  if [[ "$target_failures" -gt 0 && "$ALLOW_TARGET_VIOLATION" != "1" ]]; then
    echo "perf_gate: ${target_failures} target-budget failure(s) in mode=${mode}" >&2
    return 2
  fi

  return 0
}

echo "=== perf_gate ==="
echo "baseline=${BASELINE_FILE}"
echo "max_regression_pct=${MAX_REGRESSION_PCT}"
echo "allow_target_violation=${ALLOW_TARGET_VIOLATION}"

run_mode strict
run_mode hardened

echo ""
echo "perf_gate: PASS"
