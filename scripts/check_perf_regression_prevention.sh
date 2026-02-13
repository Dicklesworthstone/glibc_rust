#!/usr/bin/env bash
# check_perf_regression_prevention.sh — CI gate for bd-1qfc
# Validates the performance regression prevention system is complete and healthy.
#
# Checks:
#   1. Report generates successfully.
#   2. All spec suites have bench files.
#   3. Enforced suites have full baselines.
#   4. perf_gate.sh exists with required features.
#   5. Hotpath symbol coverage above threshold.
#   6. No expired waivers or config issues.
#
# --strict: requires >= 50% hotpath coverage and full baseline coverage for enforced suites.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/perf_regression_prevention.v1.json"

STRICT=false
if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

echo "=== Performance Regression Prevention Gate (bd-1qfc) ==="

# 1. Generate the report
echo "--- Generating prevention system report ---"
python3 "$SCRIPT_DIR/generate_perf_regression_prevention.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: prevention report not generated"
    exit 1
fi

# 2. Validate report and check thresholds
python3 - "$REPORT" "$STRICT" <<'PY'
import json, sys

report_path = sys.argv[1]
strict = sys.argv[2].lower() == "true"
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})

# Display summary
total_suites = summary.get("total_suites_in_spec", 0)
with_files = summary.get("suites_with_bench_files", 0)
enforced = summary.get("suites_enforced_in_gate", 0)
with_baselines = summary.get("suites_with_full_baselines", 0)
baseline_fill = summary.get("baseline_slot_fill_pct", 0)
hotpath_cov = summary.get("hotpath_symbol_coverage_pct", 0)
hotpath_total = summary.get("total_hotpath_symbols", 0)
extra = summary.get("extra_bench_files_beyond_spec", 0)
issues = summary.get("total_issues", 0)
warnings = summary.get("total_warnings", 0)

print(f"Suites in spec:       {total_suites}")
print(f"  with bench files:   {with_files}/{total_suites}")
print(f"  enforced in gate:   {enforced}/{total_suites}")
print(f"  with full baselines:{with_baselines}/{total_suites}")
print(f"Baseline slot fill:   {baseline_fill}%")
print(f"Hotpath coverage:     {hotpath_cov}% ({hotpath_total} symbols)")
print(f"Extra bench files:    {extra}")
print(f"Issues: {issues}  Warnings: {warnings}")

# Bench inventory
bench_inv = report.get("bench_file_inventory", [])
print(f"\nBench file inventory ({len(bench_inv)} suites):")
for s in bench_inv:
    status = "OK" if s["exists"] else "MISSING"
    gate = " [enforced]" if s["enforced_in_gate"] else ""
    print(f"  {s['suite_id']:20s} {s['benchmark_count']:2d} benchmarks  {status}{gate}")

# Baseline coverage
base_cov = report.get("baseline_coverage", [])
print(f"\nBaseline coverage:")
for s in base_cov:
    bar = "█" * int(s["coverage_pct"] / 10) + "░" * (10 - int(s["coverage_pct"] / 10))
    print(f"  {s['suite_id']:20s} {s['baselines_present']:2d}/{s['total_benchmarks_x_modes']:2d} {bar} {s['coverage_pct']}%")

# Gate wiring
gate = report.get("gate_wiring", {})
if gate.get("exists"):
    print(f"\nGate wiring (perf_gate.sh):")
    print(f"  Enforced suites: {', '.join(gate.get('enforced_suites', []))}")
    features = gate.get("features", {})
    for feat, present in features.items():
        mark = "✓" if present else "✗"
        print(f"  {mark} {feat}")

# Hotpath coverage
hp = report.get("hotpath_symbol_coverage", {})
print(f"\nHotpath symbol coverage:")
print(f"  Covered: {hp.get('covered_by_bench_suite', 0)}/{hp.get('total_hotpath_symbols', 0)}")
print(f"  Uncovered modules: {', '.join(hp.get('uncovered_modules', []))}")

# Config consistency
cfg = report.get("config_consistency", {})
print(f"\nConfig consistency:")
print(f"  Baseline version:   {cfg.get('baseline_version')}")
print(f"  Max regression:     {cfg.get('regression_max_pct')}%")
print(f"  Strict target:      {cfg.get('strict_target_ns')}ns")
print(f"  Hardened target:    {cfg.get('hardened_target_ns')}ns")
print(f"  Active waivers:     {cfg.get('active_waivers')}")
print(f"  Expired waivers:    {cfg.get('expired_waivers')}")
cfg_issues = cfg.get("issues", [])
for iss in cfg_issues:
    print(f"  ISSUE: {iss}")

# Extra bench files
extras = report.get("extra_bench_files", [])
if extras:
    print(f"\nExtra bench files (not in spec): {', '.join(extras)}")

# Threshold checks
print("")

# Check 1: All spec suites must have bench files
missing_files = [s for s in bench_inv if not s["exists"]]
if missing_files:
    names = ", ".join(s["suite_id"] for s in missing_files)
    print(f"FAIL: Missing bench files for spec suites: {names}")
    errors += 1
else:
    print(f"PASS: All {total_suites} spec suites have bench files")

# Check 2: Enforced suites must have full baselines
enforced_ids = {s["suite_id"] for s in bench_inv if s["enforced_in_gate"]}
incomplete_enforced = [s for s in base_cov if s["suite_id"] in enforced_ids and s["coverage_pct"] < 100.0]
if incomplete_enforced:
    for s in incomplete_enforced:
        print(f"FAIL: Enforced suite '{s['suite_id']}' has incomplete baselines ({s['coverage_pct']}%)")
    errors += 1
else:
    print(f"PASS: All enforced suites have complete baselines")

# Check 3: Gate exists with key features
if not gate.get("exists"):
    print("FAIL: perf_gate.sh not found")
    errors += 1
else:
    missing_features = [f for f, present in gate.get("features", {}).items() if not present]
    if missing_features:
        print(f"FAIL: perf_gate.sh missing features: {', '.join(missing_features)}")
        errors += 1
    else:
        print("PASS: perf_gate.sh has all required features")

# Check 4: No expired waivers
if cfg.get("expired_waivers", 0) > 0:
    print(f"FAIL: {cfg['expired_waivers']} expired waiver(s)")
    errors += 1
else:
    print("PASS: No expired waivers")

# Check 5: No config issues
if cfg_issues:
    print(f"FAIL: {len(cfg_issues)} config issue(s)")
    errors += 1
else:
    print("PASS: Configuration is consistent")

# Strict-mode checks
if strict:
    if hotpath_cov < 50.0:
        print(f"FAIL: Hotpath coverage {hotpath_cov}% below 50% strict threshold")
        errors += 1
    else:
        print(f"PASS: Hotpath coverage {hotpath_cov}% >= 50% (strict)")

    if baseline_fill < 25.0:
        print(f"FAIL: Baseline fill {baseline_fill}% below 25% strict threshold")
        errors += 1
    else:
        print(f"PASS: Baseline fill {baseline_fill}% >= 25% (strict)")

if errors > 0:
    mode = "strict" if strict else "default"
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

mode = "strict" if strict else "default"
print(f"\ncheck_perf_regression_prevention ({mode}): PASS")
PY
