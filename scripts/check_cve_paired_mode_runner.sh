#!/usr/bin/env bash
# check_cve_paired_mode_runner.sh — CI gate for bd-1m5.7
# Validates strict detection assertions + paired-mode CVE evidence runner.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/cve_arena/results/paired_mode_evidence.v1.json"

echo "=== CVE Paired-Mode Evidence Runner Gate (bd-1m5.7) ==="

echo "--- Generating paired-mode evidence report ---"
python3 "$SCRIPT_DIR/generate_cve_paired_mode_runner.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: paired-mode evidence report not generated"
    exit 1
fi

python3 - "$REPORT" <<'PY'
import json, sys

report_path = sys.argv[1]
errors = 0

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
evidence = report.get("paired_evidence", [])
val_issues = report.get("validation_issues", [])

total = summary.get("total_paired_scenarios", 0)
strict_detected = summary.get("strict_detected", 0)
hardened_prevented = summary.get("hardened_prevented", 0)
with_flags = summary.get("with_detection_flags", 0)
detection_flags = summary.get("unique_detection_flags", [])
dossier_count = summary.get("unique_dossier_ids", 0)
val_errors = summary.get("validation_errors", 0)
val_warnings = summary.get("validation_warnings", 0)

print(f"Paired scenarios:        {total}")
print(f"  Strict detected:       {strict_detected}/{total}")
print(f"  Hardened prevented:    {hardened_prevented}/{total}")
print(f"  With detection flags:  {with_flags}/{total}")
print(f"  Detection flags:       {len(detection_flags)} unique")
print(f"  Dossier IDs:           {dossier_count} unique")
print(f"  Validation errors:     {val_errors}")
print(f"  Validation warnings:   {val_warnings}")

print("\nPaired evidence matrix:")
for e in evidence:
    s_verdict = e["strict_mode"]["verdict"]
    h_verdict = e["hardened_mode"]["verdict"]
    n_flags = len(e["strict_mode"]["detection_flags"])
    healing = ", ".join(e["hardened_mode"]["healing_actions"])
    print(f"  {e['cve_id']:35s} CVSS={e.get('cvss_score', '?'):>4}  strict={s_verdict:10s}  hardened={h_verdict:10s}  flags={n_flags}  healing=[{healing}]")

if val_issues:
    print(f"\nValidation issues:")
    for issue in val_issues:
        print(f"  [{issue['severity']}] {issue['cve_id']}: {issue['issue']}")

print("")

# All strict must be "detected"
if strict_detected < total:
    undetected = [e["cve_id"] for e in evidence if e["strict_mode"]["verdict"] != "detected"]
    print(f"FAIL: {total - strict_detected} CVE(s) not detected in strict mode: {', '.join(undetected)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs detected in strict mode")

# All hardened must be "prevented"
if hardened_prevented < total:
    vulnerable = [e["cve_id"] for e in evidence if e["hardened_mode"]["verdict"] != "prevented"]
    print(f"FAIL: {total - hardened_prevented} CVE(s) not prevented in hardened mode: {', '.join(vulnerable)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs prevented in hardened mode")

# All must have detection flags
if with_flags < total:
    missing = [e["cve_id"] for e in evidence if not e["strict_mode"]["detection_flags"]]
    print(f"FAIL: {total - with_flags} CVE(s) missing detection flags: {', '.join(missing)}")
    errors += 1
else:
    print(f"PASS: All {total} CVEs have strict detection flags")

# All must have unique dossier IDs
if dossier_count < total:
    print(f"FAIL: Only {dossier_count} unique dossier IDs for {total} scenarios")
    errors += 1
else:
    print(f"PASS: All {total} scenarios have unique dossier IDs")

# Evidence bundles must be joinable
joinable = all(
    set(["dossier_id", "cve_id", "test_name"]).issubset(set(e["evidence_bundle"]["joinable_on"]))
    for e in evidence
)
if not joinable:
    print("FAIL: Evidence bundles not joinable on required fields")
    errors += 1
else:
    print(f"PASS: All evidence bundles joinable on dossier_id/cve_id/test_name")

# No validation errors
if val_errors > 0:
    print(f"FAIL: {val_errors} validation error(s)")
    errors += 1
else:
    print(f"PASS: No validation errors")

if total == 0:
    print("FAIL: No paired scenarios found")
    errors += 1

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_cve_paired_mode_runner: PASS")
PY
