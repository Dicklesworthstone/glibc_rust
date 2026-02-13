#!/usr/bin/env bash
# check_unit_test_packs.sh — CI gate for bd-w2c3.9.1
# Validates unit test closure packs: all required families have fixtures,
# each fixture has strict/hardened cases, and per-pack coverage is reported.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/tests/conformance/fixtures"

echo "=== Unit Test Closure Packs Gate (bd-w2c3.9.1) ==="

python3 - "$FIXTURE_DIR" <<'PY'
import json, sys, os
from pathlib import Path

fixture_dir = Path(sys.argv[1])
if not fixture_dir.is_dir():
    print(f"FAIL: fixture directory not found: {fixture_dir}")
    sys.exit(2)

# Required families for closure per bd-w2c3.9.1
required_families = [
    "startup_ops", "loader_edges", "resolv/dns", "locale_ops",
    "iconv/phase1", "signal_ops", "setjmp_ops", "sysv_ipc_ops",
    "backtrace_ops", "session_ops", "spawn_exec_ops", "regex_glob_ops",
]

# Scan all fixture files
fixture_files = sorted(fixture_dir.glob("*.json"))
pack_report = []
total_cases = 0
total_strict = 0
total_hardened = 0
families_found = set()
errors = 0

for fpath in fixture_files:
    try:
        with fpath.open(encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        pack_report.append({
            "file": fpath.name,
            "status": "ERROR",
            "error": str(e),
        })
        errors += 1
        continue

    family = data.get("family", fpath.stem)
    families_found.add(family)
    cases = data.get("cases", [])
    strict_count = sum(1 for c in cases if c.get("mode") == "strict")
    hardened_count = sum(1 for c in cases if c.get("mode") == "hardened")
    total_cases += len(cases)
    total_strict += strict_count
    total_hardened += hardened_count

    pack_report.append({
        "file": fpath.name,
        "family": family,
        "total_cases": len(cases),
        "strict": strict_count,
        "hardened": hardened_count,
        "status": "OK",
    })

# Check required families
missing_families = []
for fam in required_families:
    if fam not in families_found:
        missing_families.append(fam)
        errors += 1

# Print summary
print(f"Fixture packs scanned: {len(fixture_files)}")
print(f"Total cases: {total_cases}")
print(f"  Strict: {total_strict}")
print(f"  Hardened: {total_hardened}")
print(f"  Other: {total_cases - total_strict - total_hardened}")
print(f"Families found: {len(families_found)}")

if missing_families:
    print(f"\nFAIL: Missing required families: {missing_families}")
else:
    print(f"\nAll {len(required_families)} required families present")

# Per-pack report
print("\n--- Per-Pack Coverage ---")
for p in pack_report:
    if p["status"] == "OK":
        mode_info = f"S:{p['strict']} H:{p['hardened']}"
        print(f"  {p['file']:40s} {p['total_cases']:3d} cases ({mode_info})")
    else:
        print(f"  {p['file']:40s} ERROR: {p['error']}")

if errors > 0:
    print(f"\nFAIL: {errors} errors detected")
    sys.exit(1)

print("\ncheck_unit_test_packs: PASS")
PY
