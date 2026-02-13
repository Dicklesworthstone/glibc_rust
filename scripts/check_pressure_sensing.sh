#!/usr/bin/env bash
# check_pressure_sensing.sh — CI gate for bd-w2c3.7.1
# Validates: pressure sensor module compiles, unit tests pass,
# scenario fixture exists and is well-formed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Pressure Sensing Gate (bd-w2c3.7.1) ==="

# 1. Check module exists
MODULE="$REPO_ROOT/crates/frankenlibc-membrane/src/pressure_sensor.rs"
if [ ! -f "$MODULE" ]; then
    echo "FAIL: pressure_sensor.rs not found"
    exit 1
fi
echo "Module: $(wc -l < "$MODULE") lines"

# 2. Check fixture exists
FIXTURE="$REPO_ROOT/tests/conformance/fixtures/pressure_sensing.json"
if [ ! -f "$FIXTURE" ]; then
    echo "FAIL: pressure_sensing.json fixture not found"
    exit 1
fi

# 3. Check scenario fixture exists
SCENARIO="$REPO_ROOT/tests/conformance/pressure_sensing_scenarios.v1.json"
if [ ! -f "$SCENARIO" ]; then
    echo "FAIL: pressure_sensing_scenarios.v1.json not found"
    exit 1
fi

# 4. Validate fixture structure
python3 - "$FIXTURE" "$SCENARIO" <<'PY'
import json, sys

fixture_path = sys.argv[1]
scenario_path = sys.argv[2]
errors = 0

# Validate fixture
with open(fixture_path) as f:
    data = json.load(f)

cases = data.get("cases", [])
if not cases:
    print("FAIL: fixture has no cases")
    errors += 1
else:
    strict_count = sum(1 for c in cases if c.get("mode") == "strict")
    hardened_count = sum(1 for c in cases if c.get("mode") == "hardened")
    print(f"Fixture: {len(cases)} cases (strict={strict_count}, hardened={hardened_count})")
    if strict_count == 0:
        print("FAIL: no strict-mode cases")
        errors += 1
    if hardened_count == 0:
        print("FAIL: no hardened-mode cases")
        errors += 1

family = data.get("family", "")
if family != "pressure_sensing":
    print(f"FAIL: unexpected family '{family}'")
    errors += 1

# Validate scenario fixture
with open(scenario_path) as f:
    sdata = json.load(f)

scenarios = sdata.get("scenarios", [])
if not scenarios:
    print("FAIL: scenario fixture has no scenarios")
    errors += 1
else:
    print(f"Scenarios: {len(scenarios)}")

thresholds = sdata.get("thresholds", {})
required_threshold_keys = [
    "pressured_enter", "pressured_exit",
    "overloaded_enter", "overloaded_exit",
    "cooldown_epochs", "recovery_hold_epochs",
]
for key in required_threshold_keys:
    if key not in thresholds:
        print(f"FAIL: missing threshold key '{key}'")
        errors += 1

# Check threshold ordering
pe = thresholds.get("pressured_enter", 0)
px = thresholds.get("pressured_exit", 0)
oe = thresholds.get("overloaded_enter", 0)
ox = thresholds.get("overloaded_exit", 0)
if not (px < pe < oe and px < ox < oe):
    print(f"FAIL: threshold ordering invalid: exit<enter, pressured<overloaded")
    errors += 1
else:
    print(f"Thresholds: valid ordering (PE={pe} > PX={px}, OE={oe} > OX={ox})")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print("\ncheck_pressure_sensing: PASS")
PY
