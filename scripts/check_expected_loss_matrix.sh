#!/usr/bin/env bash
# check_expected_loss_matrix.sh — Validate expected-loss policy matrix artifact (bd-35a).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MATRIX="$REPO_ROOT/tests/runtime_math/expected_loss_matrix.v1.json"

if [[ ! -f "$MATRIX" ]]; then
    echo "ERROR: expected-loss matrix not found at $MATRIX" >&2
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: jq is required" >&2
    exit 1
fi

status=0

if ! jq -e '.schema_version == "v1"' "$MATRIX" >/dev/null; then
    echo "ERROR: schema_version must be v1"
    status=1
fi
if ! jq -e '.actions == ["allow","full_validate","repair","deny"]' "$MATRIX" >/dev/null; then
    echo "ERROR: actions must equal [allow, full_validate, repair, deny]"
    status=1
fi
if ! jq -e '.posterior_model.initial_alpha == 1 and .posterior_model.initial_beta == 1' "$MATRIX" >/dev/null; then
    echo "ERROR: posterior_model initial_alpha/initial_beta must both be 1"
    status=1
fi
if ! jq -e '(.assumptions | type == "array" and length >= 3)' "$MATRIX" >/dev/null; then
    echo "ERROR: assumptions[] must contain at least 3 entries"
    status=1
fi
if ! jq -e '(.sensitivity_analysis.posterior_grid | type == "array" and length >= 5)' "$MATRIX" >/dev/null; then
    echo "ERROR: sensitivity_analysis.posterior_grid must contain at least 5 points"
    status=1
fi
if ! jq -e '(.sensitivity_analysis.cost_norm_grid | type == "array" and length >= 5)' "$MATRIX" >/dev/null; then
    echo "ERROR: sensitivity_analysis.cost_norm_grid must contain at least 5 points"
    status=1
fi

families=(
    PointerValidation Allocator StringMemory Stdio Threading Resolver MathFenv Loader Stdlib Ctype
    Time Signal IoFd Socket Locale Termios Inet Process VirtualMemory Poll
)

actions=(allow full_validate repair deny)
fields=(clean_intercept adverse_intercept clean_cost_factor adverse_cost_factor)

for family in "${families[@]}"; do
    if ! jq -e --arg f "$family" '.families[$f] != null' "$MATRIX" >/dev/null; then
        echo "ERROR: missing family '$family' in matrix"
        status=1
        continue
    fi

    for action in "${actions[@]}"; do
        for field in "${fields[@]}"; do
            if ! jq -e --arg f "$family" --arg a "$action" --arg k "$field" '(.families[$f][$a][$k] | type == "number")' "$MATRIX" >/dev/null; then
                echo "ERROR: $family.$action missing numeric field '$field'"
                status=1
            fi
        done
    done
done

family_count=$(jq '.families | keys | length' "$MATRIX")
if [[ "$family_count" -ne 20 ]]; then
    echo "ERROR: expected exactly 20 API families, found $family_count"
    status=1
fi

if [[ $status -ne 0 ]]; then
    echo ""
    echo "expected-loss matrix validation FAILED"
    exit 1
fi

echo "OK: expected-loss matrix validated for 20 families with posterior/assumption/sensitivity sections."
