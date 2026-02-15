#!/usr/bin/env bash
set -euo pipefail

STRICT=0
if [[ "${1:-}" == "--strict" ]]; then
  STRICT=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$REPO_ROOT" "$STRICT" <<'PY'
import json
import pathlib
import re
import sys

repo_root = pathlib.Path(sys.argv[1])
strict = sys.argv[2] == "1"

required_targets = [
    {
        "alias": "validate_pointer",
        "file": "crates/frankenlibc-membrane/src/ptr_validator.rs",
        "fn": "validate",
    },
    {
        "alias": "generation_check",
        "file": "crates/frankenlibc-membrane/src/arena.rs",
        "fn": "lookup",
    },
    {
        "alias": "check_bounds",
        "file": "crates/frankenlibc-membrane/src/arena.rs",
        "fn": "remaining_from",
    },
    {
        "alias": "quarantine_enter",
        "file": "crates/frankenlibc-membrane/src/arena.rs",
        "fn": "free",
    },
    {
        "alias": "repair_apply",
        "file": "crates/frankenlibc-membrane/src/heal.rs",
        "fn": "record",
    },
]

required_tags = ["@separation-pre", "@separation-post", "@separation-frame", "@separation-alias"]

covered = []
missing = []

for target in required_targets:
    file_path = repo_root / target["file"]
    lines = file_path.read_text(encoding="utf-8").splitlines()

    fn_re = re.compile(rf"^\s*pub fn {re.escape(target['fn'])}\b")
    fn_line = None
    for idx, line in enumerate(lines):
        if fn_re.search(line):
            fn_line = idx
            break

    if fn_line is None:
        missing.append(
            {
                "alias": target["alias"],
                "file": target["file"],
                "function": target["fn"],
                "reason": "function_not_found",
            }
        )
        continue

    window_start = max(0, fn_line - 18)
    annotation_block = "\n".join(lines[window_start:fn_line])
    missing_tags = [tag for tag in required_tags if tag not in annotation_block]
    alias_ok = f"@separation-alias: `{target['alias']}`" in annotation_block
    if alias_ok:
        missing_tags = [tag for tag in missing_tags if tag != "@separation-alias"]
    else:
        if "@separation-alias" not in missing_tags:
            missing_tags.append("@separation-alias")

    if missing_tags:
        missing.append(
            {
                "alias": target["alias"],
                "file": target["file"],
                "function": target["fn"],
                "line": fn_line + 1,
                "missing_tags": missing_tags,
            }
        )
    else:
        covered.append(
            {
                "alias": target["alias"],
                "file": target["file"],
                "function": target["fn"],
                "line": fn_line + 1,
            }
        )

coverage_pct = 100.0
if required_targets:
    coverage_pct = round((len(covered) / len(required_targets)) * 100.0, 2)

report = {
    "annotated": len(covered),
    "verified_mechanical": 0,
    "verified_manual": len(covered),
    "coverage_pct": coverage_pct,
    "targets": len(required_targets),
    "covered": covered,
    "missing": missing,
}

print(json.dumps(report, indent=2, sort_keys=True))

for entry in missing:
    sys.stderr.write(
        "WARNING: missing separation-logic annotation tags for "
        f"{entry['alias']} at {entry['file']}::{entry['function']}\n"
    )

if strict and missing:
    sys.exit(1)
PY
