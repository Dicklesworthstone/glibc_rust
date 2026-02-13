# Release Gate Runner Runbook (`bd-5fw.2`, enhanced by `bd-w2c3.10.2`)

## Purpose
`scripts/release_dry_run.sh` executes a deterministic release gate DAG from `tests/conformance/release_gate_dag.v1.json` with fail-fast semantics and auditable resume tokens.

## Canonical Gate Order
1. `lint` - format, check, clippy
2. `unit` - workspace tests
3. `conformance` - golden fixture checksums
4. `conformance_coverage` - fixture coverage regression gate (bd-15n.3)
5. `claim_reconciliation` - FEATURE_PARITY/support/reality cross-check (bd-w2c3.10.1)
6. `e2e` - end-to-end test suite
7. `perf` - performance regression gate
8. `docs_reports` - support matrix drift, replacement levels, closure contract
9. `release_dossier` - closure evidence validation

Order is deterministic by contract policy: `topological_then_declared`.

## Standard Dry-Run
```bash
scripts/release_dry_run.sh --mode dry-run
```

Outputs:
- JSONL gate log: `/tmp/frankenlibc_release_gate_dry_run.log.jsonl`
- Resume state: `/tmp/frankenlibc_release_resume_state.json`
- Dossier summary: `/tmp/frankenlibc_release_dry_run_dossier.json`

## Simulate Fail-Fast
```bash
FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE=e2e \
  scripts/release_dry_run.sh --mode dry-run
```

Expected behavior:
- Runner stops immediately at `e2e`.
- State file includes deterministic `resume_token` such as `v1:<hash12>:3`.

## Deterministic Resume
```bash
TOKEN="$(jq -r '.resume_token' /tmp/frankenlibc_release_resume_state.json)"
scripts/release_dry_run.sh --mode dry-run --resume-token "$TOKEN"
```

Resume semantics:
- Gates before `start_index` are marked `resume_skip`.
- Execution restarts at the exact failing gate index.
- `resume_token` hash prefix must match current DAG/mode prereq hash.

## Real Execution Mode
```bash
scripts/release_dry_run.sh --mode run
```

`run` executes real gate commands from the DAG.

## Audit Fields (per gate log row)
- `trace_id`
- `gate_name`
- `prereq_hash`
- `status` (`pass` | `fail` | `resume_skip`)
- `duration_ms`
- `resume_token`
- `artifact_path` - path to gate report artifact (if applicable)
- `critical` - whether this gate blocks release
- `rationale` - human-readable pass/fail explanation

These fields are required by `tests/conformance/release_gate_dag.v1.json`.

## Dossier (v2)
The dossier output (schema_version: 2) includes:
- `summary` - total/passed/skipped/failed/verdict
- `artifact_index` - map of gate_name to report artifact paths
- `gates` - per-gate records with rationale and artifact links

## Blocker Chain (on failure)
When a gate fails, the state file includes `blocker_chain` showing all downstream gates blocked by the failure. This enables fast triage of cascading impacts.

## CI Gate
```bash
scripts/check_release_dry_run.sh
```

Validates dry-run pass and dossier schema completeness.
