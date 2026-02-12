# Release Gate Runner Runbook (`bd-5fw.2`)

## Purpose
`scripts/release_dry_run.sh` executes a deterministic release gate DAG from `tests/conformance/release_gate_dag.v1.json` with fail-fast semantics and auditable resume tokens.

## Canonical Gate Order
1. `lint`
2. `unit`
3. `conformance`
4. `e2e`
5. `perf`
6. `docs_reports`
7. `release_dossier`

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

These fields are required by `tests/conformance/release_gate_dag.v1.json`.
