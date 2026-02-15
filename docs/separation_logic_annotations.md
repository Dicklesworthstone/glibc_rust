# Separation Logic Annotations (TSM)

This document defines the annotation contract for `bd-3ohk` and maps the required
TSM entrypoints to the concrete functions currently implementing those semantics.

## Annotation Tags

Each annotated function must include:

- `@separation-pre`
- `@separation-post`
- `@separation-frame`
- `@separation-alias`

The tags are intentionally plain doc-comment markers so they can be parsed by
deterministic CI scripts without requiring a verifier runtime.

## Entrypoint Mapping

| Alias | Concrete Function | File | Mechanical Status |
|---|---|---|---|
| `validate_pointer` | `ValidationPipeline::validate` | `crates/frankenlibc-membrane/src/ptr_validator.rs` | Manual-only |
| `generation_check` | `AllocationArena::lookup` | `crates/frankenlibc-membrane/src/arena.rs` | Manual-only |
| `check_bounds` | `AllocationArena::remaining_from` | `crates/frankenlibc-membrane/src/arena.rs` | Manual-only |
| `quarantine_enter` | `AllocationArena::free` | `crates/frankenlibc-membrane/src/arena.rs` | Manual-only |
| `repair_apply` | `HealingPolicy::record` | `crates/frankenlibc-membrane/src/heal.rs` | Manual-only |

## Audit Gate

Run:

```bash
scripts/check_separation_logic_annotations.sh
```

Strict mode (non-zero exit on missing tags):

```bash
scripts/check_separation_logic_annotations.sh --strict
```

The script emits a structured JSON summary with:

- `annotated`
- `verified_mechanical`
- `verified_manual`
- `coverage_pct`
- per-target coverage/missing records

`verified_mechanical` is currently `0` because Prusti/Creusot integration is not
wired in this repository yet. This file and the audit script keep the mapping explicit
until a mechanical verifier pipeline is added.
