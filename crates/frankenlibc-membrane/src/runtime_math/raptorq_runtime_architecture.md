# RaptorQ-Inspired Runtime Evidence: Architecture Decision

Bead: `bd-3a9`

Status: Accepted (2026-02-10)

## Context

We want an audit-grade evidence trail for membrane decisions that:
- survives partial loss (ring buffer overwrites, sampling, crashes),
- remains explainable offline (decode proofs, failure reasons),
- is deterministic and versioned,
- does not violate strict/hardened budgets.

Hard constraints:
- libc runtime must not depend on `/dp/asupersync` or `/dp/frankentui` (tooling only).
- strict mode must not pay codec costs on the hot path.
- hardened mode may pay bounded costs, but heavy work must be cadence-only.

## Decision Summary

1. Runtime emits **systematic evidence symbols** in both modes (configurable), but:
   - strict mode default: **systematic off** (metrics only), unless explicitly enabled.
   - hardened mode default: **systematic on** for adverse / repaired / denied paths.
2. Runtime generates **deterministic repair symbols** only in hardened mode and only on a
   fixed cadence (never inside the strict fast path).
3. Runtime codec is **RaptorQ-inspired but not full RFC6330**:
   - encoding uses XOR-only LT-like repair symbols derived from a deterministic schedule.
   - no GF(256) Gaussian solve (ever) in libc runtime.
4. Decode + proof verification are **tooling-only**:
   - `frankenlibc-harness` depends on `/dp/asupersync` and performs decode/proof generation,
     rendering deterministic diffs via FrankentUI.

Rationale:
- keeps libc runtime code small and deterministic,
- preserves strict-mode hot-path budget,
- still achieves "appendable redundancy" and offline explainability.

## Object Model

### Epoch

An **epoch** is the unit of coding/decoding.

Epoch parameters (fixed for v1):
- `T` (symbol size): 128 bytes
- `K_max` (max systematic symbols per epoch): 256
- `slack_decode`: 2 (additive)
- `overhead_percent`: policy-controlled (default 10% in hardened)

Epoch identity:
- `epoch_id: u64` derived deterministically from:
  - `(mode, family, epoch_counter)` and a per-process boot nonce

Epoch lifecycle:
- systematic records appended until `K_max` or explicit finalize
- finalized epochs may receive `R` repair symbols on cadence

### EvidenceSymbolRecord (Envelope)

Each record is fixed-size and self-describing:

- Header:
  - `magic`, `version`
  - `epoch_id`, `seqno`
  - `family`, `mode`, `action`, `flags`
- Coding:
  - `esi`, `k_source`, `r_repair`, `symbol_size_T`, `seed`
- Integrity:
  - `payload_hash` (64-bit or 128-bit; chosen below)
  - `prev_hash` (hash-chain within epoch)
- Payload:
  - exactly `T` bytes (pad with zeros)

Storage:
- a bounded in-memory ring buffer (lock-free indices; overwrite-on-full)

Export:
- tooling reads via an explicit harness integration path (not decided here).
- no file I/O on the hot path.

## Repair Symbol Generation (Runtime)

Repair count:

`R = max(slack_decode, ceil(K_source * overhead_percent / 100))`

Repair schedule:
- deterministic from `(epoch_seed, esi, K_source)`
- XOR of a deterministic subset of source symbols
- subset size distribution favors small degrees (peeling-decoder friendly)

### Deterministic XOR Schedule (v1)

This project’s v1 schedule is intentionally simpler than RFC6330 RaptorQ. It is:
- XOR-only (bytewise XOR of selected systematic payload symbols)
- deterministic and versioned (stable inputs -> stable outputs)
- biased toward small degrees (peeling-friendly)

Concrete v1 algorithm (implemented in `runtime_math/evidence.rs`):
- Repair ESIs are `esi = K_source + i` for `i in 0..R`.
- PRNG: `splitmix64_next` seeded from `(epoch_seed, esi, K_source)` with domain separation.
- Degree:
  - `degree = 1 + min(trailing_zeros(u), REPAIR_MAX_DEGREE_V1-1)` for PRNG output `u`
  - clamped to `K_source`
- Indices:
  - propose `idx = next_u64 % K_source`
  - resolve duplicates via deterministic linear probing (wrap-around)

Encoding cost:
- occurs only on cadence (e.g., every 256 decisions or epoch finalize)
- bounded by `(R * avg_degree * T)` per epoch

Strict-mode rule:
- strict mode never generates repair symbols.

## Integrity / Tamper Evidence

Minimum integrity in libc runtime (v1):
- `payload_hash`: xxh3_64 over payload (fast; non-cryptographic)
- `prev_hash`: xxh3_64 over (prev_hash || header || coding || payload_hash)

Tooling verification:
- validates hash-chain consistency
- validates that repair symbols match deterministic schedule for the epoch seed

Optional (future):
- replace xxh3_64 with blake3 keyed MAC in tooling-only pipelines when adversarial tamper
  resistance is required.

## Strict vs Hardened Behavior

Strict:
- default: no evidence symbols (metrics only)
- optional: systematic-only recording when explicitly enabled
- never: repair symbol generation

Hardened:
- systematic symbols recorded for adverse/repair/deny paths by default
- repair symbols generated on cadence under budget control

## Tooling (Harness) Responsibilities

Tooling may depend on `/dp/asupersync` and `/dp/frankentui`:
- ingest exported symbol stream
- attempt decode / reconstruction
- emit `DecodeProof`:
  - ESI set used, reconstructed coverage, hash-chain validation
  - explainable failure reasons when decode fails
- render deterministic diffs in FrankentUI

## Alternatives Considered

1. Full RFC6330 RaptorQ codec in libc runtime:
   - rejected: too much complexity and risk for hot-path budget discipline.
2. Systematic-only (no repair symbols):
   - rejected: does not provide resilience under partial loss.
3. Runtime depends on `/dp/asupersync` codec:
   - forbidden by constraints (tooling-only dependency).

## Consequences

- We will implement a small XOR-only encoder in `frankenlibc-membrane` (cadence-only).
- Harness will own decoding/proof generation and may iterate independently.
- If later we want RFC6330 compatibility, we can version-bump the record format and
  introduce a different `codec_id` while keeping the same envelope.
