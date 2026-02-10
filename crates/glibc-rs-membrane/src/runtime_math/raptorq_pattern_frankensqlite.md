# RaptorQ Pattern (FrankenSQLite) Restated For glibc_rust

Bead: `bd-11g`

Purpose: capture the *pattern-level* design so future implementation does not need to
re-read external specs. This is **not** a line-by-line port; it is an essence extraction.

## Why libc Wants This

Runtime math kernels already decide `Allow | FullValidate | Repair | Deny`. When something
goes wrong we need an audit trail that:
- survives partial loss (ring-buffer overwrite, sampling, crashes, dropped events),
- remains explainable offline,
- is deterministic and versioned.

The key idea is **appendable redundancy**:
- emit cheap *systematic* symbols on the fast path,
- optionally emit deterministic *repair* symbols on a cadence,
- decode and generate proofs offline (harness/tooling), never on the strict hot path.

## Constraints (glibc_rust-Specific)

- Runtime must not depend on `/dp/asupersync` (tooling only).
- Strict mode must not pay codec costs on the hot path.
- Hardened mode may pay bounded, measured costs on a cadence.
- Determinism is mandatory (seed derivation and schedules are stable and versioned).

## Portable Pattern (What We Copy)

### 1) Epoching / Source Blocks

Group a bounded window of evidence events into an **epoch**.

Each epoch defines:
- `K_source`: number of systematic records (source symbols)
- `T`: fixed symbol size in bytes (e.g., 64..256)
- `seed`: deterministic seed for repair generation

Epoch boundaries must be deterministic. Examples:
- every `N` decisions per family
- explicit phase boundary (e.g., after resample cadence)
- process lifecycle boundary (on exit / dlclose)

### 2) Systematic Fast Path

Emit raw evidence records as systematic symbols:
- `ESI = 0..K_source-1`

Implementation intent:
- cheap append into a ring buffer (memcpy + atomic seqno)
- contiguous layout to make export/decode friendly

### 3) Deterministic Repair Generation (Cadence-Only)

Generate repair symbols deterministically from:

`(epoch_id, K_source, T, policy_version, seed)`

Repair symbols use:
- `ESI = K_source..K_source+R-1`

Determinism is the superpower:
- tooling can reproduce the same schedule and validate repairs,
- proofs can cite inputs unambiguously.

### 4) Overhead = Additive Slack + Multiplicative Budget

Two knobs:

- additive decode slack:
  - `slack_decode = 2` (default starting point)
- multiplicative overhead budget:
  - `overhead_percent` (policy-controlled)

Repair count selection:

`R = max(slack_decode, ceil(K_source * overhead_percent / 100))`

Engineering approximation of loss tolerated:

`loss_fraction_max ~= max(0, (R - slack_decode) / (K_source + R))`

### 5) Anytime-Valid Tuning (Optional)

Use an anytime-valid monitor (e-process) to decide when to raise redundancy.

Required properties:
- optional stopping safe,
- deterministic updates (fixed-point),
- evidence ledger records all tuning changes.

### 6) Decode Proofs (Tooling Only)

Offline decode emits a `DecodeProof` describing:
- which symbols (ESI set) were used,
- reconstructed ranges,
- integrity checks (hash-chain, payload hashes),
- reasons for decode failure when it fails.

## Deterministic Seed Derivation

Portable rule:
- `seed = xxh3_64(id_bytes)` in FrankenSQLite-like systems

glibc_rust mapping recommendation:
- define a stable `epoch_id` including a monotonic counter,
- derive `seed` from a stable tuple:

`seed = H(epoch_id || build_id || mode || family)`

This avoids collisions across runs/modes while remaining deterministic.

## Evidence Record Mapping (Proposed)

Define a fixed-size `EvidenceSymbolRecord` envelope:

- Header:
  - `magic`, `version`
  - `epoch_id`, `seqno`
  - `family`, `mode`, `action`, `flags`
- Coding:
  - `esi`, `k_source`, `r_repair`, `symbol_size_T`, `seed`
- Integrity:
  - `payload_hash` (xxh3_128 or blake3)
  - `prev_hash` (hash-chain inside epoch)
- Payload:
  - fixed `T` bytes (pad if needed)

Strict mode:
- systematic-only by default (optionally counters-only if needed).

Hardened mode:
- systematic + optional cadence repair symbol generation.

## Where Decode Happens

- Runtime: encode only (systematic always; repair optional; cadence-only).
- Harness/tooling: decode + verify + produce proofs and diffs (FrankentUI).

## Open Decision (Explicit)

We still must decide (bead `bd-3a9`):
- runtime encoder shape: XOR-only fountain (LT-like) vs RaptorQ-compatible schedule vs
  "RaptorQ-inspired" parity with matching tooling decoder.

