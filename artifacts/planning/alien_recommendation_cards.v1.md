# Alien Graveyard Recommendation Contracts (v1)

## Card 1
Change:
Active-horizon BOCPD optimization in `runtime_math::changepoint` + wave-2 migration of hot metadata reads to RCU/QSBR.
Hotspot evidence:
`ChangepointController::observe` is top hotspot in strict profile matrix; CPU share dropped from 60.45% to 52.38% after round-1 trimming.
Mapped graveyard sections:
`§0.1` profile-first loop, `§12.1` conformal calibration coupling, `§14.8` RCU/QSBR.
EV score (Impact * Confidence * Reuse / Effort * Friction):
`(5 * 4 * 4) / (2.5 * 1.8) = 17.78`.
Priority tier (S/A/B/C):
S
Adoption wedge (boundary/compatibility/rollout):
Keep strict behavior default; deploy RCU under feature-flag for read-mostly metadata first.
Budgeted mode (default budget + on-exhaustion behavior):
`cpu_budget_ns<=200` hot path; if exceeded for 2 consecutive runs, force conservative non-RCU path.
Expected-loss model (states/actions/loss):
States `{stable, drift, changepoint}`; actions `{fast, full}`; loss penalizes false-fast under drift > latency overhead under stable.
Calibration + fallback trigger:
Fallback if conformal coverage drift >3% for 3 windows or e-process alarm.
Isomorphism proof plan:
Per change: preserve update equations, MAP/state thresholds, and strict-mode action ordering; validate with changepoint unit tests + benchmark deltas.
p50/p95/p99 before/after target:
Target observe_fast strict `p95` from ~2.85us to <=2.60us; preserve/ improve p99.
Primary failure risk + countermeasure:
Risk: stalled grace period causing memory bloat. Countermeasure: retire-list caps + forced safe-mode downgrade.
Repro artifact pack (env/manifest/repro.lock/legal/provenance):
`artifacts/planning/changepoint_observe_isomorphism_proof.v1.md`, profile run dirs under `target/profiles/*`.
Primary paper status (hypothesis/read/reproduced + checklist state):
BOCPD reproduced in runtime; RCU in-progress (hypothesis->read->reproduce pending for this wave).
Interference test status (required when composing controllers):
Required: RCU + changepoint interactions under concurrent load (pending in bd-3aof).
Demo linkage (`demo_id` + `claim_id`, if production-facing):
Planned: `demo_id=frankenlibc-tsm-hotpath-rcu-v1`.
Rollback:
Feature flag off + revert single-wave commits.
Baseline comparator (what are we beating?):
Current strict runtime-math/membrane benches.
Linked open beads:
`bd-3aof`, `bd-1sp.1`, `bd-5vr`, `bd-32e`.

## Card 2
Change:
PCC fast-path at FFI boundary for proven-safe call sites (`memcpy`, `snprintf`, `malloc`) with strict fallback to full TSM.
Hotspot evidence:
FFI boundary checks are on every interposed call; reducing unnecessary validation for proven sites targets hot ABI path.
Mapped graveyard sections:
`§11.9` PCC, `§5.8` separation logic obligations, `§0.4` expected-loss decision core.
EV score (Impact * Confidence * Reuse / Effort * Friction):
`(4 * 3 * 4) / (4 * 2) = 6.0`.
Priority tier (S/A/B/C):
A
Adoption wedge (boundary/compatibility/rollout):
Thread-local proof token, ABI preserved, fallback path unchanged.
Budgeted mode (default budget + on-exhaustion behavior):
`verify_ns<=5` budget; if verification exceeds budget or fails, full TSM path.
Expected-loss model (states/actions/loss):
States `{proof_valid, proof_invalid, proof_missing}`; actions `{fast_path, full_tsm}`; high loss for false-valid acceptance.
Calibration + fallback trigger:
Disable PCC lane if invalid-proof rate >0.1% in rolling 100k calls.
Isomorphism proof plan:
Prove output/errno equivalence between fast-path and full path on accepted obligations.
p50/p95/p99 before/after target:
Target >10ns savings on proven call sites, no regression on unproven sites.
Primary failure risk + countermeasure:
Risk: verifier unsoundness. Countermeasure: tiny auditable checker + mandatory full fallback on ambiguity.
Repro artifact pack (env/manifest/repro.lock/legal/provenance):
Proof format doc + verifier tests + benchmark report.
Primary paper status (hypothesis/read/reproduced + checklist state):
Hypothesis/read in progress for this repo.
Interference test status (required when composing controllers):
Required with runtime policy table interactions.
Demo linkage (`demo_id` + `claim_id`, if production-facing):
Planned: `demo_id=ffi-pcc-fastpath-v1`.
Rollback:
Disable proof token gate and route all to full TSM.
Baseline comparator (what are we beating?):
Current ABI full-validation path.
Linked open beads:
`bd-1sp.7`, `bd-2uju`.

## Card 3
Change:
Seqlock-backed configuration/read-mostly control state for runtime policy hot reads.
Hotspot evidence:
Frequent read-side policy lookups in strict/hardened routing; lock contention risk in expanded workloads.
Mapped graveyard sections:
`§14.9` seqlocks, `§14.8` RCU/QSBR (complementary), `§0.15` tail decomposition.
EV score (Impact * Confidence * Reuse / Effort * Friction):
`(4 * 4 * 3) / (2 * 1.8) = 13.33`.
Priority tier (S/A/B/C):
S
Adoption wedge (boundary/compatibility/rollout):
Internal replacement only, no ABI/API changes.
Budgeted mode (default budget + on-exhaustion behavior):
Reader retry cap `<=8`; on exhaustion use mutex snapshot path and emit evidence event.
Expected-loss model (states/actions/loss):
States `{stable_reads, write_burst, starvation_risk}`; actions `{seqlock_read, snapshot_fallback}`.
Calibration + fallback trigger:
Fallback if retry p99 exceeds threshold for 3 windows.
Isomorphism proof plan:
Validate read snapshot equivalence and writer serialization invariants with loom tests.
p50/p95/p99 before/after target:
Target read-path p95 reduction >20% versus mutex baseline under 4-16 threads.
Primary failure risk + countermeasure:
Risk: reader starvation under write storms. Countermeasure: retry cap + deterministic fallback.
Repro artifact pack (env/manifest/repro.lock/legal/provenance):
Contention microbench pack + loom traces + artifact manifest.
Primary paper status (hypothesis/read/reproduced + checklist state):
Read status; reproduction pending.
Interference test status (required when composing controllers):
Required with RCU and policy-table updates.
Demo linkage (`demo_id` + `claim_id`, if production-facing):
Planned: `demo_id=runtime-policy-seqlock-v1`.
Rollback:
Feature flag to revert to existing lock path.
Baseline comparator (what are we beating?):
Current shared-state read synchronization.
Linked open beads:
`bd-1sp.3`, `bd-1d6e`.
