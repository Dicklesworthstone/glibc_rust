# Changepoint Observe Optimization Round 1

## Change
Two one-lever optimization waves in `ChangepointController::observe`:
1. Active-horizon trimming to skip trailing run-length states with posterior mass below `1e-300`.
2. Scratch-buffer reuse for next-step posterior/stat vectors to remove per-call stack array churn.

## Isomorphism Proof
- Ordering preserved: yes. Bayesian update order (predictive likelihood -> hazard split -> reset/growth -> normalize -> state transition) is unchanged.
- Tie-breaking unchanged: yes. MAP run-length scan and state thresholds are unchanged.
- Floating-point drift: bounded/no semantic drift expected. Same equations and threshold floor already used in-loop (`prior < 1e-300`) are now also used for horizon bounds.
- RNG seeds: N/A (no randomness).
- Golden outputs: changepoint unit suite passes, including new regression for tail trimming.

## Validation Commands
- `cargo test -p frankenlibc-membrane runtime_math::changepoint::tests:: -- --nocapture`
- `hyperfine --warmup 2 --runs 6 'FRANKENLIBC_MODE=strict cargo bench -p frankenlibc-bench --bench runtime_math_bench -- --profile-time 1 --exact runtime_math/observe_fast/strict >/tmp/changepoint_before_observe_fast.log'`
- `hyperfine --warmup 2 --runs 6 'FRANKENLIBC_MODE=strict cargo bench -p frankenlibc-bench --bench runtime_math_bench -- --profile-time 1 --exact runtime_math/observe_fast/strict >/tmp/changepoint_after_observe_fast.log'`

## Before / After (observe_fast, strict)
From benchmark logs:
- Before: `p50=2498.561 ns/op`, `p95=2849.750 ns/op`, `p99=3372.324 ns/op`, `throughput=489478.640 ops/s`
- After: `p50=2444.233 ns/op`, `p95=2813.375 ns/op`, `p99=2829.047 ns/op`, `throughput=506500.446 ops/s`
- Delta: `p50 -2.17%`, `p95 -1.28%`, `p99 -16.11%`, `throughput +3.48%`

Hyperfine command-time envelope (`cargo bench ... observe_fast/strict`):
- Before: `mean 1.242s ± 0.016s` (6 runs)
- After: `mean 1.234s ± 0.017s` (6 runs)

From profile hotspot share (`runtime_math_observe_fast_strict` top CPU symbol):
- Before: `ChangepointController::observe` = `60.45%`
- After: `ChangepointController::observe` = `56.02%`
- Delta: `-7.33%` relative share

## Rollback
`git revert <commit>` (single-file change in `crates/frankenlibc-membrane/src/runtime_math/changepoint.rs`).

## Baseline Comparator
Strict-mode runtime-math benchmark path:
`cargo bench -p frankenlibc-bench --bench runtime_math_bench -- --profile-time 1 --exact runtime_math/observe_fast/strict`
