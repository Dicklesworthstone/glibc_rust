# Alpha-Investing FDR Controller (Design)

Goal: control the rate of *unnecessary* runtime escalations (`Fast -> FullValidate/Repair`)
when many online monitors contribute signals. Naively summing "risk bonuses" leads to
frequent full checks even in benign regimes. We want a sequential controller with:

- formal control over false alarms under optional stopping,
- O(1) per-candidate update, no allocations,
- lock-free / contention-safe state updates,
- mode-aware loss tradeoffs (strict vs hardened).

This is a *design-only* document for beads `bd-2fz`. Implementation is `bd-9co` + integration
`bd-3kz`.

## Definitions (Runtime Translation of FDR)

We define a "candidate test" only when the base controller would otherwise escalate:

- `candidate := base_action in {FullValidate, Repair(..)}`

For each candidate, we run a sequential hypothesis test:

- H0: escalating here is unnecessary (full validation would find `adverse = false`)
- H1: escalating here is necessary (full validation would find `adverse = true`)

We define the observable outcomes for *rejected* candidates (the only ones we execute):

- Reject: we permit escalation and execute full validation/repair.
- Discovery: `adverse = true` observed by the executed full validation/repair.
- False discovery: reject but `adverse = false`.

We target control of **mFDR** (modified FDR):

    mFDR = E[V] / E[R + 1]

where `V` is false discoveries and `R` is number of rejections (escalations executed).

## Evidence Source: e-values -> p-values (Anytime-Valid)

The existing `runtime_math::eprocess` maintains an anytime-valid e-process per `ApiFamily`.
Under H0, its e-value is a nonnegative supermartingale with expectation <= 1, even with
optional stopping.

We convert an e-value `E_t` to a conservative p-value:

    p_t = min(1, 1 / E_t)

Then for any `alpha in (0, 1]`:

    P(p_t <= alpha) = P(E_t >= 1/alpha) <= alpha

So `p_t` is super-uniform under H0 without requiring a fixed horizon.

Implementation detail for strict hot path:
- Avoid `exp/ln` per-call. Compare in log-space:
  - Let `logE_t = ln(E_t)` (already stored as fixed-point `log_e_scaled` in eprocess).
  - Condition `p_t <= alpha` is equivalent to `E_t >= 1/alpha` which is:

        logE_t >= -ln(alpha)

We will add (or reuse, if already present) a lightweight accessor:
- `AnytimeEProcessMonitor::log_e_scaled(family) -> i64`

and compute `-ln(alpha)` via either:
- a small lookup table indexed by `alpha_milli` (0..=1000), or
- fixed-point `ln` helper from `bd-gn9` (preferred, shared infra).

## Controller State (Fixed-Point, Per-Family)

We keep one controller per `ApiFamily` (array-of-structs or struct-of-arrays):

- `wealth_milli[f] : AtomicU16/AtomicU32`
  - alpha-wealth in milli-units: 1 milli = 0.001
- `spent_milli_total[f] : AtomicU64` (telemetry)
- `tests[f] : AtomicU64` (candidate count)
- `rejects[f] : AtomicU64` (executed escalations)
- `false_rejects[f] : AtomicU64` (reject + adverse=false)
- `true_rejects[f] : AtomicU64` (reject + adverse=true)

No allocations; all updates are atomic.

## Decision Rule (Alpha-Investing)

On each `candidate`:

1. Choose spending amount `alpha_spend_milli` from current wealth and mode.
2. Spend it (wealth decreases) regardless of reject outcome.
3. Compute `p_t` from eprocess (log-space compare).
4. If `p_t <= alpha_spend`, reject and permit escalation; else downgrade action.

We use a mode-aware spend function:

    alpha_spend_milli = clamp(alpha_min, alpha_max, f(wealth_milli, mode, family, risk_ppm))

where `f` is a simple fixed-point policy (examples below).

### Reward / Wealth Update

Classic alpha-investing updates wealth on rejection. Here we can do better: since we execute
full validation only on rejection, we can observe whether the escalation was actually needed.
To be conservative (and to keep overhead low in benign regimes), we *reward only on true
discoveries*:

    wealth' = clamp(wealth - alpha_spend + reward_milli * I(adverse), 0..W_MAX)

This makes wealth growth strictly harder than classic alpha-investing, which can only
decrease the false-discovery rate (it reduces the number of future rejections).

## Loss Matrix (Mode-Aware)

We tune `alpha_min/alpha_max/spend_frac/reward` using an explicit loss matrix.
We model a binary decision per candidate: `Escalate` vs `Skip`.

Strict mode (performance-first, ABI preservation):

| Outcome | Escalate | Skip |
|---|---:|---:|
| adverse=true  |  1  |  50 |
| adverse=false |  10 |   0 |

Hardened mode (safety-first, repair allowed):

| Outcome | Escalate | Skip |
|---|---:|---:|
| adverse=true  |  1  | 200 |
| adverse=false |  5  |   0 |

Interpretation:
- "Escalate, adverse=false" is pure overhead (false discovery).
- "Skip, adverse=true" is the costly miss (false decrease); it is far more expensive in
  hardened mode.

These losses justify:
- higher initial wealth / reward in hardened mode,
- higher spend fractions in hardened mode,
- tighter caps in strict mode to protect <20ns fast-path budget.

## Parameter Sketch (Concrete Defaults)

These are starting points; we will iterate with conformance + perf gates.

Strict:
- `W0_milli = 5`        (0.005)
- `W_MAX_milli = 25`    (cap at 0.025)
- `alpha_min_milli = 1` (0.001)
- `alpha_max_milli = 5` (0.005)
- `spend_frac_milli = 200` (spend 20% of current wealth on each candidate)
- `reward_milli = 2`    (0.002, only on adverse=true)

Hardened:
- `W0_milli = 50`        (0.05)
- `W_MAX_milli = 200`    (0.20)
- `alpha_min_milli = 2`  (0.002)
- `alpha_max_milli = 25` (0.025)
- `spend_frac_milli = 250` (25%)
- `reward_milli = 10`    (0.01, only on adverse=true)

Family weighting (optional, still O(1)):
- multiply `spend_frac_milli` by a small per-family weight if some families have
  systematically higher escalation costs (e.g., pointer validation vs locale).

## Integration Points (decide/observe)

Where to hook into the existing runtime kernel:

1. `RuntimeMathKernel::decide(...)` (hot path)
   - compute base `profile` + `action` as today
   - if `candidate(action)`:
     - read `log_e_scaled` for the family from `self.anytime`
     - run `AlphaInvestingFdr::gate(...)`
     - if gate rejects: keep action
     - else: downgrade:
       - `FullValidate -> Allow`
       - `Repair(..)  -> Allow` (or `Allow` unless hard barriers demand Deny)
   - return `RuntimeDecision` augmented with:
     - `fdr_spend_milli: u16`
     - `fdr_rejected: bool`
   (so observe can update wealth deterministically without TLS/global state)

2. `RuntimeMathKernel::observe_validation_result(...)`
   - if decision carried `fdr_spend_milli > 0`:
     - call `AlphaInvestingFdr::observe(family, spend_milli, adverse)`

3. Telemetry
   - export per-family wealth and false/true reject counts via snapshot harness
     (tie into `RuntimeKernelSnapshot` fields on a stable cadence).

## Invariants (Must Hold)

For each family `f`:

- `0 <= wealth_milli[f] <= W_MAX_milli`
- `alpha_spend_milli <= wealth_before_spend`
- wealth update is monotone non-increasing when `adverse=false`:
  - `adverse=false => wealth' <= wealth_before_spend`
- bounded per-candidate work:
  - constant number of atomics + integer ops, no heap allocs
- no negative wealth under races:
  - use `compare_exchange` loops for spend/reward updates

## Complexity / Overhead Notes

- `candidate` rate is controlled by existing risk thresholds. FDR gating runs only on
  candidates (not every call).
- Strict hot path: avoid float math. Use fixed-point `log_e_scaled` and precomputed
  `-ln(alpha)` thresholds or `bd-gn9` fixed-point `ln`.
- All state is lock-free; no `Mutex` / no allocations.

## Open Questions (Resolved During Implementation)

- Whether to maintain a *global* wealth pool in addition to per-family wealth to prevent
  one family dominating total overhead.
- Whether "candidate" should include `profile.requires_full()` or only hard risk-trigger
  cases.
- How to expose the gating decision in `policy_id` for evidence logs without growing
  the hot-path struct too much.

