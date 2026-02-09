# FEATURE_PARITY.md

## Current Reality

This repository is currently in **spec/architecture stage**. No libc API is marked implemented yet.

Legend:
- `DONE`: implemented + conformance fixture pass + benchmark status recorded
- `IN_PROGRESS`: implementation underway but gates incomplete
- `PLANNED`: specified but not implemented

## Macro Coverage Targets

| Area | Target | Status |
|---|---|---|
| POSIX API surface | Full coverage | PLANNED |
| ABI symbol/version fidelity | Target-compatible | PLANNED |
| Strict mode conformance | Differentially equivalent on defined behavior | PLANNED |
| Hardened mode safety | Deterministic repair/deny coverage on unsafe patterns | PLANNED |
| Transparent Safety Membrane enforcement | All pointer-sensitive APIs | PLANNED |
| Conformance harness | Fixture-driven | IN_PROGRESS |
| Benchmark gates | Regression-blocking | PLANNED |

## Bootstrap Slice

| Family | Representative APIs | Status |
|---|---|---|
| memory ops | `memcpy`, `memmove`, `memset`, `memcmp`, `memchr`, `memrchr` | IN_PROGRESS |
| string ops | `strlen`, `strcmp`, `strncpy`, `strstr`, `strtok`, `strtok_r`, `strchr`, `strrchr`, `strcpy`, `strcat`, `strncat`, `strncmp` | IN_PROGRESS |
| wide string ops | `wcslen`, `wcscpy`, `wcscmp` | IN_PROGRESS |
| allocator boundary | `malloc`, `free`, `realloc`, `calloc` | IN_PROGRESS |

## Mode-Specific Parity Matrix

| Family | Strict Mode | Hardened Mode | Status |
|---|---|---|---|
| memory ops | host-glibc differential parity | policy-validated clamp/truncate/deny | PLANNED |
| string ops | host-glibc differential parity | termination-safe repair paths | PLANNED |
| allocator boundary | host-glibc parity for defined behavior | temporal/provenance repair policies | PLANNED |

## Runtime Math Kernel Matrix

| Runtime Kernel | Live Role | Status |
|---|---|---|
| `runtime_math::risk` | online risk upper bound per API family (`risk_upper_bound_ppm`) | IN_PROGRESS |
| `runtime_math::bandit` | constrained `Fast` vs `Full` validation-depth routing | IN_PROGRESS |
| `runtime_math::control` | primal-dual runtime threshold tuning | IN_PROGRESS |
| `runtime_math::barrier` | constant-time admissibility guard | IN_PROGRESS |
| `runtime_math::cohomology` | overlap-consistency fault detection for sharded metadata | IN_PROGRESS |
| sampled conformal risk fusion (`risk_engine`) | sampled high-order conformal alarm/full-check signal feeds live risk bonus | DONE |
| sampled stage-order oracle fusion (`check_oracle`) | sampled contextual ordering feeds cached runtime profile bias | DONE |
| quarantine controller fusion (`quarantine_controller`) | allocator observations feed primal-dual quarantine depth publication | DONE |
| tropical latency compositor (`tropical_latency`) | min-plus (tropical) algebra for provable worst-case pipeline latency bounds | DONE |
| spectral phase monitor (`spectral_monitor`) | Marchenko-Pastur / Tracy-Widom random matrix theory phase transition detection | DONE |
| pointer validator integration | runtime-math decisions affect bloom-miss/deep-check behavior | DONE |
| allocator integration | runtime-math routing at `malloc/free/realloc` boundary | PLANNED |
| string/memory integration | runtime-math routing for copy/string families | PLANNED |
| pthread/futex integration | runtime-math routing for wait/lock/cancel edges | PLANNED |
| resolver/NSS integration | runtime-math routing for retry/cache/poisoning decisions | PLANNED |

## Reverse Core Coverage Matrix

| Surface | Failure Target | Required Runtime Artifact | Status |
|---|---|---|---|
| loader/symbol/IFUNC | global compatibility drift | resolver automata + compatibility witness ledgers | PLANNED |
| allocator | temporal/provenance corruption | allocator policy tables + admissibility guards | IN_PROGRESS |
| hot string/memory kernels | overlap/alignment/dispatch edge faults | regime classifier + certified kernel routing tables | IN_PROGRESS |
| futex/pthread/cancellation | race/starvation/timeout inconsistency | transition kernels + fairness budgets | PLANNED |
| stdio/parser/locale formatting | parser-state explosion + locale divergence | generated parser/transducer tables | PLANNED |
| signal/setjmp transfer | invalid non-local transitions | admissible jump/signal/cancel transition matrices | PLANNED |
| time/timezone/rt timers | discontinuity/overrun semantic drift | temporal transition DAGs + timing envelopes | PLANNED |
| nss/resolv/nscd/sunrpc | poisoning/retry/cache instability | deterministic lookup DAGs + calibrated anomaly thresholds | PLANNED |
| locale/iconv/transliteration | conversion-state inconsistency | minimized codec automata + consistency certificates | PLANNED |
| ABI/time64/layout bridges | release compatibility fracture | invariant ledgers + drift alarms | PLANNED |
| VM transitions | unsafe map/protection trajectories | VM transition guard complexes | PLANNED |
| strict/hardened decision layer | threshold calibration drift | coverage-certified decision sets + abstain/escalate gates | PLANNED |
| process bootstrap (`csu`, TLS init, auxv, secure mode) | init-order races + secure-mode misclassification | startup dependency DAG + secure-mode policy automaton + init witness hashes | PLANNED |
| cross-ISA syscall glue (`sysdeps/*`) | architecture-specific semantic drift | per-ISA obligation matrices + dispatch witness cache | PLANNED |
| System V IPC (`sysvipc`) | capability drift + semaphore deadlock trajectories | semaphore admissibility guard polytopes + deadlock-cut certificates | PLANNED |
| i18n catalogs (`intl`, `catgets`, `localedata`) | fallback incoherence + catalog/version skew | catalog resolution automata + locale-consistency witness hashes | PLANNED |
| diagnostics/unwinding (`debug`, backtrace) | unsafe/non-deterministic frame-walk behavior | unwind stratification tables + safe-cut fallback matrix | PLANNED |
| session accounting (`login`, `utmp/wtmp`) | replay/tamper ambiguity + racey state updates | deterministic session-ledger transitions + anomaly thresholds | PLANNED |
| profiling hooks (`gmon`, sampling/probe paths) | probe-induced benchmark distortion | minimal probe schedules + deterministic debias weights | PLANNED |
| floating-point edges (`soft-fp`, `fenv` exceptional paths) | denormal/NaN/payload drift across regimes | regime-indexed numeric guard tables + certified fallback kernels | PLANNED |

## TSM Coverage Matrix (Planned)

| Safety Dimension | Description | Status |
|---|---|---|
| provenance checks | track pointer origin/ownership | PLANNED |
| bounds checks | enforce region length constraints | PLANNED |
| temporal checks | detect freed/quarantined states | PLANNED |
| repair policies | clamp/truncate/no-op/deny deterministic fixes | PLANNED |
| evidence logging | record repaired/denied operations | PLANNED |

## Legacy-Driven Engine Matrix

| Engine | Legacy Anchors | Required Artifact Class | Status |
|---|---|---|---|
| loader engine | `elf`, `sysdeps/*/dl-*` | symbol-scope automata + relocation envelopes | PLANNED |
| allocator-thread engine | `malloc`, `nptl` | contention control policies + safety certificates | PLANNED |
| format-locale engine | `stdio-common`, `wcsmbs`, `locale` | parser/transducer generated artifacts | PLANNED |
| name-service engine | `nss`, `resolv` | lookup policy DAG + anomaly confidence reports | PLANNED |
| numeric engine | `math`, `soft-fp`, `sysdeps/ieee754` | ULP/error/fenv proof bundles | PLANNED |
| cross-ISA glue engine | `sysdeps` | ISA witness bundles + campaign coverage proofs | PLANNED |
| stream-syscall engine | `libio`, `io`, `posix` | stream automata + lock/flush strategy certificates | PLANNED |
| locale-encoding engine | `localedata`, `locale`, `iconvdata`, `iconv`, `wcsmbs` | codec factorization proofs + locale-consistency diagnostics | PLANNED |
| temporal semantics engine | `time`, `timezone` | DST/leap transition proofs + temporal drift reports | PLANNED |
| cache-rpc coherence engine | `nscd`, `sunrpc`, `nss`, `resolv` | security-game equilibria + tail-risk bounds + coherence witnesses | PLANNED |
| bootstrap-observability engine | `csu`, `debug`, `support` | init-order proofs + observability-optimal probe sets | PLANNED |
| loader-audit security engine | `elf` (`dl-*`), hwcaps, tunables, audit | namespace/audit consistency certificates + robust policy maps | PLANNED |
| async-control engine | `signal`, `setjmp`, `nptl` cancellation | continuation-safety proofs + transition admissibility kernels | PLANNED |
| terminal-session engine | `termios`, `login`, `io`, `posix` | ioctl/termios guard polytopes + PTY policy tail bounds | PLANNED |
| launch-pattern engine | `spawn/exec`, `glob/fnmatch/regex`, env/path | launch DAG proofs + complexity bounds + interaction campaign evidence | PLANNED |
| secure-bootstrap policy engine | `csu`, `elf`, secure mode, diagnostics | noninterference proofs + calibrated admission-risk reports | PLANNED |
| conformal-calibration engine | cross-surface strict/hardened decision layer | finite-sample calibrated decision sets + validity monitors | PLANNED |
| topological-obstruction engine | cross-layer interaction complexes | obstruction witnesses + persistent defect signatures | PLANNED |
| algebraic-normalization engine | policy/parser/dispatch compositions | canonical normal forms + certificate-carrying rewrites | PLANNED |
| noncommutative-concurrency risk engine | `nptl`, allocator/thread hot paths | contention-spectrum bounds + operator-stability controls | PLANNED |
| Serre-invariant transport engine | cross-layer subsystem towers | spectral-page witnesses + extension-obstruction diagnostics | PLANNED |
| Grothendieck-coherence engine | cross-layer runtime + ABI/ISA compatibility glue | site/topos reconciliation + descent/stackification certificates | PLANNED |
| families-index engine | cross-variant compatibility transport | index-zero ledgers + incompatibility localization traces | PLANNED |
| equivariant-localization engine | proof/benchmark symmetry reductions | fixed-point compressed obligations + bounded-error certificates | PLANNED |
| Clifford-kernel engine | `string/memory` SIMD overlap/alignment surfaces | kernel normal forms + Spin/Pin guard witnesses | PLANNED |

## Proof and Math Matrix

| Obligation | Evidence Artifact | Status |
|---|---|---|
| strict refinement theorem | SMT/proof notes + differential fixtures | PLANNED |
| hardened safety theorem | invariant checks + policy proof notes | PLANNED |
| deterministic replay theorem | reproducibility campaign logs | PLANNED |
| sequential regression control | e-process monitoring reports | PLANNED |
| drift detection reliability | change-point validation reports | PLANNED |
| CPOMDP admissibility | policy feasibility certificates + replay logs | PLANNED |
| CHC/CEGAR convergence | abstraction refinement logs + resolved counterexamples | PLANNED |
| superoptimization soundness | SMT equivalence certificates per accepted rewrite | PLANNED |
| tail-risk control | EVT/CVaR reports for p99/p999 slices | PLANNED |
| barrier invariance | barrier-certificate proof artifacts + runtime checks | PLANNED |
| robust-radius guarantee | Wasserstein robustness reports + constraint audits | PLANNED |
| concurrent linearizability | mechanized concurrency proof notes + stress evidence | PLANNED |
| HJI viability | viability-kernel artifacts + adversarial trace audits | PLANNED |
| sheaf consistency detection | cohomology diagnostics + inconsistency replay cases | PLANNED |
| combinatorial interaction coverage | covering-array/matroid campaign proofs | PLANNED |
| probabilistic coupling bounds | coupled-trace divergence certificates + concentration reports | PLANNED |
| mean-field stability | equilibrium/stability reports + contention replay evidence | PLANNED |
| entropic transition safety | Schrödinger-bridge transport-cost/overshoot reports | PLANNED |
| SOS invariant synthesis | SDP outputs + certificate validation artifacts | PLANNED |
| large-deviation catastrophe bounds | rare-event estimation reports + threshold audits | PLANNED |
| topological anomaly detection | persistent-homology summaries + detection benchmarks | PLANNED |
| rough-signature feature stability | perturbation-stability reports + model-input audits | PLANNED |
| tropical latency composition | min-plus envelope proofs + end-to-end bound reports | IN_PROGRESS |
| online optimizer convergence | primal-dual/ADMM convergence diagnostics + rollback logs | PLANNED |
| coalgebraic stream bisimulation | minimized stream-machine proofs + protocol replay logs | PLANNED |
| Krohn-Rhodes codec factorization | automata decomposition artifacts + equivalence checks | PLANNED |
| hybrid temporal reachability | reachable-set artifacts + DST/leap edge replay audits | PLANNED |
| Stackelberg cache-security equilibria | equilibrium certificates + adversarial simulation reports | PLANNED |
| observability-rate optimality | rate-distortion/probe design reports + overhead audits | PLANNED |
| loader namespace sheaf consistency | obstruction diagnostics + namespace replay proofs | PLANNED |
| async nonlocal-control admissibility | pushdown/hybrid transition proof bundles + replay traces | PLANNED |
| termios/ioctl polyhedral safety | admissibility polytope artifacts + edge-case replay evidence | PLANNED |
| launch-pattern complexity guarantees | symbolic automata bounds + adversarial fixture audits | PLANNED |
| secure-mode noninterference | relational proof notes + leak-budget test reports | PLANNED |
| conformal decision validity | coverage/risk-control reports + calibration replay logs | PLANNED |
| spectral-sequence obstruction convergence | obstruction diagnostics + localized witness traces | PLANNED |
| algebraic normal-form uniqueness | canonicalization proofs + rewrite certificate ledgers | PLANNED |
| noncommutative contention stability | random-matrix/free-probability tail reports + stress replays | IN_PROGRESS |
| arithmetic compatibility integrity | invariant ledgers + drift/fracture threshold audits | PLANNED |
| Serre spectral convergence integrity | page-wise witness ledgers + extension-obstruction replay reports | PLANNED |
| Grothendieck descent coherence | site/topos/descent certificates + nongluable-case diagnostics | PLANNED |
| families-index nullity | index ledgers + localized nonzero-index defect reports | PLANNED |
| Atiyah-Bott localization conservativity | fixed-point/full-obligation equivalence reports + error bounds | PLANNED |
| Clifford kernel equivalence | regime-partition proofs + cross-ISA witness bundles | PLANNED |

## Gap Summary

1. ~~No Rust libc crates in repo yet.~~ Workspace scaffold with 6 crates created.
2. Initial conformance fixtures committed (`tests/conformance/fixtures/`); full capture pending.
3. Benchmark harnesses exist, but committed baseline evidence + regression thresholds are still pending.
4. Version script scaffold created (`libc.map`); full symbol/version verification pending.
5. No formal proof artifacts are committed yet.
6. Runtime math kernel is live in membrane and pointer validation; cross-family ABI wiring remains incomplete.
7. Sequential-statistical guardrails are partially wired in runtime code; calibration evidence remains pending.
8. Bootstrap string/memory + allocator boundary implementations exist; strict/hardened parity evidence remains pending.
8. Core allocator subsystem (size classes, thread cache, large allocator, MallocState) implemented with 50+ tests.
9. All string functions (mem*, str*, strtok, strtok_r, wide) implemented with comprehensive tests.
10. Tropical latency compositor live — min-plus algebra for provable worst-case pipeline bounds (math item #25).
11. Spectral phase monitor live — Marchenko-Pastur/Tracy-Widom eigenvalue edge detection for regime changes (math item #31).

## Update Policy

No entry may move to `DONE` without:

1. fixture-based conformance evidence,
2. benchmark result entry,
3. documented membrane policy behavior for that API family,
4. mode-specific strict/hardened evidence,
5. proof artifact references for applicable obligations.
