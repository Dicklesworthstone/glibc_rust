# Strict Mode Refinement Proof (bd-249m.1)

## Scope
- Theorem: strict mode refines the current FrankenLibC/glibc contract for supported symbols.
- Runtime scope today: 250 exported symbols from `tests/conformance/reality_report.v1.json`.
- Domain scope: POSIX-defined inputs plus explicit strict-mode contracts in fixture packs.

## Statement
For each supported symbol `s` and valid input `x` in the current conformance domain:

`FrankenStrict(s, x) = Glibc(s, x)` and `errno_strict(s, x) = errno_glibc(s, x)`.

Strict-mode membrane behavior is observational only:

`TSM_strict(f(x)) = f(x)`.

## Simulation Relation (Operational)
- Concrete state: internal runtime state across ABI, membrane, and core layers.
- Abstract state: glibc-visible state (return value, errno, side effects for covered symbols).
- Abstraction map `alpha` projects concrete state to externally visible glibc state.
- Obligation: each strict-mode transition preserves `alpha` against the reference fixture outcome.

## Traceability Anchors (Machine-Checked)
- `crates/frankenlibc-membrane/src/config.rs:99`  
  strict-default mode resolution and process-sticky runtime mode cache.
- `crates/frankenlibc-membrane/src/ptr_validator.rs:325`  
  strict fast profile branch avoids hardened healing path.
- `crates/frankenlibc-membrane/src/decision_contract.rs:214`  
  strict/off project active contract actions to `Log`.
- `crates/frankenlibc-abi/src/runtime_policy.rs:861`  
  strict-mode contract projection test (`Log`-only action expectation).
- `crates/frankenlibc-abi/src/errno_abi.rs:10`  
  ABI `__errno_location` TLS pointer source.
- `crates/frankenlibc-core/src/errno/mod.rs:69`  
  thread-local errno accessor semantics.
- `crates/frankenlibc-abi/src/math_abi.rs:33`  
  strict/hardened math entry routing via runtime policy.
- `crates/frankenlibc-core/src/math/float.rs:19`  
  core float round-path implementation.

## Evidence Path
- Conformance fixture parity: `tests/conformance/golden/fixture_verify_strict_hardened.v1.json`
- Traceability manifest: `tests/conformance/proof_traceability_check.json`
- Binder + source-ref validation gate: `scripts/check_proof_binder.sh`

## Status
This artifact establishes the strict-refinement traceability scaffold and machine-checked source anchors.
Full theorem closure still requires expanded per-symbol proof body and review sign-off.
