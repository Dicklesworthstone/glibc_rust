# Profiling Runtime Math Hot Paths (perf + flamegraphs)

This repo treats runtime performance as a first-class contract. Before merging any runtime_math optimization or new kernel wiring, re-run the profile loop below and record the top hotspots.

## Prereqs

Tools:
- `perf` (Linux)
- `cargo-flamegraph` (installed as `cargo flamegraph`)

Symbol quality (recommended):
- `CARGO_PROFILE_BENCH_DEBUG=true` so flamegraphs resolve symbols with line-level fidelity.
  - Alternative: add `[profile.bench] debug = true` to the workspace `Cargo.toml`.

Perf permissions:
- If `perf` fails with `perf_event_paranoid` errors, either:
  - temporarily lower it (example): `sudo sysctl -w kernel.perf_event_paranoid=0`
  - or run flamegraph with root: `cargo flamegraph --root ...`
- After profiling, restore the previous setting (example): `sudo sysctl -w kernel.perf_event_paranoid=4`

## Targets To Profile

Runtime-math (direct):
- `runtime_math/decide/<mode>`
- `runtime_math/observe_fast/<mode>`
- `runtime_math/decide_observe/<mode>`

Pointer validation call sites:
- `validate_known` (from `membrane_bench`)

## Flamegraph Commands

Notes:
- Criterion uses a hidden `--bench` flag to select benchmark-mode when running the executable directly (or via `cargo flamegraph`). Include it.
- Use `--profile-time <sec>` to run without statistical analysis (profiler-friendly).
- Use `--exact` to avoid mixing multiple benchmarks in a single flamegraph.

### RuntimeMathKernel::decide (strict)

```bash
GLIBC_RUST_MODE=strict CARGO_PROFILE_BENCH_DEBUG=true \
  cargo flamegraph -p glibc-rs-bench --bench runtime_math_bench --deterministic \
  -o /tmp/flamegraph-runtime-math-decide-strict.svg -- \
  --bench --profile-time 10 --exact 'runtime_math/decide/strict'
```

### RuntimeMathKernel::observe_validation_result (strict)

```bash
GLIBC_RUST_MODE=strict CARGO_PROFILE_BENCH_DEBUG=true \
  cargo flamegraph -F 199 -p glibc-rs-bench --bench runtime_math_bench --deterministic \
  -o /tmp/flamegraph-runtime-math-observe-fast-strict.svg -- \
  --bench --profile-time 10 --exact 'runtime_math/observe_fast/strict'
```

### decide + observe loop (strict)

```bash
GLIBC_RUST_MODE=strict CARGO_PROFILE_BENCH_DEBUG=true \
  cargo flamegraph -F 199 -p glibc-rs-bench --bench runtime_math_bench --deterministic \
  -o /tmp/flamegraph-runtime-math-decide-observe-strict.svg -- \
  --bench --profile-time 10 --exact 'runtime_math/decide_observe/strict'
```

### Pointer Validation (validate_known)

```bash
GLIBC_RUST_MODE=strict CARGO_PROFILE_BENCH_DEBUG=true \
  cargo flamegraph -F 199 -p glibc-rs-bench --bench membrane_bench --deterministic \
  -o /tmp/flamegraph-pointer-validate-known-strict.svg -- \
  --bench --profile-time 10 --exact validate_known
```

### Hardened Mode

Repeat the same commands with:
- `GLIBC_RUST_MODE=hardened`
- the `.../hardened` benchmark ids (for runtime_math_bench): `runtime_math/decide/hardened`, etc.

## Hotspot Extraction (Top-5)

`cargo flamegraph` writes a `perf.data` file in the current directory. Move it immediately so you can:
1. preserve it as an artifact
2. avoid accidentally committing a huge file

Example:

```bash
mkdir -p /tmp/glibc_rust_profiles
mv perf.data /tmp/glibc_rust_profiles/perf_runtime_math_decide_strict.data
```

Then extract the top-5 self-cost symbols:

```bash
perf report -i /tmp/glibc_rust_profiles/perf_runtime_math_decide_strict.data \
  --stdio --no-children --sort=symbol \
  | awk '/^ *[0-9]+\\.[0-9]+%/ {print; c++; if (c==5) exit}'
```

Record the output into a perf log (commit message, bead comment, or a local note) and re-run after changes. Track when the top-5 set changes and when the ordering materially shifts.

## Example Top-5 (Strict, 2026-02-10)

These are example top-5 self-cost symbols captured from this workspace environment; your machine may differ.

RuntimeMathKernel::decide:
- `__ieee754_log_fma`
- `glibc_rs_membrane::runtime_math::design::logdet_spd`
- `<glibc_rs_membrane::runtime_math::design::OptimalDesignController>::choose_plan`
- `core::slice::sort::shared::smallsort::insertion_sort_shift_left::<...>`
- `<glibc_rs_membrane::runtime_math::RuntimeMathKernel>::decide`

RuntimeMathKernel::observe_validation_result (observe_fast):
- `<glibc_rs_membrane::runtime_math::changepoint::ChangepointController>::observe`
- `<glibc_rs_membrane::spectral_monitor::SpectralMonitor>::observe`
- `<glibc_rs_membrane::runtime_math::RuntimeMathKernel>::observe_validation_result`
- `<glibc_rs_membrane::runtime_math::fusion::KernelFusionController>::observe`
- `<glibc_rs_membrane::persistence::PersistenceDetector>::observe`

Pointer validation (validate_known):
- `<glibc_rs_membrane::runtime_math::changepoint::ChangepointController>::observe`
- `<glibc_rs_membrane::runtime_math::fusion::KernelFusionController>::observe`
- `<glibc_rs_membrane::runtime_math::RuntimeMathKernel>::observe_validation_result`
- `core::slice::sort::unstable::ipnsort::<...>`
- `__ieee754_log_fma`

