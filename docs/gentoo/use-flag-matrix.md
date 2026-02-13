# Gentoo USE Flag Matrix for FrankenLibC Validation

This matrix summarizes USE flags that materially affect libc behavior, `LD_PRELOAD` viability, or signal quality during ecosystem validation.

## How to Inspect USE State

- Global defaults: `emerge --info | rg '^USE='`
- Package plan: `emerge -pv <atom>`
- Package-local details (gentoolkit): `equery uses <atom>`

## Flag Impact Matrix

| USE flag | Typical effect | libc/interposition impact | Recommended handling |
| --- | --- | --- | --- |
| `test` | Runs package test suites | Increases runtime path coverage significantly | Enable for validation waves (`FEATURES="test"`) |
| `static` / `static-libs` | Builds static artifacts | `LD_PRELOAD` is ineffective for static binaries | Keep enabled only when specifically testing static behavior; otherwise prefer dynamic paths |
| `hardened` | Extra hardening defaults | Can alter allocator/fortify behavior and call patterns | Keep consistent across baseline and instrumented runs |
| `pie` | Position-independent executables | Usually compatible, but affects perf profile | Keep same in A/B comparisons |
| `lto` | Link-time optimization | Can inline/remove libc call boundaries | Disable for first-pass compatibility triage; enable later for realism |
| `pgo` | Profile-guided optimization | Changes hot paths and timing distributions | Keep off for deterministic baseline runs |
| `custom-cflags` | User-tuned compiler flags | High variability in behavior and perf | Avoid for canonical CI validation |
| `debug` | Debug symbols/assertions | Changes timing and may expose extra checks | Use for failure diagnosis, not benchmark claims |
| `sanitize` (ASan/UBSan/etc.) | Instrumentation and checks | Can conflict with preload assumptions and timing | Run in separate diagnostic track, not primary compatibility track |
| `jemalloc` | Alternate allocator | May bypass or alter `malloc` call interception | Track separately; verify whether symbols still route through preloaded ABI |
| `tcmalloc` | Alternate allocator | Similar to `jemalloc` risk | Treat as special-case packages |
| `threads` | Multithreaded code paths | Increases pthread/futex/TLS surface | Include in coverage set; capture contention evidence |
| `nls` / `unicode` / `icu` | Localization, encoding paths | Exercises locale/iconv/wchar behavior | Keep enabled in i18n-focused test subsets |
| `ssl` / `gnutls` / `openssl` | TLS stack selection | Pulls parser/network/crypto-heavy dependencies | Preserve across baseline/instrumented A/B for fair comparison |
| `systemd` / `elogind` | Runtime integration choices | Changes startup/service call paths | Validate as separate package cohorts |
| `minimal` | Feature reduction | Shrinks exercised libc surface | Do not rely on minimal profiles for compatibility claims |

## Recommended Validation Profiles

## Profile A: Compatibility Baseline

- `FEATURES="test"`
- Stable distro-default USE settings
- No `custom-cflags`, no `pgo`, no `sanitize`

Goal: maximize reproducibility and comparability.

## Profile B: Stress/Realism

- Same as Profile A, plus selected performance flags (`lto`, hardened presets)
- Include allocator variants (`jemalloc`) in isolated cohorts

Goal: detect integration cliffs that only appear in optimized real-world builds.

## Interposition Risk Heuristics

Treat a package as higher-risk for preload validation when any of these apply:

1. `static`/`static-libs` enabled.
2. Alternate allocator enabled (`jemalloc`, `tcmalloc`).
3. setuid-heavy package behavior (independent of USE but common in security/system packages).
4. aggressive optimization flags that erase/redirect libc call boundaries.

## Recording Requirements

For each validation run, record:

- package atom and resolved USE list,
- profile name (`baseline` or `stress`),
- mode (`strict`/`hardened`),
- pass/fail status and major deviations,
- whether interposition was confirmed active.

