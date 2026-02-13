# Gentoo Critical Packages (Dependency Graph Analysis)

This report summarizes high-impact packages from the generated Top-100 dependency graph.

Source artifacts:

- `data/gentoo/dependency-graph.json`
- `data/gentoo/build-order.txt`
- `data/gentoo/build-waves.json`

Generation command:

```bash
scripts/gentoo/extract-deps.py
```

## Key Metrics

1. Package count: `100`
2. Edge count: `441`
3. Build waves: `6`
4. Estimated total build time: `651` minutes (`10.85` hours)
5. Largest SCC size: `1` (DAG in current model)

## Highest-Impact Packages

Sorted by transitive dependents (failure blast radius), then critical-path score.

| Package | Transitive Dependents | Critical Path Score | Build Wave | Est. Build Min |
| --- | ---: | ---: | ---: | ---: |
| `sys-kernel/linux-headers` | 96 | 0.6788 | 0 | 4 |
| `sys-libs/glibc` | 95 | 0.7092 | 1 | 12 |
| `sys-devel/binutils` | 95 | 0.6717 | 0 | 4 |
| `sys-devel/gcc` | 94 | 0.7396 | 2 | 18 |
| `sys-devel/make` | 94 | 0.6646 | 0 | 4 |
| `dev-libs/openssl` | 20 | 0.2914 | 3 | 4 |
| `dev-libs/libidn2` | 6 | 0.1924 | 3 | 5 |
| `dev-libs/libxml2` | 6 | 0.1924 | 3 | 5 |
| `dev-libs/libpcre2` | 5 | 0.1854 | 3 | 4 |
| `net-libs/gnutls` | 5 | 0.1854 | 3 | 6 |

## Build-Wave Plan

Wave summary from `data/gentoo/build-waves.json`:

1. Wave 0: bootstrap/tooling roots (`binutils`, `make`, `patch`, `linux-headers`)
2. Wave 1: libc runtime root (`glibc`)
3. Wave 2: compiler promotion (`gcc`)
4. Wave 3: broad base packages and reusable libraries
5. Wave 4: network/database/app stacks depending on wave 3
6. Wave 5: highest-layer packages (`docker`, `git`, `vlc`, `grpc`, `transmission`)

## Failure-Propagation Guidance

1. Prioritize early validation and retries for waves 0-2; failures there block most of the graph.
2. Treat `glibc`, `gcc`, and `binutils` as hard blockers with dedicated diagnostics.
3. Cache successful wave artifacts to avoid recomputing the full DAG after late-wave failures.
4. For wave 4/5 failures, continue independent package execution and isolate by dependent subtree.

