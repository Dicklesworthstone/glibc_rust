# Gentoo Top-100 Package Rationale

This rationale maps each tier to FrankenLibC risk/coverage priorities and explains why these package classes were selected.

## Tier 1: Core Infrastructure

Representative packages:

- `sys-libs/glibc`
- `sys-devel/gcc`
- `sys-apps/coreutils`
- `sys-apps/util-linux`
- `dev-libs/openssl`

Why included:

1. Exercises baseline libc ABI usage across essential system tooling.
2. Exposes bootstrap/toolchain regressions early.
3. Provides high-frequency call-path coverage for `string`, `stdlib`, and IO entry points.

## Tier 2: Security Critical

Representative packages:

- `net-misc/openssh`
- `net-misc/curl`
- `app-admin/sudo`
- `mail-mta/postfix`
- `app-crypt/gnupg`

Why included:

1. High-impact parser/network/authentication surfaces.
2. Strong signal for memory-safety hardening value under realistic attack-facing workloads.
3. Useful for validating strict vs hardened policy behavior.

## Tier 3: Allocation Heavy

Representative packages:

- `dev-db/redis`
- `dev-db/postgresql`
- `dev-lang/python`
- `app-emulation/qemu`
- `sys-apps/systemd`

Why included:

1. Stresses allocator correctness, temporal safety, and repair actions.
2. Generates dense evidence for `malloc`/`free`/`realloc` membrane paths.
3. Supports profiling and hotspot analysis for overhead budgets.

## Tier 4: String and Parsing Heavy

Representative packages:

- `dev-util/git`
- `dev-libs/libxml2`
- `dev-libs/json-c`
- `dev-libs/icu`
- `app-text/poppler`

Why included:

1. Targets high-risk text and parser state machines.
2. Expands coverage for encoding/locale/tokenization behavior.
3. Validates boundary handling in common parser and formatting routines.

## Tier 5: Threading and Concurrency Heavy

Representative packages:

- `media-video/ffmpeg`
- `net-libs/zeromq`
- `net-libs/grpc`
- `app-emulation/wine`
- `net-p2p/transmission`

Why included:

1. Stresses pthread/futex/TLS behavior under concurrent workloads.
2. Surfaces contention, scheduling, and synchronization corner cases.
3. Gives realistic pressure for thread-heavy networking and media pipelines.

## Coverage Notes

The full list in `configs/gentoo/top100-packages.txt` and tier map in
`configs/gentoo/package-tiers.json` are designed to jointly cover:

1. allocator/memory lifecycle stress,
2. parser/string boundary stress,
3. IO/network/authentication stress,
4. threading/concurrency stress,
5. core system/bootstrap compatibility.

This balance is intentional so downstream validation can detect regressions quickly while remaining operationally feasible for repeated runs.

