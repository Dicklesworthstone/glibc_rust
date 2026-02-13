# Gentoo Top-100 Package Selection Methodology

This document defines how FrankenLibC selects and maintains the Top-100 Gentoo package set for ecosystem validation.

## Objectives

1. Maximize real-world impact by prioritizing widely used packages.
2. Cover high-risk libc surfaces (allocator, string/parser, IO/network, threading).
3. Include security-sensitive software where memory unsafety has severe consequences.
4. Keep the set operationally feasible for repeated CI and release-gate runs.

## Selection Model

The curated list uses five tiers of 20 packages each:

1. Core infrastructure
2. Security critical
3. Allocation heavy
4. String/parsing heavy
5. Threading/concurrency heavy

Source-of-truth artifact:

- `configs/gentoo/package-tiers.json`

Generated list artifact:

- `configs/gentoo/top100-packages.txt`

## Curation Signals

The tier artifact encodes weighted qualitative signals:

- popularity (`0.35`)
- criticality (`0.30`)
- subsystem coverage (`0.25`)
- build feasibility (`0.10`)

These weights guide curation and refresh decisions but do not rely on unstable external APIs in the generation script.

## Deterministic Generation

Use:

```bash
scripts/gentoo/update-package-list.py --check
scripts/gentoo/update-package-list.py
```

Behavior:

1. Validates schema and constraints (5 tiers, 20 per tier, 100 total).
2. Rejects duplicate package atoms across tiers.
3. Writes `top100-packages.txt` in tier order for deterministic downstream consumption.

## Quality Gates

Any update must satisfy:

1. Exactly 100 unique package atoms.
2. No duplicate atoms across tiers.
3. Tier cardinality remains 20 each unless constraints are intentionally updated.
4. Selection rationale remains aligned with FrankenLibC subsystem coverage goals.

## Downstream Usage

The generated package list is designed to feed:

1. Dependency graph extraction (`bd-2icq.6`).
2. Build/test orchestration and wave planning.
3. Exclusion policy analysis (`bd-2icq.15`).
4. Regression and performance reporting across repeated validation runs.

