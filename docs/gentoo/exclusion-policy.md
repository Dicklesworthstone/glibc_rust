# Gentoo Exclusion Policy for FrankenLibC Validation

This policy defines when a package from the curated Top-100 set is excluded from the primary `LD_PRELOAD` validation lane.

Primary artifact:

- `configs/gentoo/exclusions.json`

## Exclusion Categories

1. `fundamental`
: validation model is structurally incompatible (example: `sys-libs/glibc` self-overlay).

2. `setuid`
: privileged execution sanitizes preload variables, so `LD_PRELOAD` evidence is not representative.

3. `static_binary`
: static ELF linkage bypasses interposition.

4. `frankenlibc_bug`
: currently known FrankenLibC issue requiring temporary carve-out.

5. `environmental_constraint`
: host/kernel/capability constraints make CI lane behavior non-representative.

## Policy Rules

1. Exclusion entries must include:
: `package`, `type`, `reason`, `workaround`, `tracking`.

2. Exclusion package must be in:
: `configs/gentoo/top100-packages.txt`.

3. Exclusion rate cap:
: `<= 10%` of Top-100 set.

4. Review cadence:
: weekly or on major validation-lane changes.

## Validation Commands

Validate exclusion ledger consistency:

```bash
scripts/gentoo/check-exclusions.py
```

Detect static binaries in an installed image/rootfs:

```bash
scripts/gentoo/detect-static.py --root /path/to/rootfs
scripts/gentoo/detect-static.py --root /path/to/rootfs --json
```

## Operational Guidance

1. Prefer temporary exclusions with explicit tracking over silent package drops.
2. Keep workaround text actionable (how to test partial functionality now).
3. Re-evaluate `frankenlibc_bug` and `environmental_constraint` entries first when reducing exclusion rate.
4. Keep exclusions synchronized with dependency graph and build-wave planning outputs.

