# /etc/portage/bashrc template for FrankenLibC interposition.
#
# Copy this file to:
#   /etc/portage/bashrc
#
# Then ensure the hook script is installed where FLC_HOOK_SCRIPT points.

# Master enable switch for Portage hook logic.
export FRANKENLIBC_PORTAGE_ENABLE=1

# FrankenLibC ABI library path used for LD_PRELOAD.
export FRANKENLIBC_LIB="/opt/frankenlibc/lib/libfrankenlibc_abi.so"

# Runtime mode for interposed calls.
export FRANKENLIBC_MODE="${FRANKENLIBC_MODE:-hardened}"

# Optional runtime policy table/config artifact.
export FRANKENLIBC_CONFIG="${FRANKENLIBC_CONFIG:-/opt/frankenlibc/etc/frankenlibc.toml}"

# Conservative default: only preload during package test phases.
# Expand to include src_compile only after validating toolchain stability.
export FRANKENLIBC_PHASE_ALLOWLIST="${FRANKENLIBC_PHASE_ALLOWLIST:-src_test pkg_test}"

# Package atoms to never preload (safety exclusions).
export FRANKENLIBC_PACKAGE_BLOCKLIST="${FRANKENLIBC_PACKAGE_BLOCKLIST:-sys-libs/glibc sys-apps/shadow}"

# If static-libs USE is enabled, skip preload by default.
export FRANKENLIBC_SKIP_STATIC="${FRANKENLIBC_SKIP_STATIC:-1}"

# Log destinations.
export FRANKENLIBC_LOG_DIR="${FRANKENLIBC_LOG_DIR:-/var/log/frankenlibc/portage}"
export FRANKENLIBC_PORTAGE_LOG="${FRANKENLIBC_PORTAGE_LOG:-/var/log/frankenlibc/portage/hooks.jsonl}"

# Hook script location. Override this in environment if needed.
FLC_HOOK_SCRIPT="${FLC_HOOK_SCRIPT:-/opt/frankenlibc/scripts/gentoo/frankenlibc-ebuild-hooks.sh}"
if [[ -r "${FLC_HOOK_SCRIPT}" ]]; then
    # shellcheck source=/dev/null
    . "${FLC_HOOK_SCRIPT}"
fi

# Optional per-package overrides:
# 1) Create files under /etc/portage/env/, for example:
#      /etc/portage/env/dev-db/redis
#      FRANKENLIBC_PHASE_ALLOWLIST="src_compile src_test"
#      FRANKENLIBC_MODE="strict"
# 2) Map atoms in /etc/portage/package.env:
#      dev-db/redis frankenlibc-redis
