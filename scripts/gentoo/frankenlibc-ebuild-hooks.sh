#!/usr/bin/env bash
# frankenlibc-ebuild-hooks.sh
#
# Portage phase hook helpers for injecting FrankenLibC via LD_PRELOAD.
# Intended to be sourced from /etc/portage/bashrc.
#
# Design goals:
# - safe defaults (test phases only),
# - explicit package/phase controls,
# - deterministic per-phase logging with structured JSONL events.

if [[ "${FRANKENLIBC_HOOKS_LOADED:-0}" == "1" ]]; then
    # Sourced shell path: return quietly; direct execution path: exit.
    if (return 0 2>/dev/null); then
        return 0
    fi
    exit 0
fi
export FRANKENLIBC_HOOKS_LOADED=1

frankenlibc::atom() {
    if [[ -n "${CATEGORY:-}" && -n "${PF:-}" ]]; then
        printf "%s/%s" "${CATEGORY}" "${PF}"
        return
    fi
    if [[ -n "${CATEGORY:-}" && -n "${PN:-}" ]]; then
        printf "%s/%s" "${CATEGORY}" "${PN}"
        return
    fi
    printf "unknown/unknown"
}

frankenlibc::json_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf "%s" "${value}"
}

frankenlibc::event_name() {
    local message="${1:-}"
    case "${message}" in
        enabled:*) printf "enable" ;;
        disabled*) printf "disable" ;;
        skip:*) printf "skip" ;;
        *) printf "info" ;;
    esac
}

frankenlibc::log() {
    local message="$*"
    local log_file="${FRANKENLIBC_PORTAGE_LOG:-/var/log/frankenlibc/portage/hooks.jsonl}"
    local ts event atom
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    event="$(frankenlibc::event_name "${message}")"
    atom="$(frankenlibc::atom)"

    mkdir -p "$(dirname "${log_file}")" 2>/dev/null || true
    printf '{"timestamp":"%s","event":"%s","atom":"%s","category":"%s","pn":"%s","pf":"%s","phase":"%s","pid":%s,"mode":"%s","ld_preload":"%s","log_file":"%s","message":"%s"}\n' \
        "$(frankenlibc::json_escape "${ts}")" \
        "$(frankenlibc::json_escape "${event}")" \
        "$(frankenlibc::json_escape "${atom}")" \
        "$(frankenlibc::json_escape "${CATEGORY:-unknown}")" \
        "$(frankenlibc::json_escape "${PN:-unknown}")" \
        "$(frankenlibc::json_escape "${PF:-unknown}")" \
        "$(frankenlibc::json_escape "${EBUILD_PHASE:-unknown}")" \
        "${BASHPID:-$$}" \
        "$(frankenlibc::json_escape "${FRANKENLIBC_MODE:-unknown}")" \
        "$(frankenlibc::json_escape "${LD_PRELOAD:-}")" \
        "$(frankenlibc::json_escape "${FRANKENLIBC_LOG_FILE:-${FRANKENLIBC_LOG:-}}")" \
        "$(frankenlibc::json_escape "${message}")" \
        >>"${log_file}" 2>/dev/null || true
}

frankenlibc::contains_word() {
    local haystack="$1"
    local needle="$2"
    [[ " ${haystack} " == *" ${needle} "* ]]
}

frankenlibc::phase_allowed() {
    local allowlist="${FRANKENLIBC_PHASE_ALLOWLIST:-src_test pkg_test}"
    local phase="${1:-${EBUILD_PHASE:-unknown}}"
    if frankenlibc::contains_word "${allowlist}" "${phase}"; then
        return 0
    fi

    # Portage can expose raw phase names (e.g. "test") while users often
    # configure prefixed names (e.g. "src_test"/"pkg_test"), and vice versa.
    local normalized="${phase#src_}"
    normalized="${normalized#pkg_}"
    if frankenlibc::contains_word "${allowlist}" "${normalized}"; then
        return 0
    fi
    if frankenlibc::contains_word "${allowlist}" "src_${normalized}"; then
        return 0
    fi
    if frankenlibc::contains_word "${allowlist}" "pkg_${normalized}"; then
        return 0
    fi
    return 1
}

frankenlibc::package_blocked() {
    local blocklist="${FRANKENLIBC_PACKAGE_BLOCKLIST:-sys-libs/glibc sys-apps/shadow}"
    local atom cpn
    atom="$(frankenlibc::atom)"
    cpn="${CATEGORY:-unknown}/${PN:-unknown}"
    frankenlibc::contains_word "${blocklist}" "${atom}" || frankenlibc::contains_word "${blocklist}" "${cpn}"
}

frankenlibc::should_enable() {
    if [[ "${FRANKENLIBC_PORTAGE_ENABLE:-1}" != "1" ]]; then
        frankenlibc::log "disabled: FRANKENLIBC_PORTAGE_ENABLE=${FRANKENLIBC_PORTAGE_ENABLE:-0}"
        return 1
    fi
    if ! frankenlibc::phase_allowed "${EBUILD_PHASE:-unknown}"; then
        frankenlibc::log "skip: phase not in allowlist (${FRANKENLIBC_PHASE_ALLOWLIST:-src_test pkg_test})"
        return 1
    fi
    if frankenlibc::package_blocked; then
        frankenlibc::log "skip: atom in blocklist (${FRANKENLIBC_PACKAGE_BLOCKLIST:-})"
        return 1
    fi
    if [[ "${MERGE_TYPE:-}" == "binary" ]]; then
        frankenlibc::log "skip: MERGE_TYPE=binary"
        return 1
    fi
    if [[ "${FRANKENLIBC_SKIP_STATIC:-1}" == "1" ]] && frankenlibc::contains_word "${USE:-}" "static-libs"; then
        frankenlibc::log "skip: static-libs USE flag detected"
        return 1
    fi
    if [[ -z "${FRANKENLIBC_LIB:-}" ]]; then
        export FRANKENLIBC_LIB="/opt/frankenlibc/lib/libfrankenlibc_abi.so"
    fi
    if [[ ! -r "${FRANKENLIBC_LIB}" ]]; then
        frankenlibc::log "skip: FRANKENLIBC_LIB unreadable (${FRANKENLIBC_LIB})"
        return 1
    fi
    return 0
}

frankenlibc::enable() {
    local lib="${FRANKENLIBC_LIB}"
    local mode="${FRANKENLIBC_MODE:-hardened}"
    local base_dir="${FRANKENLIBC_LOG_DIR:-/var/log/frankenlibc/portage}"
    local phase="${EBUILD_PHASE:-unknown}"
    local next_ld_preload
    local atom
    atom="$(frankenlibc::atom)"
    local safe_atom="${atom//\//__}"
    local log_dir="${base_dir}/${safe_atom}"

    mkdir -p "${log_dir}" 2>/dev/null || true

    if [[ -n "${LD_PRELOAD:-}" ]]; then
        if [[ ":${LD_PRELOAD}:" != *":${lib}:"* ]]; then
            next_ld_preload="${lib}:${LD_PRELOAD}"
        else
            next_ld_preload="${LD_PRELOAD}"
        fi
    else
        next_ld_preload="${lib}"
    fi

    export FRANKENLIBC_MODE="${mode}"
    export FRANKENLIBC_LOG="${log_dir}/${phase}.jsonl"
    export FRANKENLIBC_LOG_FILE="${FRANKENLIBC_LOG}"
    export FRANKENLIBC_PHASE_ACTIVE=1
    export FRANKENLIBC_PACKAGE="${atom}"
    export FRANKENLIBC_PHASE="${phase}"

    frankenlibc::log "enabled: mode=${FRANKENLIBC_MODE} ld_preload=${next_ld_preload} log=${FRANKENLIBC_LOG}"
    export LD_PRELOAD="${next_ld_preload}"
}

frankenlibc::disable() {
    local lib="${FRANKENLIBC_LIB:-}"
    if [[ -n "${lib}" && -n "${LD_PRELOAD:-}" ]]; then
        local current=":${LD_PRELOAD}:"
        current="${current//:${lib}:/:}"
        current="${current#:}"
        current="${current%:}"
        if [[ -n "${current}" ]]; then
            export LD_PRELOAD="${current}"
        else
            unset LD_PRELOAD
        fi
    fi
    unset FRANKENLIBC_LOG
    unset FRANKENLIBC_LOG_FILE
    unset FRANKENLIBC_PHASE_ACTIVE
    unset FRANKENLIBC_PACKAGE
    unset FRANKENLIBC_PHASE
    frankenlibc::log "disabled"
}

frankenlibc::phase_enter() {
    if frankenlibc::should_enable; then
        frankenlibc::enable
    else
        frankenlibc::disable
    fi
}

frankenlibc::phase_exit() {
    if [[ "${FRANKENLIBC_PHASE_ACTIVE:-0}" == "1" ]]; then
        frankenlibc::disable
    fi
}

# Portage phase hooks (pre/post) invoked when sourced from /etc/portage/bashrc.
pre_src_configure() { frankenlibc::phase_enter; }
post_src_configure() { frankenlibc::phase_exit; }

pre_src_compile() { frankenlibc::phase_enter; }
post_src_compile() { frankenlibc::phase_exit; }

pre_src_test() { frankenlibc::phase_enter; }
post_src_test() { frankenlibc::phase_exit; }

pre_pkg_test() { frankenlibc::phase_enter; }
post_pkg_test() { frankenlibc::phase_exit; }

pre_pkg_preinst() { frankenlibc::phase_enter; }
post_pkg_preinst() { frankenlibc::phase_exit; }

pre_pkg_postinst() { frankenlibc::phase_enter; }
post_pkg_postinst() { frankenlibc::phase_exit; }
