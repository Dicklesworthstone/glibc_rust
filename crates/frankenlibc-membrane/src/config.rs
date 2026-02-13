//! Runtime mode configuration.
//!
//! The runtime mode is set via the `FRANKENLIBC_MODE` environment variable:
//! - `strict` (default): ABI-compatible behavior with POSIX-correct errno/return
//!   semantics. The membrane validates but does NOT silently rewrite operations.
//!   Invalid operations produce the same errors a conformant libc would.
//! - `hardened`: TSM repair mode. The membrane validates AND applies deterministic
//!   healing for invalid/unsafe patterns (clamp, truncate, quarantine, safe-default).
//!   This is opt-in behavior that deviates from strict POSIX where safety requires it.
//! - `off`: No validation. Pure passthrough for benchmarking baseline only.

use std::sync::atomic::{AtomicU8, Ordering};

/// Runtime operating mode for the membrane.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SafetyLevel {
    /// Strict ABI-compatible behavior. POSIX-correct errno/return semantics.
    /// Membrane validates pointers but does not silently rewrite operations.
    /// Invalid operations produce correct error returns, not silent repairs.
    #[default]
    Strict,
    /// Hardened mode. TSM applies deterministic healing for unsafe patterns.
    /// Opt-in behavior that prioritizes safety over strict POSIX conformance
    /// when the two conflict (e.g., clamping a buffer overflow vs segfault).
    Hardened,
    /// No validation. Pure passthrough for benchmarking baseline.
    Off,
}

impl SafetyLevel {
    /// Parse from string (case-insensitive).
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "strict" | "default" | "abi" => Self::Strict,
            "hardened" | "repair" | "tsm" | "full" => Self::Hardened,
            "off" | "none" | "disabled" => Self::Off,
            _ => Self::Strict,
        }
    }

    /// Returns true if the membrane should apply healing actions.
    #[must_use]
    pub const fn heals_enabled(self) -> bool {
        matches!(self, Self::Hardened)
    }

    /// Returns true if validation is active.
    #[must_use]
    pub const fn validation_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }
}

// Atomic cache: 0=unresolved, 1=Strict, 2=Hardened, 3=Off, 255=resolving.
// Uses a non-blocking state machine instead of OnceLock to prevent deadlock
// under LD_PRELOAD when our exported strlen is called reentrant during
// std::env::var() inside OnceLock::get_or_init().
static CACHED_LEVEL: AtomicU8 = AtomicU8::new(0);

const LEVEL_UNRESOLVED: u8 = 0;
const LEVEL_STRICT: u8 = 1;
const LEVEL_HARDENED: u8 = 2;
const LEVEL_OFF: u8 = 3;
const LEVEL_RESOLVING: u8 = 255;

fn parse_runtime_mode_env(raw: &str) -> SafetyLevel {
    match raw.to_ascii_lowercase().as_str() {
        "strict" | "default" | "abi" => SafetyLevel::Strict,
        "hardened" | "repair" | "tsm" | "full" => SafetyLevel::Hardened,
        // Runtime contract is strict|hardened only. Keep benchmark-only `Off`
        // reachable via direct API use in tests/bench code, not env parsing.
        _ => SafetyLevel::Strict,
    }
}

fn level_to_u8(level: SafetyLevel) -> u8 {
    match level {
        SafetyLevel::Strict => LEVEL_STRICT,
        SafetyLevel::Hardened => LEVEL_HARDENED,
        SafetyLevel::Off => LEVEL_OFF,
    }
}

fn u8_to_level(v: u8) -> SafetyLevel {
    match v {
        LEVEL_HARDENED => SafetyLevel::Hardened,
        LEVEL_OFF => SafetyLevel::Off,
        _ => SafetyLevel::Strict,
    }
}

/// Get the configured safety level (reads env var on first call, caches thereafter).
///
/// Uses a non-blocking atomic state machine instead of OnceLock. When a reentrant
/// call arrives during env var resolution (e.g., our strlen called by std::env::var),
/// the RESOLVING state is detected and Strict is returned as safe default.
#[must_use]
pub fn safety_level() -> SafetyLevel {
    let cached = CACHED_LEVEL.load(Ordering::Relaxed);

    // Fast path: already resolved.
    if cached != LEVEL_UNRESOLVED && cached != LEVEL_RESOLVING {
        return u8_to_level(cached);
    }

    // Reentrant call during resolution: return Strict (safe default).
    if cached == LEVEL_RESOLVING {
        return SafetyLevel::Strict;
    }

    // Try to claim the resolution slot.
    if CACHED_LEVEL
        .compare_exchange(
            LEVEL_UNRESOLVED,
            LEVEL_RESOLVING,
            Ordering::SeqCst,
            Ordering::Relaxed,
        )
        .is_err()
    {
        // Another thread/reentrant call. Return Strict until resolved.
        let v = CACHED_LEVEL.load(Ordering::Relaxed);
        return if v != LEVEL_UNRESOLVED && v != LEVEL_RESOLVING {
            u8_to_level(v)
        } else {
            SafetyLevel::Strict
        };
    }

    // We own the resolution. Read env var (may trigger reentrant calls to our
    // exported functions like strlen — those will see RESOLVING and return Strict).
    let level = std::env::var("FRANKENLIBC_MODE")
        .map(|v| parse_runtime_mode_env(&v))
        .unwrap_or_default();
    CACHED_LEVEL.store(level_to_u8(level), Ordering::Release);
    level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_safety_levels() {
        assert_eq!(SafetyLevel::from_str_loose("strict"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("STRICT"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("default"), SafetyLevel::Strict);
        assert_eq!(SafetyLevel::from_str_loose("abi"), SafetyLevel::Strict);
        assert_eq!(
            SafetyLevel::from_str_loose("hardened"),
            SafetyLevel::Hardened
        );
        assert_eq!(SafetyLevel::from_str_loose("repair"), SafetyLevel::Hardened);
        assert_eq!(SafetyLevel::from_str_loose("tsm"), SafetyLevel::Hardened);
        assert_eq!(SafetyLevel::from_str_loose("off"), SafetyLevel::Off);
        assert_eq!(SafetyLevel::from_str_loose("none"), SafetyLevel::Off);
        assert_eq!(SafetyLevel::from_str_loose("bogus"), SafetyLevel::Strict);
    }

    #[test]
    fn runtime_mode_parser_is_strict_or_hardened_only() {
        assert_eq!(parse_runtime_mode_env("strict"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("hardened"), SafetyLevel::Hardened);
        assert_eq!(parse_runtime_mode_env("repair"), SafetyLevel::Hardened);
        assert_eq!(parse_runtime_mode_env("off"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("none"), SafetyLevel::Strict);
        assert_eq!(parse_runtime_mode_env("bogus"), SafetyLevel::Strict);
    }

    #[test]
    fn default_is_strict() {
        assert_eq!(SafetyLevel::default(), SafetyLevel::Strict);
    }

    #[test]
    fn healing_only_in_hardened() {
        assert!(!SafetyLevel::Strict.heals_enabled());
        assert!(SafetyLevel::Hardened.heals_enabled());
        assert!(!SafetyLevel::Off.heals_enabled());
    }

    #[test]
    fn validation_except_off() {
        assert!(SafetyLevel::Strict.validation_enabled());
        assert!(SafetyLevel::Hardened.validation_enabled());
        assert!(!SafetyLevel::Off.validation_enabled());
    }

    #[test]
    fn cached_mode_is_process_sticky_until_cache_reset() {
        let previous = CACHED_LEVEL.swap(LEVEL_STRICT, Ordering::SeqCst);
        assert_eq!(safety_level(), SafetyLevel::Strict);
        assert_eq!(safety_level(), SafetyLevel::Strict);

        CACHED_LEVEL.store(LEVEL_HARDENED, Ordering::SeqCst);
        assert_eq!(safety_level(), SafetyLevel::Hardened);
        assert_eq!(safety_level(), SafetyLevel::Hardened);

        CACHED_LEVEL.store(previous, Ordering::SeqCst);
    }

    #[test]
    fn resolving_state_returns_strict_safe_default() {
        let previous = CACHED_LEVEL.swap(LEVEL_RESOLVING, Ordering::SeqCst);
        assert_eq!(safety_level(), SafetyLevel::Strict);
        CACHED_LEVEL.store(previous, Ordering::SeqCst);
    }
}
