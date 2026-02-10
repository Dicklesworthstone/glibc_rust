//! POSIX mutex operations.
//!
//! Implements pthread mutex constants, validators, and type definitions.
//! Actual locking is performed via libc syscalls at the ABI layer;
//! this module provides the safe-Rust validation logic.

// ---------------------------------------------------------------------------
// Mutex type constants
// ---------------------------------------------------------------------------

/// Normal (default) mutex — no error checking, no recursive locking.
pub const PTHREAD_MUTEX_NORMAL: i32 = 0;
/// Recursive mutex — the owning thread can re-lock without deadlock.
pub const PTHREAD_MUTEX_RECURSIVE: i32 = 1;
/// Error-checking mutex — returns EDEADLK on recursive lock.
pub const PTHREAD_MUTEX_ERRORCHECK: i32 = 2;
/// Default mutex type (alias for NORMAL on Linux).
pub const PTHREAD_MUTEX_DEFAULT: i32 = PTHREAD_MUTEX_NORMAL;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `kind` is a recognized mutex type.
#[must_use]
pub const fn valid_mutex_type(kind: i32) -> bool {
    matches!(
        kind,
        PTHREAD_MUTEX_NORMAL | PTHREAD_MUTEX_RECURSIVE | PTHREAD_MUTEX_ERRORCHECK
    )
}

/// Sanitize mutex type: if unknown, default to NORMAL.
#[must_use]
pub const fn sanitize_mutex_type(kind: i32) -> i32 {
    if valid_mutex_type(kind) {
        kind
    } else {
        PTHREAD_MUTEX_NORMAL
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutex_type_constants() {
        assert_eq!(PTHREAD_MUTEX_NORMAL, 0);
        assert_eq!(PTHREAD_MUTEX_RECURSIVE, 1);
        assert_eq!(PTHREAD_MUTEX_ERRORCHECK, 2);
        assert_eq!(PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_NORMAL);
    }

    #[test]
    fn valid_mutex_type_check() {
        assert!(valid_mutex_type(PTHREAD_MUTEX_NORMAL));
        assert!(valid_mutex_type(PTHREAD_MUTEX_RECURSIVE));
        assert!(valid_mutex_type(PTHREAD_MUTEX_ERRORCHECK));
        assert!(!valid_mutex_type(3));
        assert!(!valid_mutex_type(-1));
    }

    #[test]
    fn sanitize_mutex_type_check() {
        assert_eq!(
            sanitize_mutex_type(PTHREAD_MUTEX_RECURSIVE),
            PTHREAD_MUTEX_RECURSIVE
        );
        assert_eq!(sanitize_mutex_type(99), PTHREAD_MUTEX_NORMAL);
        assert_eq!(sanitize_mutex_type(-1), PTHREAD_MUTEX_NORMAL);
    }
}
