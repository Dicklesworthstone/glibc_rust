//! POSIX condition variable operations.
//!
//! Implements pthread condition variable constants and validators.
//! Actual signaling is performed via libc syscalls at the ABI layer;
//! this module provides the safe-Rust validation logic.

// ---------------------------------------------------------------------------
// Condition variable clock constants
// ---------------------------------------------------------------------------

/// Use CLOCK_REALTIME for condition variable timed waits (default).
pub const PTHREAD_COND_CLOCK_REALTIME: i32 = 0;
/// Use CLOCK_MONOTONIC for condition variable timed waits.
pub const PTHREAD_COND_CLOCK_MONOTONIC: i32 = 1;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `clock_id` is a recognized condition variable clock.
#[must_use]
pub const fn valid_cond_clock(clock_id: i32) -> bool {
    matches!(
        clock_id,
        PTHREAD_COND_CLOCK_REALTIME | PTHREAD_COND_CLOCK_MONOTONIC
    )
}

/// Sanitize clock id: if unknown, default to REALTIME.
#[must_use]
pub const fn sanitize_cond_clock(clock_id: i32) -> i32 {
    if valid_cond_clock(clock_id) {
        clock_id
    } else {
        PTHREAD_COND_CLOCK_REALTIME
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cond_clock_constants() {
        assert_eq!(PTHREAD_COND_CLOCK_REALTIME, 0);
        assert_eq!(PTHREAD_COND_CLOCK_MONOTONIC, 1);
    }

    #[test]
    fn valid_cond_clock_check() {
        assert!(valid_cond_clock(PTHREAD_COND_CLOCK_REALTIME));
        assert!(valid_cond_clock(PTHREAD_COND_CLOCK_MONOTONIC));
        assert!(!valid_cond_clock(2));
        assert!(!valid_cond_clock(-1));
    }

    #[test]
    fn sanitize_cond_clock_check() {
        assert_eq!(
            sanitize_cond_clock(PTHREAD_COND_CLOCK_MONOTONIC),
            PTHREAD_COND_CLOCK_MONOTONIC
        );
        assert_eq!(sanitize_cond_clock(99), PTHREAD_COND_CLOCK_REALTIME);
    }

    #[test]
    fn sanitize_cond_clock_extremes_default_to_realtime() {
        assert_eq!(sanitize_cond_clock(i32::MIN), PTHREAD_COND_CLOCK_REALTIME);
        assert_eq!(sanitize_cond_clock(i32::MAX), PTHREAD_COND_CLOCK_REALTIME);
    }
}
