//! Signal handling — validators and types.
//!
//! Implements `<signal.h>` pure-logic helpers. Actual syscall invocations
//! (`kill`, `sigaction`, etc.) live in the ABI crate.

/// Signal numbers.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;

/// Maximum signal number on Linux (NSIG - 1).
const MAX_SIGNAL: i32 = 64;

/// Returns `true` if `signum` is within the valid signal range (1..=64).
#[inline]
pub fn valid_signal(signum: i32) -> bool {
    (1..=MAX_SIGNAL).contains(&signum)
}

/// Returns `true` if `signum` can have a user-defined handler installed.
///
/// SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
#[inline]
pub fn catchable_signal(signum: i32) -> bool {
    valid_signal(signum) && signum != SIGKILL && signum != SIGSTOP
}

/// Signal set — a bitmask of up to 64 signals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigSet {
    bits: u64,
}

impl SigSet {
    /// Creates an empty signal set.
    #[inline]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a full signal set (all signals 1..=64).
    #[inline]
    pub const fn full() -> Self {
        Self { bits: u64::MAX }
    }

    /// Adds a signal to the set.
    #[inline]
    pub fn add(&mut self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        self.bits |= 1u64 << (signum - 1);
        true
    }

    /// Removes a signal from the set.
    #[inline]
    pub fn del(&mut self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        self.bits &= !(1u64 << (signum - 1));
        true
    }

    /// Returns `true` if the signal is in the set.
    #[inline]
    pub fn is_member(&self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        (self.bits & (1u64 << (signum - 1))) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signal() {
        assert!(!valid_signal(0));
        assert!(valid_signal(1));
        assert!(valid_signal(64));
        assert!(!valid_signal(65));
        assert!(!valid_signal(-1));
    }

    #[test]
    fn test_catchable_signal() {
        assert!(catchable_signal(SIGINT));
        assert!(catchable_signal(SIGTERM));
        assert!(catchable_signal(SIGUSR1));
        assert!(!catchable_signal(SIGKILL));
        assert!(!catchable_signal(SIGSTOP));
        assert!(!catchable_signal(0));
    }

    #[test]
    fn test_sigset_empty_full() {
        let empty = SigSet::empty();
        assert!(!empty.is_member(SIGINT));
        assert!(!empty.is_member(SIGKILL));

        let full = SigSet::full();
        assert!(full.is_member(SIGINT));
        assert!(full.is_member(SIGKILL));
        assert!(full.is_member(1));
        assert!(full.is_member(64));
    }

    #[test]
    fn test_sigset_add_del() {
        let mut set = SigSet::empty();
        assert!(set.add(SIGINT));
        assert!(set.is_member(SIGINT));
        assert!(!set.is_member(SIGTERM));

        assert!(set.add(SIGTERM));
        assert!(set.is_member(SIGTERM));

        assert!(set.del(SIGINT));
        assert!(!set.is_member(SIGINT));
        assert!(set.is_member(SIGTERM));

        // invalid signal
        assert!(!set.add(0));
        assert!(!set.add(65));
        assert!(!set.del(0));
        assert!(!set.is_member(0));
    }
}
