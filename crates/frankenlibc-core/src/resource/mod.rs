//! Resource usage and limits — validators and constants.
//!
//! Implements `<sys/resource.h>` pure-logic helpers. Actual syscall
//! invocations live in the ABI crate.

/// Resource limit identifiers.
pub const RLIMIT_CPU: i32 = 0;
pub const RLIMIT_FSIZE: i32 = 1;
pub const RLIMIT_DATA: i32 = 2;
pub const RLIMIT_STACK: i32 = 3;
pub const RLIMIT_CORE: i32 = 4;
pub const RLIMIT_NOFILE: i32 = 7;
pub const RLIMIT_AS: i32 = 9;

/// Infinity sentinel for resource limits.
pub const RLIM_INFINITY: u64 = u64::MAX;

/// Resource limit values (like `struct rlimit`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rlimit {
    /// Soft limit.
    pub rlim_cur: u64,
    /// Hard limit (ceiling for soft limit).
    pub rlim_max: u64,
}

/// Returns `true` if `resource` is a known resource identifier.
#[inline]
pub fn valid_resource(resource: i32) -> bool {
    matches!(
        resource,
        RLIMIT_CPU
            | RLIMIT_FSIZE
            | RLIMIT_DATA
            | RLIMIT_STACK
            | RLIMIT_CORE
            | RLIMIT_NOFILE
            | RLIMIT_AS
    )
}

/// Returns `true` if the rlimit has a valid relationship (soft <= hard).
#[inline]
pub fn valid_rlimit(rlim: &Rlimit) -> bool {
    rlim.rlim_cur <= rlim.rlim_max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_resource() {
        assert!(valid_resource(RLIMIT_CPU));
        assert!(valid_resource(RLIMIT_FSIZE));
        assert!(valid_resource(RLIMIT_DATA));
        assert!(valid_resource(RLIMIT_STACK));
        assert!(valid_resource(RLIMIT_CORE));
        assert!(valid_resource(RLIMIT_NOFILE));
        assert!(valid_resource(RLIMIT_AS));
        assert!(!valid_resource(-1));
        assert!(!valid_resource(100));
        assert!(!valid_resource(5)); // gap between CORE=4 and NOFILE=7
    }

    #[test]
    fn test_valid_rlimit() {
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: 100,
            rlim_max: 200,
        }));
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: 200,
            rlim_max: 200,
        }));
        assert!(valid_rlimit(&Rlimit {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        }));
        assert!(!valid_rlimit(&Rlimit {
            rlim_cur: 201,
            rlim_max: 200,
        }));
    }
}
