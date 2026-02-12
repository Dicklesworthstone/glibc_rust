//! Shared startup/bootstrap helpers used by phase-0 CRT plumbing.

use std::ffi::c_int;

/// Maximum number of argv/envp/auxv entries scanned in phase-0 startup.
pub const MAX_STARTUP_SCAN: usize = 4096;

/// ELF auxv terminator key.
pub const AT_NULL: usize = 0;
/// ELF auxv secure-mode key.
pub const AT_SECURE: usize = 23;

/// Phase-0 startup invariants captured at `__libc_start_main` boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartupInvariants {
    pub argc: usize,
    pub argv_count: usize,
    pub env_count: usize,
    pub auxv_count: usize,
    pub secure_mode: bool,
}

#[must_use]
pub fn normalize_argc(argc: c_int) -> usize {
    if argc < 0 { 0 } else { argc as usize }
}

#[must_use]
pub fn scan_auxv_pairs(entries: &[(usize, usize)], max_pairs: usize) -> (usize, bool) {
    let mut count = 0usize;
    let mut secure_mode = false;

    for &(key, value) in entries.iter().take(max_pairs) {
        if key == AT_NULL {
            break;
        }
        if key == AT_SECURE && value != 0 {
            secure_mode = true;
        }
        count += 1;
    }

    (count, secure_mode)
}

#[must_use]
pub fn build_invariants(
    argc: c_int,
    argv_count: usize,
    env_count: usize,
    auxv_count: usize,
    secure_mode: bool,
) -> StartupInvariants {
    StartupInvariants {
        argc: normalize_argc(argc),
        argv_count,
        env_count,
        auxv_count,
        secure_mode,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_argc_clamps_negative() {
        assert_eq!(normalize_argc(-7), 0);
        assert_eq!(normalize_argc(0), 0);
        assert_eq!(normalize_argc(3), 3);
    }

    #[test]
    fn scan_auxv_stops_at_null() {
        let entries = [
            (15usize, 0usize),
            (AT_SECURE, 1usize),
            (AT_NULL, 0usize),
            (7usize, 0usize),
        ];
        let (count, secure) = scan_auxv_pairs(&entries, 16);
        assert_eq!(count, 2);
        assert!(secure);
    }

    #[test]
    fn scan_auxv_respects_max_pairs() {
        let entries = [(1usize, 0usize), (AT_SECURE, 1usize), (AT_NULL, 0usize)];
        let (count, secure) = scan_auxv_pairs(&entries, 1);
        assert_eq!(count, 1);
        assert!(!secure);
    }

    #[test]
    fn build_invariants_records_counts() {
        let inv = build_invariants(2, 2, 3, 4, true);
        assert_eq!(inv.argc, 2);
        assert_eq!(inv.argv_count, 2);
        assert_eq!(inv.env_count, 3);
        assert_eq!(inv.auxv_count, 4);
        assert!(inv.secure_mode);
    }
}
