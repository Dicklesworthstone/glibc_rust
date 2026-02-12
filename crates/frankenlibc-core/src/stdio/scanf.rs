//! scanf family functions.
//!
//! Implementation pending. The scanf format string parser shares structural
//! similarity with printf but operates in reverse (parsing input rather than
//! generating output). A clean-room implementation will be added in a future
//! phase, following the same spec-first methodology.

// Placeholder: no-op that returns 0 items scanned.
// The ABI layer falls back to libc::sscanf for bootstrap.
pub fn scanf_stub() -> i32 {
    0
}
