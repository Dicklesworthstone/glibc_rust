//! Error number definitions.
//!
//! Implements `<errno.h>` support with thread-local errno storage.

// TODO: Use thread-local storage for per-thread errno values.

/// Well-known errno constants.
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EEXIST: i32 = 17;
pub const EINVAL: i32 = 22;
pub const ERANGE: i32 = 34;

/// Returns the current thread-local errno value.
///
/// Equivalent to reading C `errno`.
pub fn get_errno() -> i32 {
    todo!("POSIX errno: thread-local get implementation pending")
}

/// Sets the current thread-local errno value.
///
/// Equivalent to assigning to C `errno`.
pub fn set_errno(_value: i32) {
    todo!("POSIX errno: thread-local set implementation pending")
}
