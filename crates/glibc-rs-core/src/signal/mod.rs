//! Signal handling.
//!
//! Implements `<signal.h>` functions for POSIX signal management.

/// Signal numbers.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGSEGV: i32 = 11;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;

/// Installs a signal handler for the given signal number.
///
/// Equivalent to C `signal`. Returns the previous handler disposition.
pub fn signal(_signum: i32, _handler: fn(i32)) -> Option<fn(i32)> {
    todo!("POSIX signal: implementation pending")
}

/// Sends a signal to the current process.
///
/// Equivalent to C `raise`. Returns 0 on success.
pub fn raise(_signum: i32) -> i32 {
    todo!("POSIX raise: implementation pending")
}

/// Sends a signal to a specified process.
///
/// Equivalent to C `kill`. Returns 0 on success, -1 on error.
pub fn kill(_pid: i32, _signum: i32) -> i32 {
    todo!("POSIX kill: implementation pending")
}

/// Sets the signal action for a given signal.
///
/// Equivalent to C `sigaction`. Returns 0 on success, -1 on error.
pub fn sigaction(_signum: i32) -> i32 {
    todo!("POSIX sigaction: implementation pending")
}
