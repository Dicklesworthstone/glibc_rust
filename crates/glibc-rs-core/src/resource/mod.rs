//! Resource usage and limits.
//!
//! Implements `<sys/resource.h>` functions for querying and setting
//! process resource limits.

/// Resource limit identifiers.
pub const RLIMIT_CPU: i32 = 0;
pub const RLIMIT_FSIZE: i32 = 1;
pub const RLIMIT_DATA: i32 = 2;
pub const RLIMIT_STACK: i32 = 3;
pub const RLIMIT_CORE: i32 = 4;
pub const RLIMIT_NOFILE: i32 = 7;
pub const RLIMIT_AS: i32 = 9;

/// Resource limit values (like `struct rlimit`).
#[derive(Debug, Clone, Copy, Default)]
pub struct Rlimit {
    /// Soft limit.
    pub rlim_cur: u64,
    /// Hard limit (ceiling for soft limit).
    pub rlim_max: u64,
}

/// Gets the resource limit for the specified resource.
///
/// Equivalent to C `getrlimit`. Returns 0 on success, -1 on error.
pub fn getrlimit(_resource: i32, _rlim: &mut Rlimit) -> i32 {
    todo!("POSIX getrlimit: implementation pending")
}

/// Sets the resource limit for the specified resource.
///
/// Equivalent to C `setrlimit`. Returns 0 on success, -1 on error.
pub fn setrlimit(_resource: i32, _rlim: &Rlimit) -> i32 {
    todo!("POSIX setrlimit: implementation pending")
}
