//! ABI layer for POSIX I/O functions (`dup`, `dup2`, `pipe`, `fcntl`).
//!
//! Validates via `glibc_rs_core::io` helpers, then calls `libc`.

use std::ffi::c_int;

use glibc_rs_core::errno;
use glibc_rs_core::io as io_core;
use glibc_rs_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::runtime_policy;

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
}

// ---------------------------------------------------------------------------
// dup
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup(oldfd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(oldfd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::dup(oldfd) };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(errno::EBADF) };
    }
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// dup2
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dup2(oldfd: c_int, newfd: c_int) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, oldfd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(oldfd) || !io_core::valid_fd(newfd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::dup2(oldfd, newfd) };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(errno::EBADF) };
    }
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// pipe
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe(pipefd: *mut c_int) -> c_int {
    let (mode, decision) = runtime_policy::decide(ApiFamily::IoFd, 0, 0, true, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if pipefd.is_null() {
        if mode.heals_enabled() {
            runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
            return -1;
        }
        unsafe { set_abi_errno(errno::EFAULT) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::pipe(pipefd) };
    let adverse = rc != 0;
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}

// ---------------------------------------------------------------------------
// fcntl
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fcntl(fd: c_int, cmd: c_int, arg: libc::c_long) -> c_int {
    let (_, decision) = runtime_policy::decide(ApiFamily::IoFd, fd as usize, 0, false, true, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    if !io_core::valid_fd(fd) {
        unsafe { set_abi_errno(errno::EBADF) };
        runtime_policy::observe(ApiFamily::IoFd, decision.profile, 5, true);
        return -1;
    }

    let rc = unsafe { libc::fcntl(fd, cmd, arg) };
    let adverse = rc < 0;
    runtime_policy::observe(ApiFamily::IoFd, decision.profile, 10, adverse);
    rc
}
