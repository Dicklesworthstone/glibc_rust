//! Raw x86_64 Linux syscall primitives.
//!
//! Each function issues a single `syscall` instruction with the specified
//! number of arguments. The return value is the raw kernel return in `rax`.
//!
//! # ABI
//!
//! ```text
//! syscall number → rax
//! arg1           → rdi
//! arg2           → rsi
//! arg3           → rdx
//! arg4           → r10
//! arg5           → r8
//! arg6           → r9
//! return         → rax
//! clobbered      → rcx, r11
//! ```

use core::arch::asm;

/// Issue a syscall with 0 arguments.
///
/// # Safety
///
/// The caller must supply a valid syscall number and accept the kernel's
/// return value semantics.
#[inline]
pub unsafe fn syscall0(nr: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees nr is valid.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 1 argument.
///
/// # Safety
///
/// The caller must supply valid syscall number and argument.
#[inline]
pub unsafe fn syscall1(nr: usize, a1: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 2 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 3 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 4 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
pub unsafe fn syscall4(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 5 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
pub unsafe fn syscall5(nr: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// Issue a syscall with 6 arguments.
///
/// # Safety
///
/// The caller must supply valid syscall number and arguments.
#[inline]
pub unsafe fn syscall6(
    nr: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
) -> usize {
    let ret: usize;
    // SAFETY: Inline asm issues syscall instruction. Caller guarantees validity.
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") nr => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            in("r8") a5,
            in("r9") a6,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}
