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

/// Execute `clone` syscall with a child trampoline.
///
/// The child stack at `child_sp` must contain:
/// - `[child_sp + 0]`: function pointer (8 bytes)
/// - `[child_sp + 8]`: argument value (8 bytes)
///
/// After clone, the child thread:
/// 1. Pops the function pointer into `rax`
/// 2. Pops the argument into `rdi` (first C ABI parameter)
/// 3. Aligns the stack to 16 bytes
/// 4. Calls the function via `call rax`
/// 5. On return, exits the thread via `SYS_exit` with the return value
///
/// The parent receives the child TID in `rax` (positive) or `-errno` (negative).
///
/// # Safety
///
/// - `child_sp` must point to a valid, writable stack with fn_ptr and arg placed.
/// - The function pointer must be valid and callable.
/// - `parent_tid` and `child_tid` must be valid if corresponding flags are set.
#[inline]
pub unsafe fn clone_thread_asm(
    flags: usize,
    child_sp: usize,
    parent_tid: usize,
    child_tid: usize,
    tls: usize,
) -> usize {
    let ret: usize;
    // SAFETY: The caller guarantees that child_sp points to a valid stack with
    // fn_ptr at [sp] and arg at [sp+8]. The clone syscall creates a new thread
    // that starts executing at the instruction after `syscall`. The child path
    // (rax==0) pops fn_ptr and arg from its stack and calls the function. The
    // parent path (rax>0) falls through to label 2.
    unsafe {
        asm!(
            // Move child_tid and tls into the registers clone expects
            "mov r10, {ctid}",
            "mov r8, {tls}",
            // SYS_clone = 56
            "mov eax, 56",
            "syscall",
            // Check: parent (rax > 0) or child (rax == 0)?
            "test rax, rax",
            "jnz 2f",
            // ===== Child path (rax == 0) =====
            // Clear frame pointer for clean backtraces
            "xor ebp, ebp",
            // Pop fn_ptr and arg from child stack
            "pop rax",            // fn_ptr -> rax
            "pop rdi",            // arg -> rdi (first C ABI argument)
            // Align stack to 16 bytes before call (defensive)
            "and rsp, -16",
            // Call fn_ptr(arg)
            "call rax",
            // fn_ptr returned — exit the thread with its return value
            "mov edi, eax",       // return value -> exit status
            "mov eax, 60",        // SYS_exit (thread exit, not exit_group)
            "syscall",
            "ud2",                // unreachable
            // ===== Parent path =====
            "2:",
            // rax = child TID (positive) or -errno (negative)
            ctid = in(reg) child_tid,
            tls = in(reg) tls,
            in("rdi") flags,
            in("rsi") child_sp,
            in("rdx") parent_tid,
            lateout("rax") ret,
            lateout("rcx") _,     // clobbered by syscall
            lateout("r11") _,     // clobbered by syscall
            options(nostack),
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
