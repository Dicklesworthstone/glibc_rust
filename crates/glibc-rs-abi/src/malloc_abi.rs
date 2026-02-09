//! ABI layer for memory allocation functions (`malloc`, `free`, `calloc`, `realloc`).
//!
//! These functions integrate with the membrane's generational arena for temporal safety.
//! All allocations are tracked with fingerprint headers and canaries for buffer overflow
//! detection. Double-free and use-after-free are caught via generation counters and
//! quarantine queues.
//!
//! In test mode, this module is suppressed to avoid shadowing the system allocator
//! (which would cause infinite recursion in the test binary itself).

use std::ffi::c_void;
use std::sync::OnceLock;

use glibc_rs_membrane::arena::{AllocationArena, FreeResult};
use glibc_rs_membrane::config::safety_level;
use glibc_rs_membrane::heal::{HealingAction, global_healing_policy};

/// Global allocation arena instance.
///
/// All `malloc`/`free`/`calloc`/`realloc` operations go through this arena,
/// which provides generational tracking, fingerprint integrity, and quarantine.
fn global_arena() -> &'static AllocationArena {
    static ARENA: OnceLock<AllocationArena> = OnceLock::new();
    ARENA.get_or_init(AllocationArena::new)
}

// ---------------------------------------------------------------------------
// malloc
// ---------------------------------------------------------------------------

/// POSIX `malloc` -- allocates `size` bytes of uninitialized memory.
///
/// Returns a pointer to the allocated memory, or null on failure.
/// The memory is not initialized.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    if size == 0 {
        // POSIX allows returning either null or a unique pointer for size 0.
        // We return a minimal allocation for consistency.
        return match global_arena().allocate(1) {
            Some(ptr) => ptr.cast(),
            None => std::ptr::null_mut(),
        };
    }

    match global_arena().allocate(size) {
        Some(ptr) => ptr.cast(),
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// free
// ---------------------------------------------------------------------------

/// POSIX `free` -- deallocates memory previously allocated by `malloc`, `calloc`,
/// or `realloc`.
///
/// If `ptr` is null, no operation is performed (per POSIX).
///
/// # Safety
///
/// `ptr` must have been returned by a previous call to `malloc`, `calloc`, or
/// `realloc`, and must not have been freed already.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }

    let result = global_arena().free(ptr.cast());

    match result {
        FreeResult::Freed => {}
        FreeResult::FreedWithCanaryCorruption => {
            // Buffer overflow was detected -- the canary after the allocation was
            // corrupted. In strict mode we still free (damage is done). Metrics
            // are recorded by the arena.
        }
        FreeResult::DoubleFree => {
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreDoubleFree);
            }
            // Strict mode: double free is silently ignored too (safer than UB).
            // A real glibc would abort, but our membrane prioritizes defined behavior.
        }
        FreeResult::ForeignPointer => {
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::IgnoreForeignFree);
            }
            // Strict mode: foreign pointer free is ignored.
        }
        FreeResult::InvalidPointer => {
            // Pointer is in an invalid state. Ignore to avoid undefined behavior.
        }
    }
}

// ---------------------------------------------------------------------------
// calloc
// ---------------------------------------------------------------------------

/// POSIX `calloc` -- allocates memory for an array of `nmemb` elements of `size`
/// bytes each, and initializes all bytes to zero.
///
/// Returns null if the multiplication overflows or allocation fails.
///
/// # Safety
///
/// Caller must eventually `free` the returned pointer exactly once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn calloc(nmemb: usize, size: usize) -> *mut c_void {
    let total = match nmemb.checked_mul(size) {
        Some(t) => t,
        None => return std::ptr::null_mut(), // Overflow
    };

    if total == 0 {
        return match global_arena().allocate(1) {
            Some(ptr) => {
                // SAFETY: ptr is valid for at least 1 byte from the arena.
                unsafe { std::ptr::write_bytes(ptr, 0, 1) };
                ptr.cast()
            }
            None => std::ptr::null_mut(),
        };
    }

    match global_arena().allocate(total) {
        Some(ptr) => {
            // SAFETY: ptr is valid for `total` bytes from the arena allocate contract.
            unsafe { std::ptr::write_bytes(ptr, 0, total) };
            ptr.cast()
        }
        None => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// realloc
// ---------------------------------------------------------------------------

/// POSIX `realloc` -- changes the size of a previously allocated memory block.
///
/// - If `ptr` is null, behaves like `malloc(size)`.
/// - If `size` is 0 and `ptr` is non-null, behaves like `free(ptr)` and returns null.
/// - Otherwise, allocates new memory of `size`, copies the old data, frees the old.
///
/// # Safety
///
/// `ptr` must be null or a pointer previously returned by `malloc`/`calloc`/`realloc`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    // realloc(NULL, size) == malloc(size)
    if ptr.is_null() {
        return unsafe { malloc(size) };
    }

    // realloc(ptr, 0) == free(ptr), return NULL
    if size == 0 {
        unsafe { free(ptr) };
        return std::ptr::null_mut();
    }

    let arena = global_arena();

    // Look up old allocation to get its size
    let old_addr = ptr as usize;
    let old_size = match arena.lookup(old_addr) {
        Some(slot) => slot.user_size,
        None => {
            // Foreign pointer -- in hardened mode, treat as malloc
            if safety_level().heals_enabled() {
                let policy = global_healing_policy();
                policy.record(&HealingAction::ReallocAsMalloc { size });
                return unsafe { malloc(size) };
            }
            // Strict mode: cannot determine old size; treat as malloc
            return unsafe { malloc(size) };
        }
    };

    // Allocate new block
    let new_ptr = match arena.allocate(size) {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    // Copy old data (up to the smaller of old and new sizes)
    let copy_size = old_size.min(size);

    // SAFETY: old ptr is valid for old_size bytes, new ptr is valid for size bytes.
    // copy_size <= min(old_size, size), so both reads and writes are in bounds.
    unsafe {
        std::ptr::copy_nonoverlapping(ptr.cast::<u8>(), new_ptr, copy_size);
    }

    // Free old block
    arena.free(ptr.cast());

    new_ptr.cast()
}
