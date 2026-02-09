//! ABI layer for `<string.h>` functions.
//!
//! Each function is an `extern "C"` entry point that:
//! 1. Validates pointer arguments through the membrane pipeline
//! 2. In hardened mode, applies healing (bounds clamping, null truncation)
//! 3. Delegates to `glibc-rs-core` safe implementations or inline unsafe primitives

use std::ffi::{c_char, c_int, c_void};

// ---------------------------------------------------------------------------
// memcpy
// ---------------------------------------------------------------------------

/// POSIX `memcpy` -- copies `n` bytes from `src` to `dst`.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes and do not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: Caller contract for memcpy guarantees validity.
    // Membrane validation will be wired here.
    unsafe {
        std::ptr::copy_nonoverlapping(src.cast::<u8>(), dst.cast::<u8>(), n);
    }
    dst
}

// ---------------------------------------------------------------------------
// memmove
// ---------------------------------------------------------------------------

/// POSIX `memmove` -- copies `n` bytes from `src` to `dst`, handling overlap.
///
/// # Safety
///
/// Caller must ensure `src` and `dst` are valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    if n == 0 {
        return dst;
    }
    if dst.is_null() || src.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: Caller contract for memmove guarantees validity; copy handles overlap.
    unsafe {
        std::ptr::copy(src.cast::<u8>(), dst.cast::<u8>(), n);
    }
    dst
}

// ---------------------------------------------------------------------------
// memset
// ---------------------------------------------------------------------------

/// POSIX `memset` -- fills `n` bytes of `dst` with byte value `c`.
///
/// # Safety
///
/// Caller must ensure `dst` is valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut c_void, c: c_int, n: usize) -> *mut c_void {
    if n == 0 {
        return dst;
    }
    if dst.is_null() {
        return std::ptr::null_mut();
    }

    let byte = c as u8;

    // SAFETY: Caller contract for memset guarantees dst is valid for n bytes.
    unsafe {
        std::ptr::write_bytes(dst.cast::<u8>(), byte, n);
    }
    dst
}

// ---------------------------------------------------------------------------
// memcmp
// ---------------------------------------------------------------------------

/// POSIX `memcmp` -- compares `n` bytes of `s1` and `s2`.
///
/// Returns negative, zero, or positive integer.
///
/// # Safety
///
/// Caller must ensure `s1` and `s2` are valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    if s1.is_null() || s2.is_null() {
        // Membrane: null pointer in memcmp is UB in C. Return safe default.
        return 0;
    }

    // SAFETY: Caller guarantees both pointers are valid for n bytes.
    unsafe {
        let a = std::slice::from_raw_parts(s1.cast::<u8>(), n);
        let b = std::slice::from_raw_parts(s2.cast::<u8>(), n);
        for i in 0..n {
            let diff = (a[i] as c_int) - (b[i] as c_int);
            if diff != 0 {
                return diff;
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// memchr
// ---------------------------------------------------------------------------

/// POSIX `memchr` -- locates first occurrence of byte `c` in first `n` bytes of `s`.
///
/// Returns pointer to the matching byte, or null if not found.
///
/// # Safety
///
/// Caller must ensure `s` is valid for `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memchr(s: *const c_void, c: c_int, n: usize) -> *mut c_void {
    if n == 0 || s.is_null() {
        return std::ptr::null_mut();
    }

    let needle = c as u8;

    // SAFETY: Caller guarantees s is valid for n bytes.
    unsafe {
        let bytes = std::slice::from_raw_parts(s.cast::<u8>(), n);
        for (i, &byte) in bytes.iter().enumerate() {
            if byte == needle {
                return (s as *mut u8).add(i).cast();
            }
        }
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// strlen
// ---------------------------------------------------------------------------

/// POSIX `strlen` -- computes length of null-terminated string.
///
/// # Safety
///
/// Caller must ensure `s` points to a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const c_char) -> usize {
    if s.is_null() {
        // Membrane: null pointer in strlen is UB in C. Return safe default.
        return 0;
    }

    // SAFETY: Caller guarantees s is a valid null-terminated string.
    unsafe {
        let mut len = 0usize;
        while *s.add(len) != 0 {
            len += 1;
        }
        len
    }
}

// ---------------------------------------------------------------------------
// strcmp
// ---------------------------------------------------------------------------

/// POSIX `strcmp` -- compares two null-terminated strings lexicographically.
///
/// # Safety
///
/// Caller must ensure both `s1` and `s2` point to valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    if s1.is_null() || s2.is_null() {
        return 0;
    }

    // SAFETY: Caller guarantees both pointers are valid null-terminated strings.
    unsafe {
        let mut i = 0usize;
        loop {
            let a = *s1.add(i) as u8;
            let b = *s2.add(i) as u8;
            if a != b || a == 0 {
                return (a as c_int) - (b as c_int);
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// strcpy
// ---------------------------------------------------------------------------

/// POSIX `strcpy` -- copies the null-terminated string `src` into `dst`.
///
/// # Safety
///
/// Caller must ensure `dst` is large enough to hold `src` including the null terminator,
/// and that the buffers do not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    // SAFETY: Caller guarantees dst has enough space and no overlap.
    unsafe {
        let mut i = 0usize;
        loop {
            let ch = *src.add(i);
            *dst.add(i) = ch;
            if ch == 0 {
                break;
            }
            i += 1;
        }
    }
    dst
}

// ---------------------------------------------------------------------------
// strncpy
// ---------------------------------------------------------------------------

/// POSIX `strncpy` -- copies at most `n` bytes from `src` to `dst`.
///
/// If `src` is shorter than `n`, the remainder of `dst` is filled with null bytes.
///
/// # Safety
///
/// Caller must ensure `dst` is at least `n` bytes and `src` is a valid string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }

    // SAFETY: Caller guarantees dst is valid for n bytes and src is valid.
    unsafe {
        let mut i = 0usize;
        // Copy src until null or n bytes
        while i < n {
            let ch = *src.add(i);
            *dst.add(i) = ch;
            if ch == 0 {
                i += 1;
                break;
            }
            i += 1;
        }
        // Pad remainder with null bytes
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    dst
}

// ---------------------------------------------------------------------------
// strcat
// ---------------------------------------------------------------------------

/// POSIX `strcat` -- appends `src` to the end of `dst`.
///
/// # Safety
///
/// Caller must ensure `dst` has enough space for the concatenated result
/// including null terminator, and that the buffers do not overlap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcat(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    if dst.is_null() || src.is_null() {
        return dst;
    }

    // SAFETY: Caller guarantees dst has sufficient space.
    unsafe {
        // Find end of dst
        let mut dst_len = 0usize;
        while *dst.add(dst_len) != 0 {
            dst_len += 1;
        }
        // Copy src
        let mut i = 0usize;
        loop {
            let ch = *src.add(i);
            *dst.add(dst_len + i) = ch;
            if ch == 0 {
                break;
            }
            i += 1;
        }
    }
    dst
}

// ---------------------------------------------------------------------------
// strncat
// ---------------------------------------------------------------------------

/// POSIX `strncat` -- appends at most `n` bytes from `src` to `dst`.
///
/// Always null-terminates the result.
///
/// # Safety
///
/// Caller must ensure `dst` has enough space for the concatenated result
/// (up to `strlen(dst) + n + 1` bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncat(dst: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    if dst.is_null() || src.is_null() || n == 0 {
        return dst;
    }

    // SAFETY: Caller guarantees dst has sufficient space.
    unsafe {
        // Find end of dst
        let mut dst_len = 0usize;
        while *dst.add(dst_len) != 0 {
            dst_len += 1;
        }
        // Copy at most n bytes from src
        let mut i = 0usize;
        while i < n {
            let ch = *src.add(i);
            if ch == 0 {
                break;
            }
            *dst.add(dst_len + i) = ch;
            i += 1;
        }
        // Always null-terminate
        *dst.add(dst_len + i) = 0;
    }
    dst
}

// ---------------------------------------------------------------------------
// strchr
// ---------------------------------------------------------------------------

/// POSIX `strchr` -- locates the first occurrence of `c` in the string `s`.
///
/// Returns pointer to the first occurrence, or null if not found.
/// If `c` is '\0', returns pointer to the terminating null byte.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let target = c as c_char;

    // SAFETY: Caller guarantees s is a valid null-terminated string.
    unsafe {
        let mut i = 0usize;
        loop {
            let ch = *s.add(i);
            if ch == target {
                return s.add(i) as *mut c_char;
            }
            if ch == 0 {
                return std::ptr::null_mut();
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// strrchr
// ---------------------------------------------------------------------------

/// POSIX `strrchr` -- locates the last occurrence of `c` in the string `s`.
///
/// Returns pointer to the last occurrence, or null if not found.
///
/// # Safety
///
/// Caller must ensure `s` is a valid null-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const c_char, c: c_int) -> *mut c_char {
    if s.is_null() {
        return std::ptr::null_mut();
    }

    let target = c as c_char;
    let mut result: *mut c_char = std::ptr::null_mut();

    // SAFETY: Caller guarantees s is a valid null-terminated string.
    unsafe {
        let mut i = 0usize;
        loop {
            let ch = *s.add(i);
            if ch == target {
                result = s.add(i) as *mut c_char;
            }
            if ch == 0 {
                break;
            }
            i += 1;
        }
    }
    result
}

// ---------------------------------------------------------------------------
// strstr
// ---------------------------------------------------------------------------

/// POSIX `strstr` -- locates the first occurrence of substring `needle` in `haystack`.
///
/// Returns pointer to the beginning of the located substring, or null if not found.
/// If `needle` is empty, returns `haystack`.
///
/// # Safety
///
/// Caller must ensure both `haystack` and `needle` are valid null-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if haystack.is_null() {
        return std::ptr::null_mut();
    }
    if needle.is_null() {
        return haystack as *mut c_char;
    }

    // SAFETY: Caller guarantees both are valid null-terminated strings.
    unsafe {
        // Empty needle matches immediately
        if *needle == 0 {
            return haystack as *mut c_char;
        }

        let mut h = 0usize;
        while *haystack.add(h) != 0 {
            let mut n = 0usize;
            while *needle.add(n) != 0 && *haystack.add(h + n) == *needle.add(n) {
                n += 1;
            }
            if *needle.add(n) == 0 {
                return haystack.add(h) as *mut c_char;
            }
            h += 1;
        }
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// strtok
// ---------------------------------------------------------------------------

// Thread-local save pointer for strtok state.
thread_local! {
    static STRTOK_SAVE: std::cell::Cell<*mut c_char> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// POSIX `strtok` -- splits string into tokens delimited by characters in `delim`.
///
/// On the first call, `s` should point to the string to tokenize.
/// On subsequent calls, `s` should be null to continue tokenizing the same string.
///
/// # Safety
///
/// Caller must ensure `s` (if non-null) and `delim` are valid null-terminated strings.
/// Note: `strtok` modifies the source string and is not reentrant. Use `strtok_r` for
/// reentrant usage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtok(s: *mut c_char, delim: *const c_char) -> *mut c_char {
    if delim.is_null() {
        return std::ptr::null_mut();
    }

    // SAFETY: Thread-local access; strtok is specified as non-reentrant per POSIX.
    unsafe {
        let saved = STRTOK_SAVE.get();
        let mut current = if s.is_null() { saved } else { s };

        if current.is_null() {
            return std::ptr::null_mut();
        }

        // Skip leading delimiters
        while *current != 0 && is_delim(*current, delim) {
            current = current.add(1);
        }

        if *current == 0 {
            STRTOK_SAVE.set(std::ptr::null_mut());
            return std::ptr::null_mut();
        }

        // Find end of token
        let token_start = current;
        while *current != 0 && !is_delim(*current, delim) {
            current = current.add(1);
        }

        if *current != 0 {
            *current = 0;
            STRTOK_SAVE.set(current.add(1));
        } else {
            STRTOK_SAVE.set(std::ptr::null_mut());
        }

        token_start
    }
}

/// Check if character `c` is in the delimiter set `delim`.
///
/// # Safety
///
/// `delim` must be a valid null-terminated string.
unsafe fn is_delim(c: c_char, delim: *const c_char) -> bool {
    unsafe {
        let mut i = 0usize;
        while *delim.add(i) != 0 {
            if c == *delim.add(i) {
                return true;
            }
            i += 1;
        }
        false
    }
}
