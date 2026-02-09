//! Memory operations: memcpy, memmove, memset, memcmp, memchr, memrchr.
//!
//! These are safe Rust implementations operating on byte slices.
//! They correspond to the `<string.h>` memory functions in POSIX/C.

/// Copies `n` bytes from `src` to `dest`.
///
/// Equivalent to C `memcpy`. The source and destination slices must not overlap;
/// use [`memmove`] if they might. Only copies `min(n, src.len(), dest.len())` bytes.
///
/// Returns the number of bytes actually copied.
pub fn memcpy(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Copies `n` bytes from `src` to `dest`, handling overlapping regions correctly.
///
/// Equivalent to C `memmove`. Safe Rust slices never truly alias, so this
/// behaves identically to [`memcpy`] at the API level, but the implementation
/// uses `copy_within`-compatible logic.
///
/// Returns the number of bytes actually copied.
pub fn memmove(dest: &mut [u8], src: &[u8], n: usize) -> usize {
    let count = n.min(dest.len()).min(src.len());
    // In safe Rust with separate slices, copy_from_slice is fine.
    // For true overlapping (same buffer), callers should use slice::copy_within.
    dest[..count].copy_from_slice(&src[..count]);
    count
}

/// Fills the first `n` bytes of `dest` with the byte `value`.
///
/// Equivalent to C `memset(dest, c, n)`.
///
/// Returns the number of bytes actually set.
pub fn memset(dest: &mut [u8], value: u8, n: usize) -> usize {
    let count = n.min(dest.len());
    for byte in &mut dest[..count] {
        *byte = value;
    }
    count
}

/// Compares the first `n` bytes of `a` and `b`.
///
/// Equivalent to C `memcmp`. Returns:
/// - `Ordering::Less` if `a < b`
/// - `Ordering::Equal` if `a == b`
/// - `Ordering::Greater` if `a > b`
///
/// Only compares `min(n, a.len(), b.len())` bytes.
pub fn memcmp(a: &[u8], b: &[u8], n: usize) -> core::cmp::Ordering {
    let count = n.min(a.len()).min(b.len());
    a[..count].cmp(&b[..count])
}

/// Scans the first `n` bytes of `haystack` for the byte `needle`.
///
/// Equivalent to C `memchr`. Returns the index of the first occurrence,
/// or `None` if not found.
pub fn memchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    haystack[..count].iter().position(|&b| b == needle)
}

/// Scans the first `n` bytes of `haystack` for the last occurrence of `needle`.
///
/// Equivalent to C `memrchr`. Returns the index of the last occurrence,
/// or `None` if not found.
pub fn memrchr(haystack: &[u8], needle: u8, n: usize) -> Option<usize> {
    let count = n.min(haystack.len());
    haystack[..count].iter().rposition(|&b| b == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memcpy_basic() {
        let src = b"hello";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memcpy_partial() {
        let src = b"hello world";
        let mut dest = [0u8; 5];
        let n = memcpy(&mut dest, src, 5);
        assert_eq!(n, 5);
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn test_memset_basic() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'A', 8);
        assert_eq!(&buf, b"AAAAAAAA");
    }

    #[test]
    fn test_memset_partial() {
        let mut buf = [0u8; 8];
        memset(&mut buf, b'X', 3);
        assert_eq!(&buf, b"XXX\0\0\0\0\0");
    }

    #[test]
    fn test_memcmp_equal() {
        assert_eq!(memcmp(b"abc", b"abc", 3), core::cmp::Ordering::Equal);
    }

    #[test]
    fn test_memcmp_less() {
        assert_eq!(memcmp(b"abc", b"abd", 3), core::cmp::Ordering::Less);
    }

    #[test]
    fn test_memcmp_greater() {
        assert_eq!(memcmp(b"abd", b"abc", 3), core::cmp::Ordering::Greater);
    }

    #[test]
    fn test_memchr_found() {
        assert_eq!(memchr(b"hello", b'l', 5), Some(2));
    }

    #[test]
    fn test_memchr_not_found() {
        assert_eq!(memchr(b"hello", b'z', 5), None);
    }

    #[test]
    fn test_memrchr_found() {
        assert_eq!(memrchr(b"hello", b'l', 5), Some(3));
    }

    #[test]
    fn test_memrchr_not_found() {
        assert_eq!(memrchr(b"hello", b'z', 5), None);
    }
}
