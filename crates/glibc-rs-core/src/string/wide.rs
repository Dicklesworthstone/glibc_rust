//! Wide-character string operations: wcslen, wcscpy, wcscmp.
//!
//! Corresponds to `<wchar.h>` functions. These operate on `u32` slices
//! representing `wchar_t` strings (NUL-terminated with `0u32`).

/// Returns the length of a NUL-terminated wide string (not counting the NUL).
///
/// Equivalent to C `wcslen`. Scans `s` for the first `0u32` element.
/// If no NUL is found, returns the full slice length.
pub fn wcslen(s: &[u32]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Copies a NUL-terminated wide string from `src` into `dest`.
///
/// Equivalent to C `wcscpy`. Copies elements from `src` until (and including)
/// the NUL terminator. Returns the number of elements copied (including NUL).
///
/// # Panics
///
/// Panics if `dest` is too small to hold `src` plus the NUL terminator.
pub fn wcscpy(dest: &mut [u32], src: &[u32]) -> usize {
    let src_len = wcslen(src);
    assert!(
        dest.len() > src_len,
        "wcscpy: destination buffer too small ({} elements for {} element string + NUL)",
        dest.len(),
        src_len
    );
    dest[..src_len].copy_from_slice(&src[..src_len]);
    dest[src_len] = 0;
    src_len + 1
}

/// Compares two NUL-terminated wide strings lexicographically.
///
/// Equivalent to C `wcscmp`. Compares element-by-element until a difference
/// is found or both strings reach a NUL terminator.
///
/// Returns a negative value if `s1 < s2`, zero if equal, positive if `s1 > s2`.
pub fn wcscmp(s1: &[u32], s2: &[u32]) -> i32 {
    let mut i = 0;
    loop {
        let a = if i < s1.len() { s1[i] } else { 0 };
        let b = if i < s2.len() { s2[i] } else { 0 };

        if a != b {
            if a < b {
                return -1;
            } else {
                return 1;
            }
        }
        if a == 0 {
            return 0;
        }
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wcslen_basic() {
        assert_eq!(wcslen(&[b'h' as u32, b'i' as u32, 0]), 2);
        assert_eq!(wcslen(&[0]), 0);
        assert_eq!(wcslen(&[65, 66, 67]), 3); // no NUL found
    }

    #[test]
    fn test_wcscpy_basic() {
        let src = [b'H' as u32, b'i' as u32, 0];
        let mut dest = [0u32; 4];
        let n = wcscpy(&mut dest, &src);
        assert_eq!(n, 3);
        assert_eq!(&dest[..3], &[b'H' as u32, b'i' as u32, 0]);
    }

    #[test]
    fn test_wcscmp_equal() {
        assert_eq!(wcscmp(&[65, 66, 0], &[65, 66, 0]), 0);
    }

    #[test]
    fn test_wcscmp_less() {
        assert!(wcscmp(&[65, 0], &[66, 0]) < 0);
    }

    #[test]
    fn test_wcscmp_greater() {
        assert!(wcscmp(&[66, 0], &[65, 0]) > 0);
    }

    #[test]
    fn test_wcscmp_prefix() {
        assert!(wcscmp(&[65, 0], &[65, 66, 0]) < 0);
        assert!(wcscmp(&[65, 66, 0], &[65, 0]) > 0);
    }
}
