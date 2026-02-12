//! String tokenization: strtok (legacy) and strtok_r (reentrant).
//!
//! Corresponds to `strtok` and `strtok_r` from `<string.h>`.
//!
//! In this safe Rust model, `strtok` replaces delimiter bytes in the buffer
//! with NUL bytes and returns token boundaries as `(start, len)` pairs.

/// Returns true if byte `b` is in the NUL-terminated `delimiters` set.
fn is_delim(b: u8, delimiters: &[u8]) -> bool {
    for &d in delimiters {
        if d == 0 {
            break;
        }
        if b == d {
            return true;
        }
    }
    false
}

/// Tokenizes a NUL-terminated byte string (thread-unsafe legacy version).
///
/// POSIX `strtok` uses internal static state, making it non-reentrant.
/// This safe Rust version modifies the buffer in-place, writing NUL bytes
/// over delimiter positions.
///
/// `s` is the byte string to tokenize (mutable so delimiters can be overwritten).
/// `delimiters` is a NUL-terminated byte slice of delimiter characters.
///
/// Returns the start index and length of the next token, or `None` if
/// no more tokens remain.
///
/// Callers must track the `save_ptr` returned by the first call and pass
/// it as the starting offset for subsequent scans. For the first call,
/// start scanning from index 0. For a stateful wrapper, use a `Cell<usize>`
/// or similar.
pub fn strtok(s: &mut [u8], delimiters: &[u8]) -> Option<(usize, usize)> {
    strtok_at(s, delimiters, 0)
}

/// Stateful tokenizer that scans starting from `offset`.
///
/// Returns `Some((token_start, token_len))` and writes a NUL over the
/// first delimiter after the token. Returns `None` if no tokens remain.
fn strtok_at(s: &mut [u8], delimiters: &[u8], offset: usize) -> Option<(usize, usize)> {
    let len = s.len();
    let mut pos = offset;

    // Skip leading delimiters and NUL bytes
    while pos < len && s[pos] != 0 && is_delim(s[pos], delimiters) {
        pos += 1;
    }

    // Check if we've exhausted the string
    if pos >= len || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token
    while pos < len && s[pos] != 0 && !is_delim(s[pos], delimiters) {
        pos += 1;
    }

    let token_len = pos - token_start;

    // Write NUL terminator over the delimiter (if not already at end)
    if pos < len && s[pos] != 0 {
        s[pos] = 0;
    }

    Some((token_start, token_len))
}

/// Reentrant string tokenizer.
///
/// POSIX `strtok_r`. The `save_ptr` parameter holds the position for the
/// next call, making this safe for concurrent use across different strings.
///
/// `s` is the NUL-terminated byte string to tokenize.
/// `delimiters` is a NUL-terminated byte slice of delimiter characters.
/// `save_ptr` is the saved position (initially 0 for the first call).
///
/// Returns `Some((token_start, token_len, new_save_ptr))` for the next
/// token, or `None` if no more tokens remain.
pub fn strtok_r(s: &mut [u8], delimiters: &[u8], save_ptr: usize) -> Option<(usize, usize, usize)> {
    let len = s.len();
    let mut pos = save_ptr;

    // Skip leading delimiters and NUL bytes
    while pos < len && s[pos] != 0 && is_delim(s[pos], delimiters) {
        pos += 1;
    }

    // Check if we've exhausted the string
    if pos >= len || s[pos] == 0 {
        return None;
    }

    let token_start = pos;

    // Find end of token
    while pos < len && s[pos] != 0 && !is_delim(s[pos], delimiters) {
        pos += 1;
    }

    let token_len = pos - token_start;

    // Write NUL terminator and advance save pointer
    if pos < len && s[pos] != 0 {
        s[pos] = 0;
        pos += 1;
    }

    Some((token_start, token_len, pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strtok_r_basic() {
        let mut buf = *b"hello world foo\0";
        let delim = b" \0";

        let (start, len, save) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"hello");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"world");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"foo");

        assert!(strtok_r(&mut buf, delim, save).is_none());
    }

    #[test]
    fn test_strtok_r_multiple_delims() {
        let mut buf = *b"a,,b,c\0";
        let delim = b",\0";

        let (start, len, save) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"a");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"b");

        let (start, len, save) = strtok_r(&mut buf, delim, save).unwrap();
        assert_eq!(&buf[start..start + len], b"c");

        assert!(strtok_r(&mut buf, delim, save).is_none());
    }

    #[test]
    fn test_strtok_r_leading_delims() {
        let mut buf = *b"  hello\0";
        let delim = b" \0";

        let (start, len, _) = strtok_r(&mut buf, delim, 0).unwrap();
        assert_eq!(&buf[start..start + len], b"hello");
    }

    #[test]
    fn test_strtok_r_empty() {
        let mut buf = *b"\0";
        let delim = b" \0";
        assert!(strtok_r(&mut buf, delim, 0).is_none());
    }

    #[test]
    fn test_strtok_r_all_delims() {
        let mut buf = *b"   \0";
        let delim = b" \0";
        assert!(strtok_r(&mut buf, delim, 0).is_none());
    }

    #[test]
    fn test_strtok_basic() {
        let mut buf = *b"a-b-c\0";
        let delim = b"-\0";

        let result = strtok(&mut buf, delim);
        assert!(result.is_some());
        let (start, len) = result.unwrap();
        assert_eq!(&buf[start..start + len], b"a");
    }
}
