//! Character set conversion.
//!
//! Implements `<iconv.h>` functions for converting between character encodings.

/// Opaque conversion descriptor.
pub struct IconvDescriptor {
    _private: (),
}

/// Opens a character set conversion descriptor.
///
/// Equivalent to C `iconv_open`. Converts from `fromcode` encoding to
/// `tocode` encoding. Returns `None` if the conversion is not supported.
pub fn iconv_open(_tocode: &[u8], _fromcode: &[u8]) -> Option<IconvDescriptor> {
    todo!("POSIX iconv_open: implementation pending")
}

/// Performs character set conversion.
///
/// Equivalent to C `iconv`. Converts bytes from `inbuf` and writes to `outbuf`.
/// Returns the number of irreversible conversions performed, or `usize::MAX` on error.
pub fn iconv(
    _cd: &mut IconvDescriptor,
    _inbuf: &[u8],
    _outbuf: &mut [u8],
) -> Result<(usize, usize, usize), i32> {
    todo!("POSIX iconv: implementation pending")
}

/// Closes a character set conversion descriptor.
///
/// Equivalent to C `iconv_close`. Returns 0 on success, -1 on error.
pub fn iconv_close(_cd: IconvDescriptor) -> i32 {
    todo!("POSIX iconv_close: implementation pending")
}
