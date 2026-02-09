//! Internet address manipulation.
//!
//! Implements `<arpa/inet.h>` functions for converting between
//! human-readable IP addresses and binary network representations.

/// Converts an IP address from text to binary form.
///
/// Equivalent to C `inet_pton`. `af` is the address family (AF_INET or AF_INET6).
/// Returns 1 on success, 0 if `src` is not valid for the address family,
/// or -1 on error.
pub fn inet_pton(_af: i32, _src: &[u8], _dst: &mut [u8]) -> i32 {
    todo!("POSIX inet_pton: implementation pending")
}

/// Converts an IP address from binary to text form.
///
/// Equivalent to C `inet_ntop`. `af` is the address family.
/// Returns the formatted address string, or `None` on error.
pub fn inet_ntop(_af: i32, _src: &[u8]) -> Option<Vec<u8>> {
    todo!("POSIX inet_ntop: implementation pending")
}

/// Converts a 16-bit value from host byte order to network byte order.
///
/// Equivalent to C `htons`.
pub fn htons(_hostshort: u16) -> u16 {
    todo!("POSIX htons: implementation pending")
}

/// Converts a 32-bit value from host byte order to network byte order.
///
/// Equivalent to C `htonl`.
pub fn htonl(_hostlong: u32) -> u32 {
    todo!("POSIX htonl: implementation pending")
}
