//! DNS resolver functions.
//!
//! Implements `<netdb.h>` functions for hostname resolution.

/// Address information result (like `struct addrinfo`).
#[derive(Debug, Clone)]
pub struct AddrInfo {
    /// Address family (AF_INET, AF_INET6).
    pub ai_family: i32,
    /// Socket type (SOCK_STREAM, SOCK_DGRAM).
    pub ai_socktype: i32,
    /// Protocol number.
    pub ai_protocol: i32,
    /// Socket address in binary form.
    pub ai_addr: Vec<u8>,
    /// Canonical name of the host.
    pub ai_canonname: Option<Vec<u8>>,
}

/// Resolves a hostname and/or service name to a list of addresses.
///
/// Equivalent to C `getaddrinfo`. Returns a list of matching addresses,
/// or an error code.
pub fn getaddrinfo(
    _node: Option<&[u8]>,
    _service: Option<&[u8]>,
    _hints: Option<&AddrInfo>,
) -> Result<Vec<AddrInfo>, i32> {
    todo!("POSIX getaddrinfo: implementation pending")
}

/// Converts a socket address to a hostname and service name.
///
/// Equivalent to C `getnameinfo`. Returns the host and service as byte vectors.
pub fn getnameinfo(_addr: &[u8], _flags: i32) -> Result<(Vec<u8>, Vec<u8>), i32> {
    todo!("POSIX getnameinfo: implementation pending")
}
