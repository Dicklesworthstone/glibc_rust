//! Terminal I/O control.
//!
//! Implements `<termios.h>` functions for terminal attribute manipulation.

/// Terminal attributes (like `struct termios`).
#[derive(Debug, Clone, Default)]
pub struct Termios {
    /// Input mode flags.
    pub c_iflag: u32,
    /// Output mode flags.
    pub c_oflag: u32,
    /// Control mode flags.
    pub c_cflag: u32,
    /// Local mode flags.
    pub c_lflag: u32,
    /// Control characters.
    pub c_cc: [u8; 32],
}

/// Optional action constants for `tcsetattr`.
pub const TCSANOW: i32 = 0;
pub const TCSADRAIN: i32 = 1;
pub const TCSAFLUSH: i32 = 2;

/// Gets the terminal attributes for the file descriptor.
///
/// Equivalent to C `tcgetattr`. Returns 0 on success, -1 on error.
pub fn tcgetattr(_fd: i32, _termios: &mut Termios) -> i32 {
    todo!("POSIX tcgetattr: implementation pending")
}

/// Sets the terminal attributes for the file descriptor.
///
/// Equivalent to C `tcsetattr`. `optional_actions` controls when changes
/// take effect. Returns 0 on success, -1 on error.
pub fn tcsetattr(_fd: i32, _optional_actions: i32, _termios: &Termios) -> i32 {
    todo!("POSIX tcsetattr: implementation pending")
}
