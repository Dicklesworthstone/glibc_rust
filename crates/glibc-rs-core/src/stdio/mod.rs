//! Standard I/O operations.
//!
//! Implements `<stdio.h>` functions: formatted output, formatted input,
//! file operations, and buffered I/O.

pub mod buffer;
pub mod file;
pub mod printf;
pub mod scanf;

pub use file::{fclose, fopen, fread, fwrite};
pub use printf::printf;
pub use scanf::scanf;
