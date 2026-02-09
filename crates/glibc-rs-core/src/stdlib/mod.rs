//! Standard library utilities.
//!
//! Implements `<stdlib.h>` functions: numeric conversion, sorting, searching,
//! environment variables, random numbers, and process termination.

pub mod conversion;
pub mod env;
pub mod exit;
pub mod random;
pub mod sort;

pub use conversion::{atoi, atol, strtol, strtoul};
pub use env::{getenv, setenv};
pub use exit::{atexit, exit};
pub use random::{rand, srand};
pub use sort::{bsearch, qsort};
