//! # glibc-rs-core
//!
//! Safe Rust implementations of C standard library (libc) functions.
//!
//! This crate provides pure-Rust, safe implementations of POSIX and C standard
//! library functions. No `unsafe` code is permitted at the crate level.

#![deny(unsafe_code)]

pub mod ctype;
pub mod dirent;
pub mod dlfcn;
pub mod errno;
pub mod iconv;
pub mod inet;
pub mod io;
pub mod locale;
pub mod malloc;
pub mod math;
pub mod pthread;
pub mod resolv;
pub mod resource;
pub mod setjmp;
pub mod signal;
pub mod socket;
pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod termios;
pub mod time;
pub mod unistd;
