//! Non-local jumps.
//!
//! Implements `<setjmp.h>` functions. NOTE: Real implementations of setjmp/longjmp
//! inherently require unsafe code to manipulate the call stack. These stubs
//! capture the interface; the actual implementation will need `unsafe` blocks
//! in the membrane/FFI layer.

/// Opaque jump buffer that stores the execution context.
#[derive(Debug, Clone, Default)]
pub struct JmpBuf {
    _registers: [u64; 16],
}

/// Saves the current execution context into `env`.
///
/// Equivalent to C `setjmp`. Returns 0 when called directly.
/// When restored via [`longjmp`], returns the value passed to `longjmp`.
///
/// NOTE: This will need unsafe implementation for actual stack manipulation.
pub fn setjmp(_env: &mut JmpBuf) -> i32 {
    todo!("POSIX setjmp: implementation pending (requires unsafe for real impl)")
}

/// Restores the execution context saved in `env`.
///
/// Equivalent to C `longjmp`. `val` is the value that `setjmp` will appear
/// to return (if `val` is 0, `setjmp` returns 1 instead).
///
/// NOTE: This will need unsafe implementation for actual stack manipulation.
pub fn longjmp(_env: &JmpBuf, _val: i32) -> ! {
    todo!("POSIX longjmp: implementation pending (requires unsafe for real impl)")
}
