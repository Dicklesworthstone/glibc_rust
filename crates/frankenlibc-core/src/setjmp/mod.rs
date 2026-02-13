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

#[cfg(test)]
mod tests {
    use super::*;
    const SETJMP_TEST_SEED: i32 = 0x1FF3;

    fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
        if let Some(msg) = payload.downcast_ref::<String>() {
            return msg.clone();
        }
        if let Some(msg) = payload.downcast_ref::<&'static str>() {
            return (*msg).to_string();
        }
        "<non-string panic payload>".to_string()
    }

    fn assert_placeholder_contract_panic(
        subsystem: &str,
        clause: &str,
        evidence_path: &str,
        expected_fragment: &str,
        result: std::thread::Result<()>,
    ) {
        let context = format!("[{subsystem}] {clause} ({evidence_path})");
        let payload = result.expect_err(&format!("{context}: expected panic"));
        let msg = panic_message(payload);
        assert!(
            msg.contains(expected_fragment),
            "{context}: panic message mismatch, got: {msg}"
        );
    }

    #[test]
    fn jmpbuf_layout_is_stable_for_placeholder_contract() {
        assert_eq!(
            std::mem::size_of::<JmpBuf>(),
            16 * std::mem::size_of::<u64>()
        );
        assert_eq!(std::mem::align_of::<JmpBuf>(), std::mem::align_of::<u64>());
    }

    #[test]
    fn setjmp_placeholder_panics_with_explicit_contract_message() {
        let mut env = JmpBuf::default();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = setjmp(&mut env);
        }));
        assert_placeholder_contract_panic(
            "setjmp",
            "placeholder-must-explicitly-advertise-unsafe-boundary",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX setjmp: implementation pending",
            result,
        );
    }

    #[test]
    fn longjmp_placeholder_panics_with_explicit_contract_message() {
        let env = JmpBuf::default();
        let result = std::panic::catch_unwind(|| {
            longjmp(&env, SETJMP_TEST_SEED);
        });
        assert_placeholder_contract_panic(
            "setjmp",
            "placeholder-must-explicitly-advertise-unsafe-boundary",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX longjmp: implementation pending",
            result,
        );
    }

    #[test]
    fn longjmp_placeholder_panics_when_val_zero() {
        let env = JmpBuf::default();
        let result = std::panic::catch_unwind(|| {
            longjmp(&env, 0);
        });
        assert_placeholder_contract_panic(
            "setjmp",
            "longjmp-zero-remains-unimplemented-contract-placeholder",
            "crates/frankenlibc-core/src/setjmp/mod.rs",
            "POSIX longjmp: implementation pending",
            result,
        );
    }
}
