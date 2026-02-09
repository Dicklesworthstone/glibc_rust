//! POSIX thread-local storage (TLS).
//!
//! Implements pthread key functions for thread-specific data.

/// Thread-local storage key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PthreadKey {
    _id: u32,
}

/// Creates a thread-local storage key.
///
/// Equivalent to C `pthread_key_create`. The optional `destructor` is called
/// when a thread exits with a non-null value for this key.
/// Returns 0 on success.
pub fn pthread_key_create(_key: &mut PthreadKey, _destructor: Option<fn(u64)>) -> i32 {
    todo!("POSIX pthread_key_create: implementation pending")
}

/// Deletes a thread-local storage key.
///
/// Equivalent to C `pthread_key_delete`. Returns 0 on success.
pub fn pthread_key_delete(_key: PthreadKey) -> i32 {
    todo!("POSIX pthread_key_delete: implementation pending")
}

/// Gets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_getspecific`. Returns the value, or 0 if
/// no value has been set.
pub fn pthread_getspecific(_key: PthreadKey) -> u64 {
    todo!("POSIX pthread_getspecific: implementation pending")
}

/// Sets the value associated with the TLS key for the calling thread.
///
/// Equivalent to C `pthread_setspecific`. Returns 0 on success.
pub fn pthread_setspecific(_key: PthreadKey, _value: u64) -> i32 {
    todo!("POSIX pthread_setspecific: implementation pending")
}
