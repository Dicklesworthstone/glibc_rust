//! POSIX threads.
//!
//! Implements `<pthread.h>` constants and validators for thread management,
//! mutexes, condition variables, reader-writer locks, and thread-local storage.
//! Actual synchronization primitives delegate to libc at the ABI layer.

pub mod cond;
pub mod mutex;
pub mod rwlock;
pub mod thread;
pub mod tls;

pub use cond::{PTHREAD_COND_CLOCK_MONOTONIC, PTHREAD_COND_CLOCK_REALTIME};
pub use mutex::{
    PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE,
};
pub use rwlock::{
    PTHREAD_RWLOCK_DEFAULT_NP, PTHREAD_RWLOCK_PREFER_READER_NP,
    PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP, PTHREAD_RWLOCK_PREFER_WRITER_NP,
};
pub use thread::{pthread_create, pthread_detach, pthread_join};
pub use tls::{pthread_getspecific, pthread_key_create, pthread_setspecific};
