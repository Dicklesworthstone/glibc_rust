//! POSIX threads.
//!
//! Implements `<pthread.h>` functions for thread management, mutexes,
//! condition variables, reader-writer locks, and thread-local storage.

pub mod cond;
pub mod mutex;
pub mod rwlock;
pub mod thread;
pub mod tls;

pub use cond::{pthread_cond_broadcast, pthread_cond_signal, pthread_cond_wait};
pub use mutex::{
    pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock, pthread_mutex_unlock,
};
pub use rwlock::{pthread_rwlock_rdlock, pthread_rwlock_unlock, pthread_rwlock_wrlock};
pub use thread::{pthread_create, pthread_detach, pthread_join};
pub use tls::{pthread_getspecific, pthread_key_create, pthread_setspecific};
