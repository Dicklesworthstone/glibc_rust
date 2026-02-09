//! Directory entry operations.
//!
//! Implements `<dirent.h>` functions for reading directory contents.

/// Opaque directory stream handle.
pub struct Dir {
    _private: (),
}

/// A single directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode number.
    pub d_ino: u64,
    /// Entry name (NUL-terminated bytes).
    pub d_name: Vec<u8>,
}

/// Opens a directory stream for the given path.
///
/// Equivalent to C `opendir`. Returns `None` on error.
pub fn opendir(_path: &[u8]) -> Option<Dir> {
    todo!("POSIX opendir: implementation pending")
}

/// Reads the next entry from a directory stream.
///
/// Equivalent to C `readdir`. Returns `None` when all entries have been read.
pub fn readdir(_dir: &mut Dir) -> Option<DirEntry> {
    todo!("POSIX readdir: implementation pending")
}

/// Closes a directory stream.
///
/// Equivalent to C `closedir`. Returns 0 on success, -1 on error.
pub fn closedir(_dir: Dir) -> i32 {
    todo!("POSIX closedir: implementation pending")
}
