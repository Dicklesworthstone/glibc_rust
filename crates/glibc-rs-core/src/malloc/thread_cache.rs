//! Thread-local magazine cache for malloc.
//!
//! Each thread maintains a small cache of recently freed objects per size class,
//! reducing contention on the central allocator. This follows a "magazine"
//! design where batches of objects are moved between the thread cache and
//! the central freelist.

use super::size_class::NUM_SIZE_CLASSES;

/// Maximum number of cached objects per size class per thread.
pub const MAGAZINE_CAPACITY: usize = 64;

/// Per-size-class magazine (stack of free object offsets).
#[derive(Debug, Clone)]
pub struct Magazine {
    /// Stack of free object offsets.
    objects: Vec<usize>,
    /// Maximum capacity.
    capacity: usize,
}

impl Magazine {
    /// Creates a new empty magazine with the given capacity.
    fn new(capacity: usize) -> Self {
        Self {
            objects: Vec::new(),
            capacity,
        }
    }

    /// Attempts to pop a cached object from this magazine.
    fn pop(&mut self) -> Option<usize> {
        self.objects.pop()
    }

    /// Pushes an object into this magazine.
    ///
    /// Returns `true` if the object was cached, `false` if the magazine is full.
    fn push(&mut self, ptr: usize) -> bool {
        if self.objects.len() < self.capacity {
            self.objects.push(ptr);
            true
        } else {
            false
        }
    }

    /// Returns true if the magazine is full.
    fn is_full(&self) -> bool {
        self.objects.len() >= self.capacity
    }

    /// Drains all objects from the magazine, returning them.
    fn drain(&mut self) -> Vec<usize> {
        std::mem::take(&mut self.objects)
    }
}

/// Per-thread cache containing one magazine per size class.
pub struct ThreadCache {
    /// One magazine per size class bin.
    magazines: Vec<Magazine>,
    /// Total number of cached objects across all magazines.
    total_cached: usize,
}

impl ThreadCache {
    /// Creates a new empty thread cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to allocate from the thread cache for the given size class.
    ///
    /// Returns an object offset from the magazine, or `None` if the magazine
    /// is empty (caller should fall back to central allocator).
    pub fn alloc(&mut self, size_class_index: usize) -> Option<usize> {
        if size_class_index >= NUM_SIZE_CLASSES {
            return None;
        }
        let result = self.magazines[size_class_index].pop();
        if result.is_some() {
            self.total_cached -= 1;
        }
        result
    }

    /// Returns an object to the thread cache for the given size class.
    ///
    /// Returns `true` if the object was cached. Returns `false` if the
    /// magazine is full (caller should return to central allocator instead).
    pub fn dealloc(&mut self, size_class_index: usize, ptr: usize) -> bool {
        if size_class_index >= NUM_SIZE_CLASSES {
            return false;
        }
        let cached = self.magazines[size_class_index].push(ptr);
        if cached {
            self.total_cached += 1;
        }
        cached
    }

    /// Returns the total number of cached objects across all magazines.
    pub fn total_cached(&self) -> usize {
        self.total_cached
    }

    /// Drains a specific magazine, returning all cached objects.
    pub fn drain_magazine(&mut self, size_class_index: usize) -> Vec<usize> {
        if size_class_index >= NUM_SIZE_CLASSES {
            return Vec::new();
        }
        let drained = self.magazines[size_class_index].drain();
        self.total_cached -= drained.len();
        drained
    }

    /// Returns true if the magazine for the given size class is full.
    pub fn is_full(&self, size_class_index: usize) -> bool {
        if size_class_index >= NUM_SIZE_CLASSES {
            return true;
        }
        self.magazines[size_class_index].is_full()
    }
}

impl Default for ThreadCache {
    fn default() -> Self {
        Self {
            magazines: (0..NUM_SIZE_CLASSES)
                .map(|_| Magazine::new(MAGAZINE_CAPACITY))
                .collect(),
            total_cached: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cache_empty() {
        let cache = ThreadCache::new();
        assert_eq!(cache.total_cached(), 0);
    }

    #[test]
    fn test_alloc_empty_returns_none() {
        let mut cache = ThreadCache::new();
        assert!(cache.alloc(0).is_none());
        assert!(cache.alloc(5).is_none());
    }

    #[test]
    fn test_dealloc_and_alloc() {
        let mut cache = ThreadCache::new();
        assert!(cache.dealloc(0, 0x1000));
        assert!(cache.dealloc(0, 0x2000));
        assert_eq!(cache.total_cached(), 2);

        // LIFO order
        assert_eq!(cache.alloc(0), Some(0x2000));
        assert_eq!(cache.alloc(0), Some(0x1000));
        assert!(cache.alloc(0).is_none());
        assert_eq!(cache.total_cached(), 0);
    }

    #[test]
    fn test_different_size_classes() {
        let mut cache = ThreadCache::new();
        assert!(cache.dealloc(0, 0x1000));
        assert!(cache.dealloc(5, 0x2000));

        assert_eq!(cache.alloc(0), Some(0x1000));
        assert!(cache.alloc(0).is_none());
        assert_eq!(cache.alloc(5), Some(0x2000));
        assert!(cache.alloc(5).is_none());
    }

    #[test]
    fn test_magazine_full() {
        let mut cache = ThreadCache::new();
        for i in 0..MAGAZINE_CAPACITY {
            assert!(cache.dealloc(0, i));
        }
        assert!(!cache.dealloc(0, 999)); // Should fail - full
        assert!(cache.is_full(0));
    }

    #[test]
    fn test_out_of_range() {
        let mut cache = ThreadCache::new();
        assert!(cache.alloc(NUM_SIZE_CLASSES).is_none());
        assert!(!cache.dealloc(NUM_SIZE_CLASSES, 0x1000));
    }

    #[test]
    fn test_drain_magazine() {
        let mut cache = ThreadCache::new();
        cache.dealloc(3, 0x1000);
        cache.dealloc(3, 0x2000);
        cache.dealloc(3, 0x3000);

        let drained = cache.drain_magazine(3);
        assert_eq!(drained.len(), 3);
        assert_eq!(cache.total_cached(), 0);
        assert!(cache.alloc(3).is_none());
    }
}
