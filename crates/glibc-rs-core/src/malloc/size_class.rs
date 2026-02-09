//! Size class bins for small allocations.
//!
//! Defines size classes from 16 bytes to 32KB. Each size class has a bin
//! of free blocks. The bin index is computed by rounding up the requested
//! size to the nearest size class boundary.

/// Minimum allocation size (bytes).
pub const MIN_SIZE: usize = 16;

/// Maximum size for small allocations (bytes). Above this, use large/mmap path.
pub const MAX_SMALL_SIZE: usize = 32 * 1024; // 32KB

/// Number of size class bins.
pub const NUM_SIZE_CLASSES: usize = 32;

/// Describes a single size class bin.
#[derive(Debug, Clone)]
pub struct SizeClass {
    /// The allocation size for this class (bytes).
    pub size: usize,
    /// Number of objects that fit in a slab/page for this class.
    pub objects_per_slab: usize,
}

impl SizeClass {
    /// Creates a new size class descriptor.
    pub fn new(size: usize, objects_per_slab: usize) -> Self {
        Self {
            size,
            objects_per_slab,
        }
    }
}

/// Size class table following a geometric progression.
///
/// Bins 0-7: 16-byte increments (16, 32, 48, 64, 80, 96, 112, 128)
/// Bins 8-15: 32-byte increments (160, 192, 224, 256, 288, 320, 352, 384)
/// Bins 16-23: 64-byte increments (448, 512, 576, 640, 704, 768, 832, 896)
/// Bins 24-31: 128+ byte increments up to 32KB
const SIZE_TABLE: [usize; NUM_SIZE_CLASSES] = [
    16, 32, 48, 64, 80, 96, 112, 128, // 16-byte steps
    160, 192, 224, 256, 288, 320, 352, 384, // 32-byte steps
    448, 512, 640, 768, 896, 1024, 1280, 1536, // wider steps
    2048, 2560, 3072, 4096, 8192, 16384, 24576, 32768, // large small classes
];

/// Computes the bin index for a given allocation size.
///
/// Rounds `size` up to the nearest size class boundary and returns
/// the corresponding bin index. Sizes above `MAX_SMALL_SIZE` return
/// `NUM_SIZE_CLASSES` to signal the large-allocation path.
pub fn bin_index(size: usize) -> usize {
    let size = size.max(MIN_SIZE);
    if size > MAX_SMALL_SIZE {
        return NUM_SIZE_CLASSES;
    }
    // Linear scan is fine for 32 entries; a real allocator would use
    // a lookup table indexed by (size >> 4) or similar.
    for (i, &class_size) in SIZE_TABLE.iter().enumerate() {
        if size <= class_size {
            return i;
        }
    }
    NUM_SIZE_CLASSES
}

/// Returns the allocation size for a given bin index.
///
/// This is the actual number of bytes allocated for objects in this bin.
/// Returns 0 for out-of-range indices.
pub fn bin_size(index: usize) -> usize {
    if index < NUM_SIZE_CLASSES {
        SIZE_TABLE[index]
    } else {
        0
    }
}

/// Initializes and returns the full table of size classes.
///
/// Each size class includes the allocation size and the number of objects
/// that fit in a 64KB slab (with 64-byte per-object overhead for metadata).
pub fn init_size_classes() -> Vec<SizeClass> {
    const SLAB_SIZE: usize = 64 * 1024; // 64KB slabs
    const PER_OBJECT_OVERHEAD: usize = 64; // fingerprint + canary + alignment

    SIZE_TABLE
        .iter()
        .map(|&size| {
            let effective = size + PER_OBJECT_OVERHEAD;
            let objects = SLAB_SIZE.checked_div(effective).unwrap_or(1);
            SizeClass::new(size, objects.max(1))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bin_index_min() {
        assert_eq!(bin_index(1), 0);
        assert_eq!(bin_index(16), 0);
    }

    #[test]
    fn test_bin_index_exact() {
        assert_eq!(bin_index(32), 1);
        assert_eq!(bin_index(64), 3);
        assert_eq!(bin_index(128), 7);
        assert_eq!(bin_index(256), 11);
    }

    #[test]
    fn test_bin_index_round_up() {
        // 17 bytes should round up to 32-byte class (index 1)
        assert_eq!(bin_index(17), 1);
        // 65 bytes should round up to 80-byte class (index 4)
        assert_eq!(bin_index(65), 4);
    }

    #[test]
    fn test_bin_index_large() {
        assert_eq!(bin_index(MAX_SMALL_SIZE), NUM_SIZE_CLASSES - 1);
        assert_eq!(bin_index(MAX_SMALL_SIZE + 1), NUM_SIZE_CLASSES);
    }

    #[test]
    fn test_bin_size_roundtrip() {
        for i in 0..NUM_SIZE_CLASSES {
            let size = bin_size(i);
            assert!(size > 0);
            assert_eq!(bin_index(size), i);
        }
    }

    #[test]
    fn test_bin_size_out_of_range() {
        assert_eq!(bin_size(NUM_SIZE_CLASSES), 0);
        assert_eq!(bin_size(100), 0);
    }

    #[test]
    fn test_size_table_monotonic() {
        for i in 1..NUM_SIZE_CLASSES {
            assert!(
                SIZE_TABLE[i] > SIZE_TABLE[i - 1],
                "size class {} ({}) must be > class {} ({})",
                i,
                SIZE_TABLE[i],
                i - 1,
                SIZE_TABLE[i - 1]
            );
        }
    }

    #[test]
    fn test_init_size_classes() {
        let classes = init_size_classes();
        assert_eq!(classes.len(), NUM_SIZE_CLASSES);
        for class in &classes {
            assert!(class.size >= MIN_SIZE);
            assert!(class.objects_per_slab >= 1);
        }
    }
}
