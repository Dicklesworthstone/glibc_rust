//! Allocation metadata registry.

use std::collections::HashMap;
use std::ffi::c_void;
use std::sync::OnceLock;

use parking_lot::RwLock;

use crate::safety::TemporalState;

/// Metadata for a tracked allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationMeta {
    /// Base address of the tracked allocation.
    pub base: usize,
    /// Allocation length in bytes.
    pub len: usize,
    /// Generation counter for temporal safety modeling.
    pub generation: u64,
    /// Current temporal state.
    pub state: TemporalState,
}

impl AllocationMeta {
    /// Returns true if `addr` lies inside `[base, base + len)`.
    #[must_use]
    pub fn contains(self, addr: usize) -> bool {
        let end = self.base.saturating_add(self.len);
        (self.base..end).contains(&addr)
    }

    /// Remaining bytes from `addr` to end of allocation.
    #[must_use]
    pub fn remaining(self, addr: usize) -> Option<usize> {
        if !self.contains(addr) {
            return None;
        }
        Some(self.base.saturating_add(self.len).saturating_sub(addr))
    }
}

/// Derived facts about an arbitrary pointer according to registry metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerFacts {
    /// Raw pointer address.
    pub addr: usize,
    /// Temporal state classification.
    pub temporal: TemporalState,
    /// Remaining in-bounds bytes if known.
    pub remaining: Option<usize>,
}

impl PointerFacts {
    /// Pointer facts for unknown metadata.
    #[must_use]
    pub fn unknown(addr: usize) -> Self {
        Self {
            addr,
            temporal: TemporalState::Unknown,
            remaining: None,
        }
    }
}

/// Concurrent allocation metadata registry.
#[derive(Debug, Default)]
pub struct PointerRegistry {
    allocations: RwLock<HashMap<usize, AllocationMeta>>,
}

impl PointerRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a fresh allocation.
    pub fn register_allocation(&self, base: *mut c_void, len: usize, generation: u64) {
        let base_addr = base as usize;
        let entry = AllocationMeta {
            base: base_addr,
            len,
            generation,
            state: TemporalState::Valid,
        };
        self.allocations.write().insert(base_addr, entry);
    }

    /// Mark allocation as freed.
    pub fn mark_freed(&self, base: *mut c_void) {
        let base_addr = base as usize;
        if let Some(meta) = self.allocations.write().get_mut(&base_addr) {
            meta.state = TemporalState::Freed;
            meta.generation = meta.generation.saturating_add(1);
        }
    }

    /// Look up metadata containing `ptr` if any.
    #[must_use]
    pub fn lookup_containing(&self, ptr: *const c_void) -> Option<AllocationMeta> {
        let addr = ptr as usize;
        let allocations = self.allocations.read();
        allocations
            .values()
            .copied()
            .find(|meta| meta.contains(addr))
    }
}

static GLOBAL_REGISTRY: OnceLock<PointerRegistry> = OnceLock::new();

/// Global membrane pointer registry.
#[must_use]
pub fn global_registry() -> &'static PointerRegistry {
    GLOBAL_REGISTRY.get_or_init(PointerRegistry::new)
}

/// Classify arbitrary pointer under registry facts.
#[must_use]
pub fn classify_pointer(registry: &PointerRegistry, ptr: *const c_void) -> PointerFacts {
    let addr = ptr as usize;
    if ptr.is_null() {
        return PointerFacts::unknown(0);
    }

    match registry.lookup_containing(ptr) {
        Some(meta) => PointerFacts {
            addr,
            temporal: meta.state,
            remaining: meta.remaining(addr),
        },
        None => PointerFacts::unknown(addr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_pointer_unknown_when_untracked() {
        let registry = PointerRegistry::new();
        let local = 7_u8;
        let facts = classify_pointer(&registry, (&local as *const u8).cast::<c_void>());
        assert_eq!(facts.temporal, TemporalState::Unknown);
        assert_eq!(facts.remaining, None);
    }

    #[test]
    fn classify_pointer_valid_when_tracked() {
        let registry = PointerRegistry::new();
        let mut buf = vec![0_u8; 16];
        registry.register_allocation(buf.as_mut_ptr().cast::<c_void>(), buf.len(), 1);

        let ptr = buf.as_ptr().wrapping_add(4).cast::<c_void>();
        let facts = classify_pointer(&registry, ptr);

        assert_eq!(facts.temporal, TemporalState::Valid);
        assert_eq!(facts.remaining, Some(12));
    }
}
