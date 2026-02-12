//! Atomic counters for membrane observability.
//!
//! All counters use relaxed ordering — they are advisory/diagnostic,
//! not synchronization primitives.

use std::sync::atomic::{AtomicU64, Ordering};

/// Global membrane operation counters.
pub struct MembraneMetrics {
    /// Total pointer validations performed.
    pub validations: AtomicU64,
    /// Validations resolved from TLS cache (fast path).
    pub tls_cache_hits: AtomicU64,
    /// TLS cache misses requiring full pipeline.
    pub tls_cache_misses: AtomicU64,
    /// Bloom filter true positives (pointer is ours).
    pub bloom_hits: AtomicU64,
    /// Bloom filter negatives (pointer is not ours).
    pub bloom_misses: AtomicU64,
    /// Successful arena lookups.
    pub arena_lookups: AtomicU64,
    /// Fingerprint validation passes.
    pub fingerprint_passes: AtomicU64,
    /// Fingerprint validation failures (corruption detected).
    pub fingerprint_failures: AtomicU64,
    /// Canary check passes.
    pub canary_passes: AtomicU64,
    /// Canary check failures (buffer overflow detected).
    pub canary_failures: AtomicU64,
    /// Total healing actions applied.
    pub heals: AtomicU64,
    /// Double-free attempts silently ignored.
    pub double_frees_healed: AtomicU64,
    /// Foreign-free attempts silently ignored.
    pub foreign_frees_healed: AtomicU64,
    /// Size clamps applied.
    pub size_clamps: AtomicU64,
}

impl MembraneMetrics {
    /// Create a new zeroed metrics instance.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            validations: AtomicU64::new(0),
            tls_cache_hits: AtomicU64::new(0),
            tls_cache_misses: AtomicU64::new(0),
            bloom_hits: AtomicU64::new(0),
            bloom_misses: AtomicU64::new(0),
            arena_lookups: AtomicU64::new(0),
            fingerprint_passes: AtomicU64::new(0),
            fingerprint_failures: AtomicU64::new(0),
            canary_passes: AtomicU64::new(0),
            canary_failures: AtomicU64::new(0),
            heals: AtomicU64::new(0),
            double_frees_healed: AtomicU64::new(0),
            foreign_frees_healed: AtomicU64::new(0),
            size_clamps: AtomicU64::new(0),
        }
    }

    /// Increment a counter by 1.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a counter value.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Snapshot all counters into a displayable summary.
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            validations: Self::get(&self.validations),
            tls_cache_hits: Self::get(&self.tls_cache_hits),
            tls_cache_misses: Self::get(&self.tls_cache_misses),
            bloom_hits: Self::get(&self.bloom_hits),
            bloom_misses: Self::get(&self.bloom_misses),
            arena_lookups: Self::get(&self.arena_lookups),
            fingerprint_passes: Self::get(&self.fingerprint_passes),
            fingerprint_failures: Self::get(&self.fingerprint_failures),
            canary_passes: Self::get(&self.canary_passes),
            canary_failures: Self::get(&self.canary_failures),
            heals: Self::get(&self.heals),
            double_frees_healed: Self::get(&self.double_frees_healed),
            foreign_frees_healed: Self::get(&self.foreign_frees_healed),
            size_clamps: Self::get(&self.size_clamps),
        }
    }
}

impl Default for MembraneMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of all membrane counters.
#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub validations: u64,
    pub tls_cache_hits: u64,
    pub tls_cache_misses: u64,
    pub bloom_hits: u64,
    pub bloom_misses: u64,
    pub arena_lookups: u64,
    pub fingerprint_passes: u64,
    pub fingerprint_failures: u64,
    pub canary_passes: u64,
    pub canary_failures: u64,
    pub heals: u64,
    pub double_frees_healed: u64,
    pub foreign_frees_healed: u64,
    pub size_clamps: u64,
}

/// Global metrics instance.
static GLOBAL_METRICS: MembraneMetrics = MembraneMetrics::new();

/// Access the global metrics singleton.
#[must_use]
pub fn global_metrics() -> &'static MembraneMetrics {
    &GLOBAL_METRICS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_start_at_zero() {
        let m = MembraneMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.validations, 0);
        assert_eq!(snap.heals, 0);
    }

    #[test]
    fn increment_works() {
        let m = MembraneMetrics::new();
        MembraneMetrics::inc(&m.validations);
        MembraneMetrics::inc(&m.validations);
        MembraneMetrics::inc(&m.heals);
        let snap = m.snapshot();
        assert_eq!(snap.validations, 2);
        assert_eq!(snap.heals, 1);
    }
}
