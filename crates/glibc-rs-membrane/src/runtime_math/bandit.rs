//! Constrained bandit router for validation depth selection.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

use crate::config::SafetyLevel;

use super::{ApiFamily, ValidationProfile};

const ARM_COUNT: usize = 2;
const ARM_FAST: usize = 0;
const ARM_FULL: usize = 1;

/// Online router selecting `Fast` vs `Full` validation profiles.
pub struct ConstrainedBanditRouter {
    pulls: [AtomicU64; ApiFamily::COUNT * ARM_COUNT],
    utility_milli: [AtomicI64; ApiFamily::COUNT * ARM_COUNT],
}

impl ConstrainedBanditRouter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pulls: std::array::from_fn(|_| AtomicU64::new(0)),
            utility_milli: std::array::from_fn(|_| AtomicI64::new(0)),
        }
    }

    /// Select a validation profile using UCB with hard safety constraints.
    #[must_use]
    pub fn select_profile(
        &self,
        family: ApiFamily,
        mode: SafetyLevel,
        risk_upper_bound_ppm: u32,
        contention_hint: u16,
    ) -> ValidationProfile {
        // Hard safety/robustness gates first.
        if mode.heals_enabled() && (risk_upper_bound_ppm >= 100_000 || contention_hint >= 96) {
            return ValidationProfile::Full;
        }
        if risk_upper_bound_ppm >= 300_000 {
            return ValidationProfile::Full;
        }

        let family_idx = usize::from(family as u8);
        let fast_idx = idx(family_idx, ARM_FAST);
        let full_idx = idx(family_idx, ARM_FULL);

        let fast_pulls = self.pulls[fast_idx].load(Ordering::Relaxed);
        let full_pulls = self.pulls[full_idx].load(Ordering::Relaxed);

        // Ensure initial exploration of both arms.
        if fast_pulls == 0 {
            return ValidationProfile::Fast;
        }
        if full_pulls == 0 {
            return ValidationProfile::Full;
        }

        let total = (fast_pulls + full_pulls) as f64;
        let log_total = total.ln().max(1.0);
        let c = if mode.heals_enabled() { 0.55 } else { 0.35 };

        let fast_mean =
            self.utility_milli[fast_idx].load(Ordering::Relaxed) as f64 / fast_pulls as f64;
        let full_mean =
            self.utility_milli[full_idx].load(Ordering::Relaxed) as f64 / full_pulls as f64;

        let fast_ucb = fast_mean + c * (2.0 * log_total / fast_pulls as f64).sqrt();
        let full_ucb = full_mean + c * (2.0 * log_total / full_pulls as f64).sqrt();

        if full_ucb > fast_ucb {
            ValidationProfile::Full
        } else {
            ValidationProfile::Fast
        }
    }

    /// Record realized utility for the selected profile.
    ///
    /// Utility is higher for lower latency and no adverse outcome.
    pub fn observe(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        let family_idx = usize::from(family as u8);
        let arm = match profile {
            ValidationProfile::Fast => ARM_FAST,
            ValidationProfile::Full => ARM_FULL,
        };
        let slot = idx(family_idx, arm);

        self.pulls[slot].fetch_add(1, Ordering::Relaxed);

        // Utility model:
        // - latency penalty in milli-units
        // - heavy penalty for adverse outcomes
        let latency_penalty = (estimated_cost_ns as i64).saturating_mul(8);
        let adverse_penalty = if adverse { 20_000 } else { 0 };
        let utility = 100_000 - latency_penalty - adverse_penalty;
        self.utility_milli[slot].fetch_add(utility, Ordering::Relaxed);
    }
}

impl Default for ConstrainedBanditRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
const fn idx(family_idx: usize, arm: usize) -> usize {
    family_idx * ARM_COUNT + arm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_risk_prefers_full() {
        let router = ConstrainedBanditRouter::new();
        let profile =
            router.select_profile(ApiFamily::Allocator, SafetyLevel::Hardened, 350_000, 0);
        assert_eq!(profile, ValidationProfile::Full);
    }

    #[test]
    fn observes_utilities() {
        let router = ConstrainedBanditRouter::new();
        router.observe(ApiFamily::StringMemory, ValidationProfile::Fast, 9, false);
        router.observe(ApiFamily::StringMemory, ValidationProfile::Full, 45, true);
        // Should not panic and should still return a valid profile.
        let _ = router.select_profile(ApiFamily::StringMemory, SafetyLevel::Hardened, 50_000, 8);
    }
}
