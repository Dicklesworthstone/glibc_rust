//! Runtime risk upper-bound estimator (conformal-style envelope).

use std::sync::atomic::{AtomicU64, Ordering};

use super::ApiFamily;

/// Conformal-style online risk envelope.
///
/// This tracks adverse outcomes per family and exposes a conservative upper
/// bound in ppm. It is intentionally lightweight for hot runtime use.
pub struct ConformalRiskEngine {
    calls: [AtomicU64; ApiFamily::COUNT],
    adverse: [AtomicU64; ApiFamily::COUNT],
    prior_ppm: u32,
    z_score: f64,
}

impl ConformalRiskEngine {
    /// Create a new engine.
    ///
    /// `prior_ppm` controls startup conservatism before enough calls are observed.
    /// `z_score` controls confidence width (e.g., 3.0 ~ highly conservative).
    #[must_use]
    pub fn new(prior_ppm: u32, z_score: f64) -> Self {
        Self {
            calls: std::array::from_fn(|_| AtomicU64::new(0)),
            adverse: std::array::from_fn(|_| AtomicU64::new(0)),
            prior_ppm,
            z_score,
        }
    }

    /// Record one runtime outcome for a family.
    pub fn observe(&self, family: ApiFamily, adverse: bool) {
        let idx = usize::from(family as u8);
        self.calls[idx].fetch_add(1, Ordering::Relaxed);
        if adverse {
            self.adverse[idx].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Conservative upper bound on adverse probability in ppm.
    ///
    /// Uses a smoothed binomial estimate with normal approximation envelope.
    #[must_use]
    pub fn upper_bound_ppm(&self, family: ApiFamily) -> u32 {
        let idx = usize::from(family as u8);
        let calls = self.calls[idx].load(Ordering::Relaxed);
        if calls < 32 {
            return self.prior_ppm;
        }

        let adverse = self.adverse[idx].load(Ordering::Relaxed);
        let n = calls as f64;
        let p_hat = (adverse as f64 + 1.0) / (n + 2.0);
        let var = (p_hat * (1.0 - p_hat) / (n + 3.0)).max(0.0);
        let ub = (p_hat + self.z_score * var.sqrt()).clamp(0.0, 1.0);

        (ub * 1_000_000.0).round() as u32
    }
}

impl Default for ConformalRiskEngine {
    fn default() -> Self {
        Self::new(20_000, 3.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_with_prior() {
        let risk = ConformalRiskEngine::new(12_345, 3.0);
        assert_eq!(risk.upper_bound_ppm(ApiFamily::Allocator), 12_345);
    }

    #[test]
    fn adverse_outcomes_increase_upper_bound() {
        let risk = ConformalRiskEngine::default();
        for _ in 0..128 {
            risk.observe(ApiFamily::StringMemory, true);
        }
        let ub = risk.upper_bound_ppm(ApiFamily::StringMemory);
        assert!(ub > 500_000);
    }

    #[test]
    fn mostly_clean_traffic_reduces_upper_bound() {
        let risk = ConformalRiskEngine::new(50_000, 2.0);
        for i in 0..512 {
            risk.observe(ApiFamily::PointerValidation, i % 200 == 0);
        }
        let ub = risk.upper_bound_ppm(ApiFamily::PointerValidation);
        assert!(ub < 50_000);
    }
}
