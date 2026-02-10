//! # Ito Quadratic Variation Monitor
//!
//! Tracks the realized volatility of the severity martingale component
//! via its quadratic variation, detecting when the noise process is
//! exploding (volatile) or collapsing (frozen).
//!
//! ## Mathematical Foundation
//!
//! **Ito's Quadratic Variation** (Ito 1944): For a discrete martingale
//! {M_n} with increments ΔM_k = M_k - M_{k-1}, the quadratic variation
//! (predictable compensator) is:
//!
//! ```text
//! [M]_n = Σ_{k=1}^{n} (ΔM_k)²
//! ```
//!
//! By the martingale CLT (Hall & Heyde 1980), if [M]_n / n → σ² > 0:
//!
//! ```text
//! M_n / √n → N(0, σ²)
//! ```
//!
//! The normalized quadratic variation QV_n = [M]_n / n converges to the
//! variance of the increment distribution. Monitoring QV_n reveals:
//!
//! - **Stable**: QV_n is moderate and roughly constant — normal volatility.
//! - **Volatile**: QV_n is large or growing — noise amplitude is exploding,
//!   severity transitions are becoming erratic.
//! - **Frozen**: QV_n ≈ 0 — the martingale component has collapsed,
//!   meaning severity is entirely deterministic (stuck or drifting).
//!
//! ## Relationship to Other Monitors
//!
//! - **Doob decomposition**: separates drift A_n from noise M_n.
//!   Ito QV measures the VOLATILITY of that noise.
//! - **Azuma-Hoeffding**: bounds cumulative deviation |M_n|.
//!   Ito QV tracks the realized variance [M]_n, not just bounds.
//! - **Lyapunov**: measures trajectory divergence (chaos).
//!   Ito QV measures increment variance (volatility).
//!
//! ## Online Estimation
//!
//! Per controller i:
//! 1. EWMA mean μ̂_i of severity (same as Doob/Azuma).
//! 2. Centered increment: ΔM_k = X_k - μ̂_i.
//! 3. Quadratic variation: [M]_n += (ΔM_k)².
//! 4. Normalized: QV_n = [M]_n / n.
//!
//! Aggregate: EWMA of max QV across controllers.
//!
//! ## Legacy Anchor
//!
//! `pthread_barrier_wait` — barrier synchronization produces stochastic
//! arrival times. The volatility (quadratic variation) of these arrival
//! times determines whether barriers complete in bounded time or suffer
//! from high variance causing timeouts. Ito QV detects exactly this:
//! when the noise in a cyclical process becomes pathologically volatile.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity states.
const K: usize = 4;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.03;

/// Warmup observations.
const WARMUP: u32 = 40;

/// QV threshold for Frozen state (per step).
const FROZEN_THRESHOLD: f64 = 0.02;

/// QV threshold for Volatile state (per step).
const VOLATILE_THRESHOLD: f64 = 2.0;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ItoQvState {
    /// Insufficient data.
    Calibrating = 0,
    /// Moderate realized volatility — healthy noise level.
    Stable = 1,
    /// Near-zero quadratic variation — process is frozen/deterministic.
    Frozen = 2,
    /// High quadratic variation — noise is exploding.
    Volatile = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct ItoQvSummary {
    /// Current state.
    pub state: ItoQvState,
    /// Maximum normalized QV across controllers.
    pub max_qv_per_step: f64,
    /// Mean normalized QV across controllers.
    pub mean_qv_per_step: f64,
    /// Total observations.
    pub observations: u32,
}

/// Ito quadratic variation monitor.
pub struct ItoQuadraticVariationMonitor {
    /// Per-controller EWMA mean of severity.
    mean: [f64; N],
    /// Per-controller cumulative quadratic variation [M]_n.
    qv: [f64; N],
    /// Observation count.
    count: u32,
    /// Smoothed max QV per step.
    max_qv_per_step: f64,
    /// Smoothed mean QV per step.
    mean_qv_per_step: f64,
    /// Current state.
    state: ItoQvState,
}

impl ItoQuadraticVariationMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mean: [0.0; N],
            qv: [0.0; N],
            count: 0,
            max_qv_per_step: 0.0,
            mean_qv_per_step: 0.0,
            state: ItoQvState::Calibrating,
        }
    }

    /// Feed a severity vector and update quadratic variation estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let n = self.count as f64;
        let mut max_qv = 0.0_f64;
        let mut sum_qv = 0.0_f64;

        for (i, &sev) in severity.iter().enumerate() {
            let x = (sev as usize).min(K - 1) as f64;

            // Centered increment (martingale residual).
            let delta = x - self.mean[i];

            // Update EWMA mean.
            self.mean[i] += alpha * delta;

            // Accumulate quadratic variation.
            self.qv[i] += delta * delta;

            // Normalized QV per step.
            let qv_per_step = self.qv[i] / n;
            max_qv = max_qv.max(qv_per_step);
            sum_qv += qv_per_step;
        }

        let mean_qv = sum_qv / N as f64;

        // EWMA smooth.
        self.max_qv_per_step += alpha * (max_qv - self.max_qv_per_step);
        self.mean_qv_per_step += alpha * (mean_qv - self.mean_qv_per_step);

        // State classification.
        self.state = if self.count < WARMUP {
            ItoQvState::Calibrating
        } else if self.mean_qv_per_step < FROZEN_THRESHOLD {
            ItoQvState::Frozen
        } else if self.mean_qv_per_step > VOLATILE_THRESHOLD {
            ItoQvState::Volatile
        } else {
            ItoQvState::Stable
        };
    }

    pub fn state(&self) -> ItoQvState {
        self.state
    }

    pub fn max_qv_per_step(&self) -> f64 {
        self.max_qv_per_step
    }

    pub fn mean_qv_per_step(&self) -> f64 {
        self.mean_qv_per_step
    }

    pub fn summary(&self) -> ItoQvSummary {
        ItoQvSummary {
            state: self.state,
            max_qv_per_step: self.max_qv_per_step,
            mean_qv_per_step: self.mean_qv_per_step,
            observations: self.count,
        }
    }
}

impl Default for ItoQuadraticVariationMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = ItoQuadraticVariationMonitor::new();
        assert_eq!(m.state(), ItoQvState::Calibrating);
    }

    #[test]
    fn constant_input_is_frozen() {
        let mut m = ItoQuadraticVariationMonitor::new();
        // Constant severity → zero increments → QV = 0.
        for _ in 0..300 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(
            m.state(),
            ItoQvState::Frozen,
            "Constant input should be Frozen, mean_qv={}",
            m.mean_qv_per_step()
        );
    }

    #[test]
    fn small_fluctuations_are_stable() {
        let mut m = ItoQuadraticVariationMonitor::new();
        // Oscillating between 1 and 2 — moderate variance.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 1u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            ItoQvState::Stable,
            "Small fluctuations should be Stable, mean_qv={}",
            m.mean_qv_per_step()
        );
    }

    #[test]
    fn extreme_oscillations_are_volatile() {
        let mut m = ItoQuadraticVariationMonitor::new();
        // Oscillating between 0 and 3 every step — maximum variance.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 3u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            ItoQvState::Volatile,
            "Extreme oscillations should be Volatile, mean_qv={}",
            m.mean_qv_per_step()
        );
    }

    #[test]
    fn qv_is_nonnegative() {
        let mut m = ItoQuadraticVariationMonitor::new();
        let mut rng = 77u64;
        for _ in 0..300 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_qv_per_step() >= 0.0,
            "QV must be non-negative: {}",
            m.max_qv_per_step()
        );
        assert!(
            m.mean_qv_per_step() >= 0.0,
            "Mean QV must be non-negative: {}",
            m.mean_qv_per_step()
        );
    }

    #[test]
    fn recovery_from_frozen() {
        let mut m = ItoQuadraticVariationMonitor::new();
        // Frozen phase (enough steps to dilute warmup transients).
        for _ in 0..300 {
            m.observe_and_update(&[2u8; N]);
        }
        assert_eq!(m.state(), ItoQvState::Frozen);
        // Then noisy phase.
        let mut rng = 42u64;
        for _ in 0..2000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert_ne!(
            m.state(),
            ItoQvState::Frozen,
            "Should recover from Frozen, mean_qv={}",
            m.mean_qv_per_step()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = ItoQuadraticVariationMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_qv_per_step - m.max_qv_per_step()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
