//! # Malliavin Sensitivity Controller
//!
//! Discrete Malliavin calculus for estimating how sensitive the aggregate
//! safety decision is to small perturbations in each controller state.
//!
//! ## Mathematical Foundation
//!
//! The **Malliavin derivative** of a functional F(ω) on a probability
//! space is a measure of its local sensitivity to noise perturbations.
//! In the original continuous setting (Malliavin 1978), D_t F captures
//! how an Itô functional changes when the driving Brownian motion is
//! perturbed at time t.
//!
//! We adapt this to the discrete controller ensemble. Given the
//! severity vector x = (x₁, …, x_N) ∈ {0,1,2,3}^N, define the
//! **aggregate severity functional**:
//!
//! ```text
//! F(x) = Σᵢ wᵢ xᵢ / Σᵢ wᵢ
//! ```
//!
//! where wᵢ are importance weights (derived from the fusion weights).
//! The discrete Malliavin derivative along coordinate i is:
//!
//! ```text
//! Dᵢ F = ∂F/∂xᵢ = wᵢ / Σⱼ wⱼ
//! ```
//!
//! This is constant for a linear functional, so the interesting
//! quantity is the **second-order sensitivity** — how the decision
//! *boundary* shifts when a controller's state changes. We track
//! the empirical **sensitivity score**:
//!
//! ```text
//! Sᵢ(t) = |xᵢ(t) − x̄ᵢ| × wᵢ / ‖w‖₁
//! ```
//!
//! The aggregate **sensitivity norm** is:
//!
//! ```text
//! ‖S(t)‖ = √(Σᵢ Sᵢ(t)²)
//! ```
//!
//! When ‖S‖ is high, many controllers are far from their means in
//! important directions — the system is on a decision boundary where
//! small perturbations can flip the outcome.
//!
//! ## Clark-Ocone Decomposition (Adapted)
//!
//! The Clark-Ocone formula decomposes a random variable into its
//! conditional expectation plus a stochastic integral of Malliavin
//! derivatives:
//!
//! ```text
//! F = E[F] + Σᵢ E[Dᵢ F | Fᵢ₋₁] ΔMᵢ
//! ```
//!
//! where ΔMᵢ is the innovation. In our discrete setting, this becomes
//! a running decomposition of the aggregate severity into:
//! - **predictable component**: rolling mean of F
//! - **innovation component**: weighted sum of per-controller surprises
//!
//! The ratio of innovation variance to total variance is the
//! **fragility index** — when high, the system's behavior is dominated
//! by unpredictable perturbations rather than stable trends.
//!
//! ## Why This Matters for the Runtime
//!
//! Other meta-controllers track *what* the ensemble state is. This
//! controller tracks *how fragile* that state is — whether a tiny
//! push on any single controller could cascade into a different
//! safety decision. High fragility suggests the system should invest
//! in extra validation to avoid oscillating between decisions.

use std::sync::atomic::{AtomicU8, Ordering};

/// Number of base controllers in the severity array.
const N: usize = 25;

/// EWMA smoothing factor for running statistics.
const ALPHA: f64 = 0.05;

/// Minimum warmup observations before leaving Calibrating.
const WARMUP: u32 = 20;

/// Importance weights for each controller (derived from typical
/// severity impact). In practice these could be learned; we use
/// a fixed assignment based on the fusion weight structure.
///
/// Layout matches base_severity array:
/// 0:spectral 1:rough_path 2:persistence 3:anytime 4:cvar
/// 5:bridge 6:large_dev 7:hji 8:mean_field 9:padic
/// 10:symplectic 11:sparse 12:equivariant 13:topos 14:audit
/// 15:changepoint 16:conformal 17:loss 18:coupling 19:microlocal
/// 20:serre 21:clifford 22:ktheory 23:covering 24:tstructure
const WEIGHTS: [f64; N] = [
    1.2, 1.1, 1.0, 1.3, 1.4, // spectral..cvar
    0.9, 1.1, 1.2, 1.0, 0.8, // bridge..padic
    0.9, 0.8, 1.0, 1.1, 1.2, // symplectic..audit
    1.3, 1.4, 1.1, 1.0, 0.9, // changepoint..microlocal
    0.8, 0.9, 1.0, 0.8, 0.7, // serre..tstructure
];

/// Sensitivity norm threshold for Sensitive state.
/// Low enough to detect a single high-weight controller oscillating.
const SENSITIVE_THRESHOLD: f64 = 0.10;

/// Sensitivity norm threshold for Fragile state.
const FRAGILE_THRESHOLD: f64 = 0.35;

/// Fragility index threshold (innovation-to-total variance ratio).
const FRAGILITY_INDEX_THRESHOLD: f64 = 0.70;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SensitivityState {
    /// Insufficient data for meaningful estimates.
    Calibrating = 0,
    /// Sensitivity norm is low; system is in a robust configuration.
    Robust = 1,
    /// Sensitivity norm is elevated; system is near a decision boundary.
    Sensitive = 2,
    /// Sensitivity is extreme or fragility index is high; system is
    /// dominated by unpredictable perturbations.
    Fragile = 3,
}

/// Summary statistics for snapshot reporting.
#[derive(Debug, Clone)]
pub struct MalliavSummary {
    pub state: SensitivityState,
    pub sensitivity_norm: f64,
    pub fragility_index: f64,
    pub top_contributor: usize,
    pub observations: u32,
}

/// Discrete Malliavin sensitivity controller.
pub struct MalliavSensitivity {
    /// Running mean of each controller's severity (EWMA).
    mean: [f64; N],
    /// Running mean of the aggregate functional F.
    f_mean: f64,
    /// Slow-timescale variance of F (captures total historical variance).
    f_var_slow: f64,
    /// Fast-timescale innovation variance (captures recent surprises).
    innov_var_fast: f64,
    /// Per-controller sensitivity scores (EWMA-smoothed).
    sensitivity: [f64; N],
    /// Smoothed aggregate sensitivity norm.
    sensitivity_norm: f64,
    /// Total weight for normalization.
    weight_sum: f64,
    /// Observation count.
    count: u32,
    /// Current state.
    state: SensitivityState,
    /// Cached state code for lock-free reads.
    pub cached_state: AtomicU8,
}

impl MalliavSensitivity {
    #[must_use]
    pub fn new() -> Self {
        let weight_sum: f64 = WEIGHTS.iter().sum();
        Self {
            mean: [0.0; N],
            f_mean: 0.0,
            f_var_slow: 0.0,
            innov_var_fast: 0.0,
            sensitivity: [0.0; N],
            sensitivity_norm: 0.0,
            weight_sum,
            count: 0,
            state: SensitivityState::Calibrating,
            cached_state: AtomicU8::new(0),
        }
    }

    /// Feed a new severity vector and update sensitivity estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count < WARMUP {
            // Use a wider window during warmup for stability.
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Convert to f64 and compute aggregate functional.
        let vals: [f64; N] = {
            let mut v = [0.0; N];
            for (vi, &s) in v.iter_mut().zip(severity.iter()) {
                *vi = f64::from(s);
            }
            v
        };

        let f_current: f64 = vals
            .iter()
            .zip(WEIGHTS.iter())
            .map(|(&v, &w)| v * w)
            .sum::<f64>()
            / self.weight_sum;

        // Innovation = deviation of F from its running mean.
        let innovation = f_current - self.f_mean;

        // Update running mean of F.
        self.f_mean += alpha * innovation;

        // Two-timescale variance decomposition for the Clark-Ocone fragility index.
        // Slow variance (alpha/5) captures long-term total variance of F.
        // Fast variance (alpha) captures recent innovation magnitude.
        // When innovations dominate total variance, the system is fragile.
        let alpha_slow = alpha * 0.2;
        self.f_var_slow += alpha_slow * (innovation * innovation - self.f_var_slow);
        self.innov_var_fast += alpha * (innovation * innovation - self.innov_var_fast);

        // Per-controller sensitivity: |xᵢ - x̄ᵢ| × wᵢ / ‖w‖₁.
        let mut sensitivity_sq_sum = 0.0;
        for i in 0..N {
            // Update per-controller mean.
            self.mean[i] += alpha * (vals[i] - self.mean[i]);

            // Malliavin sensitivity score for this coordinate.
            let s_i = (vals[i] - self.mean[i]).abs() * WEIGHTS[i] / self.weight_sum;

            // Smooth the per-controller sensitivity.
            self.sensitivity[i] += alpha * (s_i - self.sensitivity[i]);

            sensitivity_sq_sum += self.sensitivity[i] * self.sensitivity[i];
        }

        // Aggregate sensitivity norm (EWMA-smoothed).
        let raw_norm = sensitivity_sq_sum.sqrt();
        self.sensitivity_norm += alpha * (raw_norm - self.sensitivity_norm);

        // Fragility index = innovation variance / (innovation + slow variance).
        //
        // This matches the docstring notion of "innovation-to-total variance ratio"
        // and avoids pathological ratios > 1 when the slow variance lags during
        // warmup or rapidly stabilizing regimes.
        let denom = self.innov_var_fast + self.f_var_slow;
        let fragility = if denom > 1e-6 {
            (self.innov_var_fast / denom).clamp(0.0, 1.0)
        } else {
            0.0
        };

        // State classification.
        self.state = if self.count < WARMUP {
            SensitivityState::Calibrating
        } else if self.sensitivity_norm >= FRAGILE_THRESHOLD
            || fragility >= FRAGILITY_INDEX_THRESHOLD
        {
            SensitivityState::Fragile
        } else if self.sensitivity_norm >= SENSITIVE_THRESHOLD {
            SensitivityState::Sensitive
        } else {
            SensitivityState::Robust
        };

        self.cached_state.store(self.state as u8, Ordering::Relaxed);
    }

    /// Current state.
    pub fn state(&self) -> SensitivityState {
        self.state
    }

    /// Aggregate sensitivity norm.
    pub fn sensitivity_norm(&self) -> f64 {
        self.sensitivity_norm
    }

    /// Fragility index (innovation-to-total variance ratio).
    pub fn fragility_index(&self) -> f64 {
        let denom = self.innov_var_fast + self.f_var_slow;
        if denom > 1e-6 {
            (self.innov_var_fast / denom).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    /// Index of the controller with highest sensitivity.
    pub fn top_contributor(&self) -> usize {
        self.sensitivity
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0)
    }

    /// Produce a summary for snapshot reporting.
    pub fn summary(&self) -> MalliavSummary {
        MalliavSummary {
            state: self.state,
            sensitivity_norm: self.sensitivity_norm,
            fragility_index: self.fragility_index(),
            top_contributor: self.top_contributor(),
            observations: self.count,
        }
    }
}

impl Default for MalliavSensitivity {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_severity(vals: &[u8]) -> [u8; N] {
        let mut arr = [0u8; N];
        for (i, &v) in vals.iter().enumerate().take(N) {
            arr[i] = v;
        }
        arr
    }

    #[test]
    fn calibrating_during_warmup() {
        let mut m = MalliavSensitivity::new();
        for _ in 0..10 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(m.state(), SensitivityState::Calibrating);
        assert_eq!(m.count, 10);
    }

    #[test]
    fn stable_inputs_yield_robust() {
        let mut m = MalliavSensitivity::new();
        // Feed identical vectors for warmup + beyond.
        let stable = make_severity(&[1; N]);
        for _ in 0..100 {
            m.observe_and_update(&stable);
        }
        assert_eq!(m.state(), SensitivityState::Robust);
        // Sensitivity norm should be near zero.
        assert!(
            m.sensitivity_norm() < 0.05,
            "sensitivity_norm {} should be near zero for constant input",
            m.sensitivity_norm()
        );
    }

    #[test]
    fn high_variance_controllers_drive_sensitivity() {
        let mut m = MalliavSensitivity::new();
        // Warmup with zeros.
        for _ in 0..WARMUP {
            m.observe_and_update(&[0u8; N]);
        }
        // Spike several high-weight controllers to 3, alternating with zeros.
        // Controllers 3(anytime,1.3), 4(cvar,1.4), 15(changepoint,1.3), 16(conformal,1.4)
        let mut spiked = [0u8; N];
        spiked[3] = 3;
        spiked[4] = 3;
        spiked[15] = 3;
        spiked[16] = 3;
        for _ in 0..300 {
            m.observe_and_update(&[0u8; N]);
            m.observe_and_update(&spiked);
        }
        // Top contributor should be one of the spiked high-weight controllers.
        let top = m.top_contributor();
        assert!(
            [3, 4, 15, 16].contains(&top),
            "top contributor {} should be one of the spiked controllers",
            top
        );
        // State should be at least Sensitive.
        assert!(
            m.state() as u8 >= SensitivityState::Sensitive as u8,
            "state {:?} should be >= Sensitive (norm={})",
            m.state(),
            m.sensitivity_norm()
        );
    }

    #[test]
    fn fragility_index_increases_with_unpredictability() {
        let mut m = MalliavSensitivity::new();
        // Warmup.
        for _ in 0..WARMUP {
            m.observe_and_update(&make_severity(&[1; N]));
        }
        // Now alternate wildly between all-0 and all-3.
        for _ in 0..300 {
            m.observe_and_update(&[0u8; N]);
            m.observe_and_update(&[3u8; N]);
        }
        // Innovation variance should be high relative to total.
        let fi = m.fragility_index();
        assert!(
            fi > 0.5,
            "fragility_index {} should be high for unpredictable alternation",
            fi
        );
    }

    #[test]
    fn recovery_from_fragile() {
        let mut m = MalliavSensitivity::new();
        // Warmup.
        for _ in 0..WARMUP {
            m.observe_and_update(&[1u8; N]);
        }
        // Drive into fragile with wild alternation.
        for _ in 0..200 {
            m.observe_and_update(&[0u8; N]);
            m.observe_and_update(&[3u8; N]);
        }
        let peak_state = m.state();
        assert!(
            peak_state as u8 >= SensitivityState::Sensitive as u8,
            "should reach at least Sensitive, got {:?}",
            peak_state
        );

        // Now stabilize.
        for _ in 0..500 {
            m.observe_and_update(&[1u8; N]);
        }
        assert_eq!(
            m.state(),
            SensitivityState::Robust,
            "should recover to Robust after stabilization"
        );
    }

    #[test]
    fn all_zeros_is_robust() {
        let mut m = MalliavSensitivity::new();
        for _ in 0..100 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(m.state(), SensitivityState::Robust);
        assert!(m.fragility_index() < 0.01);
    }

    #[test]
    fn summary_fields_populated() {
        let mut m = MalliavSensitivity::new();
        for _ in 0..50 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.observations, 50);
        assert_eq!(s.state, m.state());
        assert!((s.sensitivity_norm - m.sensitivity_norm()).abs() < 1e-12);
        assert!(s.top_contributor < N);
    }
}
