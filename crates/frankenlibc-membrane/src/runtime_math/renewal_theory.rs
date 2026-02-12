//! # Renewal Theory Monitor
//!
//! Tracks the inter-arrival times of "return to healthy" events in the
//! severity process, detecting when the system loses its ability to
//! recover from perturbations.
//!
//! ## Mathematical Foundation
//!
//! **Blackwell's Renewal Theorem** (Blackwell 1948): For an aperiodic
//! renewal process with inter-arrival distribution F having finite mean μ:
//!
//! ```text
//! U(t+h) - U(t) → h/μ   as t → ∞
//! ```
//!
//! where U(t) = E[N(t)] is the renewal function and N(t) counts
//! renewals up to time t.
//!
//! **Key Renewal Theorem** (Smith 1958): For a non-arithmetic renewal
//! process with inter-arrival times {T_i} having mean μ:
//!
//! ```text
//! E[excess life at time t] → (E[T²]) / (2μ)   as t → ∞
//! ```
//!
//! The "excess life" (or residual life) at time t is the time until
//! the NEXT renewal after t.
//!
//! ## Why Renewal Theory?
//!
//! Existing monitors detect anomalies (distributional shift, drift,
//! mixing failure) but not the system's **recovery dynamics**:
//!
//! - **Renewal rate**: how often does the system return to "healthy"?
//!   A dropping renewal rate means perturbations are lasting longer.
//! - **Current age**: how long since the last renewal? A large age
//!   relative to the mean inter-arrival time means the system is
//!   "overdue" for recovery.
//! - **Age ratio**: age / mean_inter_arrival — the dimensionless
//!   measure of how far we are from expected recovery.
//!
//! No other controller monitors THIS specific property: the time
//! structure of the recovery process itself.
//!
//! ## Online Estimation
//!
//! Per controller i:
//! 1. Track the last step at which severity[i] == 0 (renewal).
//! 2. When a renewal occurs, compute inter-arrival time.
//! 3. Maintain EWMA estimate of mean inter-arrival time μ̂.
//! 4. Current age = steps since last renewal.
//! 5. Age ratio = age / μ̂.
//!
//! Aggregate: maximum age ratio across controllers.
//!
//! ## Legacy Anchor
//!
//! `malloc`/`free` cycles — memory allocation is inherently a renewal
//! process: allocate, use, free, repeat. The health of the memory
//! subsystem depends on the renewal rate: if free() calls become
//! infrequent (long inter-arrival times), memory pressure builds.
//! Renewal theory detects exactly this: when the "return to clean
//! state" cycle is breaking down.

/// Number of base controllers.
const N: usize = 25;

/// Severity state that constitutes a "renewal" (full recovery).
const RENEWAL_STATE: u8 = 0;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.03;

/// Warmup observations before state classification.
const WARMUP: u32 = 40;

/// Minimum renewals per controller before meaningful age ratio.
const MIN_RENEWALS: u32 = 3;

/// Age ratio threshold for Aging state.
const AGING_THRESHOLD: f64 = 3.0;

/// Age ratio threshold for Stale state.
const STALE_THRESHOLD: f64 = 8.0;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RenewalState {
    /// Insufficient data or renewals.
    Calibrating = 0,
    /// System recovering at expected rate.
    Renewing = 1,
    /// Recovery taking longer than expected.
    Aging = 2,
    /// System stuck — recovery is overdue.
    Stale = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct RenewalSummary {
    /// Current state.
    pub state: RenewalState,
    /// Maximum age ratio across controllers.
    pub max_age_ratio: f64,
    /// Mean EWMA inter-arrival time across controllers.
    pub mean_renewal_time: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller renewal tracker.
struct ControllerRenewal {
    /// Step at which the last renewal occurred.
    last_renewal_step: u32,
    /// Number of renewals observed.
    renewal_count: u32,
    /// EWMA estimate of mean inter-arrival time.
    mean_inter_arrival: f64,
}

impl ControllerRenewal {
    fn new() -> Self {
        Self {
            last_renewal_step: 0,
            renewal_count: 0,
            mean_inter_arrival: 0.0,
        }
    }

    /// Record a renewal at the given step. Returns the inter-arrival time.
    fn record_renewal(&mut self, step: u32, alpha: f64) -> Option<f64> {
        if self.renewal_count == 0 {
            self.last_renewal_step = step;
            self.renewal_count = 1;
            return None;
        }

        let inter_arrival = (step - self.last_renewal_step) as f64;
        self.last_renewal_step = step;
        self.renewal_count = self.renewal_count.saturating_add(1);

        if self.mean_inter_arrival < 1e-12 {
            // First real inter-arrival.
            self.mean_inter_arrival = inter_arrival;
        } else {
            self.mean_inter_arrival += alpha * (inter_arrival - self.mean_inter_arrival);
        }

        Some(inter_arrival)
    }

    /// Current age (steps since last renewal).
    fn age(&self, current_step: u32) -> u32 {
        current_step.saturating_sub(self.last_renewal_step)
    }

    /// Age ratio: current_age / mean_inter_arrival.
    fn age_ratio(&self, current_step: u32) -> f64 {
        if self.renewal_count < MIN_RENEWALS || self.mean_inter_arrival < 1e-12 {
            return 0.0; // Not enough data.
        }
        self.age(current_step) as f64 / self.mean_inter_arrival
    }
}

/// Renewal theory monitor.
pub struct RenewalTheoryMonitor {
    /// Per-controller renewal trackers.
    trackers: Vec<ControllerRenewal>,
    /// Observation count.
    count: u32,
    /// Smoothed maximum age ratio.
    max_age_ratio: f64,
    /// Smoothed mean renewal time.
    mean_renewal_time: f64,
    /// Current state.
    state: RenewalState,
}

impl RenewalTheoryMonitor {
    #[must_use]
    pub fn new() -> Self {
        let trackers = (0..N).map(|_| ControllerRenewal::new()).collect();
        Self {
            trackers,
            count: 0,
            max_age_ratio: 0.0,
            mean_renewal_time: 0.0,
            state: RenewalState::Calibrating,
        }
    }

    /// Feed a severity vector and update renewal estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        let mut max_ratio = 0.0_f64;
        let mut sum_mean_renewal = 0.0_f64;
        let mut renewal_count_sum = 0u32;

        for (i, &sev) in severity.iter().enumerate() {
            // Check for renewal (severity == 0).
            if sev == RENEWAL_STATE {
                self.trackers[i].record_renewal(self.count, alpha);
            }

            // Compute age ratio for this controller.
            let ratio = self.trackers[i].age_ratio(self.count);
            max_ratio = max_ratio.max(ratio);

            if self.trackers[i].renewal_count >= MIN_RENEWALS {
                sum_mean_renewal += self.trackers[i].mean_inter_arrival;
                renewal_count_sum += 1;
            }
        }

        // EWMA smooth the max age ratio.
        self.max_age_ratio += alpha * (max_ratio - self.max_age_ratio);

        // Mean renewal time across controllers with enough data.
        if renewal_count_sum > 0 {
            let avg_renewal = sum_mean_renewal / renewal_count_sum as f64;
            self.mean_renewal_time += alpha * (avg_renewal - self.mean_renewal_time);
        }

        // State classification.
        let has_enough_renewals = self
            .trackers
            .iter()
            .any(|t| t.renewal_count >= MIN_RENEWALS);
        self.state = if self.count < WARMUP || !has_enough_renewals {
            RenewalState::Calibrating
        } else if self.max_age_ratio >= STALE_THRESHOLD {
            RenewalState::Stale
        } else if self.max_age_ratio >= AGING_THRESHOLD {
            RenewalState::Aging
        } else {
            RenewalState::Renewing
        };
    }

    pub fn state(&self) -> RenewalState {
        self.state
    }

    pub fn max_age_ratio(&self) -> f64 {
        self.max_age_ratio
    }

    pub fn mean_renewal_time(&self) -> f64 {
        self.mean_renewal_time
    }

    pub fn summary(&self) -> RenewalSummary {
        RenewalSummary {
            state: self.state,
            max_age_ratio: self.max_age_ratio,
            mean_renewal_time: self.mean_renewal_time,
            observations: self.count,
        }
    }
}

impl Default for RenewalTheoryMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = RenewalTheoryMonitor::new();
        assert_eq!(m.state(), RenewalState::Calibrating);
    }

    #[test]
    fn frequent_renewals_are_renewing() {
        let mut m = RenewalTheoryMonitor::new();
        // Alternate between 0 (renewal) and 1 — frequent recovery.
        for i in 0u32..500 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 1u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            RenewalState::Renewing,
            "Frequent renewals should be Renewing, max_age_ratio={}",
            m.max_age_ratio()
        );
    }

    #[test]
    fn constant_zero_is_renewing() {
        let mut m = RenewalTheoryMonitor::new();
        // Always at renewal state — renewal every step.
        for _ in 0..200 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(
            m.state(),
            RenewalState::Renewing,
            "Constant zero should be Renewing, max_age_ratio={}",
            m.max_age_ratio()
        );
    }

    #[test]
    fn no_renewals_stays_calibrating() {
        let mut m = RenewalTheoryMonitor::new();
        // Never reaches state 0 — no renewals.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        assert_eq!(
            m.state(),
            RenewalState::Calibrating,
            "No renewals should stay Calibrating"
        );
    }

    #[test]
    fn stuck_after_renewals_detected() {
        let mut m = RenewalTheoryMonitor::new();
        // First: frequent renewals to establish baseline.
        for i in 0u32..200 {
            let val = if i.is_multiple_of(3) { 0u8 } else { 2u8 };
            m.observe_and_update(&[val; N]);
        }
        // Then: stuck at high severity — age grows while mean stays low.
        for _ in 0..300 {
            m.observe_and_update(&[3u8; N]);
        }
        assert_ne!(
            m.state(),
            RenewalState::Renewing,
            "Should detect aging/stale after going stuck, max_age_ratio={}",
            m.max_age_ratio()
        );
    }

    #[test]
    fn recovery_returns_to_renewing() {
        let mut m = RenewalTheoryMonitor::new();
        // Establish baseline.
        for i in 0u32..100 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 1u8 };
            m.observe_and_update(&[val; N]);
        }
        // Go stuck.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Recover with frequent renewals.
        for i in 0u32..1000 {
            let val = if i.is_multiple_of(2) { 0u8 } else { 1u8 };
            m.observe_and_update(&[val; N]);
        }
        assert_eq!(
            m.state(),
            RenewalState::Renewing,
            "Should recover to Renewing, max_age_ratio={}",
            m.max_age_ratio()
        );
    }

    #[test]
    fn age_ratio_nonnegative() {
        let mut m = RenewalTheoryMonitor::new();
        for i in 0u32..200 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_age_ratio() >= 0.0,
            "Age ratio must be non-negative: {}",
            m.max_age_ratio()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = RenewalTheoryMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[0u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_age_ratio - m.max_age_ratio()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
    }
}
