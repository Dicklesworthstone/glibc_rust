//! # Index of Dispersion (Fisher) Monitor
//!
//! Detects whether severity alarm events are independent (Poisson-like),
//! clustered (overdispersed), or unnaturally regular (underdispersed)
//! using the Fisher index of dispersion.
//!
//! ## Mathematical Foundation
//!
//! **Index of Dispersion** (Fisher 1925): For count data N in windows
//! of size w, the index of dispersion is:
//!
//! ```text
//! I = Var(N) / E[N]
//! ```
//!
//! For a Poisson process (independent events), I = 1 exactly. Deviations
//! indicate:
//!
//! - **I ≈ 1**: events are independent (Poisson) — failures happen
//!   randomly without temporal correlation.
//! - **I > 1**: overdispersed (clustered) — failures come in bursts,
//!   indicating common-cause failures or cascading.
//! - **I < 1**: underdispersed (regular) — failures are more evenly
//!   spaced than random, indicating artificial throttling or periodic
//!   causes.
//!
//! Under H₀ (Poisson), (n-1)·I ~ χ²(n-1), giving a formal test
//! for departure from independence.
//!
//! ## Why Index of Dispersion?
//!
//! Existing monitors detect:
//! - Whether failures persist (Borel-Cantelli: transient vs recurrent)
//! - When failures happen (renewal: inter-arrival times)
//! - How volatile failures are (Ito QV: quadratic variation)
//!
//! The index of dispersion answers a different question: are failures
//! INDEPENDENT or CORRELATED? This is the Poisson hypothesis test:
//!
//! - **Clustered (I >> 1):** failures are correlated — when one occurs,
//!   more follow. This indicates cascading failure modes or shared root
//!   causes that other monitors cannot distinguish from mere persistence.
//! - **Underdispersed (I << 1):** failures are anti-correlated — they
//!   occur with unnatural regularity, suggesting periodic causes (timer
//!   ticks, scheduling artifacts) rather than genuine faults.
//!
//! ## Online Estimation
//!
//! Partition observations into non-overlapping windows of size WINDOW.
//! In each window, count alarm events (severity >= threshold).
//! Maintain EWMA estimates of the window count mean and variance.
//! I = var / mean.
//!
//! ## Legacy Anchor
//!
//! `SIGSEGV` / `SIGBUS` — signal delivery in a healthy system should
//! be approximately Poisson (rare, independent). If segfaults cluster
//! (I >> 1), there's a systematic memory corruption spreading. If
//! they're perfectly periodic (I << 1), something is artificially
//! triggering them (fuzzer, periodic probe). The dispersion index
//! distinguishes these failure modes.

/// Number of base controllers.
const N: usize = 25;

/// Severity threshold defining an "alarm" event.
const ALARM_THRESHOLD: u8 = 2;

/// Window size for counting alarm events.
const WINDOW: u32 = 32;

/// EWMA smoothing parameter.
const ALPHA: f64 = 0.05;

/// Warmup: need several complete windows.
const WARMUP_WINDOWS: u32 = 5;

/// Index of dispersion threshold for Clustered state.
const CLUSTERED_THRESHOLD: f64 = 1.8;

/// Index of dispersion threshold for Underdispersed state.
const UNDERDISPERSED_THRESHOLD: f64 = 0.3;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DispersionState {
    /// Insufficient data (fewer than WARMUP_WINDOWS complete windows).
    Calibrating = 0,
    /// I ≈ 1: alarms are independent (Poisson-like).
    Poisson = 1,
    /// I >> 1: alarms are clustered (overdispersed, cascading).
    Clustered = 2,
    /// I << 1: alarms are unnaturally regular (underdispersed).
    Underdispersed = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct DispersionSummary {
    /// Current state.
    pub state: DispersionState,
    /// Maximum dispersion index across controllers.
    pub max_dispersion: f64,
    /// Mean dispersion index across controllers.
    pub mean_dispersion: f64,
    /// Total observations.
    pub observations: u32,
}

/// Per-controller dispersion tracker.
struct ControllerDispersion {
    /// Alarm count in the current window.
    window_count: u32,
    /// Position within current window.
    window_pos: u32,
    /// EWMA of window count mean (E[N]).
    mean: f64,
    /// EWMA of window count squared mean (E[N²]).
    mean_sq: f64,
    /// Number of complete windows.
    windows_completed: u32,
}

impl ControllerDispersion {
    fn new() -> Self {
        Self {
            window_count: 0,
            window_pos: 0,
            mean: 0.0,
            mean_sq: 0.0,
            windows_completed: 0,
        }
    }

    /// Dispersion index: Var(N) / E[N].
    fn dispersion_index(&self) -> f64 {
        if self.mean < 1e-12 || self.windows_completed < 2 {
            return 1.0; // Default to Poisson assumption.
        }
        let variance = (self.mean_sq - self.mean * self.mean).max(0.0);
        variance / self.mean
    }
}

/// Index of dispersion monitor.
pub struct DispersionIndexMonitor {
    /// Per-controller trackers.
    trackers: [ControllerDispersion; N],
    /// Observation count.
    count: u32,
    /// Smoothed max dispersion index.
    max_dispersion: f64,
    /// Smoothed mean dispersion index.
    mean_dispersion: f64,
    /// Current state.
    state: DispersionState,
}

impl DispersionIndexMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            trackers: core::array::from_fn(|_| ControllerDispersion::new()),
            count: 0,
            max_dispersion: 1.0,
            mean_dispersion: 1.0,
            state: DispersionState::Calibrating,
        }
    }

    /// Feed a severity vector and update dispersion estimates.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);

        for (i, &sev) in severity.iter().enumerate() {
            let t = &mut self.trackers[i];

            // Count alarms in current window.
            if sev >= ALARM_THRESHOLD {
                t.window_count += 1;
            }
            t.window_pos += 1;

            // End of window: update EWMA statistics.
            if t.window_pos >= WINDOW {
                let n = t.window_count as f64;
                let alpha = if t.windows_completed < WARMUP_WINDOWS {
                    2.0 / (t.windows_completed as f64 + 2.0)
                } else {
                    ALPHA
                };

                t.mean += alpha * (n - t.mean);
                t.mean_sq += alpha * (n * n - t.mean_sq);
                t.windows_completed += 1;

                // Reset window.
                t.window_count = 0;
                t.window_pos = 0;
            }
        }

        // Update aggregate statistics when any tracker has enough windows.
        let min_windows = self
            .trackers
            .iter()
            .map(|t| t.windows_completed)
            .min()
            .unwrap_or(0);
        if min_windows < WARMUP_WINDOWS {
            return;
        }

        let mut max_disp = 0.0_f64;
        let mut sum_disp = 0.0_f64;

        for t in &self.trackers {
            let d = t.dispersion_index();
            max_disp = max_disp.max(d);
            sum_disp += d;
        }

        let mean_disp = sum_disp / N as f64;
        let alpha = ALPHA;
        self.max_dispersion += alpha * (max_disp - self.max_dispersion);
        self.mean_dispersion += alpha * (mean_disp - self.mean_dispersion);

        // State classification based on max dispersion.
        self.state = if self.max_dispersion > CLUSTERED_THRESHOLD {
            DispersionState::Clustered
        } else if self.mean_dispersion < UNDERDISPERSED_THRESHOLD {
            DispersionState::Underdispersed
        } else {
            DispersionState::Poisson
        };
    }

    pub fn state(&self) -> DispersionState {
        self.state
    }

    pub fn max_dispersion(&self) -> f64 {
        self.max_dispersion
    }

    pub fn mean_dispersion(&self) -> f64 {
        self.mean_dispersion
    }

    pub fn summary(&self) -> DispersionSummary {
        DispersionSummary {
            state: self.state,
            max_dispersion: self.max_dispersion,
            mean_dispersion: self.mean_dispersion,
            observations: self.count,
        }
    }
}

impl Default for DispersionIndexMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = DispersionIndexMonitor::new();
        assert_eq!(m.state(), DispersionState::Calibrating);
    }

    #[test]
    fn no_alarms_is_poisson() {
        let mut m = DispersionIndexMonitor::new();
        // All severity below threshold — zero alarm count, Var = 0, mean ≈ 0.
        // Dispersion defaults to 1.0 (Poisson assumption) when mean ≈ 0.
        for _ in 0..1000 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_eq!(
            m.state(),
            DispersionState::Poisson,
            "No alarms should be Poisson, dispersion={}",
            m.max_dispersion()
        );
    }

    #[test]
    fn constant_alarms_is_underdispersed() {
        let mut m = DispersionIndexMonitor::new();
        // Constant severity 3 — every observation is an alarm.
        // Window counts are all identical → Var = 0 → I = 0.
        for _ in 0..1000 {
            m.observe_and_update(&[3u8; N]);
        }
        assert_eq!(
            m.state(),
            DispersionState::Underdispersed,
            "Constant alarms should be Underdispersed, mean_disp={}",
            m.mean_dispersion()
        );
    }

    #[test]
    fn bursty_alarms_is_clustered() {
        let mut m = DispersionIndexMonitor::new();
        // Bursty pattern: alternate between all-alarm and no-alarm windows.
        // This creates high variance in window counts → I >> 1.
        for cycle in 0u32..30 {
            let val = if cycle.is_multiple_of(2) { 3u8 } else { 0u8 };
            for _ in 0..WINDOW {
                m.observe_and_update(&[val; N]);
            }
        }
        assert_eq!(
            m.state(),
            DispersionState::Clustered,
            "Bursty alarms should be Clustered, max_disp={}",
            m.max_dispersion()
        );
    }

    #[test]
    fn dispersion_nonnegative() {
        let mut m = DispersionIndexMonitor::new();
        let mut rng = 55u64;
        for _ in 0..1000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.max_dispersion() >= 0.0,
            "Max dispersion must be non-negative: {}",
            m.max_dispersion()
        );
        assert!(
            m.mean_dispersion() >= 0.0,
            "Mean dispersion must be non-negative: {}",
            m.mean_dispersion()
        );
    }

    #[test]
    fn recovery_from_clustered() {
        let mut m = DispersionIndexMonitor::new();
        // Bursty phase.
        for cycle in 0u32..20 {
            let val = if cycle.is_multiple_of(2) { 3u8 } else { 0u8 };
            for _ in 0..WINDOW {
                m.observe_and_update(&[val; N]);
            }
        }
        // Then steady low severity.
        for _ in 0..3000 {
            m.observe_and_update(&[0u8; N]);
        }
        assert_ne!(
            m.state(),
            DispersionState::Clustered,
            "Should recover from Clustered, max_disp={}",
            m.max_dispersion()
        );
    }

    #[test]
    fn summary_consistent() {
        let mut m = DispersionIndexMonitor::new();
        for _ in 0..500 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.max_dispersion - m.max_dispersion()).abs() < 1e-12);
        assert_eq!(s.observations, 500);
    }
}
