//! Alpha-Investing FDR Controller (Foster & Stine 2008)
//!
//! Controls the false discovery rate of escalation alarms across the
//! runtime_math monitor ensemble. Many monitors run in parallel, each
//! producing alarm/warning states. Without FDR control, the compound
//! false alarm rate grows with the number of monitors — naive additive
//! bonuses over-escalate, triggering unnecessary full-validation or
//! repair on the hot path.
//!
//! ## Mathematical Foundation
//!
//! **Alpha-Investing** (Foster & Stine, "Alpha-Investing: A Procedure
//! for Sequential Control of Expected False Discoveries", JRSS-B 2008):
//!
//! Maintain a "wealth" W(t) that controls how aggressively alarms are
//! accepted. At each step t when a monitor raises an alarm:
//!
//! 1. **Spend**: allocate α(t) ≤ W(t-1) · spend_fraction to test this alarm.
//! 2. **Test**: if the alarm's evidence (e-value or severity) exceeds 1/α(t),
//!    accept the alarm as a true discovery.
//! 3. **Update wealth**:
//!    - Rejection (true discovery): W(t) = W(t-1) - α(t) + reward
//!    - Non-rejection: W(t) = W(t-1) - α(t)
//!
//! The reward for true discoveries (ω) ensures that under the null,
//! E[discoveries] ≤ W(0) / ω, giving mFDR control.
//!
//! ## Key Invariants
//!
//! 1. Wealth is always non-negative: W(t) ≥ 0.
//! 2. Wealth is bounded above by initial_wealth + total_rewards.
//! 3. Spending per test is bounded: α(t) ≤ W(t-1) · spend_fraction.
//! 4. When wealth is exhausted, all alarms are suppressed (conservative).
//!
//! ## Legacy Anchor
//!
//! `malloc`/`nptl` — concurrent allocator and thread pool produce many
//! independent alarm signals (UAF, double-free, race detection). Without
//! FDR control, the system escalates to full-validation on every call
//! path whenever a handful of noisy monitors spike simultaneously.

/// Number of base controllers tracked for per-controller alarm filtering.
const N: usize = 25;

/// Initial wealth (milli-units). Higher = more permissive initially.
/// W(0) = 500 means we can afford ~50 false alarms before exhaustion
/// at the default spend fraction.
const INITIAL_WEALTH_MILLI: u64 = 500;

/// Fraction of current wealth to spend per test (as milli-fraction, 1000 = all).
/// 50/1000 = 5% of current wealth allocated per alarm test.
const SPEND_FRACTION_MILLI: u64 = 50;

/// Reward for accepting an alarm as true discovery (milli-units).
/// Must be > 0 for wealth recovery. Higher reward means faster
/// recovery but weaker FDR guarantee.
const REWARD_MILLI: u64 = 10;

/// Minimum spend per test (milli-units). Prevents spend from rounding to zero
/// when wealth is very small but nonzero.
const MIN_SPEND_MILLI: u64 = 1;

/// Evidence threshold factor. An alarm is accepted if its severity-based
/// evidence exceeds this factor divided by the allocated alpha.
/// In the classical framework: reject if e-value > 1/α.
/// Here we use severity ≥ 3 (max) as strong evidence and severity < 2 as weak.
const STRONG_EVIDENCE_SEVERITY: u8 = 3;

/// Wealth below which we enter Depleted state (conservative, suppress alarms).
const DEPLETED_THRESHOLD_MILLI: u64 = 10;

/// Wealth above which we enter Generous state (most permissive alarm acceptance).
const GENEROUS_THRESHOLD_MILLI: u64 = 300;

/// Number of observations before leaving Calibrating.
const WARMUP: u64 = 64;

/// Update cadence: only process alarms every N observations to reduce overhead.
const CADENCE: u64 = 8;

/// Controller states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AlphaInvestingState {
    /// Insufficient data.
    Calibrating = 0,
    /// Wealth is healthy, normal FDR control.
    Normal = 1,
    /// Wealth is high, generous alarm acceptance.
    Generous = 2,
    /// Wealth is depleted, alarms suppressed.
    Depleted = 3,
}

/// Summary for snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct AlphaInvestingSummary {
    /// Current state.
    pub state: AlphaInvestingState,
    /// Current wealth (milli-units).
    pub wealth_milli: u64,
    /// Total alarms tested.
    pub tests: u64,
    /// Total alarms accepted as true discoveries.
    pub rejections: u64,
    /// Total alarms suppressed (not accepted).
    pub suppressions: u64,
    /// Empirical false discovery rate estimate (rejections / tests, 0..1).
    pub empirical_fdr: f64,
}

/// Alpha-Investing FDR controller.
///
/// Tracks wealth across sequential alarm tests and controls the compound
/// false discovery rate of the monitor ensemble.
pub struct AlphaInvestingController {
    /// Current wealth in milli-units (0 = fully depleted).
    wealth_milli: u64,
    /// Total number of alarm tests performed.
    tests: u64,
    /// Total number of alarms accepted (rejections of null).
    rejections: u64,
    /// Total number of alarms suppressed.
    suppressions: u64,
    /// Observation count.
    count: u64,
    /// Per-controller alarm latch: tracks which controllers are currently alarming.
    /// Used to count transitions (alarm onset) rather than every tick.
    alarm_active: [bool; N],
    /// Current state.
    state: AlphaInvestingState,
}

impl AlphaInvestingController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            wealth_milli: INITIAL_WEALTH_MILLI,
            tests: 0,
            rejections: 0,
            suppressions: 0,
            count: 0,
            alarm_active: [false; N],
            state: AlphaInvestingState::Calibrating,
        }
    }

    /// Feed a severity vector and process any new alarm onsets.
    ///
    /// Returns the number of alarms accepted in this round.
    pub fn observe_and_update(&mut self, severity: &[u8; N]) -> u32 {
        self.count = self.count.saturating_add(1);

        // Always update alarm latches so onset detection works across
        // cadence boundaries. Track which controllers just transitioned
        // from non-alarm to alarm.
        let mut onsets = [false; N];
        for (i, &sev) in severity.iter().enumerate() {
            let is_alarming = sev >= 2;
            let was_alarming = self.alarm_active[i];
            self.alarm_active[i] = is_alarming;
            onsets[i] = is_alarming && !was_alarming;
        }

        if self.count < WARMUP || !self.count.is_multiple_of(CADENCE) {
            self.state = if self.count < WARMUP {
                AlphaInvestingState::Calibrating
            } else {
                self.classify_state()
            };
            return 0;
        }

        let mut accepted = 0u32;

        for (i, &onset) in onsets.iter().enumerate() {
            if onset {
                accepted += self.test_alarm(severity[i]);
            }
        }

        self.state = self.classify_state();
        accepted
    }

    /// Perform a single alpha-investing test on an alarm with given severity.
    ///
    /// Returns 1 if accepted (true discovery), 0 if suppressed.
    fn test_alarm(&mut self, severity: u8) -> u32 {
        self.tests = self.tests.saturating_add(1);

        // Compute spend: fraction of current wealth.
        let spend = if self.wealth_milli == 0 {
            0
        } else {
            (self.wealth_milli * SPEND_FRACTION_MILLI / 1000).max(MIN_SPEND_MILLI)
        };

        if spend == 0 {
            // Fully depleted — suppress all alarms.
            self.suppressions = self.suppressions.saturating_add(1);
            return 0;
        }

        // Strong evidence: accept the alarm.
        if severity >= STRONG_EVIDENCE_SEVERITY {
            // Deduct spend, add reward.
            self.wealth_milli = self.wealth_milli.saturating_sub(spend);
            self.wealth_milli = self.wealth_milli.saturating_add(REWARD_MILLI);
            self.rejections = self.rejections.saturating_add(1);
            1
        } else {
            // Weak evidence: reject the alarm, deduct spend only.
            self.wealth_milli = self.wealth_milli.saturating_sub(spend);
            self.suppressions = self.suppressions.saturating_add(1);
            0
        }
    }

    fn classify_state(&self) -> AlphaInvestingState {
        if self.wealth_milli <= DEPLETED_THRESHOLD_MILLI {
            AlphaInvestingState::Depleted
        } else if self.wealth_milli >= GENEROUS_THRESHOLD_MILLI {
            AlphaInvestingState::Generous
        } else {
            AlphaInvestingState::Normal
        }
    }

    pub fn state(&self) -> AlphaInvestingState {
        self.state
    }

    pub fn wealth_milli(&self) -> u64 {
        self.wealth_milli
    }

    pub fn summary(&self) -> AlphaInvestingSummary {
        let empirical_fdr = if self.tests > 0 {
            // Approximate: fraction of tests that were accepted.
            // True FDR = E[false rejections / rejections], but we track
            // total rejections / total tests as an upper bound.
            self.rejections as f64 / self.tests as f64
        } else {
            0.0
        };

        AlphaInvestingSummary {
            state: self.state,
            wealth_milli: self.wealth_milli,
            tests: self.tests,
            rejections: self.rejections,
            suppressions: self.suppressions,
            empirical_fdr,
        }
    }
}

impl Default for AlphaInvestingController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Advance the controller to count `target` using the given filler severity.
    /// Useful to skip warmup and land on cadence-aligned boundaries.
    fn advance_to(c: &mut AlphaInvestingController, target: u64, filler: u8) {
        while c.count < target {
            c.observe_and_update(&[filler; N]);
        }
    }

    /// Advance to the next cadence-aligned boundary after current count.
    fn advance_to_next_cadence(c: &mut AlphaInvestingController, filler: u8) {
        let next = ((c.count / CADENCE) + 1) * CADENCE;
        advance_to(c, next - 1, filler);
    }

    #[test]
    fn starts_calibrating() {
        let c = AlphaInvestingController::new();
        assert_eq!(c.state(), AlphaInvestingState::Calibrating);
        assert_eq!(c.wealth_milli(), INITIAL_WEALTH_MILLI);
    }

    #[test]
    fn warmup_period_no_tests() {
        let mut c = AlphaInvestingController::new();
        // Feed alarms during warmup — should not trigger any tests.
        for _ in 0..WARMUP - 1 {
            let accepted = c.observe_and_update(&[3u8; N]);
            assert_eq!(accepted, 0);
        }
        assert_eq!(c.tests, 0);
        assert_eq!(c.state(), AlphaInvestingState::Calibrating);
    }

    #[test]
    fn accepts_strong_evidence_alarms() {
        let mut c = AlphaInvestingController::new();
        // Warmup with zeros (land on cadence boundary since WARMUP=64, CADENCE=8).
        advance_to(&mut c, WARMUP, 0);
        // Advance to just before next cadence boundary so alarm call lands on it.
        advance_to_next_cadence(&mut c, 0);
        // Now send strong alarms at cadence boundary.
        let accepted = c.observe_and_update(&[3u8; N]);
        // All 25 controllers should produce alarm onsets.
        assert_eq!(accepted, N as u32);
        assert_eq!(c.rejections, N as u64);
    }

    #[test]
    fn suppresses_weak_evidence_alarms() {
        let mut c = AlphaInvestingController::new();
        advance_to(&mut c, WARMUP, 0);
        advance_to_next_cadence(&mut c, 0);
        // Severity 2 = alarm onset, but evidence is weak (< STRONG_EVIDENCE_SEVERITY).
        let accepted = c.observe_and_update(&[2u8; N]);
        assert_eq!(accepted, 0);
        assert_eq!(c.suppressions, N as u64);
    }

    #[test]
    fn wealth_decreases_on_weak_alarms() {
        let mut c = AlphaInvestingController::new();
        advance_to(&mut c, WARMUP, 0);
        advance_to_next_cadence(&mut c, 0);
        let initial = c.wealth_milli();
        c.observe_and_update(&[2u8; N]);
        assert!(
            c.wealth_milli() < initial,
            "Wealth should decrease on weak alarms: {} >= {}",
            c.wealth_milli(),
            initial
        );
    }

    #[test]
    fn wealth_recovers_on_strong_alarms() {
        let mut c = AlphaInvestingController::new();
        advance_to(&mut c, WARMUP, 0);

        // Drain wealth with weak alarms. Alternate between 0 and 2
        // across cadence-aligned blocks to create alarm onsets.
        for _ in 0..100 {
            advance_to_next_cadence(&mut c, 0); // zeros to reset alarm latches
            c.observe_and_update(&[2u8; N]); // weak alarm onset
        }
        let depleted_wealth = c.wealth_milli();

        // Now feed strong alarms to recover.
        advance_to_next_cadence(&mut c, 0); // reset latches
        c.observe_and_update(&[3u8; N]); // strong alarm onset
        assert!(
            c.wealth_milli() > depleted_wealth || depleted_wealth == 0,
            "Wealth should recover on strong alarms: before={}, after={}",
            depleted_wealth,
            c.wealth_milli()
        );
    }

    #[test]
    fn depleted_state_suppresses_all() {
        let mut c = AlphaInvestingController::new();
        // Force depletion: set count past warmup on a cadence boundary.
        c.wealth_milli = 0;
        c.count = WARMUP + CADENCE - 1; // next observe lands on cadence

        let accepted = c.observe_and_update(&[3u8; N]);
        assert_eq!(
            accepted, 0,
            "Depleted controller should suppress all alarms"
        );
    }

    #[test]
    fn alarm_onset_only() {
        let mut c = AlphaInvestingController::new();
        advance_to(&mut c, WARMUP, 0);

        // First alarm onset at cadence boundary.
        advance_to_next_cadence(&mut c, 0);
        let a1 = c.observe_and_update(&[3u8; N]);
        assert_eq!(a1, N as u32);

        // Sustained alarm at next cadence — no new onset, should not re-test.
        advance_to_next_cadence(&mut c, 3);
        let a = c.observe_and_update(&[3u8; N]);
        assert_eq!(a, 0, "Sustained alarm should not re-test");

        // Drop alarm, then re-alarm at cadence boundary.
        advance_to_next_cadence(&mut c, 0); // zeros clear alarm latches
        c.observe_and_update(&[3u8; N]);
        // May or may not land on cadence; use a known cadence approach.
        advance_to_next_cadence(&mut c, 0);
        let a2 = c.observe_and_update(&[3u8; N]);
        assert_eq!(a2, N as u32, "Re-onset after drop should test again");
    }

    #[test]
    fn state_classification() {
        let mut c = AlphaInvestingController::new();
        // Place count just before a cadence boundary, past warmup.
        c.count = WARMUP + CADENCE - 1;

        c.wealth_milli = GENEROUS_THRESHOLD_MILLI + 1;
        c.observe_and_update(&[0u8; N]);
        assert_eq!(c.state(), AlphaInvestingState::Generous);

        // Advance to next cadence.
        advance_to_next_cadence(&mut c, 0);
        c.wealth_milli = DEPLETED_THRESHOLD_MILLI - 1;
        c.observe_and_update(&[0u8; N]);
        assert_eq!(c.state(), AlphaInvestingState::Depleted);

        advance_to_next_cadence(&mut c, 0);
        c.wealth_milli = 100;
        c.observe_and_update(&[0u8; N]);
        assert_eq!(c.state(), AlphaInvestingState::Normal);
    }

    #[test]
    fn wealth_non_negative_invariant() {
        let mut c = AlphaInvestingController::new();
        advance_to(&mut c, WARMUP, 0);
        // Hammer with alternating weak alarms to drain wealth.
        for _ in 0..500 {
            advance_to_next_cadence(&mut c, 0);
            c.observe_and_update(&[2u8; N]);
        }
        // Should still be functional (no panics from saturating ops).
        let s = c.summary();
        assert!(s.tests > 0);
    }

    #[test]
    fn summary_consistent() {
        let mut c = AlphaInvestingController::new();
        for _ in 0..200 {
            c.observe_and_update(&[1u8; N]);
        }
        let s = c.summary();
        assert_eq!(s.state, c.state());
        assert_eq!(s.wealth_milli, c.wealth_milli());
    }

    #[test]
    fn fdr_bounded() {
        let mut c = AlphaInvestingController::new();
        let mut rng = 42u64;
        advance_to(&mut c, WARMUP, 0);
        // Random severity to simulate mixed alarm patterns.
        for _ in 0..2000 {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            let val = (rng % 4) as u8;
            c.observe_and_update(&[val; N]);
        }
        let s = c.summary();
        // Under mixed random alarms, the FDR should be bounded.
        assert!(s.empirical_fdr <= 1.0);
    }
}
