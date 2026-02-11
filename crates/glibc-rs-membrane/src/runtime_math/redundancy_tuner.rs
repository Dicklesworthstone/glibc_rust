//! # Adaptive Redundancy Tuner
//!
//! Anytime-valid monitor that tunes evidence redundancy (overhead_percent)
//! based on observed loss/corruption rates, using an e-process sequential
//! test and a conservative fixed-point state machine.
//!
//! ## Mathematical Foundation
//!
//! The tuner maintains a likelihood-ratio e-process on epoch loss events.
//! Under null hypothesis H₀: loss_rate ≤ budget, the e-value stays bounded.
//! Under alternative H₁: loss_rate > budget, the e-value grows exponentially.
//!
//! When the e-process triggers (loss budget exceeded), overhead_percent is
//! increased by a fixed step. When the e-process has been consistently below
//! threshold for a sustained period, overhead may be conservatively decreased.
//!
//! All arithmetic is fixed-point (ppm or basis points). No floating-point.
//!
//! ## Ledger Guarantee
//!
//! Every change to overhead_percent emits a ledger entry with:
//! - Epoch at which change occurred
//! - Previous and new overhead values
//! - Loss rate and e-value at decision time
//! - Reason code (increase/decrease/reset)

/// State of the redundancy tuner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum RedundancyState {
    /// Insufficient observations for valid inference.
    #[default]
    Calibrating = 0,
    /// Loss rate within budget; overhead stable.
    Nominal = 1,
    /// Loss rate approaching budget; overhead may increase soon.
    Stressed = 2,
    /// Loss rate exceeding budget; overhead has been increased.
    Critical = 3,
}

/// Ledger entry recording a redundancy adjustment decision.
#[derive(Debug, Clone, Copy)]
pub struct RedundancyLedgerEntry {
    /// Monotonic ledger sequence number.
    pub ledger_seqno: u64,
    /// Epoch counter at decision time.
    pub epoch_at_decision: u64,
    /// Previous overhead in ppm (0..1_000_000).
    pub prev_overhead_ppm: u32,
    /// New overhead in ppm.
    pub new_overhead_ppm: u32,
    /// Observed loss rate in ppm at decision time.
    pub loss_rate_ppm: u32,
    /// Scaled log e-value (fixed-point, SCALE=1_000_000).
    pub log_e_scaled: i64,
    /// Reason code.
    pub reason: AdjustReason,
}

/// Reason for a redundancy adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AdjustReason {
    /// E-process alarm triggered increase.
    LossBudgetExceeded = 0,
    /// Sustained low-loss period triggered conservative decrease.
    SustainedLowLoss = 1,
}

/// Summary exported to snapshot.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedundancyTunerSummary {
    /// Current overhead in ppm.
    pub overhead_ppm: u32,
    /// Observed loss rate in ppm (EWMA).
    pub loss_rate_ppm: u32,
    /// Current state.
    pub state: u8,
    /// Total epochs observed.
    pub epochs_observed: u64,
    /// Number of adjustments made.
    pub adjustments: u64,
    /// Scaled log e-value.
    pub log_e_scaled: i64,
}

/// Adaptive redundancy tuner.
///
/// Fixed-point state machine that monitors epoch loss rates and adjusts
/// the evidence `overhead_percent` parameter.
pub struct RedundancyTuner {
    /// Current overhead in ppm (10% = 100_000 ppm).
    overhead_ppm: u32,
    /// Minimum allowed overhead in ppm.
    min_overhead_ppm: u32,
    /// Maximum allowed overhead in ppm.
    max_overhead_ppm: u32,
    /// Step size for increases in ppm.
    increase_step_ppm: u32,
    /// Step size for decreases in ppm.
    decrease_step_ppm: u32,

    // EWMA loss rate tracking (ppm, fixed-point).
    /// Smoothed loss rate in ppm.
    loss_rate_ppm: u32,
    /// EWMA decay factor (ppm). 50_000 = 5% weight to new observation.
    ewma_alpha_ppm: u32,

    // E-process state (fixed-point).
    /// Scaled log e-value (×1_000_000).
    log_e_scaled: i64,
    /// Null hypothesis: loss rate ≤ p0_ppm.
    p0_ppm: u32,
    /// Warning threshold (scaled log).
    warning_threshold: i64,
    /// Alarm threshold (scaled log).
    alarm_threshold: i64,
    /// Floor for log e-value.
    log_e_floor: i64,

    // Counters.
    /// Total epochs observed.
    epochs_observed: u64,
    /// Epochs since last adjustment.
    epochs_since_adjust: u64,
    /// Minimum epochs of low-loss before allowing decrease.
    decrease_cooldown: u64,
    /// Warmup epochs before state transitions.
    warmup_epochs: u64,
    /// Total adjustments made.
    adjustments: u64,
    /// Monotonic ledger sequence.
    ledger_seqno: u64,

    // Small ring buffer for recent ledger entries.
    ledger: [Option<RedundancyLedgerEntry>; 8],
    ledger_write_idx: usize,
}

impl RedundancyTuner {
    /// Create a new tuner with default parameters.
    ///
    /// Default: 10% overhead (100_000 ppm), budget p0 = 2% loss rate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            overhead_ppm: 100_000,     // 10%
            min_overhead_ppm: 20_000,  // 2%
            max_overhead_ppm: 500_000, // 50%
            increase_step_ppm: 20_000, // +2% per step
            decrease_step_ppm: 10_000, // -1% per step (conservative)
            loss_rate_ppm: 0,
            ewma_alpha_ppm: 50_000, // 5% new weight
            log_e_scaled: 0,
            p0_ppm: 20_000,               // 2% null
            warning_threshold: 4_605_170, // ln(100) * 1M ≈ 4.605M
            alarm_threshold: 9_210_340,   // ln(10000) * 1M ≈ 9.210M
            log_e_floor: -20_000_000,
            epochs_observed: 0,
            epochs_since_adjust: 0,
            decrease_cooldown: 20,
            warmup_epochs: 5,
            adjustments: 0,
            ledger_seqno: 0,
            ledger: [None; 8],
            ledger_write_idx: 0,
        }
    }

    /// Observe the outcome of a completed epoch.
    ///
    /// `loss_ppm`: fraction of symbols lost in this epoch (0..1_000_000).
    /// `epoch_counter`: monotonic epoch identifier.
    ///
    /// Returns `Some(entry)` if an overhead adjustment was made.
    pub fn observe_epoch(
        &mut self,
        loss_ppm: u32,
        epoch_counter: u64,
    ) -> Option<RedundancyLedgerEntry> {
        self.epochs_observed += 1;
        self.epochs_since_adjust += 1;

        // Update EWMA loss rate: loss_rate = alpha * loss + (1 - alpha) * loss_rate
        let alpha = self.ewma_alpha_ppm as u64;
        let one_minus_alpha = 1_000_000u64.saturating_sub(alpha);
        self.loss_rate_ppm = ((alpha.saturating_mul(loss_ppm as u64)
            + one_minus_alpha.saturating_mul(self.loss_rate_ppm as u64))
            / 1_000_000) as u32;

        // Update e-process: log_e += log(q1/p0) if loss, log((1-q1)/(1-p0)) if no loss.
        // For epoch-level: if loss_ppm > p0_ppm, treat as "adverse" for the e-process.
        let adverse = loss_ppm > self.p0_ppm;
        self.update_eprocess(adverse);

        // State machine transition + possible adjustment.
        if self.epochs_observed < self.warmup_epochs {
            return None;
        }

        let state = self.state();
        match state {
            RedundancyState::Critical => {
                // Already increased; don't spam adjustments.
                // Only increase again if still in alarm after cooldown.
                if self.epochs_since_adjust >= self.decrease_cooldown
                    && self.log_e_scaled >= self.alarm_threshold
                {
                    return self.increase_overhead(epoch_counter);
                }
                None
            }
            RedundancyState::Stressed => {
                if self.log_e_scaled >= self.alarm_threshold {
                    return self.increase_overhead(epoch_counter);
                }
                None
            }
            RedundancyState::Nominal => {
                // Conservative decrease: only after sustained cooldown with consistently
                // low loss and overhead above minimum.
                if self.epochs_since_adjust >= self.decrease_cooldown
                    && self.overhead_ppm > self.min_overhead_ppm
                    && self.loss_rate_ppm == 0
                    && self.log_e_scaled < 0
                {
                    return self.decrease_overhead(epoch_counter);
                }
                None
            }
            RedundancyState::Calibrating => None,
        }
    }

    /// Current state derived from e-process and counters.
    #[must_use]
    pub fn state(&self) -> RedundancyState {
        if self.epochs_observed < self.warmup_epochs {
            return RedundancyState::Calibrating;
        }
        if self.log_e_scaled >= self.alarm_threshold {
            RedundancyState::Critical
        } else if self.log_e_scaled >= self.warning_threshold {
            RedundancyState::Stressed
        } else {
            RedundancyState::Nominal
        }
    }

    /// Current overhead in percent (for derive_repair_symbol_count_v1).
    #[must_use]
    pub fn overhead_percent(&self) -> u16 {
        (self.overhead_ppm / 10_000) as u16
    }

    /// Current overhead in ppm.
    #[must_use]
    pub fn overhead_ppm(&self) -> u32 {
        self.overhead_ppm
    }

    /// Summary for snapshot export.
    #[must_use]
    pub fn summary(&self) -> RedundancyTunerSummary {
        RedundancyTunerSummary {
            overhead_ppm: self.overhead_ppm,
            loss_rate_ppm: self.loss_rate_ppm,
            state: self.state() as u8,
            epochs_observed: self.epochs_observed,
            adjustments: self.adjustments,
            log_e_scaled: self.log_e_scaled,
        }
    }

    /// Most recent ledger entry (if any).
    #[must_use]
    pub fn last_ledger_entry(&self) -> Option<&RedundancyLedgerEntry> {
        if self.ledger_write_idx == 0 && self.ledger[0].is_none() {
            return None;
        }
        let idx = if self.ledger_write_idx == 0 {
            self.ledger.len() - 1
        } else {
            self.ledger_write_idx - 1
        };
        self.ledger[idx].as_ref()
    }

    fn update_eprocess(&mut self, adverse: bool) {
        // Fixed-point log-likelihood ratio update.
        // adverse: log(q1/p0), non-adverse: log((1-q1)/(1-p0))
        //
        // For fixed-point: pre-compute scaled increments.
        // log(q1/p0) = log(100000/20000) = log(5) ≈ 1.609 → 1_609_438 scaled
        // log((1-q1)/(1-p0)) = log(900000/980000) = log(0.9184) ≈ -0.0851 → -85_159 scaled
        let increment = if adverse {
            1_609_438i64 // ln(5) * 1M
        } else {
            -85_159i64 // ln(9/9.8) * 1M
        };
        self.log_e_scaled = self
            .log_e_scaled
            .saturating_add(increment)
            .max(self.log_e_floor);
    }

    fn increase_overhead(&mut self, epoch_counter: u64) -> Option<RedundancyLedgerEntry> {
        let prev = self.overhead_ppm;
        self.overhead_ppm = self
            .overhead_ppm
            .saturating_add(self.increase_step_ppm)
            .min(self.max_overhead_ppm);
        if self.overhead_ppm == prev {
            return None; // Already at max.
        }
        self.emit_ledger(epoch_counter, prev, AdjustReason::LossBudgetExceeded)
    }

    fn decrease_overhead(&mut self, epoch_counter: u64) -> Option<RedundancyLedgerEntry> {
        let prev = self.overhead_ppm;
        self.overhead_ppm = self
            .overhead_ppm
            .saturating_sub(self.decrease_step_ppm)
            .max(self.min_overhead_ppm);
        if self.overhead_ppm == prev {
            return None; // Already at min.
        }
        self.emit_ledger(epoch_counter, prev, AdjustReason::SustainedLowLoss)
    }

    fn emit_ledger(
        &mut self,
        epoch_counter: u64,
        prev_overhead_ppm: u32,
        reason: AdjustReason,
    ) -> Option<RedundancyLedgerEntry> {
        self.adjustments += 1;
        self.epochs_since_adjust = 0;

        let entry = RedundancyLedgerEntry {
            ledger_seqno: self.ledger_seqno,
            epoch_at_decision: epoch_counter,
            prev_overhead_ppm,
            new_overhead_ppm: self.overhead_ppm,
            loss_rate_ppm: self.loss_rate_ppm,
            log_e_scaled: self.log_e_scaled,
            reason,
        };
        self.ledger_seqno += 1;
        self.ledger[self.ledger_write_idx] = Some(entry);
        self.ledger_write_idx = (self.ledger_write_idx + 1) % self.ledger.len();
        Some(entry)
    }
}

impl Default for RedundancyTuner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state_is_calibrating() {
        let tuner = RedundancyTuner::new();
        assert_eq!(tuner.state(), RedundancyState::Calibrating);
        assert_eq!(tuner.overhead_percent(), 10);
        assert_eq!(tuner.overhead_ppm(), 100_000);
    }

    #[test]
    fn transitions_to_nominal_after_warmup() {
        let mut tuner = RedundancyTuner::new();
        for epoch in 0..5 {
            let _ = tuner.observe_epoch(0, epoch);
        }
        assert_eq!(tuner.state(), RedundancyState::Nominal);
    }

    #[test]
    fn sustained_loss_triggers_increase() {
        let mut tuner = RedundancyTuner::new();
        let mut adjustment = None;
        // Feed epochs with high loss (50% = 500_000 ppm).
        for epoch in 0..20 {
            if let Some(entry) = tuner.observe_epoch(500_000, epoch) {
                adjustment = Some(entry);
            }
        }
        assert!(adjustment.is_some(), "should have triggered adjustment");
        let entry = adjustment.unwrap();
        assert_eq!(entry.reason, AdjustReason::LossBudgetExceeded);
        assert!(entry.new_overhead_ppm > entry.prev_overhead_ppm);
        assert_eq!(tuner.state(), RedundancyState::Critical);
    }

    #[test]
    fn no_loss_stays_nominal() {
        let mut tuner = RedundancyTuner::new();
        for epoch in 0..100 {
            let entry = tuner.observe_epoch(0, epoch);
            // May decrease after cooldown but state stays Nominal.
            if let Some(e) = entry {
                assert_eq!(e.reason, AdjustReason::SustainedLowLoss);
            }
        }
        assert_eq!(tuner.state(), RedundancyState::Nominal);
    }

    #[test]
    fn overhead_bounded_by_max() {
        let mut tuner = RedundancyTuner::new();
        // Spam high loss to trigger many increases.
        for epoch in 0..500 {
            let _ = tuner.observe_epoch(500_000, epoch);
        }
        assert!(tuner.overhead_ppm() <= 500_000);
    }

    #[test]
    fn overhead_bounded_by_min() {
        let mut tuner = RedundancyTuner::new();
        // First warm up.
        for epoch in 0..5 {
            let _ = tuner.observe_epoch(0, epoch);
        }
        // Then many no-loss epochs to trigger decreases.
        for epoch in 5..500 {
            let _ = tuner.observe_epoch(0, epoch);
        }
        assert!(tuner.overhead_ppm() >= 20_000);
    }

    #[test]
    fn ledger_entries_recorded() {
        let mut tuner = RedundancyTuner::new();
        for epoch in 0..20 {
            let _ = tuner.observe_epoch(500_000, epoch);
        }
        assert!(tuner.adjustments > 0);
        let entry = tuner.last_ledger_entry();
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().reason, AdjustReason::LossBudgetExceeded);
    }

    #[test]
    fn deterministic_same_inputs() {
        let mut t1 = RedundancyTuner::new();
        let mut t2 = RedundancyTuner::new();
        let losses = [0u32, 0, 50_000, 0, 100_000, 0, 200_000, 0, 0, 0, 500_000, 0];
        for (epoch, &loss) in losses.iter().enumerate() {
            let _ = t1.observe_epoch(loss, epoch as u64);
            let _ = t2.observe_epoch(loss, epoch as u64);
        }
        let s1 = t1.summary();
        let s2 = t2.summary();
        assert_eq!(s1.overhead_ppm, s2.overhead_ppm);
        assert_eq!(s1.loss_rate_ppm, s2.loss_rate_ppm);
        assert_eq!(s1.state, s2.state);
        assert_eq!(s1.log_e_scaled, s2.log_e_scaled);
    }

    #[test]
    fn summary_fields_populated() {
        let mut tuner = RedundancyTuner::new();
        for epoch in 0..10 {
            let _ = tuner.observe_epoch(0, epoch);
        }
        let s = tuner.summary();
        assert_eq!(s.epochs_observed, 10);
        assert_eq!(s.state, RedundancyState::Nominal as u8);
        assert_eq!(s.overhead_ppm, 100_000);
    }

    #[test]
    fn recovery_from_critical_after_loss_stops() {
        let mut tuner = RedundancyTuner::new();
        // Drive into critical.
        for epoch in 0..20 {
            let _ = tuner.observe_epoch(500_000, epoch);
        }
        assert_eq!(tuner.state(), RedundancyState::Critical);
        // Feed many no-loss epochs: e-process decays, state should improve.
        for epoch in 20..500 {
            let _ = tuner.observe_epoch(0, epoch);
        }
        assert_ne!(tuner.state(), RedundancyState::Critical);
    }
}
