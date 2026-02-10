//! # Submodular Validation Stage Coverage Monitor
//!
//! Selects the budget-optimal subset of validation stages via greedy
//! submodular maximization (Nemhauser, Wolsey, Fisher 1978), guaranteeing
//! at least (1 - 1/e) ~ 63.2% of optimal failure-mode coverage.
//!
//! ## Mathematical Foundation
//!
//! A set function f: 2^V -> R is **submodular** if for all A <= B <= V and
//! x not in B:
//!
//! ```text
//! f(A U {x}) - f(A) >= f(B U {x}) - f(B)
//! ```
//!
//! (diminishing marginal returns).
//!
//! For a monotone submodular function with cardinality constraint |S| <= k:
//!
//! ```text
//! max_{|S| <= k} f(S)
//! ```
//!
//! the greedy algorithm (pick element with max marginal gain at each step)
//! achieves:
//!
//! ```text
//! f(S_greedy) >= (1 - 1/e) * f(S_opt) ~ 0.632 * f(S_opt)
//! ```
//!
//! ## Application to Validation
//!
//! Each validation stage s covers a set of failure modes. The coverage
//! function:
//!
//! ```text
//! f(S) = |Union_{s in S} Coverage(s)|
//! ```
//!
//! is monotone submodular (union of sets). Under a budget constraint
//! (k stages max), greedy selection provably achieves >= 63.2% of optimal
//! coverage.
//!
//! ## Why Submodular Coverage?
//!
//! Existing controllers decide WHAT to do (validate/repair/deny) and HOW
//! MUCH to check. This controller decides WHICH stages to prioritize when
//! the budget is limited. It answers: "Given I can only run k of the
//! available validation stages, which k gives the best coverage?"
//!
//! ## Coverage Model
//!
//! Each of the 8 validation stages (bloom, arena, fingerprint, canary,
//! bounds, TLS, page_oracle, full) has affinity weights for the K=4
//! severity levels. The base affinity matrix is offline-derived:
//!
//! ```text
//! Rows: stages, Cols: severity levels (0=ok, 1=mild, 2=moderate, 3=severe)
//! bloom:        [0.8, 0.5, 0.3, 0.1] -- best at detecting valid pointers
//! arena:        [0.2, 0.6, 0.7, 0.9] -- best at moderate/severe
//! fingerprint:  [0.1, 0.3, 0.8, 0.9] -- best at moderate/severe
//! canary:       [0.1, 0.2, 0.6, 0.95]-- best at severe (overflow)
//! bounds:       [0.3, 0.7, 0.8, 0.6] -- good at mild/moderate
//! TLS:          [0.9, 0.4, 0.2, 0.1] -- fast-path caching
//! page_oracle:  [0.5, 0.5, 0.5, 0.5] -- uniform
//! full:         [0.1, 0.1, 0.2, 0.3] -- catches everything but expensive
//! ```
//!
//! Weights are modulated online by observed severity frequency via EWMA.
//! The greedy algorithm selects stages maximizing weighted set coverage.
//!
//! ## Greedy Algorithm
//!
//! 1. Compute severity distribution from observed severity vector.
//! 2. For each stage, compute weighted coverage: sum_j affinity[stage][j] * freq[j].
//! 3. Greedily select stages accounting for diminishing returns via set
//!    coverage semantics (each severity level's residual weight is reduced
//!    by the max coverage already selected).
//! 4. Coverage ratio = selected_coverage / total_possible_coverage.
//!
//! ## Legacy Anchor
//!
//! `elf`, `dl-*`, symbol/IFUNC (loader subsystem) -- dynamic linking
//! validation involves multiple independent checks (symbol version,
//! relocation type, section permissions, IFUNC dispatch). Under
//! strict-mode latency budgets, not all checks can run. Submodular
//! coverage selects the subset maximizing failure-mode coverage.

/// Number of base controllers.
const N: usize = 25;

/// Number of discrete severity levels.
const K: usize = 4;

/// Number of validation stages.
const STAGES: usize = 8;

/// EWMA smoothing factor for severity frequency estimation.
const ALPHA: f64 = 0.03;

/// Warmup observations before state classification activates.
const WARMUP: u32 = 40;

/// Coverage ratio below which state is Marginal.
const MARGINAL_THRESHOLD: f64 = 0.50;

/// Coverage ratio below which state is Insufficient.
const INSUFFICIENT_THRESHOLD: f64 = 0.30;

/// Base affinity matrix: offline-derived detection probability per stage per severity.
///
/// Rows: validation stages (bloom, arena, fingerprint, canary, bounds, TLS, page_oracle, full).
/// Cols: severity levels (0=ok, 1=mild, 2=moderate, 3=severe).
const BASE_AFFINITY: [[f64; K]; STAGES] = [
    [0.8, 0.5, 0.3, 0.1],  // bloom: best at detecting valid pointers
    [0.2, 0.6, 0.7, 0.9],  // arena: best at moderate/severe
    [0.1, 0.3, 0.8, 0.9],  // fingerprint: best at moderate/severe
    [0.1, 0.2, 0.6, 0.95], // canary: best at severe (overflow)
    [0.3, 0.7, 0.8, 0.6],  // bounds: good at mild/moderate
    [0.9, 0.4, 0.2, 0.1],  // TLS: fast-path caching
    [0.5, 0.5, 0.5, 0.5],  // page_oracle: uniform
    [0.1, 0.1, 0.2, 0.3],  // full: catches everything but expensive
];

/// Controller states for the submodular coverage monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SubmodularState {
    /// Insufficient data for classification.
    Calibrating = 0,
    /// Greedy coverage ratio is above the marginal threshold.
    Sufficient = 1,
    /// Coverage is mediocre (between insufficient and marginal thresholds).
    Marginal = 2,
    /// Coverage is critically low.
    Insufficient = 3,
}

/// Summary snapshot for telemetry and kernel snapshot reporting.
#[derive(Debug, Clone, Copy)]
pub struct SubmodularSummary {
    /// Current state.
    pub state: SubmodularState,
    /// Greedy coverage / total coverage (0..1).
    pub coverage_ratio: f64,
    /// Number of stages selected by the budget.
    pub selected_stages: u8,
    /// Total observations.
    pub observations: u32,
}

/// Submodular validation stage coverage monitor.
///
/// Maintains an online model of stage-severity detection affinity and uses
/// greedy submodular maximization to select the budget-optimal subset of
/// validation stages.
pub struct SubmodularCoverageMonitor {
    /// Per-stage per-severity detection weights, EWMA-smoothed.
    stage_weights: [[f64; K]; STAGES],
    /// Maximum number of stages that can run within the latency budget.
    budget: usize,
    /// Smoothed greedy coverage ratio (0..1).
    coverage_ratio: f64,
    /// EWMA-smoothed severity frequency distribution.
    severity_freq: [f64; K],
    /// Number of stages actually selected by the last greedy run.
    last_selected_count: u8,
    /// Observation count.
    count: u32,
    /// Current state.
    state: SubmodularState,
}

impl SubmodularCoverageMonitor {
    /// Create a new monitor with uniform initialization.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stage_weights: BASE_AFFINITY,
            budget: 4,
            coverage_ratio: 0.0,
            severity_freq: [0.25; K],
            last_selected_count: 0,
            count: 0,
            state: SubmodularState::Calibrating,
        }
    }

    /// Feed a severity vector and recompute greedy coverage.
    ///
    /// Uses the severity vector to estimate the frequency distribution of
    /// severity levels, modulates stage weights accordingly, then runs the
    /// greedy submodular maximization to select the best `budget` stages.
    #[allow(clippy::needless_range_loop)]
    pub fn observe_and_update(&mut self, severity: &[u8; N]) {
        self.count = self.count.saturating_add(1);
        let alpha = if self.count <= WARMUP {
            2.0 / (self.count as f64 + 1.0)
        } else {
            ALPHA
        };

        // Compute observed severity frequency from the current vector.
        let mut observed_freq = [0.0_f64; K];
        for &s in severity.iter() {
            let level = (s as usize).min(K - 1);
            observed_freq[level] += 1.0;
        }
        // Normalize.
        let total = N as f64;
        for f in &mut observed_freq {
            *f /= total;
        }

        // EWMA update of severity frequency distribution.
        for j in 0..K {
            self.severity_freq[j] += alpha * (observed_freq[j] - self.severity_freq[j]);
        }

        // Modulate stage weights: blend base affinity with observed frequency.
        // Higher observed frequency for a severity level increases the
        // effective weight of stages that detect that level.
        for stage in 0..STAGES {
            for j in 0..K {
                let modulated = BASE_AFFINITY[stage][j] * (0.5 + self.severity_freq[j]);
                self.stage_weights[stage][j] += alpha * (modulated - self.stage_weights[stage][j]);
            }
        }

        // Run greedy submodular maximization.
        let (ratio, sel_count) = self.greedy_coverage();
        self.coverage_ratio += alpha * (ratio - self.coverage_ratio);
        self.last_selected_count = sel_count;

        // State classification.
        self.state = if self.count < WARMUP {
            SubmodularState::Calibrating
        } else if self.coverage_ratio < INSUFFICIENT_THRESHOLD {
            SubmodularState::Insufficient
        } else if self.coverage_ratio < MARGINAL_THRESHOLD {
            SubmodularState::Marginal
        } else {
            SubmodularState::Sufficient
        };
    }

    /// Greedy submodular maximization for weighted set coverage.
    ///
    /// Returns (coverage_ratio, selected_count) where coverage_ratio =
    /// selected_coverage / total_possible_coverage.
    ///
    /// The coverage model treats each severity level j as a "failure mode"
    /// with weight freq[j]. Each stage covers level j with effectiveness
    /// stage_weights[stage][j]. The coverage of a set S of stages for level
    /// j is: 1 - product_{s in S} (1 - w[s][j]), i.e., probability that at
    /// least one selected stage detects level j.
    ///
    /// Total weighted coverage:
    ///   f(S) = sum_j freq[j] * (1 - product_{s in S} (1 - w[s][j]))
    ///
    /// This is monotone submodular because each term is a weighted coverage
    /// function (composition of affine and product).
    #[allow(clippy::needless_range_loop)]
    fn greedy_coverage(&self) -> (f64, u8) {
        // Total possible coverage: selecting ALL stages.
        let total_coverage = self.compute_coverage_all();

        if total_coverage < 1e-12 {
            return (0.0, 0);
        }

        // Greedy stage selection.
        let mut selected = [false; STAGES];
        let mut selected_count = 0_usize;
        // Residual miss probability per severity level.
        let mut miss_prob = [1.0_f64; K];

        while selected_count < self.budget.min(STAGES) {
            let mut best_stage = 0_usize;
            let mut best_gain = -1.0_f64;

            for stage in 0..STAGES {
                if selected[stage] {
                    continue;
                }
                // Marginal gain of adding this stage.
                let mut gain = 0.0_f64;
                for j in 0..K {
                    let w = self.stage_weights[stage][j].clamp(0.0, 1.0);
                    // Current miss for level j: miss_prob[j]
                    // New miss if we add this stage: miss_prob[j] * (1 - w)
                    // Marginal gain: freq[j] * miss_prob[j] * w
                    gain += self.severity_freq[j] * miss_prob[j] * w;
                }

                if gain > best_gain {
                    best_gain = gain;
                    best_stage = stage;
                }
            }

            if best_gain <= 0.0 {
                break;
            }

            // Select the best stage and update miss probabilities.
            selected[best_stage] = true;
            selected_count += 1;
            for j in 0..K {
                let w = self.stage_weights[best_stage][j].clamp(0.0, 1.0);
                miss_prob[j] *= 1.0 - w;
            }
        }

        // Compute selected coverage.
        let mut selected_coverage = 0.0_f64;
        for j in 0..K {
            selected_coverage += self.severity_freq[j] * (1.0 - miss_prob[j]);
        }

        let ratio = (selected_coverage / total_coverage).clamp(0.0, 1.0);
        (ratio, selected_count as u8)
    }

    /// Compute total possible coverage when all stages are selected.
    #[allow(clippy::needless_range_loop)]
    fn compute_coverage_all(&self) -> f64 {
        let mut total = 0.0_f64;
        for j in 0..K {
            let mut miss = 1.0_f64;
            for stage in 0..STAGES {
                let w = self.stage_weights[stage][j].clamp(0.0, 1.0);
                miss *= 1.0 - w;
            }
            total += self.severity_freq[j] * (1.0 - miss);
        }
        total
    }

    /// Current state.
    pub fn state(&self) -> SubmodularState {
        self.state
    }

    /// Current smoothed coverage ratio.
    pub fn coverage_ratio(&self) -> f64 {
        self.coverage_ratio
    }

    /// Current stage budget.
    pub fn budget(&self) -> usize {
        self.budget
    }

    /// Summary snapshot for telemetry.
    pub fn summary(&self) -> SubmodularSummary {
        SubmodularSummary {
            state: self.state,
            coverage_ratio: self.coverage_ratio,
            selected_stages: self.last_selected_count,
            observations: self.count,
        }
    }
}

impl Default for SubmodularCoverageMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let m = SubmodularCoverageMonitor::new();
        assert_eq!(m.state(), SubmodularState::Calibrating);
        assert_eq!(m.count, 0);
    }

    #[test]
    fn uniform_severity_gives_decent_coverage() {
        let mut m = SubmodularCoverageMonitor::new();
        // Feed uniform severity distribution (each controller gets level i%4).
        for i in 0u32..200 {
            let mut sev = [0u8; N];
            for (c, s) in sev.iter_mut().enumerate() {
                *s = ((c + i as usize) % K) as u8;
            }
            m.observe_and_update(&sev);
        }
        // With budget=4 out of 8 stages and uniform severity, the greedy
        // algorithm should achieve reasonable coverage (well above insufficient).
        assert_ne!(m.state(), SubmodularState::Calibrating);
        assert!(
            m.coverage_ratio() > INSUFFICIENT_THRESHOLD,
            "Uniform severity should have decent coverage: ratio={}",
            m.coverage_ratio()
        );
    }

    #[test]
    fn high_severity_coverage() {
        let mut m = SubmodularCoverageMonitor::new();
        // Concentrated severe inputs: all controllers report level 3.
        for _ in 0..200 {
            m.observe_and_update(&[3u8; N]);
        }
        // Stages like canary (0.95), arena (0.9), fingerprint (0.9) excel at
        // severe detection. Coverage should still be decent.
        assert_ne!(m.state(), SubmodularState::Calibrating);
        assert!(
            m.coverage_ratio() > INSUFFICIENT_THRESHOLD,
            "High severity should have decent coverage: ratio={}",
            m.coverage_ratio()
        );
    }

    #[test]
    fn coverage_ratio_bounded() {
        let mut m = SubmodularCoverageMonitor::new();
        // Various inputs.
        for i in 0u32..500 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        assert!(
            m.coverage_ratio() >= 0.0 && m.coverage_ratio() <= 1.0,
            "Coverage ratio must be in [0,1]: {}",
            m.coverage_ratio()
        );
    }

    #[test]
    fn more_stages_means_more_coverage() {
        // Monotonicity: increasing budget should not decrease coverage.
        let base_severity: [u8; N] = {
            let mut arr = [0u8; N];
            for (i, s) in arr.iter_mut().enumerate() {
                *s = (i % K) as u8;
            }
            arr
        };

        let mut coverages = Vec::new();
        for budget in 1..=STAGES {
            let mut m = SubmodularCoverageMonitor::new();
            m.budget = budget;
            // Run enough observations for the EWMA to stabilize.
            for _ in 0..300 {
                m.observe_and_update(&base_severity);
            }
            coverages.push(m.coverage_ratio());
        }

        // Each budget level should yield coverage >= previous budget level
        // (within a small tolerance for EWMA smoothing artifacts).
        for i in 1..coverages.len() {
            assert!(
                coverages[i] >= coverages[i - 1] - 0.01,
                "Monotonicity violated: budget={} coverage={}, budget={} coverage={}",
                i,
                coverages[i - 1],
                i + 1,
                coverages[i]
            );
        }
    }

    #[test]
    fn summary_consistent() {
        let mut m = SubmodularCoverageMonitor::new();
        for _ in 0..100 {
            m.observe_and_update(&[1u8; N]);
        }
        let s = m.summary();
        assert_eq!(s.state, m.state());
        assert!((s.coverage_ratio - m.coverage_ratio()).abs() < 1e-12);
        assert_eq!(s.observations, 100);
        // After observations, selected_stages should reflect actual greedy selection.
        assert!(s.selected_stages <= m.budget().min(STAGES) as u8);
    }

    #[test]
    fn full_budget_gives_full_coverage() {
        let mut m = SubmodularCoverageMonitor::new();
        m.budget = STAGES; // All stages available.
        for i in 0u32..300 {
            let val = ((i % 4) as u8).min(3);
            m.observe_and_update(&[val; N]);
        }
        // With all stages selected, coverage ratio should be 1.0 (or very close).
        assert!(
            m.coverage_ratio() > 0.95,
            "Full budget should give near-full coverage: ratio={}",
            m.coverage_ratio()
        );
    }

    #[test]
    fn zero_severity_coverage() {
        let mut m = SubmodularCoverageMonitor::new();
        // All controllers report level 0 (ok).
        for _ in 0..200 {
            m.observe_and_update(&[0u8; N]);
        }
        // Bloom (0.8) and TLS (0.9) are strong at level 0.
        // Coverage should still be reasonable.
        assert!(
            m.coverage_ratio() > INSUFFICIENT_THRESHOLD,
            "Zero severity should have decent coverage: ratio={}",
            m.coverage_ratio()
        );
    }
}
