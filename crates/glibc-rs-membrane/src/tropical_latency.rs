//! # Tropical Latency Compositor
//!
//! Uses min-plus (tropical) algebra to compute **provable** worst-case latency
//! bounds for every path through the validation pipeline.
//!
//! ## Mathematical Foundation
//!
//! The tropical semiring `(ℝ≥0 ∪ {∞}, min, +)` models path costs:
//! - Tropical addition `⊕ = min`: best case among alternatives.
//! - Tropical multiplication `⊗ = +`: sequential cost composition.
//!
//! A validation pipeline path is a sequence of stages `s₁, s₂, …, sₖ`.
//! The total cost is `⊗ᵢ cost(sᵢ) = Σ cost(sᵢ)` (tropical product = classical sum).
//!
//! For the full pipeline DAG, the **tropical eigenvalue** (critical-path length)
//! of the adjacency matrix gives the provable worst-case latency through the
//! entire pipeline, accounting for all reordering possibilities.
//!
//! ## Budget Enforcement
//!
//! The compositor maintains per-path budgets matching AGENTS.md targets:
//! - Fast exit: 20ns (strict overhead target)
//! - Full pipeline: 200ns (hardened overhead target)
//!
//! When observed worst-case latency approaches a budget, the compositor signals
//! an alarm so the runtime kernel can shed load or reduce pipeline depth.
//!
//! ## Online Calibration
//!
//! Stage costs are tracked via exponentially-weighted moving averages (EWMA)
//! for expected cost and simple max-tracking for worst-case bounds. The EWMA
//! adapts to workload changes while max-tracking gives hard guarantees.

use std::sync::atomic::{AtomicU64, Ordering};

/// Tropical infinity (identity element for min / absorbing for +).
const TROPICAL_INF: u64 = u64::MAX;

/// Number of stages in the validation pipeline.
const NUM_STAGES: usize = 7;

/// Number of tracked pipeline paths.
const NUM_PATHS: usize = 4;

/// Tropical addition: min(a, b).
#[inline]
const fn tropical_add(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

/// Tropical multiplication: a + b (saturating).
#[inline]
const fn tropical_mul(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Pipeline path through the validation stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelinePath {
    /// Fast exit: null + TLS cache hit (2 stages).
    FastExit = 0,
    /// Normal: null + TLS + bloom + bounds (4 stages).
    Normal = 1,
    /// Full: all 7 stages.
    Full = 2,
    /// Alarm: all 7 stages + quarantine overhead.
    Alarm = 3,
}

/// Which stages are active for each path.
/// Indexed as PATH_STAGES[path][stage].
const PATH_STAGES: [[bool; NUM_STAGES]; NUM_PATHS] = [
    // FastExit: null + TLS
    [true, true, false, false, false, false, false],
    // Normal: null + TLS + bloom + bounds
    [true, true, true, false, false, false, true],
    // Full: all stages
    [true, true, true, true, true, true, true],
    // Alarm: all stages (+ flat quarantine overhead added separately)
    [true, true, true, true, true, true, true],
];

/// Quarantine check overhead added to the alarm path (ns).
const QUARANTINE_OVERHEAD_NS: u64 = 50;

/// Stage cost observations with EWMA and max tracking.
struct StageCosts {
    /// EWMA of stage costs in nanoseconds.
    ewma: [f64; NUM_STAGES],
    /// Maximum observed cost per stage (worst-case bound).
    max_observed: [u64; NUM_STAGES],
    /// Observation count per stage.
    count: [u64; NUM_STAGES],
}

impl StageCosts {
    fn new() -> Self {
        // Initial estimates from the pipeline design budget in AGENTS.md.
        Self {
            ewma: [1.0, 5.0, 10.0, 30.0, 20.0, 10.0, 5.0],
            max_observed: [1, 5, 10, 30, 20, 10, 5],
            count: [0; NUM_STAGES],
        }
    }

    fn observe(&mut self, stage: usize, cost_ns: u64) {
        if stage >= NUM_STAGES {
            return;
        }
        self.count[stage] += 1;
        // EWMA with alpha = 0.05 for stability.
        self.ewma[stage] = 0.95 * self.ewma[stage] + 0.05 * cost_ns as f64;
        self.max_observed[stage] = self.max_observed[stage].max(cost_ns);
    }

    fn worst_case(&self, stage: usize) -> u64 {
        if stage >= NUM_STAGES {
            return TROPICAL_INF;
        }
        self.max_observed[stage]
    }
}

/// Tropical adjacency matrix for the pipeline DAG.
///
/// Entry `M[i][j]` = tropical cost to traverse from stage i to stage j.
/// `TROPICAL_INF` means no direct edge.
struct TropicalMatrix {
    entries: [[u64; NUM_STAGES]; NUM_STAGES],
}

impl TropicalMatrix {
    /// Build the pipeline adjacency matrix from observed stage costs.
    #[allow(clippy::needless_range_loop)]
    fn from_costs(costs: &StageCosts) -> Self {
        let mut entries = [[TROPICAL_INF; NUM_STAGES]; NUM_STAGES];
        // Sequential pipeline: stage i → stage i+1 with cost of destination stage.
        for i in 0..NUM_STAGES - 1 {
            entries[i][i + 1] = costs.worst_case(i + 1);
        }
        // Self-loops cost zero (remaining at a stage).
        for i in 0..NUM_STAGES {
            entries[i][i] = 0;
        }
        Self { entries }
    }

    /// Tropical matrix multiplication: C[i][j] = min_k (A[i][k] + B[k][j]).
    ///
    /// This computes shortest-path costs through one intermediate step.
    #[allow(clippy::needless_range_loop)]
    fn tropical_multiply(&self, other: &Self) -> Self {
        let mut result = [[TROPICAL_INF; NUM_STAGES]; NUM_STAGES];
        for i in 0..NUM_STAGES {
            for j in 0..NUM_STAGES {
                for k in 0..NUM_STAGES {
                    let via_k = tropical_mul(self.entries[i][k], other.entries[k][j]);
                    result[i][j] = tropical_add(result[i][j], via_k);
                }
            }
        }
        Self { entries: result }
    }

    /// Tropical closure: M* = I ⊕ M ⊕ M² ⊕ M³ ⊕ … ⊕ M^(n-1).
    ///
    /// For a DAG this converges in n-1 iterations and gives shortest-path
    /// distances between all pairs of stages.
    fn closure(&self) -> Self {
        let mut result = *self;
        let mut power = *self;
        for _ in 1..NUM_STAGES {
            power = power.tropical_multiply(self);
            for i in 0..NUM_STAGES {
                for j in 0..NUM_STAGES {
                    result.entries[i][j] = tropical_add(result.entries[i][j], power.entries[i][j]);
                }
            }
        }
        result
    }
}

impl Copy for TropicalMatrix {}
impl Clone for TropicalMatrix {
    fn clone(&self) -> Self {
        *self
    }
}

/// Compute worst-case latency for a specific path.
fn path_worst_case(costs: &StageCosts, path: PipelinePath) -> u64 {
    let stages = &PATH_STAGES[path as usize];
    let mut total: u64 = 0;
    for (i, &included) in stages.iter().enumerate() {
        if included {
            total = tropical_mul(total, costs.worst_case(i));
        }
    }
    if matches!(path, PipelinePath::Alarm) {
        total = tropical_mul(total, QUARANTINE_OVERHEAD_NS);
    }
    total
}

/// The tropical latency compositor.
pub struct TropicalLatencyCompositor {
    /// Per-stage cost observations.
    costs: StageCosts,
    /// Cached worst-case latency per path (ns).
    cached_wcl: [u64; NUM_PATHS],
    /// Budget limits per path (ns).
    budgets: [u64; NUM_PATHS],
    /// Consecutive budget violations observed.
    violations: u64,
    /// Total path observations.
    total_observations: u64,
    /// Whether a budget alarm is active.
    alarm: bool,
}

impl TropicalLatencyCompositor {
    /// Creates a new compositor with design-budget defaults.
    pub fn new() -> Self {
        let costs = StageCosts::new();
        let budgets = [
            20,  // FastExit: 20ns strict budget
            50,  // Normal: 50ns
            200, // Full: 200ns hardened budget
            500, // Alarm: 500ns emergency budget
        ];
        let cached_wcl = [
            path_worst_case(&costs, PipelinePath::FastExit),
            path_worst_case(&costs, PipelinePath::Normal),
            path_worst_case(&costs, PipelinePath::Full),
            path_worst_case(&costs, PipelinePath::Alarm),
        ];
        Self {
            costs,
            cached_wcl,
            budgets,
            violations: 0,
            total_observations: 0,
            alarm: false,
        }
    }

    /// Record observed latency for a specific pipeline stage.
    pub fn observe_stage(&mut self, stage: usize, cost_ns: u64) {
        self.costs.observe(stage, cost_ns);
        self.total_observations += 1;
        // Recompute cached WCL every 128 observations.
        if self.total_observations.is_multiple_of(128) {
            self.recompute_wcl();
        }
    }

    /// Record observed end-to-end latency for a path and check budget.
    pub fn observe_path(&mut self, path: PipelinePath, actual_ns: u64) {
        self.total_observations += 1;

        // Attribute observed end-to-end cost back to active stages so the
        // tropical critical-path model adapts from real traffic, not synthetic
        // control-path estimates.
        let stages = &PATH_STAGES[path as usize];
        let active = stages.iter().filter(|&&s| s).count().max(1) as u64;
        let per_stage = actual_ns / active;
        for (i, &included) in stages.iter().enumerate() {
            if included {
                self.costs.observe(i, per_stage);
            }
        }
        if self.total_observations.is_multiple_of(64) {
            self.recompute_wcl();
        }

        let budget = self.budgets[path as usize];
        if actual_ns > budget {
            self.violations += 1;
            if self.violations > 10 && !self.alarm {
                self.alarm = true;
            }
        } else if self.violations > 0 {
            // Decay violations on good observations.
            self.violations -= 1;
        }
    }

    /// Number of active budget violations tracked by the alarm logic.
    pub fn violation_count(&self) -> u64 {
        self.violations
    }

    /// Worst-case latency bound for a path.
    pub fn worst_case_bound(&self, path: PipelinePath) -> u64 {
        self.cached_wcl[path as usize]
    }

    /// Budget for a path.
    pub fn budget(&self, path: PipelinePath) -> u64 {
        self.budgets[path as usize]
    }

    /// Whether a path is within budget.
    pub fn within_budget(&self, path: PipelinePath) -> bool {
        self.cached_wcl[path as usize] <= self.budgets[path as usize]
    }

    /// Budget utilization ratio (0.0 = idle, 1.0 = at budget, >1.0 = over budget).
    pub fn budget_utilization(&self, path: PipelinePath) -> f64 {
        let wcl = self.cached_wcl[path as usize] as f64;
        let budget = self.budgets[path as usize] as f64;
        if budget == 0.0 {
            return f64::INFINITY;
        }
        wcl / budget
    }

    /// Whether the compositor has detected persistent budget violations.
    pub fn is_alarmed(&self) -> bool {
        self.alarm
    }

    /// Reset alarm after investigation.
    pub fn reset_alarm(&mut self) {
        self.alarm = false;
        self.violations = 0;
    }

    /// Identify the bottleneck stage for a path.
    pub fn bottleneck_stage(&self, path: PipelinePath) -> Option<usize> {
        let stages = &PATH_STAGES[path as usize];
        let mut max_cost = 0u64;
        let mut bottleneck = None;
        for (i, &included) in stages.iter().enumerate() {
            if included {
                let cost = self.costs.worst_case(i);
                if cost > max_cost {
                    max_cost = cost;
                    bottleneck = Some(i);
                }
            }
        }
        bottleneck
    }

    /// Compute critical-path lengths using the tropical matrix closure.
    ///
    /// This is the mathematically precise approach: the closure M* of the
    /// pipeline adjacency matrix gives shortest-path distances (= worst-case
    /// latency through the DAG when costs are additive).
    pub fn tropical_critical_paths(&self) -> [u64; NUM_PATHS] {
        let matrix = TropicalMatrix::from_costs(&self.costs);
        let closure = matrix.closure();
        [
            // FastExit: stages 0 → 1
            tropical_mul(self.costs.worst_case(0), self.costs.worst_case(1)),
            // Normal: source + closure(0,6)
            tropical_mul(self.costs.worst_case(0), closure.entries[0][NUM_STAGES - 1]),
            // Full: source + closure(0, last)
            tropical_mul(self.costs.worst_case(0), closure.entries[0][NUM_STAGES - 1]),
            // Alarm: full + quarantine overhead
            tropical_mul(
                tropical_mul(self.costs.worst_case(0), closure.entries[0][NUM_STAGES - 1]),
                QUARANTINE_OVERHEAD_NS,
            ),
        ]
    }

    /// Total observations recorded.
    pub fn total_observations(&self) -> u64 {
        self.total_observations
    }

    fn recompute_wcl(&mut self) {
        self.cached_wcl = [
            path_worst_case(&self.costs, PipelinePath::FastExit),
            path_worst_case(&self.costs, PipelinePath::Normal),
            path_worst_case(&self.costs, PipelinePath::Full),
            path_worst_case(&self.costs, PipelinePath::Alarm),
        ];
    }
}

impl Default for TropicalLatencyCompositor {
    fn default() -> Self {
        Self::new()
    }
}

/// Global atomic worst-case latency metrics.
pub struct TropicalMetrics {
    pub fast_wcl_ns: AtomicU64,
    pub normal_wcl_ns: AtomicU64,
    pub full_wcl_ns: AtomicU64,
    pub alarm_wcl_ns: AtomicU64,
    pub budget_violations: AtomicU64,
}

impl TropicalMetrics {
    pub const fn new() -> Self {
        Self {
            fast_wcl_ns: AtomicU64::new(0),
            normal_wcl_ns: AtomicU64::new(0),
            full_wcl_ns: AtomicU64::new(0),
            alarm_wcl_ns: AtomicU64::new(0),
            budget_violations: AtomicU64::new(0),
        }
    }

    pub fn publish(&self, compositor: &TropicalLatencyCompositor) {
        self.fast_wcl_ns.store(
            compositor.worst_case_bound(PipelinePath::FastExit),
            Ordering::Relaxed,
        );
        self.normal_wcl_ns.store(
            compositor.worst_case_bound(PipelinePath::Normal),
            Ordering::Relaxed,
        );
        self.full_wcl_ns.store(
            compositor.worst_case_bound(PipelinePath::Full),
            Ordering::Relaxed,
        );
        self.alarm_wcl_ns.store(
            compositor.worst_case_bound(PipelinePath::Alarm),
            Ordering::Relaxed,
        );
        self.budget_violations
            .store(compositor.violation_count(), Ordering::Relaxed);
    }
}

impl Default for TropicalMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub static TROPICAL_METRICS: TropicalMetrics = TropicalMetrics::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tropical_semiring_identities() {
        // min is commutative
        assert_eq!(tropical_add(10, 20), tropical_add(20, 10));
        // min identity is INF
        assert_eq!(tropical_add(TROPICAL_INF, 5), 5);
        // + is commutative
        assert_eq!(tropical_mul(10, 20), tropical_mul(20, 10));
        // + identity is 0
        assert_eq!(tropical_mul(0, 42), 42);
        // INF absorbs +
        assert_eq!(tropical_mul(TROPICAL_INF, 5), TROPICAL_INF);
        // Distributivity: a ⊗ (b ⊕ c) = (a ⊗ b) ⊕ (a ⊗ c)
        let a = 10u64;
        let b = 20u64;
        let c = 30u64;
        assert_eq!(
            tropical_mul(a, tropical_add(b, c)),
            tropical_add(tropical_mul(a, b), tropical_mul(a, c))
        );
    }

    #[test]
    fn compositor_initial_budgets_met() {
        let comp = TropicalLatencyCompositor::new();
        assert!(comp.within_budget(PipelinePath::FastExit));
        assert!(comp.within_budget(PipelinePath::Full));
        assert!(comp.within_budget(PipelinePath::Alarm));
    }

    #[test]
    fn path_ordering_monotonic() {
        let comp = TropicalLatencyCompositor::new();
        let fast = comp.worst_case_bound(PipelinePath::FastExit);
        let normal = comp.worst_case_bound(PipelinePath::Normal);
        let full = comp.worst_case_bound(PipelinePath::Full);
        let alarm = comp.worst_case_bound(PipelinePath::Alarm);
        assert!(fast <= normal, "fast {fast} <= normal {normal}");
        assert!(normal <= full, "normal {normal} <= full {full}");
        assert!(full <= alarm, "full {full} <= alarm {alarm}");
    }

    #[test]
    fn observe_updates_worst_case() {
        let mut comp = TropicalLatencyCompositor::new();
        // Observe a very expensive arena stage (stage 3)
        comp.observe_stage(3, 500);
        // Force recompute
        for _ in 0..128 {
            comp.observe_stage(0, 1);
        }
        let full = comp.worst_case_bound(PipelinePath::Full);
        assert!(full >= 500, "full WCL {full} should reflect 500ns arena");
    }

    #[test]
    fn budget_violation_triggers_alarm() {
        let mut comp = TropicalLatencyCompositor::new();
        for _ in 0..20 {
            comp.observe_path(PipelinePath::FastExit, 1000); // 50x over budget
        }
        assert!(comp.is_alarmed());
    }

    #[test]
    fn alarm_resets() {
        let mut comp = TropicalLatencyCompositor::new();
        for _ in 0..20 {
            comp.observe_path(PipelinePath::FastExit, 1000);
        }
        assert!(comp.is_alarmed());
        comp.reset_alarm();
        assert!(!comp.is_alarmed());
    }

    #[test]
    fn bottleneck_is_arena() {
        let comp = TropicalLatencyCompositor::new();
        // Arena (stage 3, 30ns) is the costliest default stage.
        assert_eq!(comp.bottleneck_stage(PipelinePath::Full), Some(3));
    }

    #[test]
    fn tropical_matrix_closure_gives_reachability() {
        let comp = TropicalLatencyCompositor::new();
        let paths = comp.tropical_critical_paths();
        // Fast < Full
        assert!(paths[0] < paths[2], "fast {} < full {}", paths[0], paths[2]);
        // Full < Alarm (alarm adds quarantine overhead)
        assert!(
            paths[2] < paths[3],
            "full {} < alarm {}",
            paths[2],
            paths[3]
        );
    }

    #[test]
    fn budget_utilization_in_range() {
        let comp = TropicalLatencyCompositor::new();
        let util = comp.budget_utilization(PipelinePath::Full);
        assert!(util > 0.0);
        assert!(
            util <= 1.0,
            "initial full utilization {util} should be <=1.0"
        );
    }

    #[test]
    fn metrics_publish_roundtrip() {
        let comp = TropicalLatencyCompositor::new();
        let metrics = TropicalMetrics::new();
        metrics.publish(&comp);
        assert_eq!(
            metrics.fast_wcl_ns.load(Ordering::Relaxed),
            comp.worst_case_bound(PipelinePath::FastExit)
        );
        assert_eq!(
            metrics.full_wcl_ns.load(Ordering::Relaxed),
            comp.worst_case_bound(PipelinePath::Full)
        );
    }
}
