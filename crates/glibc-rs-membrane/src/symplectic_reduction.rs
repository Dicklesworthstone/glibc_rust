//! # Symplectic Reduction for Resource Lifecycle Admissibility
//!
//! Applies geometric invariant theory and symplectic geometry to guard
//! IPC and resource lifecycle transitions against deadlock and capability drift.
//!
//! ## Mathematical Foundation (Marsden-Weinstein 1974)
//!
//! A **symplectic manifold** (M, ω) is a smooth manifold equipped with a
//! closed, non-degenerate 2-form ω. When a Lie group G acts on M preserving
//! ω (a Hamiltonian action), there exists a **moment map**:
//!
//! ```text
//! μ: M → g*
//! ```
//!
//! where g* is the dual of the Lie algebra of G. The moment map encodes
//! conservation laws (Noether's theorem in symplectic language).
//!
//! The **symplectic quotient** (Marsden-Weinstein reduction) is:
//!
//! ```text
//! M // G = μ⁻¹(0) / G
//! ```
//!
//! This removes symmetry degrees of freedom while preserving the
//! essential phase-space dynamics. States in μ⁻¹(0) satisfy all
//! conservation constraints simultaneously.
//!
//! ## Application to Resource Lifecycle
//!
//! Model the resource state space as a finite-dimensional phase space:
//!
//! ```text
//! M = R^{2N}  where N = number of resource types
//! ```
//!
//! Each resource type has a conjugate pair (q_i, p_i):
//! - q_i = cumulative acquisitions (creation, allocation, attach)
//! - p_i = cumulative releases (destruction, deallocation, detach)
//!
//! The **canonical symplectic form** is:
//!
//! ```text
//! ω = Σ dq_i ∧ dp_i
//! ```
//!
//! The **moment map** encodes conservation laws:
//!
//! ```text
//! μ_i = q_i - p_i = net held resources of type i
//! ```
//!
//! ## Admissibility Polytope
//!
//! The admissible states lie in the polytope:
//!
//! ```text
//! P = { x ∈ M : 0 ≤ μ_i(x) ≤ cap_i  for all i }
//! ```
//!
//! where cap_i is the maximum allowed held resources of type i.
//! States outside P indicate resource leaks (μ_i > cap_i) or
//! impossible states (μ_i < 0, releasing more than acquired).
//!
//! ## Deadlock Detection
//!
//! A **deadlock configuration** occurs when multiple resource types
//! have near-capacity holdings simultaneously, creating circular
//! wait conditions. We detect this via the Hamiltonian energy:
//!
//! ```text
//! H(x) = Σ μ_i(x)² / cap_i²
//! ```
//!
//! When H approaches N (all resources at capacity), deadlock risk
//! is maximal. The symplectic gradient flow of H is:
//!
//! ```text
//! ẋ = X_H = ω⁻¹(dH)
//! ```
//!
//! and conservation of H along this flow gives energy-based
//! deadlock predictions.
//!
//! ## Connection to Math Item #39
//!
//! Geometric invariant theory + symplectic reduction for System V IPC
//! admissibility and deadlock elimination.

/// Number of resource types tracked.
const RESOURCE_TYPES: usize = 4;
/// Maximum resources per type (capacity).
const CAPACITY: [u32; RESOURCE_TYPES] = [64, 32, 16, 256];
/// Near-boundary warning threshold (fraction of capacity).
const BOUNDARY_WARN: f64 = 0.75;
/// Critical threshold (fraction of capacity).
const BOUNDARY_CRIT: f64 = 0.90;
/// Deadlock energy threshold (normalized, in [0, RESOURCE_TYPES]).
const DEADLOCK_ENERGY_WARN: f64 = 2.5;
/// Window size for flow rate estimation.
const FLOW_WINDOW: u64 = 128;
/// Baseline calibration windows.
const SYMPL_BASELINE_WINDOWS: u64 = 4;

// ── Resource type identifiers ───────────────────────────────────

/// Resource types with natural conjugate pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    /// Semaphore (SysV sem* or POSIX sem_*)
    Semaphore = 0,
    /// Shared memory segment (shm* / mmap shared)
    SharedMemory = 1,
    /// Message queue (msgget/msgsnd/msgrcv)
    MessageQueue = 2,
    /// File descriptor (open/socket/pipe)
    FileDescriptor = 3,
}

// ── Symplectic geometry computations ────────────────────────────

/// Phase-space state vector: (q_0, p_0, q_1, p_1, ..., q_{N-1}, p_{N-1}).
type PhaseState = [u64; RESOURCE_TYPES * 2];

/// Moment map: μ_i = q_i - p_i (net held resources per type).
///
/// Returns signed values — negative indicates release exceeded acquisition
/// (an inadmissible state).
fn moment_map(state: &PhaseState) -> [i64; RESOURCE_TYPES] {
    let mut mu = [0i64; RESOURCE_TYPES];
    for (i, mu_v) in mu.iter_mut().enumerate() {
        *mu_v = state[2 * i] as i64 - state[2 * i + 1] as i64;
    }
    mu
}

/// Normalized moment: μ_i / cap_i ∈ [0, 1] for admissible states.
fn normalized_moment(mu: &[i64; RESOURCE_TYPES]) -> [f64; RESOURCE_TYPES] {
    let mut norm = [0.0f64; RESOURCE_TYPES];
    for (i, nv) in norm.iter_mut().enumerate() {
        let cap = CAPACITY[i].max(1) as f64;
        *nv = mu[i] as f64 / cap;
    }
    norm
}

/// Hamiltonian energy: H = Σ (μ_i / cap_i)².
///
/// This is the squared L2 norm of the normalized moment map.
/// H ∈ [0, N] where N = RESOURCE_TYPES.
/// H = 0 means all resources released (vacuum state).
/// H = N means all resource types at capacity (maximum deadlock risk).
fn hamiltonian_energy(mu: &[i64; RESOURCE_TYPES]) -> f64 {
    let norm = normalized_moment(mu);
    norm.iter().map(|&n| n * n).sum()
}

/// Symplectic form evaluation: ω(a, b) = Σ (a_{2i} · b_{2i+1} - a_{2i+1} · b_{2i}).
///
/// For the canonical form ω = Σ dq_i ∧ dp_i on R^{2N}.
/// This computes the signed area of the parallelogram spanned by
/// tangent vectors a and b in phase space.
#[cfg_attr(not(test), allow(dead_code))]
#[cfg(test)]
fn symplectic_form(a: &[f64; RESOURCE_TYPES * 2], b: &[f64; RESOURCE_TYPES * 2]) -> f64 {
    let mut omega = 0.0f64;
    for i in 0..RESOURCE_TYPES {
        omega += a[2 * i] * b[2 * i + 1] - a[2 * i + 1] * b[2 * i];
    }
    omega
}

/// Distance from the admissibility boundary.
///
/// Returns the minimum margin across all resource types.
/// Positive = inside polytope, negative = outside (violation).
fn boundary_distance(mu: &[i64; RESOURCE_TYPES]) -> f64 {
    let mut min_margin = f64::INFINITY;
    for (i, &mu_i) in mu.iter().enumerate() {
        let cap = CAPACITY[i] as f64;
        // Distance from lower bound (μ_i ≥ 0)
        let lower = mu_i as f64;
        // Distance from upper bound (μ_i ≤ cap)
        let upper = cap - mu_i as f64;
        let margin = lower.min(upper) / cap.max(1.0);
        min_margin = min_margin.min(margin);
    }
    min_margin
}

// ── Public types ────────────────────────────────────────────────

/// Symplectic admissibility state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymplecticState {
    /// Baseline not yet established.
    Calibrating,
    /// State well inside admissibility polytope.
    Admissible,
    /// State approaching admissibility boundary.
    NearBoundary,
    /// State at or beyond admissibility boundary (violation).
    Inadmissible,
}

/// Telemetry snapshot for the symplectic monitor.
pub struct SymplecticSummary {
    pub state: SymplecticState,
    pub hamiltonian_energy: f64,
    pub boundary_distance: f64,
    pub moment_map: [i64; RESOURCE_TYPES],
    pub violation_count: u64,
}

/// Symplectic reduction resource-lifecycle controller.
///
/// Tracks resource acquisitions and releases as phase-space evolution,
/// computes the moment map (conservation laws), and guards transitions
/// against inadmissible states and deadlock configurations.
pub struct SymplecticReductionController {
    /// Cumulative phase-space state.
    phase_state: PhaseState,
    /// Flow rate estimation window.
    window_acquisitions: [u64; RESOURCE_TYPES],
    window_releases: [u64; RESOURCE_TYPES],
    window_total: u64,
    /// Baseline flow rates (acquisitions per window).
    baseline_rates: [f64; RESOURCE_TYPES],
    baseline_ready: bool,
    baseline_windows: u64,
    /// Current state.
    state: SymplecticState,
    /// Violation count.
    violation_count: u64,
}

impl SymplecticReductionController {
    #[must_use]
    pub fn new() -> Self {
        Self {
            phase_state: [0; RESOURCE_TYPES * 2],
            window_acquisitions: [0; RESOURCE_TYPES],
            window_releases: [0; RESOURCE_TYPES],
            window_total: 0,
            baseline_rates: [0.0; RESOURCE_TYPES],
            baseline_ready: false,
            baseline_windows: 0,
            state: SymplecticState::Calibrating,
            violation_count: 0,
        }
    }

    /// Record a resource acquisition (q_i += 1).
    pub fn acquire(&mut self, resource: ResourceType) {
        let idx = resource as usize;
        self.phase_state[2 * idx] += 1;
        self.window_acquisitions[idx] += 1;
        self.window_total += 1;
        self.evaluate_window();
    }

    /// Record a resource release (p_i += 1).
    pub fn release(&mut self, resource: ResourceType) {
        let idx = resource as usize;
        self.phase_state[2 * idx + 1] += 1;
        self.window_releases[idx] += 1;
        self.window_total += 1;
        self.evaluate_window();
    }

    /// Check if acquiring the given resource would be admissible.
    ///
    /// Returns true if the resulting state would remain inside the
    /// admissibility polytope.
    #[must_use]
    pub fn would_be_admissible(&self, resource: ResourceType) -> bool {
        let mu = moment_map(&self.phase_state);
        let idx = resource as usize;
        let new_mu = mu[idx] + 1;
        new_mu >= 0 && new_mu <= CAPACITY[idx] as i64
    }

    fn evaluate_window(&mut self) {
        if self.window_total < FLOW_WINDOW {
            return;
        }

        if !self.baseline_ready {
            let n = self.baseline_windows as f64 + 1.0;
            for (i, bv) in self.baseline_rates.iter_mut().enumerate() {
                let current_rate = self.window_acquisitions[i] as f64;
                *bv = ((n - 1.0) * *bv + current_rate) / n;
            }
            self.baseline_windows += 1;
            self.baseline_ready = self.baseline_windows >= SYMPL_BASELINE_WINDOWS;
            self.reset_window();
            self.state = SymplecticState::Calibrating;
            return;
        }

        // Compute moment map and admissibility metrics.
        let mu = moment_map(&self.phase_state);
        let bdist = boundary_distance(&mu);
        let energy = hamiltonian_energy(&mu);

        // State classification.
        if bdist < 0.0 {
            // Outside admissibility polytope.
            self.state = SymplecticState::Inadmissible;
            self.violation_count += 1;
        } else if energy <= 1e-12 {
            // Balanced lifecycle (moment map ~= 0) is admissible even when
            // geometrically on the lower boundary.
            self.state = SymplecticState::Admissible;
        } else if bdist < (1.0 - BOUNDARY_CRIT) || energy > DEADLOCK_ENERGY_WARN {
            self.state = SymplecticState::NearBoundary;
            self.violation_count += 1;
        } else if bdist < (1.0 - BOUNDARY_WARN) {
            self.state = SymplecticState::NearBoundary;
        } else {
            self.state = SymplecticState::Admissible;
        }

        self.reset_window();
    }

    fn reset_window(&mut self) {
        self.window_acquisitions = [0; RESOURCE_TYPES];
        self.window_releases = [0; RESOURCE_TYPES];
        self.window_total = 0;
    }

    #[must_use]
    pub fn state(&self) -> SymplecticState {
        self.state
    }

    #[must_use]
    pub fn violation_count(&self) -> u64 {
        self.violation_count
    }

    #[must_use]
    pub fn summary(&self) -> SymplecticSummary {
        let mu = moment_map(&self.phase_state);
        SymplecticSummary {
            state: self.state,
            hamiltonian_energy: hamiltonian_energy(&mu),
            boundary_distance: boundary_distance(&mu),
            moment_map: mu,
            violation_count: self.violation_count,
        }
    }
}

impl Default for SymplecticReductionController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moment_map_zero_initial() {
        let state = [0u64; RESOURCE_TYPES * 2];
        let mu = moment_map(&state);
        assert!(mu.iter().all(|&m| m == 0));
    }

    #[test]
    fn moment_map_acquire_release() {
        // Acquire 3 semaphores, release 1 → μ₀ = 2
        let mut state = [0u64; RESOURCE_TYPES * 2];
        state[0] = 3; // q_0 = 3 acquisitions
        state[1] = 1; // p_0 = 1 release
        let mu = moment_map(&state);
        assert_eq!(mu[0], 2);
    }

    #[test]
    fn hamiltonian_energy_zero_for_vacuum() {
        let mu = [0i64; RESOURCE_TYPES];
        assert_eq!(hamiltonian_energy(&mu), 0.0);
    }

    #[test]
    fn hamiltonian_energy_max_at_capacity() {
        let mu = [
            CAPACITY[0] as i64,
            CAPACITY[1] as i64,
            CAPACITY[2] as i64,
            CAPACITY[3] as i64,
        ];
        let energy = hamiltonian_energy(&mu);
        // Each term is (cap/cap)² = 1.0, total = RESOURCE_TYPES
        assert!((energy - RESOURCE_TYPES as f64).abs() < 1e-10);
    }

    #[test]
    fn symplectic_form_antisymmetric() {
        let a = [1.0, 0.0, 0.5, 0.3, 0.0, 0.0, 0.0, 0.0];
        let b = [0.0, 1.0, 0.2, 0.7, 0.0, 0.0, 0.0, 0.0];
        let omega_ab = symplectic_form(&a, &b);
        let omega_ba = symplectic_form(&b, &a);
        assert!(
            (omega_ab + omega_ba).abs() < 1e-10,
            "symplectic form not antisymmetric: ω(a,b)={omega_ab}, ω(b,a)={omega_ba}"
        );
    }

    #[test]
    fn symplectic_form_canonical_basis() {
        // ω(dq₀, dp₀) = 1, ω(dp₀, dq₀) = -1
        let dq0 = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let dp0 = [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        assert!((symplectic_form(&dq0, &dp0) - 1.0).abs() < 1e-10);
        assert!((symplectic_form(&dp0, &dq0) + 1.0).abs() < 1e-10);

        // ω(dq₀, dq₁) = 0 (different types, not conjugate)
        let dq1 = [0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        assert!((symplectic_form(&dq0, &dq1)).abs() < 1e-10);
    }

    #[test]
    fn boundary_distance_vacuum_is_zero() {
        let mu = [0i64; RESOURCE_TYPES];
        let bd = boundary_distance(&mu);
        assert!(bd.abs() < 1e-10, "vacuum should be on boundary (lower=0)");
    }

    #[test]
    fn boundary_distance_positive_inside() {
        // Half-capacity: should be well inside
        let mu = [
            CAPACITY[0] as i64 / 2,
            CAPACITY[1] as i64 / 2,
            CAPACITY[2] as i64 / 2,
            CAPACITY[3] as i64 / 2,
        ];
        let bd = boundary_distance(&mu);
        assert!(bd > 0.0, "half-capacity should be inside polytope");
    }

    #[test]
    fn boundary_distance_negative_outside() {
        // Over-capacity: should be outside
        let mu = [CAPACITY[0] as i64 + 5, 0, 0, 0];
        let bd = boundary_distance(&mu);
        assert!(bd < 0.0, "over-capacity should be outside polytope");
    }

    #[test]
    fn controller_starts_calibrating() {
        let ctrl = SymplecticReductionController::new();
        assert_eq!(ctrl.state(), SymplecticState::Calibrating);
    }

    #[test]
    fn balanced_lifecycle_reaches_admissible() {
        let mut ctrl = SymplecticReductionController::new();
        // Balanced acquire/release pattern.
        for _ in 0..3000 {
            ctrl.acquire(ResourceType::Semaphore);
            ctrl.release(ResourceType::Semaphore);
            ctrl.acquire(ResourceType::FileDescriptor);
            ctrl.release(ResourceType::FileDescriptor);
        }
        assert!(
            matches!(
                ctrl.state(),
                SymplecticState::Admissible | SymplecticState::Calibrating
            ),
            "balanced lifecycle should be admissible, got {:?}",
            ctrl.state()
        );
    }

    #[test]
    fn would_be_admissible_basic() {
        let ctrl = SymplecticReductionController::new();
        // Initial state: no resources held, so acquiring should be admissible.
        assert!(ctrl.would_be_admissible(ResourceType::Semaphore));
        assert!(ctrl.would_be_admissible(ResourceType::SharedMemory));
    }

    #[test]
    fn summary_has_zero_energy_initially() {
        let ctrl = SymplecticReductionController::new();
        let s = ctrl.summary();
        assert_eq!(s.hamiltonian_energy, 0.0);
        assert!(s.moment_map.iter().all(|&m| m == 0));
    }

    #[test]
    fn normalized_moment_at_capacity() {
        let mu = [
            CAPACITY[0] as i64,
            CAPACITY[1] as i64,
            CAPACITY[2] as i64,
            CAPACITY[3] as i64,
        ];
        let norm = normalized_moment(&mu);
        for &n in &norm {
            assert!(
                (n - 1.0).abs() < 1e-10,
                "at capacity, normalized should be 1.0"
            );
        }
    }

    #[test]
    fn leak_detection_triggers_near_boundary() {
        let mut ctrl = SymplecticReductionController::new();
        // Calibrate with balanced traffic.
        for _ in 0..1000 {
            ctrl.acquire(ResourceType::Semaphore);
            ctrl.release(ResourceType::Semaphore);
        }
        // Leak: acquire without releasing (small semaphore capacity = 64).
        for _ in 0..60 {
            ctrl.acquire(ResourceType::Semaphore);
        }
        // Pump more events to trigger evaluation.
        for _ in 0..500 {
            ctrl.acquire(ResourceType::FileDescriptor);
            ctrl.release(ResourceType::FileDescriptor);
        }
        assert!(
            matches!(
                ctrl.state(),
                SymplecticState::NearBoundary | SymplecticState::Inadmissible
            ),
            "resource leak should trigger boundary warning, got {:?}",
            ctrl.state()
        );
    }
}
