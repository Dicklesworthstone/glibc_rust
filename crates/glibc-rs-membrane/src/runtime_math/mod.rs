//! Runtime math kernel for membrane decision control.
//!
//! This module makes the "alien-artifact" stack operational at runtime by
//! compiling advanced methods into tiny online controllers:
//! - conformal-like risk upper bounds (`risk`)
//! - constrained bandit routing of validation depth (`bandit`)
//! - primal-dual budget controller (`control`)
//! - barrier admissibility filter (`barrier`)
//! - incremental overlap-consistency monitor (`cohomology`)
//!
//! The runtime path remains deterministic and low overhead. Heavy synthesis
//! stays offline; online code only executes compact control kernels.

pub mod admm_budget;
pub mod atiyah_bott;
pub mod bandit;
pub mod barrier;
pub mod changepoint;
pub mod clifford;
pub mod cohomology;
pub mod commitment_audit;
pub mod conformal;
pub mod control;
pub mod coupling;
pub mod covering_array;
pub mod cvar;
pub mod derived_tstructure;
pub mod design;
pub mod eprocess;
pub mod equivariant;
pub mod fusion;
pub mod grobner_normalizer;
pub mod grothendieck_glue;
pub mod higher_topos;
pub mod ktheory;
pub mod loss_minimizer;
pub mod microlocal;
pub mod obstruction_detector;
pub mod operator_norm;
pub mod pareto;
pub mod pomdp_repair;
pub mod provenance_info;
pub mod risk;
pub mod serre_spectral;
pub mod sos_invariant;
pub mod sparse;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::check_oracle::{CheckContext, CheckOracle, CheckStage};
use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::hji_reachability::{HjiReachabilityController, ReachState};
use crate::large_deviations::{LargeDeviationsMonitor, RateState};
use crate::mean_field_game::{MeanFieldGameController, MfgState};
use crate::padic_valuation::{PadicState, PadicValuationMonitor};
use crate::persistence::{PersistenceDetector, TopologicalState};
use crate::quarantine_controller::{QuarantineController, current_depth, publish_depth};
use crate::risk_engine::{CallFamily, RiskDecision, RiskEngine};
use crate::rough_path::{RoughPathMonitor, SignatureState};
use crate::schrodinger_bridge::{BridgeState, SchrodingerBridgeController};
use crate::spectral_monitor::{PhaseState, SpectralMonitor};
use crate::symplectic_reduction::{ResourceType, SymplecticReductionController, SymplecticState};
use crate::tropical_latency::{PipelinePath, TROPICAL_METRICS, TropicalLatencyCompositor};

use self::admm_budget::{AdmmBudgetController, AdmmState};
use self::atiyah_bott::{AtiyahBottController, LocalizationState};
use self::bandit::ConstrainedBanditRouter;
use self::barrier::BarrierOracle;
use self::changepoint::{ChangepointController, ChangepointState};
use self::clifford::{AlignmentObservation, AlignmentRegime, CliffordController, CliffordState};
use self::cohomology::CohomologyMonitor;
use self::commitment_audit::{AuditState, CommitmentAuditController};
use self::conformal::{ConformalRiskController, ConformalState};
use self::control::PrimalDualController;
use self::coupling::{CouplingController, CouplingState};
use self::covering_array::{CoverageState, CoveringArrayController};
use self::cvar::{DroCvarController, TailState};
use self::derived_tstructure::{TStructureController, TStructureState};
use self::design::{OptimalDesignController, Probe, ProbePlan};
use self::eprocess::{AnytimeEProcessMonitor, SequentialState};
use self::equivariant::{EquivariantState, EquivariantTransportController};
use self::fusion::KernelFusionController;
use self::grobner_normalizer::{GrobnerNormalizerController, GrobnerState};
use self::grothendieck_glue::{
    CocycleObservation, DataSource, GlueState, GrothendieckGlueController, QueryFamily,
};
use self::higher_topos::{HigherToposController, ToposState};
use self::ktheory::{KTheoryController, KTheoryState};
use self::loss_minimizer::{LossMinimizationController, LossState};
use self::microlocal::{MicrolocalController, MicrolocalState, Stratum};
use self::obstruction_detector::{ObstructionDetector, ObstructionState};
use self::operator_norm::{OperatorNormMonitor, StabilityState};
use self::pareto::ParetoController;
use self::pomdp_repair::{PomdpRepairController, PomdpState};
use self::provenance_info::{ProvenanceInfoController, ProvenanceState};
use self::risk::ConformalRiskEngine;
use self::serre_spectral::{
    InvariantClass, LayerPair, SerreSpectralController, SpectralSequenceState,
};
use self::sos_invariant::{SosInvariantController, SosState};
use self::sparse::{SparseRecoveryController, SparseState};

const FAST_PATH_BUDGET_NS: u64 = 20;
const FULL_PATH_BUDGET_NS: u64 = 200;

/// Runtime API family used for online control decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ApiFamily {
    PointerValidation = 0,
    Allocator = 1,
    StringMemory = 2,
    Stdio = 3,
    Threading = 4,
    Resolver = 5,
    MathFenv = 6,
    Loader = 7,
    Stdlib = 8,
}

impl ApiFamily {
    pub const COUNT: usize = 9;
}

/// Validation profile selected by the runtime controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationProfile {
    Fast,
    Full,
}

impl ValidationProfile {
    /// Returns true if full pipeline checks are required.
    #[must_use]
    pub const fn requires_full(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Compact runtime context for online policy decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeContext {
    pub family: ApiFamily,
    pub addr_hint: usize,
    pub requested_bytes: usize,
    pub is_write: bool,
    pub contention_hint: u16,
    pub bloom_negative: bool,
}

impl RuntimeContext {
    /// Convenience constructor for pointer-validation flow.
    #[must_use]
    pub const fn pointer_validation(addr_hint: usize, bloom_negative: bool) -> Self {
        Self {
            family: ApiFamily::PointerValidation,
            addr_hint,
            requested_bytes: 0,
            is_write: false,
            contention_hint: 0,
            bloom_negative,
        }
    }
}

/// Runtime membrane action selected by control kernels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembraneAction {
    Allow,
    FullValidate,
    Repair(HealingAction),
    Deny,
}

/// Online decision output consumed by membrane call paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeDecision {
    pub profile: ValidationProfile,
    pub action: MembraneAction,
    pub policy_id: u32,
    pub risk_upper_bound_ppm: u32,
}

impl RuntimeDecision {
    /// Returns true if call path should execute full validation checks.
    #[must_use]
    pub const fn requires_full_validation(self) -> bool {
        self.profile.requires_full()
            || matches!(
                self.action,
                MembraneAction::FullValidate | MembraneAction::Repair(_)
            )
    }
}

/// Runtime state snapshot useful for tests/telemetry export.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RuntimeKernelSnapshot {
    pub decisions: u64,
    pub consistency_faults: u64,
    pub full_validation_trigger_ppm: u32,
    pub repair_trigger_ppm: u32,
    pub sampled_risk_bonus_ppm: u32,
    pub pareto_cumulative_regret_milli: u64,
    pub pareto_cap_enforcements: u64,
    pub pareto_exhausted_families: u32,
    pub quarantine_depth: usize,
    /// Tropical worst-case latency for the full pipeline path (ns).
    pub tropical_full_wcl_ns: u64,
    /// Spectral edge ratio (max_eigenvalue / median_eigenvalue).
    pub spectral_edge_ratio: f64,
    /// Whether a spectral phase transition is active.
    pub spectral_phase_transition: bool,
    /// Rough-path signature anomaly score (0 = normal, >2 = anomalous).
    pub signature_anomaly_score: f64,
    /// Total rough-path anomaly detections.
    pub signature_anomaly_count: u64,
    /// Persistence entropy of the validation cost point cloud.
    pub persistence_entropy: f64,
    /// Total topological anomaly detections.
    pub topo_anomaly_count: u64,
    /// Maximum anytime e-process value across runtime families.
    pub anytime_max_e_value: f64,
    /// Number of families currently in e-process alarm mode.
    pub anytime_alarmed_families: u32,
    /// Maximum robust CVaR latency estimate across families.
    pub cvar_max_robust_ns: u64,
    /// Number of families in CVaR alarm state.
    pub cvar_alarmed_families: u32,
    /// Schrödinger bridge transport distance (W_ε between current policy and equilibrium).
    pub bridge_transport_distance: f64,
    /// Whether a regime transition is detected via optimal transport.
    pub bridge_transitioning: bool,
    /// Number of families with elevated/critical large-deviation rate state.
    pub ld_elevated_families: u32,
    /// Maximum anomaly count across families in the large-deviation monitor.
    pub ld_max_anomaly_count: u64,
    /// HJI reachability value at current discrete state (>0 = safe, ≤0 = breached).
    pub hji_safety_value: f64,
    /// Whether the system state is inside the backward reachable tube.
    pub hji_breached: bool,
    /// Mean-field game empirical contention level (normalized 0..1).
    pub mfg_mean_contention: f64,
    /// Mean-field game congestion collapse detections.
    pub mfg_congestion_count: u64,
    /// p-adic ultrametric distance between current and baseline valuation profiles.
    pub padic_ultrametric_distance: f64,
    /// p-adic regime drift detection count.
    pub padic_drift_count: u64,
    /// Symplectic Hamiltonian energy (deadlock risk indicator, 0..N).
    pub symplectic_energy: f64,
    /// Symplectic admissibility violation count.
    pub symplectic_violation_count: u64,
    /// Higher-topos descent violation rate (EWMA, 0..1).
    pub topos_violation_rate: f64,
    /// Higher-topos descent violation count.
    pub topos_violation_count: u64,
    /// Commitment audit martingale process value.
    pub audit_martingale_value: f64,
    /// Commitment audit replay detection count.
    pub audit_replay_count: u64,
    /// Bayesian change-point posterior short-run-length mass (0..1).
    pub changepoint_posterior_short_mass: f64,
    /// Bayesian change-point detection count.
    pub changepoint_count: u64,
    /// Conformal prediction empirical coverage (0..1).
    pub conformal_empirical_coverage: f64,
    /// Conformal prediction coverage violation count.
    pub conformal_violation_count: u64,
    /// Design-kernel identifiability score (0..1e6).
    pub design_identifiability_ppm: u32,
    /// Number of heavy probes selected in the current budgeted plan.
    pub design_selected_probes: u8,
    /// Probe-budget assigned by mode/controller.
    pub design_budget_ns: u64,
    /// Expected cost of selected probes.
    pub design_expected_cost_ns: u64,
    /// Sparse-recovery latent support size.
    pub sparse_support_size: u8,
    /// Sparse-recovery L1 energy.
    pub sparse_l1_energy: f64,
    /// Sparse-recovery residual EWMA.
    pub sparse_residual_ewma: f64,
    /// Sparse-recovery critical detections.
    pub sparse_critical_count: u64,
    /// Equivariant controller alignment score (higher is more symmetric/stable).
    pub equivariant_alignment_ppm: u32,
    /// Equivariant drift detections.
    pub equivariant_drift_count: u64,
    /// Equivariant fractured-state detections.
    pub equivariant_fractured_count: u64,
    /// Most active runtime orbit class.
    pub equivariant_dominant_orbit: u8,
    /// Robust fusion bonus currently applied to risk.
    pub fusion_bonus_ppm: u32,
    /// Fusion entropy (0..1000) over signal trust weights.
    pub fusion_entropy_milli: u32,
    /// Fusion weight-drift score in ppm.
    pub fusion_drift_ppm: u32,
    /// Dominant fused signal index.
    pub fusion_dominant_signal: u8,
    /// Microlocal wavefront active strata count.
    pub microlocal_active_strata: u8,
    /// Microlocal propagation failure rate (EWMA, 0..1).
    pub microlocal_failure_rate: f64,
    /// Microlocal fault boundary detection count.
    pub microlocal_fault_count: u64,
    /// Serre spectral sequence max differential density.
    pub serre_max_differential: f64,
    /// Serre spectral sequence non-trivial cell count.
    pub serre_nontrivial_cells: u8,
    /// Serre spectral sequence lifting failure count.
    pub serre_lifting_count: u64,
    /// Clifford grade-2 (bivector) energy fraction.
    pub clifford_grade2_energy: f64,
    /// Clifford grade parity imbalance.
    pub clifford_parity_imbalance: f64,
    /// Clifford overlap violation count.
    pub clifford_violation_count: u64,
    /// K-theory maximum transport distance across ABI families.
    pub ktheory_max_transport_distance: f64,
    /// K-theory ABI fracture detection count.
    pub ktheory_fracture_count: u64,
    /// Covering-array conformance coverage fraction (0..1).
    pub covering_coverage_fraction: f64,
    /// Covering-array coverage gap detection count.
    pub covering_gap_count: u64,
    /// Derived t-structure maximum ordering violation rate.
    pub tstructure_max_violation_rate: f64,
    /// Derived t-structure orthogonality violation count.
    pub tstructure_violation_count: u64,
    /// Atiyah-Bott localization Euler weight.
    pub atiyah_bott_euler_weight: f64,
    /// Atiyah-Bott concentrated anomaly detection count.
    pub atiyah_bott_concentration_count: u64,
    /// POMDP repair optimality gap (0..1+).
    pub pomdp_optimality_gap: f64,
    /// POMDP policy divergence detection count.
    pub pomdp_divergence_count: u64,
    /// SOS invariant maximum stress fraction.
    pub sos_max_stress: f64,
    /// SOS invariant violation event count.
    pub sos_violation_count: u64,
    /// ADMM primal-dual gap (0..∞, lower is better).
    pub admm_primal_dual_gap: f64,
    /// ADMM constraint violation count.
    pub admm_violation_count: u64,
    /// Spectral-sequence obstruction norm (0..∞).
    pub obstruction_norm: f64,
    /// Critical obstruction detection count.
    pub obstruction_critical_count: u64,
    /// Operator-norm spectral radius estimate.
    pub operator_norm_spectral_radius: f64,
    /// Operator-norm instability detection count.
    pub operator_norm_instability_count: u64,
    /// Provenance Shannon entropy per byte (0..8, ideal = 8.0).
    pub provenance_shannon_entropy: f64,
    /// Provenance Rényi H₂ collision entropy per byte (0..8).
    pub provenance_renyi_h2: f64,
    /// Provenance collision risk detection count.
    pub provenance_collision_count: u64,
    /// Grobner constraint violation rate (EWMA, 0..1).
    pub grobner_violation_rate: f64,
    /// Grobner structural fault detection count.
    pub grobner_fault_count: u64,
    /// Grothendieck glue global cocycle violation rate (EWMA, 0..1).
    pub grothendieck_violation_rate: f64,
    /// Grothendieck stackification fault detection count.
    pub grothendieck_stack_fault_count: u64,
}

/// Online control kernel for strict/hardened runtime decisions.
pub struct RuntimeMathKernel {
    risk: ConformalRiskEngine,
    router: ConstrainedBanditRouter,
    controller: PrimalDualController,
    barrier: BarrierOracle,
    cohomology: CohomologyMonitor,
    pareto: ParetoController,
    sampled_risk: Mutex<RiskEngine>,
    sampled_oracle: Mutex<CheckOracle>,
    quarantine: Mutex<QuarantineController>,
    tropical: Mutex<TropicalLatencyCompositor>,
    spectral: Mutex<SpectralMonitor>,
    rough_path: Mutex<RoughPathMonitor>,
    persistence: Mutex<PersistenceDetector>,
    anytime: Mutex<AnytimeEProcessMonitor>,
    cvar: Mutex<DroCvarController>,
    bridge: Mutex<SchrodingerBridgeController>,
    large_dev: Mutex<LargeDeviationsMonitor>,
    hji: Mutex<HjiReachabilityController>,
    mfg: Mutex<MeanFieldGameController>,
    padic: Mutex<PadicValuationMonitor>,
    symplectic: Mutex<SymplecticReductionController>,
    design: Mutex<OptimalDesignController>,
    sparse: Mutex<SparseRecoveryController>,
    equivariant: Mutex<EquivariantTransportController>,
    topos: Mutex<HigherToposController>,
    audit: Mutex<CommitmentAuditController>,
    changepoint: Mutex<ChangepointController>,
    conformal: Mutex<ConformalRiskController>,
    loss_minimizer: Mutex<LossMinimizationController>,
    coupling: Mutex<CouplingController>,
    fusion: Mutex<KernelFusionController>,
    microlocal: Mutex<MicrolocalController>,
    serre: Mutex<SerreSpectralController>,
    clifford: Mutex<CliffordController>,
    ktheory: Mutex<KTheoryController>,
    covering: Mutex<CoveringArrayController>,
    tstructure: Mutex<TStructureController>,
    admm: Mutex<AdmmBudgetController>,
    atiyah_bott: Mutex<AtiyahBottController>,
    obstruction: Mutex<ObstructionDetector>,
    operator_norm: Mutex<OperatorNormMonitor>,
    pomdp: Mutex<PomdpRepairController>,
    sos: Mutex<SosInvariantController>,
    provenance: Mutex<ProvenanceInfoController>,
    grobner: Mutex<GrobnerNormalizerController>,
    grothendieck: Mutex<GrothendieckGlueController>,
    cached_risk_bonus_ppm: AtomicU64,
    cached_oracle_bias: [AtomicU8; ApiFamily::COUNT],
    cached_spectral_phase: AtomicU8,
    cached_signature_state: AtomicU8,
    cached_topological_state: AtomicU8,
    cached_anytime_state: [AtomicU8; ApiFamily::COUNT],
    cached_cvar_state: [AtomicU8; ApiFamily::COUNT],
    cached_bridge_state: AtomicU8,
    cached_ld_state: [AtomicU8; ApiFamily::COUNT],
    cached_hji_state: AtomicU8,
    cached_mfg_state: AtomicU8,
    cached_padic_state: AtomicU8,
    cached_symplectic_state: AtomicU8,
    cached_probe_mask: AtomicU64,
    cached_design_ident_ppm: AtomicU64,
    cached_design_budget_ns: AtomicU64,
    cached_design_expected_ns: AtomicU64,
    cached_design_selected: AtomicU8,
    cached_sparse_state: AtomicU8,
    cached_equivariant_state: AtomicU8,
    cached_equivariant_alignment_ppm: AtomicU64,
    cached_equivariant_orbit: AtomicU8,
    cached_topos_state: AtomicU8,
    cached_audit_state: AtomicU8,
    cached_changepoint_state: AtomicU8,
    cached_conformal_state: AtomicU8,
    cached_loss_minimizer_state: AtomicU8,
    cached_coupling_state: AtomicU8,
    cached_fusion_bonus_ppm: AtomicU64,
    cached_fusion_entropy_milli: AtomicU64,
    cached_fusion_drift_ppm: AtomicU64,
    cached_fusion_dominant_signal: AtomicU8,
    cached_microlocal_state: AtomicU8,
    cached_serre_state: AtomicU8,
    cached_clifford_state: AtomicU8,
    cached_ktheory_state: AtomicU8,
    cached_covering_state: AtomicU8,
    cached_tstructure_state: AtomicU8,
    cached_admm_state: AtomicU8,
    cached_atiyah_bott_state: AtomicU8,
    cached_obstruction_state: AtomicU8,
    cached_operator_norm_state: AtomicU8,
    cached_pomdp_state: AtomicU8,
    cached_sos_state: AtomicU8,
    cached_provenance_state: AtomicU8,
    cached_grobner_state: AtomicU8,
    cached_grothendieck_state: AtomicU8,
    decisions: AtomicU64,
}

impl RuntimeMathKernel {
    /// Create a new runtime kernel.
    #[must_use]
    pub fn new() -> Self {
        Self {
            risk: ConformalRiskEngine::new(20_000, 3.0),
            router: ConstrainedBanditRouter::new(),
            controller: PrimalDualController::new(),
            barrier: BarrierOracle::new(),
            cohomology: CohomologyMonitor::new(),
            pareto: ParetoController::new(),
            sampled_risk: Mutex::new(RiskEngine::new()),
            sampled_oracle: Mutex::new(CheckOracle::new()),
            quarantine: Mutex::new(QuarantineController::new()),
            tropical: Mutex::new(TropicalLatencyCompositor::new()),
            spectral: Mutex::new(SpectralMonitor::new()),
            rough_path: Mutex::new(RoughPathMonitor::new()),
            persistence: Mutex::new(PersistenceDetector::new()),
            anytime: Mutex::new(AnytimeEProcessMonitor::new()),
            cvar: Mutex::new(DroCvarController::new()),
            bridge: Mutex::new(SchrodingerBridgeController::new()),
            large_dev: Mutex::new(LargeDeviationsMonitor::new()),
            hji: Mutex::new(HjiReachabilityController::new()),
            mfg: Mutex::new(MeanFieldGameController::new()),
            padic: Mutex::new(PadicValuationMonitor::new()),
            symplectic: Mutex::new(SymplecticReductionController::new()),
            design: Mutex::new(OptimalDesignController::new()),
            sparse: Mutex::new(SparseRecoveryController::new()),
            equivariant: Mutex::new(EquivariantTransportController::new()),
            topos: Mutex::new(HigherToposController::new()),
            audit: Mutex::new(CommitmentAuditController::new()),
            changepoint: Mutex::new(ChangepointController::new()),
            conformal: Mutex::new(ConformalRiskController::new()),
            loss_minimizer: Mutex::new(LossMinimizationController::new()),
            coupling: Mutex::new(CouplingController::new()),
            fusion: Mutex::new(KernelFusionController::new()),
            microlocal: Mutex::new(MicrolocalController::new()),
            serre: Mutex::new(SerreSpectralController::new()),
            clifford: Mutex::new(CliffordController::new()),
            ktheory: Mutex::new(KTheoryController::new()),
            covering: Mutex::new(CoveringArrayController::new()),
            tstructure: Mutex::new(TStructureController::new()),
            admm: Mutex::new(AdmmBudgetController::new()),
            atiyah_bott: Mutex::new(AtiyahBottController::new()),
            obstruction: Mutex::new(ObstructionDetector::new()),
            operator_norm: Mutex::new(OperatorNormMonitor::new()),
            pomdp: Mutex::new(PomdpRepairController::new()),
            sos: Mutex::new(SosInvariantController::new()),
            provenance: Mutex::new(ProvenanceInfoController::new()),
            grobner: Mutex::new(GrobnerNormalizerController::new()),
            grothendieck: Mutex::new(GrothendieckGlueController::new()),
            cached_risk_bonus_ppm: AtomicU64::new(0),
            cached_oracle_bias: std::array::from_fn(|_| AtomicU8::new(1)),
            cached_spectral_phase: AtomicU8::new(0),
            cached_signature_state: AtomicU8::new(0),
            cached_topological_state: AtomicU8::new(0),
            cached_anytime_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_cvar_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_bridge_state: AtomicU8::new(0),
            cached_ld_state: std::array::from_fn(|_| AtomicU8::new(0)),
            cached_hji_state: AtomicU8::new(0),
            cached_mfg_state: AtomicU8::new(0),
            cached_padic_state: AtomicU8::new(0),
            cached_symplectic_state: AtomicU8::new(0),
            cached_probe_mask: AtomicU64::new(u64::from(Probe::all_mask())),
            cached_design_ident_ppm: AtomicU64::new(0),
            cached_design_budget_ns: AtomicU64::new(0),
            cached_design_expected_ns: AtomicU64::new(0),
            cached_design_selected: AtomicU8::new(Probe::COUNT as u8),
            cached_sparse_state: AtomicU8::new(0),
            cached_equivariant_state: AtomicU8::new(0),
            cached_equivariant_alignment_ppm: AtomicU64::new(0),
            cached_equivariant_orbit: AtomicU8::new(0),
            cached_topos_state: AtomicU8::new(0),
            cached_audit_state: AtomicU8::new(0),
            cached_changepoint_state: AtomicU8::new(0),
            cached_conformal_state: AtomicU8::new(0),
            cached_loss_minimizer_state: AtomicU8::new(0),
            cached_coupling_state: AtomicU8::new(0),
            cached_fusion_bonus_ppm: AtomicU64::new(0),
            cached_fusion_entropy_milli: AtomicU64::new(0),
            cached_fusion_drift_ppm: AtomicU64::new(0),
            cached_fusion_dominant_signal: AtomicU8::new(0),
            cached_microlocal_state: AtomicU8::new(0),
            cached_serre_state: AtomicU8::new(0),
            cached_clifford_state: AtomicU8::new(0),
            cached_ktheory_state: AtomicU8::new(0),
            cached_covering_state: AtomicU8::new(0),
            cached_tstructure_state: AtomicU8::new(0),
            cached_admm_state: AtomicU8::new(0),
            cached_atiyah_bott_state: AtomicU8::new(0),
            cached_obstruction_state: AtomicU8::new(0),
            cached_operator_norm_state: AtomicU8::new(0),
            cached_pomdp_state: AtomicU8::new(0),
            cached_sos_state: AtomicU8::new(0),
            cached_provenance_state: AtomicU8::new(0),
            cached_grobner_state: AtomicU8::new(0),
            cached_grothendieck_state: AtomicU8::new(0),
            decisions: AtomicU64::new(0),
        }
    }

    /// Decide runtime validation/repair strategy for one call context.
    #[must_use]
    pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {
        let sequence = self.decisions.fetch_add(1, Ordering::Relaxed) + 1;
        if sequence.is_multiple_of(64) {
            self.resample_high_order_kernels(mode, ctx);
        }

        let base_risk_ppm = self.risk.upper_bound_ppm(ctx.family);
        let sampled_bonus = self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32;
        let consistency_faults = self.cohomology.fault_count();
        let cohomology_bonus = (consistency_faults.min(16) as u32) * 15_000;
        let fast_wcl = TROPICAL_METRICS.fast_wcl_ns.load(Ordering::Relaxed);
        let full_wcl = TROPICAL_METRICS.full_wcl_ns.load(Ordering::Relaxed);
        let fast_over_budget = fast_wcl > FAST_PATH_BUDGET_NS;
        let full_over_budget = full_wcl > FULL_PATH_BUDGET_NS;
        let tropical_bonus = match (fast_over_budget, full_over_budget) {
            (true, true) => 120_000u32,
            (false, true) => 60_000u32,
            _ => 0u32,
        };
        // Spectral phase transition: boost risk by 100k ppm when workload regime changes.
        let spectral_bonus = match self.cached_spectral_phase.load(Ordering::Relaxed) {
            2 => 100_000u32, // NewRegime
            1 => 50_000u32,  // Transitioning
            _ => 0u32,       // Stationary
        };
        // Rough-path signature anomaly: the signature captures ALL moments and
        // temporal ordering — strictly more powerful than spectral (2nd-order only).
        let sig_bonus = match self.cached_signature_state.load(Ordering::Relaxed) {
            2 => 75_000u32, // Anomalous
            _ => 0u32,      // Calibrating/Normal
        };
        // Persistent homology anomaly: detects structural changes in the data
        // shape that are invisible to all statistical methods.
        let topo_bonus = match self.cached_topological_state.load(Ordering::Relaxed) {
            2 => 80_000u32, // Anomalous
            _ => 0u32,      // Calibrating/Normal
        };
        let anytime_bonus = match self.cached_anytime_state[usize::from(ctx.family as u8)]
            .load(Ordering::Relaxed)
        {
            3 => 150_000u32, // Alarm
            2 => 60_000u32,  // Warning
            _ => 0u32,       // Calibrating/Normal
        };
        let cvar_bonus =
            match self.cached_cvar_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) {
                3 => 130_000u32, // Alarm
                2 => 45_000u32,  // Warning
                _ => 0u32,       // Calibrating/Normal
            };
        // Schrödinger bridge: entropic optimal transport detects regime
        // transitions as the W_ε distance between current and equilibrium policy.
        let bridge_bonus = match self.cached_bridge_state.load(Ordering::Relaxed) {
            2 => 90_000u32, // Transitioning
            _ => 0u32,      // Calibrating/Stable
        };
        // Large-deviations rate function: Cramér bound gives rigorous
        // exponential probability guarantees for catastrophic failure sequences.
        let ld_bonus =
            match self.cached_ld_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) {
                3 => 140_000u32, // Critical — rate function collapse
                2 => 55_000u32,  // Elevated
                _ => 0u32,       // Calibrating/Normal
            };
        // Hamilton-Jacobi-Isaacs reachability: formal worst-case safety
        // certificate. Breached = adversary has a winning strategy.
        let hji_bonus = match self.cached_hji_state.load(Ordering::Relaxed) {
            3 => 200_000u32, // Breached — inside backward reachable tube
            2 => 70_000u32,  // Approaching — near BRT boundary
            _ => 0u32,       // Calibrating/Safe
        };
        // Mean-field game congestion: Nash equilibrium deviation signals
        // resource coordination failure (tragedy of the commons).
        let mfg_bonus = match self.cached_mfg_state.load(Ordering::Relaxed) {
            3 => 100_000u32, // Collapsed — severe congestion failure
            2 => 40_000u32,  // Congested — above equilibrium
            _ => 0u32,       // Calibrating/Equilibrium
        };
        // p-adic valuation: non-Archimedean regime drift in floating-point
        // exponents. ExceptionalRegime means NaN/Inf/subnormal flood.
        let padic_bonus = match self.cached_padic_state.load(Ordering::Relaxed) {
            3 => 110_000u32, // ExceptionalRegime
            2 => 45_000u32,  // DenormalDrift
            _ => 0u32,       // Calibrating/Normal
        };
        // Symplectic reduction: resource lifecycle admissibility guard.
        // Inadmissible means outside the conservation-law polytope.
        let symplectic_bonus = match self.cached_symplectic_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // Inadmissible — outside polytope
            2 => 50_000u32,  // NearBoundary — approaching capacity
            _ => 0u32,       // Calibrating/Admissible
        };
        // Sparse-recovery root-cause concentration:
        // focused high-energy support indicates a coherent fault source; critical
        // indicates high-residual adversarial or unstable latent dynamics.
        let sparse_bonus = match self.cached_sparse_state.load(Ordering::Relaxed) {
            4 => 150_000u32, // Critical
            3 => 70_000u32,  // Diffuse
            2 => 40_000u32,  // Focused
            _ => 0u32,       // Calibrating/Stable
        };
        let equivariant_bonus = match self.cached_equivariant_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // Fractured cross-family symmetry
            2 => 60_000u32,  // Drift
            _ => 0u32,       // Calibrating/Aligned
        };
        // Higher-topos descent: locale/catalog coherence violation
        // signals i18n fallback chain corruption.
        let topos_bonus = match self.cached_topos_state.load(Ordering::Relaxed) {
            3 => 110_000u32, // Incoherent — sustained descent violation
            2 => 45_000u32,  // DescentViolation
            _ => 0u32,       // Calibrating/Coherent
        };
        // Commitment audit: martingale-based tamper detection for
        // session/accounting traces.
        let audit_bonus = match self.cached_audit_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // TamperDetected — martingale alarm
            2 => 55_000u32,  // Anomalous — martingale warning
            _ => 0u32,       // Calibrating/Consistent
        };
        // Bayesian change-point: posterior mass on short run-lengths
        // signals abrupt shift in adverse-rate regime.
        let changepoint_bonus = match self.cached_changepoint_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // ChangePoint — high posterior short mass
            2 => 50_000u32,  // Drift — moderate posterior shift
            _ => 0u32,       // Calibrating/Stable
        };
        // Conformal prediction: empirical coverage dropping below
        // finite-sample guarantee indicates distribution shift.
        let conformal_bonus = match self.cached_conformal_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // CoverageFailure — severe miscoverage
            2 => 45_000u32,  // Undercoverage — coverage drifting
            _ => 0u32,       // Calibrating/Covered
        };
        // Decision-theoretic loss minimizer: cost explosion across all
        // action categories signals a fundamentally adversarial regime.
        let loss_min_bonus = match self.cached_loss_minimizer_state.load(Ordering::Relaxed) {
            4 => 160_000u32, // CostExplosion — all actions losing
            3 => 50_000u32,  // DenyBiased — deny is cheapest (suspicious)
            2 => 35_000u32,  // RepairBiased — repairs dominating
            _ => 0u32,       // Calibrating/Balanced
        };
        // Probabilistic coupling: strict/hardened divergence beyond
        // Hoeffding concentration bound signals mode inconsistency.
        let coupling_bonus = match self.cached_coupling_state.load(Ordering::Relaxed) {
            4 => 170_000u32, // CertificationFailure — modes incompatible
            3 => 65_000u32,  // Diverged — significant disagreement
            2 => 30_000u32,  // Drifting — mild disagreement
            _ => 0u32,       // Calibrating/Coupled
        };
        let fusion_bonus = self.cached_fusion_bonus_ppm.load(Ordering::Relaxed) as u32;
        // Microlocal sheaf: wavefront set propagation fault-surface control.
        // SingularSupport means dense active microsupport.
        let microlocal_bonus = match self.cached_microlocal_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // SingularSupport — dense fault surface
            2 => 55_000u32,  // FaultBoundary — localized fault
            _ => 0u32,       // Calibrating/Propagating
        };
        // Serre spectral sequence: cross-layer lifting failure detection.
        let serre_bonus = match self.cached_serre_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // Collapsed — diverging spectral sequence
            2 => 50_000u32,  // LiftingFailure — non-trivial differentials
            _ => 0u32,       // Calibrating/Converged
        };
        // Clifford algebra: SIMD alignment/overlap correctness.
        let clifford_bonus = match self.cached_clifford_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // OverlapViolation — Pin parity break
            2 => 45_000u32,  // MisalignmentDrift — bivector energy rising
            _ => 0u32,       // Calibrating/Aligned
        };
        // K-theory transport: ABI compatibility integrity.
        // Fractured K-class means ABI contract bundle diverged from baseline.
        let ktheory_bonus = match self.cached_ktheory_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // Fractured — ABI compatibility broken
            2 => 50_000u32,  // Drift — compatibility degrading
            _ => 0u32,       // Calibrating/Compatible
        };
        // Covering-array matroid: conformance interaction coverage.
        // CriticalGap means many interaction tuples are untested.
        let covering_bonus = match self.cached_covering_state.load(Ordering::Relaxed) {
            3 => 100_000u32, // CriticalGap — many untested interactions
            2 => 40_000u32,  // CoverageGap — some missing coverage
            _ => 0u32,       // Calibrating/Complete
        };
        // Derived t-structure: bootstrap ordering invariants.
        // OrthogonalityViolation means stages executing severely out of order.
        let tstructure_bonus = match self.cached_tstructure_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // OrthogonalityViolation — severe ordering fault
            2 => 55_000u32,  // Disorder — minor ordering issues
            _ => 0u32,       // Calibrating/WellOrdered
        };
        // Atiyah-Bott fixed-point localization: concentrated anomaly detection.
        // ConcentratedAnomaly means risk localizes at very few controllers
        // while the rest are perfectly stable — an isolated severe fault.
        let atiyah_bott_bonus = match self.cached_atiyah_bott_state.load(Ordering::Relaxed) {
            3 => 150_000u32, // ConcentratedAnomaly — isolated severe fault
            2 => 45_000u32,  // Localized — risk concentrating
            _ => 0u32,       // Calibrating/Distributed
        };
        // POMDP repair policy: optimality gap monitoring.
        // PolicyDivergence means the threshold cascade is severely miscalibrated
        // relative to the Bellman-optimal policy.
        let pomdp_bonus = match self.cached_pomdp_state.load(Ordering::Relaxed) {
            3 => 120_000u32, // PolicyDivergence — severe miscalibration
            2 => 50_000u32,  // SuboptimalPolicy — growing gap
            _ => 0u32,       // Calibrating/Optimal
        };
        // SOS polynomial invariant: cross-controller coherence guard.
        // InvariantViolated means the combined controller state is in a region
        // that the SOS certificate proved impossible under normal operation.
        let sos_bonus = match self.cached_sos_state.load(Ordering::Relaxed) {
            3 => 180_000u32, // InvariantViolated — structurally impossible state
            2 => 60_000u32,  // InvariantStressed — approaching violation
            _ => 0u32,       // Calibrating/InvariantSatisfied
        };
        // ADMM budget allocator: primal-dual convergence of budget allocation.
        // ConstraintViolation means the risk/latency/coverage budget split
        // is significantly suboptimal — shadow prices indicate binding constraints.
        let admm_bonus = match self.cached_admm_state.load(Ordering::Relaxed) {
            3 => 130_000u32, // ConstraintViolation — budget severely suboptimal
            2 => 45_000u32,  // DualDrift — budget allocation adapting
            _ => 0u32,       // Calibrating/Converged
        };
        // Spectral-sequence obstruction: cross-layer consistency defects.
        // CriticalObstruction means d² ≠ 0 — the controller ensemble has
        // a global consistency defect invisible to individual controllers.
        let obstruction_bonus = match self.cached_obstruction_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // CriticalObstruction — ensemble breakdown
            2 => 50_000u32,  // MinorObstruction — emerging defect
            _ => 0u32,       // Calibrating/Exact
        };
        // Operator-norm spectral radius: ensemble dynamics stability.
        // Unstable means perturbations are amplifying across the controller
        // ensemble — a positive feedback cascade.
        let operator_norm_bonus = match self.cached_operator_norm_state.load(Ordering::Relaxed) {
            3 => 170_000u32, // Unstable — perturbation amplification
            2 => 55_000u32,  // Marginal — near stability boundary
            _ => 0u32,       // Calibrating/Contractive
        };
        // Provenance info-theoretic: fingerprint entropy degradation signals
        // collision resistance loss in the allocation integrity subsystem.
        let provenance_bonus = match self.cached_provenance_state.load(Ordering::Relaxed) {
            3 => 160_000u32, // CollisionRisk — key rotation needed
            2 => 55_000u32,  // EntropyDrift — entropy degrading
            _ => 0u32,       // Calibrating/Secure
        };
        // Grobner normalizer: confluent constraint verification over the
        // controller state vector. StructuralFault = state outside the ideal.
        let grobner_bonus = match self.cached_grobner_state.load(Ordering::Relaxed) {
            3 => 170_000u32, // StructuralFault — impossible controller config
            2 => 50_000u32,  // MinorInconsistency — some constraints breached
            _ => 0u32,       // Calibrating/Consistent
        };
        // Grothendieck glue: cocycle/descent coherence for NSS/resolv/locale.
        // StackificationFault = equivalence classes don't compose.
        let grothendieck_bonus = match self.cached_grothendieck_state.load(Ordering::Relaxed) {
            3 => 140_000u32, // StackificationFault — deep incoherence
            2 => 55_000u32,  // DescentFailure — cocycle violations
            _ => 0u32,       // Calibrating/Coherent
        };
        let pre_design_risk_ppm = base_risk_ppm
            .saturating_add(sampled_bonus)
            .saturating_add(cohomology_bonus)
            .saturating_add(tropical_bonus)
            .saturating_add(spectral_bonus)
            .saturating_add(sig_bonus)
            .saturating_add(topo_bonus)
            .saturating_add(anytime_bonus)
            .saturating_add(cvar_bonus)
            .saturating_add(bridge_bonus)
            .saturating_add(ld_bonus)
            .saturating_add(hji_bonus)
            .saturating_add(mfg_bonus)
            .saturating_add(padic_bonus)
            .saturating_add(symplectic_bonus)
            .saturating_add(sparse_bonus)
            .saturating_add(equivariant_bonus)
            .saturating_add(topos_bonus)
            .saturating_add(audit_bonus)
            .saturating_add(changepoint_bonus)
            .saturating_add(conformal_bonus)
            .saturating_add(loss_min_bonus)
            .saturating_add(coupling_bonus)
            .saturating_add(fusion_bonus)
            .saturating_add(microlocal_bonus)
            .saturating_add(serre_bonus)
            .saturating_add(clifford_bonus)
            .saturating_add(ktheory_bonus)
            .saturating_add(covering_bonus)
            .saturating_add(tstructure_bonus)
            .saturating_add(atiyah_bott_bonus)
            .saturating_add(pomdp_bonus)
            .saturating_add(sos_bonus)
            .saturating_add(admm_bonus)
            .saturating_add(obstruction_bonus)
            .saturating_add(operator_norm_bonus)
            .saturating_add(provenance_bonus)
            .saturating_add(grobner_bonus)
            .saturating_add(grothendieck_bonus)
            .min(1_000_000);

        // D-optimal probe scheduling:
        // choose heavy monitors under budget to maximize online identifiability.
        let design_bonus = {
            let adverse_hint = ctx.bloom_negative || (ctx.is_write && ctx.requested_bytes > 4096);
            let mut design = self.design.lock();
            let plan =
                design.choose_plan(mode, pre_design_risk_ppm, adverse_hint, fast_over_budget);
            let ident_ppm = design.identifiability_ppm();
            self.cached_probe_mask
                .store(u64::from(plan.mask), Ordering::Relaxed);
            self.cached_design_ident_ppm
                .store(u64::from(ident_ppm), Ordering::Relaxed);
            self.cached_design_budget_ns
                .store(plan.budget_ns, Ordering::Relaxed);
            self.cached_design_expected_ns
                .store(plan.expected_cost_ns, Ordering::Relaxed);
            self.cached_design_selected
                .store(plan.selected_count(), Ordering::Relaxed);
            if ident_ppm < 150_000 {
                95_000u32
            } else if ident_ppm < 300_000 {
                40_000u32
            } else {
                0u32
            }
        };

        let risk_upper_bound_ppm = pre_design_risk_ppm
            .saturating_add(design_bonus)
            .min(1_000_000);

        let limits = self.controller.limits(mode);
        let mut profile =
            self.router
                .select_profile(ctx.family, mode, risk_upper_bound_ppm, ctx.contention_hint);
        let pareto_profile = self.pareto.recommend_profile(
            mode,
            ctx.family,
            risk_upper_bound_ppm,
            limits.full_validation_trigger_ppm,
            limits.repair_trigger_ppm,
        );
        let pareto_budget_exhausted = self.pareto.is_budget_exhausted(mode, ctx.family);

        let family_idx = usize::from(ctx.family as u8);
        let oracle_bias = self.cached_oracle_bias[family_idx].load(Ordering::Relaxed);
        if oracle_bias == 0 && risk_upper_bound_ppm >= limits.repair_trigger_ppm / 2 {
            profile = ValidationProfile::Full;
        } else if oracle_bias == 2 && risk_upper_bound_ppm <= limits.full_validation_trigger_ppm / 3
        {
            profile = ValidationProfile::Fast;
        }

        // Tropical budget pressure acts as a runtime governor:
        // - if full path is over budget while fast path is healthy and risk is low,
        //   bias toward fast validation;
        // - if both paths are over budget under elevated risk, force full checks.
        if full_over_budget && !fast_over_budget && risk_upper_bound_ppm < limits.repair_trigger_ppm
        {
            profile = ValidationProfile::Fast;
        }
        if fast_over_budget && full_over_budget && risk_upper_bound_ppm >= limits.repair_trigger_ppm
        {
            profile = ValidationProfile::Full;
        }
        if consistency_faults > 0 && mode.heals_enabled() {
            profile = ValidationProfile::Full;
        }
        if self.cached_design_selected.load(Ordering::Relaxed) <= 2
            && risk_upper_bound_ppm >= limits.full_validation_trigger_ppm / 2
        {
            profile = ValidationProfile::Full;
        }
        if self.cached_sparse_state.load(Ordering::Relaxed) >= 4 {
            profile = ValidationProfile::Full;
        }
        if self.cached_equivariant_state.load(Ordering::Relaxed) >= 3 {
            profile = ValidationProfile::Full;
        }

        // Pareto kernel contributes a mode-aware latency/risk tradeoff with
        // explicit regret accounting. Merge conservatively with existing profile.
        if matches!(pareto_profile, ValidationProfile::Full) {
            profile = ValidationProfile::Full;
        }
        // In strict mode, once a family has exhausted its regret budget, lock
        // routing to Pareto's deterministic empirical-optimal arm unless hard
        // risk gates already demand full validation.
        if matches!(mode, SafetyLevel::Strict)
            && pareto_budget_exhausted
            && risk_upper_bound_ppm < limits.full_validation_trigger_ppm
        {
            profile = pareto_profile;
        }

        // Adaptive allocator guard: when quarantine depth is low under elevated
        // risk, force full validation to preserve temporal safety.
        if matches!(ctx.family, ApiFamily::Allocator)
            && mode.heals_enabled()
            && current_depth() < 128
            && risk_upper_bound_ppm >= limits.repair_trigger_ppm / 2
        {
            profile = ValidationProfile::Full;
        }
        if self.cached_cvar_state[usize::from(ctx.family as u8)].load(Ordering::Relaxed) >= 3 {
            profile = ValidationProfile::Full;
        }

        let admissible = self
            .barrier
            .admissible(&ctx, mode, profile, risk_upper_bound_ppm, limits);

        let action = if !admissible {
            if mode.heals_enabled() {
                MembraneAction::Repair(HealingAction::ReturnSafeDefault)
            } else {
                MembraneAction::Deny
            }
        } else if profile.requires_full()
            || risk_upper_bound_ppm >= limits.full_validation_trigger_ppm
        {
            MembraneAction::FullValidate
        } else if mode.heals_enabled() && risk_upper_bound_ppm >= limits.repair_trigger_ppm {
            MembraneAction::Repair(HealingAction::UpgradeToSafeVariant)
        } else {
            MembraneAction::Allow
        };

        RuntimeDecision {
            profile,
            action,
            policy_id: compute_policy_id(mode, ctx.family, profile, action),
            risk_upper_bound_ppm,
        }
    }

    /// Return the current contextual check ordering for a given family/context.
    ///
    /// This is intentionally lightweight and is used by hot validation paths
    /// (notably pointer validation) to execute stage order selected by the
    /// online check oracle.
    #[must_use]
    pub fn check_ordering(
        &self,
        family: ApiFamily,
        aligned: bool,
        recent_page: bool,
    ) -> [CheckStage; 7] {
        let ctx = CheckContext {
            family: family as u8,
            aligned,
            recent_page,
        };
        let oracle = self.sampled_oracle.lock();
        *oracle.get_ordering(&ctx)
    }

    /// Feed exact stage-exit outcomes for the contextual check oracle.
    ///
    /// This closes the loop between runtime-selected ordering and real pipeline
    /// exits so the oracle learns from true hot-path behavior.
    pub fn note_check_order_outcome(
        &self,
        family: ApiFamily,
        aligned: bool,
        recent_page: bool,
        ordering_used: &[CheckStage; 7],
        exit_stage: Option<usize>,
    ) {
        let mode = crate::config::safety_level();
        let ctx = CheckContext {
            family: family as u8,
            aligned,
            recent_page,
        };
        let mut oracle = self.sampled_oracle.lock();
        oracle.report_outcome(&ctx, ordering_used, exit_stage);
        let refreshed = *oracle.get_ordering(&ctx);
        let bias = oracle_bias_from_ordering(&refreshed, mode);
        self.cached_oracle_bias[usize::from(family as u8)].store(bias, Ordering::Relaxed);
    }

    /// Feed observed runtime outcome back into online controllers.
    pub fn observe_validation_result(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        let mode = crate::config::safety_level();
        let probe_mask = self.cached_probe_mask.load(Ordering::Relaxed) as u32;
        self.risk.observe(family, adverse);
        self.router
            .observe(family, profile, estimated_cost_ns, adverse);
        self.controller.observe(estimated_cost_ns, adverse);
        let risk_bound_ppm = self.risk.upper_bound_ppm(family);
        self.pareto.observe(
            mode,
            family,
            profile,
            estimated_cost_ns,
            adverse,
            risk_bound_ppm,
        );

        let mut spectral_anomaly = None;
        let mut rough_anomaly = None;
        let mut persistence_anomaly = None;
        let mut anytime_anomaly = None;
        let mut cvar_anomaly = None;
        let mut bridge_anomaly = None;
        let mut ld_anomaly = None;
        let mut hji_anomaly = None;
        let mut mfg_anomaly = None;
        let mut padic_anomaly = None;
        let mut symplectic_anomaly = None;
        let mut topos_anomaly = None;
        let mut audit_anomaly = None;
        let mut changepoint_anomaly = None;
        let mut conformal_anomaly = None;
        let mut loss_minimizer_anomaly = None;
        let mut coupling_anomaly = None;

        // Feed tropical latency compositor with per-path observations.
        {
            let path = match profile {
                ValidationProfile::Fast => PipelinePath::FastExit,
                ValidationProfile::Full => PipelinePath::Full,
            };
            let mut tropical = self.tropical.lock();
            tropical.observe_path(path, estimated_cost_ns);
            // Publish metrics every 256 observations.
            if tropical.total_observations().is_multiple_of(256) {
                TROPICAL_METRICS.publish(&tropical);
            }
        }

        // Feed spectral monitor with multi-dimensional observation.
        if ProbePlan::includes_mask(probe_mask, Probe::Spectral) {
            let contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let hit_rate = if adverse { 1.0 } else { 0.0 };
            let risk_score = f64::from(risk_bound_ppm) / 1_000_000.0;
            let latency = (estimated_cost_ns as f64).ln_1p();
            let mut spectral = self.spectral.lock();
            spectral.observe(risk_score, latency, contention, hit_rate);
            // Cache the phase state for the hot-path decision.
            let phase = spectral.phase();
            let phase_code = match phase {
                PhaseState::Stationary => 0u8,
                PhaseState::Transitioning => 1u8,
                PhaseState::NewRegime => 2u8,
            };
            self.cached_spectral_phase
                .store(phase_code, Ordering::Relaxed);
            spectral_anomaly = Some(!matches!(phase, PhaseState::Stationary));
        }

        // Feed rough-path/persistence monitors with the same 4D observation vector.
        let run_rough = ProbePlan::includes_mask(probe_mask, Probe::RoughPath);
        let run_persistence = ProbePlan::includes_mask(probe_mask, Probe::Persistence);
        if run_rough || run_persistence {
            let rp_risk = f64::from(risk_bound_ppm) / 1_000_000.0;
            let rp_latency = (estimated_cost_ns as f64).ln_1p();
            let rp_contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let rp_hit_rate = if adverse { 1.0 } else { 0.0 };
            let obs = [rp_risk, rp_latency, rp_contention, rp_hit_rate];
            if run_rough {
                let mut rp = self.rough_path.lock();
                rp.observe(obs);
                let state = rp.state();
                let sig_state_code = match state {
                    SignatureState::Calibrating => 0u8,
                    SignatureState::Normal => 1u8,
                    SignatureState::Anomalous => 2u8,
                };
                rough_anomaly = Some(matches!(state, SignatureState::Anomalous));
                self.cached_signature_state
                    .store(sig_state_code, Ordering::Relaxed);
            }
            if run_persistence {
                let mut pd = self.persistence.lock();
                pd.observe(obs);
                let state = pd.state();
                let topo_state_code = match state {
                    TopologicalState::Calibrating => 0u8,
                    TopologicalState::Normal => 1u8,
                    TopologicalState::Anomalous => 2u8,
                };
                persistence_anomaly = Some(matches!(state, TopologicalState::Anomalous));
                self.cached_topological_state
                    .store(topo_state_code, Ordering::Relaxed);
            }
        }

        // Feed anytime-valid sequential detector and cache state for hot path.
        if ProbePlan::includes_mask(probe_mask, Probe::Anytime) {
            let state_code = {
                let mon = self.anytime.lock();
                mon.observe(family, adverse);
                let state = mon.state(family);
                anytime_anomaly = Some(matches!(
                    state,
                    SequentialState::Warning | SequentialState::Alarm
                ));
                match state {
                    SequentialState::Calibrating => 0u8,
                    SequentialState::Normal => 1u8,
                    SequentialState::Warning => 2u8,
                    SequentialState::Alarm => 3u8,
                }
            };
            self.cached_anytime_state[usize::from(family as u8)]
                .store(state_code, Ordering::Relaxed);
        }

        // Feed robust CVaR tail controller and cache family state.
        if ProbePlan::includes_mask(probe_mask, Probe::Cvar) {
            let state_code = {
                let cvar = self.cvar.lock();
                cvar.observe(family, profile, estimated_cost_ns);
                let state = cvar.family_state(mode, family);
                cvar_anomaly = Some(matches!(state, TailState::Warning | TailState::Alarm));
                match state {
                    TailState::Calibrating => 0u8,
                    TailState::Normal => 1u8,
                    TailState::Warning => 2u8,
                    TailState::Alarm => 3u8,
                }
            };
            self.cached_cvar_state[usize::from(family as u8)].store(state_code, Ordering::Relaxed);
        }

        // Feed Schrödinger bridge with inferred action index.
        // Maps (profile, adverse, mode) to the 4-action simplex:
        //   0 = Allow, 1 = FullValidate, 2 = Repair, 3 = Deny.
        if ProbePlan::includes_mask(probe_mask, Probe::Bridge) {
            let action_idx = match (profile, adverse, mode.heals_enabled()) {
                (ValidationProfile::Fast, false, _) => 0, // Allow
                (ValidationProfile::Full, false, _) => 1, // FullValidate
                (_, true, true) => 2,                     // Repair (hardened)
                (_, true, false) => 3,                    // Deny (strict)
            };
            let bridge_code = {
                let mut br = self.bridge.lock();
                br.observe_action(action_idx);
                let state = br.state();
                bridge_anomaly = Some(matches!(state, BridgeState::Transitioning));
                match state {
                    BridgeState::Calibrating => 0u8,
                    BridgeState::Stable => 1u8,
                    BridgeState::Transitioning => 2u8,
                }
            };
            self.cached_bridge_state
                .store(bridge_code, Ordering::Relaxed);
        }

        // Feed large-deviations monitor with per-family adverse indicator.
        // The Cramér rate function tracks how quickly the empirical adverse
        // frequency deviates from its baseline, giving exact exponential bounds.
        if ProbePlan::includes_mask(probe_mask, Probe::LargeDeviations) {
            let fidx = usize::from(family as u8);
            let ld_code = {
                let mut ld = self.large_dev.lock();
                ld.observe(fidx, adverse);
                let state = ld.state(fidx);
                ld_anomaly = Some(matches!(state, RateState::Elevated | RateState::Critical));
                match state {
                    RateState::Calibrating => 0u8,
                    RateState::Normal => 1u8,
                    RateState::Elevated => 2u8,
                    RateState::Critical => 3u8,
                }
            };
            self.cached_ld_state[fidx].store(ld_code, Ordering::Relaxed);
        }

        // Feed HJI reachability controller with (risk, latency, adverse).
        // The pre-computed value function gives O(1) formal safety lookup.
        if ProbePlan::includes_mask(probe_mask, Probe::Hji) {
            let hji_code = {
                let mut hji = self.hji.lock();
                hji.observe(risk_bound_ppm, estimated_cost_ns, adverse);
                let state = hji.state();
                hji_anomaly = Some(matches!(
                    state,
                    ReachState::Approaching | ReachState::Breached
                ));
                match state {
                    ReachState::Calibrating => 0u8,
                    ReachState::Safe => 1u8,
                    ReachState::Approaching => 2u8,
                    ReachState::Breached => 3u8,
                }
            };
            self.cached_hji_state.store(hji_code, Ordering::Relaxed);
        }

        // Feed mean-field game controller with contention proxy.
        // We use estimated_cost_ns as a contention signal: high validation
        // latency indicates resource contention across families.
        if ProbePlan::includes_mask(probe_mask, Probe::MeanField) {
            let contention_hint = estimated_cost_ns.min(65535) as u16;
            let mfg_code = {
                let mut mfg = self.mfg.lock();
                mfg.observe(contention_hint);
                let state = mfg.state();
                mfg_anomaly = Some(matches!(state, MfgState::Congested | MfgState::Collapsed));
                match state {
                    MfgState::Calibrating => 0u8,
                    MfgState::Equilibrium => 1u8,
                    MfgState::Congested => 2u8,
                    MfgState::Collapsed => 3u8,
                }
            };
            self.cached_mfg_state.store(mfg_code, Ordering::Relaxed);
        }

        // Feed p-adic valuation monitor with risk bound as a floating-point
        // value. The 2-adic exponent structure of the risk metric reveals
        // numerical regime transitions invisible to Archimedean analysis.
        if ProbePlan::includes_mask(probe_mask, Probe::Padic) {
            let risk_f64 = risk_bound_ppm as f64;
            let padic_code = {
                let mut padic = self.padic.lock();
                padic.observe_f64(risk_f64);
                let state = padic.state();
                padic_anomaly = Some(matches!(
                    state,
                    PadicState::DenormalDrift | PadicState::ExceptionalRegime
                ));
                match state {
                    PadicState::Calibrating => 0u8,
                    PadicState::Normal => 1u8,
                    PadicState::DenormalDrift => 2u8,
                    PadicState::ExceptionalRegime => 3u8,
                }
            };
            self.cached_padic_state.store(padic_code, Ordering::Relaxed);
        }

        // Feed symplectic reduction controller with resource lifecycle events.
        // Allocator family maps to SharedMemory acquire/release;
        // Threading maps to Semaphore; others map to FileDescriptor.
        if ProbePlan::includes_mask(probe_mask, Probe::Symplectic) {
            let resource = match family {
                ApiFamily::Allocator => ResourceType::SharedMemory,
                ApiFamily::Threading => ResourceType::Semaphore,
                ApiFamily::Resolver => ResourceType::MessageQueue,
                _ => ResourceType::FileDescriptor,
            };
            let sympl_code = {
                let mut sympl = self.symplectic.lock();
                if adverse {
                    sympl.acquire(resource);
                } else {
                    sympl.release(resource);
                }
                let state = sympl.state();
                symplectic_anomaly = Some(matches!(
                    state,
                    SymplecticState::NearBoundary | SymplecticState::Inadmissible
                ));
                match state {
                    SymplecticState::Calibrating => 0u8,
                    SymplecticState::Admissible => 1u8,
                    SymplecticState::NearBoundary => 2u8,
                    SymplecticState::Inadmissible => 3u8,
                }
            };
            self.cached_symplectic_state
                .store(sympl_code, Ordering::Relaxed);
        }

        // Feed higher-topos descent controller with locale-scope proxies.
        // We map (family, adverse) to a scope/result/depth observation:
        // scope_hash from family index, result_hash from risk_bound_ppm,
        // fallback_depth from profile (Full = deeper fallback).
        if ProbePlan::includes_mask(probe_mask, Probe::HigherTopos) {
            let scope_hash = (family as u64).wrapping_mul(0x9e3779b97f4a7c15) ^ estimated_cost_ns;
            let result_hash = u64::from(risk_bound_ppm).wrapping_mul(0x517cc1b727220a95);
            let fallback_depth = if matches!(profile, ValidationProfile::Full) {
                2u8
            } else {
                0u8
            };
            let topos_code = {
                let mut topos = self.topos.lock();
                topos.observe(scope_hash, result_hash, fallback_depth);
                let state = topos.state();
                topos_anomaly = Some(matches!(
                    state,
                    ToposState::DescentViolation | ToposState::Incoherent
                ));
                match state {
                    ToposState::Calibrating => 0u8,
                    ToposState::Coherent => 1u8,
                    ToposState::DescentViolation => 2u8,
                    ToposState::Incoherent => 3u8,
                }
            };
            self.cached_topos_state.store(topos_code, Ordering::Relaxed);
        }

        // Feed commitment audit controller with session state transitions.
        // We encode (family, profile) as state indices and use risk_bound_ppm
        // XOR'd with estimated_cost_ns as a transition fingerprint.
        if ProbePlan::includes_mask(probe_mask, Probe::CommitmentAudit) {
            let from_state = family as u32;
            let to_state = (family as u32).wrapping_mul(3).wrapping_add(profile as u32);
            let transition_hash =
                u64::from(risk_bound_ppm) ^ estimated_cost_ns.wrapping_mul(0x6c62272e07bb0142);
            let audit_code = {
                let mut audit = self.audit.lock();
                audit.observe_transition(from_state, to_state, transition_hash);
                let state = audit.state();
                audit_anomaly = Some(matches!(
                    state,
                    AuditState::Anomalous | AuditState::TamperDetected
                ));
                match state {
                    AuditState::Calibrating => 0u8,
                    AuditState::Consistent => 1u8,
                    AuditState::Anomalous => 2u8,
                    AuditState::TamperDetected => 3u8,
                }
            };
            self.cached_audit_state.store(audit_code, Ordering::Relaxed);
        }

        // Feed Bayesian change-point detector with adverse indicator.
        // The run-length posterior tracks abrupt shifts in failure rates
        // that gradual EWMA smoothers miss entirely.
        if ProbePlan::includes_mask(probe_mask, Probe::Changepoint) {
            let cp_code = {
                let mut cp = self.changepoint.lock();
                cp.observe(adverse);
                let state = cp.state();
                changepoint_anomaly = Some(matches!(
                    state,
                    ChangepointState::Drift | ChangepointState::ChangePoint
                ));
                match state {
                    ChangepointState::Calibrating => 0u8,
                    ChangepointState::Stable => 1u8,
                    ChangepointState::Drift => 2u8,
                    ChangepointState::ChangePoint => 3u8,
                }
            };
            self.cached_changepoint_state
                .store(cp_code, Ordering::Relaxed);
        }

        // Feed conformal risk controller with risk score as nonconformity score.
        // The distribution-free coverage guarantee detects when the runtime
        // risk distribution has shifted beyond finite-sample bounds.
        if ProbePlan::includes_mask(probe_mask, Probe::Conformal) {
            let conf_code = {
                let score = f64::from(risk_bound_ppm) / 1_000_000.0;
                let mut conf = self.conformal.lock();
                conf.observe(score);
                let state = conf.state();
                conformal_anomaly = Some(matches!(
                    state,
                    ConformalState::Undercoverage | ConformalState::CoverageFailure
                ));
                match state {
                    ConformalState::Calibrating => 0u8,
                    ConformalState::Covered => 1u8,
                    ConformalState::Undercoverage => 2u8,
                    ConformalState::CoverageFailure => 3u8,
                }
            };
            self.cached_conformal_state
                .store(conf_code, Ordering::Relaxed);
        }

        // Feed decision-theoretic loss minimizer with action/outcome data.
        // The proper scoring framework learns which membrane action minimizes
        // expected regret across the current operational regime.
        if ProbePlan::includes_mask(probe_mask, Probe::LossMinimizer) {
            let action_code = match (profile, adverse) {
                (ValidationProfile::Fast, false) => 0u8,  // Allow
                (ValidationProfile::Full, false) => 1u8,  // FullValidate
                (_, true) if mode.heals_enabled() => 2u8, // Repair
                (_, true) => 3u8,                         // Deny
            };
            let lm_code = {
                let mut lm = self.loss_minimizer.lock();
                lm.observe(action_code, adverse, estimated_cost_ns);
                let state = lm.state();
                loss_minimizer_anomaly = Some(matches!(
                    state,
                    LossState::DenyBiased | LossState::CostExplosion
                ));
                match state {
                    LossState::Calibrating => 0u8,
                    LossState::Balanced => 1u8,
                    LossState::RepairBiased => 2u8,
                    LossState::DenyBiased => 3u8,
                    LossState::CostExplosion => 4u8,
                }
            };
            self.cached_loss_minimizer_state
                .store(lm_code, Ordering::Relaxed);
        }

        // Feed probabilistic coupling controller with strict/hardened action pair.
        // We infer the "other mode" action from current risk level to simulate
        // what the opposite mode would have chosen.
        if ProbePlan::includes_mask(probe_mask, Probe::Coupling) {
            let strict_action = if risk_bound_ppm >= 500_000 {
                3u8 // Deny
            } else if risk_bound_ppm >= 200_000 {
                1u8 // FullValidate
            } else {
                0u8 // Allow
            };
            let hardened_action = if risk_bound_ppm >= 500_000 {
                2u8 // Repair (hardened heals instead of deny)
            } else if risk_bound_ppm >= 150_000 {
                1u8 // FullValidate (lower threshold)
            } else {
                0u8 // Allow
            };
            let cp_code = {
                let mut cp = self.coupling.lock();
                cp.observe(strict_action, hardened_action, adverse);
                let state = cp.state();
                coupling_anomaly = Some(matches!(
                    state,
                    CouplingState::Diverged | CouplingState::CertificationFailure
                ));
                match state {
                    CouplingState::Calibrating => 0u8,
                    CouplingState::Coupled => 1u8,
                    CouplingState::Drifting => 2u8,
                    CouplingState::Diverged => 3u8,
                    CouplingState::CertificationFailure => 4u8,
                }
            };
            self.cached_coupling_state.store(cp_code, Ordering::Relaxed);
        }

        // Feed microlocal sheaf controller with stratum transition proxy.
        // Signal-heavy families (Threading, Resolver) map to SignalBoundary;
        // StringMemory maps to LongjmpBoundary (longjmp crosses cleanup);
        // others map to NormalFlow.
        {
            let from = Stratum::NormalFlow;
            let to = match family {
                ApiFamily::Threading => Stratum::SignalBoundary,
                ApiFamily::Resolver => Stratum::SignalBoundary,
                ApiFamily::StringMemory if adverse => Stratum::LongjmpBoundary,
                _ => Stratum::NormalFlow,
            };
            let mc_code = {
                let mut mc = self.microlocal.lock();
                mc.observe_and_update(from, to, adverse);
                match mc.state() {
                    MicrolocalState::Calibrating => 0u8,
                    MicrolocalState::Propagating => 1u8,
                    MicrolocalState::FaultBoundary => 2u8,
                    MicrolocalState::SingularSupport => 3u8,
                }
            };
            self.cached_microlocal_state
                .store(mc_code, Ordering::Relaxed);
        }

        // Feed Serre spectral sequence controller with cross-layer lifting proxy.
        // We map (family, adverse) to a layer-pair and invariant-class observation:
        // ABI→Membrane for Allocator/StringMemory; Membrane→Core for others.
        {
            let layer_pair = match family {
                ApiFamily::Allocator | ApiFamily::StringMemory => LayerPair::AbiToMembrane,
                ApiFamily::Threading | ApiFamily::Resolver => LayerPair::AbiToCore,
                _ => LayerPair::MembraneToCore,
            };
            let inv_class = match family {
                ApiFamily::Allocator => InvariantClass::ResourceLifecycle,
                ApiFamily::StringMemory => InvariantClass::ReturnSemantics,
                ApiFamily::Threading => InvariantClass::SideEffectOrder,
                _ => InvariantClass::ErrorRecovery,
            };
            let serre_code = {
                let mut serre = self.serre.lock();
                serre.observe_and_update(layer_pair, inv_class, !adverse);
                match serre.state() {
                    SpectralSequenceState::Calibrating => 0u8,
                    SpectralSequenceState::Converged => 1u8,
                    SpectralSequenceState::LiftingFailure => 2u8,
                    SpectralSequenceState::Collapsed => 3u8,
                }
            };
            self.cached_serre_state.store(serre_code, Ordering::Relaxed);
        }

        // Feed Clifford controller with alignment observation proxy.
        // Source/destination alignment inferred from addr_hint and requested_bytes.
        {
            let obs = AlignmentObservation {
                src_alignment: AlignmentRegime::classify(estimated_cost_ns as usize & 0xFF),
                dst_alignment: AlignmentRegime::classify(risk_bound_ppm as usize & 0xFF),
                overlap_fraction: if adverse { 0.5 } else { 0.0 },
                length_regime: (estimated_cost_ns as f64).clamp(0.0, 200.0) / 200.0,
            };
            let cliff_code = {
                let mut cliff = self.clifford.lock();
                cliff.observe_and_update(obs);
                match cliff.state() {
                    CliffordState::Calibrating => 0u8,
                    CliffordState::Aligned => 1u8,
                    CliffordState::MisalignmentDrift => 2u8,
                    CliffordState::OverlapViolation => 3u8,
                }
            };
            self.cached_clifford_state
                .store(cliff_code, Ordering::Relaxed);
        }

        // Feed K-theory transport controller with behavioral contract coordinates.
        // Encodes: (normalized_latency, adverse, profile_depth, risk_level).
        {
            let norm_latency = (estimated_cost_ns as f64).clamp(0.0, 200.0) / 200.0;
            let adverse_f = if adverse { 1.0 } else { 0.0 };
            let prof_depth = if matches!(profile, ValidationProfile::Full) {
                1.0
            } else {
                0.0
            };
            let risk_level = f64::from(risk_bound_ppm) / 1_000_000.0;
            let coords = [norm_latency, adverse_f, prof_depth, risk_level];
            let kt_code = {
                let mut kt = self.ktheory.lock();
                kt.observe_and_update(family as usize, coords);
                match kt.state() {
                    KTheoryState::Calibrating => 0u8,
                    KTheoryState::Compatible => 1u8,
                    KTheoryState::Drift => 2u8,
                    KTheoryState::Fractured => 3u8,
                }
            };
            self.cached_ktheory_state.store(kt_code, Ordering::Relaxed);
        }

        // Feed covering-array matroid conformance scheduler.
        // Binary parameters: family_high, mode_hardened, profile_full, adverse,
        // contention_high, aligned.
        {
            let family_high = if (family as u8) >= 4 { 1u8 } else { 0u8 };
            let mode_hard = if mode.heals_enabled() { 1u8 } else { 0u8 };
            let prof_full = if matches!(profile, ValidationProfile::Full) {
                1u8
            } else {
                0u8
            };
            let adverse_b = if adverse { 1u8 } else { 0u8 };
            let contention_high = if estimated_cost_ns > 100 { 1u8 } else { 0u8 };
            let aligned = if estimated_cost_ns <= 16 && !adverse {
                1u8
            } else {
                0u8
            };
            let params = [
                family_high,
                mode_hard,
                prof_full,
                adverse_b,
                contention_high,
                aligned,
            ];
            let cov_code = {
                let mut cov = self.covering.lock();
                cov.observe_and_update(params);
                match cov.state() {
                    CoverageState::Calibrating => 0u8,
                    CoverageState::Complete => 1u8,
                    CoverageState::CoverageGap => 2u8,
                    CoverageState::CriticalGap => 3u8,
                }
            };
            self.cached_covering_state
                .store(cov_code, Ordering::Relaxed);
        }

        // Feed derived t-structure bootstrap ordering controller.
        // We map family to a stage index (families are loosely ordered by
        // initialization dependency depth) and check predecessors via risk.
        {
            let stage_idx = (family as usize).min(7);
            let predecessors_complete = !adverse && risk_bound_ppm < 200_000;
            let ts_code = {
                let mut ts = self.tstructure.lock();
                ts.observe_and_update(stage_idx, predecessors_complete);
                match ts.state() {
                    TStructureState::Calibrating => 0u8,
                    TStructureState::WellOrdered => 1u8,
                    TStructureState::Disorder => 2u8,
                    TStructureState::OrthogonalityViolation => 3u8,
                }
            };
            self.cached_tstructure_state
                .store(ts_code, Ordering::Relaxed);
        }

        // Feed POMDP repair policy controller.
        // Infer approximate action code from profile, mode, and risk.
        {
            let action_code = if risk_bound_ppm >= 500_000 {
                if mode.heals_enabled() { 2u8 } else { 3u8 } // Repair / Deny
            } else if profile.requires_full() || risk_bound_ppm >= 200_000 {
                1u8 // FullValidate
            } else if mode.heals_enabled() && risk_bound_ppm >= 100_000 {
                2u8 // Repair
            } else {
                0u8 // Allow
            };
            let pomdp_code = {
                let mut p = self.pomdp.lock();
                p.observe_and_update(risk_bound_ppm, action_code, adverse);
                match p.state() {
                    PomdpState::Calibrating => 0u8,
                    PomdpState::Optimal => 1u8,
                    PomdpState::SuboptimalPolicy => 2u8,
                    PomdpState::PolicyDivergence => 3u8,
                }
            };
            self.cached_pomdp_state.store(pomdp_code, Ordering::Relaxed);
        }

        // Feed ADMM budget allocator with risk/latency/coverage signals.
        {
            let risk_cost = (risk_bound_ppm as f64 / 1_000_000.0).clamp(0.0, 1.0);
            let latency_fraction = (estimated_cost_ns as f64 / 200.0).clamp(0.0, 1.0);
            let coverage_gap = if profile.requires_full() { 0.1 } else { 0.4 };
            let admm_code = {
                let mut admm = self.admm.lock();
                admm.observe_and_update(risk_cost, latency_fraction, coverage_gap);
                match admm.state() {
                    AdmmState::Calibrating => 0u8,
                    AdmmState::Converged => 1u8,
                    AdmmState::DualDrift => 2u8,
                    AdmmState::ConstraintViolation => 3u8,
                }
            };
            self.cached_admm_state.store(admm_code, Ordering::Relaxed);
        }

        let mut anomaly_vec = [false; Probe::COUNT];
        if let Some(flag) = spectral_anomaly {
            anomaly_vec[Probe::Spectral as usize] = flag;
        }
        if let Some(flag) = rough_anomaly {
            anomaly_vec[Probe::RoughPath as usize] = flag;
        }
        if let Some(flag) = persistence_anomaly {
            anomaly_vec[Probe::Persistence as usize] = flag;
        }
        if let Some(flag) = anytime_anomaly {
            anomaly_vec[Probe::Anytime as usize] = flag;
        }
        if let Some(flag) = cvar_anomaly {
            anomaly_vec[Probe::Cvar as usize] = flag;
        }
        if let Some(flag) = bridge_anomaly {
            anomaly_vec[Probe::Bridge as usize] = flag;
        }
        if let Some(flag) = ld_anomaly {
            anomaly_vec[Probe::LargeDeviations as usize] = flag;
        }
        if let Some(flag) = hji_anomaly {
            anomaly_vec[Probe::Hji as usize] = flag;
        }
        if let Some(flag) = mfg_anomaly {
            anomaly_vec[Probe::MeanField as usize] = flag;
        }
        if let Some(flag) = padic_anomaly {
            anomaly_vec[Probe::Padic as usize] = flag;
        }
        if let Some(flag) = symplectic_anomaly {
            anomaly_vec[Probe::Symplectic as usize] = flag;
        }
        if let Some(flag) = topos_anomaly {
            anomaly_vec[Probe::HigherTopos as usize] = flag;
        }
        if let Some(flag) = audit_anomaly {
            anomaly_vec[Probe::CommitmentAudit as usize] = flag;
        }
        if let Some(flag) = changepoint_anomaly {
            anomaly_vec[Probe::Changepoint as usize] = flag;
        }
        if let Some(flag) = conformal_anomaly {
            anomaly_vec[Probe::Conformal as usize] = flag;
        }
        if let Some(flag) = loss_minimizer_anomaly {
            anomaly_vec[Probe::LossMinimizer as usize] = flag;
        }
        if let Some(flag) = coupling_anomaly {
            anomaly_vec[Probe::Coupling as usize] = flag;
        }

        // Feed sparse-recovery latent controller with executed-probe anomalies.
        {
            let sparse_code = {
                let mut sparse = self.sparse.lock();
                sparse.observe(probe_mask, anomaly_vec, adverse);
                match sparse.state() {
                    SparseState::Calibrating => 0u8,
                    SparseState::Stable => 1u8,
                    SparseState::Focused => 2u8,
                    SparseState::Diffuse => 3u8,
                    SparseState::Critical => 4u8,
                }
            };
            self.cached_sparse_state
                .store(sparse_code, Ordering::Relaxed);
        }

        // Feed equivariant transport controller (always-on, O(1)):
        // tracks cross-family symmetry breaking under mode/profile actions.
        let _equivariant_anomaly = {
            let (eq_code, eq_summary) = {
                let mut eq = self.equivariant.lock();
                eq.observe(
                    family,
                    mode,
                    profile,
                    estimated_cost_ns,
                    adverse,
                    risk_bound_ppm,
                );
                let summary = eq.summary();
                let code = match summary.state {
                    EquivariantState::Calibrating => 0u8,
                    EquivariantState::Aligned => 1u8,
                    EquivariantState::Drift => 2u8,
                    EquivariantState::Fractured => 3u8,
                };
                (code, summary)
            };
            self.cached_equivariant_state
                .store(eq_code, Ordering::Relaxed);
            self.cached_equivariant_alignment_ppm
                .store(u64::from(eq_summary.alignment_ppm), Ordering::Relaxed);
            self.cached_equivariant_orbit
                .store(eq_summary.dominant_orbit, Ordering::Relaxed);
            eq_code >= 2
        };

        // Feed information-theoretic provenance controller with a compact byte
        // derived from call context, risk, and latency.
        {
            let fingerprint_byte = (u64::from(risk_bound_ppm)
                ^ estimated_cost_ns
                ^ u64::from(family as u8).wrapping_mul(0x9e)
                ^ u64::from(profile as u8).wrapping_mul(0x6d))
                as u8;
            let prov_code = {
                let mut prov = self.provenance.lock();
                prov.observe_bytes(&[fingerprint_byte]);
                match prov.state() {
                    ProvenanceState::Calibrating => 0u8,
                    ProvenanceState::Secure => 1u8,
                    ProvenanceState::EntropyDrift => 2u8,
                    ProvenanceState::CollisionRisk => 3u8,
                }
            };
            self.cached_provenance_state
                .store(prov_code, Ordering::Relaxed);
        }

        // Feed Grothendieck glue controller with local-to-global coherence
        // observations mapped from API family + adverse outcome.
        {
            let (query_family, source_i, source_j, is_stack_check) = match family {
                ApiFamily::Resolver => (
                    QueryFamily::Hostname,
                    DataSource::Files,
                    DataSource::Dns,
                    false,
                ),
                ApiFamily::Threading => (
                    QueryFamily::UserGroup,
                    DataSource::Cache,
                    DataSource::Files,
                    false,
                ),
                ApiFamily::StringMemory => (
                    QueryFamily::EncodingLookup,
                    DataSource::IconvTables,
                    DataSource::Fallback,
                    true,
                ),
                ApiFamily::Stdlib => (
                    QueryFamily::LocaleResolution,
                    DataSource::LocaleFiles,
                    DataSource::Fallback,
                    true,
                ),
                ApiFamily::MathFenv => (
                    QueryFamily::Transliteration,
                    DataSource::LocaleFiles,
                    DataSource::IconvTables,
                    true,
                ),
                _ => (
                    QueryFamily::Service,
                    DataSource::Files,
                    DataSource::Cache,
                    false,
                ),
            };
            let glue_code = {
                let mut glue = self.grothendieck.lock();
                let obs = CocycleObservation {
                    family: query_family,
                    source_i,
                    source_j,
                    compatible: !adverse,
                    is_stack_check,
                };
                glue.observe_cocycle(&obs);
                match glue.state() {
                    GlueState::Calibrating => 0u8,
                    GlueState::Coherent => 1u8,
                    GlueState::DescentFailure => 2u8,
                    GlueState::StackificationFault => 3u8,
                }
            };
            self.cached_grothendieck_state
                .store(glue_code, Ordering::Relaxed);
        }

        // Feed Grobner normalizer with the constrained 16-variable controller
        // severity vector used for canonical consistency checks.
        {
            let risk_state = if risk_bound_ppm >= 500_000 {
                3u8
            } else if risk_bound_ppm >= 200_000 {
                2u8
            } else if risk_bound_ppm >= 50_000 {
                1u8
            } else {
                0u8
            };
            let state_vec = [
                risk_state,                                                   // 0 risk
                self.cached_bridge_state.load(Ordering::Relaxed).min(3),      // 1 bridge
                self.cached_changepoint_state.load(Ordering::Relaxed).min(3), // 2 changepoint
                self.cached_hji_state.load(Ordering::Relaxed).min(3),         // 3 hji
                self.cached_anytime_state[usize::from(family as u8)] // 4 eprocess/padic
                    .load(Ordering::Relaxed)
                    .max(self.cached_padic_state.load(Ordering::Relaxed))
                    .min(3),
                self.cached_cvar_state[usize::from(family as u8)] // 5 cvar
                    .load(Ordering::Relaxed)
                    .min(3),
                self.cached_coupling_state.load(Ordering::Relaxed).min(3), // 6 coupling
                self.cached_mfg_state.load(Ordering::Relaxed).min(3),      // 7 mfg
                self.cached_equivariant_state.load(Ordering::Relaxed).min(3), // 8 equivariant
                self.cached_microlocal_state.load(Ordering::Relaxed).min(3), // 9 microlocal
                self.cached_ktheory_state.load(Ordering::Relaxed).min(3),  // 10 ktheory
                self.cached_serre_state.load(Ordering::Relaxed).min(3),    // 11 serre
                self.cached_tstructure_state.load(Ordering::Relaxed).min(3), // 12 tstructure
                self.cached_clifford_state.load(Ordering::Relaxed).min(3), // 13 clifford
                self.cached_topos_state.load(Ordering::Relaxed).min(3),    // 14 topos
                self.cached_audit_state.load(Ordering::Relaxed).min(3),    // 15 audit
            ];
            let grobner_code = {
                let mut grobner = self.grobner.lock();
                grobner.check_state_vector(&state_vec);
                match grobner.state() {
                    GrobnerState::Calibrating => 0u8,
                    GrobnerState::Consistent => 1u8,
                    GrobnerState::MinorInconsistency => 2u8,
                    GrobnerState::StructuralFault => 3u8,
                }
            };
            self.cached_grobner_state
                .store(grobner_code, Ordering::Relaxed);
        }

        // Build base 25-element severity vector from cached controller states.
        // This is consumed by Atiyah-Bott (localization), SOS (invariant guard),
        // and the robust fusion controller.
        let base_severity: [u8; 25] = [
            self.cached_spectral_phase.load(Ordering::Relaxed), // 0..2
            self.cached_signature_state.load(Ordering::Relaxed), // 0..2
            self.cached_topological_state.load(Ordering::Relaxed), // 0..2
            self.cached_anytime_state[usize::from(family as u8)].load(Ordering::Relaxed), // 0..3
            self.cached_cvar_state[usize::from(family as u8)].load(Ordering::Relaxed), // 0..3
            self.cached_bridge_state.load(Ordering::Relaxed),   // 0..2
            self.cached_ld_state[usize::from(family as u8)].load(Ordering::Relaxed), // 0..3
            self.cached_hji_state.load(Ordering::Relaxed),      // 0..3
            self.cached_mfg_state.load(Ordering::Relaxed),      // 0..3
            self.cached_padic_state.load(Ordering::Relaxed),    // 0..3
            self.cached_symplectic_state.load(Ordering::Relaxed), // 0..3
            self.cached_sparse_state.load(Ordering::Relaxed),   // 0..4
            self.cached_equivariant_state.load(Ordering::Relaxed), // 0..3
            self.cached_topos_state.load(Ordering::Relaxed),    // 0..3
            self.cached_audit_state.load(Ordering::Relaxed),    // 0..3
            self.cached_changepoint_state.load(Ordering::Relaxed), // 0..3
            self.cached_conformal_state.load(Ordering::Relaxed), // 0..3
            self.cached_loss_minimizer_state.load(Ordering::Relaxed), // 0..4
            self.cached_coupling_state.load(Ordering::Relaxed), // 0..4
            self.cached_microlocal_state.load(Ordering::Relaxed), // 0..3
            self.cached_serre_state.load(Ordering::Relaxed),    // 0..3
            self.cached_clifford_state.load(Ordering::Relaxed), // 0..3
            self.cached_ktheory_state.load(Ordering::Relaxed),  // 0..3
            self.cached_covering_state.load(Ordering::Relaxed), // 0..3
            self.cached_tstructure_state.load(Ordering::Relaxed), // 0..3
        ];

        // Feed Atiyah-Bott fixed-point localization meta-controller.
        // Tracks concentration of anomaly signal across the base controller set.
        {
            let ab_code = {
                let mut ab = self.atiyah_bott.lock();
                ab.observe_and_update(&base_severity);
                match ab.state() {
                    LocalizationState::Calibrating => 0u8,
                    LocalizationState::Distributed => 1u8,
                    LocalizationState::Localized => 2u8,
                    LocalizationState::ConcentratedAnomaly => 3u8,
                }
            };
            self.cached_atiyah_bott_state
                .store(ab_code, Ordering::Relaxed);
        }

        // Feed SOS polynomial invariant meta-controller.
        // Checks cross-controller quadratic coherence invariants.
        {
            let sos_code = {
                let mut sos = self.sos.lock();
                sos.observe_and_update(&base_severity);
                match sos.state() {
                    SosState::Calibrating => 0u8,
                    SosState::InvariantSatisfied => 1u8,
                    SosState::InvariantStressed => 2u8,
                    SosState::InvariantViolated => 3u8,
                }
            };
            self.cached_sos_state.store(sos_code, Ordering::Relaxed);
        }

        // Feed spectral-sequence obstruction detector.
        // Tracks d² ≈ 0 (exactness) across tracked controller pairs.
        {
            let obs_code = {
                let mut obs = self.obstruction.lock();
                obs.observe_and_update(&base_severity);
                match obs.state() {
                    ObstructionState::Calibrating => 0u8,
                    ObstructionState::Exact => 1u8,
                    ObstructionState::MinorObstruction => 2u8,
                    ObstructionState::CriticalObstruction => 3u8,
                }
            };
            self.cached_obstruction_state
                .store(obs_code, Ordering::Relaxed);
        }

        // Feed operator-norm spectral radius stability monitor.
        // Tracks ensemble dynamics amplification via online power iteration.
        {
            let on_code = {
                let mut on = self.operator_norm.lock();
                on.observe_and_update(&base_severity);
                match on.state() {
                    StabilityState::Calibrating => 0u8,
                    StabilityState::Contractive => 1u8,
                    StabilityState::Marginal => 2u8,
                    StabilityState::Unstable => 3u8,
                }
            };
            self.cached_operator_norm_state
                .store(on_code, Ordering::Relaxed);
        }

        // Feed robust fusion controller from extended severity vector.
        // Includes the 25 base controller signals plus 6 meta-controller states.
        {
            let mut severity = [0u8; 31];
            severity[..25].copy_from_slice(&base_severity);
            severity[25] = self.cached_atiyah_bott_state.load(Ordering::Relaxed); // 0..3
            severity[26] = self.cached_pomdp_state.load(Ordering::Relaxed); // 0..3
            severity[27] = self.cached_sos_state.load(Ordering::Relaxed); // 0..3
            severity[28] = self.cached_admm_state.load(Ordering::Relaxed); // 0..3
            severity[29] = self.cached_obstruction_state.load(Ordering::Relaxed); // 0..3
            severity[30] = self.cached_operator_norm_state.load(Ordering::Relaxed); // 0..3
            let summary = {
                let mut fusion = self.fusion.lock();
                fusion.observe(severity, adverse, mode)
            };
            self.cached_fusion_bonus_ppm
                .store(u64::from(summary.bonus_ppm), Ordering::Relaxed);
            self.cached_fusion_entropy_milli
                .store(u64::from(summary.entropy_milli), Ordering::Relaxed);
            self.cached_fusion_drift_ppm
                .store(u64::from(summary.drift_ppm), Ordering::Relaxed);
            self.cached_fusion_dominant_signal
                .store(summary.dominant_signal, Ordering::Relaxed);
        }

        // Record executed probes into the design kernel for online information updates.
        {
            let mut design = self.design.lock();
            if let Some(flag) = spectral_anomaly {
                design.record_probe(Probe::Spectral, flag);
            }
            if let Some(flag) = rough_anomaly {
                design.record_probe(Probe::RoughPath, flag);
            }
            if let Some(flag) = persistence_anomaly {
                design.record_probe(Probe::Persistence, flag);
            }
            if let Some(flag) = anytime_anomaly {
                design.record_probe(Probe::Anytime, flag);
            }
            if let Some(flag) = cvar_anomaly {
                design.record_probe(Probe::Cvar, flag);
            }
            if let Some(flag) = bridge_anomaly {
                design.record_probe(Probe::Bridge, flag);
            }
            if let Some(flag) = ld_anomaly {
                design.record_probe(Probe::LargeDeviations, flag);
            }
            if let Some(flag) = hji_anomaly {
                design.record_probe(Probe::Hji, flag);
            }
            if let Some(flag) = mfg_anomaly {
                design.record_probe(Probe::MeanField, flag);
            }
            if let Some(flag) = padic_anomaly {
                design.record_probe(Probe::Padic, flag);
            }
            if let Some(flag) = symplectic_anomaly {
                design.record_probe(Probe::Symplectic, flag);
            }
            if let Some(flag) = topos_anomaly {
                design.record_probe(Probe::HigherTopos, flag);
            }
            if let Some(flag) = audit_anomaly {
                design.record_probe(Probe::CommitmentAudit, flag);
            }
            if let Some(flag) = changepoint_anomaly {
                design.record_probe(Probe::Changepoint, flag);
            }
            if let Some(flag) = conformal_anomaly {
                design.record_probe(Probe::Conformal, flag);
            }
            if let Some(flag) = loss_minimizer_anomaly {
                design.record_probe(Probe::LossMinimizer, flag);
            }
            if let Some(flag) = coupling_anomaly {
                design.record_probe(Probe::Coupling, flag);
            }
        }

        // Feed allocator frees into primal-dual quarantine controller.
        if matches!(family, ApiFamily::Allocator) {
            let mut quarantine = self.quarantine.lock();
            let updated = quarantine.record_free(estimated_cost_ns, adverse);
            if updated {
                publish_depth(&quarantine);
            }
        }

        // For non-pointer families we only have coarse stage-exit information.
        // PointerValidation feeds exact stage exits via `note_check_order_outcome`.
        if !matches!(family, ApiFamily::PointerValidation) {
            let ctx = CheckContext {
                family: family as u8,
                aligned: estimated_cost_ns <= 16 && !adverse,
                recent_page: !adverse,
            };
            let exit_stage = if adverse {
                Some(3)
            } else if matches!(profile, ValidationProfile::Fast) {
                Some(1)
            } else {
                None
            };
            let mut oracle = self.sampled_oracle.lock();
            let ordering_used = *oracle.get_ordering(&ctx);
            oracle.report_outcome(&ctx, &ordering_used, exit_stage);
        }
    }

    /// Record overlap information for cross-shard consistency checks.
    ///
    /// Returns true when overlap is consistent, false when a cocycle fault is detected.
    pub fn note_overlap(&self, left_shard: usize, right_shard: usize, witness_hash: u64) -> bool {
        self.cohomology
            .note_overlap(left_shard, right_shard, witness_hash)
    }

    /// Point-in-time kernel snapshot.
    #[must_use]
    pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot {
        let limits = self.controller.limits(mode);
        let tropical_full_wcl_ns = self.tropical.lock().worst_case_bound(PipelinePath::Full);
        let spectral_sig = self.spectral.lock().signature();
        let rp_summary = self.rough_path.lock().summary();
        let pd = self.persistence.lock();
        let pd_summary = pd.last_summary();
        let pd_anomaly_count = pd.anomaly_count();
        drop(pd);
        let anytime = self.anytime.lock();
        let anytime_max_e_value = anytime.max_e_value();
        let anytime_alarmed_families = anytime.alarmed_family_count();
        drop(anytime);
        let cvar = self.cvar.lock();
        let cvar_max_robust_ns = cvar.max_family_robust_cvar_ns();
        let cvar_alarmed_families = cvar.alarmed_family_count(mode);
        drop(cvar);
        let bridge_summary = self.bridge.lock().summary();
        let ld = self.large_dev.lock();
        let ld_elevated_families = ld.elevated_family_count();
        let ld_max_anomaly_count = ld.max_anomaly_count();
        drop(ld);
        let hji_summary = self.hji.lock().summary();
        let mfg_summary = self.mfg.lock().summary();
        let padic_summary = self.padic.lock().summary();
        let symplectic_summary = self.symplectic.lock().summary();
        let topos_summary = self.topos.lock().summary();
        let audit_summary = self.audit.lock().summary();
        let changepoint_summary = self.changepoint.lock().summary();
        let conformal_summary = self.conformal.lock().summary();
        let design_summary = self.design.lock().summary();
        let sparse_summary = self.sparse.lock().summary();
        let equivariant_summary = self.equivariant.lock().summary();
        let ktheory_summary = self.ktheory.lock().summary();
        let covering_summary = self.covering.lock().summary();
        let tstructure_summary = self.tstructure.lock().summary();
        let atiyah_bott_summary = self.atiyah_bott.lock().summary();
        let pomdp_summary = self.pomdp.lock().summary();
        let sos_summary = self.sos.lock().summary();
        let admm_summary = self.admm.lock().summary();
        let obstruction_summary = self.obstruction.lock().summary();
        let operator_norm_summary = self.operator_norm.lock().summary();
        let provenance_snapshot = self.provenance.lock().snapshot();
        let grobner_snapshot = self.grobner.lock().snapshot();
        let grothendieck_snapshot = self.grothendieck.lock().snapshot();
        let microlocal_summary = self.microlocal.lock().summary();
        let serre_summary = self.serre.lock().summary();
        let clifford_summary = self.clifford.lock().summary();
        RuntimeKernelSnapshot {
            decisions: self.decisions.load(Ordering::Relaxed),
            consistency_faults: self.cohomology.fault_count(),
            full_validation_trigger_ppm: limits.full_validation_trigger_ppm,
            repair_trigger_ppm: limits.repair_trigger_ppm,
            sampled_risk_bonus_ppm: self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32,
            pareto_cumulative_regret_milli: self.pareto.cumulative_regret_milli(),
            pareto_cap_enforcements: self.pareto.cap_enforcement_count(),
            pareto_exhausted_families: self.pareto.exhausted_family_count(mode),
            quarantine_depth: current_depth(),
            tropical_full_wcl_ns,
            spectral_edge_ratio: spectral_sig.edge_ratio,
            spectral_phase_transition: spectral_sig.phase != PhaseState::Stationary,
            signature_anomaly_score: rp_summary.anomaly_score,
            signature_anomaly_count: rp_summary.anomaly_count,
            persistence_entropy: pd_summary.persistence_entropy,
            topo_anomaly_count: pd_anomaly_count,
            anytime_max_e_value,
            anytime_alarmed_families,
            cvar_max_robust_ns,
            cvar_alarmed_families,
            bridge_transport_distance: bridge_summary.transport_distance,
            bridge_transitioning: bridge_summary.state == BridgeState::Transitioning,
            ld_elevated_families,
            ld_max_anomaly_count,
            hji_safety_value: hji_summary.value,
            hji_breached: hji_summary.state == ReachState::Breached,
            mfg_mean_contention: mfg_summary.mean_contention,
            mfg_congestion_count: mfg_summary.congestion_count,
            padic_ultrametric_distance: padic_summary.ultrametric_distance,
            padic_drift_count: padic_summary.drift_count,
            symplectic_energy: symplectic_summary.hamiltonian_energy,
            symplectic_violation_count: symplectic_summary.violation_count,
            topos_violation_rate: topos_summary.violation_rate,
            topos_violation_count: topos_summary.violation_count,
            audit_martingale_value: audit_summary.martingale_value,
            audit_replay_count: audit_summary.replay_count,
            changepoint_posterior_short_mass: changepoint_summary.posterior_short_mass,
            changepoint_count: changepoint_summary.change_point_count,
            conformal_empirical_coverage: conformal_summary.empirical_coverage,
            conformal_violation_count: conformal_summary.violation_count,
            design_identifiability_ppm: design_summary.identifiability_ppm,
            design_selected_probes: design_summary.selected_count,
            design_budget_ns: design_summary.budget_ns,
            design_expected_cost_ns: design_summary.expected_cost_ns,
            sparse_support_size: sparse_summary.support_size,
            sparse_l1_energy: sparse_summary.l1_energy,
            sparse_residual_ewma: sparse_summary.residual_ewma,
            sparse_critical_count: sparse_summary.critical_count,
            equivariant_alignment_ppm: equivariant_summary.alignment_ppm,
            equivariant_drift_count: equivariant_summary.drift_count,
            equivariant_fractured_count: equivariant_summary.fractured_count,
            equivariant_dominant_orbit: self.cached_equivariant_orbit.load(Ordering::Relaxed),
            fusion_bonus_ppm: self.cached_fusion_bonus_ppm.load(Ordering::Relaxed) as u32,
            fusion_entropy_milli: self.cached_fusion_entropy_milli.load(Ordering::Relaxed) as u32,
            fusion_drift_ppm: self.cached_fusion_drift_ppm.load(Ordering::Relaxed) as u32,
            fusion_dominant_signal: self.cached_fusion_dominant_signal.load(Ordering::Relaxed),
            microlocal_active_strata: microlocal_summary.active_strata,
            microlocal_failure_rate: microlocal_summary.propagation_failure_rate,
            microlocal_fault_count: microlocal_summary.fault_boundary_count,
            serre_max_differential: serre_summary.max_differential,
            serre_nontrivial_cells: serre_summary.nontrivial_cells,
            serre_lifting_count: serre_summary.lifting_failure_count,
            clifford_grade2_energy: clifford_summary.grade2_energy,
            clifford_parity_imbalance: clifford_summary.parity_imbalance,
            clifford_violation_count: clifford_summary.overlap_violation_count,
            ktheory_max_transport_distance: ktheory_summary.max_transport_distance,
            ktheory_fracture_count: ktheory_summary.fracture_count,
            covering_coverage_fraction: covering_summary.coverage_fraction,
            covering_gap_count: covering_summary.gap_count,
            tstructure_max_violation_rate: tstructure_summary.max_violation_rate,
            tstructure_violation_count: tstructure_summary.orthogonality_violation_count,
            atiyah_bott_euler_weight: atiyah_bott_summary.euler_weight,
            atiyah_bott_concentration_count: atiyah_bott_summary.concentration_count,
            pomdp_optimality_gap: pomdp_summary.optimality_gap,
            pomdp_divergence_count: pomdp_summary.divergence_count,
            sos_max_stress: sos_summary.max_stress_fraction,
            sos_violation_count: sos_summary.violation_event_count,
            admm_primal_dual_gap: admm_summary.primal_dual_gap,
            admm_violation_count: admm_summary.violation_count,
            obstruction_norm: obstruction_summary.obstruction_norm,
            obstruction_critical_count: obstruction_summary.critical_count,
            operator_norm_spectral_radius: operator_norm_summary.spectral_radius,
            operator_norm_instability_count: operator_norm_summary.instability_count,
            provenance_shannon_entropy: provenance_snapshot.shannon_entropy,
            provenance_renyi_h2: provenance_snapshot.renyi_h2,
            provenance_collision_count: provenance_snapshot.collision_risk_count,
            grobner_violation_rate: grobner_snapshot.violation_rate,
            grobner_fault_count: grobner_snapshot.fault_count,
            grothendieck_violation_rate: grothendieck_snapshot.global_violation_rate,
            grothendieck_stack_fault_count: grothendieck_snapshot.stack_fault_count,
        }
    }

    fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {
        let mut sampled_risk = self.sampled_risk.lock();
        let risk_decision = sampled_risk.evaluate(
            map_family(ctx.family),
            ctx.addr_hint,
            ctx.requested_bytes.max(1),
        );
        drop(sampled_risk);

        let bonus_ppm = match risk_decision {
            RiskDecision::AlarmMode => 500_000_u32,
            RiskDecision::FullCheck => 250_000_u32,
            RiskDecision::NormalCheck => 0_u32,
            RiskDecision::FastPath => 0_u32,
        };
        self.cached_risk_bonus_ppm
            .store(u64::from(bonus_ppm), Ordering::Relaxed);

        let oracle_ctx = CheckContext {
            family: ctx.family as u8,
            aligned: ctx.addr_hint & 0x7 == 0,
            recent_page: !ctx.bloom_negative,
        };
        let mut oracle = self.sampled_oracle.lock();
        let ordering = *oracle.get_ordering(&oracle_ctx);
        let exit_stage = match risk_decision {
            RiskDecision::AlarmMode | RiskDecision::FullCheck => Some(3),
            RiskDecision::FastPath if !ctx.bloom_negative => Some(1),
            _ => None,
        };
        oracle.report_outcome(&oracle_ctx, &ordering, exit_stage);

        let bias = oracle_bias_from_ordering(&ordering, mode);
        self.cached_oracle_bias[usize::from(ctx.family as u8)].store(bias, Ordering::Relaxed);
    }
}

impl Default for RuntimeMathKernel {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_policy_id(
    mode: SafetyLevel,
    family: ApiFamily,
    profile: ValidationProfile,
    action: MembraneAction,
) -> u32 {
    let mode_bits: u32 = match mode {
        SafetyLevel::Strict => 1,
        SafetyLevel::Hardened => 2,
        SafetyLevel::Off => 3,
    };
    let profile_bits: u32 = match profile {
        ValidationProfile::Fast => 1,
        ValidationProfile::Full => 2,
    };
    let action_bits: u32 = match action {
        MembraneAction::Allow => 1,
        MembraneAction::FullValidate => 2,
        MembraneAction::Repair(_) => 3,
        MembraneAction::Deny => 4,
    };

    (mode_bits << 28)
        | ((u32::from(family as u8) & 0xFF) << 16)
        | ((profile_bits & 0xF) << 8)
        | (action_bits & 0xF)
}

fn map_family(family: ApiFamily) -> CallFamily {
    match family {
        ApiFamily::PointerValidation => CallFamily::Memory,
        ApiFamily::Allocator => CallFamily::Alloc,
        ApiFamily::StringMemory => CallFamily::String,
        ApiFamily::Stdio => CallFamily::Stdio,
        ApiFamily::Threading => CallFamily::Thread,
        ApiFamily::Resolver => CallFamily::Socket,
        ApiFamily::MathFenv => CallFamily::Other,
        ApiFamily::Loader => CallFamily::Other,
        ApiFamily::Stdlib => CallFamily::String,
    }
}

/// 0 => full-bias, 1 => neutral, 2 => fast-bias.
fn oracle_bias_from_ordering(ordering: &[CheckStage; 7], mode: SafetyLevel) -> u8 {
    let first = ordering[0];
    let second = ordering[1];

    if matches!(first, CheckStage::Null)
        && matches!(
            second,
            CheckStage::Arena | CheckStage::Fingerprint | CheckStage::Canary
        )
    {
        return 0;
    }
    if matches!(first, CheckStage::Null)
        && matches!(second, CheckStage::TlsCache)
        && !mode.heals_enabled()
    {
        return 2;
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_can_escalate_to_full() {
        let kernel = RuntimeMathKernel::new();
        let decision = kernel.decide(
            SafetyLevel::Hardened,
            RuntimeContext {
                family: ApiFamily::Allocator,
                addr_hint: 0x2000,
                requested_bytes: 8192,
                is_write: true,
                contention_hint: 128,
                bloom_negative: true,
            },
        );
        assert!(decision.requires_full_validation());
    }

    #[test]
    fn strict_decision_is_policy_tagged() {
        let kernel = RuntimeMathKernel::new();
        let decision = kernel.decide(
            SafetyLevel::Strict,
            RuntimeContext::pointer_validation(0x1000, false),
        );
        assert_ne!(decision.policy_id, 0);
    }

    #[test]
    fn observe_updates_snapshot() {
        let kernel = RuntimeMathKernel::new();
        kernel.observe_validation_result(
            ApiFamily::PointerValidation,
            ValidationProfile::Fast,
            7,
            false,
        );
        kernel.observe_validation_result(
            ApiFamily::PointerValidation,
            ValidationProfile::Full,
            45,
            true,
        );
        let snap = kernel.snapshot(SafetyLevel::Hardened);
        assert!(snap.decisions <= 2);
        assert!(snap.full_validation_trigger_ppm > 0);
    }

    #[test]
    fn explicit_oracle_feedback_updates_bias_cache() {
        let kernel = RuntimeMathKernel::new();
        let ordering = kernel.check_ordering(ApiFamily::PointerValidation, true, true);
        kernel.note_check_order_outcome(
            ApiFamily::PointerValidation,
            true,
            true,
            &ordering,
            Some(1),
        );
        let bias = kernel.cached_oracle_bias[usize::from(ApiFamily::PointerValidation as u8)]
            .load(Ordering::Relaxed);
        assert!(bias <= 2);
    }

    #[test]
    fn snapshot_literal_never_relocks_summary_mutexes() {
        let src = include_str!("mod.rs");
        let snapshot_fn_start = src
            .find("pub fn snapshot(&self, mode: SafetyLevel) -> RuntimeKernelSnapshot")
            .expect("snapshot function signature must exist");
        let snapshot_tail = &src[snapshot_fn_start..];
        let resample_fn_start = snapshot_tail
            .find("fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {")
            .expect("resample function must follow snapshot");
        let snapshot_src = &snapshot_tail[..resample_fn_start];

        let struct_start = snapshot_src
            .find("RuntimeKernelSnapshot {\n            decisions:")
            .expect("snapshot must build RuntimeKernelSnapshot struct literal");
        let struct_literal = &snapshot_src[struct_start..];
        assert!(
            !struct_literal.contains(".lock()"),
            "snapshot struct literal must only read cached locals; direct mutex locking in the literal can deadlock"
        );

        for needle in [
            "let tropical_full_wcl_ns = self.tropical.lock().worst_case_bound(PipelinePath::Full);",
            "let spectral_sig = self.spectral.lock().signature();",
            "let rp_summary = self.rough_path.lock().summary();",
            "let bridge_summary = self.bridge.lock().summary();",
            "let hji_summary = self.hji.lock().summary();",
            "let mfg_summary = self.mfg.lock().summary();",
            "let padic_summary = self.padic.lock().summary();",
            "let symplectic_summary = self.symplectic.lock().summary();",
            "let topos_summary = self.topos.lock().summary();",
            "let audit_summary = self.audit.lock().summary();",
            "let changepoint_summary = self.changepoint.lock().summary();",
            "let conformal_summary = self.conformal.lock().summary();",
            "let design_summary = self.design.lock().summary();",
            "let sparse_summary = self.sparse.lock().summary();",
            "let equivariant_summary = self.equivariant.lock().summary();",
            "let ktheory_summary = self.ktheory.lock().summary();",
            "let covering_summary = self.covering.lock().summary();",
            "let tstructure_summary = self.tstructure.lock().summary();",
            "let atiyah_bott_summary = self.atiyah_bott.lock().summary();",
            "let pomdp_summary = self.pomdp.lock().summary();",
            "let sos_summary = self.sos.lock().summary();",
            "let admm_summary = self.admm.lock().summary();",
            "let obstruction_summary = self.obstruction.lock().summary();",
            "let operator_norm_summary = self.operator_norm.lock().summary();",
            "let provenance_snapshot = self.provenance.lock().snapshot();",
            "let grobner_snapshot = self.grobner.lock().snapshot();",
            "let grothendieck_snapshot = self.grothendieck.lock().snapshot();",
            "let microlocal_summary = self.microlocal.lock().summary();",
            "let serre_summary = self.serre.lock().summary();",
            "let clifford_summary = self.clifford.lock().summary();",
        ] {
            assert_eq!(
                snapshot_src.matches(needle).count(),
                1,
                "snapshot must cache exactly one local for `{needle}` before struct construction"
            );
        }
    }

    #[test]
    fn observe_validation_result_records_all_probe_anomalies() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        for needle in [
            "if let Some(flag) = spectral_anomaly {\n                design.record_probe(Probe::Spectral, flag);",
            "if let Some(flag) = rough_anomaly {\n                design.record_probe(Probe::RoughPath, flag);",
            "if let Some(flag) = persistence_anomaly {\n                design.record_probe(Probe::Persistence, flag);",
            "if let Some(flag) = anytime_anomaly {\n                design.record_probe(Probe::Anytime, flag);",
            "if let Some(flag) = cvar_anomaly {\n                design.record_probe(Probe::Cvar, flag);",
            "if let Some(flag) = bridge_anomaly {\n                design.record_probe(Probe::Bridge, flag);",
            "if let Some(flag) = ld_anomaly {\n                design.record_probe(Probe::LargeDeviations, flag);",
            "if let Some(flag) = hji_anomaly {\n                design.record_probe(Probe::Hji, flag);",
            "if let Some(flag) = mfg_anomaly {\n                design.record_probe(Probe::MeanField, flag);",
            "if let Some(flag) = padic_anomaly {\n                design.record_probe(Probe::Padic, flag);",
            "if let Some(flag) = symplectic_anomaly {\n                design.record_probe(Probe::Symplectic, flag);",
            "if let Some(flag) = topos_anomaly {\n                design.record_probe(Probe::HigherTopos, flag);",
            "if let Some(flag) = audit_anomaly {\n                design.record_probe(Probe::CommitmentAudit, flag);",
            "if let Some(flag) = changepoint_anomaly {\n                design.record_probe(Probe::Changepoint, flag);",
            "if let Some(flag) = conformal_anomaly {\n                design.record_probe(Probe::Conformal, flag);",
            "if let Some(flag) = loss_minimizer_anomaly {\n                design.record_probe(Probe::LossMinimizer, flag);",
            "if let Some(flag) = coupling_anomaly {\n                design.record_probe(Probe::Coupling, flag);",
        ] {
            assert!(
                observe_src.contains(needle),
                "observe_validation_result must feed design kernel with `{needle}`"
            );
        }
    }

    #[test]
    fn high_risk_aggregation_literals_are_lock_free() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        let base_start = observe_src
            .find("let base_severity: [u8; 25] = [")
            .expect("base_severity literal must exist");
        let base_tail = &observe_src[base_start..];
        let base_end = base_tail
            .find("];")
            .expect("base_severity literal must terminate");
        let base_literal = &base_tail[..base_end + 2];
        assert!(
            !base_literal.contains(".lock()"),
            "base_severity aggregation must use cached atomics only (no locking in literal)"
        );

        let fusion_start = observe_src
            .find("let mut severity = [0u8; 31];")
            .expect("fusion severity buffer must exist");
        let fusion_tail = &observe_src[fusion_start..];
        let fusion_end = fusion_tail
            .find("let summary = {")
            .expect("fusion summary acquisition block must exist");
        let fusion_literal = &fusion_tail[..fusion_end];
        assert!(
            !fusion_literal.contains(".lock()"),
            "fusion severity aggregation must use cached atomics only (no locking in literal)"
        );
    }

    #[test]
    fn grobner_state_vector_literal_is_lock_free() {
        let src = include_str!("mod.rs");
        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        let state_vec_start = observe_src
            .find("let state_vec = [")
            .expect("grobner state_vec literal must exist");
        let state_vec_tail = &observe_src[state_vec_start..];
        let state_vec_end = state_vec_tail
            .find("];")
            .expect("grobner state_vec literal must terminate");
        let state_vec_literal = &state_vec_tail[..state_vec_end + 2];

        assert!(
            !state_vec_literal.contains(".lock()"),
            "grobner state_vec aggregation must use cached atomics only (no locking in literal)"
        );
    }

    #[test]
    fn resample_high_order_kernels_has_no_multi_lock_statements() {
        let src = include_str!("mod.rs");
        let resample_start = src
            .find("fn resample_high_order_kernels(&self, mode: SafetyLevel, ctx: RuntimeContext) {")
            .expect("resample_high_order_kernels must exist");
        let resample_tail = &src[resample_start..];
        let resample_end = resample_tail
            .find("\n}\n\nimpl Default for RuntimeMathKernel")
            .expect("resample_high_order_kernels end marker must exist");
        let resample_src = &resample_tail[..resample_end];

        for (idx, line) in resample_src.lines().enumerate() {
            let lock_count = line.matches(".lock()").count();
            assert!(
                lock_count <= 1,
                "resample_high_order_kernels line {} contains multiple lock() calls: `{}`",
                idx + 1,
                line.trim()
            );
        }
    }

    #[test]
    fn decide_pre_design_aggregation_is_lock_free() {
        let src = include_str!("mod.rs");
        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let pre_design_start = decide_tail
            .find("let base_risk_ppm = self.risk.upper_bound_ppm(ctx.family);")
            .expect("base risk aggregation start must exist");
        let pre_design_tail = &decide_tail[pre_design_start..];
        let pre_design_end = pre_design_tail
            .find("let design_bonus = {")
            .expect("design bonus block must exist");
        let pre_design_src = &pre_design_tail[..pre_design_end];

        assert!(
            !pre_design_src.contains(".lock()"),
            "pre-design risk aggregation must only consume cached atomics; no mutex locking allowed"
        );
    }

    #[test]
    fn decide_and_observe_critical_regions_avoid_multi_lock_statements() {
        let src = include_str!("mod.rs");

        let decide_start = src
            .find(
                "pub fn decide(&self, mode: SafetyLevel, ctx: RuntimeContext) -> RuntimeDecision {",
            )
            .expect("decide must exist");
        let decide_tail = &src[decide_start..];
        let decide_end = decide_tail
            .find("/// Return the current contextual check ordering for a given family/context.")
            .expect("decide end marker must exist");
        let decide_src = &decide_tail[..decide_end];

        let observe_start = src
            .find("pub fn observe_validation_result(")
            .expect("observe_validation_result must exist");
        let observe_tail = &src[observe_start..];
        let observe_end = observe_tail
            .find("/// Record overlap information for cross-shard consistency checks.")
            .expect("observe_validation_result end marker must exist");
        let observe_src = &observe_tail[..observe_end];

        for (label, body) in [
            ("decide", decide_src),
            ("observe_validation_result", observe_src),
        ] {
            for (idx, line) in body.lines().enumerate() {
                let lock_count = line.matches(".lock()").count();
                assert!(
                    lock_count <= 1,
                    "{label} line {} contains multiple lock() calls: `{}`",
                    idx + 1,
                    line.trim()
                );
            }
        }
    }
}
