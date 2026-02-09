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

pub mod bandit;
pub mod barrier;
pub mod cohomology;
pub mod control;
pub mod risk;

use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};

use parking_lot::Mutex;

use crate::check_oracle::{CheckContext, CheckOracle, CheckStage};
use crate::config::SafetyLevel;
use crate::heal::HealingAction;
use crate::quarantine_controller::{QuarantineController, current_depth, publish_depth};
use crate::risk_engine::{CallFamily, RiskDecision, RiskEngine};
use crate::spectral_monitor::{PhaseState, SpectralMonitor};
use crate::tropical_latency::{PipelinePath, TROPICAL_METRICS, TropicalLatencyCompositor};

use self::bandit::ConstrainedBanditRouter;
use self::barrier::BarrierOracle;
use self::cohomology::CohomologyMonitor;
use self::control::PrimalDualController;
use self::risk::ConformalRiskEngine;

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
}

impl ApiFamily {
    pub const COUNT: usize = 8;
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
    pub quarantine_depth: usize,
    /// Tropical worst-case latency for the full pipeline path (ns).
    pub tropical_full_wcl_ns: u64,
    /// Spectral edge ratio (max_eigenvalue / median_eigenvalue).
    pub spectral_edge_ratio: f64,
    /// Whether a spectral phase transition is active.
    pub spectral_phase_transition: bool,
}

/// Online control kernel for strict/hardened runtime decisions.
pub struct RuntimeMathKernel {
    risk: ConformalRiskEngine,
    router: ConstrainedBanditRouter,
    controller: PrimalDualController,
    barrier: BarrierOracle,
    cohomology: CohomologyMonitor,
    sampled_risk: Mutex<RiskEngine>,
    sampled_oracle: Mutex<CheckOracle>,
    quarantine: Mutex<QuarantineController>,
    tropical: Mutex<TropicalLatencyCompositor>,
    spectral: Mutex<SpectralMonitor>,
    cached_risk_bonus_ppm: AtomicU64,
    cached_oracle_bias: [AtomicU8; ApiFamily::COUNT],
    cached_spectral_phase: AtomicU8,
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
            sampled_risk: Mutex::new(RiskEngine::new()),
            sampled_oracle: Mutex::new(CheckOracle::new()),
            quarantine: Mutex::new(QuarantineController::new()),
            tropical: Mutex::new(TropicalLatencyCompositor::new()),
            spectral: Mutex::new(SpectralMonitor::new()),
            cached_risk_bonus_ppm: AtomicU64::new(0),
            cached_oracle_bias: std::array::from_fn(|_| AtomicU8::new(1)),
            cached_spectral_phase: AtomicU8::new(0),
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
        let risk_upper_bound_ppm = base_risk_ppm
            .saturating_add(sampled_bonus)
            .saturating_add(cohomology_bonus)
            .saturating_add(tropical_bonus)
            .saturating_add(spectral_bonus)
            .min(1_000_000);

        let limits = self.controller.limits(mode);
        let mut profile =
            self.router
                .select_profile(ctx.family, mode, risk_upper_bound_ppm, ctx.contention_hint);

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

        // Adaptive allocator guard: when quarantine depth is low under elevated
        // risk, force full validation to preserve temporal safety.
        if matches!(ctx.family, ApiFamily::Allocator)
            && mode.heals_enabled()
            && current_depth() < 128
            && risk_upper_bound_ppm >= limits.repair_trigger_ppm / 2
        {
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

    /// Feed observed runtime outcome back into online controllers.
    pub fn observe_validation_result(
        &self,
        family: ApiFamily,
        profile: ValidationProfile,
        estimated_cost_ns: u64,
        adverse: bool,
    ) {
        self.risk.observe(family, adverse);
        self.router
            .observe(family, profile, estimated_cost_ns, adverse);
        self.controller.observe(estimated_cost_ns, adverse);

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
        {
            let contention = f64::from(
                self.cached_oracle_bias[usize::from(family as u8)].load(Ordering::Relaxed),
            ) / 2.0;
            let hit_rate = if adverse { 1.0 } else { 0.0 };
            let risk_score = f64::from(self.risk.upper_bound_ppm(family)) / 1_000_000.0;
            let latency = (estimated_cost_ns as f64).ln_1p();
            let mut spectral = self.spectral.lock();
            spectral.observe(risk_score, latency, contention, hit_rate);
            // Cache the phase state for the hot-path decision.
            let phase_code = match spectral.phase() {
                PhaseState::Stationary => 0u8,
                PhaseState::Transitioning => 1u8,
                PhaseState::NewRegime => 2u8,
            };
            self.cached_spectral_phase
                .store(phase_code, Ordering::Relaxed);
        }

        // Feed allocator frees into primal-dual quarantine controller.
        if matches!(family, ApiFamily::Allocator) {
            let mut quarantine = self.quarantine.lock();
            let updated = quarantine.record_free(estimated_cost_ns, adverse);
            if updated {
                publish_depth(&quarantine);
            }
        }

        // Feed coarse observations into contextual check oracle for future
        // ordering bias (full precision context is refreshed in sampled path).
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
        RuntimeKernelSnapshot {
            decisions: self.decisions.load(Ordering::Relaxed),
            consistency_faults: self.cohomology.fault_count(),
            full_validation_trigger_ppm: limits.full_validation_trigger_ppm,
            repair_trigger_ppm: limits.repair_trigger_ppm,
            sampled_risk_bonus_ppm: self.cached_risk_bonus_ppm.load(Ordering::Relaxed) as u32,
            quarantine_depth: current_depth(),
            tropical_full_wcl_ns,
            spectral_edge_ratio: spectral_sig.edge_ratio,
            spectral_phase_transition: spectral_sig.phase != PhaseState::Stationary,
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
}
