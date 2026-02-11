//! Decision-theoretic expected-loss minimization for hardened repair policy selection.
//!
//! **Math item #4**: proper scoring rules / decision-theoretic loss minimization.
//!
//! This controller implements:
//! - explicit per-API-family loss matrices over `C ∈ {Clean, Adverse}`,
//! - online posterior tracking `P(C=Adverse | evidence)` via a Beta model,
//! - runtime decision law: `argmin_a E[L(a, C) | evidence]`,
//! - competing-action cost tracking for evidence/audit attribution.

#![deny(unsafe_code)]

use super::ApiFamily;

/// Number of observations required before leaving `Calibrating`.
const WARMUP_COUNT: u64 = 32;
/// EWMA smoothing factor for per-action loss tracking.
const EWMA_ALPHA: f64 = 0.05;
/// Cost normalization divisor: maps nanosecond costs into a compact range.
const COST_NORM_NS: f64 = 1000.0;
/// Threshold ratio between highest and lowest loss EWMA for bias detection.
const BIAS_RATIO: f64 = 2.5;
/// Absolute loss threshold: when all action losses exceed this, classify as explosion.
const COST_EXPLOSION_THRESHOLD: f64 = 2.0;

const NUM_ACTIONS: usize = 4;
const ACTION_ALLOW: usize = 0;
const ACTION_FULL_VALIDATE: usize = 1;
const ACTION_REPAIR: usize = 2;
const ACTION_DENY: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
struct ActionLossModel {
    clean_intercept: f64,
    adverse_intercept: f64,
    clean_cost_factor: f64,
    adverse_cost_factor: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct FamilyLossMatrix {
    actions: [ActionLossModel; NUM_ACTIONS],
}

const fn action_model(
    clean_intercept: f64,
    adverse_intercept: f64,
    clean_cost_factor: f64,
    adverse_cost_factor: f64,
) -> ActionLossModel {
    ActionLossModel {
        clean_intercept,
        adverse_intercept,
        clean_cost_factor,
        adverse_cost_factor,
    }
}

const fn family_matrix(
    allow_adverse: f64,
    deny_clean: f64,
    validate_adverse: f64,
    repair_adverse: f64,
) -> FamilyLossMatrix {
    FamilyLossMatrix {
        actions: [
            action_model(0.0, allow_adverse, 0.08, 1.00),    // Allow
            action_model(0.5, validate_adverse, 0.30, 0.35), // FullValidate
            action_model(0.6, repair_adverse, 0.35, 0.40),   // Repair
            action_model(deny_clean, deny_clean, 0.00, 0.10), // Deny
        ],
    }
}

const fn loss_matrix_for_family(family: ApiFamily) -> FamilyLossMatrix {
    match family {
        ApiFamily::PointerValidation => family_matrix(11.0, 1.8, 1.6, 0.9),
        ApiFamily::Allocator => family_matrix(12.0, 1.7, 1.8, 0.8),
        ApiFamily::StringMemory => family_matrix(13.0, 2.1, 2.0, 0.9),
        ApiFamily::Stdio => family_matrix(9.0, 2.5, 1.4, 0.8),
        ApiFamily::Threading => family_matrix(10.5, 2.7, 1.7, 0.95),
        ApiFamily::Resolver => family_matrix(8.5, 3.0, 1.3, 0.9),
        ApiFamily::MathFenv => family_matrix(7.0, 1.6, 1.2, 0.75),
        ApiFamily::Loader => family_matrix(14.0, 1.4, 2.1, 1.0),
        ApiFamily::Stdlib => family_matrix(8.5, 2.0, 1.3, 0.8),
        ApiFamily::Ctype => family_matrix(6.0, 1.3, 1.1, 0.7),
        ApiFamily::Time => family_matrix(7.0, 1.9, 1.2, 0.75),
        ApiFamily::Signal => family_matrix(12.5, 1.2, 2.2, 1.2),
        ApiFamily::IoFd => family_matrix(11.0, 2.2, 1.8, 0.9),
        ApiFamily::Socket => family_matrix(10.0, 2.6, 1.6, 0.9),
        ApiFamily::Locale => family_matrix(8.0, 2.4, 1.3, 0.85),
        ApiFamily::Termios => family_matrix(8.5, 2.3, 1.4, 0.85),
        ApiFamily::Inet => family_matrix(9.0, 2.5, 1.5, 0.88),
        ApiFamily::Process => family_matrix(11.5, 1.8, 1.9, 1.0),
        ApiFamily::VirtualMemory => family_matrix(13.5, 1.5, 2.0, 1.05),
        ApiFamily::Poll => family_matrix(8.0, 2.1, 1.3, 0.82),
    }
}

/// Point-in-time expected-loss evidence used by runtime ledger export.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LossDecisionEvidence {
    /// API family the evidence corresponds to.
    pub family: ApiFamily,
    /// Posterior probability `P(C=Adverse | evidence)`.
    pub posterior_adverse_prob: f64,
    /// Expected loss for `[Allow, FullValidate, Repair, Deny]`.
    pub expected_losses: [f64; NUM_ACTIONS],
    /// Selected action `argmin_a E[L(a,C)|evidence]`.
    pub selected_action: u8,
    /// Closest competing action (second-lowest expected loss).
    pub competing_action: u8,
    /// Expected loss for the selected action.
    pub selected_expected_loss: f64,
    /// Expected loss for the competing action.
    pub competing_expected_loss: f64,
}

/// Qualitative state of the loss minimization controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossState {
    /// Fewer than `WARMUP_COUNT` observations received.
    Calibrating,
    /// All action losses are within a reasonable ratio of each other.
    Balanced,
    /// Repair action has substantially lower loss than others (repair-biased).
    RepairBiased,
    /// Deny action has substantially lower loss than others (deny-biased).
    DenyBiased,
    /// All action losses exceed `COST_EXPLOSION_THRESHOLD` simultaneously.
    CostExplosion,
}

/// Point-in-time summary of the loss minimization controller.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LossSummary {
    /// Current qualitative state.
    pub state: LossState,
    /// Recommended action (0=allow, 1=full-validate, 2=repair, 3=deny).
    pub recommended_action: u8,
    /// EWMA-smoothed loss for the Repair action.
    pub repair_loss_ewma: f64,
    /// EWMA-smoothed loss for the Deny action.
    pub deny_loss_ewma: f64,
    /// EWMA-smoothed loss for the Allow action.
    pub allow_loss_ewma: f64,
    /// Posterior probability `P(C=Adverse | evidence)` for latest family.
    pub posterior_adverse_prob: f64,
    /// Expected loss for selected action.
    pub selected_expected_loss: f64,
    /// Competing action id.
    pub competing_action: u8,
    /// Expected loss for competing action.
    pub competing_expected_loss: f64,
    /// Total observations fed to the controller.
    pub total_decisions: u64,
    /// Number of times `CostExplosion` state was entered.
    pub cost_explosion_count: u64,
}

/// Online loss minimization controller for hardened repair policy selection.
pub struct LossMinimizationController {
    /// Per-action EWMA-smoothed observed loss: [allow, full_validate, repair, deny].
    loss_ewma: [f64; NUM_ACTIONS],
    /// Per-action observation count.
    action_counts: [u64; NUM_ACTIONS],
    /// Beta posterior α for each API family (adverse observations).
    posterior_alpha: [f64; ApiFamily::COUNT],
    /// Beta posterior β for each API family (clean observations).
    posterior_beta: [f64; ApiFamily::COUNT],
    /// Latest family-conditioned decision evidence.
    last_evidence: LossDecisionEvidence,
    /// Total observations received.
    total_decisions: u64,
    /// Number of times `CostExplosion` state was entered.
    cost_explosion_count: u64,
    /// Current qualitative state.
    state: LossState,
}

impl LossMinimizationController {
    /// Create a new controller in the `Calibrating` state.
    #[must_use]
    pub fn new() -> Self {
        let initial_family = ApiFamily::PointerValidation;
        let initial_posterior = 0.5;
        let initial_expected = compute_expected_losses(initial_family, initial_posterior, 0.0);
        let (selected_idx, competing_idx) = rank_actions(&initial_expected);
        Self {
            loss_ewma: [0.0; NUM_ACTIONS],
            action_counts: [0; NUM_ACTIONS],
            posterior_alpha: [1.0; ApiFamily::COUNT],
            posterior_beta: [1.0; ApiFamily::COUNT],
            last_evidence: LossDecisionEvidence {
                family: initial_family,
                posterior_adverse_prob: initial_posterior,
                expected_losses: initial_expected,
                selected_action: selected_idx as u8,
                competing_action: competing_idx as u8,
                selected_expected_loss: initial_expected[selected_idx],
                competing_expected_loss: initial_expected[competing_idx],
            },
            total_decisions: 0,
            cost_explosion_count: 0,
            state: LossState::Calibrating,
        }
    }

    /// Feed one observation for a specific API family.
    ///
    /// Decision law:
    /// `a* = argmin_a E[L(a, C) | evidence]`.
    pub fn observe(
        &mut self,
        family: ApiFamily,
        action_taken: u8,
        adverse: bool,
        estimated_cost_ns: u64,
    ) {
        self.total_decisions += 1;
        let action_idx = (action_taken as usize).min(NUM_ACTIONS - 1);
        self.action_counts[action_idx] += 1;

        let family_idx = usize::from(family as u8);
        if adverse {
            self.posterior_alpha[family_idx] += 1.0;
        } else {
            self.posterior_beta[family_idx] += 1.0;
        }
        let posterior_adverse_prob = self.posterior_alpha[family_idx]
            / (self.posterior_alpha[family_idx] + self.posterior_beta[family_idx]);

        let cost_norm = (estimated_cost_ns as f64 / COST_NORM_NS).min(10.0);
        let observed_losses = compute_observed_losses(family, adverse, cost_norm);
        for (i, loss) in observed_losses.iter().enumerate().take(NUM_ACTIONS) {
            self.loss_ewma[i] = EWMA_ALPHA * *loss + (1.0 - EWMA_ALPHA) * self.loss_ewma[i];
        }

        let expected_losses = compute_expected_losses(family, posterior_adverse_prob, cost_norm);
        let (selected_idx, competing_idx) = rank_actions(&expected_losses);
        self.last_evidence = LossDecisionEvidence {
            family,
            posterior_adverse_prob,
            expected_losses,
            selected_action: selected_idx as u8,
            competing_action: competing_idx as u8,
            selected_expected_loss: expected_losses[selected_idx],
            competing_expected_loss: expected_losses[competing_idx],
        };

        let prev_state = self.state;
        self.state = self.classify_state();
        if self.state == LossState::CostExplosion && prev_state != LossState::CostExplosion {
            self.cost_explosion_count += 1;
        }
    }

    /// Current qualitative state.
    #[must_use]
    pub fn state(&self) -> LossState {
        self.state
    }

    /// Latest family-conditioned expected-loss evidence.
    #[must_use]
    pub fn latest_evidence(&self) -> LossDecisionEvidence {
        self.last_evidence
    }

    /// Point-in-time summary.
    #[must_use]
    pub fn summary(&self) -> LossSummary {
        LossSummary {
            state: self.state,
            recommended_action: self.recommended_action(),
            repair_loss_ewma: self.loss_ewma[ACTION_REPAIR],
            deny_loss_ewma: self.loss_ewma[ACTION_DENY],
            allow_loss_ewma: self.loss_ewma[ACTION_ALLOW],
            posterior_adverse_prob: self.last_evidence.posterior_adverse_prob,
            selected_expected_loss: self.last_evidence.selected_expected_loss,
            competing_action: self.last_evidence.competing_action,
            competing_expected_loss: self.last_evidence.competing_expected_loss,
            total_decisions: self.total_decisions,
            cost_explosion_count: self.cost_explosion_count,
        }
    }

    /// Recommend the action with the lowest current expected loss.
    #[must_use]
    pub fn recommended_action(&self) -> u8 {
        if self.total_decisions < WARMUP_COUNT {
            // During calibration, default to full-validate (safest exploratory action).
            return ACTION_FULL_VALIDATE as u8;
        }
        self.last_evidence.selected_action
    }

    fn classify_state(&self) -> LossState {
        if self.total_decisions < WARMUP_COUNT {
            return LossState::Calibrating;
        }

        if self.loss_ewma.iter().all(|&l| l > COST_EXPLOSION_THRESHOLD) {
            return LossState::CostExplosion;
        }

        let min_loss = self.loss_ewma.iter().copied().fold(f64::INFINITY, f64::min);
        let max_loss = self
            .loss_ewma
            .iter()
            .copied()
            .fold(f64::NEG_INFINITY, f64::max);

        if min_loss > 0.0 && max_loss / min_loss > BIAS_RATIO {
            let best_action = self
                .loss_ewma
                .iter()
                .enumerate()
                .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(core::cmp::Ordering::Equal))
                .map(|(i, _)| i)
                .unwrap_or(ACTION_ALLOW);
            return match best_action {
                ACTION_REPAIR => LossState::RepairBiased,
                ACTION_DENY => LossState::DenyBiased,
                _ => LossState::Balanced,
            };
        }

        LossState::Balanced
    }
}

impl Default for LossMinimizationController {
    fn default() -> Self {
        Self::new()
    }
}

fn loss_for_class(model: ActionLossModel, adverse: bool, cost_norm: f64) -> f64 {
    let (intercept, factor) = if adverse {
        (model.adverse_intercept, model.adverse_cost_factor)
    } else {
        (model.clean_intercept, model.clean_cost_factor)
    };
    (intercept + factor * cost_norm).max(0.0)
}

fn compute_observed_losses(family: ApiFamily, adverse: bool, cost_norm: f64) -> [f64; NUM_ACTIONS] {
    let matrix = loss_matrix_for_family(family);
    core::array::from_fn(|idx| loss_for_class(matrix.actions[idx], adverse, cost_norm))
}

fn compute_expected_losses(
    family: ApiFamily,
    posterior_adverse_prob: f64,
    cost_norm: f64,
) -> [f64; NUM_ACTIONS] {
    let p = posterior_adverse_prob.clamp(0.0, 1.0);
    let matrix = loss_matrix_for_family(family);
    core::array::from_fn(|idx| {
        let adverse_loss = loss_for_class(matrix.actions[idx], true, cost_norm);
        let clean_loss = loss_for_class(matrix.actions[idx], false, cost_norm);
        p * adverse_loss + (1.0 - p) * clean_loss
    })
}

fn rank_actions(losses: &[f64; NUM_ACTIONS]) -> (usize, usize) {
    let mut order = [0usize, 1, 2, 3];
    order.sort_by(|a, b| {
        losses[*a]
            .partial_cmp(&losses[*b])
            .unwrap_or(core::cmp::Ordering::Equal)
    });
    (order[0], order[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_calibrating() {
        let ctrl = LossMinimizationController::new();
        assert_eq!(ctrl.state(), LossState::Calibrating);
        let s = ctrl.summary();
        assert_eq!(s.state, LossState::Calibrating);
        assert_eq!(s.total_decisions, 0);
        assert_eq!(s.cost_explosion_count, 0);
        assert_eq!(s.recommended_action, ACTION_FULL_VALIDATE as u8);
        assert!(s.posterior_adverse_prob > 0.0 && s.posterior_adverse_prob < 1.0);
    }

    #[test]
    fn balanced_under_uniform_outcomes() {
        let mut ctrl = LossMinimizationController::new();
        for i in 0..200_u64 {
            let action = (i % 4) as u8;
            ctrl.observe(ApiFamily::PointerValidation, action, false, 50);
        }
        assert_eq!(ctrl.state(), LossState::Balanced);
    }

    #[test]
    fn repair_bias_detection() {
        let mut ctrl = LossMinimizationController::new();
        for _ in 0..500 {
            ctrl.observe(ApiFamily::Allocator, ACTION_REPAIR as u8, true, 500);
        }
        let s = ctrl.summary();
        assert!(s.repair_loss_ewma < s.allow_loss_ewma);
        assert_eq!(s.recommended_action, ACTION_REPAIR as u8);
    }

    #[test]
    fn deny_bias_detection() {
        let mut ctrl = LossMinimizationController::new();
        for i in 0..500_u64 {
            let adverse = i % 5 != 0;
            ctrl.observe(ApiFamily::Signal, ACTION_DENY as u8, adverse, 3000);
        }
        let s = ctrl.summary();
        assert!(s.deny_loss_ewma < s.allow_loss_ewma);
        assert_eq!(s.state, LossState::DenyBiased);
    }

    #[test]
    fn cost_explosion_detection() {
        let mut ctrl = LossMinimizationController::new();
        for i in 0..1000_u64 {
            let action = (i % 4) as u8;
            ctrl.observe(ApiFamily::VirtualMemory, action, true, 500_000);
        }
        let s = ctrl.summary();
        assert!(s.repair_loss_ewma > COST_EXPLOSION_THRESHOLD);
        assert!(s.deny_loss_ewma > COST_EXPLOSION_THRESHOLD);
        assert_eq!(s.state, LossState::CostExplosion);
        assert!(s.cost_explosion_count >= 1);
    }

    #[test]
    fn recommendation_changes_with_conditions() {
        let mut ctrl = LossMinimizationController::new();
        for _ in 0..200 {
            ctrl.observe(ApiFamily::StringMemory, ACTION_ALLOW as u8, false, 10);
        }
        let rec_clean = ctrl.recommended_action();
        for _ in 0..500 {
            ctrl.observe(ApiFamily::StringMemory, ACTION_REPAIR as u8, true, 300);
        }
        let rec_adverse = ctrl.recommended_action();
        assert_ne!(rec_clean, rec_adverse);
    }

    #[test]
    fn loss_values_bounded() {
        let mut ctrl = LossMinimizationController::new();
        for i in 0..500_u64 {
            let action = (i % 4) as u8;
            let adverse = i % 7 == 0;
            ctrl.observe(
                ApiFamily::PointerValidation,
                action,
                adverse,
                (i * 10) % 2000,
            );
        }
        let s = ctrl.summary();
        assert!(s.allow_loss_ewma >= 0.0);
        assert!(s.repair_loss_ewma >= 0.0);
        assert!(s.deny_loss_ewma >= 0.0);
        assert!(s.allow_loss_ewma < 50.0);
        assert!(s.repair_loss_ewma < 50.0);
        assert!(s.deny_loss_ewma < 50.0);
        assert_eq!(s.total_decisions, 500);
        assert!(s.recommended_action <= ACTION_DENY as u8);
    }

    #[test]
    fn family_loss_matrices_are_explicitly_distinct() {
        let ptr = loss_matrix_for_family(ApiFamily::PointerValidation);
        let strm = loss_matrix_for_family(ApiFamily::StringMemory);
        let sig = loss_matrix_for_family(ApiFamily::Signal);
        assert_ne!(
            ptr.actions[ACTION_ALLOW].adverse_intercept,
            strm.actions[ACTION_ALLOW].adverse_intercept
        );
        assert_ne!(
            sig.actions[ACTION_DENY].clean_intercept,
            ptr.actions[ACTION_DENY].clean_intercept
        );
    }

    #[test]
    fn evidence_includes_posterior_and_competing_costs() {
        let mut ctrl = LossMinimizationController::new();
        for _ in 0..64 {
            ctrl.observe(ApiFamily::Allocator, ACTION_REPAIR as u8, true, 400);
        }
        let ev = ctrl.latest_evidence();
        assert_eq!(ev.family, ApiFamily::Allocator);
        assert!(ev.posterior_adverse_prob > 0.5);
        assert!(ev.selected_action <= ACTION_DENY as u8);
        assert!(ev.competing_action <= ACTION_DENY as u8);
        assert_ne!(ev.selected_action, ev.competing_action);
        assert!(ev.selected_expected_loss <= ev.competing_expected_loss);
    }

    #[test]
    fn default_impl_matches_new() {
        let from_new = LossMinimizationController::new();
        let from_default = LossMinimizationController::default();
        assert_eq!(from_new.state(), from_default.state());
        assert_eq!(
            from_new.summary().total_decisions,
            from_default.summary().total_decisions
        );
        assert_eq!(
            from_new.summary().recommended_action,
            from_default.summary().recommended_action
        );
    }
}
