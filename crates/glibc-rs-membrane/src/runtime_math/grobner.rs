//! Table-driven normal-form reduction (Grobner-style).
//!
//! This module is intentionally runtime-light:
//! - No Grobner basis computation at runtime.
//! - Only applies an oriented reduction table (rewrite rules).
//! - Deterministic, bounded-time, and allocation-free.
//!
//! v1 implementation treats a signature as a boolean monomial represented by a bitset:
//! each variable is a bit, and a monomial is the bitwise OR of its variables.
//!
//! Reduction rule semantics:
//! - `lhs` matches when all bits in `lhs` are present in the current mask.
//! - applying a rule replaces `lhs` bits with `rhs` bits:
//!   `mask := (mask & ~lhs) | rhs`
//!
//! Termination and confluence are policy responsibilities:
//! - When rules are extracted from a Grobner basis with a fixed term order, the reduction
//!   is confluent and terminates.
//! - We still enforce a hard step budget to bound time in the face of malformed policies.

/// Bitset type used for monomial/signature representation (up to 128 variables).
pub type MonomialMask = u128;

/// One oriented reduction rule: `lhs -> rhs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReductionRule {
    pub lhs: MonomialMask,
    pub rhs: MonomialMask,
}

impl ReductionRule {
    #[inline]
    #[must_use]
    pub const fn matches(&self, mask: MonomialMask) -> bool {
        self.lhs != 0 && (mask & self.lhs) == self.lhs
    }

    #[inline]
    #[must_use]
    pub const fn apply(&self, mask: MonomialMask) -> MonomialMask {
        (mask & !self.lhs) | self.rhs
    }
}

/// Reduction statistics (useful for tests/telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReduceStats {
    /// How many successful rewrites were applied.
    pub steps: u32,
    /// Whether reduction reached a fixed point within the step limit.
    pub reached_fixpoint: bool,
}

/// Reduction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReduceError {
    /// The rule set did not converge within the configured step budget.
    StepLimitExceeded { steps: u32 },
}

/// Default maximum number of successful rewrites permitted per reduction.
///
/// This is a safety belt, not a claim about required iterations for well-formed policies.
pub const DEFAULT_STEP_LIMIT: u32 = 1024;

/// Reduce a monomial/signature mask to normal form using the provided rule table.
///
/// Returns the reduced mask and reduction stats.
pub fn reduce_mask_with_limit(
    mut mask: MonomialMask,
    rules: &[ReductionRule],
    step_limit: u32,
) -> Result<(MonomialMask, ReduceStats), ReduceError> {
    let mut steps = 0_u32;

    loop {
        let mut changed = false;

        for rule in rules {
            if !rule.matches(mask) {
                continue;
            }

            let next = rule.apply(mask);
            if next == mask {
                continue;
            }

            mask = next;
            changed = true;
            steps = steps.saturating_add(1);

            if steps >= step_limit {
                return Err(ReduceError::StepLimitExceeded { steps });
            }
        }

        if !changed {
            break;
        }
    }

    Ok((
        mask,
        ReduceStats {
            steps,
            reached_fixpoint: true,
        },
    ))
}

/// Reduce using the default step limit.
#[inline]
pub fn reduce_mask(
    mask: MonomialMask,
    rules: &[ReductionRule],
) -> Result<MonomialMask, ReduceError> {
    Ok(reduce_mask_with_limit(mask, rules, DEFAULT_STEP_LIMIT)?.0)
}

// ── Canonical root-cause classification ──────────────────────────────────
//
// The 6 latent causes from sparse recovery map to monomial bits:
//   bit 0 (C0): temporal/provenance
//   bit 1 (C1): tail-latency/congestion
//   bit 2 (C2): topological/path-complexity
//   bit 3 (C3): transition/regime-shift
//   bit 4 (C4): numeric/floating exceptional
//   bit 5 (C5): resource-admissibility
//
// The reduction rules below form a confluent, terminating rewrite system
// (a Gröbner basis under degree-lex order over 6 boolean variables) that
// collapses co-occurring causes to their canonical root:
//
//   c0 ∧ c3 → c3   (temporal subsumed by regime-shift)
//   c1 ∧ c4 → c1   (numeric subsumed by congestion)
//   c2 ∧ c5 → c5   (topology subsumed by admissibility)

/// Bit for latent cause 0: temporal/provenance.
pub const C0_TEMPORAL: MonomialMask = 1 << 0;
/// Bit for latent cause 1: tail-latency/congestion.
pub const C1_CONGESTION: MonomialMask = 1 << 1;
/// Bit for latent cause 2: topological/path-complexity.
pub const C2_TOPOLOGICAL: MonomialMask = 1 << 2;
/// Bit for latent cause 3: transition/regime-shift.
pub const C3_REGIME: MonomialMask = 1 << 3;
/// Bit for latent cause 4: numeric/floating exceptional.
pub const C4_NUMERIC: MonomialMask = 1 << 4;
/// Bit for latent cause 5: resource-admissibility.
pub const C5_ADMISSIBILITY: MonomialMask = 1 << 5;

/// Number of latent causes tracked by sparse recovery.
pub const NUM_LATENT_CAUSES: usize = 6;

/// Oriented reduction rules for canonical root-cause classification.
///
/// These are confluent and terminating (each rule strictly decreases the
/// degree under lex order since `rhs` is a proper subset of `lhs`).
const CANONICAL_RULES: [ReductionRule; 3] = [
    // temporal + regime-shift → regime-shift
    ReductionRule {
        lhs: C0_TEMPORAL | C3_REGIME,
        rhs: C3_REGIME,
    },
    // congestion + numeric → congestion
    ReductionRule {
        lhs: C1_CONGESTION | C4_NUMERIC,
        rhs: C1_CONGESTION,
    },
    // topological + admissibility → admissibility
    ReductionRule {
        lhs: C2_TOPOLOGICAL | C5_ADMISSIBILITY,
        rhs: C5_ADMISSIBILITY,
    },
];

/// Canonical class IDs (compact u8 for telemetry).
pub const CANONICAL_CLASS_NONE: u8 = 0;
pub const CANONICAL_CLASS_TEMPORAL: u8 = 1;
pub const CANONICAL_CLASS_CONGESTION: u8 = 2;
pub const CANONICAL_CLASS_TOPOLOGICAL: u8 = 3;
pub const CANONICAL_CLASS_REGIME: u8 = 4;
pub const CANONICAL_CLASS_NUMERIC: u8 = 5;
pub const CANONICAL_CLASS_ADMISSIBILITY: u8 = 6;
pub const CANONICAL_CLASS_COMPOUND: u8 = 7;

/// Number of canonical class bins (for per-class counting).
pub const NUM_CANONICAL_CLASSES: usize = 8;

/// Convert a sparse-recovery support vector to a canonical class ID.
///
/// Takes a boolean array indicating which latent causes are active
/// (above the support threshold), reduces the corresponding monomial
/// mask via the Gröbner reduction table, and returns a compact class ID.
#[must_use]
pub fn canonical_class_from_support(active: &[bool; NUM_LATENT_CAUSES]) -> u8 {
    let mut mask: MonomialMask = 0;
    for (i, &a) in active.iter().enumerate() {
        if a {
            mask |= 1u128 << i;
        }
    }
    if mask == 0 {
        return CANONICAL_CLASS_NONE;
    }

    // Reduce — the canonical rules are confluent and terminate in ≤3 steps.
    let reduced = reduce_mask_with_limit(mask, &CANONICAL_RULES, 16)
        .map(|(m, _)| m)
        .unwrap_or(mask);

    canonical_id_from_reduced(reduced)
}

/// Map a reduced monomial mask to a compact canonical class ID.
#[must_use]
fn canonical_id_from_reduced(mask: MonomialMask) -> u8 {
    match mask {
        0 => CANONICAL_CLASS_NONE,
        m if m == C0_TEMPORAL => CANONICAL_CLASS_TEMPORAL,
        m if m == C1_CONGESTION => CANONICAL_CLASS_CONGESTION,
        m if m == C2_TOPOLOGICAL => CANONICAL_CLASS_TOPOLOGICAL,
        m if m == C3_REGIME => CANONICAL_CLASS_REGIME,
        m if m == C4_NUMERIC => CANONICAL_CLASS_NUMERIC,
        m if m == C5_ADMISSIBILITY => CANONICAL_CLASS_ADMISSIBILITY,
        _ => CANONICAL_CLASS_COMPOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MonomialMask = 1u128 << 0;
    const B: MonomialMask = 1u128 << 1;
    const C: MonomialMask = 1u128 << 2;
    const D: MonomialMask = 1u128 << 3;

    #[test]
    fn drops_redundant_atom() {
        // a*b -> a
        let rules = [ReductionRule { lhs: A | B, rhs: A }];
        let (out, stats) = reduce_mask_with_limit(A | B, &rules, 16).unwrap();
        assert_eq!(out, A);
        assert!(stats.steps >= 1);
    }

    #[test]
    fn supports_chained_rewrites() {
        // a*b -> a, a -> c
        let rules = [
            ReductionRule { lhs: A | B, rhs: A },
            ReductionRule { lhs: A, rhs: C },
        ];
        let out = reduce_mask(A | B, &rules).unwrap();
        assert_eq!(out, C);
    }

    #[test]
    fn preserves_unrelated_bits() {
        // a -> c, but d remains.
        let rules = [ReductionRule { lhs: A, rhs: C }];
        let out = reduce_mask(A | D, &rules).unwrap();
        assert_eq!(out, C | D);
    }

    #[test]
    fn ignores_zero_lhs_rule() {
        // lhs=0 is invalid; it must not match everything.
        let rules = [
            ReductionRule { lhs: 0, rhs: C },
            ReductionRule { lhs: A, rhs: B },
        ];
        let out = reduce_mask(A, &rules).unwrap();
        assert_eq!(out, B);
    }

    #[test]
    fn detects_non_converging_rules_via_step_limit() {
        // a <-> b ping-pong. With a strict step budget, this should error.
        let rules = [
            ReductionRule { lhs: A, rhs: B },
            ReductionRule { lhs: B, rhs: A },
        ];

        let err = reduce_mask_with_limit(A, &rules, 8).unwrap_err();
        assert_eq!(err, ReduceError::StepLimitExceeded { steps: 8 });
    }

    // ── Canonical root-cause classification tests ──

    #[test]
    fn no_active_causes_yields_none() {
        let active = [false; NUM_LATENT_CAUSES];
        assert_eq!(canonical_class_from_support(&active), CANONICAL_CLASS_NONE);
    }

    #[test]
    fn single_cause_maps_to_itself() {
        for (i, expected) in [
            CANONICAL_CLASS_TEMPORAL,
            CANONICAL_CLASS_CONGESTION,
            CANONICAL_CLASS_TOPOLOGICAL,
            CANONICAL_CLASS_REGIME,
            CANONICAL_CLASS_NUMERIC,
            CANONICAL_CLASS_ADMISSIBILITY,
        ]
        .iter()
        .enumerate()
        {
            let mut active = [false; NUM_LATENT_CAUSES];
            active[i] = true;
            assert_eq!(
                canonical_class_from_support(&active),
                *expected,
                "single cause {} should yield class {}",
                i,
                expected
            );
        }
    }

    #[test]
    fn temporal_plus_regime_reduces_to_regime() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[0] = true; // c0 temporal
        active[3] = true; // c3 regime
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_REGIME
        );
    }

    #[test]
    fn congestion_plus_numeric_reduces_to_congestion() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[1] = true; // c1 congestion
        active[4] = true; // c4 numeric
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_CONGESTION
        );
    }

    #[test]
    fn topological_plus_admissibility_reduces_to_admissibility() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[2] = true; // c2 topological
        active[5] = true; // c5 admissibility
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_ADMISSIBILITY
        );
    }

    #[test]
    fn unrelated_pair_yields_compound() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[0] = true; // c0 temporal
        active[1] = true; // c1 congestion
        // No rule reduces c0+c1, so it stays compound.
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_COMPOUND
        );
    }

    #[test]
    fn all_active_reduces_via_chained_rules() {
        let active = [true; NUM_LATENT_CAUSES];
        let cls = canonical_class_from_support(&active);
        // After reduction: c0|c3 → c3, c1|c4 → c1, c2|c5 → c5
        // Remaining: c1|c3|c5 → compound (3 irreducible causes).
        assert_eq!(cls, CANONICAL_CLASS_COMPOUND);
    }
}
