//! Barrier admissibility filter for runtime actions.

use crate::config::SafetyLevel;

use super::control::ControlLimits;
use super::{RuntimeContext, ValidationProfile};

/// Constant-time barrier guard.
///
/// This is the runtime embodiment of barrier-certificate admissibility:
/// if a proposed action exits the certified safe set, deny/escalate.
pub struct BarrierOracle;

impl BarrierOracle {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns true if the decision candidate is admissible.
    #[must_use]
    pub fn admissible(
        &self,
        ctx: &RuntimeContext,
        mode: SafetyLevel,
        profile: ValidationProfile,
        risk_upper_bound_ppm: u32,
        limits: ControlLimits,
    ) -> bool {
        // Keep gigantic requests out of the admissible region.
        if ctx.requested_bytes > limits.max_request_bytes {
            return false;
        }

        // In strict mode, avoid introducing surprise hard denies on pointer
        // classification paths. Escalate to `Full` instead of deny.
        if matches!(mode, SafetyLevel::Strict)
            && matches!(ctx.family, super::ApiFamily::PointerValidation)
            && ctx.bloom_negative
            && risk_upper_bound_ppm < 900_000
        {
            return true;
        }

        // If a write operation has extreme risk and still asks for fast profile,
        // it's outside admissible region.
        if ctx.is_write
            && risk_upper_bound_ppm > limits.repair_trigger_ppm
            && matches!(profile, ValidationProfile::Fast)
        {
            return false;
        }

        true
    }
}

impl Default for BarrierOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_math::control::ControlLimits;
    use crate::runtime_math::{ApiFamily, RuntimeContext};

    #[test]
    fn rejects_unbounded_request() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x1000,
                requested_bytes: usize::MAX,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Fast,
            10_000,
            ControlLimits {
                full_validation_trigger_ppm: 50_000,
                repair_trigger_ppm: 80_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    #[test]
    fn strict_pointer_validation_bloom_negative_is_admissible() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::PointerValidation,
                addr_hint: 0x2000,
                requested_bytes: 64,
                is_write: false,
                contention_hint: 0,
                bloom_negative: true,
            },
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            100_000,
            ControlLimits {
                full_validation_trigger_ppm: 220_000,
                repair_trigger_ppm: 1_000_000,
                max_request_bytes: 4096,
            },
        );
        assert!(ok);
    }

    #[test]
    fn fast_write_with_extreme_risk_is_rejected() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x3000,
                requested_bytes: 128,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Fast,
            200_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    #[test]
    fn full_profile_keeps_high_risk_write_admissible_for_escalation() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x4000,
                requested_bytes: 128,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Full,
            200_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(ok);
    }
}
