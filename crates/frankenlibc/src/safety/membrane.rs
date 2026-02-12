//! Copy decision logic for the Transparent Safety Membrane.

use crate::safety::{CopyDisposition, PointerFacts, RepairReason, TemporalState};

/// Result of membrane policy evaluation for copy-like operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyDecision {
    /// Decision disposition.
    pub disposition: CopyDisposition,
    /// Effective length to apply.
    pub effective_len: usize,
    /// Decision rationale.
    pub reason: RepairReason,
}

impl CopyDecision {
    #[must_use]
    fn allow(effective_len: usize) -> Self {
        Self {
            disposition: CopyDisposition::Allow,
            effective_len,
            reason: RepairReason::None,
        }
    }

    #[must_use]
    fn repair(effective_len: usize, reason: RepairReason) -> Self {
        Self {
            disposition: CopyDisposition::Repair,
            effective_len,
            reason,
        }
    }

    #[must_use]
    fn deny(reason: RepairReason) -> Self {
        Self {
            disposition: CopyDisposition::Deny,
            effective_len: 0,
            reason,
        }
    }
}

/// Decide copy policy from source/destination pointer facts.
#[must_use]
pub fn decide_copy(requested_len: usize, src: PointerFacts, dst: PointerFacts) -> CopyDecision {
    if requested_len == 0 {
        return CopyDecision::allow(0);
    }

    if src.addr == 0 || dst.addr == 0 {
        return CopyDecision::deny(RepairReason::InvalidPointerFacts);
    }

    if !is_live(src.temporal) || !is_live(dst.temporal) {
        return CopyDecision::deny(RepairReason::NonLivePointer);
    }

    match (src.remaining, dst.remaining) {
        (Some(src_rem), Some(dst_rem)) => {
            let safe_len = src_rem.min(dst_rem);
            if requested_len > safe_len {
                return CopyDecision::repair(safe_len, RepairReason::LengthClamp);
            }
            CopyDecision::allow(requested_len)
        }
        _ => CopyDecision::allow(requested_len),
    }
}

fn is_live(state: TemporalState) -> bool {
    matches!(state, TemporalState::Valid | TemporalState::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(addr: usize, temporal: TemporalState, remaining: Option<usize>) -> PointerFacts {
        PointerFacts {
            addr,
            temporal,
            remaining,
        }
    }

    #[test]
    fn decide_copy_repairs_when_exceeding_known_bounds() {
        let src = facts(0x10, TemporalState::Valid, Some(8));
        let dst = facts(0x20, TemporalState::Valid, Some(4));
        let decision = decide_copy(16, src, dst);

        assert_eq!(decision.disposition, CopyDisposition::Repair);
        assert_eq!(decision.effective_len, 4);
        assert_eq!(decision.reason, RepairReason::LengthClamp);
    }

    #[test]
    fn decide_copy_denies_when_pointer_non_live() {
        let src = facts(0x10, TemporalState::Freed, Some(8));
        let dst = facts(0x20, TemporalState::Valid, Some(8));
        let decision = decide_copy(4, src, dst);

        assert_eq!(decision.disposition, CopyDisposition::Deny);
        assert_eq!(decision.reason, RepairReason::NonLivePointer);
    }

    #[test]
    fn decide_copy_allows_unknown_metadata() {
        let src = facts(0x10, TemporalState::Unknown, None);
        let dst = facts(0x20, TemporalState::Unknown, None);
        let decision = decide_copy(12, src, dst);

        assert_eq!(decision.disposition, CopyDisposition::Allow);
        assert_eq!(decision.effective_len, 12);
    }
}
