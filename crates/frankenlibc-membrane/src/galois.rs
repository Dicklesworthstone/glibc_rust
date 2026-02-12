//! Galois connection between C flat pointer model and rich safety model.
//!
//! A Galois connection (alpha, gamma) between two lattices provides:
//! - alpha: C world -> Safety world (abstraction)
//! - gamma: Safety world -> C world (concretization)
//!
//! For any C operation c: gamma(alpha(c)) >= c
//! Our safe interpretation is always at least as permissive as what a
//! correct program needs.

use crate::heal::HealingAction;
use crate::lattice::SafetyState;

/// Abstraction of a C pointer into the safety domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerAbstraction {
    /// The raw address from C world.
    pub addr: usize,
    /// Safety classification after validation.
    pub state: SafetyState,
    /// Known allocation base (if any).
    pub alloc_base: Option<usize>,
    /// Known remaining bytes from addr (if any).
    pub remaining: Option<usize>,
    /// Generation at time of abstraction.
    pub generation: Option<u32>,
}

impl PointerAbstraction {
    /// Create an abstraction for an unknown pointer.
    #[must_use]
    pub fn unknown(addr: usize) -> Self {
        Self {
            addr,
            state: SafetyState::Unknown,
            alloc_base: None,
            remaining: None,
            generation: None,
        }
    }

    /// Create an abstraction for a null pointer.
    #[must_use]
    pub const fn null() -> Self {
        Self {
            addr: 0,
            state: SafetyState::Invalid,
            alloc_base: None,
            remaining: None,
            generation: None,
        }
    }

    /// Create an abstraction for a validated pointer.
    #[must_use]
    pub fn validated(
        addr: usize,
        state: SafetyState,
        alloc_base: usize,
        remaining: usize,
        generation: u32,
    ) -> Self {
        Self {
            addr,
            state,
            alloc_base: Some(alloc_base),
            remaining: Some(remaining),
            generation: Some(generation),
        }
    }
}

/// Concrete action to take after safety analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcreteAction {
    /// Proceed with the operation using the given effective parameters.
    Proceed {
        /// Effective address to use.
        effective_addr: usize,
        /// Effective size to use (may be clamped).
        effective_size: usize,
    },
    /// Apply a healing action and then proceed.
    Heal {
        action: HealingAction,
        /// Effective address after healing.
        effective_addr: usize,
        /// Effective size after healing.
        effective_size: usize,
    },
    /// Deny the operation entirely.
    Deny,
}

/// The safety abstraction layer implementing the Galois connection.
pub struct SafetyAbstraction;

impl SafetyAbstraction {
    /// Alpha: abstract a C pointer into the safety domain.
    ///
    /// This is the "lifting" operation that takes raw C pointer facts
    /// and produces a rich safety classification.
    #[must_use]
    pub fn abstract_pointer(
        addr: usize,
        state: SafetyState,
        alloc_base: Option<usize>,
        remaining: Option<usize>,
        generation: Option<u32>,
    ) -> PointerAbstraction {
        if addr == 0 {
            return PointerAbstraction::null();
        }

        PointerAbstraction {
            addr,
            state,
            alloc_base,
            remaining,
            generation,
        }
    }

    /// Gamma: concretize a safety decision into a concrete C-world action.
    ///
    /// Given an abstracted pointer and a requested operation size,
    /// decide the concrete action. The key Galois property is maintained:
    /// gamma(alpha(c)) >= c — we never deny a valid operation.
    #[must_use]
    pub fn concretize_decision(ptr: &PointerAbstraction, requested_size: usize) -> ConcreteAction {
        // Null pointer: deny
        if ptr.addr == 0 {
            return ConcreteAction::Deny;
        }

        match ptr.state {
            SafetyState::Valid | SafetyState::Readable | SafetyState::Writable => {
                // Live pointer — check bounds
                if let Some(remaining) = ptr.remaining {
                    if requested_size > remaining {
                        // Clamp to available bounds
                        ConcreteAction::Heal {
                            action: HealingAction::ClampSize {
                                requested: requested_size,
                                clamped: remaining,
                            },
                            effective_addr: ptr.addr,
                            effective_size: remaining,
                        }
                    } else {
                        ConcreteAction::Proceed {
                            effective_addr: ptr.addr,
                            effective_size: requested_size,
                        }
                    }
                } else {
                    // No bounds known — allow (Galois: don't over-restrict)
                    ConcreteAction::Proceed {
                        effective_addr: ptr.addr,
                        effective_size: requested_size,
                    }
                }
            }
            SafetyState::Quarantined | SafetyState::Freed => {
                // Temporal violation — deny
                ConcreteAction::Deny
            }
            SafetyState::Invalid => ConcreteAction::Deny,
            SafetyState::Unknown => {
                // Unknown — allow (Galois: don't over-restrict foreign pointers)
                ConcreteAction::Proceed {
                    effective_addr: ptr.addr,
                    effective_size: requested_size,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_pointer_denied() {
        let ptr = PointerAbstraction::null();
        let action = SafetyAbstraction::concretize_decision(&ptr, 10);
        assert_eq!(action, ConcreteAction::Deny);
    }

    #[test]
    fn valid_pointer_within_bounds_proceeds() {
        let ptr = PointerAbstraction::validated(0x1000, SafetyState::Valid, 0x1000, 256, 1);
        let action = SafetyAbstraction::concretize_decision(&ptr, 100);
        assert_eq!(
            action,
            ConcreteAction::Proceed {
                effective_addr: 0x1000,
                effective_size: 100
            }
        );
    }

    #[test]
    fn valid_pointer_exceeding_bounds_heals() {
        let ptr = PointerAbstraction::validated(0x1000, SafetyState::Valid, 0x1000, 100, 1);
        let action = SafetyAbstraction::concretize_decision(&ptr, 500);
        match action {
            ConcreteAction::Heal { effective_size, .. } => assert_eq!(effective_size, 100),
            other => panic!("expected Heal, got {other:?}"),
        }
    }

    #[test]
    fn freed_pointer_denied() {
        let ptr = PointerAbstraction {
            addr: 0x1000,
            state: SafetyState::Freed,
            alloc_base: Some(0x1000),
            remaining: Some(256),
            generation: Some(1),
        };
        let action = SafetyAbstraction::concretize_decision(&ptr, 10);
        assert_eq!(action, ConcreteAction::Deny);
    }

    #[test]
    fn unknown_pointer_allowed_galois_property() {
        // Galois connection: don't over-restrict unknown (foreign) pointers
        let ptr = PointerAbstraction::unknown(0xDEAD_BEEF);
        let action = SafetyAbstraction::concretize_decision(&ptr, 42);
        assert_eq!(
            action,
            ConcreteAction::Proceed {
                effective_addr: 0xDEAD_BEEF,
                effective_size: 42
            }
        );
    }

    #[test]
    fn abstraction_roundtrip() {
        let abs = SafetyAbstraction::abstract_pointer(
            0x2000,
            SafetyState::Valid,
            Some(0x2000),
            Some(512),
            Some(3),
        );
        assert_eq!(abs.addr, 0x2000);
        assert_eq!(abs.state, SafetyState::Valid);
        assert_eq!(abs.remaining, Some(512));

        let action = SafetyAbstraction::concretize_decision(&abs, 256);
        assert_eq!(
            action,
            ConcreteAction::Proceed {
                effective_addr: 0x2000,
                effective_size: 256
            }
        );
    }
}
