//! Safety state lattice with formal join/meet operations.
//!
//! The lattice defines a **partial order** on pointer safety states.
//! Readable and Writable are **incomparable** (neither implies the other).
//!
//! ```text
//!              Valid
//!             /     \
//!        Readable  Writable
//!             \     /
//!          Quarantined
//!               |
//!             Freed
//!               |
//!            Invalid
//!               |
//!            Unknown
//! ```
//!
//! Join (least upper bound) and meet (greatest lower bound) respect this
//! diamond structure. Safety states only become more restrictive on new
//! information (monotonic).

/// Safety classification for a tracked memory region.
///
/// This forms a lattice with a diamond at the top (Readable/Writable are
/// incomparable). `Valid` implies both Readable and Writable.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SafetyState {
    /// Region is fully valid for read and write.
    Valid = 6,
    /// Region is valid for reads only.
    Readable = 5,
    /// Region is valid for writes only (rare; e.g., write-only DMA).
    Writable = 4,
    /// Region is quarantined due to suspicious activity.
    Quarantined = 3,
    /// Region has been freed but not yet recycled.
    Freed = 2,
    /// Region is known to be invalid.
    Invalid = 1,
    /// No metadata available for this region.
    #[default]
    Unknown = 0,
}

impl SafetyState {
    /// Join (least upper bound) — the most restrictive state that is
    /// at least as restrictive as both inputs.
    ///
    /// In a safety context, joining two pieces of information about the
    /// same region produces the most conservative (safe) conclusion.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        // Handle the diamond: Readable and Writable are incomparable.
        // Their join (most restrictive common refinement) is Quarantined.
        match (self, other) {
            // Same state: idempotent
            (a, b) if a as u8 == b as u8 => a,

            // Valid is top of the live states
            (Self::Valid, other) | (other, Self::Valid) => other,

            // Readable vs Writable: incomparable, join = Quarantined
            (Self::Readable, Self::Writable) | (Self::Writable, Self::Readable) => {
                Self::Quarantined
            }

            // Everything joins downward toward Unknown
            (a, b) => {
                // For non-diamond cases, take the lower rank
                if (a as u8) <= (b as u8) { a } else { b }
            }
        }
    }

    /// Meet (greatest lower bound) — the most permissive state that is
    /// at least as permissive as both inputs.
    #[must_use]
    pub const fn meet(self, other: Self) -> Self {
        match (self, other) {
            (a, b) if a as u8 == b as u8 => a,

            // Readable and Writable: incomparable, meet = Valid
            (Self::Readable, Self::Writable) | (Self::Writable, Self::Readable) => Self::Valid,

            // For non-diamond cases, take the higher rank
            (a, b) => {
                if (a as u8) >= (b as u8) {
                    a
                } else {
                    b
                }
            }
        }
    }

    /// Returns true if this state allows read access.
    #[must_use]
    pub const fn can_read(self) -> bool {
        matches!(self, Self::Valid | Self::Readable)
    }

    /// Returns true if this state allows write access.
    #[must_use]
    pub const fn can_write(self) -> bool {
        matches!(self, Self::Valid | Self::Writable)
    }

    /// Returns true if this state represents a live (usable) region.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Valid | Self::Readable | Self::Writable)
    }

    /// Returns true if this state is terminal (no further operations allowed).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Invalid | Self::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_is_commutative() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(
                    a.join(b),
                    b.join(a),
                    "join({a:?}, {b:?}) != join({b:?}, {a:?})"
                );
            }
        }
    }

    #[test]
    fn join_is_associative() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(
                        a.join(b).join(c),
                        a.join(b.join(c)),
                        "associativity failed for ({a:?}, {b:?}, {c:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn join_is_idempotent() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &s in &states {
            assert_eq!(s.join(s), s, "join({s:?}, {s:?}) should be {s:?}");
        }
    }

    #[test]
    fn meet_is_commutative() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &a in &states {
            for &b in &states {
                assert_eq!(
                    a.meet(b),
                    b.meet(a),
                    "meet({a:?}, {b:?}) != meet({b:?}, {a:?})"
                );
            }
        }
    }

    #[test]
    fn meet_is_associative() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &a in &states {
            for &b in &states {
                for &c in &states {
                    assert_eq!(
                        a.meet(b).meet(c),
                        a.meet(b.meet(c)),
                        "associativity failed for ({a:?}, {b:?}, {c:?})"
                    );
                }
            }
        }
    }

    #[test]
    fn meet_is_idempotent() {
        let states = [
            SafetyState::Valid,
            SafetyState::Readable,
            SafetyState::Writable,
            SafetyState::Quarantined,
            SafetyState::Freed,
            SafetyState::Invalid,
            SafetyState::Unknown,
        ];
        for &s in &states {
            assert_eq!(s.meet(s), s, "meet({s:?}, {s:?}) should be {s:?}");
        }
    }

    #[test]
    fn readable_writable_diamond() {
        // Readable and Writable are incomparable
        // Their join (most restrictive) is Quarantined
        assert_eq!(
            SafetyState::Readable.join(SafetyState::Writable),
            SafetyState::Quarantined
        );
        // Their meet (most permissive) is Valid
        assert_eq!(
            SafetyState::Readable.meet(SafetyState::Writable),
            SafetyState::Valid
        );
    }

    #[test]
    fn valid_is_top_of_live() {
        // Valid joined with anything live gives that thing
        assert_eq!(
            SafetyState::Valid.join(SafetyState::Readable),
            SafetyState::Readable
        );
        assert_eq!(
            SafetyState::Valid.join(SafetyState::Writable),
            SafetyState::Writable
        );
    }

    #[test]
    fn join_takes_more_restrictive() {
        assert_eq!(
            SafetyState::Valid.join(SafetyState::Freed),
            SafetyState::Freed
        );
        assert_eq!(
            SafetyState::Readable.join(SafetyState::Unknown),
            SafetyState::Unknown
        );
        assert_eq!(
            SafetyState::Quarantined.join(SafetyState::Invalid),
            SafetyState::Invalid
        );
    }

    #[test]
    fn meet_takes_more_permissive() {
        assert_eq!(
            SafetyState::Freed.meet(SafetyState::Valid),
            SafetyState::Valid
        );
        assert_eq!(
            SafetyState::Unknown.meet(SafetyState::Readable),
            SafetyState::Readable
        );
    }

    #[test]
    fn access_permissions() {
        assert!(SafetyState::Valid.can_read());
        assert!(SafetyState::Valid.can_write());
        assert!(SafetyState::Readable.can_read());
        assert!(!SafetyState::Readable.can_write());
        assert!(!SafetyState::Writable.can_read());
        assert!(SafetyState::Writable.can_write());
        assert!(!SafetyState::Freed.can_read());
        assert!(!SafetyState::Freed.can_write());
        assert!(!SafetyState::Unknown.can_read());
    }

    #[test]
    fn liveness() {
        assert!(SafetyState::Valid.is_live());
        assert!(SafetyState::Readable.is_live());
        assert!(SafetyState::Writable.is_live());
        assert!(!SafetyState::Quarantined.is_live());
        assert!(!SafetyState::Freed.is_live());
        assert!(!SafetyState::Invalid.is_live());
        assert!(!SafetyState::Unknown.is_live());
    }
}
