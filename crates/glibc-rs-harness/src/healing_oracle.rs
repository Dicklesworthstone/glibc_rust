//! Healing oracle for hardened mode testing.
//!
//! Intentionally triggers unsafe conditions and verifies that the
//! membrane applies the correct healing action in hardened mode.

use serde::{Deserialize, Serialize};

/// An oracle test that triggers a specific unsafe condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOracleCase {
    /// Test identifier.
    pub id: String,
    /// The unsafe condition being triggered.
    pub condition: UnsafeCondition,
    /// Expected healing action in hardened mode.
    pub expected_healing: String,
    /// Expected behavior in strict mode (should NOT heal).
    pub strict_expected: String,
}

/// Classification of unsafe conditions to test.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum UnsafeCondition {
    /// Null pointer dereference attempt.
    NullPointer,
    /// Use after free.
    UseAfterFree,
    /// Double free.
    DoubleFree,
    /// Buffer overflow (write past allocation).
    BufferOverflow,
    /// Foreign pointer free (pointer not from our allocator).
    ForeignFree,
    /// Size exceeds allocation bounds.
    BoundsExceeded,
    /// Realloc of freed pointer.
    ReallocFreed,
}

/// Collection of healing oracle tests.
#[derive(Debug, Default)]
pub struct HealingOracleSuite {
    cases: Vec<HealingOracleCase>,
}

impl HealingOracleSuite {
    /// Create a new empty suite.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a test case.
    pub fn add(&mut self, case: HealingOracleCase) {
        self.cases.push(case);
    }

    /// Get all cases.
    #[must_use]
    pub fn cases(&self) -> &[HealingOracleCase] {
        &self.cases
    }
}
