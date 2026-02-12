//! TSM-specific conformance tests.
//!
//! Tests that verify membrane behavior across both strict and hardened modes.

use serde::{Deserialize, Serialize};

/// A membrane test case specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneTestCase {
    /// Test identifier.
    pub id: String,
    /// TSM policy section reference.
    pub policy_section: String,
    /// Description of what's being tested.
    pub description: String,
    /// Expected behavior in strict mode.
    pub strict_expected: String,
    /// Expected behavior in hardened mode.
    pub hardened_expected: String,
}

/// Collection of membrane tests.
#[derive(Debug, Default)]
pub struct MembraneTestSuite {
    cases: Vec<MembraneTestCase>,
}

impl MembraneTestSuite {
    /// Create a new empty suite.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a test case.
    pub fn add(&mut self, case: MembraneTestCase) {
        self.cases.push(case);
    }

    /// Get all cases.
    #[must_use]
    pub fn cases(&self) -> &[MembraneTestCase] {
        &self.cases
    }
}
