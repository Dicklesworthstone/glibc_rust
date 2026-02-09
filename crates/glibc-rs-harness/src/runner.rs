//! Test execution engine.

use crate::fixtures::FixtureSet;
use crate::verify::VerificationResult;

/// Runs a fixture set and collects verification results.
pub struct TestRunner {
    /// Name of the test campaign.
    pub campaign: String,
    /// Mode being tested (strict or hardened).
    pub mode: String,
}

impl TestRunner {
    /// Create a new test runner.
    #[must_use]
    pub fn new(campaign: impl Into<String>, mode: impl Into<String>) -> Self {
        Self {
            campaign: campaign.into(),
            mode: mode.into(),
        }
    }

    /// Run all fixtures in a set and return results.
    pub fn run(&self, fixture_set: &FixtureSet) -> Vec<VerificationResult> {
        fixture_set
            .cases
            .iter()
            .map(|case| VerificationResult {
                case_name: case.name.clone(),
                spec_section: case.spec_section.clone(),
                passed: false, // TODO: wire to actual execution
                expected: case.expected_output.clone(),
                actual: String::new(),
                diff: None,
            })
            .collect()
    }
}
