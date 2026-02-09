//! Fixture loading and management.

use serde::{Deserialize, Serialize};

/// A single fixture test case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureCase {
    /// Case identifier.
    pub name: String,
    /// Function being tested.
    pub function: String,
    /// POSIX/C spec section reference.
    pub spec_section: String,
    /// Input parameters (serialized).
    pub inputs: serde_json::Value,
    /// Expected output (serialized as string for comparison).
    pub expected_output: String,
    /// Expected errno after call.
    pub expected_errno: i32,
    /// Whether this tests strict or hardened behavior.
    pub mode: String,
}

/// A collection of fixture cases for a function family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureSet {
    /// Schema version.
    pub version: String,
    /// Function family name.
    pub family: String,
    /// UTC timestamp of capture.
    pub captured_at: String,
    /// Individual test cases.
    pub cases: Vec<FixtureCase>,
}

impl FixtureSet {
    /// Load fixture set from JSON string.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize fixture set to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Load fixture set from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let set = Self::from_json(&content)?;
        Ok(set)
    }
}
