//! Host glibc fixture capture.
//!
//! Runs test vectors against the host glibc and serializes
//! inputs/outputs as JSON fixtures for later verification.

use serde::{Deserialize, Serialize};

/// A captured operation with its input/output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedOperation {
    /// Function name (e.g., "memcpy", "strlen").
    pub function: String,
    /// Input parameters as serialized values.
    pub inputs: serde_json::Value,
    /// Expected output from host glibc.
    pub output: serde_json::Value,
    /// errno value after the call (0 if none).
    pub errno_after: i32,
}

/// Capture a set of operations against host glibc.
///
/// Returns serialized fixture data suitable for writing to JSON.
pub fn capture_operations(ops: &[CapturedOperation]) -> String {
    serde_json::to_string_pretty(ops).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}
