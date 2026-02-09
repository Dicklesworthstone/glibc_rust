//! Report generation for conformance results.

use serde::{Deserialize, Serialize};

use crate::verify::VerificationSummary;

/// A conformance report combining verification and traceability data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceReport {
    /// Report title.
    pub title: String,
    /// Runtime mode tested (strict or hardened).
    pub mode: String,
    /// Timestamp (UTC).
    pub timestamp: String,
    /// Verification summary.
    pub summary: VerificationSummary,
}

impl ConformanceReport {
    /// Render the report as markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n\n", self.title));
        out.push_str(&format!("- Mode: {}\n", self.mode));
        out.push_str(&format!("- Timestamp: {}\n", self.timestamp));
        out.push_str(&format!("- Total: {}\n", self.summary.total));
        out.push_str(&format!("- Passed: {}\n", self.summary.passed));
        out.push_str(&format!("- Failed: {}\n\n", self.summary.failed));

        out.push_str("| Case | Spec | Status |\n");
        out.push_str("|------|------|--------|\n");
        for r in &self.summary.results {
            let status = if r.passed { "PASS" } else { "FAIL" };
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                r.case_name, r.spec_section, status
            ));
        }
        out
    }

    /// Render the report as JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
    }
}
