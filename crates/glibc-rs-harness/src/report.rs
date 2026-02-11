//! Report generation for conformance results.

use std::path::Path;

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

/// Taxonomy count summary derived from support matrix symbols.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityCounts {
    pub implemented: u64,
    pub raw_syscall: u64,
    pub glibc_call_through: u64,
    pub stub: u64,
}

/// Machine-readable single source-of-truth report for docs reality tables.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RealityReport {
    pub generated_at_utc: String,
    pub total_exported: u64,
    pub counts: RealityCounts,
    pub stubs: Vec<String>,
}

impl RealityReport {
    /// Build report from support_matrix JSON bytes.
    pub fn from_support_matrix_json_str(json: &str) -> Result<Self, String> {
        let matrix: serde_json::Value = serde_json::from_str(json)
            .map_err(|err| format!("invalid support matrix JSON: {err}"))?;

        let generated_at_utc = matrix["generated_at_utc"]
            .as_str()
            .ok_or("missing generated_at_utc in support matrix")?
            .to_string();
        let total_exported = matrix["total_exported"]
            .as_u64()
            .ok_or("missing total_exported in support matrix")?;

        let symbols = matrix["symbols"]
            .as_array()
            .ok_or("missing symbols[] in support matrix")?;
        let symbol_count = u64::try_from(symbols.len())
            .map_err(|_| "support matrix symbols[] length does not fit u64".to_string())?;
        if symbol_count != total_exported {
            return Err(format!(
                "support matrix total_exported ({total_exported}) does not match symbols[] length ({symbol_count})"
            ));
        }

        let mut stubs = Vec::new();
        let mut implemented = 0u64;
        let mut raw_syscall = 0u64;
        let mut glibc_call_through = 0u64;
        let mut stub = 0u64;

        for sym in symbols {
            let status = sym["status"].as_str().ok_or("symbol missing status")?;
            let symbol_name = sym["symbol"].as_str().ok_or("symbol missing symbol name")?;
            match status {
                "Implemented" => implemented += 1,
                "RawSyscall" => raw_syscall += 1,
                "GlibcCallThrough" => glibc_call_through += 1,
                "Stub" => {
                    stub += 1;
                    stubs.push(symbol_name.to_string());
                }
                _ => {
                    return Err(format!(
                        "unknown support status '{status}' for symbol '{symbol_name}'"
                    ));
                }
            }
        }

        stubs.sort();

        let computed_total = implemented + raw_syscall + glibc_call_through + stub;
        if computed_total != total_exported {
            return Err(format!(
                "support matrix status totals ({computed_total}) do not match total_exported ({total_exported})"
            ));
        }

        Ok(Self {
            generated_at_utc,
            total_exported,
            counts: RealityCounts {
                implemented,
                raw_syscall,
                glibc_call_through,
                stub,
            },
            stubs,
        })
    }

    /// Build report from support_matrix file on disk.
    pub fn from_support_matrix_path(path: &Path) -> Result<Self, String> {
        let json = std::fs::read_to_string(path)
            .map_err(|err| format!("failed reading support matrix '{}': {err}", path.display()))?;
        Self::from_support_matrix_json_str(&json)
    }

    /// Render report as pretty JSON.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{RealityCounts, RealityReport};

    fn sample_matrix(symbol_rows: &str, total_exported: u64) -> String {
        format!(
            r#"{{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": {total_exported},
  "symbols": [
{symbol_rows}
  ]
}}"#
        )
    }

    #[test]
    fn parses_valid_support_matrix() {
        let json = sample_matrix(
            r#"    { "symbol": "zeta", "status": "Stub" },
    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "beta", "status": "RawSyscall" },
    { "symbol": "gamma", "status": "GlibcCallThrough" },
    { "symbol": "eta", "status": "Stub" }"#,
            5,
        );
        let report = RealityReport::from_support_matrix_json_str(&json).unwrap();

        assert_eq!(report.generated_at_utc, "2026-02-11T03:14:20Z");
        assert_eq!(report.total_exported, 5);
        assert_eq!(
            report.counts,
            RealityCounts {
                implemented: 1,
                raw_syscall: 1,
                glibc_call_through: 1,
                stub: 2
            }
        );
        assert_eq!(report.stubs, vec!["eta".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn rejects_unknown_status() {
        let json = sample_matrix(
            r#"    { "symbol": "alpha", "status": "Implemented" },
    { "symbol": "omega", "status": "Experimental" }"#,
            2,
        );

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("unknown support status"));
        assert!(err.contains("Experimental"));
    }

    #[test]
    fn rejects_missing_required_fields() {
        let json = r#"{
  "generated_at_utc": "2026-02-11T03:14:20Z",
  "total_exported": 1,
  "symbols": [
    { "status": "Implemented" }
  ]
}"#;

        let err = RealityReport::from_support_matrix_json_str(json).unwrap_err();
        assert!(err.contains("symbol missing symbol name"));
    }

    #[test]
    fn rejects_total_export_mismatch() {
        let json = sample_matrix(r#"    { "symbol": "alpha", "status": "Implemented" }"#, 2);

        let err = RealityReport::from_support_matrix_json_str(&json).unwrap_err();
        assert!(err.contains("does not match symbols[] length"));
    }
}
