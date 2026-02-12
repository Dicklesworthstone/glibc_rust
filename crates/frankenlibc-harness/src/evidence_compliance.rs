//! Evidence compliance gate helpers.
//!
//! This module implements the "closure requires hard failure when telemetry is incomplete"
//! rule by validating:
//! - JSONL structured logs conform to `structured_log::validate_log_line`
//! - Artifact index schema and content
//! - Failure-path artifact references resolve to real files and match the index
//!
//! This is build/test tooling only.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::structured_log::{ArtifactIndex, Outcome, validate_log_line};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceViolation {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_number: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceComplianceReport {
    pub ok: bool,
    pub violations: Vec<EvidenceViolation>,
}

impl EvidenceComplianceReport {
    #[must_use]
    pub fn ok() -> Self {
        Self {
            ok: true,
            violations: Vec::new(),
        }
    }

    pub fn push(&mut self, v: EvidenceViolation) {
        self.ok = false;
        self.violations.push(v);
    }

    pub fn sort_deterministically(&mut self) {
        self.violations.sort_by(|a, b| {
            a.code
                .cmp(&b.code)
                .then_with(|| a.path.cmp(&b.path))
                .then_with(|| a.line_number.cmp(&b.line_number))
                .then_with(|| a.trace_id.cmp(&b.trace_id))
                .then_with(|| a.message.cmp(&b.message))
        });
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut out, "{b:02x}").expect("writing to String should not fail");
    }
    out
}

fn sha256_hex(path: &Path) -> Result<String, String> {
    use sha2::Digest;
    let data =
        std::fs::read(path).map_err(|err| format!("failed reading '{}': {err}", path.display()))?;
    Ok(hex_lower(&sha2::Sha256::digest(&data)))
}

fn resolve_artifact_path(workspace_root: &Path, run_root: &Path, path: &str) -> Option<PathBuf> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Some(candidate.to_path_buf());
    }

    // Preferred: relative to the run directory (self-contained bundles).
    let in_run = run_root.join(candidate);
    if in_run.exists() {
        return Some(in_run);
    }

    // Fallback: relative to workspace root (legacy scripts).
    let in_ws = workspace_root.join(candidate);
    if in_ws.exists() {
        return Some(in_ws);
    }

    None
}

fn validate_artifact_index(
    report: &mut EvidenceComplianceReport,
    workspace_root: &Path,
    index_path: &Path,
) -> Option<ArtifactIndex> {
    let run_root = index_path.parent().unwrap_or(workspace_root);
    let content = match std::fs::read_to_string(index_path) {
        Ok(s) => s,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "artifact_index.missing".to_string(),
                message: format!(
                    "artifact index not readable: {}: {err}",
                    index_path.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(index_path.display().to_string()),
                remediation_hint: Some("regenerate artifact index for the run".to_string()),
            });
            return None;
        }
    };

    let idx: ArtifactIndex = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "artifact_index.invalid_json".to_string(),
                message: format!(
                    "artifact index JSON parse failed: {}: {err}",
                    index_path.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(index_path.display().to_string()),
                remediation_hint: Some(
                    "write valid JSON matching the artifact_index schema".to_string(),
                ),
            });
            return None;
        }
    };

    if idx.index_version != 1 {
        report.push(EvidenceViolation {
            code: "artifact_index.bad_version".to_string(),
            message: format!(
                "artifact index_version must be 1, got {}",
                idx.index_version
            ),
            trace_id: None,
            line_number: None,
            path: Some(index_path.display().to_string()),
            remediation_hint: Some("regenerate artifact index using the v1 schema".to_string()),
        });
    }

    for art in &idx.artifacts {
        let resolved = resolve_artifact_path(workspace_root, run_root, &art.path);
        let Some(resolved_path) = resolved else {
            report.push(EvidenceViolation {
                code: "artifact_index.artifact_missing".to_string(),
                message: format!(
                    "artifact listed in index does not exist: '{}' (searched under '{}' and '{}')",
                    art.path,
                    run_root.display(),
                    workspace_root.display()
                ),
                trace_id: None,
                line_number: None,
                path: Some(art.path.clone()),
                remediation_hint: Some(
                    "ensure artifacts are written and paths in artifact_index.json are correct"
                        .to_string(),
                ),
            });
            continue;
        };

        match sha256_hex(&resolved_path) {
            Ok(actual) => {
                if !actual.eq_ignore_ascii_case(&art.sha256) {
                    report.push(EvidenceViolation {
                        code: "artifact_index.sha_mismatch".to_string(),
                        message: format!(
                            "sha256 mismatch for '{}': expected={}, actual={}",
                            art.path, art.sha256, actual
                        ),
                        trace_id: None,
                        line_number: None,
                        path: Some(art.path.clone()),
                        remediation_hint: Some(
                            "regenerate the artifact or update its sha256 in artifact_index.json"
                                .to_string(),
                        ),
                    });
                }
            }
            Err(err) => report.push(EvidenceViolation {
                code: "artifact_index.sha_error".to_string(),
                message: err,
                trace_id: None,
                line_number: None,
                path: Some(art.path.clone()),
                remediation_hint: Some("ensure artifact file is readable".to_string()),
            }),
        }
    }

    Some(idx)
}

fn validate_failure_artifact_refs(
    report: &mut EvidenceComplianceReport,
    workspace_root: &Path,
    run_root: &Path,
    idx: &ArtifactIndex,
    trace_id: Option<String>,
    refs: &[String],
) {
    for r in refs {
        let resolved = resolve_artifact_path(workspace_root, run_root, r);
        if resolved.is_none() {
            report.push(EvidenceViolation {
                code: "failure_artifact_ref.missing".to_string(),
                message: format!(
                    "failure artifact ref does not exist: '{r}' (searched under '{}' and '{}')",
                    run_root.display(),
                    workspace_root.display()
                ),
                trace_id: trace_id.clone(),
                line_number: None,
                path: Some(r.clone()),
                remediation_hint: Some("write the referenced diagnostic artifact".to_string()),
            });
        }

        if !idx.artifacts.iter().any(|a| a.path == *r) {
            report.push(EvidenceViolation {
                code: "failure_artifact_ref.not_indexed".to_string(),
                message: format!("failure artifact ref not present in artifact_index.json: '{r}'"),
                trace_id: trace_id.clone(),
                line_number: None,
                path: Some(r.clone()),
                remediation_hint: Some(
                    "add the artifact to artifact_index.json (path/kind/sha256)".to_string(),
                ),
            });
        }
    }
}

/// Validate a (log, index) evidence bundle.
///
/// `workspace_root` is used as a fallback for legacy artifact paths; `index_path.parent()`
/// is treated as the preferred run root.
#[must_use]
pub fn validate_evidence_bundle(
    workspace_root: &Path,
    log_path: &Path,
    index_path: &Path,
) -> EvidenceComplianceReport {
    let mut report = EvidenceComplianceReport::ok();

    let idx = match validate_artifact_index(&mut report, workspace_root, index_path) {
        Some(v) => v,
        None => {
            report.sort_deterministically();
            return report;
        }
    };

    let run_root = index_path.parent().unwrap_or(workspace_root);
    let content = match std::fs::read_to_string(log_path) {
        Ok(s) => s,
        Err(err) => {
            report.push(EvidenceViolation {
                code: "log.missing".to_string(),
                message: format!("log not readable: {}: {err}", log_path.display()),
                trace_id: None,
                line_number: None,
                path: Some(log_path.display().to_string()),
                remediation_hint: Some("ensure the run writes a JSONL log file".to_string()),
            });
            report.sort_deterministically();
            return report;
        }
    };

    for (idx_line, raw) in content.lines().enumerate() {
        let line_no = idx_line + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }

        let entry = match validate_log_line(line, line_no) {
            Ok(e) => e,
            Err(errs) => {
                for e in errs {
                    report.push(EvidenceViolation {
                        code: "log.schema_violation".to_string(),
                        message: e.message,
                        trace_id: None,
                        line_number: Some(e.line_number),
                        path: Some(log_path.display().to_string()),
                        remediation_hint: Some(format!(
                            "fix field '{}' in emitted log line",
                            e.field
                        )),
                    });
                }
                continue;
            }
        };

        let is_failure = matches!(
            entry.outcome,
            Some(Outcome::Fail) | Some(Outcome::Error) | Some(Outcome::Timeout)
        );
        if !is_failure {
            continue;
        }

        let refs = entry.artifact_refs.clone().unwrap_or_default();
        if refs.is_empty() {
            report.push(EvidenceViolation {
                code: "failure_event.missing_artifact_refs".to_string(),
                message: "failure outcome requires non-empty artifact_refs".to_string(),
                trace_id: Some(entry.trace_id.clone()),
                line_number: Some(line_no),
                path: Some(log_path.display().to_string()),
                remediation_hint: Some(
                    "emit artifact_refs pointing to diffs/backtraces/reports for the failure"
                        .to_string(),
                ),
            });
            continue;
        }

        validate_failure_artifact_refs(
            &mut report,
            workspace_root,
            run_root,
            &idx,
            Some(entry.trace_id.clone()),
            &refs,
        );
    }

    report.sort_deterministically();
    report
}
