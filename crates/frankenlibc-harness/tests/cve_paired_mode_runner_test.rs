// cve_paired_mode_runner_test.rs — bd-1m5.7
// Integration tests for the strict detection + paired-mode CVE evidence runner.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn paired_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_paired_mode_runner.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute paired-mode runner");
    assert!(
        output.status.success(),
        "Paired-mode runner failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn paired_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.7"));

    let summary = &data["summary"];
    for field in &[
        "total_paired_scenarios",
        "strict_detected",
        "hardened_prevented",
        "unique_detection_flags",
        "unique_dossier_ids",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["paired_evidence"].is_array());
}

#[test]
fn paired_all_strict_detected() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    assert!(!evidence.is_empty(), "No paired evidence entries");

    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        assert_eq!(
            e["strict_mode"]["verdict"].as_str().unwrap(),
            "detected",
            "{} not detected in strict mode",
            cve_id
        );
    }
}

#[test]
fn paired_all_hardened_prevented() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        assert_eq!(
            e["hardened_mode"]["verdict"].as_str().unwrap(),
            "prevented",
            "{} not prevented in hardened mode",
            cve_id
        );
    }
}

#[test]
fn paired_unique_dossier_ids() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    let dossier_ids: HashSet<&str> = evidence
        .iter()
        .map(|e| e["dossier_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        dossier_ids.len(),
        evidence.len(),
        "Duplicate dossier IDs found"
    );
}

#[test]
fn paired_evidence_bundles_joinable() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let evidence = data["paired_evidence"].as_array().unwrap();
    for e in evidence {
        let cve_id = e["cve_id"].as_str().unwrap_or("unknown");
        let joinable: Vec<&str> = e["evidence_bundle"]["joinable_on"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            joinable.contains(&"dossier_id"),
            "{} not joinable on dossier_id",
            cve_id
        );
        assert!(
            joinable.contains(&"cve_id"),
            "{} not joinable on cve_id",
            cve_id
        );
    }
}

#[test]
fn paired_no_validation_errors() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/paired_mode_evidence.v1.json");
    let data = load_json(&report_path);

    let val_errors = data["summary"]["validation_errors"].as_u64().unwrap();
    assert_eq!(val_errors, 0, "Validation errors found");
}
