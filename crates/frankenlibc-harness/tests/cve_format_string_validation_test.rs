// cve_format_string_validation_test.rs — bd-1m5.2
// Integration tests for the CVE Arena format string validation system.
// Validates: report generation, manifest completeness, attack vector coverage,
// healing action coverage, and coverage matrix consistency.

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
fn format_string_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/format_string_validation.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_format_string_validation.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute format string validator");
    assert!(
        output.status.success(),
        "Format string validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn format_string_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/format_string_validation.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.2"));

    let summary = &data["summary"];
    for field in &[
        "total_format_string_tests",
        "manifests_valid",
        "unique_healing_actions",
        "attack_vectors_covered",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["tests"].is_array());
    assert!(data["coverage_matrix_check"].is_object());
}

#[test]
fn format_string_manifests_valid() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/format_string_validation.v1.json");
    let data = load_json(&report_path);

    let tests = data["tests"].as_array().unwrap();
    assert!(!tests.is_empty(), "No format string tests found");

    for test in tests {
        let cve_id = test["cve_id"].as_str().unwrap_or("unknown");
        assert!(
            test["manifest_valid"].as_bool().unwrap(),
            "Invalid manifest for {}",
            cve_id
        );
    }
}

#[test]
fn format_string_attack_vectors_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/format_string_validation.v1.json");
    let data = load_json(&report_path);

    let covered: Vec<&str> = data["summary"]["attack_vectors_covered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    let target: Vec<&str> = data["summary"]["attack_vectors_target"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    for expected in &target {
        assert!(
            covered.contains(expected),
            "Missing attack vector: {}",
            expected
        );
    }
}

#[test]
fn format_string_upgrade_to_safe_variant_exercised() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/format_string_validation.v1.json");
    let data = load_json(&report_path);

    let healing = data["summary"]["unique_healing_actions"]
        .as_array()
        .unwrap();
    let has_upgrade = healing
        .iter()
        .any(|h| h.as_str() == Some("UpgradeToSafeVariant"));
    assert!(
        has_upgrade,
        "UpgradeToSafeVariant not exercised by any format string test"
    );
}
