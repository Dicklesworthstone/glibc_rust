// cve_integer_overflow_validation_test.rs — bd-1m5.4
// Integration tests for the CVE Arena integer overflow validation system.

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
fn intovf_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/integer_overflow_validation.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_integer_overflow_validation.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute integer overflow validator");
    assert!(
        output.status.success(),
        "Integer overflow validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn intovf_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/integer_overflow_validation.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.4"));

    let summary = &data["summary"];
    for field in &[
        "total_intovf_tests",
        "manifests_valid",
        "unique_healing_actions",
        "overflow_patterns_covered",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["tests"].is_array());
}

#[test]
fn intovf_all_manifests_valid() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/integer_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let tests = data["tests"].as_array().unwrap();
    assert!(!tests.is_empty(), "No integer overflow tests found");

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
fn intovf_clamp_size_healing_exercised() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/integer_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let healing: Vec<&str> = data["summary"]["unique_healing_actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert!(
        healing.contains(&"ClampSize"),
        "ClampSize healing action not exercised"
    );
}

#[test]
fn intovf_overflow_pattern_covered() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/integer_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let patterns: Vec<&str> = data["summary"]["overflow_patterns_covered"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();

    assert!(
        patterns.contains(&"integer_overflow"),
        "integer_overflow pattern not covered"
    );
}
