// cve_heap_overflow_validation_test.rs — bd-1m5.1
// Integration tests for the CVE Arena heap overflow validation system.
// Validates: report generation, manifest completeness, C trigger compilation,
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
fn heap_overflow_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_heap_overflow_validation.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute heap overflow validator");
    assert!(
        output.status.success(),
        "Heap overflow validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report_path.exists(),
        "Report not generated at {}",
        report_path.display()
    );
}

#[test]
fn heap_overflow_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    if !report_path.exists() {
        let _ = Command::new("python3")
            .args([
                root.join("scripts/generate_cve_heap_overflow_validation.py")
                    .to_str()
                    .unwrap(),
                "-o",
                report_path.to_str().unwrap(),
            ])
            .current_dir(&root)
            .output();
    }
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.1"));

    let summary = &data["summary"];
    for field in &[
        "total_heap_overflow_tests",
        "manifests_valid",
        "with_trigger_files",
        "unique_healing_actions",
        "heap_cwes_covered",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }

    assert!(data["tests"].is_array(), "Missing tests array");
    assert!(
        data["coverage_matrix_check"].is_object(),
        "Missing coverage_matrix_check"
    );
}

#[test]
fn heap_overflow_all_manifests_valid() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let tests = data["tests"].as_array().unwrap();
    assert!(!tests.is_empty(), "No heap overflow tests found");

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
fn heap_overflow_c_triggers_compile() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let tests = data["tests"].as_array().unwrap();
    for test in tests {
        if let Some(compiles) = test["c_compiles"].as_bool() {
            let cve_id = test["cve_id"].as_str().unwrap_or("unknown");
            assert!(compiles, "C trigger for {} fails to compile", cve_id);
        }
    }
}

#[test]
fn heap_overflow_clampsize_exercised() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let healing = data["summary"]["unique_healing_actions"]
        .as_array()
        .unwrap();
    let has_clamp = healing.iter().any(|h| h.as_str() == Some("ClampSize"));
    assert!(
        has_clamp,
        "ClampSize healing not exercised by any heap overflow test"
    );
}

#[test]
fn heap_overflow_coverage_matrix_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/heap_overflow_validation.v1.json");
    let data = load_json(&report_path);

    let matrix = &data["coverage_matrix_check"];
    assert!(
        matrix["exists"].as_bool().unwrap(),
        "Coverage matrix missing"
    );

    let missing = matrix["heap_cves_missing"].as_array().unwrap();
    assert!(
        missing.is_empty(),
        "Coverage matrix missing heap CVEs: {:?}",
        missing
    );
}
