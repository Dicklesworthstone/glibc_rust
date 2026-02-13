// support_matrix_maintenance_test.rs — bd-3g4p
// Integration tests for the automated support matrix maintenance system.
// Validates: report generation, report schema, status validation coverage,
// conformance linkage coverage, and module coverage completeness.

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
fn maintenance_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_support_matrix_maintenance.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute maintenance validator");
    assert!(
        output.status.success(),
        "Maintenance validator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        report_path.exists(),
        "Report not generated at {}",
        report_path.display()
    );
}

#[test]
fn maintenance_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    if !report_path.exists() {
        // Generate it if missing
        let _ = Command::new("python3")
            .args([
                root.join("scripts/generate_support_matrix_maintenance.py")
                    .to_str()
                    .unwrap(),
                "-o",
                report_path.to_str().unwrap(),
            ])
            .current_dir(&root)
            .output();
    }
    let data = load_json(&report_path);

    // Check top-level fields
    assert_eq!(
        data["schema_version"].as_str(),
        Some("v1"),
        "Wrong schema version"
    );
    assert_eq!(
        data["bead"].as_str(),
        Some("bd-3g4p"),
        "Wrong bead reference"
    );

    // Check summary fields
    let summary = &data["summary"];
    let required_fields = [
        "total_symbols",
        "status_validated",
        "status_invalid",
        "status_skipped",
        "status_valid_pct",
        "fixture_linked",
        "fixture_unlinked",
        "fixture_coverage_pct",
    ];
    for field in &required_fields {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }

    // Check sections exist
    assert!(
        data["status_distribution"].is_object(),
        "Missing status_distribution"
    );
    assert!(
        data["module_coverage"].is_object(),
        "Missing module_coverage"
    );
    assert!(
        data["status_validation_issues"].is_array(),
        "Missing status_validation_issues"
    );
    assert!(
        data["unlinked_symbols"].is_array(),
        "Missing unlinked_symbols"
    );
}

#[test]
fn maintenance_status_validation_above_threshold() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let valid_pct = data["summary"]["status_valid_pct"].as_f64().unwrap();
    assert!(
        valid_pct >= 80.0,
        "Status validation {valid_pct}% below 80% threshold"
    );

    let total = data["summary"]["total_symbols"].as_u64().unwrap();
    assert!(
        total >= 200,
        "Expected at least 200 symbols in matrix, got {total}"
    );
}

#[test]
fn maintenance_module_coverage_consistent() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/support_matrix_maintenance_report.v1.json");
    let data = load_json(&report_path);

    let module_cov = data["module_coverage"].as_object().unwrap();
    let mut total_from_modules: u64 = 0;
    for (_mod_name, info) in module_cov {
        let t = info["total"].as_u64().unwrap();
        let l = info["linked"].as_u64().unwrap();
        total_from_modules += t;
        assert!(
            l <= t,
            "Module {} has more linked ({l}) than total ({t})",
            _mod_name
        );
        let pct = info["coverage_pct"].as_f64().unwrap();
        assert!(
            (0.0..=100.0).contains(&pct),
            "Module {} coverage {pct}% out of range",
            _mod_name
        );
    }

    let total_from_summary = data["summary"]["total_symbols"].as_u64().unwrap();
    assert_eq!(
        total_from_modules, total_from_summary,
        "Module total ({total_from_modules}) != summary total ({total_from_summary})"
    );
}
