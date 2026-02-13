// conformance_fixture_pipeline_test.rs — bd-2hh.1
// Integration tests for the conformance fixture capture pipeline.

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
fn pipeline_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_conformance_fixture_pipeline.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute fixture pipeline generator");
    assert!(
        output.status.success(),
        "Fixture pipeline generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn pipeline_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2hh.1"));

    let summary = &data["summary"];
    for field in &[
        "total_fixture_files",
        "total_fixture_cases",
        "implemented_symbols",
        "symbols_with_fixtures",
        "coverage_pct",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["module_summary"].is_array());
    assert!(data["symbol_coverage"].is_array());
    assert!(data["fixture_files"].is_array());
}

#[test]
fn pipeline_fixtures_have_valid_format() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path);

    let format_issues = data["summary"]["fixture_format_issues"].as_u64().unwrap();
    assert_eq!(format_issues, 0, "Fixture format issues found");

    let files = data["fixture_files"].as_array().unwrap();
    for f in files {
        assert!(
            f["valid"].as_bool().unwrap(),
            "Invalid fixture file: {}",
            f["file"].as_str().unwrap()
        );
    }
}

#[test]
fn pipeline_sufficient_coverage() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path);

    let coverage = data["summary"]["coverage_pct"].as_f64().unwrap();
    assert!(
        coverage >= 50.0,
        "Symbol coverage {coverage}% is below 50% minimum"
    );
}

#[test]
fn pipeline_sufficient_cases() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path);

    let total = data["summary"]["total_fixture_cases"].as_u64().unwrap();
    assert!(total >= 100, "Only {total} fixture cases (need >= 100)");
}

#[test]
fn pipeline_multiple_modules_covered() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_pipeline.v1.json");
    let data = load_json(&report_path);

    let modules = data["module_summary"].as_array().unwrap();
    let covered = modules
        .iter()
        .filter(|m| m["covered_symbols"].as_u64().unwrap() > 0)
        .count();
    assert!(
        covered >= 5,
        "Only {covered} modules have fixtures (need >= 5)"
    );
}
