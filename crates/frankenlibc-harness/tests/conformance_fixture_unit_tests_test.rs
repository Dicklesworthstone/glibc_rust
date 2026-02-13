// conformance_fixture_unit_tests_test.rs — bd-2hh.5
// Integration tests for conformance fixture verification and regression detection.

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
fn fixture_unit_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_conformance_fixture_unit_tests.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute fixture unit test generator");
    assert!(
        output.status.success(),
        "Fixture unit test generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn fixture_unit_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2hh.5"));

    let summary = &data["summary"];
    for field in &[
        "total_fixture_files",
        "valid_fixture_files",
        "total_cases",
        "total_issues",
        "determinism_verified",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["fixture_results"].is_array());
    assert!(data["regression_baseline"].is_object());
    assert!(data["fixture_hashes"].is_object());
}

#[test]
fn fixture_unit_all_files_valid() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let results = data["fixture_results"].as_array().unwrap();
    assert!(!results.is_empty(), "No fixture results");

    for r in results {
        let file = r["file"].as_str().unwrap_or("unknown");
        assert!(r["valid"].as_bool().unwrap(), "Invalid fixture: {}", file);
    }
}

#[test]
fn fixture_unit_determinism_verified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    assert!(
        data["summary"]["determinism_verified"].as_bool().unwrap(),
        "Fixture parsing not deterministic"
    );
}

#[test]
fn fixture_unit_regression_baseline_populated() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let baseline = &data["regression_baseline"];
    let symbol_count = baseline["symbol_count"].as_u64().unwrap();
    assert!(
        symbol_count >= 50,
        "Only {} symbols in baseline (need >= 50)",
        symbol_count
    );

    let symbols = baseline["symbols"].as_object().unwrap();
    for (sym, info) in symbols {
        let count = info["count"].as_u64().unwrap();
        assert!(count > 0, "Symbol {} has 0 cases in baseline", sym);
    }
}

#[test]
fn fixture_unit_all_have_hashes() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fixture_unit_tests.v1.json");
    let data = load_json(&report_path);

    let hashes = data["fixture_hashes"].as_object().unwrap();
    let results = data["fixture_results"].as_array().unwrap();

    assert_eq!(
        hashes.len(),
        results.len(),
        "Hash count doesn't match fixture count"
    );

    for (file, hash) in hashes {
        let h = hash.as_str().unwrap();
        assert!(!h.is_empty(), "Empty hash for fixture {}", file);
    }
}
