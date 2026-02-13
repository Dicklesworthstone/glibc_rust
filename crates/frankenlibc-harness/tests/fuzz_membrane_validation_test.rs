// fuzz_membrane_validation_test.rs — bd-1oz.4
// Integration tests for membrane fuzz target validation.

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
fn membrane_validation_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_membrane_validation.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute membrane validation generator");
    assert!(
        output.status.success(),
        "Membrane validation generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn membrane_validation_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.4"));
    assert!(data["validation_hash"].is_string());

    let summary = &data["summary"];
    assert!(!summary["readiness_pct"].is_null());
    assert!(!summary["total_gaps"].is_null());
    assert!(data["source_analysis"].is_object());
    assert!(data["fuzzing_strategies"].is_array());
    assert!(data["state_transitions"].is_array());
    assert!(data["cache_coherence"].is_array());
    assert!(data["invariant_checks"].is_array());
    assert!(data["gap_analysis"].is_array());
    assert!(data["success_criteria"].is_object());
}

#[test]
fn membrane_validation_pipeline_exercised() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let source = &data["source_analysis"];
    assert!(
        source["has_pipeline_creation"].as_bool().unwrap(),
        "ValidationPipeline not created in fuzz target"
    );
    assert!(
        source["has_outcome_checking"].as_bool().unwrap(),
        "Validation outcomes not checked in fuzz target"
    );
    assert!(
        source["has_fuzz_target"].as_bool().unwrap(),
        "Missing fuzz_target! macro"
    );
}

#[test]
fn membrane_validation_strategies_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let strategies = data["fuzzing_strategies"].as_array().unwrap();
    assert!(
        strategies.len() >= 3,
        "Only {} strategies documented (need >= 3)",
        strategies.len()
    );

    // At least one must be implemented
    let implemented = strategies
        .iter()
        .filter(|s| s["implemented"].as_bool().unwrap_or(false))
        .count();
    assert!(implemented >= 1, "No fuzzing strategies implemented");
}

#[test]
fn membrane_validation_state_transitions_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let transitions = data["state_transitions"].as_array().unwrap();
    assert!(
        transitions.len() >= 3,
        "Only {} state transitions (need >= 3)",
        transitions.len()
    );

    for t in transitions {
        assert!(t["from_state"].is_string());
        assert!(t["to_state"].is_string());
        assert!(t["trigger"].is_string());
    }
}

#[test]
fn membrane_validation_gaps_analyzed() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let readiness = data["summary"]["readiness_pct"].as_f64().unwrap();
    let gaps = data["gap_analysis"].as_array().unwrap();

    // If readiness < 100%, gaps must be documented
    if readiness < 100.0 {
        assert!(
            !gaps.is_empty(),
            "Readiness {}% but no gaps documented",
            readiness
        );
    }

    // Each gap must have required fields
    let valid_severities = ["low", "medium", "high"];
    for g in gaps {
        let severity = g["severity"].as_str().unwrap_or("?");
        assert!(
            valid_severities.contains(&severity),
            "Invalid gap severity: {}",
            severity
        );
        assert!(g["area"].is_string());
        assert!(g["item"].is_string());
    }
}

#[test]
fn membrane_validation_cwe_targets() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_membrane_validation.v1.json");
    let data = load_json(&report_path);

    let cwes = data["summary"]["cwe_targets"].as_array().unwrap();
    assert!(
        cwes.len() >= 2,
        "Only {} CWEs targeted (need >= 2)",
        cwes.len()
    );

    for cwe in cwes {
        let s = cwe.as_str().unwrap();
        assert!(s.starts_with("CWE-"), "Invalid CWE format: {}", s);
    }
}
