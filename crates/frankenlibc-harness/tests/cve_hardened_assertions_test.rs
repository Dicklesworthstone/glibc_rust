// cve_hardened_assertions_test.rs — bd-1m5.6
// Integration tests for the hardened CVE prevention/healing assertion suite.

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
fn hardened_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_hardened_assertions.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute hardened assertions generator");
    assert!(
        output.status.success(),
        "Hardened assertions generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn hardened_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.6"));

    let summary = &data["summary"];
    for field in &[
        "total_assertions",
        "no_crash_in_hardened",
        "with_healing_actions",
        "prevention_strategies",
        "unique_healing_actions",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["assertion_matrix"].is_array());
    assert!(data["healing_expectation_map"].is_object());
}

#[test]
fn hardened_all_cves_no_crash() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let assertions = data["assertion_matrix"].as_array().unwrap();
    assert!(!assertions.is_empty(), "No hardened assertions");

    for a in assertions {
        let cve_id = a["cve_id"].as_str().unwrap_or("unknown");
        assert!(
            !a["hardened_expectations"]["crashes"].as_bool().unwrap(),
            "{} expected to crash in hardened mode",
            cve_id
        );
        assert!(
            a["hardened_expectations"]["no_uncontrolled_unsafety"]
                .as_bool()
                .unwrap(),
            "{} has uncontrolled memory unsafety",
            cve_id
        );
    }
}

#[test]
fn hardened_all_cves_have_healing_actions() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let assertions = data["assertion_matrix"].as_array().unwrap();
    for a in assertions {
        let cve_id = a["cve_id"].as_str().unwrap_or("unknown");
        let healing = a["hardened_expectations"]["healing_actions_required"]
            .as_array()
            .unwrap();
        assert!(
            !healing.is_empty(),
            "{} has no healing actions defined",
            cve_id
        );
    }
}

#[test]
fn hardened_multiple_prevention_strategies() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let strategies = data["summary"]["prevention_strategies"]
        .as_object()
        .unwrap();
    assert!(
        strategies.len() >= 2,
        "Only {} prevention strategies (need >= 2)",
        strategies.len()
    );
}

#[test]
fn hardened_no_validation_errors() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let val_errors = data["summary"]["validation_errors"].as_u64().unwrap();
    assert_eq!(val_errors, 0, "Validation errors found");
}

#[test]
fn hardened_healing_expectation_map_populated() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/hardened_assertions.v1.json");
    let data = load_json(&report_path);

    let map = data["healing_expectation_map"].as_object().unwrap();
    assert!(
        map.len() >= 4,
        "Only {} healing actions in map (need >= 4)",
        map.len()
    );

    for (action, info) in map {
        let count = info["count"].as_u64().unwrap();
        assert!(count > 0, "Healing action {} has count 0", action);
    }
}
