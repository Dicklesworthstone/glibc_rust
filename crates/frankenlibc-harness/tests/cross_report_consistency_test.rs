// cross_report_consistency_test.rs — bd-2vv.11
// Integration tests for cross-report consistency gate.

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
fn consistency_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cross_report_consistency.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute consistency generator");
    assert!(
        output.status.success(),
        "Consistency generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn consistency_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2vv.11"));
    assert!(data["consistency_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "overall_verdict",
        "total_findings",
        "reports_loaded",
        "reports_total",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(summary["by_severity"].is_object());
    assert!(summary["by_verdict"].is_object());
    assert!(data["findings"].is_array());
    assert!(data["reports_loaded"].is_object());
    assert!(data["consistency_rules"].is_object());
    assert!(data["ci_policy"].is_object());
}

#[test]
fn consistency_no_critical_findings() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    let critical = data["summary"]["by_severity"]["critical"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        critical, 0,
        "Found {} critical consistency findings",
        critical
    );
}

#[test]
fn consistency_symbol_counts_match() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    let findings = data["findings"].as_array().unwrap();
    let count_fails: Vec<_> = findings
        .iter()
        .filter(|f| {
            f["rule"].as_str().unwrap_or("").starts_with("symbol_count")
                && f["verdict"].as_str() == Some("fail")
        })
        .collect();

    assert!(
        count_fails.is_empty(),
        "Symbol count mismatches: {:?}",
        count_fails
            .iter()
            .map(|f| f["description"].as_str().unwrap_or(""))
            .collect::<Vec<_>>()
    );
}

#[test]
fn consistency_no_unknown_status() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    let findings = data["findings"].as_array().unwrap();
    let unknown_fail = findings.iter().any(|f| {
        f["rule"].as_str() == Some("no_unknown_status") && f["verdict"].as_str() == Some("fail")
    });

    assert!(!unknown_fail, "Symbols with unknown status found");
}

#[test]
fn consistency_multiple_reports_loaded() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    let loaded = data["summary"]["reports_loaded"].as_u64().unwrap();
    assert!(loaded >= 3, "Only {} reports loaded (need >= 3)", loaded);

    // support_matrix must always be loaded
    assert!(
        data["reports_loaded"]["support_matrix"].as_bool().unwrap(),
        "support_matrix not loaded"
    );
}

#[test]
fn consistency_rules_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/cross_report_consistency.v1.json");
    let data = load_json(&report_path);

    let rules = data["consistency_rules"].as_object().unwrap();
    assert!(
        rules.len() >= 3,
        "Only {} consistency rules (need >= 3)",
        rules.len()
    );

    let policy = data["ci_policy"].as_object().unwrap();
    assert!(
        policy.len() >= 3,
        "Only {} CI policy entries (need >= 3)",
        policy.len()
    );
}
