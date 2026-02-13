// fuzz_harness_architecture_test.rs — bd-1oz.5
// Integration tests for fuzz harness architecture spec and corpus seeding.

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
fn fuzz_architecture_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_harness_architecture.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute fuzz architecture generator");
    assert!(
        output.status.success(),
        "Fuzz architecture generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn fuzz_architecture_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.5"));

    let summary = &data["summary"];
    for field in &[
        "total_targets",
        "functional_targets",
        "stub_targets",
        "checks_passed",
        "checks_total",
        "total_seed_corpus",
        "total_dict_entries",
        "unique_cwes",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["target_analyses"].is_array());
    assert!(data["corpus_strategy"].is_object());
    assert!(data["dictionary_strategy"].is_object());
    assert!(data["harness_conventions"].is_object());
    assert!(data["quality_checklist"].is_object());
}

#[test]
fn fuzz_architecture_all_conventions_pass() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_analyses"].as_array().unwrap();
    assert!(!targets.is_empty(), "No target analyses");

    for t in targets {
        let name = t["target"].as_str().unwrap_or("unknown");
        let checks = t["checks"].as_array().unwrap();
        for c in checks {
            let check_name = c["check"].as_str().unwrap_or("?");
            assert!(
                c["passed"].as_bool().unwrap(),
                "Target {} failed convention check: {}",
                name,
                check_name
            );
        }
    }
}

#[test]
fn fuzz_architecture_corpus_seeded() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    let manifests = data["corpus_strategy"]["manifests"].as_array().unwrap();
    assert!(!manifests.is_empty(), "No corpus manifests");

    for m in manifests {
        let target = m["target"].as_str().unwrap_or("unknown");
        let count = m["count"].as_u64().unwrap();
        assert!(count > 0, "Target {} has no seed corpus", target);
        assert!(
            m["reproducible"].as_bool().unwrap(),
            "Target {} corpus is not reproducible",
            target
        );
    }
}

#[test]
fn fuzz_architecture_dictionaries_present() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    let manifests = data["dictionary_strategy"]["manifests"].as_array().unwrap();
    assert!(!manifests.is_empty(), "No dictionary manifests");

    for m in manifests {
        let target = m["target"].as_str().unwrap_or("unknown");
        let count = m["count"].as_u64().unwrap();
        assert!(count > 0, "Target {} has no dictionary entries", target);
    }
}

#[test]
fn fuzz_architecture_cwe_coverage() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    let cwes = data["summary"]["cwe_coverage"].as_array().unwrap();
    assert!(
        cwes.len() >= 5,
        "Only {} CWEs covered (need >= 5)",
        cwes.len()
    );

    // Check each CWE is properly formatted
    for cwe in cwes {
        let s = cwe.as_str().unwrap();
        assert!(s.starts_with("CWE-"), "Invalid CWE format: {}", s);
    }
}

#[test]
fn fuzz_architecture_harness_conventions_documented() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_harness_architecture.v1.json");
    let data = load_json(&report_path);

    let conventions = &data["harness_conventions"];
    assert!(conventions["required_attributes"].is_array());
    assert!(conventions["required_macros"].is_array());
    assert!(conventions["input_handling"].is_object());
    assert!(conventions["safety_rules"].is_array());
    assert!(conventions["artifact_layout"].is_object());
    assert!(conventions["domains"].is_object());

    let safety_rules = conventions["safety_rules"].as_array().unwrap();
    assert!(
        safety_rules.len() >= 3,
        "Need at least 3 safety rules, got {}",
        safety_rules.len()
    );
}
