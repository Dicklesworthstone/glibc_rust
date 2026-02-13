// cve_corpus_normalization_test.rs — bd-1m5.5
// Integration tests for CVE corpus normalization and deterministic replay metadata.

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
fn corpus_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_cve_corpus_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute corpus normalization validator");
    assert!(
        output.status.success(),
        "Corpus normalization failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn corpus_report_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1m5.5"));

    let summary = &data["summary"];
    for field in &[
        "total_cve_tests",
        "manifests_valid",
        "vulnerability_classes",
        "unique_healing_actions",
        "unique_cwe_ids",
        "categories",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["corpus_index"].is_array());
    assert!(data["normalization_changes"].is_array());
}

#[test]
fn corpus_all_manifests_valid() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    assert!(!corpus.is_empty(), "No CVE tests in corpus");

    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        assert!(
            entry["manifest_valid"].as_bool().unwrap(),
            "Invalid manifest for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_replay_keys() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let replay_key = entry["replay"]["replay_key"].as_str();
        assert!(
            replay_key.is_some() && !replay_key.unwrap().is_empty(),
            "Missing replay_key for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_vulnerability_classes() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let classes = entry["vulnerability_classes"].as_array().unwrap();
        assert!(
            !classes.is_empty(),
            "No vulnerability classes for {}",
            cve_id
        );
        let first = classes[0].as_str().unwrap();
        assert_ne!(
            first, "unknown",
            "Unknown vulnerability class for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_all_entries_have_dual_mode_expectations() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let corpus = data["corpus_index"].as_array().unwrap();
    for entry in corpus {
        let cve_id = entry["cve_id"].as_str().unwrap_or("unknown");
        let replay = &entry["replay"];
        assert!(
            !replay["expected_strict"]["crashes"].is_null(),
            "Missing strict crashes expectation for {}",
            cve_id
        );
        assert!(
            !replay["expected_hardened"]["crashes"].is_null(),
            "Missing hardened crashes expectation for {}",
            cve_id
        );
    }
}

#[test]
fn corpus_multiple_vulnerability_classes_covered() {
    let root = repo_root();
    let report_path = root.join("tests/cve_arena/results/corpus_normalization.v1.json");
    let data = load_json(&report_path);

    let classes = data["summary"]["vulnerability_classes"].as_array().unwrap();
    assert!(
        classes.len() >= 3,
        "Only {} vulnerability classes covered (need >= 3)",
        classes.len()
    );
}
