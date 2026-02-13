// reverse_round_contracts_test.rs — bd-2a2.4
// Integration tests for reverse-round math-to-subsystem contract verification.

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
fn contracts_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_reverse_round_contracts.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute contracts generator");
    assert!(
        output.status.success(),
        "Contracts generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn contracts_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2a2.4"));
    assert!(data["report_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "rounds_verified",
        "total_math_families",
        "modules_found",
        "invariants_specified",
        "math_class_count",
        "all_rounds_diverse",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["round_results"].is_object());
    assert!(data["branch_diversity_rule"].is_object());
    assert!(data["golden_output"].is_object());
}

#[test]
fn contracts_all_modules_exist() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let families = round_data["math_families"].as_object().unwrap();
        for (fam_name, fam_data) in families {
            assert!(
                fam_data["module_exists"].as_bool().unwrap(),
                "Round {} family {} module {} not found",
                round_id,
                fam_name,
                fam_data["module"].as_str().unwrap_or("?")
            );
        }
    }
}

#[test]
fn contracts_all_invariants_specified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let specified = data["summary"]["invariants_specified"].as_u64().unwrap();
    let total = data["summary"]["invariants_total"].as_u64().unwrap();
    assert_eq!(
        specified,
        total,
        "{} invariants missing ({}/{})",
        total - specified,
        specified,
        total
    );
}

#[test]
fn contracts_branch_diversity() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    assert!(
        data["summary"]["all_rounds_diverse"].as_bool().unwrap(),
        "Not all rounds pass branch-diversity (>= 3 math classes)"
    );

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let diversity = &round_data["branch_diversity"];
        let class_count = diversity["class_count"].as_u64().unwrap();
        assert!(
            class_count >= 3,
            "Round {} has only {} math classes (need >= 3)",
            round_id,
            class_count
        );
    }
}

#[test]
fn contracts_legacy_surfaces_anchored() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data = load_json(&report_path);

    let rounds = data["round_results"].as_object().unwrap();
    for (round_id, round_data) in rounds {
        let surfaces = round_data["legacy_surfaces"].as_array().unwrap();
        assert!(
            !surfaces.is_empty(),
            "Round {} has no legacy surface anchors",
            round_id
        );
        assert!(
            round_data["failure_class"].is_string(),
            "Round {} missing failure class",
            round_id
        );
    }
}

#[test]
fn contracts_reproducible() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/reverse_round_contracts.v1.json");
    let data1 = load_json(&report_path);

    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_reverse_round_contracts.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["report_hash"].as_str(),
        data2["report_hash"].as_str(),
        "Report hash changed on regeneration"
    );
}
