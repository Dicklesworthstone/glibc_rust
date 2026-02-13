// fuzz_phase1_targets_test.rs — bd-1oz.6
// Integration tests for fuzz phase-1 target readiness and crash triage flow.

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
fn phase1_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_fuzz_phase1_targets.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute phase-1 target generator");
    assert!(
        output.status.success(),
        "Phase-1 target generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn phase1_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-1oz.6"));

    let summary = &data["summary"];
    for field in &[
        "total_targets",
        "functional_targets",
        "smoke_viable_targets",
        "average_readiness_score",
        "total_symbols_covered",
        "total_cwes_targeted",
        "triage_steps",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(data["target_assessments"].is_array());
    assert!(data["crash_triage_policy"].is_object());
    assert!(data["smoke_test_configs"].is_object());
    assert!(data["coverage_summary"].is_object());
}

#[test]
fn phase1_targets_smoke_viable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    assert!(!targets.is_empty(), "No target assessments");

    for t in targets {
        let name = t["target"].as_str().unwrap_or("unknown");
        assert!(
            t["smoke_viable"].as_bool().unwrap(),
            "Target {} is not smoke-viable",
            name
        );
    }
}

#[test]
fn phase1_crash_triage_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    let triage = &data["crash_triage_policy"];

    // Classification
    let severity = &triage["classification"]["severity_levels"];
    assert!(severity.is_object(), "Missing severity levels");
    let severity_map = severity.as_object().unwrap();
    assert!(
        severity_map.len() >= 8,
        "Only {} severity classes (need >= 8)",
        severity_map.len()
    );

    // Dedup policy
    let dedup = &triage["dedup"];
    assert!(dedup["method"].is_string(), "Missing dedup method");
    assert!(dedup["frame_depth"].as_u64().unwrap() >= 3);

    // Triage flow
    let flow = triage["triage_flow"].as_array().unwrap();
    assert!(
        flow.len() >= 4,
        "Only {} triage steps (need >= 4)",
        flow.len()
    );

    // Check flow step ordering
    for (i, step) in flow.iter().enumerate() {
        let step_num = step["step"].as_u64().unwrap() as usize;
        assert_eq!(step_num, i + 1, "Triage steps not sequential");
    }
}

#[test]
fn phase1_symbol_coverage_adequate() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    let all_symbols = data["coverage_summary"]["all_symbols"].as_array().unwrap();
    assert!(
        all_symbols.len() >= 20,
        "Only {} symbols covered (need >= 20)",
        all_symbols.len()
    );

    let all_cwes = data["coverage_summary"]["all_cwes"].as_array().unwrap();
    assert!(
        all_cwes.len() >= 5,
        "Only {} CWEs targeted (need >= 5)",
        all_cwes.len()
    );
}

#[test]
fn phase1_smoke_configs_present() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    let configs = data["smoke_test_configs"].as_object().unwrap();
    assert!(!configs.is_empty(), "No smoke test configs");

    for (target, config) in configs {
        let max_time = config["max_total_time_secs"].as_u64().unwrap();
        assert!(
            max_time > 0 && max_time <= 300,
            "Target {} has unreasonable smoke time: {}s",
            target,
            max_time
        );
        assert!(
            config["expected_outcome"].as_str() == Some("no_crash"),
            "Target {} expected outcome should be no_crash",
            target
        );
    }
}

#[test]
fn phase1_readiness_scores_reasonable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/fuzz_phase1_targets.v1.json");
    let data = load_json(&report_path);

    let targets = data["target_assessments"].as_array().unwrap();
    let total_score: u64 = targets
        .iter()
        .map(|t| t["readiness_score"].as_u64().unwrap())
        .sum();
    let avg = total_score as f64 / targets.len() as f64;

    assert!(avg >= 50.0, "Average readiness score {} < 50 minimum", avg);

    // At least 2 targets should be functional
    let functional = targets
        .iter()
        .filter(|t| t["implementation_status"].as_str() == Some("functional"))
        .count();
    assert!(
        functional >= 2,
        "Only {} functional targets (need >= 2)",
        functional
    );
}
