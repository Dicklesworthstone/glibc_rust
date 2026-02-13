//! Integration test: math value-proof ablations (bd-1rxj)
//!
//! Validates that:
//! 1. Ablation artifact exists and is well-formed.
//! 2. Ablation module set matches math_value_proof production modules.
//! 3. Gate script exists and is executable.
//! 4. Gate script succeeds and emits structured logs/report.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path).expect("json file should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn artifact_exists_and_valid() {
    let root = workspace_root();
    let path = root.join("tests/conformance/math_value_ablations.v1.json");
    let doc = load_json(&path);

    assert_eq!(doc["schema_version"].as_u64(), Some(1));
    assert_eq!(doc["bead"].as_str(), Some("bd-1rxj"));
    assert!(doc["evaluation_policy"].is_object());
    assert!(doc["experiments"].is_array());
    assert!(doc["summary"].is_object());
}

#[test]
fn module_set_matches_math_value_proof() {
    let root = workspace_root();
    let abl = load_json(&root.join("tests/conformance/math_value_ablations.v1.json"));
    let vp = load_json(&root.join("tests/conformance/math_value_proof.json"));

    let abl_modules: HashSet<String> = abl["experiments"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["module"].as_str().map(String::from))
        .collect();

    let vp_modules: HashSet<String> = vp["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            vp["production_monitor_assessments"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .filter_map(|e| e["module"].as_str().map(String::from))
        .collect();

    assert_eq!(
        abl_modules, vp_modules,
        "ablation module set must match value proof module set"
    );
    assert_eq!(
        abl["summary"]["total_modules"].as_u64(),
        Some(vp_modules.len() as u64),
        "summary.total_modules mismatch"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_value_ablations.sh");
    assert!(
        script.exists(),
        "scripts/check_math_value_ablations.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_value_ablations.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_value_ablations.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run value ablation gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/math_value_ablations.log.jsonl");
    let report_path = root.join("target/conformance/math_value_ablations.report.json");
    let report = load_json(&report_path);

    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-1rxj"));
    assert_eq!(report["ok"].as_bool(), Some(true));
    assert_eq!(report["failure_count"].as_u64(), Some(0));

    let content = std::fs::read_to_string(&log_path).expect("structured log file should exist");
    let mut count = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line).expect("log line must be JSON");
        assert!(row["trace_id"].as_str().is_some());
        assert!(row["mode"].as_str().is_some());
        assert!(row["symbol"].as_str().is_some());
        assert!(row["outcome"].as_str().is_some());
        assert!(row["errno"].is_number());
        assert!(row["timing_ns"].is_number());
        count += 1;
    }

    // one event per module per mode (strict + hardened)
    let modules = report["summary"]["total_modules"].as_u64().unwrap() as usize;
    assert_eq!(count, modules * 2, "expected 2 log rows per module");
}
