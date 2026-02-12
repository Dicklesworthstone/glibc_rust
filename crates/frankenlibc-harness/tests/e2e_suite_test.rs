//! Integration test: E2E suite infrastructure (bd-2ez)
//!
//! Validates that:
//! 1. e2e_suite.sh exists and is executable.
//! 2. check_e2e_suite.sh exists and is executable.
//! 3. The suite produces valid JSONL structured logs.
//! 4. Artifact index format is correct.
//!
//! Note: This tests the E2E *infrastructure*, not program pass rates.
//! LD_PRELOAD timeouts are expected during the interpose phase.
//!
//! Run: cargo test -p frankenlibc-harness --test e2e_suite_test

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn e2e_suite_script_exists() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");
    assert!(script.exists(), "scripts/e2e_suite.sh must exist");

    // Check executable bit
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(perms.mode() & 0o111 != 0, "e2e_suite.sh must be executable");
    }
}

#[test]
fn check_e2e_suite_script_exists() {
    let root = workspace_root();
    let script = root.join("scripts/check_e2e_suite.sh");
    assert!(script.exists(), "scripts/check_e2e_suite.sh must exist");
}

#[test]
fn e2e_suite_runs_and_produces_jsonl() {
    let root = workspace_root();

    // Run just the fault scenario with a very short timeout
    let output = Command::new("bash")
        .arg(root.join("scripts/e2e_suite.sh"))
        .arg("fault")
        .arg("strict")
        .env("TIMEOUT_SECONDS", "2")
        .output()
        .expect("e2e_suite.sh should execute");

    // The suite may fail (timeouts expected), but it should run
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("E2E Suite v1"), "Should print suite header");

    // Find the trace.jsonl in the latest run directory
    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        // Suite didn't produce output (maybe no lib), skip
        return;
    }

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("e2e-"))
        .collect();
    runs.sort_by_key(|e| e.file_name());

    if let Some(latest) = runs.last() {
        let trace_path = latest.path().join("trace.jsonl");
        if trace_path.exists() {
            let content = std::fs::read_to_string(&trace_path).unwrap();
            let mut valid_lines = 0;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let obj: serde_json::Value = serde_json::from_str(line)
                    .unwrap_or_else(|e| panic!("Invalid JSON at line: {e}"));
                assert!(obj["timestamp"].is_string(), "Missing timestamp");
                assert!(obj["trace_id"].is_string(), "Missing trace_id");
                assert!(obj["level"].is_string(), "Missing level");
                assert!(obj["event"].is_string(), "Missing event");

                let tid = obj["trace_id"].as_str().unwrap();
                assert!(tid.contains("::"), "trace_id should contain ::");
                assert!(
                    tid.starts_with("bd-2ez::"),
                    "trace_id should start with bd-2ez::"
                );
                valid_lines += 1;
            }
            assert!(
                valid_lines >= 2,
                "Expected at least suite_start + suite_end, got {} lines",
                valid_lines
            );
        }
    }
}

#[test]
fn e2e_artifact_index_valid() {
    let root = workspace_root();
    let e2e_dir = root.join("target/e2e_suite");
    if !e2e_dir.exists() {
        return; // No runs yet
    }

    let mut runs: Vec<_> = std::fs::read_dir(&e2e_dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().starts_with("e2e-"))
        .collect();
    runs.sort_by_key(|e| e.file_name());

    if let Some(latest) = runs.last() {
        let index_path = latest.path().join("artifact_index.json");
        if index_path.exists() {
            let content = std::fs::read_to_string(&index_path).unwrap();
            let idx: serde_json::Value =
                serde_json::from_str(&content).expect("artifact_index.json should be valid JSON");

            assert_eq!(
                idx["index_version"].as_u64().unwrap(),
                1,
                "Expected index_version 1"
            );
            assert_eq!(
                idx["bead_id"].as_str().unwrap(),
                "bd-2ez",
                "Expected bead_id bd-2ez"
            );
            assert!(idx["run_id"].is_string(), "Expected run_id string");
            assert!(idx["artifacts"].is_array(), "Expected artifacts array");

            let artifacts = idx["artifacts"].as_array().unwrap();
            for art in artifacts {
                assert!(art["path"].is_string(), "Artifact missing path");
                assert!(art["kind"].is_string(), "Artifact missing kind");
                assert!(art["sha256"].is_string(), "Artifact missing sha256");
            }
        }
    }
}

#[test]
fn e2e_suite_supports_scenario_filter() {
    let root = workspace_root();
    let script = root.join("scripts/e2e_suite.sh");

    // Verify that passing a scenario class filter works
    let output = Command::new("bash")
        .arg(&script)
        .arg("smoke")
        .arg("strict")
        .env("TIMEOUT_SECONDS", "1")
        .output()
        .expect("e2e_suite.sh should execute with filters");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should only run smoke, not stress or fault
    assert!(
        stdout.contains("scenario=smoke"),
        "Should show smoke scenario filter"
    );
    assert!(
        !stdout.contains("[FAIL] stress/"),
        "Should not run stress scenarios when filtered to smoke"
    );
    assert!(
        !stdout.contains("[FAIL] fault/"),
        "Should not run fault scenarios when filtered to smoke"
    );
}
