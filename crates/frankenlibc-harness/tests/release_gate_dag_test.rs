//! Integration test: deterministic release gate DAG runner (bd-5fw.2)
//!
//! Validates that:
//! 1. `release_gate_dag.v1.json` exists and has required schema fields.
//! 2. Gate dependencies are topological in declared order.
//! 3. `scripts/release_dry_run.sh` exists and is executable.
//! 4. Dry-run mode passes and emits dossier/state/log artifacts.
//! 5. Fail-fast simulation emits deterministic resume token.
//! 6. Resume token restarts from deterministic gate index with audit trail.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_dag() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/release_gate_dag.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("release_gate_dag.v1.json should be readable");
    serde_json::from_str(&content).expect("release_gate_dag.v1.json should be valid JSON")
}

fn unique_tmp_path(prefix: &str, suffix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after UNIX_EPOCH")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}{suffix}", std::process::id()))
}

#[test]
fn dag_exists_and_valid() {
    let dag = load_dag();
    assert_eq!(dag["schema_version"].as_u64(), Some(1));
    assert_eq!(dag["bead"].as_str(), Some("bd-5fw.2"));
    assert!(dag["gates"].is_array(), "gates must be an array");
    assert!(
        dag["gate_ordering_policy"].is_object(),
        "gate_ordering_policy missing"
    );
    assert!(dag["resume_policy"].is_object(), "resume_policy missing");
    assert!(
        dag["structured_log_requirements"].is_object(),
        "structured_log_requirements missing"
    );

    let gates = dag["gates"].as_array().unwrap();
    assert!(!gates.is_empty(), "gates must be non-empty");
    for gate in gates {
        let name = gate["gate_name"].as_str().unwrap_or("<missing>");
        assert!(gate["depends_on"].is_array(), "{name}: depends_on missing");
        assert!(
            gate["command"].as_str().is_some_and(|v| !v.is_empty()),
            "{name}: command missing"
        );
    }
}

#[test]
fn dependencies_are_topological_in_declared_order() {
    let dag = load_dag();
    let gates = dag["gates"].as_array().unwrap();
    let mut seen = HashSet::new();

    for gate in gates {
        let gate_name = gate["gate_name"].as_str().unwrap();
        for dep in gate["depends_on"].as_array().unwrap() {
            let dep_name = dep.as_str().unwrap();
            assert!(
                seen.contains(dep_name),
                "{gate_name}: dependency '{dep_name}' appears after this gate"
            );
        }
        seen.insert(gate_name.to_string());
    }
}

#[test]
fn runner_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/release_dry_run.sh");
    assert!(script.exists(), "scripts/release_dry_run.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "release_dry_run.sh must be executable"
        );
    }
}

#[test]
fn dry_run_passes_and_emits_artifacts() {
    let root = workspace_root();
    let script = root.join("scripts/release_dry_run.sh");
    let log_path = unique_tmp_path("release-dry-run-pass-log", ".jsonl");
    let state_path = unique_tmp_path("release-dry-run-pass-state", ".json");
    let dossier_path = unique_tmp_path("release-dry-run-pass-dossier", ".json");

    let output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--log-path")
        .arg(&log_path)
        .arg("--state-path")
        .arg(&state_path)
        .arg("--dossier-path")
        .arg(&dossier_path)
        .current_dir(&root)
        .output()
        .expect("release_dry_run.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "release_dry_run.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );
    }

    assert!(log_path.exists(), "log output must exist");
    assert!(state_path.exists(), "state output must exist");
    assert!(dossier_path.exists(), "dossier output must exist");

    let log_body = std::fs::read_to_string(&log_path).expect("log should be readable");
    let lines: Vec<&str> = log_body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "log should contain gate rows");

    let dossier: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&dossier_path).unwrap()).unwrap();
    assert!(
        dossier["gate_count"].as_u64().unwrap() as usize >= lines.len(),
        "dossier gate_count should cover logged rows"
    );

    let _ = std::fs::remove_file(log_path);
    let _ = std::fs::remove_file(state_path);
    let _ = std::fs::remove_file(dossier_path);
}

#[test]
fn fail_fast_then_resume_is_deterministic() {
    let root = workspace_root();
    let script = root.join("scripts/release_dry_run.sh");
    let fail_log = unique_tmp_path("release-dry-run-fail-log", ".jsonl");
    let fail_state = unique_tmp_path("release-dry-run-fail-state", ".json");
    let fail_dossier = unique_tmp_path("release-dry-run-fail-dossier", ".json");

    let fail_output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--log-path")
        .arg(&fail_log)
        .arg("--state-path")
        .arg(&fail_state)
        .arg("--dossier-path")
        .arg(&fail_dossier)
        .env("FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE", "e2e")
        .current_dir(&root)
        .output()
        .expect("release_dry_run.sh fail-fast run should execute");

    assert!(
        !fail_output.status.success(),
        "simulated failure gate must force non-zero exit"
    );
    assert!(
        fail_state.exists(),
        "state file should be written on failure"
    );
    assert!(fail_log.exists(), "log file should be written on failure");

    let state_json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&fail_state).unwrap()).unwrap();
    assert_eq!(
        state_json["failed_gate"].as_str(),
        Some("e2e"),
        "expected fail-fast at e2e gate"
    );
    assert_eq!(state_json["failed_gate_index"].as_u64(), Some(3));
    let token = state_json["resume_token"]
        .as_str()
        .expect("resume token should be emitted");
    assert!(
        token.starts_with("v1:"),
        "resume token should use v1 format, got {token}"
    );

    let resume_log = unique_tmp_path("release-dry-run-resume-log", ".jsonl");
    let resume_state = unique_tmp_path("release-dry-run-resume-state", ".json");
    let resume_dossier = unique_tmp_path("release-dry-run-resume-dossier", ".json");

    let resume_output = Command::new("bash")
        .arg(&script)
        .arg("--mode")
        .arg("dry-run")
        .arg("--resume-token")
        .arg(token)
        .arg("--log-path")
        .arg(&resume_log)
        .arg("--state-path")
        .arg(&resume_state)
        .arg("--dossier-path")
        .arg(&resume_dossier)
        .current_dir(&root)
        .output()
        .expect("release_dry_run.sh resume run should execute");

    if !resume_output.status.success() {
        let stdout = String::from_utf8_lossy(&resume_output.stdout);
        let stderr = String::from_utf8_lossy(&resume_output.stderr);
        panic!(
            "resume run failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            resume_output.status, stdout, stderr
        );
    }

    let resume_lines = std::fs::read_to_string(&resume_log).unwrap();
    let rows: Vec<serde_json::Value> = resume_lines
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("resume log row must be valid JSON"))
        .collect();
    assert!(
        rows.len() >= 4,
        "resume run should emit rows for all gates, got {}",
        rows.len()
    );

    for row in rows.iter().take(3) {
        assert_eq!(
            row["status"].as_str(),
            Some("resume_skip"),
            "gates before resume index should be resume_skip"
        );
    }
    assert_eq!(
        rows[3]["gate_name"].as_str(),
        Some("e2e"),
        "resume should restart at e2e gate index"
    );
    assert_eq!(
        rows[3]["status"].as_str(),
        Some("pass"),
        "resume should execute failed gate successfully after clearing failure env"
    );

    let _ = std::fs::remove_file(fail_log);
    let _ = std::fs::remove_file(fail_state);
    let _ = std::fs::remove_file(fail_dossier);
    let _ = std::fs::remove_file(resume_log);
    let _ = std::fs::remove_file(resume_state);
    let _ = std::fs::remove_file(resume_dossier);
}
