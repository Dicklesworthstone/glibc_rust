//! Integration test: runtime_math risk+pareto calibration guard (bd-w2c3.5.1)
//!
//! Validates that:
//! 1. calibration baseline artifact exists and has expected shape,
//! 2. generator check mode passes against committed baseline,
//! 3. gate script emits report + structured log and passes,
//! 4. gate script fails when artifact is tampered.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn script_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn lock_scripts() -> MutexGuard<'static, ()> {
    script_lock().lock().unwrap_or_else(|e| e.into_inner())
}

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
    let content = std::fs::read_to_string(path).expect("json should be readable");
    serde_json::from_str(&content).expect("json should parse")
}

#[test]
fn calibration_artifact_shape_is_valid() {
    let root = workspace_root();
    let artifact = root.join("tests/runtime_math/risk_pareto_calibration.v1.json");
    assert!(artifact.exists(), "missing {}", artifact.display());

    let doc = load_json(&artifact);
    assert_eq!(doc["schema_version"].as_str(), Some("v1"));
    assert_eq!(doc["bead"].as_str(), Some("bd-w2c3.5.1"));

    for mode in ["strict", "hardened"] {
        let row = &doc[mode];
        assert!(
            row["family_diagnostics"].is_array(),
            "{mode} family_diagnostics must be an array"
        );
        assert!(
            row["snapshot"].is_object(),
            "{mode} snapshot must be an object"
        );
        assert!(
            row["action_summary"].is_object(),
            "{mode} action_summary must be an object"
        );
        assert!(
            row["risk_summary"].is_object(),
            "{mode} risk_summary must be an object"
        );
    }
}

#[test]
fn generator_check_passes() {
    let _guard = lock_scripts();
    let root = workspace_root();
    let script = root.join("scripts/generate_runtime_math_risk_pareto_calibration.py");
    assert!(script.exists(), "missing {}", script.display());

    let output = Command::new("python3")
        .arg(&script)
        .arg("--check")
        .current_dir(&root)
        .output()
        .expect("failed to run generator in check mode");

    assert!(
        output.status.success(),
        "generator --check failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn gate_script_emits_report_and_log() {
    let _guard = lock_scripts();
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_risk_pareto_calibration.sh");
    assert!(script.exists(), "missing {}", script.display());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_math_risk_pareto_calibration.sh must be executable"
        );
    }

    let output = Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run risk+pareto calibration gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_path =
        root.join("target/conformance/runtime_math_risk_pareto_calibration.report.json");
    let log_path = root.join("target/conformance/runtime_math_risk_pareto_calibration.log.jsonl");

    let report = load_json(&report_path);
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["bead"].as_str(), Some("bd-w2c3.5.1"));
    assert_eq!(report["summary"]["failed"].as_u64(), Some(0));

    let (line_count, errors) = frankenlibc_harness::structured_log::validate_log_file(&log_path)
        .expect("structured log should be readable");
    assert_eq!(line_count, 1, "expected one summary log line");
    assert!(errors.is_empty(), "structured log errors: {errors:#?}");
}

#[test]
fn gate_script_fails_when_artifact_is_tampered() {
    let _guard = lock_scripts();
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_math_risk_pareto_calibration.sh");

    let original_path = root.join("tests/runtime_math/risk_pareto_calibration.v1.json");
    let mut doc = load_json(&original_path);

    let strict_rows = doc["strict"]["family_diagnostics"]
        .as_array_mut()
        .expect("strict family_diagnostics must be array");
    let first = strict_rows
        .first_mut()
        .expect("strict family_diagnostics should be non-empty");
    let current = first["mean_risk_ppm"]
        .as_u64()
        .expect("mean_risk_ppm should be integer");
    first["mean_risk_ppm"] = serde_json::json!(current.saturating_add(1));

    let tmp_name = format!(
        "risk_pareto_calibration_tampered_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let tmp_path = std::env::temp_dir().join(tmp_name);
    std::fs::write(
        &tmp_path,
        serde_json::to_string_pretty(&doc).unwrap() + "\n",
    )
    .unwrap();

    let output = Command::new(&script)
        .env("FRANKENLIBC_RISK_PARETO_CALIBRATION_PATH", &tmp_path)
        .current_dir(&root)
        .output()
        .expect("failed to run risk+pareto calibration guard with tampered artifact");

    let _ = std::fs::remove_file(&tmp_path);

    assert!(
        !output.status.success(),
        "gate should fail when calibration baseline is tampered"
    );

    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("calibration_baseline_match"),
        "failure output should mention calibration_baseline_match; output:\n{}",
        combined
    );
}
