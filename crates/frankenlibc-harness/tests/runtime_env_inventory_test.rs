//! Integration test: runtime env inventory gate (bd-29b.1)
//!
//! Validates that:
//! 1. Runtime env inventory file exists and is valid JSON.
//! 2. Required semantic metadata fields are present for each key.
//! 3. Unknown/ambiguous key list is empty.
//! 4. Gate script exists and is executable.
//! 5. Gate script passes reproducibility check.

use std::collections::HashSet;
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

fn load_inventory() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/runtime_env_inventory.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("runtime_env_inventory.v1.json should exist");
    serde_json::from_str(&content).expect("runtime_env_inventory.v1.json should be valid JSON")
}

#[test]
fn inventory_file_exists_and_has_schema() {
    let payload = load_inventory();
    assert_eq!(
        payload["schema_version"].as_str(),
        Some("v1"),
        "schema_version must be v1"
    );
    assert!(
        payload["inventory"].is_array(),
        "inventory must be an array"
    );
    assert!(
        payload["unknown_or_ambiguous"].is_array(),
        "unknown_or_ambiguous must be an array"
    );
    assert!(payload["summary"].is_object(), "summary must be an object");
}

#[test]
fn unknown_or_ambiguous_is_empty() {
    let payload = load_inventory();
    let unknown = payload["unknown_or_ambiguous"].as_array().unwrap();
    assert!(
        unknown.is_empty(),
        "unknown_or_ambiguous must be empty, got: {unknown:?}"
    );
}

#[test]
fn each_entry_has_semantic_metadata_and_accesses() {
    let payload = load_inventory();
    let entries = payload["inventory"].as_array().unwrap();
    assert!(!entries.is_empty(), "inventory must not be empty");

    let expected_metadata_fields = [
        "default_value",
        "allowed_values",
        "parse_rule",
        "mutability",
        "mode_impact",
        "owner",
        "safety_impact",
    ];

    for entry in entries {
        let key = entry["env_key"].as_str().unwrap_or("<unknown>");
        assert!(
            key.starts_with("FRANKENLIBC_"),
            "{key}: env_key must start with FRANKENLIBC_"
        );

        let metadata = entry["metadata"]
            .as_object()
            .expect("metadata must be object");
        for field in expected_metadata_fields {
            assert!(
                metadata.contains_key(field),
                "{key}: missing metadata.{field}"
            );
        }

        let accesses = entry["accesses"]
            .as_array()
            .expect("accesses must be array");
        assert!(!accesses.is_empty(), "{key}: accesses must not be empty");

        for access in accesses {
            assert!(access["path"].is_string(), "{key}: access.path missing");
            assert!(access["line"].is_u64(), "{key}: access.line missing");
            assert!(access["scope"].is_string(), "{key}: access.scope missing");
            assert!(
                access["operation"].is_string(),
                "{key}: access.operation missing"
            );
            assert!(
                access["snippet"].is_string(),
                "{key}: access.snippet missing"
            );
        }
    }
}

#[test]
fn expected_key_set_matches_inventory() {
    let payload = load_inventory();
    let actual: HashSet<&str> = payload["inventory"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["env_key"].as_str())
        .collect();

    let expected: HashSet<&str> = [
        "FRANKENLIBC_BENCH_PIN",
        "FRANKENLIBC_CLOSURE_CONTRACT_PATH",
        "FRANKENLIBC_CLOSURE_LEVEL",
        "FRANKENLIBC_CLOSURE_LOG",
        "FRANKENLIBC_E2E_SEED",
        "FRANKENLIBC_E2E_STRESS_ITERS",
        "FRANKENLIBC_EXTENDED_GATES",
        "FRANKENLIBC_HOOKS_LOADED",
        "FRANKENLIBC_LIB",
        "FRANKENLIBC_LOG",
        "FRANKENLIBC_LOG_FILE",
        "FRANKENLIBC_LOG_DIR",
        "FRANKENLIBC_MODE",
        "FRANKENLIBC_PACKAGE",
        "FRANKENLIBC_PACKAGE_BLOCKLIST",
        "FRANKENLIBC_PERF_ALLOW_TARGET_VIOLATION",
        "FRANKENLIBC_PERF_ENABLE_KERNEL_SUITE",
        "FRANKENLIBC_PERF_MAX_LOAD_FACTOR",
        "FRANKENLIBC_PERF_MAX_REGRESSION_PCT",
        "FRANKENLIBC_PERF_SKIP_OVERLOADED",
        "FRANKENLIBC_PHASE",
        "FRANKENLIBC_PHASE_ACTIVE",
        "FRANKENLIBC_PHASE_ALLOWLIST",
        "FRANKENLIBC_PORTAGE_ENABLE",
        "FRANKENLIBC_PORTAGE_LOG",
        "FRANKENLIBC_RELEASE_SIMULATE_FAIL_GATE",
        "FRANKENLIBC_SKIP_STATIC",
        "FRANKENLIBC_STARTUP_PHASE0",
        "FRANKENLIBC_TMPDIR",
    ]
    .into_iter()
    .collect();

    assert_eq!(
        actual, expected,
        "runtime env key set drift detected; regenerate inventory and update test expectations"
    );
}

#[test]
fn gate_script_exists_and_is_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_env_inventory.sh");
    assert!(
        script.exists(),
        "scripts/check_runtime_env_inventory.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_runtime_env_inventory.sh must be executable"
        );
    }
}

#[test]
fn gate_script_passes() {
    let root = workspace_root();
    let script = root.join("scripts/check_runtime_env_inventory.sh");
    let output = Command::new("bash")
        .arg(script)
        .current_dir(&root)
        .output()
        .expect("check_runtime_env_inventory.sh should execute");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "check_runtime_env_inventory.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
            output.status.code(),
            stdout,
            stderr
        );
    }
}
