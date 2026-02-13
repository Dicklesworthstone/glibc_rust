//! Integration test: Math production-set change policy gate (bd-25pf)
//!
//! Validates that:
//! 1. The policy artifact exists and has required source/digest fields.
//! 2. Summary counts are consistent with manifest/governance/value-proof inputs.
//! 3. Gate script exists and is executable.
//! 4. Gate script succeeds and emits structured logs/report artifacts.

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

fn policy_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/math_production_set_policy.v1.json")
}

#[test]
fn policy_exists_and_basic_fields_are_valid() {
    let root = workspace_root();
    let policy = load_json(&policy_path(&root));

    assert_eq!(policy["schema_version"].as_u64(), Some(1));
    assert_eq!(policy["bead"].as_str(), Some("bd-25pf"));
    assert!(policy["description"].is_string(), "description missing");

    let sources = policy["sources"]
        .as_object()
        .expect("sources must be object");
    for key in [
        "production_manifest",
        "governance",
        "linkage",
        "value_proof",
        "retirement_policy",
    ] {
        assert!(sources.contains_key(key), "sources.{key} missing");
        assert!(sources[key].is_string(), "sources.{key} must be string");
    }

    assert!(
        policy["policy"]["admission_requirements"].is_array(),
        "admission_requirements must be an array"
    );
    assert!(
        policy["policy"]["change_gate"]["manifest_sha256"]
            .as_str()
            .is_some(),
        "change_gate.manifest_sha256 missing"
    );
    assert!(
        policy["policy"]["change_gate"]["module_count"]
            .as_u64()
            .is_some(),
        "change_gate.module_count missing"
    );
}

#[test]
fn policy_summary_matches_current_artifacts() {
    let root = workspace_root();
    let policy = load_json(&policy_path(&root));
    let manifest = load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"));
    let governance = load_json(&root.join("tests/conformance/math_governance.json"));
    let value = load_json(&root.join("tests/conformance/math_value_proof.json"));
    let retirement = load_json(&root.join("tests/conformance/math_retirement_policy.json"));

    let manifest_modules: HashSet<String> = manifest["production_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let prod_tier: HashSet<String> = governance["classifications"]["production_core"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            governance["classifications"]["production_monitor"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .filter_map(|v| v["module"].as_str().map(String::from))
        .collect();
    let research_tier: HashSet<String> = governance["classifications"]["research"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v["module"].as_str().map(String::from))
        .collect();
    let value_modules: HashSet<String> = value["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            value["production_monitor_assessments"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .filter_map(|v| v["module"].as_str().map(String::from))
        .collect();

    let prod_in_manifest: HashSet<String> =
        manifest_modules.intersection(&prod_tier).cloned().collect();
    let research_in_manifest: HashSet<String> = manifest_modules
        .intersection(&research_tier)
        .cloned()
        .collect();

    let waiver_modules = retirement["active_waivers"].as_array().unwrap();
    let all_research_waived = waiver_modules
        .iter()
        .any(|w| w["module"].as_str() == Some("ALL_RESEARCH"));
    let waived_research_modules = if all_research_waived {
        research_in_manifest.len()
    } else {
        waiver_modules
            .iter()
            .filter_map(|w| w["module"].as_str())
            .filter(|m| research_in_manifest.contains(*m))
            .count()
    };

    assert_eq!(
        policy["summary"]["total_production_modules"].as_u64(),
        Some(manifest_modules.len() as u64),
        "summary.total_production_modules mismatch"
    );
    assert_eq!(
        policy["summary"]["production_tier_modules"].as_u64(),
        Some(prod_in_manifest.len() as u64),
        "summary.production_tier_modules mismatch"
    );
    assert_eq!(
        policy["summary"]["research_tier_modules"].as_u64(),
        Some(research_in_manifest.len() as u64),
        "summary.research_tier_modules mismatch"
    );
    assert_eq!(
        policy["summary"]["waived_research_modules"].as_u64(),
        Some(waived_research_modules as u64),
        "summary.waived_research_modules mismatch"
    );

    let missing_value = prod_in_manifest.difference(&value_modules).count() as u64;
    assert_eq!(
        policy["summary"]["missing_value_proof"].as_u64(),
        Some(missing_value),
        "summary.missing_value_proof mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_production_set_policy.sh");
    assert!(
        script.exists(),
        "scripts/check_math_production_set_policy.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_production_set_policy.sh must be executable"
        );
    }
}

#[test]
fn gate_script_emits_logs_and_report() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_production_set_policy.sh");

    let output = std::process::Command::new(&script)
        .current_dir(&root)
        .output()
        .expect("failed to run production-set policy gate script");

    assert!(
        output.status.success(),
        "gate script failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let log_path = root.join("target/conformance/math_production_set_policy.log.jsonl");
    let report_path = root.join("target/conformance/math_production_set_policy.report.json");

    let log_content = std::fs::read_to_string(&log_path).expect("log file must exist");
    let mut line_count = 0usize;
    for line in log_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let row: serde_json::Value = serde_json::from_str(line).expect("log line must be JSON");
        assert!(row["trace_id"].as_str().is_some(), "trace_id missing");
        assert_eq!(row["mode"].as_str(), Some("policy"), "mode mismatch");
        assert!(row["symbol"].as_str().is_some(), "symbol missing");
        assert!(row["outcome"].as_str().is_some(), "outcome missing");
        assert!(row["errno"].is_number(), "errno missing");
        assert!(row["timing_ns"].is_number(), "timing_ns missing");
        line_count += 1;
    }

    let manifest = load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"));
    let expected = manifest["production_modules"].as_array().unwrap().len();
    assert_eq!(
        line_count, expected,
        "log line count must equal production module count"
    );

    let report = load_json(&report_path);
    assert_eq!(report["bead"].as_str(), Some("bd-25pf"));
    assert_eq!(report["schema_version"].as_str(), Some("v1"));
    assert_eq!(report["ok"].as_bool(), Some(true));
    assert_eq!(report["failure_count"].as_u64(), Some(0));
}
