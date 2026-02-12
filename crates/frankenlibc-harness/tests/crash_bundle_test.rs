//! Integration test: Crash bundle spec (bd-6yd)
//!
//! Validates that:
//! 1. The crash bundle spec JSON exists and is valid.
//! 2. All required artifacts have size bounds, descriptions, and formats.
//! 3. Determinism rules are well-formed and cover key constraints.
//! 4. Reproduction checklist covers essential concepts.
//! 5. Runner integration entries reference real scripts.
//! 6. Summary statistics are consistent.
//! 7. Evidence snapshot record limit matches membrane K_MAX.
//! 8. Gate script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test crash_bundle_test

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

fn load_spec() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/crash_bundle_spec.json");
    let content = std::fs::read_to_string(&path).expect("crash_bundle_spec.json should exist");
    serde_json::from_str(&content).expect("crash_bundle_spec.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let s = load_spec();
    assert!(s["schema_version"].is_number(), "Missing schema_version");
    assert!(s["bundle_format"].is_object(), "Missing bundle_format");
    assert!(
        s["bundle_format"]["required_artifacts"].is_array(),
        "Missing required_artifacts"
    );
    assert!(
        s["determinism_requirements"].is_object(),
        "Missing determinism_requirements"
    );
    assert!(
        s["reproduction_requirements"].is_object(),
        "Missing reproduction_requirements"
    );
    assert!(s["integration"].is_object(), "Missing integration");
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn required_artifacts_have_bounds() {
    let s = load_spec();
    let required = s["bundle_format"]["required_artifacts"].as_array().unwrap();

    assert!(
        required.len() >= 5,
        "Need at least 5 required artifacts, got {}",
        required.len()
    );

    for art in required {
        let filename = art["filename"].as_str().unwrap_or("?");
        assert!(
            art["max_size_bytes"].is_u64(),
            "{filename}: missing or invalid max_size_bytes"
        );
        assert!(
            art["max_size_bytes"].as_u64().unwrap() > 0,
            "{filename}: max_size_bytes must be > 0"
        );
        assert!(
            art["description"].is_string() && !art["description"].as_str().unwrap().is_empty(),
            "{filename}: missing description"
        );
        assert!(
            art["format"].is_string() && !art["format"].as_str().unwrap().is_empty(),
            "{filename}: missing format"
        );
    }
}

#[test]
fn required_artifact_filenames_complete() {
    let s = load_spec();
    let required = s["bundle_format"]["required_artifacts"].as_array().unwrap();

    let filenames: HashSet<&str> = required
        .iter()
        .filter_map(|a| a["filename"].as_str())
        .collect();

    let expected = [
        "bundle.meta",
        "env.txt",
        "proc_self_maps.txt",
        "backtrace.txt",
        "evidence_snapshot.jsonl",
        "allocator_stats.json",
        "command.shline",
        "stdout.txt",
        "stderr.txt",
    ];

    for name in &expected {
        assert!(
            filenames.contains(name),
            "Missing required artifact: {name}"
        );
    }
}

#[test]
fn determinism_rules_well_formed() {
    let s = load_spec();
    let rules = s["determinism_requirements"]["rules"].as_array().unwrap();

    assert!(
        rules.len() >= 3,
        "Need at least 3 determinism rules, got {}",
        rules.len()
    );

    let mut ids = HashSet::new();
    for rule in rules {
        let id = rule["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate rule ID: {id}");
        assert!(
            rule["rule"].is_string() && !rule["rule"].as_str().unwrap().is_empty(),
            "{id}: missing rule text"
        );
        assert!(
            rule["rationale"].is_string() && !rule["rationale"].as_str().unwrap().is_empty(),
            "{id}: missing rationale"
        );
    }

    // Must have bundle size limit rule
    let all_rules_text: String = rules
        .iter()
        .filter_map(|r| r["rule"].as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    assert!(
        all_rules_text.contains("bundle") && all_rules_text.contains("size"),
        "Determinism rules must include a total bundle size constraint"
    );

    assert!(
        all_rules_text.contains("truncat"),
        "Determinism rules must include a truncation rule"
    );
}

#[test]
fn reproduction_checklist_covers_essentials() {
    let s = load_spec();
    let checklist = s["reproduction_requirements"]["checklist"]
        .as_array()
        .unwrap();

    assert!(
        checklist.len() >= 3,
        "Need at least 3 reproduction checklist items, got {}",
        checklist.len()
    );

    let text: String = checklist
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

    assert!(
        text.contains("command"),
        "Reproduction checklist must mention command"
    );
    assert!(
        text.contains("env"),
        "Reproduction checklist must mention env"
    );
    assert!(
        text.contains("mode"),
        "Reproduction checklist must mention mode"
    );
}

#[test]
fn evidence_snapshot_bounded_by_k_max() {
    let s = load_spec();
    let required = s["bundle_format"]["required_artifacts"].as_array().unwrap();

    let evidence = required
        .iter()
        .find(|a| a["filename"].as_str() == Some("evidence_snapshot.jsonl"))
        .expect("evidence_snapshot.jsonl must be a required artifact");

    let max_records = evidence["max_records"].as_u64().unwrap();
    assert_eq!(
        max_records, 256,
        "evidence_snapshot max_records must be 256 (K_MAX)"
    );
}

#[test]
fn runner_integration_scripts_exist() {
    let s = load_spec();
    let root = workspace_root();
    let runners = s["integration"]["runners"].as_array().unwrap();

    assert!(!runners.is_empty(), "At least one runner must be listed");

    for runner in runners {
        let script = runner["script"].as_str().unwrap();
        let path = root.join(script);
        assert!(path.exists(), "{script} must exist on disk");

        let status = runner["status"].as_str().unwrap();
        assert!(
            ["full", "partial", "none"].contains(&status),
            "{script}: invalid status '{status}'"
        );

        if status == "partial" {
            let missing = runner["missing"].as_array().unwrap();
            assert!(
                !missing.is_empty(),
                "{script}: status=partial but missing list is empty"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];
    let fmt = &s["bundle_format"];
    let required = fmt["required_artifacts"].as_array().unwrap();
    let optional = fmt["optional_artifacts"].as_array().unwrap();
    let det_rules = s["determinism_requirements"]["rules"].as_array().unwrap();
    let repro_items = s["reproduction_requirements"]["checklist"]
        .as_array()
        .unwrap();
    let runners = s["integration"]["runners"].as_array().unwrap();

    assert_eq!(
        summary["required_artifacts"].as_u64().unwrap() as usize,
        required.len(),
        "required_artifacts mismatch"
    );
    assert_eq!(
        summary["optional_artifacts"].as_u64().unwrap() as usize,
        optional.len(),
        "optional_artifacts mismatch"
    );
    assert_eq!(
        summary["determinism_rules"].as_u64().unwrap() as usize,
        det_rules.len(),
        "determinism_rules mismatch"
    );
    assert_eq!(
        summary["reproduction_checklist_items"].as_u64().unwrap() as usize,
        repro_items.len(),
        "reproduction_checklist_items mismatch"
    );
    assert_eq!(
        summary["runners_integrated"].as_u64().unwrap() as usize,
        runners.len(),
        "runners_integrated mismatch"
    );
    assert_eq!(
        summary["max_bundle_size_bytes"].as_u64().unwrap(),
        4_194_304,
        "max_bundle_size_bytes must be 4MB"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_crash_bundle.sh");
    assert!(script.exists(), "check_crash_bundle.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_crash_bundle.sh must be executable"
        );
    }
}
