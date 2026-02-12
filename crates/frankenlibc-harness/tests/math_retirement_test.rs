//! Integration test: Math retirement gate (bd-545)
//!
//! Validates that:
//! 1. The retirement policy JSON exists and is valid.
//! 2. RC-1 candidates match governance research modules vs production manifest.
//! 3. Production-compliant modules match governance core + monitor tiers.
//! 4. Active waivers cover all retirement candidates.
//! 5. Migration waves account for all RC-1 candidates.
//! 6. Summary statistics are consistent.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test math_retirement_test

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

fn load_policy() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/math_retirement_policy.json");
    let content = std::fs::read_to_string(&path).expect("math_retirement_policy.json should exist");
    serde_json::from_str(&content).expect("math_retirement_policy.json should be valid JSON")
}

fn load_governance() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/math_governance.json");
    let content = std::fs::read_to_string(&path).expect("math_governance.json should exist");
    serde_json::from_str(&content).expect("math_governance.json should be valid JSON")
}

fn load_manifest() -> serde_json::Value {
    let path = workspace_root().join("tests/runtime_math/production_kernel_manifest.v1.json");
    let content =
        std::fs::read_to_string(&path).expect("production_kernel_manifest.v1.json should exist");
    serde_json::from_str(&content).expect("production_kernel_manifest.v1.json should be valid JSON")
}

#[test]
fn policy_exists_and_valid() {
    let p = load_policy();
    assert!(p["schema_version"].is_number(), "Missing schema_version");
    assert!(
        p["retirement_criteria"]["rules"].is_array(),
        "Missing retirement_criteria.rules"
    );
    assert!(
        p["deprecation_stages"]["stages"].is_array(),
        "Missing deprecation_stages.stages"
    );
    assert!(
        p["current_assessment"].is_object(),
        "Missing current_assessment"
    );
    assert!(p["active_waivers"].is_array(), "Missing active_waivers");
    assert!(
        p["migration_notes"]["waves"].is_array(),
        "Missing migration_notes.waves"
    );
    assert!(p["summary"].is_object(), "Missing summary");
}

#[test]
fn retirement_criteria_complete() {
    let p = load_policy();
    let rules = p["retirement_criteria"]["rules"].as_array().unwrap();
    assert!(
        rules.len() >= 2,
        "Need at least 2 retirement criteria rules"
    );

    let rule_ids: HashSet<String> = rules
        .iter()
        .filter_map(|r| r["id"].as_str().map(String::from))
        .collect();

    assert!(
        rule_ids.contains("RC-1"),
        "Missing RC-1 (governance_mismatch)"
    );
    assert!(
        rule_ids.contains("RC-2"),
        "Missing RC-2 (no_decision_linkage)"
    );

    for rule in rules {
        let rid = rule["id"].as_str().unwrap_or("?");
        assert!(rule["name"].is_string(), "{rid}: missing name");
        assert!(
            rule["description"].is_string(),
            "{rid}: missing description"
        );
        assert!(rule["severity"].is_string(), "{rid}: missing severity");
        assert!(
            rule["enforcement"].is_string(),
            "{rid}: missing enforcement"
        );
    }
}

#[test]
fn deprecation_stages_ordered() {
    let p = load_policy();
    let stages = p["deprecation_stages"]["stages"].as_array().unwrap();

    let expected_order = ["active", "deprecated", "research_only", "removed"];
    assert_eq!(
        stages.len(),
        expected_order.len(),
        "Expected {} deprecation stages",
        expected_order.len()
    );

    for (i, stage) in stages.iter().enumerate() {
        let name = stage["stage"].as_str().unwrap_or("?");
        assert_eq!(
            name, expected_order[i],
            "Stage {i}: expected '{}' got '{name}'",
            expected_order[i]
        );
        assert!(
            stage["description"].is_string(),
            "{name}: missing description"
        );
    }
}

#[test]
fn rc1_candidates_match_governance_vs_manifest() {
    let p = load_policy();
    let gov = load_governance();
    let manifest = load_manifest();

    // Get research modules from governance
    let research_modules: HashSet<String> = gov["classifications"]["research"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    // Get manifest modules
    let manifest_modules: HashSet<String> = manifest["production_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();

    // Actual RC-1 = research modules in production manifest
    let actual_rc1: HashSet<String> = research_modules
        .intersection(&manifest_modules)
        .cloned()
        .collect();

    // Policy-claimed RC-1
    let claimed_rc1: HashSet<String> = p["current_assessment"]["rc1_candidates"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();

    assert_eq!(
        claimed_rc1, actual_rc1,
        "RC-1 candidates mismatch with governance/manifest"
    );

    let claimed_count = p["current_assessment"]["rc1_candidates"]["count"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(claimed_count, actual_rc1.len(), "RC-1 count mismatch");
}

#[test]
fn production_compliant_match_governance() {
    let p = load_policy();
    let gov = load_governance();
    let manifest = load_manifest();

    let core_modules: HashSet<String> = gov["classifications"]["production_core"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let monitor_modules: HashSet<String> = gov["classifications"]["production_monitor"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let manifest_modules: HashSet<String> = manifest["production_modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();

    let actual_compliant: HashSet<String> = core_modules
        .union(&monitor_modules)
        .filter(|m| manifest_modules.contains(*m))
        .cloned()
        .collect();

    let claimed_core: HashSet<String> =
        p["current_assessment"]["production_compliant"]["production_core"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m.as_str().map(String::from))
            .collect();

    let claimed_monitor: HashSet<String> =
        p["current_assessment"]["production_compliant"]["production_monitor"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m.as_str().map(String::from))
            .collect();

    assert_eq!(claimed_core, core_modules, "production_core mismatch");
    assert_eq!(
        claimed_monitor, monitor_modules,
        "production_monitor mismatch"
    );

    let claimed_count = p["current_assessment"]["production_compliant"]["count"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(
        claimed_count,
        actual_compliant.len(),
        "compliant count mismatch"
    );
}

#[test]
fn waivers_cover_all_rc1() {
    let p = load_policy();

    let rc1_modules: HashSet<String> = p["current_assessment"]["rc1_candidates"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();

    let waivers = p["active_waivers"].as_array().unwrap();
    let required_fields = p["waiver_policy"]["required_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f.as_str())
        .collect::<Vec<_>>();

    let mut covered = HashSet::new();
    for w in waivers {
        // Check required fields
        for field in &required_fields {
            assert!(!w[field].is_null(), "Waiver missing field '{field}'");
        }

        let module = w["module"].as_str().unwrap_or("");
        if module == "ALL_RESEARCH" {
            covered = rc1_modules.clone();
        } else {
            covered.insert(module.to_string());
        }
    }

    let unwaived: HashSet<_> = rc1_modules.difference(&covered).collect();
    assert!(
        unwaived.is_empty(),
        "{} RC-1 modules without waiver: {:?}",
        unwaived.len(),
        unwaived
    );
}

#[test]
fn migration_waves_cover_all_rc1() {
    let p = load_policy();

    let rc1_modules: HashSet<String> = p["current_assessment"]["rc1_candidates"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m.as_str().map(String::from))
        .collect();

    let waves = p["migration_notes"]["waves"].as_array().unwrap();
    let mut wave_modules = HashSet::new();

    for w in waves {
        let mods = w["modules"].as_array().unwrap();
        let claimed_count = w["count"].as_u64().unwrap() as usize;
        assert_eq!(
            mods.len(),
            claimed_count,
            "Wave {}: count mismatch",
            w["wave"]
        );

        for m in mods {
            let name = m.as_str().unwrap().to_string();
            assert!(
                wave_modules.insert(name.clone()),
                "Duplicate module in waves: {name}"
            );
        }
    }

    assert_eq!(
        wave_modules, rc1_modules,
        "Migration waves must cover exactly all RC-1 candidates"
    );

    let claimed_total = p["migration_notes"]["total_modules_to_migrate"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(
        claimed_total,
        wave_modules.len(),
        "total_modules_to_migrate mismatch"
    );
}

#[test]
fn summary_consistent() {
    let p = load_policy();
    let manifest = load_manifest();
    let summary = &p["summary"];

    let manifest_count = manifest["production_modules"].as_array().unwrap().len();
    let rc1_count = p["current_assessment"]["rc1_candidates"]["modules"]
        .as_array()
        .unwrap()
        .len();
    let compliant_count = p["current_assessment"]["production_compliant"]["count"]
        .as_u64()
        .unwrap() as usize;
    let waiver_count = p["active_waivers"].as_array().unwrap().len();
    let wave_count = p["migration_notes"]["waves"].as_array().unwrap().len();

    assert_eq!(
        summary["total_modules_in_manifest"].as_u64().unwrap() as usize,
        manifest_count,
        "total_modules_in_manifest mismatch"
    );
    assert_eq!(
        summary["production_compliant"].as_u64().unwrap() as usize,
        compliant_count,
        "production_compliant mismatch"
    );
    assert_eq!(
        summary["retirement_candidates_rc1"].as_u64().unwrap() as usize,
        rc1_count,
        "retirement_candidates_rc1 mismatch"
    );
    assert_eq!(
        summary["active_waivers"].as_u64().unwrap() as usize,
        waiver_count,
        "active_waivers mismatch"
    );
    assert_eq!(
        summary["migration_waves"].as_u64().unwrap() as usize,
        wave_count,
        "migration_waves mismatch"
    );

    // Manifest = compliant + rc1
    assert_eq!(
        manifest_count,
        compliant_count + rc1_count,
        "manifest_count != compliant + rc1"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_retirement.sh");
    assert!(
        script.exists(),
        "scripts/check_math_retirement.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_retirement.sh must be executable"
        );
    }
}
