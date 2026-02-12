//! Integration test: Anytime-valid monitor standard (bd-182)
//!
//! Validates that:
//! 1. The monitor spec JSON exists and is valid.
//! 2. E-process parameters are internally consistent.
//! 3. Alpha-investing FDR bound is correctly computed.
//! 4. Alert budget contracts are complete.
//! 5. Companion monitors match governance production_monitor list.
//! 6. API family count matches eprocess.rs implementation.
//! 7. Summary statistics are consistent.
//! 8. Gate script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test anytime_valid_monitor_test

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
    let path = workspace_root().join("tests/conformance/anytime_valid_monitor_spec.json");
    let content =
        std::fs::read_to_string(&path).expect("anytime_valid_monitor_spec.json should exist");
    serde_json::from_str(&content).expect("anytime_valid_monitor_spec.json should be valid JSON")
}

fn load_governance() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/math_governance.json");
    let content = std::fs::read_to_string(&path).expect("math_governance.json should exist");
    serde_json::from_str(&content).expect("math_governance.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let s = load_spec();
    assert!(s["schema_version"].is_number(), "Missing schema_version");
    assert!(s["eprocess_policy"].is_object(), "Missing eprocess_policy");
    assert!(
        s["alpha_investing_policy"].is_object(),
        "Missing alpha_investing_policy"
    );
    assert!(
        s["alert_budget_contracts"].is_object(),
        "Missing alert_budget_contracts"
    );
    assert!(
        s["companion_monitors"].is_object(),
        "Missing companion_monitors"
    );
    assert!(
        s["false_alarm_calibration"].is_object(),
        "Missing false_alarm_calibration"
    );
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn eprocess_parameters_consistent() {
    let s = load_spec();
    let params = &s["eprocess_policy"]["parameters"];

    let p0 = params["null_budget_p0"]["value"].as_f64().unwrap();
    let q1 = params["alternative_q1"]["value"].as_f64().unwrap();
    let warn_e = params["warning_threshold_e"]["value"].as_f64().unwrap();
    let alarm_e = params["alarm_threshold_e"]["value"].as_f64().unwrap();
    let warmup = params["warmup_calls"]["value"].as_u64().unwrap();

    assert!(p0 > 0.0 && p0 < 1.0, "p0 must be in (0,1)");
    assert!(q1 > p0 && q1 < 1.0, "q1 must be in (p0,1)");
    assert!(warn_e > 1.0, "warning_e must be > 1");
    assert!(alarm_e > warn_e, "alarm_e must be > warning_e");
    assert!(warmup >= 1, "warmup_calls must be >= 1");

    // Check states
    let states: HashSet<&str> = s["eprocess_policy"]["states"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["state"].as_str())
        .collect();

    for expected in &["Calibrating", "Normal", "Warning", "Alarm"] {
        assert!(states.contains(expected), "Missing state: {expected}");
    }
}

#[test]
fn alpha_investing_fdr_bound_correct() {
    let s = load_spec();
    let ai = &s["alpha_investing_policy"];
    let params = &ai["parameters"];

    let w0 = params["initial_wealth_milli"]["value"].as_u64().unwrap();
    let reward = params["reward_milli"]["value"].as_u64().unwrap();
    let depleted = params["depleted_threshold_milli"]["value"]
        .as_u64()
        .unwrap();
    let generous = params["generous_threshold_milli"]["value"]
        .as_u64()
        .unwrap();

    // FDR bound = W(0) / reward
    let expected_bound = w0 / reward;
    let claimed_bound = ai["fdr_guarantee"]["bound"].as_u64().unwrap();
    assert_eq!(
        claimed_bound, expected_bound,
        "FDR bound: claimed={claimed_bound} expected=W(0)/reward={expected_bound}"
    );

    // Threshold ordering
    assert!(
        depleted < generous && generous < w0,
        "Ordering: depleted({depleted}) < generous({generous}) < initial({w0})"
    );

    // Check states
    let states: HashSet<&str> = ai["states"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["state"].as_str())
        .collect();

    for expected in &["Calibrating", "Normal", "Generous", "Depleted"] {
        assert!(states.contains(expected), "Missing state: {expected}");
    }
}

#[test]
fn alert_budget_contracts_complete() {
    let s = load_spec();
    let contracts = s["alert_budget_contracts"]["contracts"].as_array().unwrap();

    assert!(
        contracts.len() >= 4,
        "Need at least 4 contracts, got {}",
        contracts.len()
    );

    let mut ids = HashSet::new();
    for c in contracts {
        let id = c["id"].as_str().unwrap();
        assert!(ids.insert(id), "Duplicate contract ID: {id}");
        assert!(
            c["name"].is_string() && !c["name"].as_str().unwrap().is_empty(),
            "{id}: missing name"
        );
        assert!(
            c["invariant"].is_string() && !c["invariant"].as_str().unwrap().is_empty(),
            "{id}: missing invariant"
        );
        assert!(
            c["enforcement"].is_string() && !c["enforcement"].as_str().unwrap().is_empty(),
            "{id}: missing enforcement"
        );
    }

    // Must include anytime validity and wealth contracts
    let names: Vec<String> = contracts
        .iter()
        .filter_map(|c| c["name"].as_str().map(|s| s.to_lowercase()))
        .collect();

    assert!(
        names.iter().any(|n| n.contains("anytime")),
        "Must have an anytime validity contract"
    );
    assert!(
        names.iter().any(|n| n.contains("wealth")),
        "Must have a wealth non-negativity contract"
    );
}

#[test]
fn companion_monitors_match_governance() {
    let s = load_spec();
    let gov = load_governance();

    let spec_monitors: HashSet<String> = s["companion_monitors"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let gov_monitors: HashSet<String> = gov["classifications"]["production_monitor"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let missing: HashSet<_> = gov_monitors.difference(&spec_monitors).collect();
    let extra: HashSet<_> = spec_monitors.difference(&gov_monitors).collect();

    assert!(
        missing.is_empty(),
        "Monitors in governance but not in spec: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "Monitors in spec but not in governance: {extra:?}"
    );

    let claimed = s["companion_monitors"]["total_production_monitors"]
        .as_u64()
        .unwrap() as usize;
    assert_eq!(
        claimed,
        spec_monitors.len(),
        "total_production_monitors mismatch"
    );
}

#[test]
fn api_family_count_matches_implementation() {
    let s = load_spec();
    let families = s["eprocess_policy"]["api_family_list"].as_array().unwrap();
    let claimed = s["eprocess_policy"]["api_families_monitored"]
        .as_u64()
        .unwrap() as usize;

    assert_eq!(
        families.len(),
        claimed,
        "api_family_list length != api_families_monitored"
    );
    // Implementation has ApiFamily::COUNT = 20
    assert_eq!(
        families.len(),
        20,
        "Must monitor 20 API families (ApiFamily::COUNT)"
    );
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];

    let ep = &s["eprocess_policy"];
    let ai = &s["alpha_investing_policy"];
    let abc = s["alert_budget_contracts"]["contracts"].as_array().unwrap();
    let cm = s["companion_monitors"]["modules"].as_array().unwrap();
    let cal = &s["false_alarm_calibration"]["targets"];

    assert_eq!(
        summary["eprocess_parameters"].as_u64().unwrap() as usize,
        ep["parameters"].as_object().unwrap().len(),
        "eprocess_parameters mismatch"
    );
    assert_eq!(
        summary["eprocess_states"].as_u64().unwrap() as usize,
        ep["states"].as_array().unwrap().len(),
        "eprocess_states mismatch"
    );
    assert_eq!(
        summary["alpha_investing_parameters"].as_u64().unwrap() as usize,
        ai["parameters"].as_object().unwrap().len(),
        "alpha_investing_parameters mismatch"
    );
    assert_eq!(
        summary["alpha_investing_states"].as_u64().unwrap() as usize,
        ai["states"].as_array().unwrap().len(),
        "alpha_investing_states mismatch"
    );
    assert_eq!(
        summary["alert_budget_contracts"].as_u64().unwrap() as usize,
        abc.len(),
        "alert_budget_contracts mismatch"
    );
    assert_eq!(
        summary["companion_monitors"].as_u64().unwrap() as usize,
        cm.len(),
        "companion_monitors mismatch"
    );
    assert_eq!(
        summary["api_families_monitored"].as_u64().unwrap() as usize,
        ep["api_families_monitored"].as_u64().unwrap() as usize,
        "api_families_monitored mismatch"
    );
    assert_eq!(
        summary["fdr_bound"].as_u64().unwrap(),
        ai["fdr_guarantee"]["bound"].as_u64().unwrap(),
        "fdr_bound mismatch"
    );
    assert_eq!(
        summary["calibration_targets"].as_u64().unwrap() as usize,
        cal.as_object().unwrap().len(),
        "calibration_targets mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_anytime_valid_monitor.sh");
    assert!(script.exists(), "check_anytime_valid_monitor.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_anytime_valid_monitor.sh must be executable"
        );
    }
}
