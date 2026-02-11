//! Integration test: Changepoint drift policy (bd-3tc)
//!
//! Validates that:
//! 1. The drift policy spec JSON exists and is valid.
//! 2. BOCPD parameters are internally consistent.
//! 3. Routing policies cover all detector states with increasing escalation.
//! 4. Monitor integration references valid spec files.
//! 5. False positive control targets are defined.
//! 6. Summary statistics are consistent.
//! 7. Gate script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test changepoint_drift_test

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
    let path = workspace_root().join("tests/conformance/changepoint_drift_policy.json");
    let content =
        std::fs::read_to_string(&path).expect("changepoint_drift_policy.json should exist");
    serde_json::from_str(&content).expect("changepoint_drift_policy.json should be valid JSON")
}

#[test]
fn spec_exists_and_valid() {
    let s = load_spec();
    assert!(s["schema_version"].is_number(), "Missing schema_version");
    assert!(
        s["bocpd_parameters"].is_object(),
        "Missing bocpd_parameters"
    );
    assert!(s["routing_policy"].is_object(), "Missing routing_policy");
    assert!(
        s["integration_with_monitors"].is_object(),
        "Missing integration_with_monitors"
    );
    assert!(
        s["false_positive_control"].is_object(),
        "Missing false_positive_control"
    );
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn bocpd_parameters_consistent() {
    let s = load_spec();
    let params = &s["bocpd_parameters"]["parameters"];

    let warmup = params["warmup_count"]["value"].as_u64().unwrap();
    let drift_t = params["drift_threshold"]["value"].as_f64().unwrap();
    let cp_t = params["changepoint_threshold"]["value"].as_f64().unwrap();
    let max_rl = params["max_run_length"]["value"].as_u64().unwrap();
    let short_w = params["short_window"]["value"].as_u64().unwrap();
    let hazard = params["hazard_lambda"]["value"].as_f64().unwrap();
    let ewma = params["ewma_alpha"]["value"].as_f64().unwrap();

    assert!(warmup >= 1, "warmup_count must be >= 1");
    assert!(
        drift_t > 0.0 && drift_t < cp_t && cp_t <= 1.0,
        "Must have 0 < drift_threshold ({drift_t}) < changepoint_threshold ({cp_t}) <= 1.0"
    );
    assert!(
        short_w >= 1 && short_w <= max_rl,
        "short_window ({short_w}) must be in [1, max_run_length ({max_rl})]"
    );
    assert!(hazard > 0.0, "hazard_lambda must be > 0");
    assert!(ewma > 0.0 && ewma < 1.0, "ewma_alpha must be in (0, 1)");

    // Check beta prior
    let alpha0 = params["beta_prior"]["alpha0"].as_f64().unwrap();
    let beta0 = params["beta_prior"]["beta0"].as_f64().unwrap();
    assert!(
        alpha0 > 0.0 && beta0 > 0.0,
        "Beta prior parameters must be > 0"
    );

    // Check states
    let states: HashSet<&str> = s["bocpd_parameters"]["states"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["state"].as_str())
        .collect();

    for expected in &["Calibrating", "Stable", "Drift", "ChangePoint"] {
        assert!(states.contains(expected), "Missing state: {expected}");
    }
}

#[test]
fn routing_policies_cover_states_with_escalation() {
    let s = load_spec();
    let policies = s["routing_policy"]["policies"].as_array().unwrap();

    assert!(policies.len() >= 3, "Need at least 3 routing policies");

    let mut ids = HashSet::new();
    for p in policies {
        let pid = p["id"].as_str().unwrap();
        assert!(ids.insert(pid), "Duplicate policy ID: {pid}");
        assert!(p["state"].is_string(), "{pid}: missing state");
        assert!(p["action"].is_string(), "{pid}: missing action");
        assert!(p["description"].is_string(), "{pid}: missing description");
        assert!(
            p["escalation_level"].is_u64(),
            "{pid}: missing escalation_level"
        );
    }

    // Find policies for each state
    let stable = policies
        .iter()
        .find(|p| p["state"].as_str() == Some("Stable"))
        .expect("Must have Stable routing policy");
    let drift = policies
        .iter()
        .find(|p| p["state"].as_str() == Some("Drift"))
        .expect("Must have Drift routing policy");
    let cp = policies
        .iter()
        .find(|p| p["state"].as_str() == Some("ChangePoint"))
        .expect("Must have ChangePoint routing policy");

    // Escalation levels must increase
    let stable_lvl = stable["escalation_level"].as_u64().unwrap();
    let drift_lvl = drift["escalation_level"].as_u64().unwrap();
    let cp_lvl = cp["escalation_level"].as_u64().unwrap();
    assert!(
        stable_lvl < drift_lvl,
        "Stable escalation ({stable_lvl}) must be < Drift ({drift_lvl})"
    );
    assert!(
        drift_lvl < cp_lvl,
        "Drift escalation ({drift_lvl}) must be < ChangePoint ({cp_lvl})"
    );
}

#[test]
fn integration_references_valid_specs() {
    let s = load_spec();
    let root = workspace_root();
    let integ = &s["integration_with_monitors"];

    // Check upstream feeds exist
    let upstream = integ["upstream_feeds"].as_array().unwrap();
    assert!(!upstream.is_empty(), "Must have at least one upstream feed");

    let downstream = integ["downstream_consumers"].as_array().unwrap();
    assert!(
        !downstream.is_empty(),
        "Must have at least one downstream consumer"
    );

    // Check file references
    let monitor_ref = integ["monitor_spec_ref"].as_str().unwrap();
    assert!(
        root.join(monitor_ref).exists(),
        "monitor_spec_ref not found: {monitor_ref}"
    );

    let crash_ref = integ["crash_bundle_ref"].as_str().unwrap();
    assert!(
        root.join(crash_ref).exists(),
        "crash_bundle_ref not found: {crash_ref}"
    );
}

#[test]
fn false_positive_control_targets_defined() {
    let s = load_spec();
    let fpc = &s["false_positive_control"];
    let targets = &fpc["targets"];

    assert!(
        targets["stable_traffic_fp_rate"].is_object(),
        "Missing stable_traffic_fp_rate target"
    );
    assert!(
        targets["stable_traffic_fp_rate"]["target"]
            .as_f64()
            .unwrap()
            > 0.0,
        "stable_traffic_fp_rate target must be > 0"
    );

    assert!(
        targets["recovery_time"].is_object(),
        "Missing recovery_time target"
    );

    // Check unit test coverage
    let tests = fpc["unit_test_coverage"]["tests"].as_array().unwrap();
    assert!(
        tests.len() >= 5,
        "Need at least 5 unit tests listed, got {}",
        tests.len()
    );
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];

    let bocpd_params = s["bocpd_parameters"]["parameters"]
        .as_object()
        .unwrap()
        .len();
    let bocpd_states = s["bocpd_parameters"]["states"].as_array().unwrap().len();
    let routing = s["routing_policy"]["policies"].as_array().unwrap().len();
    let upstream = s["integration_with_monitors"]["upstream_feeds"]
        .as_array()
        .unwrap()
        .len();
    let downstream = s["integration_with_monitors"]["downstream_consumers"]
        .as_array()
        .unwrap()
        .len();
    let fp_targets = s["false_positive_control"]["targets"]
        .as_object()
        .unwrap()
        .len();
    let unit_tests = s["false_positive_control"]["unit_test_coverage"]["tests"]
        .as_array()
        .unwrap()
        .len();

    assert_eq!(
        summary["bocpd_parameters"].as_u64().unwrap() as usize,
        bocpd_params,
        "bocpd_parameters mismatch"
    );
    assert_eq!(
        summary["bocpd_states"].as_u64().unwrap() as usize,
        bocpd_states,
        "bocpd_states mismatch"
    );
    assert_eq!(
        summary["routing_policies"].as_u64().unwrap() as usize,
        routing,
        "routing_policies mismatch"
    );
    assert_eq!(
        summary["upstream_feeds"].as_u64().unwrap() as usize,
        upstream,
        "upstream_feeds mismatch"
    );
    assert_eq!(
        summary["downstream_consumers"].as_u64().unwrap() as usize,
        downstream,
        "downstream_consumers mismatch"
    );
    assert_eq!(
        summary["false_positive_targets"].as_u64().unwrap() as usize,
        fp_targets,
        "false_positive_targets mismatch"
    );
    assert_eq!(
        summary["unit_tests"].as_u64().unwrap() as usize,
        unit_tests,
        "unit_tests mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_changepoint_drift.sh");
    assert!(script.exists(), "check_changepoint_drift.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_changepoint_drift.sh must be executable"
        );
    }
}
