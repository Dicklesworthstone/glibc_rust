//! Integration test: Math value proof (bd-3tp)
//!
//! Validates that:
//! 1. The math value proof JSON exists and is valid.
//! 2. Core module assessments match governance.
//! 3. Monitor module assessments match governance.
//! 4. All retained modules meet the opportunity score threshold.
//! 5. Score formula (impact * confidence / effort) is consistent.
//! 6. All assessments have required fields.
//! 7. Summary statistics are consistent.
//! 8. Gate script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test math_value_proof_test

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
    let path = workspace_root().join("tests/conformance/math_value_proof.json");
    let content = std::fs::read_to_string(&path).expect("math_value_proof.json should exist");
    serde_json::from_str(&content).expect("math_value_proof.json should be valid JSON")
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
    assert!(
        s["scoring_methodology"].is_object(),
        "Missing scoring_methodology"
    );
    assert!(
        s["production_core_assessments"].is_array(),
        "Missing production_core_assessments"
    );
    assert!(
        s["production_monitor_assessments"].is_array(),
        "Missing production_monitor_assessments"
    );
    assert!(
        s["retention_summary"].is_object(),
        "Missing retention_summary"
    );
    assert!(s["summary"].is_object(), "Missing summary");
}

#[test]
fn core_modules_match_governance() {
    let s = load_spec();
    let gov = load_governance();

    let spec_core: HashSet<String> = s["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["module"].as_str().map(String::from))
        .collect();

    let gov_core: HashSet<String> = gov["classifications"]["production_core"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let missing: HashSet<_> = gov_core.difference(&spec_core).collect();
    let extra: HashSet<_> = spec_core.difference(&gov_core).collect();

    assert!(
        missing.is_empty(),
        "Core modules in governance but not assessed: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "Core modules assessed but not in governance: {extra:?}"
    );
}

#[test]
fn monitor_modules_match_governance() {
    let s = load_spec();
    let gov = load_governance();

    let spec_mon: HashSet<String> = s["production_monitor_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["module"].as_str().map(String::from))
        .collect();

    let gov_mon: HashSet<String> = gov["classifications"]["production_monitor"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["module"].as_str().map(String::from))
        .collect();

    let missing: HashSet<_> = gov_mon.difference(&spec_mon).collect();
    let extra: HashSet<_> = spec_mon.difference(&gov_mon).collect();

    assert!(
        missing.is_empty(),
        "Monitor modules in governance but not assessed: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "Monitor modules assessed but not in governance: {extra:?}"
    );
}

#[test]
fn retained_modules_meet_threshold() {
    let s = load_spec();
    let threshold = s["scoring_methodology"]["retention_threshold"]
        .as_f64()
        .unwrap();

    let all_assessments: Vec<&serde_json::Value> = s["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            s["production_monitor_assessments"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .collect();

    for a in &all_assessments {
        let module = a["module"].as_str().unwrap_or("?");
        let score = a["score"].as_f64().unwrap();
        let verdict = a["verdict"].as_str().unwrap();

        if verdict == "retain" {
            assert!(
                score >= threshold,
                "{module}: score={score} < threshold={threshold} but verdict=retain"
            );
        }
    }
}

#[test]
fn score_formula_consistent() {
    let s = load_spec();

    let all_assessments: Vec<&serde_json::Value> = s["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            s["production_monitor_assessments"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .collect();

    for a in &all_assessments {
        let module = a["module"].as_str().unwrap_or("?");
        let impact = a["impact"].as_f64().unwrap();
        let confidence = a["confidence"].as_f64().unwrap();
        let effort = a["effort"].as_f64().unwrap();
        let claimed_score = a["score"].as_f64().unwrap();

        assert!(effort > 0.0, "{module}: effort must be > 0");

        let computed = (impact * confidence) / effort;
        let diff = (computed - claimed_score).abs();
        assert!(
            diff < 0.2,
            "{module}: score mismatch — claimed={claimed_score}, computed={computed:.1} (impact={impact}, confidence={confidence}, effort={effort})"
        );

        // Range checks
        assert!(
            (1.0..=5.0).contains(&impact),
            "{module}: impact={impact} out of [1,5]"
        );
        assert!(
            (1.0..=5.0).contains(&confidence),
            "{module}: confidence={confidence} out of [1,5]"
        );
        assert!(
            (1.0..=5.0).contains(&effort),
            "{module}: effort={effort} out of [1,5]"
        );
    }
}

#[test]
fn assessments_have_required_fields() {
    let s = load_spec();

    let all_assessments: Vec<&serde_json::Value> = s["production_core_assessments"]
        .as_array()
        .unwrap()
        .iter()
        .chain(
            s["production_monitor_assessments"]
                .as_array()
                .unwrap()
                .iter(),
        )
        .collect();

    let required = [
        "module",
        "value_category",
        "baseline_alternative",
        "measurable_benefit",
        "impact",
        "confidence",
        "effort",
        "score",
        "verdict",
        "evidence",
    ];

    for a in &all_assessments {
        let module = a["module"].as_str().unwrap_or("?");
        for field in &required {
            assert!(
                !a[field].is_null(),
                "{module}: missing required field '{field}'"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let s = load_spec();
    let summary = &s["summary"];
    let core = s["production_core_assessments"].as_array().unwrap();
    let monitor = s["production_monitor_assessments"].as_array().unwrap();
    let threshold = s["scoring_methodology"]["retention_threshold"]
        .as_f64()
        .unwrap();

    assert_eq!(
        summary["total_modules_assessed"].as_u64().unwrap() as usize,
        core.len() + monitor.len(),
        "total_modules_assessed mismatch"
    );
    assert_eq!(
        summary["core_assessments"].as_u64().unwrap() as usize,
        core.len(),
        "core_assessments mismatch"
    );
    assert_eq!(
        summary["monitor_assessments"].as_u64().unwrap() as usize,
        monitor.len(),
        "monitor_assessments mismatch"
    );
    assert_eq!(
        summary["retention_threshold"].as_f64().unwrap(),
        threshold,
        "retention_threshold mismatch"
    );

    let all_retained = core
        .iter()
        .chain(monitor.iter())
        .all(|a| a["verdict"].as_str() == Some("retain"));
    assert_eq!(
        summary["all_retained"].as_bool().unwrap(),
        all_retained,
        "all_retained mismatch"
    );

    let research_count = s["research_assessment"]["module_count"].as_u64().unwrap() as usize;
    assert_eq!(
        summary["research_modules_excluded"].as_u64().unwrap() as usize,
        research_count,
        "research_modules_excluded mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_value_proof.sh");
    assert!(script.exists(), "check_math_value_proof.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_value_proof.sh must be executable"
        );
    }
}
