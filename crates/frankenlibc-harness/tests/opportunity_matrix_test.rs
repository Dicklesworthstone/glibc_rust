//! Integration test: Opportunity matrix scoring workflow (bd-1ik)
//!
//! Validates that:
//! 1. The opportunity matrix JSON exists and is valid.
//! 2. Scoring dimensions are defined with anchors.
//! 3. All entries have required fields and valid ranges.
//! 4. Scores match the formula.
//! 5. Threshold policy is enforced (eligible entries >= threshold).
//! 6. Summary statistics are consistent.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test opportunity_matrix_test

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

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/opportunity_matrix.json");
    let content = std::fs::read_to_string(&path).expect("opportunity_matrix.json should exist");
    serde_json::from_str(&content).expect("opportunity_matrix.json should be valid JSON")
}

#[test]
fn matrix_exists_and_valid() {
    let mat = load_matrix();
    assert!(mat["schema_version"].is_number(), "Missing schema_version");
    assert!(mat["scoring"].is_object(), "Missing scoring");
    assert!(mat["entries"].is_array(), "Missing entries");
    assert!(mat["summary"].is_object(), "Missing summary");
}

#[test]
fn scoring_dimensions_defined() {
    let mat = load_matrix();
    let dims = mat["scoring"]["dimensions"].as_object().unwrap();

    for dim_name in ["impact", "confidence", "effort"] {
        assert!(dims.contains_key(dim_name), "Missing dimension: {dim_name}");
        let dim = &dims[dim_name];
        assert!(
            dim["description"].is_string(),
            "{dim_name}: missing description"
        );
        assert!(dim["scale"].is_string(), "{dim_name}: missing scale");
        assert!(dim["anchors"].is_object(), "{dim_name}: missing anchors");
    }

    assert!(
        mat["scoring"]["formula"].is_string(),
        "Missing scoring formula"
    );
    assert!(
        mat["scoring"]["threshold"].is_number(),
        "Missing scoring threshold"
    );
}

#[test]
fn entries_have_required_fields() {
    let mat = load_matrix();
    let entries = mat["entries"].as_array().unwrap();
    let required = [
        "id",
        "title",
        "impact",
        "confidence",
        "effort",
        "score",
        "rationale",
        "status",
    ];

    let mut ids_seen = HashSet::new();

    for entry in entries {
        let eid = entry["id"].as_str().unwrap_or("?");

        for field in &required {
            assert!(!entry[field].is_null(), "{eid}: missing field \"{field}\"");
        }

        // Ranges
        for dim in ["impact", "confidence", "effort"] {
            let val = entry[dim].as_f64().unwrap();
            assert!(
                (0.0..=5.0).contains(&val),
                "{eid}.{dim}={val}: out of range [0.0, 5.0]"
            );
        }

        // Valid status
        let status = entry["status"].as_str().unwrap_or("");
        assert!(
            ["eligible", "deferred", "in_progress", "completed"].contains(&status),
            "{eid}: invalid status \"{status}\""
        );

        // Unique IDs
        assert!(ids_seen.insert(eid.to_string()), "{eid}: duplicate ID");
    }
}

#[test]
fn scores_match_formula() {
    let mat = load_matrix();
    let entries = mat["entries"].as_array().unwrap();

    for entry in entries {
        let eid = entry["id"].as_str().unwrap_or("?");
        let impact = entry["impact"].as_f64().unwrap();
        let confidence = entry["confidence"].as_f64().unwrap();
        let effort = entry["effort"].as_f64().unwrap();
        let claimed = entry["score"].as_f64().unwrap();

        let computed = (impact * 0.5) + (confidence * 0.3) + (effort * 0.2);
        let computed_rounded = (computed * 10.0).round() / 10.0;

        assert!(
            (computed_rounded - claimed).abs() < 0.05,
            "{eid}: claimed={claimed} computed={computed_rounded} (impact={impact} conf={confidence} effort={effort})"
        );
    }
}

#[test]
fn threshold_enforced() {
    let mat = load_matrix();
    let threshold = mat["scoring"]["threshold"].as_f64().unwrap();
    let entries = mat["entries"].as_array().unwrap();

    for entry in entries {
        let eid = entry["id"].as_str().unwrap_or("?");
        let score = entry["score"].as_f64().unwrap();
        let status = entry["status"].as_str().unwrap_or("");

        if status == "eligible" || status == "in_progress" {
            assert!(
                score >= threshold,
                "{eid}: score={score} < threshold={threshold} but status={status}"
            );
        }
    }
}

#[test]
fn summary_consistent() {
    let mat = load_matrix();
    let entries = mat["entries"].as_array().unwrap();
    let deferred = mat["deferred"].as_array().unwrap();
    let summary = &mat["summary"];

    let total = entries.len();
    let eligible = entries
        .iter()
        .filter(|e| e["status"].as_str() == Some("eligible"))
        .count();

    assert_eq!(
        summary["total_entries"].as_u64().unwrap() as usize,
        total,
        "total_entries mismatch"
    );
    assert_eq!(
        summary["eligible"].as_u64().unwrap() as usize,
        eligible,
        "eligible count mismatch"
    );
    assert_eq!(
        summary["deferred"].as_u64().unwrap() as usize,
        deferred.len(),
        "deferred count mismatch"
    );

    // Average score
    let avg: f64 = entries
        .iter()
        .map(|e| e["score"].as_f64().unwrap())
        .sum::<f64>()
        / total as f64;
    let avg_rounded = (avg * 100.0).round() / 100.0;
    let claimed_avg = summary["average_score"].as_f64().unwrap();
    assert!(
        (avg_rounded - claimed_avg).abs() < 0.05,
        "average_score: claimed={claimed_avg} computed={avg_rounded}"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_opportunity_matrix.sh");
    assert!(
        script.exists(),
        "scripts/check_opportunity_matrix.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_opportunity_matrix.sh must be executable"
        );
    }
}
