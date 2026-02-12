//! Integration test: Closure evidence gate (bd-4rl)
//!
//! Validates that:
//! 1. The closure evidence schema exists and is valid JSON.
//! 2. Every required evidence field is defined in the schema.
//! 3. Legacy-exempt list covers only closed critique beads.
//! 4. Non-exempt closed critique beads have matrix entries with evidence.
//! 5. The CI gate script exists and is executable.
//! 6. Matrix rows have the evidence fields the schema requires.
//!
//! Run: cargo test -p frankenlibc-harness --test closure_gate_test

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

fn load_schema() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/closure_evidence_schema.json");
    let content =
        std::fs::read_to_string(&path).expect("closure_evidence_schema.json should exist");
    serde_json::from_str(&content).expect("closure_evidence_schema.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/verification_matrix.json");
    let content = std::fs::read_to_string(&path).expect("verification_matrix.json should exist");
    serde_json::from_str(&content).expect("verification_matrix.json should be valid JSON")
}

fn load_beads() -> Vec<serde_json::Value> {
    let path = workspace_root().join(".beads/issues.jsonl");
    let content = std::fs::read_to_string(&path).expect(".beads/issues.jsonl should exist");
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each bead line should be valid JSON"))
        .collect()
}

#[test]
fn schema_exists_and_valid() {
    let schema = load_schema();
    assert!(
        schema["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        schema["evidence_requirements"].is_object(),
        "Missing evidence_requirements"
    );
    assert!(schema["legacy_exempt"].is_array(), "Missing legacy_exempt");
    assert!(schema["enforcement"].is_object(), "Missing enforcement");
    assert!(schema["paths"].is_object(), "Missing paths");
}

#[test]
fn schema_has_required_evidence_fields() {
    let schema = load_schema();
    let reqs = schema["evidence_requirements"].as_object().unwrap();

    let expected = [
        "matrix_entry",
        "test_commands",
        "artifact_references",
        "coverage_not_missing",
        "close_blockers_empty",
    ];

    for field in &expected {
        assert!(
            reqs.contains_key(*field),
            "evidence_requirements missing '{field}'"
        );
        let req = &reqs[*field];
        assert!(
            req["required"].is_boolean(),
            "{field}: missing 'required' boolean"
        );
        assert!(
            req["description"].is_string(),
            "{field}: missing 'description'"
        );
    }
}

#[test]
fn legacy_exempt_only_contains_closed_critique_beads() {
    let schema = load_schema();
    let beads = load_beads();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let closed_critique: HashSet<String> = beads
        .iter()
        .filter(|b| {
            b["status"].as_str() == Some("closed")
                && b["labels"]
                    .as_array()
                    .is_some_and(|l| l.iter().any(|v| v.as_str() == Some("critique")))
        })
        .filter_map(|b| b["id"].as_str().map(String::from))
        .collect();

    let invalid: Vec<_> = exempt.difference(&closed_critique).collect();
    assert!(
        invalid.is_empty(),
        "Legacy-exempt beads that are not closed critique beads: {:?}",
        invalid
    );
}

#[test]
fn non_exempt_closed_beads_have_matrix_entries() {
    let schema = load_schema();
    let beads = load_beads();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_ids: HashSet<String> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(String::from))
        .collect();

    let mut missing = Vec::new();
    for b in &beads {
        if b["status"].as_str() != Some("closed") {
            continue;
        }
        let labels = b["labels"].as_array();
        let is_critique = labels.is_some_and(|l| l.iter().any(|v| v.as_str() == Some("critique")));
        if !is_critique {
            continue;
        }
        let bid = b["id"].as_str().unwrap_or("");
        if !exempt.contains(bid) && !matrix_ids.contains(bid) {
            missing.push(bid.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "Non-exempt closed critique beads without matrix entries: {:?}",
        missing
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_closure_gate.sh");
    assert!(script.exists(), "scripts/check_closure_gate.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_closure_gate.sh must be executable"
        );
    }
}

#[test]
fn matrix_rows_have_evidence_fields() {
    let matrix = load_matrix();
    let entries = matrix["entries"].as_array().unwrap();

    let required_row_fields = ["unit_cmds", "e2e_cmds", "artifact_paths", "close_blockers"];

    for entry in entries {
        let bid = entry["bead_id"].as_str().unwrap_or("<unknown>");
        let row = &entry["row"];
        assert!(row.is_object(), "{bid}: missing row object");

        for field in &required_row_fields {
            assert!(
                !row[field].is_null(),
                "{bid}: row missing required field '{field}'"
            );
        }

        assert!(
            entry["coverage_summary"].is_object(),
            "{bid}: missing coverage_summary"
        );
        let overall = entry["coverage_summary"]["overall"].as_str().unwrap_or("");
        assert!(
            ["missing", "partial", "complete"].contains(&overall),
            "{bid}: invalid coverage_summary.overall '{overall}'"
        );
    }
}

#[test]
fn non_exempt_closed_beads_have_evidence() {
    let schema = load_schema();
    let beads = load_beads();
    let matrix = load_matrix();

    let exempt: HashSet<String> = schema["legacy_exempt"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let matrix_map: std::collections::HashMap<String, &serde_json::Value> = matrix["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["bead_id"].as_str().map(|id| (id.to_string(), e)))
        .collect();

    let mut violations = Vec::new();
    for b in &beads {
        if b["status"].as_str() != Some("closed") {
            continue;
        }
        let labels = b["labels"].as_array();
        let is_critique = labels.is_some_and(|l| l.iter().any(|v| v.as_str() == Some("critique")));
        if !is_critique {
            continue;
        }
        let bid = b["id"].as_str().unwrap_or("");
        if exempt.contains(bid) {
            continue;
        }

        if let Some(entry) = matrix_map.get(bid) {
            let row = &entry["row"];
            let cs = &entry["coverage_summary"];

            let unit_cmds = row["unit_cmds"].as_array().is_none_or(|a| a.is_empty());
            let e2e_cmds = row["e2e_cmds"].as_array().is_none_or(|a| a.is_empty());
            if unit_cmds && e2e_cmds {
                violations.push(format!("{bid}: no test commands"));
            }

            let artifacts = row["artifact_paths"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            let log_refs = row["log_schema_refs"]
                .as_array()
                .is_none_or(|a| a.is_empty());
            if artifacts && log_refs {
                violations.push(format!("{bid}: no artifact references"));
            }

            if cs["overall"].as_str() == Some("missing") {
                violations.push(format!("{bid}: coverage_summary is 'missing'"));
            }

            let blockers = row["close_blockers"]
                .as_array()
                .is_some_and(|a| !a.is_empty());
            if blockers {
                violations.push(format!("{bid}: has close_blockers"));
            }
        } else {
            violations.push(format!("{bid}: no matrix entry"));
        }
    }

    assert!(
        violations.is_empty(),
        "Non-exempt closed beads with evidence violations:\n{}",
        violations.join("\n")
    );
}
