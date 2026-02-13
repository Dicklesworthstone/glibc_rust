// release_dossier_validator_test.rs — bd-5fw.3
// Verifies that the release dossier validator runs, produces a valid report,
// and enforces integrity checking with SHA256 checksums.

use std::process::Command;

#[test]
fn dossier_validator_produces_valid_report() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let script = repo_root.join("scripts/release_dossier_validator.py");
    assert!(
        script.exists(),
        "release_dossier_validator.py not found at {:?}",
        script
    );

    let output = Command::new("python3")
        .arg(&script)
        .current_dir(repo_root)
        .output()
        .expect("failed to run release_dossier_validator.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let report: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "Failed to parse dossier report: {}\nstdout: {}\nstderr: {}",
            e, stdout, stderr
        );
    });

    // Required report fields
    let required_keys = [
        "schema_version",
        "bead",
        "status",
        "verdict",
        "summary",
        "artifact_results",
        "integrity_index",
        "findings",
        "compatibility_policy",
        "dossier_manifest_version",
    ];
    for key in required_keys {
        assert!(
            report.get(key).is_some(),
            "Report missing required key: {key}"
        );
    }

    // Summary fields
    let summary = &report["summary"];
    assert!(summary["total_artifacts"].as_u64().unwrap_or(0) > 0);
    assert!(summary["valid"].as_u64().is_some());
    assert!(summary["missing"].as_u64().is_some());
    assert!(summary["critical_missing"].as_u64().is_some());
    assert!(summary["errors"].as_u64().is_some());
    assert!(summary["warnings"].as_u64().is_some());

    // Verdict must be a known value
    let verdict = report["verdict"].as_str().unwrap();
    assert!(
        ["PASS", "FAIL", "FAIL_CRITICAL"].contains(&verdict),
        "Unknown verdict: {verdict}"
    );
}

#[test]
fn dossier_artifact_results_have_required_fields() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    assert!(
        report_path.exists(),
        "Dossier report artifact not found at {:?}",
        report_path
    );

    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let results = report["artifact_results"].as_array().unwrap();
    assert!(!results.is_empty(), "artifact_results must be non-empty");

    for r in results {
        assert!(r["id"].as_str().is_some(), "result missing id");
        assert!(r["path"].as_str().is_some(), "result missing path");
        assert!(r["kind"].as_str().is_some(), "result missing kind");
        assert!(r["required"].is_boolean(), "result missing required");
        assert!(r["critical"].is_boolean(), "result missing critical");

        let st = r["status"].as_str().unwrap();
        assert!(
            ["VALID", "PRESENT", "MISSING"].contains(&st),
            "Unknown artifact status: {st}"
        );

        // Valid/present artifacts must have SHA256
        if st != "MISSING" {
            assert!(
                r["sha256"].as_str().is_some(),
                "Present artifact {} missing sha256",
                r["id"]
            );
            let sha = r["sha256"].as_str().unwrap();
            assert_eq!(sha.len(), 64, "SHA256 must be 64 hex chars for {}", r["id"]);
        }
    }
}

#[test]
fn dossier_integrity_index_consistent() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let index = report["integrity_index"].as_object().unwrap();
    let results = report["artifact_results"].as_array().unwrap();

    // Every non-missing artifact must be in the integrity index
    for r in results {
        if r["status"].as_str() != Some("MISSING") {
            let id = r["id"].as_str().unwrap();
            assert!(
                index.contains_key(id),
                "Artifact '{id}' is present but missing from integrity_index"
            );

            // Checksums must match
            let idx_entry = &index[id];
            assert_eq!(
                r["sha256"].as_str(),
                idx_entry["sha256"].as_str(),
                "SHA256 mismatch for {id} between artifact_results and integrity_index"
            );
        }
    }

    // No critical missing
    assert_eq!(
        report["summary"]["critical_missing"].as_u64().unwrap(),
        0,
        "No critical artifacts should be missing"
    );
}

#[test]
fn dossier_compatibility_policy_present() {
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    let report_path = repo_root.join("tests/release/dossier_validation_report.v1.json");
    let content = std::fs::read_to_string(&report_path).expect("failed to read report");
    let report: serde_json::Value =
        serde_json::from_str(&content).expect("report is not valid JSON");

    let policy = report["compatibility_policy"].as_object().unwrap();
    assert!(policy.contains_key("format"), "policy missing 'format'");
    assert!(
        policy.contains_key("schema_versions"),
        "policy missing 'schema_versions'"
    );
    assert!(
        policy.contains_key("integrity"),
        "policy missing 'integrity'"
    );
}
