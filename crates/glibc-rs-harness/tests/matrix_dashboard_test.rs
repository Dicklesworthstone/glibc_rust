//! Integration test: Verification matrix dashboard export (bd-38s)
//!
//! Validates that:
//! 1. The dashboard export script exists and is executable.
//! 2. Text output contains expected header and table structure.
//! 3. JSON output is valid and contains summary + rows.
//! 4. Row counts match matrix entries.
//!
//! Run: cargo test -p glibc-rs-harness --test matrix_dashboard_test

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

#[test]
fn dashboard_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/export_matrix_dashboard.sh");
    assert!(
        script.exists(),
        "scripts/export_matrix_dashboard.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "export_matrix_dashboard.sh must be executable"
        );
    }
}

#[test]
fn text_output_has_expected_structure() {
    let root = workspace_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/export_matrix_dashboard.sh"))
        .arg("text")
        .output()
        .expect("dashboard script should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Verification Matrix Dashboard"),
        "Should contain dashboard header"
    );
    assert!(
        stdout.contains("Total beads:"),
        "Should contain totals line"
    );
    assert!(stdout.contains("BEAD"), "Should contain table header");
    assert!(stdout.contains("bd-"), "Should contain bead IDs");
    assert!(stdout.contains("Legend:"), "Should contain legend");
}

#[test]
fn json_output_is_valid() {
    let root = workspace_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/export_matrix_dashboard.sh"))
        .arg("json")
        .output()
        .expect("dashboard script should execute");

    assert!(output.status.success(), "JSON export should succeed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let data: serde_json::Value =
        serde_json::from_str(&stdout).expect("JSON output should be valid JSON");

    assert!(data["summary"].is_object(), "Missing summary");
    assert!(data["rows"].is_array(), "Missing rows array");
    assert!(data["by_priority"].is_object(), "Missing by_priority");

    let total = data["summary"]["total"].as_u64().unwrap();
    let rows = data["rows"].as_array().unwrap();
    assert_eq!(
        total as usize,
        rows.len(),
        "Summary total should match row count"
    );

    // Verify summary consistency
    let complete = data["summary"]["complete"].as_u64().unwrap();
    let partial = data["summary"]["partial"].as_u64().unwrap();
    let missing = data["summary"]["missing"].as_u64().unwrap();
    assert_eq!(
        complete + partial + missing,
        total,
        "Summary counts should sum to total"
    );
}

#[test]
fn json_rows_match_matrix_entries() {
    let root = workspace_root();

    // Load matrix directly
    let matrix_path = root.join("tests/conformance/verification_matrix.json");
    let matrix_content = std::fs::read_to_string(&matrix_path).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&matrix_content).unwrap();
    let matrix_entries = matrix["entries"].as_array().unwrap();

    // Generate JSON dashboard
    let output = Command::new("bash")
        .arg(root.join("scripts/export_matrix_dashboard.sh"))
        .arg("json")
        .output()
        .expect("dashboard script should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let data: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rows = data["rows"].as_array().unwrap();

    assert_eq!(
        matrix_entries.len(),
        rows.len(),
        "Dashboard rows should match matrix entry count"
    );
}

#[test]
fn json_rows_have_required_fields() {
    let root = workspace_root();
    let output = Command::new("bash")
        .arg(root.join("scripts/export_matrix_dashboard.sh"))
        .arg("json")
        .output()
        .expect("dashboard script should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let data: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rows = data["rows"].as_array().unwrap();

    for row in rows {
        let bid = row["bead_id"].as_str().unwrap_or("<unknown>");
        assert!(row["bead_id"].is_string(), "{bid}: missing bead_id");
        assert!(row["priority"].is_number(), "{bid}: missing priority");
        assert!(row["overall"].is_string(), "{bid}: missing overall");
        assert!(row["gaps"].is_array(), "{bid}: missing gaps");
    }
}
