//! Integration test: Isomorphism proof protocol (bd-2bd)
//!
//! Validates that:
//! 1. The protocol JSON exists and is valid.
//! 2. All six proof categories are defined with checks and golden formats.
//! 3. Proof template has required fields and valid statuses.
//! 4. Example proof satisfies the template.
//! 5. Applicable modules reference valid ABI modules.
//! 6. Summary statistics are consistent.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test isomorphism_proof_test

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

fn load_protocol() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/isomorphism_proof_protocol.json");
    let content =
        std::fs::read_to_string(&path).expect("isomorphism_proof_protocol.json should exist");
    serde_json::from_str(&content).expect("isomorphism_proof_protocol.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn protocol_exists_and_valid() {
    let proto = load_protocol();
    assert!(
        proto["schema_version"].is_number(),
        "Missing schema_version"
    );
    assert!(
        proto["proof_categories"].is_object(),
        "Missing proof_categories"
    );
    assert!(
        proto["proof_template"].is_object(),
        "Missing proof_template"
    );
    assert!(proto["enforcement"].is_object(), "Missing enforcement");
    assert!(
        proto["applicable_modules"].is_object(),
        "Missing applicable_modules"
    );
    assert!(proto["summary"].is_object(), "Missing summary");
}

#[test]
fn all_proof_categories_defined() {
    let proto = load_protocol();
    let cats = proto["proof_categories"].as_object().unwrap();

    let expected = [
        "ordering",
        "tie_breaking",
        "fp_behavior",
        "rng_behavior",
        "side_effects",
        "memory_semantics",
    ];

    for cat_name in &expected {
        assert!(
            cats.contains_key(*cat_name),
            "Missing proof category: {cat_name}"
        );
        let cat = &cats[*cat_name];
        assert!(
            cat["description"].is_string(),
            "{cat_name}: missing description"
        );
        let checks = cat["required_checks"].as_array().unwrap();
        assert!(!checks.is_empty(), "{cat_name}: empty required_checks");
        assert!(
            cat["golden_format"].is_string(),
            "{cat_name}: missing golden_format"
        );
    }
}

#[test]
fn proof_template_complete() {
    let proto = load_protocol();
    let template = &proto["proof_template"];

    let required = template["required_fields"].as_array().unwrap();
    let required_strs: HashSet<&str> = required.iter().filter_map(|v| v.as_str()).collect();

    for field in [
        "lever_id",
        "bead_id",
        "functions",
        "categories",
        "golden_commands",
        "golden_hash",
        "proof_status",
    ] {
        assert!(
            required_strs.contains(field),
            "required_fields missing: {field}"
        );
    }

    // Valid statuses
    let statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    for st in ["pending", "verified", "failed", "waived"] {
        assert!(statuses.contains(st), "proof_statuses missing: {st}");
    }
}

#[test]
fn example_satisfies_template() {
    let proto = load_protocol();
    let template = &proto["proof_template"];
    let example = &template["example"];

    assert!(!example.is_null(), "Missing example proof");

    let required = template["required_fields"].as_array().unwrap();
    for field in required {
        let field_str = field.as_str().unwrap();
        assert!(
            !example[field_str].is_null(),
            "Example missing required field: {field_str}"
        );
    }

    // Example proof_status must be a valid status
    let statuses: HashSet<&str> = template["proof_statuses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let example_status = example["proof_status"].as_str().unwrap();
    assert!(
        statuses.contains(example_status),
        "Example proof_status \"{example_status}\" not in valid statuses"
    );

    // Example categories must reference defined categories
    let cats: HashSet<&str> = proto["proof_categories"]
        .as_object()
        .unwrap()
        .keys()
        .map(|k| k.as_str())
        .collect();
    for cat in example["categories"].as_array().unwrap() {
        let cat_str = cat.as_str().unwrap();
        assert!(
            cats.contains(cat_str),
            "Example references undefined category: {cat_str}"
        );
    }
}

#[test]
fn applicable_modules_valid() {
    let proto = load_protocol();
    let matrix = load_matrix();

    let valid_modules: HashSet<String> = matrix["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s["module"].as_str().map(String::from))
        .collect();

    let applicable = &proto["applicable_modules"];
    let mut all_modules = Vec::new();

    for priority in ["high_priority", "medium_priority", "low_priority"] {
        let entries = applicable[priority].as_array().unwrap();
        for entry in entries {
            let module = entry["module"].as_str().unwrap();
            assert!(
                valid_modules.contains(module),
                "{module} ({priority}): not a valid ABI module"
            );
            assert!(
                entry["reason"].is_string(),
                "{module} ({priority}): missing reason"
            );
            all_modules.push(module.to_string());
        }
    }

    // No duplicates
    let unique: HashSet<&str> = all_modules.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        all_modules.len(),
        "Duplicate modules in applicable_modules"
    );
}

#[test]
fn summary_consistent() {
    let proto = load_protocol();
    let summary = &proto["summary"];
    let cats = proto["proof_categories"].as_object().unwrap();
    let applicable = &proto["applicable_modules"];
    let proofs = proto["existing_proofs"].as_array().unwrap();

    assert_eq!(
        summary["total_categories"].as_u64().unwrap() as usize,
        cats.len(),
        "total_categories mismatch"
    );

    for (priority, key) in [
        ("high_priority", "high_priority_modules"),
        ("medium_priority", "medium_priority_modules"),
        ("low_priority", "low_priority_modules"),
    ] {
        let claimed = summary[key].as_u64().unwrap() as usize;
        let actual = applicable[priority].as_array().unwrap().len();
        assert_eq!(claimed, actual, "{key} mismatch");
    }

    assert_eq!(
        summary["existing_proof_count"].as_u64().unwrap() as usize,
        proofs.len(),
        "existing_proof_count mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_isomorphism_proof.sh");
    assert!(
        script.exists(),
        "scripts/check_isomorphism_proof.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_isomorphism_proof.sh must be executable"
        );
    }
}
