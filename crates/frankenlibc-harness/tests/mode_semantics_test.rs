//! Integration test: Mode semantics matrix (bd-wud)
//!
//! Validates that:
//! 1. The mode semantics matrix exists and is valid JSON.
//! 2. All 20 API families are documented with required fields.
//! 3. Every family references a real ABI module source file.
//! 4. Both strict and hardened behaviors are documented per family.
//! 5. Summary statistics are consistent with family entries.
//! 6. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test mode_semantics_test

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
    let path = workspace_root().join("tests/conformance/mode_semantics_matrix.json");
    let content = std::fs::read_to_string(&path).expect("mode_semantics_matrix.json should exist");
    serde_json::from_str(&content).expect("mode_semantics_matrix.json should be valid JSON")
}

#[test]
fn matrix_exists_and_valid() {
    let m = load_matrix();
    assert!(m["schema_version"].is_number(), "Missing schema_version");
    assert!(m["modes"].is_object(), "Missing modes");
    assert!(m["families"].is_array(), "Missing families");
    assert!(m["summary"].is_object(), "Missing summary");

    let modes = m["modes"].as_object().unwrap();
    assert!(modes.contains_key("strict"), "Missing strict mode");
    assert!(modes.contains_key("hardened"), "Missing hardened mode");
}

#[test]
fn all_families_have_required_fields() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();
    assert!(!families.is_empty(), "Families should not be empty");

    let required = [
        "family",
        "module",
        "heals_call_sites",
        "symbols",
        "strict_behavior",
        "hardened_behavior",
    ];

    for fam in families {
        let name = fam["family"].as_str().unwrap_or("<unknown>");
        for field in &required {
            assert!(!fam[field].is_null(), "{name}: missing '{field}'");
        }
        assert!(
            fam["symbols"].as_array().is_some_and(|a| !a.is_empty()),
            "{name}: symbols should be non-empty array"
        );
        assert!(
            fam["strict_behavior"].is_object(),
            "{name}: strict_behavior should be object"
        );
        assert!(
            fam["hardened_behavior"].is_object(),
            "{name}: hardened_behavior should be object"
        );
    }
}

#[test]
fn family_modules_exist_in_abi_source() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    for fam in families {
        let name = fam["family"].as_str().unwrap_or("<unknown>");
        let module = fam["module"].as_str().unwrap();
        let src_file = abi_src.join(format!("{module}.rs"));
        assert!(
            src_file.exists(),
            "{name}: {module}.rs not found in ABI source"
        );
    }
}

#[test]
fn heals_call_sites_match_source() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    let mut mismatches = Vec::new();
    for fam in families {
        let name = fam["family"].as_str().unwrap_or("<unknown>");
        let module = fam["module"].as_str().unwrap();
        let claimed = fam["heals_call_sites"].as_u64().unwrap();

        let src_file = abi_src.join(format!("{module}.rs"));
        if !src_file.exists() {
            continue;
        }
        let content = std::fs::read_to_string(&src_file).unwrap();
        let actual = content.matches("heals_enabled()").count() as u64;

        if actual != claimed {
            mismatches.push(format!(
                "{name} ({module}): claimed={claimed} actual={actual}"
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "heals_enabled() call site mismatches:\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn behaviors_have_matching_scenarios() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();

    for fam in families {
        let name = fam["family"].as_str().unwrap_or("<unknown>");
        let strict = fam["strict_behavior"].as_object().unwrap();
        let hardened = fam["hardened_behavior"].as_object().unwrap();

        // Every scenario in strict should have a corresponding hardened entry
        for key in strict.keys() {
            assert!(
                hardened.contains_key(key),
                "{name}: scenario '{key}' in strict_behavior but missing from hardened_behavior"
            );
        }
    }
}

#[test]
fn summary_consistent_with_entries() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();
    let summary = &m["summary"];

    let claimed_total = summary["total_families"].as_u64().unwrap() as usize;
    assert_eq!(claimed_total, families.len(), "total_families mismatch");

    let claimed_healing = summary["families_with_healing"].as_u64().unwrap() as usize;
    let actual_healing = families
        .iter()
        .filter(|f| f["heals_call_sites"].as_u64().unwrap_or(0) > 0)
        .count();
    assert_eq!(
        claimed_healing, actual_healing,
        "families_with_healing mismatch"
    );

    let claimed_sites = summary["total_heals_call_sites"].as_u64().unwrap();
    let actual_sites: u64 = families
        .iter()
        .map(|f| f["heals_call_sites"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(
        claimed_sites, actual_sites,
        "total_heals_call_sites mismatch"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_mode_semantics.sh");
    assert!(
        script.exists(),
        "scripts/check_mode_semantics.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_mode_semantics.sh must be executable"
        );
    }
}

#[test]
fn no_duplicate_families() {
    let m = load_matrix();
    let families = m["families"].as_array().unwrap();

    let mut seen = std::collections::HashSet::new();
    let mut dups = Vec::new();
    for fam in families {
        let name = fam["family"].as_str().unwrap_or("<unknown>");
        if !seen.insert(name) {
            dups.push(name.to_string());
        }
    }

    assert!(dups.is_empty(), "Duplicate family names: {:?}", dups);
}
