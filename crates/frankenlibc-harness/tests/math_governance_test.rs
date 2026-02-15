//! Integration test: Math governance classification (bd-2yx)
//!
//! Validates that:
//! 1. The governance classification exists and is valid JSON.
//! 2. All three tiers are defined with required metadata.
//! 3. Every classified module exists in the production manifest.
//! 4. Every manifest module is classified (no gaps).
//! 5. No module appears in multiple tiers.
//! 6. Summary statistics match actual classifications.
//! 7. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test math_governance_test

use std::collections::{HashMap, HashSet};
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

fn manifest_union_modules(manifest: &serde_json::Value) -> HashSet<String> {
    manifest["production_modules"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(
            manifest["research_only_modules"]
                .as_array()
                .into_iter()
                .flatten(),
        )
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

#[test]
fn governance_exists_and_valid() {
    let gov = load_governance();
    assert!(gov["schema_version"].is_number(), "Missing schema_version");
    assert!(gov["tiers"].is_object(), "Missing tiers");
    assert!(
        gov["classifications"].is_object(),
        "Missing classifications"
    );
    assert!(gov["summary"].is_object(), "Missing summary");
}

#[test]
fn all_tiers_defined() {
    let gov = load_governance();
    let tiers = gov["tiers"].as_object().unwrap();

    for tier_name in ["production_core", "production_monitor", "research"] {
        assert!(
            tiers.contains_key(tier_name),
            "Missing tier definition: {tier_name}"
        );
        let tier = &tiers[tier_name];
        assert!(
            tier["description"].is_string(),
            "{tier_name}: missing description"
        );
        assert!(
            tier["feature_gate"].is_string(),
            "{tier_name}: missing feature_gate"
        );
    }
}

#[test]
fn classified_modules_exist_in_manifest() {
    let gov = load_governance();
    let manifest = load_manifest();
    let manifest_modules = manifest_union_modules(&manifest);

    let classifications = gov["classifications"].as_object().unwrap();
    let mut missing = Vec::new();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>");
            if !manifest_modules.contains(module) {
                missing.push(format!("{module} (tier={tier})"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "Classified modules not in manifest:\n{}",
        missing.join("\n")
    );
}

#[test]
fn all_manifest_modules_classified() {
    let gov = load_governance();
    let manifest = load_manifest();
    let manifest_modules = manifest_union_modules(&manifest);

    let classifications = gov["classifications"].as_object().unwrap();
    let mut classified = HashSet::new();

    for entries in classifications.values() {
        for entry in entries.as_array().unwrap() {
            if let Some(module) = entry["module"].as_str() {
                classified.insert(module.to_string());
            }
        }
    }

    let unclassified: Vec<_> = manifest_modules.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "Manifest modules not classified:\n{:?}",
        unclassified
    );
}

#[test]
fn no_duplicate_classifications() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();

    let mut seen: HashMap<String, String> = HashMap::new();
    let mut dups = Vec::new();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>").to_string();
            if let Some(prev_tier) = seen.insert(module.clone(), tier.clone()) {
                dups.push(format!("{module}: in both {prev_tier} and {tier}"));
            }
        }
    }

    assert!(
        dups.is_empty(),
        "Modules in multiple tiers:\n{}",
        dups.join("\n")
    );
}

#[test]
fn summary_consistent() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();
    let summary = &gov["summary"];

    let mut total = 0usize;
    for tier_name in ["production_core", "production_monitor", "research"] {
        let entries = classifications
            .get(tier_name)
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let claimed = summary[tier_name].as_u64().unwrap() as usize;
        assert_eq!(
            claimed, entries,
            "summary.{tier_name} mismatch: claimed={claimed} actual={entries}"
        );
        total += entries;
    }

    let claimed_total = summary["total_modules"].as_u64().unwrap() as usize;
    assert_eq!(claimed_total, total, "summary.total_modules mismatch");
}

#[test]
fn every_entry_has_rationale() {
    let gov = load_governance();
    let classifications = gov["classifications"].as_object().unwrap();

    for (tier, entries) in classifications {
        for entry in entries.as_array().unwrap() {
            let module = entry["module"].as_str().unwrap_or("<unknown>");
            assert!(
                entry["rationale"].is_string(),
                "{module} (tier={tier}): missing rationale"
            );
            let rationale = entry["rationale"].as_str().unwrap();
            assert!(
                !rationale.is_empty(),
                "{module} (tier={tier}): empty rationale"
            );
        }
    }
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_math_governance.sh");
    assert!(
        script.exists(),
        "scripts/check_math_governance.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_math_governance.sh must be executable"
        );
    }
}
