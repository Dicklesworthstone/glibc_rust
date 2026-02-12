//! Integration test: Perf budget enforcement policy (bd-2r0)
//!
//! Validates that:
//! 1. The perf budget policy JSON exists and is valid.
//! 2. All three budget tiers are defined with required fields.
//! 3. Hotpath symbols match support_matrix.json perf_class assignments.
//! 4. Assessment counts match support_matrix.json.
//! 5. Budget thresholds are consistent with replacement_levels.json.
//! 6. Active waivers have required fields.
//! 7. Variance guardrails are reasonable.
//! 8. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test perf_budget_test

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

fn load_policy() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/perf_budget_policy.json");
    let content = std::fs::read_to_string(&path).expect("perf_budget_policy.json should exist");
    serde_json::from_str(&content).expect("perf_budget_policy.json should be valid JSON")
}

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

fn load_levels() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/replacement_levels.json");
    let content = std::fs::read_to_string(&path).expect("replacement_levels.json should exist");
    serde_json::from_str(&content).expect("replacement_levels.json should be valid JSON")
}

#[test]
fn policy_exists_and_valid() {
    let pol = load_policy();
    assert!(pol["schema_version"].is_number(), "Missing schema_version");
    assert!(pol["budgets"].is_object(), "Missing budgets");
    assert!(
        pol["hotpath_symbols"].is_object(),
        "Missing hotpath_symbols"
    );
    assert!(
        pol["current_assessment"].is_object(),
        "Missing current_assessment"
    );
    assert!(
        pol["variance_guardrails"].is_object(),
        "Missing variance_guardrails"
    );
    assert!(pol["waiver_policy"].is_object(), "Missing waiver_policy");
    assert!(pol["enforcement"].is_object(), "Missing enforcement");
}

#[test]
fn all_budget_tiers_defined() {
    let pol = load_policy();
    let budgets = pol["budgets"].as_object().unwrap();

    for tier in ["strict_hotpath", "hardened_hotpath", "coldpath"] {
        assert!(budgets.contains_key(tier), "Missing budget tier: {tier}");
        let tier_def = &budgets[tier];
        assert!(
            tier_def["description"].is_string(),
            "{tier}: missing description"
        );
        assert!(
            tier_def["applies_to"].is_string(),
            "{tier}: missing applies_to"
        );
    }

    // strict_hotpath must have both mode budgets
    let strict = &budgets["strict_hotpath"];
    assert!(
        strict["strict_mode_ns"].is_u64(),
        "strict_hotpath: strict_mode_ns must be a positive integer"
    );
    assert!(
        strict["hardened_mode_ns"].is_u64(),
        "strict_hotpath: hardened_mode_ns must be a positive integer"
    );

    // Budget ordering: strict < hardened
    let strict_ns = strict["strict_mode_ns"].as_u64().unwrap();
    let hardened_ns = strict["hardened_mode_ns"].as_u64().unwrap();
    assert!(
        strict_ns < hardened_ns,
        "strict_mode_ns ({strict_ns}) should be less than hardened_mode_ns ({hardened_ns})"
    );
}

#[test]
fn hotpath_symbols_match_matrix() {
    let pol = load_policy();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();

    // Build set of strict_hotpath symbols from matrix
    let matrix_strict: HashSet<String> = symbols
        .iter()
        .filter(|s| s["perf_class"].as_str() == Some("strict_hotpath"))
        .filter_map(|s| s["symbol"].as_str().map(String::from))
        .collect();

    // Build set from policy
    let policy_strict: HashSet<String> = pol["hotpath_symbols"]["strict_hotpath"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["symbol"].as_str().map(String::from))
        .collect();

    let missing: Vec<_> = matrix_strict.difference(&policy_strict).collect();
    let extra: Vec<_> = policy_strict.difference(&matrix_strict).collect();

    assert!(
        missing.is_empty(),
        "Symbols in matrix strict_hotpath but missing from policy: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "Symbols in policy but not matrix strict_hotpath: {extra:?}"
    );

    // Verify module/status match
    let matrix_map: HashMap<String, (&str, &str)> = symbols
        .iter()
        .filter_map(|s| {
            let name = s["symbol"].as_str()?;
            let module = s["module"].as_str()?;
            let status = s["status"].as_str()?;
            Some((name.to_string(), (module, status)))
        })
        .collect();

    for entry in pol["hotpath_symbols"]["strict_hotpath"].as_array().unwrap() {
        let sym = entry["symbol"].as_str().unwrap();
        let pol_module = entry["module"].as_str().unwrap_or("");
        let pol_status = entry["status"].as_str().unwrap_or("");

        if let Some(&(matrix_module, matrix_status)) = matrix_map.get(sym) {
            assert_eq!(
                pol_module, matrix_module,
                "{sym}: module mismatch policy={pol_module} matrix={matrix_module}"
            );
            assert_eq!(
                pol_status, matrix_status,
                "{sym}: status mismatch policy={pol_status} matrix={matrix_status}"
            );
        }
    }
}

#[test]
fn assessment_matches_matrix() {
    let pol = load_policy();
    let matrix = load_matrix();

    let symbols = matrix["symbols"].as_array().unwrap();
    let assessment = &pol["current_assessment"];

    // Total
    let total = symbols.len();
    let claimed_total = assessment["total_symbols"].as_u64().unwrap() as usize;
    assert_eq!(
        claimed_total, total,
        "total_symbols: policy={claimed_total} matrix={total}"
    );

    // Count perf classes from matrix
    let mut class_counts: HashMap<String, usize> = HashMap::new();
    let mut mod_counts: HashMap<String, usize> = HashMap::new();
    let mut status_counts: HashMap<String, usize> = HashMap::new();

    for sym in symbols {
        let pc = sym["perf_class"].as_str().unwrap_or("coldpath");
        *class_counts.entry(pc.to_string()).or_default() += 1;

        if pc == "strict_hotpath" {
            let m = sym["module"].as_str().unwrap_or("unknown");
            let s = sym["status"].as_str().unwrap_or("Unknown");
            *mod_counts.entry(m.to_string()).or_default() += 1;
            *status_counts.entry(s.to_string()).or_default() += 1;
        }
    }

    // Verify class counts
    for (pc, key) in [
        ("strict_hotpath", "strict_hotpath_count"),
        ("hardened_hotpath", "hardened_hotpath_count"),
        ("coldpath", "coldpath_count"),
    ] {
        let actual = *class_counts.get(pc).unwrap_or(&0);
        let claimed = assessment[key].as_u64().unwrap() as usize;
        assert_eq!(claimed, actual, "{key}: policy={claimed} matrix={actual}");
    }

    // Verify module breakdown
    let by_mod = assessment["strict_hotpath_by_module"].as_object().unwrap();
    for (m, claimed_val) in by_mod {
        let claimed = claimed_val.as_u64().unwrap() as usize;
        let actual = *mod_counts.get(m.as_str()).unwrap_or(&0);
        assert_eq!(
            claimed, actual,
            "strict_hotpath_by_module.{m}: policy={claimed} matrix={actual}"
        );
    }
}

#[test]
fn budgets_consistent_with_replacement_levels() {
    let pol = load_policy();
    let lvl = load_levels();

    let pol_strict = pol["budgets"]["strict_hotpath"]["strict_mode_ns"]
        .as_u64()
        .unwrap();
    let pol_hardened = pol["budgets"]["strict_hotpath"]["hardened_mode_ns"]
        .as_u64()
        .unwrap();

    for entry in lvl["levels"].as_array().unwrap() {
        let lid = entry["level"].as_str().unwrap_or("?");
        let gc = &entry["gate_criteria"];

        if let Some(strict_ns) = gc["perf_budget_strict_ns"].as_u64() {
            assert_eq!(
                pol_strict, strict_ns,
                "{lid}: strict budget policy={pol_strict}ns levels={strict_ns}ns"
            );
        }
        if let Some(hardened_ns) = gc["perf_budget_hardened_ns"].as_u64() {
            assert_eq!(
                pol_hardened, hardened_ns,
                "{lid}: hardened budget policy={pol_hardened}ns levels={hardened_ns}ns"
            );
        }
    }
}

#[test]
fn waivers_have_required_fields() {
    let pol = load_policy();
    let waivers = pol["active_waivers"].as_array().unwrap();
    let required = pol["waiver_policy"]["required_fields"].as_array().unwrap();

    let required_keys: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();

    for waiver in waivers {
        let bid = waiver["bead_id"].as_str().unwrap_or("<no bead_id>");
        for key in &required_keys {
            assert!(
                !waiver[key].is_null(),
                "Waiver {bid}: missing required field \"{key}\""
            );
        }
    }
}

#[test]
fn variance_guardrails_reasonable() {
    let pol = load_policy();
    let vg = &pol["variance_guardrails"];

    let min_runs = vg["min_repeat_runs"].as_u64().unwrap();
    let max_runs = vg["max_repeat_runs"].as_u64().unwrap();
    let max_cv = vg["max_coefficient_of_variation_pct"].as_u64().unwrap();

    assert!(
        min_runs >= 3,
        "min_repeat_runs ({min_runs}) should be >= 3 for statistical validity"
    );
    assert!(
        max_runs >= min_runs,
        "max_repeat_runs ({max_runs}) should be >= min_repeat_runs ({min_runs})"
    );
    assert!(
        max_cv > 0 && max_cv <= 50,
        "max_coefficient_of_variation_pct ({max_cv}) should be in (0, 50]"
    );

    // Load guard
    let load_guard = &vg["load_guard"];
    assert!(
        load_guard["enabled"].is_boolean(),
        "load_guard.enabled must be boolean"
    );

    let load_factor = load_guard["max_load_factor"].as_f64().unwrap();
    assert!(
        (0.0..=1.0).contains(&load_factor),
        "max_load_factor ({load_factor}) should be in [0.0, 1.0]"
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_perf_budget.sh");
    assert!(script.exists(), "scripts/check_perf_budget.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_perf_budget.sh must be executable"
        );
    }
}
