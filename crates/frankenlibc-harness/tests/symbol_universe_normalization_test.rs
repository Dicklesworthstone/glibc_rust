// symbol_universe_normalization_test.rs — bd-2vv.9
// Integration tests for symbol universe normalization and classification.

use std::path::Path;
use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn load_json(path: &Path) -> serde_json::Value {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("Invalid JSON in {}: {}", path.display(), e))
}

#[test]
fn normalization_report_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_universe_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute normalization generator");
    assert!(
        output.status.success(),
        "Normalization generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn normalization_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2vv.9"));
    assert!(data["universe_hash"].is_string());

    let summary = &data["summary"];
    for field in &[
        "total_symbols",
        "unique_symbols",
        "duplicates",
        "families",
        "native_implementation_pct",
        "unknown_action_count",
    ] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(summary["classifications"].is_object());
    assert!(summary["confidence_levels"].is_object());
    assert!(data["normalized_symbols"].is_array());
    assert!(data["family_statistics"].is_object());
    assert!(data["unknown_action_list"].is_array());
    assert!(data["classification_rules"].is_object());
}

#[test]
fn normalization_all_symbols_classified() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    assert!(symbols.len() >= 100, "Too few symbols: {}", symbols.len());

    let valid_classifications = ["native", "syscall-passthrough", "host-delegated"];
    for s in symbols {
        let name = s["symbol"].as_str().unwrap_or("?");
        let class = s["classification"].as_str().unwrap_or("unknown");
        assert!(
            valid_classifications.contains(&class),
            "Symbol {} has invalid classification: {}",
            name,
            class
        );
    }
}

#[test]
fn normalization_no_duplicates() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let dupes = data["summary"]["duplicates"].as_u64().unwrap();
    assert_eq!(dupes, 0, "Found {} duplicate symbols", dupes);

    // Also verify by checking names are unique
    let symbols = data["normalized_symbols"].as_array().unwrap();
    let mut names: Vec<&str> = symbols
        .iter()
        .map(|s| s["symbol"].as_str().unwrap_or(""))
        .collect();
    let total = names.len();
    names.sort();
    names.dedup();
    assert_eq!(total, names.len(), "Duplicate symbol names detected");
}

#[test]
fn normalization_families_populated() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let families = data["family_statistics"].as_object().unwrap();
    assert!(
        families.len() >= 10,
        "Only {} families (need >= 10)",
        families.len()
    );

    for (fam, stats) in families {
        let total = stats["total"].as_u64().unwrap();
        assert!(total > 0, "Family {} has 0 symbols", fam);
        let native = stats["native"].as_u64().unwrap();
        assert!(
            native <= total,
            "Family {} native count {} > total {}",
            fam,
            native,
            total
        );
    }
}

#[test]
fn normalization_reproducible() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data1 = load_json(&report_path);

    // Re-generate
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_universe_normalization.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute normalization generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["universe_hash"].as_str(),
        data2["universe_hash"].as_str(),
        "Universe hash changed on regeneration — not reproducible"
    );
}

#[test]
fn normalization_priority_scores_reasonable() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_universe_normalization.v1.json");
    let data = load_json(&report_path);

    let symbols = data["normalized_symbols"].as_array().unwrap();
    for s in symbols {
        let name = s["symbol"].as_str().unwrap_or("?");
        let score = s["priority_score"].as_i64().unwrap();
        // Scores should be within reasonable bounds
        assert!(
            (-100..=1000).contains(&score),
            "Symbol {} has unreasonable priority score: {}",
            name,
            score
        );
    }

    // Hotpath symbols should have higher scores than coldpath
    let hotpath_avg: f64 = {
        let hp: Vec<i64> = symbols
            .iter()
            .filter(|s| s["perf_class"].as_str() == Some("strict_hotpath"))
            .map(|s| s["priority_score"].as_i64().unwrap())
            .collect();
        if hp.is_empty() {
            0.0
        } else {
            hp.iter().sum::<i64>() as f64 / hp.len() as f64
        }
    };
    let coldpath_avg: f64 = {
        let cp: Vec<i64> = symbols
            .iter()
            .filter(|s| s["perf_class"].as_str() == Some("coldpath"))
            .map(|s| s["priority_score"].as_i64().unwrap())
            .collect();
        if cp.is_empty() {
            0.0
        } else {
            cp.iter().sum::<i64>() as f64 / cp.len() as f64
        }
    };
    assert!(
        hotpath_avg > coldpath_avg,
        "Hotpath avg score ({}) should be > coldpath avg ({})",
        hotpath_avg,
        coldpath_avg
    );
}
