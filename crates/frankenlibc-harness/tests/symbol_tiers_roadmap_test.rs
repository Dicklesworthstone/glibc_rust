// symbol_tiers_roadmap_test.rs — bd-2vv.10
// Integration tests for trace-weighted symbol tiers and family wave roadmap.

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
fn tiers_roadmap_generates_successfully() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_tiers_roadmap.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute tiers roadmap generator");
    assert!(
        output.status.success(),
        "Tiers roadmap generator failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report_path.exists());
}

#[test]
fn tiers_roadmap_schema_complete() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data = load_json(&report_path);

    assert_eq!(data["schema_version"].as_str(), Some("v1"));
    assert_eq!(data["bead"].as_str(), Some("bd-2vv.10"));
    assert!(data["roadmap_hash"].is_string());

    let summary = &data["summary"];
    for field in &["total_symbols", "wave_count", "overall_native_pct"] {
        assert!(!summary[field].is_null(), "Missing summary field: {field}");
    }
    assert!(summary["tier_counts"].is_object());
    assert!(data["tiered_symbols"].is_array());
    assert!(data["wave_roadmap"].is_object());
    assert!(data["family_readiness"].is_object());
    assert!(data["wave_acceptance_checklist"].is_array());
}

#[test]
fn tiers_correct_distribution() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data = load_json(&report_path);

    let tier_counts = &data["summary"]["tier_counts"];
    let top50 = tier_counts["top50"].as_u64().unwrap();
    assert_eq!(top50, 50, "Top50 tier should have exactly 50 symbols");

    // Verify all symbols have valid tiers
    let symbols = data["tiered_symbols"].as_array().unwrap();
    let valid_tiers = ["top50", "top100", "top200", "all"];
    for s in symbols {
        let tier = s["tier"].as_str().unwrap_or("?");
        assert!(
            valid_tiers.contains(&tier),
            "Symbol {} has invalid tier: {}",
            s["symbol"].as_str().unwrap_or("?"),
            tier
        );
    }
}

#[test]
fn waves_cover_all_symbols() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data = load_json(&report_path);

    let total = data["summary"]["total_symbols"].as_u64().unwrap();
    let waves = data["wave_roadmap"].as_object().unwrap();

    let wave_total: u64 = waves
        .values()
        .map(|w| w["total_symbols"].as_u64().unwrap())
        .sum();

    assert_eq!(
        wave_total, total,
        "Wave symbol total {} != universe total {}",
        wave_total, total
    );

    // Each wave must have a name and description
    for (num, wave) in waves {
        assert!(wave["name"].is_string(), "Wave {} missing name", num);
        assert!(
            wave["description"].is_string(),
            "Wave {} missing description",
            num
        );
    }
}

#[test]
fn family_readiness_populated() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data = load_json(&report_path);

    let families = data["family_readiness"].as_object().unwrap();
    assert!(
        families.len() >= 10,
        "Only {} families (need >= 10)",
        families.len()
    );

    let valid_readiness = ["complete", "in-progress", "planned"];
    for (fam, info) in families {
        let readiness = info["readiness"].as_str().unwrap_or("?");
        assert!(
            valid_readiness.contains(&readiness),
            "Family {} has invalid readiness: {}",
            fam,
            readiness
        );
        let total = info["total"].as_u64().unwrap();
        assert!(total > 0, "Family {} has 0 symbols", fam);
    }
}

#[test]
fn acceptance_checklist_has_mandatory_items() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data = load_json(&report_path);

    let checklist = data["wave_acceptance_checklist"].as_array().unwrap();
    let mandatory: Vec<_> = checklist
        .iter()
        .filter(|c| c["mandatory"].as_bool().unwrap_or(false))
        .collect();

    assert!(
        mandatory.len() >= 3,
        "Only {} mandatory checklist items (need >= 3)",
        mandatory.len()
    );

    for item in &mandatory {
        assert!(
            item["requirement"].is_string(),
            "Checklist item missing requirement field"
        );
        assert!(
            item["description"].is_string(),
            "Checklist item missing description"
        );
    }
}

#[test]
fn tiers_roadmap_reproducible() {
    let root = repo_root();
    let report_path = root.join("tests/conformance/symbol_tiers_roadmap.v1.json");
    let data1 = load_json(&report_path);

    let output = Command::new("python3")
        .args([
            root.join("scripts/generate_symbol_tiers_roadmap.py")
                .to_str()
                .unwrap(),
            "-o",
            report_path.to_str().unwrap(),
        ])
        .current_dir(&root)
        .output()
        .expect("failed to execute generator");
    assert!(output.status.success());

    let data2 = load_json(&report_path);
    assert_eq!(
        data1["roadmap_hash"].as_str(),
        data2["roadmap_hash"].as_str(),
        "Roadmap hash changed on regeneration — not reproducible"
    );
}
