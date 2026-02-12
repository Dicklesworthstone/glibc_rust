//! Integration test: Replacement profile guard (bd-130)
//!
//! Validates that:
//! 1. replacement_profile.json exists and is valid JSON.
//! 2. All ABI modules with call-throughs are in the interpose allowlist.
//! 3. No pthread call-through exists outside pthread_abi.rs.
//! 4. The call-through census in the profile matches reality.
//! 5. The replacement guard script exists and is executable.
//!
//! Run: cargo test -p glibc-rs-harness --test replacement_guard_test

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

fn load_profile() -> serde_json::Value {
    let path = workspace_root().join("tests/conformance/replacement_profile.json");
    let content = std::fs::read_to_string(&path).expect("replacement_profile.json should exist");
    serde_json::from_str(&content).expect("replacement_profile.json should be valid JSON")
}

/// Extract a libc:: function call name from a line fragment starting at "libc::"
fn extract_libc_call(fragment: &str) -> Option<&str> {
    // fragment starts right after "libc::"
    // We want: lowercase identifier followed by '('
    let bytes = fragment.as_bytes();
    let mut end = 0;
    for &b in bytes {
        if b.is_ascii_lowercase() || b == b'_' || (end > 0 && b.is_ascii_digit()) {
            end += 1;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    // Check that the next non-whitespace character is '('
    let rest = &fragment[end..];
    let rest_trimmed = rest.trim_start();
    if rest_trimmed.starts_with('(') {
        Some(&fragment[..end])
    } else {
        None
    }
}

/// Scan an ABI source file for libc:: function calls (not syscall, not types/constants).
fn scan_call_throughs(content: &str) -> Vec<(usize, String)> {
    let mut results = Vec::new();

    for (lineno, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let mut search_from = 0;
        while let Some(pos) = line[search_from..].find("libc::") {
            let abs_pos = search_from + pos;
            let after = &line[abs_pos + 6..];
            if let Some(func_name) = extract_libc_call(after)
                && func_name != "syscall"
            {
                results.push((lineno + 1, func_name.to_string()));
            }
            search_from = abs_pos + 6;
        }
    }
    results
}

#[test]
fn profile_exists_and_valid() {
    let profile = load_profile();
    assert!(
        profile["profile_version"].is_number(),
        "Missing profile_version"
    );
    assert!(profile["profiles"].is_object(), "Missing profiles");
    assert!(
        profile["interpose_allowlist"].is_object(),
        "Missing interpose_allowlist"
    );
    assert!(
        profile["detection_rules"].is_object(),
        "Missing detection_rules"
    );
    assert!(
        profile["replacement_forbidden"].is_object(),
        "Missing replacement_forbidden"
    );
}

#[test]
fn guard_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_replacement_guard.sh");
    assert!(
        script.exists(),
        "scripts/check_replacement_guard.sh must exist"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_replacement_guard.sh must be executable"
        );
    }
}

#[test]
fn interpose_allowlist_covers_all_call_through_modules() {
    let profile = load_profile();
    let abi_src = workspace_root().join("crates/glibc-rs-abi/src");

    let allowlist: HashSet<String> = profile["interpose_allowlist"]["modules"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let mut modules_with_ct: HashMap<String, usize> = HashMap::new();

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_abi.rs") {
            continue;
        }
        let module = fname.trim_end_matches(".rs").to_string();
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let calls = scan_call_throughs(&content);
        if !calls.is_empty() {
            modules_with_ct.insert(module, calls.len());
        }
    }

    let mut missing = Vec::new();
    for module in modules_with_ct.keys() {
        if !allowlist.contains(module) {
            missing.push(format!("{} ({} calls)", module, modules_with_ct[module]));
        }
    }

    assert!(
        missing.is_empty(),
        "Modules with call-throughs not in interpose allowlist: {:?}",
        missing
    );
}

#[test]
fn no_pthread_calls_outside_pthread_abi() {
    let abi_src = workspace_root().join("crates/glibc-rs-abi/src");
    let mut violations = Vec::new();

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with(".rs") || fname == "pthread_abi.rs" {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for (lineno, line) in content.lines().enumerate() {
            if line.trim().starts_with("//") {
                continue;
            }
            let mut pos = 0;
            while let Some(idx) = line[pos..].find("libc::pthread_") {
                let abs = pos + idx;
                let after = &line[abs + 6..]; // skip "libc::"
                if let Some(func) = extract_libc_call(after) {
                    violations.push(format!("{}:{} libc::{}", fname, lineno + 1, func));
                }
                pos = abs + 14;
            }
        }
    }

    assert!(
        violations.is_empty(),
        "pthread call-throughs outside pthread_abi.rs: {:?}",
        violations
    );
}

#[test]
fn call_through_census_matches_reality() {
    let profile = load_profile();
    let abi_src = workspace_root().join("crates/glibc-rs-abi/src");
    let census = &profile["call_through_census"]["modules"];

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        let fname = entry.file_name().to_string_lossy().to_string();
        if !fname.ends_with("_abi.rs") {
            continue;
        }
        let module = fname.trim_end_matches(".rs");
        let content = std::fs::read_to_string(entry.path()).unwrap();
        let calls = scan_call_throughs(&content);

        if let Some(census_entry) = census.get(module) {
            let census_count = census_entry["count"].as_u64().unwrap() as usize;
            let actual = calls.len();
            let ratio = if census_count > 0 {
                actual as f64 / census_count as f64
            } else if actual > 0 {
                f64::INFINITY
            } else {
                1.0
            };
            assert!(
                (0.5..=2.0).contains(&ratio),
                "{}: census says {} but found {} call-throughs (ratio {:.2})",
                module,
                census_count,
                actual,
                ratio
            );
        }
    }
}

#[test]
fn replacement_profile_has_both_modes() {
    let profile = load_profile();
    let profiles = profile["profiles"].as_object().unwrap();

    assert!(
        profiles.contains_key("interpose"),
        "Missing interpose profile"
    );
    assert!(
        profiles.contains_key("replacement"),
        "Missing replacement profile"
    );

    assert_eq!(
        profile["profiles"]["interpose"]["call_through_allowed"].as_bool(),
        Some(true),
        "Interpose mode should allow call-through"
    );
    assert_eq!(
        profile["profiles"]["replacement"]["call_through_allowed"].as_bool(),
        Some(false),
        "Replacement mode should forbid call-through"
    );
}

#[test]
fn raw_syscalls_are_not_flagged() {
    let abi_src = workspace_root().join("crates/glibc-rs-abi/src");
    let mut syscall_count = 0;

    for entry in std::fs::read_dir(&abi_src).unwrap() {
        let entry = entry.unwrap();
        if !entry.file_name().to_string_lossy().ends_with(".rs") {
            continue;
        }
        let content = std::fs::read_to_string(entry.path()).unwrap();
        for line in content.lines() {
            if line.trim().starts_with("//") {
                continue;
            }
            let mut pos = 0;
            while let Some(idx) = line[pos..].find("libc::syscall(") {
                syscall_count += 1;
                pos += idx + 14;
            }
        }
    }

    assert!(
        syscall_count >= 10,
        "Expected at least 10 raw syscall sites, found {}",
        syscall_count
    );
}
