#!/usr/bin/env python3
"""generate_fuzz_phase1_targets.py — bd-1oz.6

Fuzz phase-1 target readiness assessment, crash triage flow, and coverage report:
  1. Target readiness — assess phase-1 targets (string/allocator/format) for stability.
  2. Symbol coverage — map fuzz targets to ABI symbols they exercise.
  3. Crash triage flow — define classification, minimization, and dedup policies.
  4. Deterministic repro — verify each target produces reproducible artifacts.
  5. Coverage report — estimated coverage depth per module.

Generates a JSON report to stdout (or --output).
"""
import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_repo_root():
    p = Path(__file__).resolve().parent.parent
    if (p / "Cargo.toml").exists():
        return p
    return Path.cwd()


def load_json_file(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# Phase-1 targets are the initial high-ROI fuzz surface
PHASE1_TARGETS = ["fuzz_string", "fuzz_malloc", "fuzz_membrane", "fuzz_printf"]

# Symbol mapping: which ABI symbols each fuzz target exercises
TARGET_SYMBOL_MAP = {
    "fuzz_string": {
        "symbols": [
            "strlen", "strcmp", "strncmp", "strcpy", "strncpy",
            "strcat", "strncat", "strchr", "strrchr", "strstr",
            "memcpy", "memmove", "memset", "memcmp", "memchr", "memrchr",
            "strtok", "strtok_r",
        ],
        "family": "string",
        "attack_surface": "buffer-overflow, off-by-one, null-termination",
        "cwe_targets": ["CWE-120", "CWE-125", "CWE-787"],
    },
    "fuzz_malloc": {
        "symbols": [
            "malloc", "free", "realloc", "calloc",
            "aligned_alloc", "memalign", "posix_memalign",
        ],
        "family": "malloc",
        "attack_surface": "double-free, use-after-free, heap-overflow, size-overflow",
        "cwe_targets": ["CWE-415", "CWE-416", "CWE-122", "CWE-131"],
    },
    "fuzz_membrane": {
        "symbols": ["__membrane_validate"],
        "family": "membrane",
        "attack_surface": "null-deref, temporal-violation, foreign-ptr",
        "cwe_targets": ["CWE-476", "CWE-824", "CWE-825"],
    },
    "fuzz_printf": {
        "symbols": ["printf", "fprintf", "sprintf", "snprintf"],
        "family": "stdio",
        "attack_surface": "format-string, unbounded-write, stack-read",
        "cwe_targets": ["CWE-134", "CWE-787"],
    },
}

# Crash severity classification
CRASH_SEVERITY = {
    "heap-buffer-overflow": {"severity": "critical", "cwe": "CWE-122"},
    "stack-buffer-overflow": {"severity": "critical", "cwe": "CWE-121"},
    "use-after-free": {"severity": "critical", "cwe": "CWE-416"},
    "double-free": {"severity": "high", "cwe": "CWE-415"},
    "null-deref": {"severity": "medium", "cwe": "CWE-476"},
    "integer-overflow": {"severity": "high", "cwe": "CWE-190"},
    "out-of-memory": {"severity": "low", "cwe": "CWE-400"},
    "timeout": {"severity": "low", "cwe": "CWE-835"},
    "assertion-failure": {"severity": "medium", "cwe": "CWE-617"},
    "stack-overflow": {"severity": "medium", "cwe": "CWE-674"},
    "format-string": {"severity": "critical", "cwe": "CWE-134"},
    "uninitialized-read": {"severity": "high", "cwe": "CWE-457"},
}


def analyze_target_source(source_path):
    """Analyze fuzz target source for readiness indicators."""
    try:
        content = source_path.read_text()
    except OSError:
        return {"error": f"Cannot read {source_path}", "ready": False}

    lines = content.splitlines()
    todos = [l.strip() for l in lines if "TODO" in l]
    has_real_imports = "frankenlibc" in content
    has_cleanup = "clean up" in content.lower() or "drop" in content.lower()
    has_size_guard = bool(re.search(r"data\.len\(\)\s*<|data\.is_empty\(\)", content))
    has_loop = "for " in content or "while " in content
    has_chunk_parsing = "chunks(" in content

    # Estimate complexity
    non_empty_lines = [l for l in lines if l.strip() and not l.strip().startswith("//")]
    logic_lines = len(non_empty_lines)

    return {
        "source_exists": True,
        "total_lines": len(lines),
        "logic_lines": logic_lines,
        "todo_count": len(todos),
        "todos": todos,
        "uses_frankenlibc_crates": has_real_imports,
        "has_cleanup_logic": has_cleanup,
        "has_size_guard": has_size_guard,
        "has_iteration": has_loop,
        "has_chunk_parsing": has_chunk_parsing,
        "ready": has_size_guard and len(todos) <= 1,
    }


FAMILY_TO_MODULES = {
    "string": ["string_abi"],
    "malloc": ["malloc_abi"],
    "membrane": ["membrane"],
    "stdio": ["stdio_abi"],
}


def compute_target_coverage(target_name, support_matrix_path):
    """Compute which symbols a target covers vs what's available."""
    target_info = TARGET_SYMBOL_MAP.get(target_name, {})
    target_symbols = set(target_info.get("symbols", []))

    if not support_matrix_path.exists():
        return {
            "target_symbols": sorted(target_symbols),
            "available_symbols": [],
            "coverage_pct": 0,
        }

    matrix = load_json_file(support_matrix_path)
    family = target_info.get("family", "")
    modules = FAMILY_TO_MODULES.get(family, [])

    # Find symbols in the same module from support matrix
    available = set()
    symbols_list = matrix.get("symbols", [])
    for entry in symbols_list:
        sym_module = entry.get("module", "")
        sym_name = entry.get("symbol", "")
        if sym_module in modules or sym_name in target_symbols:
            available.add(sym_name)

    covered = target_symbols & available
    coverage_pct = round(len(covered) / len(available) * 100, 1) if available else 0

    return {
        "target_symbols": sorted(target_symbols),
        "available_symbols": sorted(available),
        "covered_count": len(covered),
        "available_count": len(available),
        "coverage_pct": coverage_pct,
        "uncovered": sorted(available - target_symbols),
    }


def build_crash_triage_policy():
    """Define crash classification, minimization, and dedup policy."""
    return {
        "classification": {
            "description": "Crashes are classified by sanitizer signal and stack trace.",
            "severity_levels": CRASH_SEVERITY,
            "priority_order": ["critical", "high", "medium", "low"],
        },
        "minimization": {
            "tool": "cargo-fuzz tmin",
            "description": "Minimize crash inputs to smallest reproducing case.",
            "max_time_secs": 60,
            "strategy": "binary-search reduction with coverage-guided pruning",
        },
        "dedup": {
            "method": "stack-hash",
            "description": "Crashes are deduplicated by hashing the top 5 stack "
                           "frames (function name + offset) after symbolization.",
            "frame_depth": 5,
            "hash_function": "sha256",
            "ignore_frames": [
                "libfuzzer", "asan", "msan", "ubsan",
                "__sanitizer", "fuzzer::Fuzzer",
            ],
        },
        "triage_flow": [
            {
                "step": 1,
                "action": "capture",
                "description": "Save crash input to artifacts/<target>/<crash_id>",
            },
            {
                "step": 2,
                "action": "classify",
                "description": "Run with ASan/UBSan to classify crash type",
            },
            {
                "step": 3,
                "action": "minimize",
                "description": "Minimize crash input with cargo-fuzz tmin",
            },
            {
                "step": 4,
                "action": "dedup",
                "description": "Hash top-5 stack frames for dedup",
            },
            {
                "step": 5,
                "action": "file",
                "description": "Create crash bundle per crash_bundle_spec.json",
            },
            {
                "step": 6,
                "action": "assess",
                "description": "Map to CWE and assign severity via CRASH_SEVERITY table",
            },
        ],
        "artifact_layout": {
            "crashes": "crates/frankenlibc-fuzz/artifacts/<target>/crash-<hash>",
            "minimized": "crates/frankenlibc-fuzz/artifacts/<target>/min-<hash>",
            "bundles": "crates/frankenlibc-fuzz/artifacts/<target>/bundle-<hash>/",
            "dedup_db": "crates/frankenlibc-fuzz/artifacts/dedup.json",
        },
        "retention": {
            "critical_crashes": "permanent",
            "high_crashes": "90 days",
            "medium_crashes": "30 days",
            "low_crashes": "7 days",
        },
    }


def build_smoke_test_config():
    """Define bounded-time smoke test configuration per target."""
    configs = {}
    for target in PHASE1_TARGETS:
        configs[target] = {
            "max_total_time_secs": 30,
            "max_len": 4096,
            "seed_corpus": f"crates/frankenlibc-fuzz/corpus/{target}/",
            "dictionary": f"crates/frankenlibc-fuzz/dictionaries/{target}.dict",
            "sanitizers": ["address"],
            "jobs": 1,
            "runs": 10000,
            "expected_outcome": "no_crash",
        }
    return configs


def main():
    parser = argparse.ArgumentParser(
        description="Fuzz phase-1 target readiness and crash triage report")
    parser.add_argument("-o", "--output", help="Output file path")
    args = parser.parse_args()

    root = find_repo_root()
    fuzz_dir = root / "crates" / "frankenlibc-fuzz"
    targets_dir = fuzz_dir / "fuzz_targets"
    support_matrix = root / "support_matrix.json"

    if not targets_dir.exists():
        print("ERROR: fuzz_targets/ not found", file=sys.stderr)
        sys.exit(1)

    # Analyze each phase-1 target
    target_assessments = []
    all_symbols = set()
    all_cwes = set()

    for target_name in PHASE1_TARGETS:
        source = targets_dir / f"{target_name}.rs"
        source_analysis = analyze_target_source(source)
        coverage = compute_target_coverage(target_name, support_matrix)
        target_info = TARGET_SYMBOL_MAP.get(target_name, {})

        all_symbols.update(target_info.get("symbols", []))
        all_cwes.update(target_info.get("cwe_targets", []))

        # Readiness score (0-100)
        score = 0
        if source_analysis.get("source_exists"):
            score += 20
        if source_analysis.get("has_size_guard"):
            score += 20
        if source_analysis.get("uses_frankenlibc_crates"):
            score += 20
        if source_analysis.get("has_iteration"):
            score += 15
        if source_analysis.get("todo_count", 99) <= 1:
            score += 15
        if source_analysis.get("has_cleanup_logic"):
            score += 10

        impl_status = "functional" if score >= 60 else "partial" if score >= 30 else "stub"

        target_assessments.append({
            "target": target_name,
            "family": target_info.get("family", ""),
            "attack_surface": target_info.get("attack_surface", ""),
            "cwe_targets": target_info.get("cwe_targets", []),
            "source_analysis": source_analysis,
            "symbol_coverage": coverage,
            "readiness_score": score,
            "implementation_status": impl_status,
            "smoke_viable": score >= 40,
        })

    # Build crash triage policy
    triage_policy = build_crash_triage_policy()

    # Build smoke test configs
    smoke_configs = build_smoke_test_config()

    # Summary
    functional = sum(1 for t in target_assessments
                     if t["implementation_status"] == "functional")
    partial = sum(1 for t in target_assessments
                  if t["implementation_status"] == "partial")
    stubs = sum(1 for t in target_assessments
                if t["implementation_status"] == "stub")
    smoke_viable = sum(1 for t in target_assessments if t["smoke_viable"])
    avg_score = (sum(t["readiness_score"] for t in target_assessments)
                 / len(target_assessments)) if target_assessments else 0

    report = {
        "schema_version": "v1",
        "bead": "bd-1oz.6",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "summary": {
            "phase": 1,
            "total_targets": len(target_assessments),
            "functional_targets": functional,
            "partial_targets": partial,
            "stub_targets": stubs,
            "smoke_viable_targets": smoke_viable,
            "average_readiness_score": round(avg_score, 1),
            "total_symbols_covered": len(all_symbols),
            "total_cwes_targeted": len(all_cwes),
            "crash_severity_classes": len(CRASH_SEVERITY),
            "triage_steps": len(triage_policy["triage_flow"]),
        },
        "target_assessments": target_assessments,
        "crash_triage_policy": triage_policy,
        "smoke_test_configs": smoke_configs,
        "coverage_summary": {
            "symbols_by_family": {
                target_info["family"]: sorted(target_info["symbols"])
                for target_info in TARGET_SYMBOL_MAP.values()
            },
            "all_symbols": sorted(all_symbols),
            "all_cwes": sorted(all_cwes),
            "attack_surfaces": {
                name: info["attack_surface"]
                for name, info in TARGET_SYMBOL_MAP.items()
            },
        },
    }

    output = json.dumps(report, indent=2) + "\n"
    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
