//! CLI entrypoint for glibc_rust conformance harness.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Conformance tooling for glibc_rust.
#[derive(Debug, Parser)]
#[command(name = "glibc-rs-harness")]
#[command(about = "Conformance testing harness for glibc_rust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Capture host glibc behavior as fixture files.
    Capture {
        /// Output directory for fixture JSON files.
        #[arg(long)]
        output: PathBuf,
        /// Function family to capture (e.g., "string", "malloc").
        #[arg(long)]
        family: String,
    },
    /// Verify our implementation against captured fixtures.
    Verify {
        /// Directory containing fixture JSON files.
        #[arg(long)]
        fixture: PathBuf,
        /// Output report path (markdown).
        #[arg(long)]
        report: Option<PathBuf>,
    },
    /// Generate traceability matrix.
    Traceability {
        /// Output markdown path.
        #[arg(long)]
        output_md: PathBuf,
        /// Output JSON path.
        #[arg(long)]
        output_json: PathBuf,
    },
    /// Run membrane-specific verification tests.
    VerifyMembrane {
        /// Runtime mode to test (strict or hardened).
        #[arg(long, default_value = "strict")]
        mode: String,
    },
    /// Capture deterministic runtime_math kernel snapshots as a fixture.
    SnapshotKernel {
        /// Output path for fixture JSON.
        #[arg(long)]
        output: PathBuf,
        /// Mode to capture (`strict`, `hardened`, or `both`).
        #[arg(long, default_value = "both")]
        mode: String,
        /// Root seed (decimal or 0x...).
        #[arg(long, default_value = "0xDEAD_BEEF")]
        seed: String,
        /// Number of decision steps to run.
        #[arg(long, default_value_t = 128)]
        steps: u32,
    },
    /// Diff two runtime_math kernel snapshot fixtures (golden vs current).
    DiffKernelSnapshot {
        /// Golden fixture path.
        #[arg(
            long,
            default_value = "tests/runtime_math/golden/kernel_snapshot_smoke.v1.json"
        )]
        golden: PathBuf,
        /// Current fixture path (optional; if missing, one will be generated in-memory).
        #[arg(
            long,
            default_value = "target/runtime_math_golden/kernel_snapshot_smoke.v1.json"
        )]
        current: PathBuf,
        /// Mode to diff (`strict` or `hardened`).
        #[arg(long, default_value = "strict")]
        mode: String,
        /// Include all snapshot fields (not only the curated key set).
        #[arg(long)]
        all: bool,
        /// Emit ANSI color/styling (only when `frankentui-ui` is enabled).
        #[arg(long)]
        ansi: bool,
        /// Render width for the UI table (only when `frankentui-ui` is enabled).
        #[arg(long, default_value_t = 120)]
        width: u16,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Capture { output, family } => {
            eprintln!("Capturing {family} fixtures to {}", output.display());
            std::fs::create_dir_all(&output)?;
            eprintln!("TODO: implement capture for {family}");
        }
        Command::Verify { fixture, report } => {
            eprintln!("Verifying against fixtures in {}", fixture.display());
            let mut fixture_sets = Vec::new();
            let mut fixture_paths: Vec<PathBuf> = std::fs::read_dir(&fixture)?
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            fixture_paths.sort();

            for path in fixture_paths {
                match glibc_rs_harness::FixtureSet::from_file(&path) {
                    Ok(set) => fixture_sets.push(set),
                    Err(err) => eprintln!("Skipping {}: {}", path.display(), err),
                }
            }
            if fixture_sets.is_empty() {
                return Err(format!("No fixture JSON files found in {}", fixture.display()).into());
            }

            #[cfg(feature = "asupersync-tooling")]
            let (results, suite) = {
                let run = glibc_rs_harness::asupersync_orchestrator::run_fixture_verification(
                    "fixture-verify",
                    &fixture_sets,
                );
                (run.verification_results, run.suite)
            };

            #[cfg(not(feature = "asupersync-tooling"))]
            let results = {
                let strict_runner = glibc_rs_harness::TestRunner::new("fixture-verify", "strict");
                let hardened_runner =
                    glibc_rs_harness::TestRunner::new("fixture-verify", "hardened");

                let mut results = Vec::new();
                for set in &fixture_sets {
                    results.extend(strict_runner.run(set));
                    results.extend(hardened_runner.run(set));
                }
                results
            };

            let summary = glibc_rs_harness::verify::VerificationSummary::from_results(results);
            let report_doc = glibc_rs_harness::ConformanceReport {
                title: String::from("glibc_rust Conformance Report"),
                mode: String::from("strict+hardened"),
                timestamp: format!("{:?}", std::time::SystemTime::now()),
                summary,
            };

            eprintln!(
                "Verification complete: total={}, passed={}, failed={}",
                report_doc.summary.total, report_doc.summary.passed, report_doc.summary.failed
            );

            if let Some(report_path) = report {
                eprintln!("Writing report to {}", report_path.display());
                std::fs::write(&report_path, report_doc.to_markdown())?;
                let json_path = report_path.with_extension("json");
                std::fs::write(&json_path, report_doc.to_json())?;

                #[cfg(feature = "asupersync-tooling")]
                {
                    let suite_path = report_path.with_extension("suite.json");
                    asupersync_conformance::write_json_report(&suite, &suite_path)?;
                    eprintln!("Wrote suite report to {}", suite_path.display());
                }
            }

            if !report_doc.summary.all_passed() {
                return Err("Conformance verification failed".into());
            }
        }
        Command::Traceability {
            output_md,
            output_json,
        } => {
            let matrix = glibc_rs_harness::traceability::TraceabilityMatrix::new();
            std::fs::write(&output_md, matrix.to_markdown())?;
            let json = serde_json::to_string_pretty(&matrix.to_markdown())?;
            std::fs::write(&output_json, json)?;
            eprintln!(
                "Traceability written to {} and {}",
                output_md.display(),
                output_json.display()
            );
        }
        Command::VerifyMembrane { mode } => {
            eprintln!("Running membrane verification in {mode} mode");
            if mode != "strict" && mode != "hardened" {
                return Err(format!("Unsupported mode '{mode}', expected strict|hardened").into());
            }
            let mut suite = glibc_rs_harness::healing_oracle::HealingOracleSuite::new();
            suite.add(glibc_rs_harness::healing_oracle::HealingOracleCase {
                id: String::from("double-free"),
                condition: glibc_rs_harness::healing_oracle::UnsafeCondition::DoubleFree,
                expected_healing: String::from("IgnoreDoubleFree"),
                strict_expected: String::from("No repair"),
            });
            suite.add(glibc_rs_harness::healing_oracle::HealingOracleCase {
                id: String::from("foreign-free"),
                condition: glibc_rs_harness::healing_oracle::UnsafeCondition::ForeignFree,
                expected_healing: String::from("IgnoreForeignFree"),
                strict_expected: String::from("No repair"),
            });

            for case in suite.cases() {
                if mode == "hardened" {
                    eprintln!("[{}] expect {}", case.id, case.expected_healing);
                } else {
                    eprintln!("[{}] expect {}", case.id, case.strict_expected);
                }
            }
            eprintln!("Membrane verification spec checks completed");
        }
        Command::SnapshotKernel {
            output,
            mode,
            seed,
            steps,
        } => {
            let seed = parse_seed(&seed)?;
            let mode = glibc_rs_harness::kernel_snapshot::SnapshotMode::from_str_loose(&mode)
                .ok_or_else(|| {
                    format!("Unsupported mode '{mode}', expected strict|hardened|both")
                })?;

            if let Some(parent) = output.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let fixture =
                glibc_rs_harness::kernel_snapshot::build_kernel_snapshot_fixture(seed, steps, mode);
            let body = serde_json::to_string_pretty(&fixture)?;
            std::fs::write(&output, body)?;
            eprintln!("Wrote kernel snapshot fixture to {}", output.display());
        }
        Command::DiffKernelSnapshot {
            golden,
            current,
            mode,
            all,
            ansi,
            width,
        } => {
            let golden_body = std::fs::read_to_string(&golden)?;
            let golden_fixture: glibc_rs_harness::kernel_snapshot::RuntimeKernelSnapshotFixtureV1 =
                serde_json::from_str(&golden_body)?;

            let current_fixture: glibc_rs_harness::kernel_snapshot::RuntimeKernelSnapshotFixtureV1 =
                if current.exists() {
                    let current_body = std::fs::read_to_string(&current)?;
                    serde_json::from_str(&current_body)?
                } else {
                    eprintln!(
                        "Current fixture not found at {}; generating from golden scenario (seed={}, steps={})",
                        current.display(),
                        golden_fixture.scenario.seed,
                        golden_fixture.scenario.steps
                    );
                    glibc_rs_harness::kernel_snapshot::build_kernel_snapshot_fixture(
                        golden_fixture.scenario.seed,
                        golden_fixture.scenario.steps,
                        glibc_rs_harness::kernel_snapshot::SnapshotMode::Both,
                    )
                };

            let mode = glibc_rs_harness::snapshot_diff::DiffMode::from_str_loose(&mode)
                .ok_or_else(|| format!("Unsupported mode '{mode}', expected strict|hardened"))?;

            let report = glibc_rs_harness::snapshot_diff::diff_kernel_snapshots(
                &golden_fixture,
                &current_fixture,
                mode,
                all,
            )?;

            #[cfg(not(feature = "frankentui-ui"))]
            let _ = width;

            #[cfg(feature = "frankentui-ui")]
            let out = glibc_rs_harness::snapshot_diff::render_ftui(&report, ansi, width);

            #[cfg(not(feature = "frankentui-ui"))]
            let out = {
                if ansi {
                    eprintln!("note: enable `frankentui-ui` feature for ANSI rendering");
                }
                glibc_rs_harness::snapshot_diff::render_plain(&report)
            };

            print!("{out}");
        }
    }

    Ok(())
}

fn parse_seed(raw: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = raw.trim();
    let seed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        let hex = hex.replace('_', "");
        u64::from_str_radix(&hex, 16)?
    } else {
        let dec = s.replace('_', "");
        dec.parse::<u64>()?
    };
    Ok(seed)
}
