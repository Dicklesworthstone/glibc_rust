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
            if let Some(report_path) = report {
                eprintln!("Report will be written to {}", report_path.display());
            }
            eprintln!("TODO: implement verification");
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
            eprintln!("TODO: implement membrane verification");
        }
    }

    Ok(())
}
