//! Fixture execution adapter shared by harness tooling.
//!
//! This crate provides a stable seam so the harness does not directly depend on
//! legacy migration crates while preserving exact execution semantics.

pub use frankenlibc_conformance::{DifferentialExecution, execute_fixture_case};
