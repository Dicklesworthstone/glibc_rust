//! Spec section mapping and traceability matrix.
//!
//! Maps every test case to POSIX/C11 spec sections and TSM policy sections.

use serde::{Deserialize, Serialize};

/// A traceability entry mapping a test to spec requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceabilityEntry {
    /// Test case identifier.
    pub test_id: String,
    /// POSIX/C11 spec section (e.g., "POSIX.1-2017 memcpy").
    pub spec_section: String,
    /// TSM policy section (e.g., "TSM-COPY-1: bounds clamping").
    pub tsm_section: Option<String>,
    /// Requirement category.
    pub category: String,
    /// Brief description.
    pub description: String,
}

/// Traceability matrix builder.
#[derive(Debug, Default)]
pub struct TraceabilityMatrix {
    entries: Vec<TraceabilityEntry>,
}

impl TraceabilityMatrix {
    /// Create a new empty matrix.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a traceability entry.
    pub fn add(&mut self, entry: TraceabilityEntry) -> &mut Self {
        self.entries.push(entry);
        self
    }

    /// Build with asupersync conformance integration.
    #[cfg(feature = "asupersync-tooling")]
    pub fn build_with_asupersync(&self) -> (String, String) {
        use asupersync_conformance::TraceabilityMatrixBuilder;

        let mut builder = TraceabilityMatrixBuilder::new();
        for entry in &self.entries {
            builder = builder.requirement_with_category(
                &entry.test_id,
                &entry.description,
                &entry.category,
            );
        }
        let mut matrix = builder.build();
        let markdown = matrix.to_markdown();
        let json = matrix
            .to_json()
            .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"));
        (markdown, json)
    }

    /// Render as markdown (fallback without asupersync).
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# Traceability Matrix\n\n");
        out.push_str("| Test | Spec | TSM | Category |\n");
        out.push_str("|------|------|-----|----------|\n");
        for e in &self.entries {
            let tsm = e.tsm_section.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                e.test_id, e.spec_section, tsm, e.category
            ));
        }
        out
    }

    /// Entries count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the matrix is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
