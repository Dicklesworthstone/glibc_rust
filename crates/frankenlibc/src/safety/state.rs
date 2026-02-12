//! Core membrane state types.

/// Temporal state of a tracked region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalState {
    /// Region has no known metadata.
    Unknown,
    /// Region is currently live.
    Valid,
    /// Region has been freed.
    Freed,
    /// Region has been quarantined due to suspicious behavior.
    Quarantined,
}

/// Copy operation disposition selected by the membrane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyDisposition {
    /// Requested operation is allowed as-is.
    Allow,
    /// Requested operation is repaired (for example, clamped length).
    Repair,
    /// Requested operation is denied.
    Deny,
}

/// Explanation for repair/deny behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairReason {
    /// No remediation required.
    None,
    /// Length was clamped to fit known region bounds.
    LengthClamp,
    /// Operation denied because pointer state was non-live.
    NonLivePointer,
    /// Operation denied because pointer facts were unusable.
    InvalidPointerFacts,
}
