//! Transparent Safety Membrane (TSM) primitives.

mod membrane;
mod registry;
mod state;

pub use membrane::{CopyDecision, decide_copy};
pub use registry::{
    AllocationMeta, PointerFacts, PointerRegistry, classify_pointer, global_registry,
};
pub use state::{CopyDisposition, RepairReason, TemporalState};
