//! Teach mode, daemon side: the per-broker registry of imported login methods (#382).

pub mod registry;

pub use registry::{
    Checked, EditRefusal, Entry, ImportFlags, ImportRefusal, LastResult, Recorded, Stale,
    TeachRegistry, WithHook, site_key,
};
