//! Shared types between the method registry (`crate::teach`) and the fill
//! engine: what a lookup returns, and the record of how a fill used it.
//! Plain data only. Nothing here holds a value or page text.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use kharon_recording::{LoginMethod, Rung};

/// Where the fill engine finds a site's taught method.
pub trait MethodSource: Send + Sync + std::fmt::Debug {
    /// The site's method for the page at `live_url` (the URL the browser reported), if the registry holds one.
    fn lookup(&self, live_url: &str) -> Option<MethodLookup>;
}

#[derive(Debug, Clone)]
pub struct MethodLookup {
    pub domain: String,
    pub method: Arc<LoginMethod>,
    /// Step number (flat index) to owner-supplied selectors, tried first.
    pub overrides: BTreeMap<u32, Vec<String>>,
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodResult {
    Succeeded,
    Unconfirmed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodEnd {
    Stale,
    WrongPage,
    FieldNotRequested,
    Drift { step: u32 },
    NotReady { step: u32 },
    Filled(MethodResult),
    Other,
}

/// How one fill used a method; handed to `TeachRegistry::record_fill`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodUse {
    pub domain: String,
    pub rung: Rung,
    pub end: MethodEnd,
    pub selectors_ignored: bool,
    pub browser_product: Option<String>,
}

/// A write-once slot a fill path shares with its caller to report a [`MethodUse`].
#[derive(Debug, Clone, Default)]
pub struct MethodNote(Arc<OnceLock<MethodUse>>);

impl MethodNote {
    pub fn new() -> Self {
        Self::default()
    }

    /// First write wins; returns whether this call was the first.
    pub fn record(&self, used: MethodUse) -> bool {
        self.0.set(used).is_ok()
    }

    pub fn get(&self) -> Option<&MethodUse> {
        self.0.get()
    }
}
