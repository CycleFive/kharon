//! kharon broker daemon library.
//!
//! The daemon binary itself is still a placeholder (see issue #4); this crate
//! exists so that daemon subsystems are developed and tested as a library.
#![forbid(unsafe_code)]

pub mod audit;
pub mod origin;
