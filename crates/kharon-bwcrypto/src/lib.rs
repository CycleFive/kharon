//! Bitwarden client-side crypto (REQ-CRY-*), implemented from the
//! Bitwarden whitepaper with RustCrypto primitives (SPEC §3.1).

pub mod encstring;

pub use encstring::{EncError, EncString, SymmetricKey};
