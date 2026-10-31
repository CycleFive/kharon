//! Bitwarden client-side crypto (REQ-CRY-*), implemented from the
//! Bitwarden whitepaper with RustCrypto primitives (SPEC §3.1).

pub mod encstring;
pub mod kdf;
pub mod keys;

pub use encstring::{EncError, EncString, SymmetricKey};
pub use kdf::{Kdf, KdfError, MasterKey, derive_master_key};
pub use keys::{
    OrgKeyUnwrapper, decrypt_item_field, unwrap_cipher_key, unwrap_private_key, unwrap_user_key,
};
