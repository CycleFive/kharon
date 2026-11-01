//! `Secret<T>`: the wrapper for secret-bearing values (REQ-API-005).
//!
//! Built on [`zeroize::Zeroizing`], which the rest of the crate already
//! uses for key material, so the contents are wiped on drop. On top of
//! that, `Secret` deliberately implements none of `Debug`, `Display`,
//! `Serialize` or `Clone` (SPEC §5, REQ-API-005): a secret cannot be
//! logged, formatted, serialized into an API response, or silently
//! duplicated. The only way to the contents is the explicit, greppable
//! [`Secret::expose_secret`].
//!
//! No `PartialEq` is provided: nothing compares secrets today. If that
//! changes, add a constant-time comparison (e.g. `subtle`), never a
//! derived one.

use zeroize::{Zeroize, Zeroizing};

/// A secret value, zeroized on drop, with no `Debug`/`Display`/
/// `Serialize`/`Clone`.
///
/// ```
/// use kharon_bwcrypto::Secret;
/// let s = Secret::new(String::from("hunter2"));
/// assert_eq!(s.expose_secret(), "hunter2");
/// ```
///
/// ```compile_fail
/// let s = kharon_bwcrypto::Secret::new(String::from("hunter2"));
/// println!("{:?}", s); // no Debug
/// ```
pub struct Secret<T: Zeroize>(Zeroizing<T>);

impl<T: Zeroize> Secret<T> {
    /// Wrap a value. The caller's original binding is moved in.
    pub fn new(value: T) -> Self {
        Self(Zeroizing::new(value))
    }

    /// Borrow the secret contents. Every call site is a place where
    /// plaintext is handled; keep them few and reviewable.
    pub fn expose_secret(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> From<Zeroizing<T>> for Secret<T> {
    /// Adopt an existing zeroizing buffer (e.g. a decrypted field from
    /// [`crate::decrypt_item_field`]) without copying it.
    fn from(value: Zeroizing<T>) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn req_api_005_expose_secret_returns_contents() {
        let s = Secret::new(String::from("canary-1234"));
        assert_eq!(s.expose_secret(), "canary-1234");
        let v: Secret<Vec<u8>> = Zeroizing::new(vec![1, 2, 3]).into();
        assert_eq!(v.expose_secret(), &[1, 2, 3]);
    }

    #[test]
    fn req_api_005_inner_value_is_zeroized() {
        // Zeroize the inner value directly (what Drop does) and check
        // it is wiped, without reading freed memory.
        let mut z = Zeroizing::new(vec![0xAAu8; 32]);
        z.zeroize();
        assert!(z.is_empty());
        let mut s = Secret::new([0xAAu8; 32]);
        s.0.zeroize();
        assert_eq!(s.expose_secret(), &[0u8; 32]);
    }
}
