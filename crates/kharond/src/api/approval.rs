//! One-time approval tokens for the ntfy channel (REQ-APR-004).
//!
//! When a grant request is created, the broker mints a pair of
//! single-use tokens for it — one approve, one deny. Each token is
//! 256 random bits, hex-encoded; the store keeps only the token's
//! SHA-256 digest as its key, so the store's own memory image does
//! not hand out live tokens to anyone who can read it back by digest
//! (the plaintext lives in a `Zeroizing` buffer inside the record,
//! for the owner surfaces that must render the action URLs, and is
//! never written to the audit log or any response other than the
//! owner's own channels).
//!
//! Semantics (SPEC §5, REQ-APR-004):
//! - a token is redeemable **once**; a replay is [`TokenGone::Used`];
//! - a token older than [`TOKEN_TTL`] (120 s, the grant-request
//!   timeout of REQ-APR-003) is [`TokenGone::Expired`];
//! - both map to HTTP 410 at the transport, as does an unknown token
//!   ([`TokenGone::Unknown`]) — the endpoint does not distinguish
//!   "never existed" from "gone" to an unauthenticated caller;
//! - looking a token up ([`ApprovalTokenStore::peek`], the GET
//!   confirm page) never consumes it and never mutates grant state.

use std::collections::HashMap;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// REQ-APR-004: an approval token lives 120 s (the same bound as the
/// grant request it decides, REQ-APR-003).
pub const TOKEN_TTL: Duration = Duration::from_secs(120);

/// What a one-time token decides when redeemed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalAction {
    /// Approve the request (a `once` grant, SPEC §5's ntfy rule).
    Approve,
    /// Deny the request.
    Deny,
}

impl ApprovalAction {
    /// URL path segment for this action (`/owner/approve/…`).
    pub fn path_segment(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// Why a token cannot be used. Every variant is HTTP 410 at the
/// `/owner/*` endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenGone {
    /// No such token (never minted, or its tombstone has aged out).
    Unknown,
    /// The token was already redeemed (replay).
    Used,
    /// The token is older than [`TOKEN_TTL`].
    Expired,
}

#[derive(Debug)]
struct TokenRecord {
    request_id: String,
    action: ApprovalAction,
    issued_at: Duration,
    used: bool,
    /// The plaintext token, for owner surfaces rendering the action
    /// URLs. Zeroized on drop; never logged.
    plaintext: Zeroizing<String>,
}

/// The broker's outstanding one-time approval tokens, keyed by
/// SHA-256 digest of the token text.
#[derive(Debug, Default)]
pub struct ApprovalTokenStore {
    records: HashMap<String, TokenRecord>,
}

fn digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

impl ApprovalTokenStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh 256-bit token deciding `action` for
    /// `request_id`. Returns the plaintext (the only copy that ever
    /// leaves the store is the one in the record and this return).
    pub fn mint(&mut self, request_id: &str, action: ApprovalAction, now: Duration) -> String {
        self.prune(now);
        let token = hex::encode(rand::random::<[u8; 32]>());
        self.records.insert(
            digest(&token),
            TokenRecord {
                request_id: request_id.to_owned(),
                action,
                issued_at: now,
                used: false,
                plaintext: Zeroizing::new(token.clone()),
            },
        );
        token
    }

    /// Look a token up without consuming it (the GET confirm page).
    /// Grant state is untouched either way.
    pub fn peek(&self, token: &str, now: Duration) -> Result<(String, ApprovalAction), TokenGone> {
        let rec = self.records.get(&digest(token)).ok_or(TokenGone::Unknown)?;
        if rec.used {
            return Err(TokenGone::Used);
        }
        if now.saturating_sub(rec.issued_at) > TOKEN_TTL {
            return Err(TokenGone::Expired);
        }
        Ok((rec.request_id.clone(), rec.action))
    }

    /// Consume a token: the first redemption succeeds and marks it
    /// used; any later one is [`TokenGone::Used`]. An expired token
    /// is refused without being marked used (its request is timing
    /// out on its own path, REQ-APR-003).
    pub fn redeem(
        &mut self,
        token: &str,
        now: Duration,
    ) -> Result<(String, ApprovalAction), TokenGone> {
        let key = digest(token);
        let rec = self.records.get_mut(&key).ok_or(TokenGone::Unknown)?;
        if rec.used {
            return Err(TokenGone::Used);
        }
        if now.saturating_sub(rec.issued_at) > TOKEN_TTL {
            return Err(TokenGone::Expired);
        }
        rec.used = true;
        Ok((rec.request_id.clone(), rec.action))
    }

    /// The live token pair for `request_id`, as URL paths
    /// (`/owner/approve/<token>`, `/owner/deny/<token>`), for the
    /// owner surfaces that render or send them. Tokens that are used
    /// or expired are omitted; a request with no live pair yields
    /// `None`.
    ///
    /// These paths are relative; the ntfy publisher (#128,
    /// [`super::notify`]) joins them onto the owner listener's
    /// address (`[owner_ui] listen`), which is where the routes are
    /// served (#136).
    pub fn paths_for(&self, request_id: &str, now: Duration) -> Option<(String, String)> {
        let mut approve = None;
        let mut deny = None;
        for rec in self.records.values() {
            if rec.request_id != request_id
                || rec.used
                || now.saturating_sub(rec.issued_at) > TOKEN_TTL
            {
                continue;
            }
            let path = format!(
                "/owner/{}/{}",
                rec.action.path_segment(),
                rec.plaintext.as_str()
            );
            match rec.action {
                ApprovalAction::Approve => approve = Some(path),
                ApprovalAction::Deny => deny = Some(path),
            }
        }
        Some((approve?, deny?))
    }

    /// Drop records (and replay tombstones) that can never be
    /// redeemed again: older than the TTL. Called on mint; peeks and
    /// redeems evaluate expiry per-record, so correctness never
    /// depends on pruning.
    fn prune(&mut self, now: Duration) {
        self.records
            .retain(|_, rec| now.saturating_sub(rec.issued_at) <= TOKEN_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: Duration = Duration::from_secs(1_000);

    #[test]
    fn req_apr_004_tokens_are_256_bit_and_distinct() {
        let mut store = ApprovalTokenStore::new();
        let a = store.mint("gr_1", ApprovalAction::Approve, T0);
        let d = store.mint("gr_1", ApprovalAction::Deny, T0);
        assert_eq!(a.len(), 64, "256 bits hex-encoded");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, d);
    }

    #[test]
    fn req_apr_004_replay_of_a_used_token_is_gone() {
        let mut store = ApprovalTokenStore::new();
        let tok = store.mint("gr_1", ApprovalAction::Approve, T0);
        assert_eq!(
            store.redeem(&tok, T0),
            Ok(("gr_1".to_owned(), ApprovalAction::Approve))
        );
        assert_eq!(store.redeem(&tok, T0), Err(TokenGone::Used));
        assert_eq!(store.peek(&tok, T0), Err(TokenGone::Used));
    }

    #[test]
    fn req_apr_004_token_older_than_120s_is_gone() {
        let mut store = ApprovalTokenStore::new();
        let tok = store.mint("gr_1", ApprovalAction::Deny, T0);
        let late = T0 + TOKEN_TTL + Duration::from_secs(1);
        assert_eq!(store.redeem(&tok, late), Err(TokenGone::Expired));
        assert_eq!(store.peek(&tok, late), Err(TokenGone::Expired));
        // Exactly at the bound the token still works.
        let tok2 = store.mint("gr_2", ApprovalAction::Deny, T0);
        assert!(store.redeem(&tok2, T0 + TOKEN_TTL).is_ok());
    }

    #[test]
    fn req_apr_004_peek_never_consumes() {
        let mut store = ApprovalTokenStore::new();
        let tok = store.mint("gr_1", ApprovalAction::Approve, T0);
        for _ in 0..3 {
            assert_eq!(
                store.peek(&tok, T0),
                Ok(("gr_1".to_owned(), ApprovalAction::Approve))
            );
        }
        assert!(store.redeem(&tok, T0).is_ok());
    }

    #[test]
    fn req_apr_004_unknown_token_is_gone() {
        let store = ApprovalTokenStore::new();
        assert_eq!(store.peek("deadbeef", T0), Err(TokenGone::Unknown));
    }
}
