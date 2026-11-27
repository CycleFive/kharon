//! API key type check (#403, SPEC §3.1).
//!
//! kharond syncs with the dedicated account's **personal** API key,
//! whose `client_id` is `user.<uuid>`. Bitwarden also issues an
//! organization API key (`organization.<uuid>`, Admin Console →
//! Settings → Organization info). It looks the same in a JSON file and
//! authenticates, but it reaches the Public API only and yields no
//! vault keys, so a broker configured with it can never sync. Mixing
//! the two up is the first footgun in #401.
//!
//! The type is read from the `client_id` prefix alone, with no network
//! call, so the check can run before anything else touches the key:
//! at startup ([`crate::config::Config::check_startup`], through
//! [`super::ApiKey::new`]) and on entry to `kharon setup` (#404). Both
//! call [`check_client_id`], so they refuse the same keys with the same
//! text.
//!
//! Messages are fixed text. They never echo the `client_id` or the
//! secret (REQ-API-006).

/// Where the personal key lives in the Bitwarden (or Vaultwarden) web
/// vault, signed in as the dedicated account. One literal, so every
/// message names the same fix.
macro_rules! personal_key_fix {
    () => {
        "sign in to the web vault as the dedicated kharon account and use its personal API key \
         (Settings > Security > Keys > View API key; client_id user.<uuid>), \
         not the organization's API key"
    };
}

/// What a `client_id` prefix says the key is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyType {
    /// `user.<id>`: the account's personal API key. The one kharond uses.
    Personal,
    /// `organization.<id>`: an organization API key (Public API only).
    Organization,
    /// Anything else: empty, `user.` with no id, another prefix, or no
    /// prefix at all.
    Malformed,
}

/// Why a `client_id` was refused. [`KeyTypeError::message`] is the
/// fixed, actionable text shown to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyTypeError {
    /// An `organization.` key.
    #[error("{}", Self::Organization.message())]
    Organization,
    /// The `client_id` is empty or whitespace.
    #[error("{}", Self::Empty.message())]
    Empty,
    /// `user.` with nothing after the prefix.
    #[error("{}", Self::MissingId.message())]
    MissingId,
    /// Any other prefix, or none.
    #[error("{}", Self::UnknownPrefix.message())]
    UnknownPrefix,
}

impl KeyTypeError {
    /// The operator-facing text: what is wrong, then the fix.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Organization => concat!(
                "this is an organization API key (client_id organization.<id>); it reaches the \
                 Public API only and cannot sync a vault. Fix: ",
                personal_key_fix!()
            ),
            Self::Empty => concat!("client_id is empty. Fix: ", personal_key_fix!()),
            Self::MissingId => concat!(
                "client_id is \"user.\" with no id after it; copy the whole client_id. Fix: ",
                personal_key_fix!()
            ),
            Self::UnknownPrefix => concat!(
                "client_id is not a personal API key (expected user.<uuid>). Fix: ",
                personal_key_fix!()
            ),
        }
    }
}

/// Classify a `client_id` by its prefix. Surrounding whitespace is
/// ignored, as [`super::ApiKey::new`] trims it. Prefixes are
/// case-sensitive, as Bitwarden issues them.
pub fn classify_client_id(client_id: &str) -> ApiKeyType {
    match check_client_id(client_id) {
        Ok(()) => ApiKeyType::Personal,
        Err(KeyTypeError::Organization) => ApiKeyType::Organization,
        Err(_) => ApiKeyType::Malformed,
    }
}

/// Accept only a personal key (`user.<id>`). The one shared check for
/// startup and `kharon setup`; it is exactly as strict as kharond's
/// startup refusal has always been (#401 assumption 5): the id after
/// `user.` must be non-empty, and its shape is left to the server.
pub fn check_client_id(client_id: &str) -> Result<(), KeyTypeError> {
    let id = client_id.trim();
    if id.is_empty() {
        return Err(KeyTypeError::Empty);
    }
    if id.starts_with("organization.") {
        return Err(KeyTypeError::Organization);
    }
    match id.strip_prefix("user.") {
        Some("") => Err(KeyTypeError::MissingId),
        Some(_) => Ok(()),
        None => Err(KeyTypeError::UnknownPrefix),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Placeholder ids only; none of these is a real key.
    const USER: &str = "user.00000000-0000-0000-0000-000000000000";
    const ORG: &str = "organization.00000000-0000-0000-0000-000000000000";

    #[test]
    fn req_cry_005_personal_key_passes() {
        assert_eq!(check_client_id(USER), Ok(()));
        assert_eq!(check_client_id(&format!("  {USER}\n")), Ok(()));
        assert_eq!(classify_client_id(USER), ApiKeyType::Personal);
        // Unchanged strictness: any non-empty id after `user.` passes.
        assert_eq!(check_client_id("user.x"), Ok(()));
    }

    #[test]
    fn req_cry_005_organization_key_refused_with_fix() {
        assert_eq!(check_client_id(ORG), Err(KeyTypeError::Organization));
        assert_eq!(
            check_client_id("organization."),
            Err(KeyTypeError::Organization)
        );
        assert_eq!(classify_client_id(ORG), ApiKeyType::Organization);
        let m = KeyTypeError::Organization.message();
        assert!(m.contains("organization API key"), "{m}");
        assert!(m.contains("personal API key"), "{m}");
        assert!(m.contains("dedicated kharon account"), "{m}");
        assert!(m.contains("Settings > Security > Keys"), "{m}");
        assert_eq!(KeyTypeError::Organization.to_string(), m);
    }

    #[test]
    fn req_cry_005_malformed_and_unknown_refused() {
        let cases = [
            ("", KeyTypeError::Empty),
            ("   ", KeyTypeError::Empty),
            ("user.", KeyTypeError::MissingId),
            (" user. ", KeyTypeError::MissingId),
            (
                "installation.00000000-0000-0000-0000-000000000000",
                KeyTypeError::UnknownPrefix,
            ),
            (
                "00000000-0000-0000-0000-000000000000",
                KeyTypeError::UnknownPrefix,
            ),
            (
                "User.00000000-0000-0000-0000-000000000000",
                KeyTypeError::UnknownPrefix,
            ),
            ("Organization.x", KeyTypeError::UnknownPrefix),
            ("user", KeyTypeError::UnknownPrefix),
        ];
        for (id, want) in cases {
            assert_eq!(check_client_id(id), Err(want), "{id:?}");
            assert_eq!(classify_client_id(id), ApiKeyType::Malformed, "{id:?}");
        }
    }

    #[test]
    fn req_api_006_messages_never_echo_the_client_id() {
        for id in ["organization.CANARYid", "CANARYid", "user."] {
            let e = check_client_id(id).unwrap_err();
            assert!(!e.message().contains("CANARY"), "{id}");
            // Every refusal names the fix.
            assert!(e.message().contains("personal API key"), "{id}");
        }
    }
}
