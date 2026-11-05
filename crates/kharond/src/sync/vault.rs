//! Unlock against a sync payload and build the scoped item set
//! (REQ-CRY-005 decrypt half, REQ-CRY-007 collection filter).
//!
//! Scope rule (REQ-CRY-007): an item is visible only if its
//! `organizationId` is the configured `organization_id` **and** at
//! least one of its `collectionIds` is a configured collection. The
//! filter runs on the ciphertext payload *before* anything is
//! decrypted, so out-of-scope items never reach a key (and their org
//! keys are never unwrapped: REQ-CRY-011). Items outside scope are
//! absent from [`Vault::items`] and every lookup by id returns
//! [`SyncError::ItemNotFound`], which is what `list` and `fill` build
//! on.
//!
//! Field classes (REQ-CRY-006): name, username and URIs are decrypted
//! at sync and held as metadata; password and TOTP stay as EncString
//! text and are decrypted only by [`Session::decrypt_secret`], per
//! fill, into a zeroizing buffer.

use std::collections::{BTreeMap, BTreeSet};

use kharon_bwcrypto::{
    EncError, EncString, Kdf, OrgKeyUnwrapper, SymmetricKey, decrypt_item_field, derive_master_key,
    unwrap_cipher_key, unwrap_private_key, unwrap_user_key,
};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use super::SyncError;
use super::wire::{CIPHER_TYPE_LOGIN, Cipher, SyncResponse};

pub(crate) fn norm_id(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// The configured org and collections (`[bitwarden]` in SPEC §9).
#[derive(Debug, Clone)]
pub struct Scope {
    organization_id: String,
    collection_ids: BTreeSet<String>,
}

impl Scope {
    pub fn new(
        organization_id: &str,
        collection_ids: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, SyncError> {
        let collection_ids: BTreeSet<String> = collection_ids
            .into_iter()
            .map(|c| norm_id(c.as_ref()))
            .filter(|c| !c.is_empty())
            .collect();
        let organization_id = norm_id(organization_id);
        if organization_id.is_empty() || collection_ids.is_empty() {
            return Err(SyncError::EmptyScope);
        }
        Ok(Self {
            organization_id,
            collection_ids,
        })
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    /// The REQ-CRY-007 predicate, on ciphertext only.
    pub fn contains(&self, c: &Cipher) -> bool {
        c.organization_id
            .as_deref()
            .is_some_and(|o| norm_id(o) == self.organization_id)
            && c.collection_ids
                .iter()
                .flatten()
                .any(|id| self.collection_ids.contains(&norm_id(id)))
    }
}

/// A login URI with its Bitwarden match type (`None` = default).
#[derive(Clone, PartialEq, Eq)]
pub struct ItemUri {
    pub uri: String,
    pub match_type: Option<u8>,
}

/// One in-scope login item. Metadata is plaintext; secrets are still
/// ciphertext. `Debug` prints the id only.
pub struct Item {
    id: String,
    name: String,
    username: Option<String>,
    uris: Vec<ItemUri>,
    revision: Option<String>,
    /// Collections the cipher sits in (sync path; empty for export
    /// items, whose format has folders, not collections). Metadata
    /// (REQ-CRY-006 classes): the grant model matches
    /// collection-scoped grants against it (REQ-APR-002).
    collection_ids: Vec<String>,
    protected_cipher_key: Option<String>,
    protected_password: Option<String>,
    protected_totp: Option<String>,
}

impl std::fmt::Debug for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Item")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Item {
    /// Build an item from already-classified parts. The sync path
    /// builds items in [`decrypt_metadata`]; this constructor is for
    /// the export loader (issue #12), whose source is a decrypted
    /// plaintext export: metadata arrives as plaintext (REQ-CRY-006
    /// classes) and secrets arrive already re-wrapped as EncString
    /// text under the export session's per-unlock key, so an `Item`
    /// never holds a plaintext secret in either mode.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_parts(
        id: String,
        name: String,
        username: Option<String>,
        uris: Vec<ItemUri>,
        revision: Option<String>,
        protected_password: Option<String>,
        protected_totp: Option<String>,
    ) -> Self {
        Self {
            id,
            name,
            username,
            uris,
            revision,
            collection_ids: Vec::new(),
            protected_cipher_key: None,
            protected_password,
            protected_totp,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Plain username, for the API layer to mask (OQ-4) before it
    /// leaves the broker.
    pub fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }
    pub fn uris(&self) -> &[ItemUri] {
        &self.uris
    }
    /// Collections the item sits in (empty for export items).
    pub fn collection_ids(&self) -> &[String] {
        &self.collection_ids
    }
    /// Server `revisionDate` (RFC 3339), for grant pinning (REQ-REV-004).
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }
    /// The protected (EncString) password text, for the session that
    /// owns the key for it (the export loader's wrap key). Ciphertext,
    /// never plaintext.
    pub(crate) fn protected_password(&self) -> Option<&str> {
        self.protected_password.as_deref()
    }
    /// The protected (EncString) TOTP text; see
    /// [`Item::protected_password`].
    pub(crate) fn protected_totp(&self) -> Option<&str> {
        self.protected_totp.as_deref()
    }
    pub fn has_password(&self) -> bool {
        self.protected_password.is_some()
    }
    pub fn has_totp(&self) -> bool {
        self.protected_totp.is_some()
    }
}

/// Which secret field a fill wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretField {
    Password,
    Totp,
}

/// What a sync did, for status and audit. Contains ids only.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SyncReport {
    /// Items kept (in scope, login type, not trashed, decryptable).
    pub kept: usize,
    /// Ciphers dropped by the org/collection filter without decrypting.
    pub out_of_scope: usize,
    /// In-scope ciphers that are not logins or are in the trash.
    pub skipped: usize,
    /// In-scope ciphers whose metadata failed to decrypt. Fail closed
    /// per item: they are left out rather than failing the sync.
    pub undecryptable: Vec<String>,
    /// Configured collection ids the server did not return.
    pub missing_collections: Vec<String>,
    /// Profile orgs other than the configured one (input to
    /// REQ-CRY-008, issue 5b; nothing is decrypted for them).
    pub other_orgs: Vec<String>,
    /// The server presented a different protected org key than at
    /// unlock (possible rotation; REQ-MEM-006 decides the response).
    pub org_key_changed: bool,
}

/// The scoped item set produced by one sync.
#[derive(Debug, Default)]
pub struct Vault {
    items: BTreeMap<String, Item>,
    report: SyncReport,
}

impl Vault {
    /// Build a vault from items constructed outside the sync path
    /// (the export loader, issue #12), with the loader's own report.
    pub(crate) fn with_report(items: Vec<Item>, report: SyncReport) -> Self {
        let items = items.into_iter().map(|i| (i.id.clone(), i)).collect();
        Self { items, report }
    }

    /// Every in-scope item, ordered by id.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Look up an in-scope item. Anything else, including items the
    /// account can see in other collections or orgs, is `ItemNotFound`.
    pub fn get(&self, item_id: &str) -> Result<&Item, SyncError> {
        self.items
            .get(&norm_id(item_id))
            .ok_or(SyncError::ItemNotFound)
    }

    pub fn report(&self) -> &SyncReport {
        &self.report
    }
}

/// Keys for one unlock. Holds only the org-key unwrapper (which owns
/// the RSA private key and the cached org key); the master key,
/// stretched key and user key are dropped (zeroized) inside
/// [`Session::unlock`].
pub struct Session {
    scope: Scope,
    orgs: OrgKeyUnwrapper,
}

/// The session's keys live in `orgs`, which is `ZeroizeOnDrop`, and
/// `Scope` holds only ids — so dropping a `Session` wipes its key
/// material. That is the destruction contract the lock state machine
/// relies on (REQ-MEM-003): it cannot wipe the session in place,
/// because `RsaPrivateKey` implements `ZeroizeOnDrop` but not
/// `Zeroize`.
impl ZeroizeOnDrop for Session {}

fn parse(s: Option<&str>) -> Result<EncString, SyncError> {
    EncString::parse(s.ok_or(SyncError::Malformed("sync"))?).map_err(SyncError::Crypto)
}

impl Session {
    /// Derive the master key, unwrap user key → private key → the
    /// configured org's key. The org-key unwrapper is restricted to
    /// the profile's organizations (REQ-CRY-011) and only the
    /// configured org is unwrapped.
    pub fn unlock(
        password: &Zeroizing<String>,
        email: &str,
        kdf: &Kdf,
        sync: &SyncResponse,
        scope: Scope,
    ) -> Result<Self, SyncError> {
        if !sync.profile.email.trim().eq_ignore_ascii_case(email.trim()) {
            return Err(SyncError::AccountMismatch);
        }
        let protected_user_key = parse(sync.profile.key.as_deref())?;
        let protected_private_key = parse(sync.profile.private_key.as_deref())?;
        let user_key = {
            let master = derive_master_key(password, email, kdf)?;
            let stretched = master.stretch();
            unwrap_user_key(&protected_user_key, &stretched).map_err(SyncError::Crypto)?
        };
        let private_key =
            unwrap_private_key(&protected_private_key, &user_key).map_err(SyncError::Crypto)?;
        drop(user_key);
        let orgs = sync.profile.organizations.iter().flatten();
        let mut session = Self {
            orgs: OrgKeyUnwrapper::with_allowed_orgs(private_key, orgs.map(|o| o.id.as_str())),
            scope,
        };
        session.org_key(sync)?;
        Ok(session)
    }

    /// The configured org's key, unwrapped at most once per unlock.
    fn org_key(&mut self, sync: &SyncResponse) -> Result<&SymmetricKey, SyncError> {
        let org = sync
            .profile
            .organizations
            .iter()
            .flatten()
            .find(|o| norm_id(&o.id) == self.scope.organization_id)
            .ok_or(SyncError::OrgNotVisible)?;
        let protected = parse(org.key.as_deref())?;
        self.orgs
            .unwrap_org_key(&self.scope.organization_id, &protected)
            .map_err(SyncError::Crypto)
    }

    /// Filter and decrypt the metadata of one sync payload. Call on
    /// every sync (unlock and re-sync); the org key comes from the
    /// per-unlock cache.
    pub fn apply_sync(&mut self, sync: &SyncResponse) -> Result<Vault, SyncError> {
        if !sync
            .profile
            .organizations
            .iter()
            .flatten()
            .any(|o| norm_id(&o.id) == self.scope.organization_id)
        {
            return Err(SyncError::OrgNotVisible);
        }
        self.org_key(sync)?;
        let mut report = SyncReport {
            org_key_changed: self.orgs.ciphertext_mismatch(&self.scope.organization_id),
            other_orgs: sync
                .profile
                .organizations
                .iter()
                .flatten()
                .map(|o| norm_id(&o.id))
                .filter(|o| *o != self.scope.organization_id)
                .collect(),
            ..SyncReport::default()
        };
        let returned: BTreeSet<String> = sync
            .collections
            .iter()
            .flatten()
            .filter(|c| {
                c.organization_id
                    .as_deref()
                    .is_some_and(|o| norm_id(o) == self.scope.organization_id)
            })
            .map(|c| norm_id(&c.id))
            .collect();
        report.missing_collections = self
            .scope
            .collection_ids
            .iter()
            .filter(|c| !returned.contains(*c))
            .cloned()
            .collect();

        let org_key = self
            .orgs
            .org_key(&self.scope.organization_id)
            .expect("invariant: unwrapped above");
        let mut items = BTreeMap::new();
        for c in sync.ciphers.iter().flatten() {
            if !self.scope.contains(c) {
                report.out_of_scope += 1;
                continue;
            }
            if c.kind != CIPHER_TYPE_LOGIN || c.deleted_date.is_some() {
                report.skipped += 1;
                continue;
            }
            match decrypt_metadata(c, org_key) {
                Ok(item) => {
                    items.insert(item.id.clone(), item);
                }
                Err(_) => report.undecryptable.push(norm_id(&c.id)),
            }
        }
        report.kept = items.len();
        Ok(Vault { items, report })
    }

    /// Decrypt one secret field of an in-scope item for a fill. The
    /// item must be in `vault` (else `ItemNotFound`); a field the item
    /// lacks is `FieldMissing`.
    pub fn decrypt_secret(
        &self,
        vault: &Vault,
        item_id: &str,
        field: SecretField,
    ) -> Result<Zeroizing<Vec<u8>>, SyncError> {
        let item = vault.get(item_id)?;
        let protected = match field {
            SecretField::Password => item.protected_password.as_deref(),
            SecretField::Totp => item.protected_totp.as_deref(),
        }
        .ok_or(SyncError::FieldMissing)?;
        let org_key = self
            .orgs
            .org_key(&self.scope.organization_id)
            .ok_or(SyncError::OrgNotVisible)?;
        let cipher_key = item
            .protected_cipher_key
            .as_deref()
            .map(|k| unwrap_cipher_key(&EncString::parse(k)?, org_key))
            .transpose()
            .map_err(SyncError::Crypto)?;
        decrypt_item_field(
            &EncString::parse(protected).map_err(SyncError::Crypto)?,
            org_key,
            cipher_key.as_ref(),
        )
        .map_err(SyncError::Crypto)
    }

    /// Type-4 decrypts performed this unlock (REQ-CRY-011 bound).
    pub fn org_key_decrypts(&self) -> usize {
        self.orgs.decrypt_count()
    }
}

fn decrypt_metadata(c: &Cipher, org_key: &SymmetricKey) -> Result<Item, EncError> {
    let cipher_key = c
        .key
        .as_deref()
        .map(|k| unwrap_cipher_key(&EncString::parse(k)?, org_key))
        .transpose()?;
    let text = |s: &str| -> Result<String, EncError> {
        let pt = decrypt_item_field(&EncString::parse(s)?, org_key, cipher_key.as_ref())?;
        String::from_utf8(pt.to_vec()).map_err(|_| EncError::DecryptionFailed)
    };
    let name = text(c.name.as_deref().ok_or(EncError::DecryptionFailed)?)?;
    let login = c.login.as_ref();
    let username = login
        .and_then(|l| l.username.as_deref())
        .map(text)
        .transpose()?;
    let mut uris = Vec::new();
    for u in login.and_then(|l| l.uris.as_ref()).into_iter().flatten() {
        if let Some(uri) = u.uri.as_deref() {
            uris.push(ItemUri {
                uri: text(uri)?,
                match_type: u.match_type,
            });
        }
    }
    let nonempty = |s: Option<&String>| s.filter(|s| !s.is_empty()).cloned();
    Ok(Item {
        id: norm_id(&c.id),
        name,
        username,
        uris,
        revision: c.revision_date.clone(),
        collection_ids: c
            .collection_ids
            .iter()
            .flatten()
            .map(|id| norm_id(id))
            .collect(),
        protected_cipher_key: nonempty(c.key.as_ref()),
        protected_password: nonempty(login.and_then(|l| l.password.as_ref())),
        protected_totp: nonempty(login.and_then(|l| l.totp.as_ref())),
    })
}
