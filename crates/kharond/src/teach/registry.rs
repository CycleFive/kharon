//! The per-broker registry of imported login methods (#382).
//!
//! One file, `<data_dir>/teach/registry.json`, holds one entry per site key.
//! A method, the file and every refusal here hold no value and no page text;
//! refusals are fixed enum variants, never strings built from file content.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use kharon_recording::{
    ListenerWorld, LoginMethod, METHOD_FORMAT_VERSION, MethodStep, Provenance, Rung, RungCeiling,
    Shape, SubmitVia,
};
use serde::{Deserialize, Serialize};

use crate::cdp::{MethodEnd, MethodLookup, MethodResult, MethodSource, MethodUse};

const REGISTRY_FORMAT_VERSION: u32 = 1;
const MAX_SELECTOR_BYTES: usize = 1024;

/// The registry key for a host: its registrable domain, lowercased and without a trailing dot.
/// An IP literal, `localhost`, a single-label host or a host the list gives no answer for is its
/// lowercased self. Same answers as `kharon_teach::site::registrable_domain`.
pub fn site_key(host: &str) -> String {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);
    if bare.parse::<IpAddr>().is_ok() {
        return host;
    }
    crate::origin::registrable_domain(&host).unwrap_or(host)
}

/// The site key of the host in `url`; `None` when it does not parse or has no host.
fn url_site_key(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url).ok()?;
    parsed.host_str().map(site_key)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Checked {
    /// RFC 3339 UTC.
    pub at: String,
    pub browser: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum LastResult {
    Succeeded,
    Unconfirmed,
    Failed,
    Drift { step: u32 },
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stale {
    pub step: u32,
    pub at: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub method: LoginMethod,
    pub rung: Rung,
    pub shape: Shape,
    pub overrides: BTreeMap<u32, Vec<String>>,
    pub imported_at: String,
    pub last_checked: Option<Checked>,
    pub last_result: Option<LastResult>,
    pub stale: Option<Stale>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ImportFlags {
    pub replace: bool,
    pub accept_main_world: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportRefusal {
    Invalid,
    OffDomain,
    MainWorld,
    RungAboveCeiling,
    Exists,
    Store,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditRefusal {
    NotFound,
    BadStep,
    BadSelector,
    Store,
}

/// Why a `*_with` operation did not commit: the registry refused it (the hook was
/// not called), or the hook did (nothing was changed). `Refused(Store)` after the
/// hook returned `Ok` means the file could not be put in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WithHook<R, E> {
    Refused(R),
    Hook(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recorded {
    pub newly_stale: bool,
    pub wrote: bool,
}

#[derive(Deserialize)]
struct VersionProbe {
    format_version: u32,
}

#[derive(Deserialize)]
struct FileIn {
    entries: BTreeMap<String, Entry>,
}

#[derive(Serialize)]
struct FileOut<'a> {
    format_version: u32,
    entries: &'a BTreeMap<String, Entry>,
}

type Entries = BTreeMap<String, Entry>;

#[derive(Debug)]
pub struct TeachRegistry {
    path: PathBuf,
    entries: Mutex<Entries>,
}

/// True when `origin` is exactly what the browser reports as `location.origin` for
/// that address, so the method's origin check can ever match a live page.
fn origin_is_canonical(origin: &str) -> bool {
    url::Url::parse(origin).is_ok_and(|u| {
        u.origin().ascii_serialization() == origin
            // A trailing dot names the same host as the site key but is a different origin.
            && !u.host_str().is_some_and(|h| h.ends_with('.'))
    })
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

impl TeachRegistry {
    /// Load `<data_dir>/teach/registry.json`. A missing file is an empty registry.
    pub fn load(data_dir: &Path) -> io::Result<Self> {
        let path = data_dir.join("teach").join("registry.json");
        let entries = match std::fs::metadata(&path) {
            Ok(_) => {
                check_mode(&path)?;
                let text = std::fs::read_to_string(&path)?;
                let probe: VersionProbe =
                    serde_json::from_str(&text).map_err(|_| invalid("registry file unreadable"))?;
                if probe.format_version != REGISTRY_FORMAT_VERSION {
                    return Err(invalid("registry format_version unsupported"));
                }
                let file: FileIn =
                    serde_json::from_str(&text).map_err(|_| invalid("registry file unreadable"))?;
                let sound = file.entries.iter().all(|(key, e)| {
                    e.method.format_version == METHOD_FORMAT_VERSION
                        && e.method.validate().is_ok()
                        && origin_is_canonical(&e.method.site.origin)
                        && *key == e.method.site.domain
                        && url_site_key(&e.method.site.origin).as_deref() == Some(key.as_str())
                });
                if !sound {
                    return Err(invalid("registry holds an unusable method"));
                }
                file.entries
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Entries::new(),
            Err(e) => return Err(e),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    fn guard(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Stage `next` on disk, call `hook`, then rename the staged
    /// file into place and swap memory. A hook error removes the staged file and changes
    /// nothing. Runs under the registry lock the caller holds in `guard`.
    fn commit_with<E>(
        &self,
        guard: &mut Entries,
        next: Entries,
        hook: impl FnOnce() -> Result<(), E>,
    ) -> Result<(), WithHook<(), E>> {
        let text = serde_json::to_string_pretty(&FileOut {
            format_version: REGISTRY_FORMAT_VERSION,
            entries: &next,
        })
        .map_err(|_| WithHook::Refused(()))?;
        let tmp = stage_private(&self.path, text.as_bytes()).map_err(|_| WithHook::Refused(()))?;
        if let Err(e) = hook() {
            let _ = std::fs::remove_file(&tmp);
            return Err(WithHook::Hook(e));
        }
        if std::fs::rename(&tmp, &self.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(WithHook::Refused(()));
        }
        *guard = next;
        Ok(())
    }

    pub fn import(
        &self,
        method: LoginMethod,
        flags: ImportFlags,
        now: &str,
    ) -> Result<Entry, ImportRefusal> {
        self.import_with(method, flags, now, |_| Ok::<(), Infallible>(()))
            .map_err(|e| match e {
                WithHook::Refused(r) => r,
                WithHook::Hook(never) => match never {},
            })
    }

    /// As [`Self::import`], with `before_commit` called with the new entry once every
    /// check has passed and the file is staged, before it is put in place. The hook
    /// runs under the registry lock: it must not call back into the registry, and it
    /// is where the caller appends its audit entry. A hook error changes nothing.
    pub fn import_with<E>(
        &self,
        method: LoginMethod,
        flags: ImportFlags,
        now: &str,
        before_commit: impl FnOnce(&Entry) -> Result<(), E>,
    ) -> Result<Entry, WithHook<ImportRefusal, E>> {
        use WithHook::Refused;
        let refuse = |r| Err(Refused(r));
        if method.format_version != METHOD_FORMAT_VERSION
            || method.validate().is_err()
            || !origin_is_canonical(&method.site.origin)
        {
            return refuse(ImportRefusal::Invalid);
        }
        if url_site_key(&method.site.origin).as_deref() != Some(method.site.domain.as_str()) {
            return refuse(ImportRefusal::OffDomain);
        }
        if let Provenance::Recording {
            listener_world,
            rung_ceiling,
            ..
        } = &method.provenance
        {
            if *listener_world == ListenerWorld::Main && !flags.accept_main_world {
                return refuse(ImportRefusal::MainWorld);
            }
            let allowed = match rung_ceiling {
                RungCeiling::Milliseconds => true,
                RungCeiling::AgentContinues => method.rung == Rung::AgentContinues,
                RungCeiling::NeedsPerson => false,
            };
            if !allowed {
                return refuse(ImportRefusal::RungAboveCeiling);
            }
        }
        let mut guard = self.guard();
        if guard.contains_key(&method.site.domain) && !flags.replace {
            return refuse(ImportRefusal::Exists);
        }
        let entry = Entry {
            rung: method.rung,
            shape: method.shape.clone(),
            method,
            overrides: BTreeMap::new(),
            imported_at: now.to_owned(),
            last_checked: None,
            last_result: None,
            stale: None,
        };
        let mut next = guard.clone();
        next.insert(entry.method.site.domain.clone(), entry.clone());
        self.commit_with(&mut guard, next, || before_commit(&entry))
            .map_err(|e| match e {
                WithHook::Refused(()) => Refused(ImportRefusal::Store),
                WithHook::Hook(e) => WithHook::Hook(e),
            })?;
        Ok(entry)
    }

    /// Every entry, sorted by domain.
    pub fn list(&self) -> Vec<(String, Entry)> {
        self.guard()
            .iter()
            .map(|(d, e)| (d.clone(), e.clone()))
            .collect()
    }

    pub fn get(&self, domain: &str) -> Option<Entry> {
        self.guard().get(domain).cloned()
    }

    /// Put `selector` first in the step's override list (a repeat moves to the front).
    pub fn set_override(
        &self,
        domain: &str,
        step: u32,
        selector: &str,
    ) -> Result<Entry, EditRefusal> {
        Self::unhook(self.set_override_with(domain, step, selector, |_| Ok::<(), Infallible>(())))
    }

    /// As [`Self::set_override`], with `before_commit` called with the edited entry
    /// before it is put in place. The hook runs under the registry lock and must not
    /// call back into the registry.
    pub fn set_override_with<E>(
        &self,
        domain: &str,
        step: u32,
        selector: &str,
        before_commit: impl FnOnce(&Entry) -> Result<(), E>,
    ) -> Result<Entry, WithHook<EditRefusal, E>> {
        let mut guard = self.guard();
        let entry = guard
            .get(domain)
            .ok_or(WithHook::Refused(EditRefusal::NotFound))?;
        let editable = entry.method.steps().any(|(i, _, s)| {
            i == step
                && matches!(
                    s,
                    MethodStep::Fill { .. }
                        | MethodStep::Submit {
                            via: SubmitVia::Click { .. }
                        }
                )
        });
        if !editable {
            return Err(WithHook::Refused(EditRefusal::BadStep));
        }
        if selector.trim().is_empty() || selector.len() > MAX_SELECTOR_BYTES {
            return Err(WithHook::Refused(EditRefusal::BadSelector));
        }
        self.edit_with(
            &mut guard,
            domain,
            |e| {
                let list = e.overrides.entry(step).or_default();
                list.retain(|s| s != selector);
                list.insert(0, selector.to_owned());
            },
            before_commit,
        )
    }

    pub fn clear_stale(&self, domain: &str) -> Result<Entry, EditRefusal> {
        Self::unhook(self.clear_stale_with(domain, |_| Ok::<(), Infallible>(())))
    }

    /// As [`Self::clear_stale`], with a hook under the registry lock (see
    /// [`Self::set_override_with`]).
    pub fn clear_stale_with<E>(
        &self,
        domain: &str,
        before_commit: impl FnOnce(&Entry) -> Result<(), E>,
    ) -> Result<Entry, WithHook<EditRefusal, E>> {
        let mut guard = self.guard();
        self.edit_with(&mut guard, domain, |e| e.stale = None, before_commit)
    }

    pub fn remove(&self, domain: &str) -> Result<Entry, EditRefusal> {
        Self::unhook(self.remove_with(domain, |_| Ok::<(), Infallible>(())))
    }

    /// As [`Self::remove`], with a hook called with the entry about to be removed,
    /// under the registry lock (see [`Self::set_override_with`]).
    pub fn remove_with<E>(
        &self,
        domain: &str,
        before_commit: impl FnOnce(&Entry) -> Result<(), E>,
    ) -> Result<Entry, WithHook<EditRefusal, E>> {
        let mut guard = self.guard();
        let gone = guard
            .get(domain)
            .cloned()
            .ok_or(WithHook::Refused(EditRefusal::NotFound))?;
        let mut next = guard.clone();
        next.remove(domain);
        self.commit_with(&mut guard, next, || before_commit(&gone))
            .map_err(Self::store_or_hook)?;
        Ok(gone)
    }

    fn store_or_hook<E>(e: WithHook<(), E>) -> WithHook<EditRefusal, E> {
        match e {
            WithHook::Refused(()) => WithHook::Refused(EditRefusal::Store),
            WithHook::Hook(e) => WithHook::Hook(e),
        }
    }

    fn unhook(r: Result<Entry, WithHook<EditRefusal, Infallible>>) -> Result<Entry, EditRefusal> {
        r.map_err(|e| match e {
            WithHook::Refused(r) => r,
            WithHook::Hook(never) => match never {},
        })
    }

    fn edit(
        &self,
        guard: &mut Entries,
        domain: &str,
        f: impl FnOnce(&mut Entry),
    ) -> Result<Entry, EditRefusal> {
        Self::unhook(self.edit_with(guard, domain, f, |_| Ok::<(), Infallible>(())))
    }

    fn edit_with<E>(
        &self,
        guard: &mut Entries,
        domain: &str,
        f: impl FnOnce(&mut Entry),
        before_commit: impl FnOnce(&Entry) -> Result<(), E>,
    ) -> Result<Entry, WithHook<EditRefusal, E>> {
        let mut next = guard.clone();
        let entry = next
            .get_mut(domain)
            .ok_or(WithHook::Refused(EditRefusal::NotFound))?;
        f(entry);
        let out = entry.clone();
        self.commit_with(guard, next, || before_commit(&out))
            .map_err(Self::store_or_hook)?;
        Ok(out)
    }

    /// Note the outcome of a fill that used a method. Outcomes that say nothing about the
    /// method (wrong page, stale, a role not requested, anything else) write nothing.
    pub fn record_fill(&self, used: &MethodUse, now: &str) -> Recorded {
        let none = Recorded {
            newly_stale: false,
            wrote: false,
        };
        let result = match used.end {
            MethodEnd::Stale
            | MethodEnd::WrongPage
            | MethodEnd::FieldNotRequested
            | MethodEnd::Other => return none,
            MethodEnd::Drift { step } => LastResult::Drift { step },
            MethodEnd::NotReady { .. } => LastResult::NotReady,
            MethodEnd::Filled(MethodResult::Succeeded) => LastResult::Succeeded,
            MethodEnd::Filled(MethodResult::Unconfirmed) => LastResult::Unconfirmed,
            MethodEnd::Filled(MethodResult::Failed) => LastResult::Failed,
        };
        let mut guard = self.guard();
        let Some(existing) = guard.get(&used.domain) else {
            return none;
        };
        let newly_stale = matches!(used.end, MethodEnd::Drift { .. }) && existing.stale.is_none();
        let outcome = self.edit(&mut guard, &used.domain, |e| {
            e.last_checked = Some(Checked {
                at: now.to_owned(),
                browser: used.browser_product.clone(),
            });
            if let MethodEnd::Drift { step } = used.end {
                e.stale = Some(Stale {
                    step,
                    at: now.to_owned(),
                });
            }
            e.last_result = Some(result);
        });
        match outcome {
            Ok(_) => Recorded {
                newly_stale,
                wrote: true,
            },
            Err(_) => none,
        }
    }

    /// The rung of the method held for the site of `origin`, for the approval prompt.
    pub fn rung_for_origin(&self, origin: &str) -> Option<Rung> {
        let key = url_site_key(origin)?;
        let origin = url::Url::parse(origin).ok()?.origin().ascii_serialization();
        self.guard()
            .get(&key)
            .filter(|e| e.method.site.origin == origin)
            .map(|e| e.rung)
    }
}

impl MethodSource for TeachRegistry {
    fn lookup(&self, live_url: &str) -> Option<MethodLookup> {
        let key = url_site_key(live_url)?;
        let guard = self.guard();
        let entry = guard.get(&key)?;
        Some(MethodLookup {
            domain: key,
            method: Arc::new(entry.method.clone()),
            overrides: entry.overrides.clone(),
            stale: entry.stale.is_some(),
        })
    }
}

fn check_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "teach registry is accessible to group or others",
        ));
    }
    Ok(())
}

/// Write `bytes` to a temp file next to `path` as mode 0600 (directory 0700) and return
/// its path; the caller renames it over `path` or removes it.
fn stage_private(path: &Path, bytes: &[u8]) -> io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(parent) = path.parent() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        b.mode(0o700);
        b.create(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let staged = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
    })();
    match staged {
        Ok(()) => Ok(tmp),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cdp::{MethodEnd, MethodResult, MethodSource, MethodUse};
    use kharon_recording::{
        Expected, FillRole, Leg, ListenerWorld, LoginMethod, MethodStep, Provenance, Rung,
        RungCeiling, Shape, Site, SubmitVia, SuccessCheck,
    };
    use std::os::unix::fs::PermissionsExt;

    const NOW: &str = "2026-11-24T10:00:00Z";
    const LATER: &str = "2026-11-24T11:00:00Z";

    fn expect(input_type: &str) -> Expected {
        Expected {
            tag: "input".into(),
            input_type: Some(input_type.into()),
            id: None,
            name: None,
            autocomplete: None,
        }
    }

    fn method(domain: &str, origin: &str) -> LoginMethod {
        LoginMethod {
            format_version: 1,
            site: Site {
                domain: domain.into(),
                origin: origin.into(),
                path: "/login".into(),
            },
            shape: Shape::FormPost,
            rung: Rung::Milliseconds,
            legs: vec![Leg {
                steps: vec![
                    MethodStep::Navigate {
                        path: "/login".into(),
                    },
                    MethodStep::Fill {
                        role: FillRole::Username,
                        selectors: vec!["#user".into()],
                        expect: expect("text"),
                    },
                    MethodStep::Fill {
                        role: FillRole::Password,
                        selectors: vec!["#pw".into()],
                        expect: expect("password"),
                    },
                    MethodStep::Submit {
                        via: SubmitVia::Click {
                            selectors: vec!["#go".into()],
                            expect: expect("submit"),
                        },
                    },
                ],
            }],
            success: SuccessCheck::None {},
            provenance: Provenance::HandWritten {
                author: "test".into(),
            },
        }
    }

    fn recorded(world: ListenerWorld, ceiling: RungCeiling, rung: Rung) -> LoginMethod {
        let mut m = method("example.com", "https://login.example.com");
        m.rung = rung;
        m.provenance = Provenance::Recording {
            sha256: "ab".repeat(32),
            tool_version: "0.0.0".into(),
            browser_product: "Chrome/1".into(),
            listener_world: world,
            rung_ceiling: ceiling,
        };
        m
    }

    fn used(domain: &str, end: MethodEnd) -> MethodUse {
        MethodUse {
            domain: domain.into(),
            rung: Rung::Milliseconds,
            end,
            selectors_ignored: false,
            browser_product: Some("Chrome/142".into()),
        }
    }

    fn fresh() -> (tempfile::TempDir, TeachRegistry) {
        let dir = tempfile::tempdir().unwrap();
        let reg = TeachRegistry::load(dir.path()).unwrap();
        (dir, reg)
    }

    fn file(dir: &tempfile::TempDir) -> std::path::PathBuf {
        dir.path().join("teach").join("registry.json")
    }

    #[test]
    fn site_key_reduces_hosts() {
        assert_eq!(site_key("login.example.co.uk"), "example.co.uk");
        assert_eq!(site_key("Login.Example.CO.uk."), "example.co.uk");
        assert_eq!(site_key("127.0.0.1"), "127.0.0.1");
        assert_eq!(site_key("[::1]"), "[::1]");
        assert_eq!(site_key("::1"), "::1");
        assert_eq!(site_key("Login.Example.CO.UK."), "example.co.uk");
        assert_eq!(site_key("localhost"), "localhost");
        assert_eq!(site_key("LOCALHOST"), "localhost");
        assert_eq!(site_key("intranet"), "intranet");
    }

    #[test]
    fn req_tch_010_import_refuses_off_domain() {
        let (_d, reg) = fresh();
        let m = method("example.com", "https://login.other.org");
        assert_eq!(
            reg.import(m, ImportFlags::default(), NOW).unwrap_err(),
            ImportRefusal::OffDomain
        );
        let m = method("example.com", "https://login.example.com");
        assert!(reg.import(m, ImportFlags::default(), NOW).is_ok());
    }

    #[test]
    fn req_tch_010_import_refuses_a_non_canonical_origin() {
        for bad in [
            "https://Login.Example.com",
            "https://login.example.com:443",
            "https://login.example.com.",
            "https://login.example.com:",
        ] {
            let (_d, reg) = fresh();
            assert_eq!(
                reg.import(method("example.com", bad), ImportFlags::default(), NOW)
                    .unwrap_err(),
                ImportRefusal::Invalid,
                "{bad}"
            );
        }
        for good in ["https://login.example.com", "http://127.0.0.1:4455"] {
            let (_d, reg) = fresh();
            let domain = if good.contains("127") {
                "127.0.0.1"
            } else {
                "example.com"
            };
            assert!(
                reg.import(method(domain, good), ImportFlags::default(), NOW)
                    .is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn req_tch_010_load_refuses_a_non_canonical_origin() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        rewrite_entry(&dir, |e| {
            e.get_mut("example.com").unwrap().method.site.origin =
                "https://login.example.com:443".into();
        });
        assert_eq!(
            TeachRegistry::load(dir.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn req_tch_011_rung_for_origin_names_a_rung_only_for_the_methods_own_origin() {
        let (_d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        assert!(reg.rung_for_origin("https://login.example.com").is_some());
        assert!(reg.rung_for_origin("https://app.example.com").is_none());
        assert!(reg.rung_for_origin("http://login.example.com").is_none());
    }

    #[test]
    fn req_tch_010_import_refuses_main_world_without_the_flag() {
        let (_d, reg) = fresh();
        let m = recorded(
            ListenerWorld::Main,
            RungCeiling::Milliseconds,
            Rung::Milliseconds,
        );
        assert_eq!(
            reg.import(m.clone(), ImportFlags::default(), NOW)
                .unwrap_err(),
            ImportRefusal::MainWorld
        );
        let flags = ImportFlags {
            accept_main_world: true,
            ..ImportFlags::default()
        };
        assert!(reg.import(m, flags, NOW).is_ok());
    }

    #[test]
    fn req_tch_010_import_refuses_rung_above_ceiling() {
        let (_d, reg) = fresh();
        let flags = ImportFlags {
            replace: true,
            ..ImportFlags::default()
        };
        let try_it = |ceiling, rung| {
            reg.import(recorded(ListenerWorld::Isolated, ceiling, rung), flags, NOW)
                .map(|_| ())
        };
        assert!(try_it(RungCeiling::Milliseconds, Rung::Milliseconds).is_ok());
        assert!(try_it(RungCeiling::Milliseconds, Rung::AgentContinues).is_ok());
        assert_eq!(
            try_it(RungCeiling::AgentContinues, Rung::Milliseconds),
            Err(ImportRefusal::RungAboveCeiling)
        );
        assert!(try_it(RungCeiling::AgentContinues, Rung::AgentContinues).is_ok());
        assert_eq!(
            try_it(RungCeiling::NeedsPerson, Rung::Milliseconds),
            Err(ImportRefusal::RungAboveCeiling)
        );
        assert_eq!(
            try_it(RungCeiling::NeedsPerson, Rung::AgentContinues),
            Err(ImportRefusal::RungAboveCeiling)
        );
    }

    #[test]
    fn req_tch_010_hand_written_skips_main_world_and_ceiling_checks() {
        let (_d, reg) = fresh();
        let mut m = method("example.com", "https://login.example.com");
        m.rung = Rung::Milliseconds;
        assert!(reg.import(m, ImportFlags::default(), NOW).is_ok());
    }

    #[test]
    fn req_tch_010_import_refuses_a_second_method_without_replace() {
        let (_d, reg) = fresh();
        let m = method("example.com", "https://login.example.com");
        reg.import(m.clone(), ImportFlags::default(), NOW).unwrap();
        reg.set_override("example.com", 1, "#other").unwrap();
        reg.record_fill(&used("example.com", MethodEnd::Drift { step: 2 }), NOW);
        assert_eq!(
            reg.import(m.clone(), ImportFlags::default(), LATER)
                .unwrap_err(),
            ImportRefusal::Exists
        );
        let flags = ImportFlags {
            replace: true,
            ..ImportFlags::default()
        };
        let e = reg.import(m, flags, LATER).unwrap();
        assert!(e.overrides.is_empty());
        assert!(e.stale.is_none());
        assert!(e.last_checked.is_none() && e.last_result.is_none());
        assert_eq!(e.imported_at, LATER);
        assert_eq!(reg.get("example.com").unwrap(), e);
    }

    #[test]
    fn req_tch_010_import_refuses_an_invalid_method() {
        let (_d, reg) = fresh();
        let mut m = method("example.com", "https://login.example.com");
        m.legs.clear();
        assert_eq!(
            reg.import(m, ImportFlags::default(), NOW).unwrap_err(),
            ImportRefusal::Invalid
        );
    }

    #[test]
    fn req_tch_011_entry_records_rung_shape_overrides_and_last_fill() {
        let (dir, reg) = fresh();
        let mut m = method("example.com", "https://login.example.com");
        m.rung = Rung::AgentContinues;
        reg.import(m.clone(), ImportFlags::default(), NOW).unwrap();
        reg.set_override("example.com", 2, "#pw2").unwrap();
        let r = reg.record_fill(
            &used("example.com", MethodEnd::Filled(MethodResult::Succeeded)),
            LATER,
        );
        assert!(r.wrote && !r.newly_stale);

        let back = TeachRegistry::load(dir.path()).unwrap();
        let e = back.get("example.com").unwrap();
        assert_eq!(e.method, m);
        assert_eq!(e.rung, Rung::AgentContinues);
        assert_eq!(e.shape, Shape::FormPost);
        assert_eq!(e.overrides.get(&2), Some(&vec!["#pw2".to_string()]));
        assert_eq!(e.imported_at, NOW);
        assert_eq!(
            e.last_checked,
            Some(Checked {
                at: LATER.into(),
                browser: Some("Chrome/142".into())
            })
        );
        assert_eq!(e.last_result, Some(LastResult::Succeeded));
        assert!(e.stale.is_none());
        assert_eq!(
            back.rung_for_origin("https://login.example.com"),
            Some(Rung::AgentContinues)
        );
        assert_eq!(back.rung_for_origin("https://nope.org"), None);
    }

    #[test]
    fn req_tch_008_drift_marks_stale_once_and_wrong_page_marks_nothing() {
        let (dir, reg) = fresh();
        let m = method("example.com", "https://login.example.com");
        reg.import(m.clone(), ImportFlags::default(), NOW).unwrap();
        let before = std::fs::read(file(&dir)).unwrap();

        for end in [
            MethodEnd::WrongPage,
            MethodEnd::Stale,
            MethodEnd::FieldNotRequested,
            MethodEnd::Other,
        ] {
            let r = reg.record_fill(&used("example.com", end), LATER);
            assert!(!r.wrote && !r.newly_stale);
        }
        assert_eq!(std::fs::read(file(&dir)).unwrap(), before);

        let r = reg.record_fill(&used("example.com", MethodEnd::Drift { step: 2 }), LATER);
        assert!(r.newly_stale && r.wrote);
        let e = reg.get("example.com").unwrap();
        assert_eq!(
            e.stale,
            Some(Stale {
                step: 2,
                at: LATER.into()
            })
        );
        assert_eq!(e.last_result, Some(LastResult::Drift { step: 2 }));
        assert!(reg.lookup("https://login.example.com/login").unwrap().stale);

        let r = reg.record_fill(&used("example.com", MethodEnd::Drift { step: 1 }), LATER);
        assert!(!r.newly_stale && r.wrote);

        let e = reg.clear_stale("example.com").unwrap();
        assert!(e.stale.is_none());
        assert!(!reg.lookup("https://example.com/").unwrap().stale);

        reg.record_fill(&used("example.com", MethodEnd::Drift { step: 2 }), LATER);
        let flags = ImportFlags {
            replace: true,
            ..ImportFlags::default()
        };
        assert!(reg.import(m, flags, LATER).unwrap().stale.is_none());
    }

    #[test]
    fn not_ready_records_the_check_and_unknown_domains_write_nothing() {
        let (_d, reg) = fresh();
        let m = method("example.com", "https://login.example.com");
        reg.import(m, ImportFlags::default(), NOW).unwrap();
        let r = reg.record_fill(&used("example.com", MethodEnd::NotReady { step: 1 }), LATER);
        assert!(r.wrote && !r.newly_stale);
        let e = reg.get("example.com").unwrap();
        assert_eq!(e.last_result, Some(LastResult::NotReady));
        assert!(e.stale.is_none());
        let r = reg.record_fill(&used("nowhere.org", MethodEnd::Drift { step: 1 }), LATER);
        assert!(!r.wrote);
    }

    #[test]
    fn registry_file_is_0600_in_a_0700_directory() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let f = std::fs::metadata(file(&dir)).unwrap().permissions().mode() & 0o777;
        let d = std::fs::metadata(dir.path().join("teach"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(f, 0o600);
        assert_eq!(d, 0o700);
        assert!(!dir.path().join("teach").join("registry.json.tmp").exists());
    }

    #[test]
    fn load_refuses_a_group_readable_file() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        std::fs::set_permissions(file(&dir), std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = TeachRegistry::load(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn load_refuses_an_unknown_format_version() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let text = std::fs::read_to_string(file(&dir)).unwrap().replacen(
            "\"format_version\": 1",
            "\"format_version\": 2",
            1,
        );
        std::fs::write(file(&dir), text).unwrap();
        let err = TeachRegistry::load(dir.path()).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn load_refuses_garbage_and_an_invalid_stored_method() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let good = std::fs::read_to_string(file(&dir)).unwrap();
        std::fs::write(file(&dir), "not json").unwrap();
        assert_eq!(
            TeachRegistry::load(dir.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        let mut parsed: FileIn = serde_json::from_str(&good).unwrap();
        parsed
            .entries
            .get_mut("example.com")
            .unwrap()
            .method
            .legs
            .clear();
        let out = FileOut {
            format_version: 1,
            entries: &parsed.entries,
        };
        std::fs::write(file(&dir), serde_json::to_string(&out).unwrap()).unwrap();
        assert_eq!(
            TeachRegistry::load(dir.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    fn rewrite_entry(dir: &tempfile::TempDir, f: impl FnOnce(&mut Entries)) {
        let good = std::fs::read_to_string(file(dir)).unwrap();
        let mut parsed: FileIn = serde_json::from_str(&good).unwrap();
        f(&mut parsed.entries);
        let out = FileOut {
            format_version: 1,
            entries: &parsed.entries,
        };
        std::fs::write(file(dir), serde_json::to_string(&out).unwrap()).unwrap();
    }

    #[test]
    fn load_refuses_an_entry_under_the_wrong_key() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        rewrite_entry(&dir, |e| {
            let entry = e.remove("example.com").unwrap();
            e.insert("other.org".into(), entry);
        });
        assert_eq!(
            TeachRegistry::load(dir.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn load_refuses_an_origin_off_the_entry_domain() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        rewrite_entry(&dir, |e| {
            e.get_mut("example.com").unwrap().method.site.origin = "https://login.other.org".into();
        });
        assert_eq!(
            TeachRegistry::load(dir.path()).unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn missing_file_is_an_empty_registry() {
        let (dir, reg) = fresh();
        assert!(reg.list().is_empty());
        assert!(!file(&dir).exists());
    }

    #[test]
    fn override_rules() {
        let (_d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        // 0 is the navigate step, 99 is out of range.
        assert_eq!(
            reg.set_override("example.com", 0, "#a").unwrap_err(),
            EditRefusal::BadStep
        );
        assert_eq!(
            reg.set_override("example.com", 99, "#a").unwrap_err(),
            EditRefusal::BadStep
        );
        assert_eq!(
            reg.set_override("example.com", 1, "").unwrap_err(),
            EditRefusal::BadSelector
        );
        assert_eq!(
            reg.set_override("example.com", 1, " \t ").unwrap_err(),
            EditRefusal::BadSelector
        );
        assert_eq!(
            reg.set_override("example.com", 1, &"a".repeat(1025))
                .unwrap_err(),
            EditRefusal::BadSelector
        );
        assert!(
            reg.set_override("example.com", 1, &"a".repeat(1024))
                .is_ok()
        );
        assert_eq!(
            reg.set_override("nope.org", 1, "#a").unwrap_err(),
            EditRefusal::NotFound
        );

        reg.set_override("example.com", 3, "#first").unwrap();
        reg.set_override("example.com", 3, "#second").unwrap();
        let e = reg.set_override("example.com", 3, "#first").unwrap();
        assert_eq!(
            e.overrides[&3],
            vec!["#first".to_string(), "#second".to_string()]
        );
    }

    #[test]
    fn remove_deletes_the_entry() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        assert!(reg.remove("example.com").is_ok());
        assert_eq!(
            reg.remove("example.com").unwrap_err(),
            EditRefusal::NotFound
        );
        assert_eq!(
            reg.clear_stale("example.com").unwrap_err(),
            EditRefusal::NotFound
        );
        assert!(TeachRegistry::load(dir.path()).unwrap().list().is_empty());
    }

    #[test]
    fn lookup_by_live_url() {
        let (_d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        reg.import(
            method("127.0.0.1", "http://127.0.0.1:4455"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let hit = reg.lookup("https://app.example.com/x?y").unwrap();
        assert_eq!(hit.domain, "example.com");
        assert!(!hit.stale);
        assert_eq!(
            reg.lookup("http://127.0.0.1:4455/form").unwrap().domain,
            "127.0.0.1"
        );
        assert!(reg.lookup("about:blank").is_none());
        assert!(reg.lookup("not a url").is_none());
        assert!(reg.lookup("https://other.org/").is_none());
        let names: Vec<_> = reg.list().into_iter().map(|(d, _)| d).collect();
        assert_eq!(names, ["127.0.0.1", "example.com"]);
    }

    #[test]
    fn registry_file_holds_no_dropped_field() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let text = std::fs::read_to_string(file(&dir)).unwrap();
        for word in ["value_len", "placeholder", "query_keys"] {
            assert!(!text.contains(word), "{word}");
        }
    }

    fn dir_listing(dir: &tempfile::TempDir) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir.path().join("teach"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn drift(step: u32) -> MethodUse {
        MethodUse {
            domain: "example.com".into(),
            rung: Rung::Milliseconds,
            end: MethodEnd::Drift { step },
            selectors_ignored: false,
            browser_product: None,
        }
    }

    #[test]
    fn import_refuses_another_format_version() {
        let (_d, reg) = fresh();
        let mut m = method("example.com", "https://login.example.com");
        m.format_version = METHOD_FORMAT_VERSION + 1;
        assert_eq!(
            reg.import(m, ImportFlags::default(), NOW).unwrap_err(),
            ImportRefusal::Invalid
        );
        assert!(reg.list().is_empty());
    }

    #[test]
    fn load_refuses_a_stored_method_with_another_format_version() {
        let (d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let text = std::fs::read_to_string(file(&d)).unwrap();
        let edited = text.replacen(
            &format!("\"format_version\": {METHOD_FORMAT_VERSION},\n        \"site\""),
            &format!(
                "\"format_version\": {},\n        \"site\"",
                METHOD_FORMAT_VERSION + 1
            ),
            1,
        );
        assert_ne!(edited, text, "the method's version field was found");
        std::fs::write(file(&d), edited).unwrap();
        assert_eq!(
            TeachRegistry::load(d.path()).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn the_hook_is_not_called_on_a_refusal() {
        let (_d, reg) = fresh();
        let m = method("example.com", "https://login.example.com");
        reg.import(m.clone(), ImportFlags::default(), NOW).unwrap();
        let mut called = 0;
        let mut hook = |_: &Entry| {
            called += 1;
            Ok::<(), ()>(())
        };
        assert_eq!(
            reg.import_with(m, ImportFlags::default(), NOW, &mut hook)
                .unwrap_err(),
            WithHook::Refused(ImportRefusal::Exists)
        );
        assert_eq!(
            reg.set_override_with("example.com", 0, "#x", &mut hook)
                .unwrap_err(),
            WithHook::Refused(EditRefusal::BadStep)
        );
        assert_eq!(
            reg.remove_with("nowhere.org", &mut hook).unwrap_err(),
            WithHook::Refused(EditRefusal::NotFound)
        );
        assert_eq!(called, 0);
    }

    #[test]
    fn a_hook_error_changes_nothing_in_memory_file_or_directory() {
        let (d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let bytes = std::fs::read(file(&d)).unwrap();
        let listing = dir_listing(&d);
        let memory = reg.list();
        let no = |_: &Entry| Err::<(), &str>("no");

        let again = method("example.com", "https://login.example.com");
        let flags = ImportFlags {
            replace: true,
            ..ImportFlags::default()
        };
        assert_eq!(
            reg.import_with(again, flags, LATER, no).unwrap_err(),
            WithHook::Hook("no")
        );
        assert_eq!(
            reg.set_override_with("example.com", 1, "#x", no)
                .unwrap_err(),
            WithHook::Hook("no")
        );
        assert_eq!(
            reg.clear_stale_with("example.com", no).unwrap_err(),
            WithHook::Hook("no")
        );
        assert_eq!(
            reg.remove_with("example.com", no).unwrap_err(),
            WithHook::Hook("no")
        );
        assert_eq!(reg.list(), memory);
        assert_eq!(std::fs::read(file(&d)).unwrap(), bytes);
        assert_eq!(dir_listing(&d), listing);
    }

    #[test]
    fn a_rename_failure_after_the_hook_changes_nothing_and_is_store() {
        let (d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let memory = reg.list();
        let target = file(&d);
        // The hook puts a non-empty directory where the file goes, so the rename fails.
        let sabotage = |_: &Entry| {
            std::fs::remove_file(&target).unwrap();
            std::fs::create_dir(&target).unwrap();
            std::fs::write(target.join("x"), b"x").unwrap();
            Ok::<(), ()>(())
        };
        assert_eq!(
            reg.set_override_with("example.com", 1, "#x", sabotage)
                .unwrap_err(),
            WithHook::Refused(EditRefusal::Store)
        );
        assert_eq!(reg.list(), memory, "memory unchanged");
        assert_eq!(
            dir_listing(&d),
            vec!["registry.json".to_owned()],
            "no temp file"
        );
    }

    #[test]
    fn a_fill_recorded_between_two_owner_edits_survives_both() {
        let (_d, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        reg.set_override_with("example.com", 1, "#a", |_| Ok::<(), ()>(()))
            .unwrap();
        assert!(reg.record_fill(&drift(2), LATER).newly_stale);
        // an edit that fails its hook, then one that succeeds: neither drops the mark
        let _ = reg.set_override_with("example.com", 1, "#b", |_| Err::<(), ()>(()));
        reg.set_override_with("example.com", 2, "#c", |_| Ok::<(), ()>(()))
            .unwrap();
        let entry = reg.get("example.com").unwrap();
        assert_eq!(entry.stale.as_ref().unwrap().step, 2);
        assert_eq!(entry.last_result, Some(LastResult::Drift { step: 2 }));
        assert_eq!(entry.overrides.len(), 2);
    }

    #[test]
    fn a_failed_persist_leaves_memory_as_it_was() {
        let (dir, reg) = fresh();
        reg.import(
            method("example.com", "https://login.example.com"),
            ImportFlags::default(),
            NOW,
        )
        .unwrap();
        let teach = dir.path().join("teach");
        std::fs::set_permissions(&teach, std::fs::Permissions::from_mode(0o500)).unwrap();
        let can_write = std::fs::File::create(teach.join("probe")).is_ok();
        if !can_write {
            assert_eq!(
                reg.set_override("example.com", 1, "#x").unwrap_err(),
                EditRefusal::Store
            );
            assert!(reg.get("example.com").unwrap().overrides.is_empty());
        }
        std::fs::set_permissions(&teach, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
