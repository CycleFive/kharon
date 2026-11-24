//! REQ-TCH-008 / 009 (#382) on a real Chromium: a login is recorded by `kharon-teach` on the
//! loopback fixture server, converted to a method, imported into a `TeachRegistry`, and then a
//! `FillEngine` fills the same pages by that method in a second headless browser.
//!
//! Skips when no Chromium binary is found; `KHARON_REQUIRE_CHROMIUM=1` turns the skip into a
//! failure. The Chromium flags are for this throwaway test browser only.

#[path = "../../kharon-teach/tests/support/mod.rs"]
mod teach_support;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use kharon_recording::{ConvertOptions, FillRole, LoginMethod, MethodStep, Rung, Shape};
use kharond::cdp::{
    AgentContext, Browser, CdpClient, CdpEndpoint, CdpSession, FieldFill, FieldKind, FillEngine,
    FillOutcome, FillPlan, LiveOrigin, MethodEnd, MethodNote, MethodSource, ScrubNote, Tunnel,
    ValuesSent,
};
use kharond::origin::{OriginConfig, OriginMatcher};
use kharond::teach::{Entry, ImportFlags, LastResult, TeachRegistry};
use serde::{Deserialize, Serialize};
use teach_support::{Fixture, Login, chromium_or_skip, record_login_keep};
use zeroize::Zeroizing;

const DOMAIN: &str = "127.0.0.1";
const NOW: &str = "2026-11-24T12:00:00Z";
const FILL_USER: &str = "kh.user";
const FILL_PASS: &str = "Kh-fill-9x";

struct Chromium {
    child: Child,
    ws: String,
    _profile: tempfile::TempDir,
}

impl Drop for Chromium {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn launch_chromium(bin: &Path) -> Chromium {
    let profile = tempfile::tempdir().unwrap();
    let mut child = Command::new(bin)
        .args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--password-store=basic",
            "--no-proxy-server",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
        ])
        .arg(format!("--user-data-dir={}", profile.path().display()))
        .arg("about:blank")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("cannot launch Chromium at {}: {e}", bin.display()));
    let port_file = profile.path().join("DevToolsActivePort");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let ws = loop {
        if let Ok(text) = std::fs::read_to_string(&port_file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                break format!("ws://127.0.0.1:{port}{path}");
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("Chromium exited {status} before DevTools opened");
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Chromium never opened DevTools"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    Chromium {
        child,
        ws,
        _profile: profile,
    }
}

// ---- typed CDP parameters and replies for the test's own page calls ----

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CreateTarget<'a> {
    url: &'static str,
    browser_context_id: &'a str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Created {
    target_id: String,
}

#[derive(Serialize)]
struct Navigate<'a> {
    url: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Evaluate<'a> {
    expression: &'a str,
    return_by_value: bool,
}

#[derive(Deserialize)]
struct Evaluated {
    result: Remote,
}

#[derive(Deserialize)]
struct Remote {
    #[serde(default)]
    value: Option<String>,
}

/// One tab in the agent's context, with a page session to read it back.
struct Tab {
    target_id: String,
    session: CdpSession,
}

impl Tab {
    async fn eval(&self, expression: &str) -> Option<String> {
        let params = serde_json::to_value(Evaluate {
            expression,
            return_by_value: true,
        })
        .unwrap();
        let reply = self
            .session
            .request("Runtime.evaluate", params)
            .await
            .ok()?;
        serde_json::from_value::<Evaluated>(reply)
            .ok()?
            .result
            .value
    }

    async fn path(&self) -> Option<String> {
        self.eval("location.pathname").await
    }

    /// Polls until the tab is on `path` and loaded.
    async fn wait_for_path(&self, path: &str) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            let done = self
                .eval("document.readyState === 'complete' ? location.pathname : ''")
                .await;
            if done.as_deref() == Some(path) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the tab never reached {path}; it is on {:?}",
                self.path().await
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn value_of(&self, css: &str) -> Option<String> {
        let sel = serde_json::to_string(css).unwrap();
        self.eval(&format!(
            "(()=>{{const e=document.querySelector({sel});return e?e.value:null}})()"
        ))
        .await
    }
}

// ---- the broker under test ----

struct Rig {
    fixture: Fixture,
    method: LoginMethod,
    registry: Arc<TeachRegistry>,
    browser: Browser,
    engine: FillEngine,
    ctx: AgentContext,
    _data_dir: tempfile::TempDir,
    _chromium: Chromium,
    _permit: tokio::sync::SemaphorePermit<'static>,
}

impl Rig {
    /// Records `login`, converts and imports it, and starts the fill browser. `None` when there
    /// is no Chromium and the run does not require one.
    async fn start(test: &str, login: Login) -> Option<Rig> {
        let bin = chromium_or_skip(test)?;
        let (rec, fixture) = record_login_keep(test, login).await?;
        let method = LoginMethod::from_recording(
            &rec,
            rec.to_json().as_bytes(),
            DOMAIN,
            ConvertOptions::default(),
        )
        .expect("the recording converts");
        let data_dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(TeachRegistry::load(data_dir.path()).unwrap());
        registry
            .import(method.clone(), ImportFlags::default(), NOW)
            .expect("the method imports");
        let permit = teach_support::browser_permit().await;
        let chromium = launch_chromium(&bin).await;
        let endpoint = CdpEndpoint::validate(&chromium.ws, Tunnel::Direct, None).unwrap();
        let browser = Browser::new(CdpClient::connect(&endpoint).await.unwrap());
        let ctx = browser.create_agent_context("teach-e2e").await.unwrap();
        let engine = FillEngine::new(browser.clone());
        Some(Rig {
            fixture,
            method,
            registry,
            browser,
            engine,
            ctx,
            _data_dir: data_dir,
            _chromium: chromium,
            _permit: permit,
        })
    }

    /// Opens `path_and_query` of the fixture in a new tab of the agent's context and waits until
    /// it is loaded.
    async fn open(&self, path_and_query: &str) -> Tab {
        let client = self.browser.client();
        let params = serde_json::to_value(CreateTarget {
            url: "about:blank",
            browser_context_id: self.ctx.browser_context_id(),
        })
        .unwrap();
        let created: Created =
            serde_json::from_value(client.request("Target.createTarget", params).await.unwrap())
                .unwrap();
        let session = client.attach(&created.target_id).await.unwrap();
        let url = self.fixture.url(path_and_query);
        let nav = serde_json::to_value(Navigate { url: url.as_str() }).unwrap();
        session.request("Page.navigate", nav).await.unwrap();
        let tab = Tab {
            target_id: created.target_id,
            session,
        };
        let path = path_and_query.split('?').next().unwrap();
        tab.wait_for_path(path).await;
        tab
    }

    fn plan(&self, tab: &Tab, kinds: &[FieldKind], submit: bool) -> FillPlan {
        let fields = kinds
            .iter()
            .map(|&kind| FieldFill {
                kind,
                selector: None,
                value: Zeroizing::new(match kind {
                    FieldKind::Username => FILL_USER.to_owned(),
                    FieldKind::Password => FILL_PASS.to_owned(),
                    FieldKind::Totp => unreachable!("no TOTP in these tests"),
                }),
            })
            .collect();
        let origin = format!("http://127.0.0.1:{}", self.fixture.port);
        FillPlan {
            target_id: tab.target_id.clone(),
            fields,
            item_matchers: vec![OriginMatcher::new(&origin, Some(1)).unwrap()],
            origin_cfg: OriginConfig { allow_http: true },
            cross_origin_iframe_hosts: Vec::new(),
            submit,
            expected_origin: None,
            live_origin: LiveOrigin::new(),
            deadline: None,
            values_sent: ValuesSent::new(),
            post_submit_scrub: false,
            post_submit_scrub_delay: Duration::from_millis(500),
            scrub: ScrubNote::new(),
            method_source: Some(self.registry.clone() as Arc<dyn MethodSource>),
            method: MethodNote::new(),
        }
    }

    /// One fill by the method, then the registry is told what happened, as the broker does.
    async fn fill(&self, tab: &Tab, kinds: &[FieldKind], submit: bool) -> FillOutcome {
        self.fill_noted(tab, kinds, submit).await.0
    }

    /// [`Rig::fill`], with how the fill ended as the method note reports it.
    async fn fill_noted(
        &self,
        tab: &Tab,
        kinds: &[FieldKind],
        submit: bool,
    ) -> (FillOutcome, MethodEnd) {
        let plan = self.plan(tab, kinds, submit);
        let outcome = self.engine.fill(&plan, &self.ctx, false).await;
        let used = plan.method.get().expect("the fill consulted the method");
        assert_eq!(used.domain, DOMAIN);
        self.registry.record_fill(used, NOW);
        (outcome, used.end)
    }

    fn entry(&self) -> Entry {
        self.registry.get(DOMAIN).expect("the method is imported")
    }

    /// Index of the `nth` password fill step of leg `leg`.
    fn password_step(&self, leg: usize) -> u32 {
        self.method
            .steps()
            .find(|(_, l, step)| {
                *l == leg
                    && matches!(
                        step,
                        MethodStep::Fill {
                            role: FillRole::Password,
                            ..
                        }
                    )
            })
            .map(|(index, _, _)| index)
            .expect("the leg has a password step")
    }

    async fn assert_checked_by_this_browser(&self, entry: &Entry) {
        let product = self.browser.product().await.expect("a browser product");
        let checked = entry.last_checked.as_ref().expect("last_checked");
        assert_eq!(checked.browser.as_deref(), Some(product.as_str()));
        assert!(entry.stale.is_none(), "{entry:?}");
        assert_eq!(entry.last_result, Some(LastResult::Succeeded), "{entry:?}");
    }
}

const BOTH: [FieldKind; 2] = [FieldKind::Username, FieldKind::Password];

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_form_login_fills_by_its_method() {
    let Some(rig) = Rig::start("req_tch_008_form_login_fills_by_its_method", Login::Form).await
    else {
        return;
    };
    let tab = rig.open("/form").await;
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    tab.wait_for_path("/home").await;
    let entry = rig.entry();
    rig.assert_checked_by_this_browser(&entry).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_script_login_fills_by_its_method() {
    let Some(rig) = Rig::start(
        "req_tch_008_script_login_fills_by_its_method",
        Login::Script,
    )
    .await
    else {
        return;
    };
    let tab = rig.open("/script").await;
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    tab.wait_for_path("/home").await;
    let entry = rig.entry();
    rig.assert_checked_by_this_browser(&entry).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_hashed_login_fills_by_its_method() {
    let Some(rig) = Rig::start(
        "req_tch_008_hashed_login_fills_by_its_method",
        Login::Hashed,
    )
    .await
    else {
        return;
    };
    assert_eq!(
        rig.method.shape,
        Shape::Transformed {
            digest: Some("sha256".into())
        }
    );
    let tab = rig.open("/hashed").await;
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    tab.wait_for_path("/home").await;
    let entry = rig.entry();
    rig.assert_checked_by_this_browser(&entry).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_two_step_login_runs_leg_by_leg() {
    let Some(rig) = Rig::start("req_tch_008_two_step_login_runs_leg_by_leg", Login::TwoStep).await
    else {
        return;
    };
    assert_eq!(rig.method.rung, Rung::AgentContinues);
    let tab = rig.open("/two-step").await;
    let out = rig.fill(&tab, &[FieldKind::Username], false).await;
    assert_eq!(
        out,
        FillOutcome::Filled {
            kinds: vec![FieldKind::Username]
        }
    );
    tab.wait_for_path("/two-step/password").await;
    let out = rig.fill(&tab, &[FieldKind::Password], false).await;
    assert_eq!(
        out,
        FillOutcome::Filled {
            kinds: vec![FieldKind::Password]
        }
    );
    tab.wait_for_path("/home").await;
    let entry = rig.entry();
    assert_eq!(entry.last_result, Some(LastResult::Succeeded), "{entry:?}");
    assert!(entry.stale.is_none(), "{entry:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_drift_variant_types_nothing_and_goes_stale() {
    let Some(rig) = Rig::start(
        "req_tch_008_drift_variant_types_nothing_and_goes_stale",
        Login::Form,
    )
    .await
    else {
        return;
    };
    let step = rig.password_step(0);
    let tab = rig.open("/form?v=drift").await;
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out, FillOutcome::MethodDrift { step }, "{out:?}");
    assert_eq!(
        tab.value_of("input[name=user]").await.as_deref(),
        Some(""),
        "the user name field was left empty"
    );
    assert_eq!(
        tab.value_of("input[name=secret]").await.as_deref(),
        Some(""),
        "the renamed password field was left empty"
    );
    assert_eq!(tab.path().await.as_deref(), Some("/form"));
    let entry = rig.entry();
    assert_eq!(
        entry.stale.as_ref().map(|s| s.step),
        Some(step),
        "{entry:?}"
    );
    assert_eq!(entry.last_result, Some(LastResult::Drift { step }));

    // A stale method is not tried again.
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out, FillOutcome::MethodStale, "{out:?}");
    assert_eq!(tab.value_of("input[name=user]").await.as_deref(), Some(""));
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_fill_on_the_home_page_is_wrong_page_and_not_stale() {
    let Some(rig) = Rig::start(
        "req_tch_008_fill_on_the_home_page_is_wrong_page_and_not_stale",
        Login::Form,
    )
    .await
    else {
        return;
    };
    let tab = rig.open("/").await;
    let before = rig.entry();
    let (out, end) = rig.fill_noted(&tab, &BOTH, false).await;
    assert_eq!(out, FillOutcome::MethodWrongPage, "{out:?}");
    assert_eq!(end, MethodEnd::WrongPage);
    assert_eq!(tab.value_of("input").await, None, "the page has no field");
    assert_eq!(
        rig.entry(),
        before,
        "a wrong page says nothing about the method"
    );
    assert!(before.stale.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_008_two_step_leg_two_renamed_is_drift_on_leg_two() {
    let Some(rig) = Rig::start(
        "req_tch_008_two_step_leg_two_renamed_is_drift_on_leg_two",
        Login::TwoStep,
    )
    .await
    else {
        return;
    };
    let step = rig.password_step(1);
    let tab = rig.open("/two-step/password?v=drift").await;
    let out = rig.fill(&tab, &[FieldKind::Password], false).await;
    assert_eq!(out, FillOutcome::MethodDrift { step }, "{out:?}");
    assert_eq!(
        tab.value_of("input[name=secret]").await.as_deref(),
        Some(""),
        "nothing was typed"
    );
    assert_eq!(tab.path().await.as_deref(), Some("/two-step/password"));
    let entry = rig.entry();
    assert_eq!(
        entry.stale.as_ref().map(|s| s.step),
        Some(step),
        "{entry:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn req_tch_009_submit_false_does_not_leave_the_password_in_the_page() {
    let Some(rig) = Rig::start(
        "req_tch_009_submit_false_does_not_leave_the_password_in_the_page",
        Login::Form,
    )
    .await
    else {
        return;
    };
    assert_eq!(rig.method.rung, Rung::Milliseconds);
    let tab = rig.open("/form").await;
    // The request says no submit; a milliseconds method submits anyway, so the typed password
    // does not sit in the page waiting for the agent.
    let out = rig.fill(&tab, &BOTH, false).await;
    assert_eq!(out.status(), "filled", "{out:?}");
    tab.wait_for_path("/home").await;
}
