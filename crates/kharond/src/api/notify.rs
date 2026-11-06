//! Publishing approval prompts to the owner's ntfy channel — the
//! send half of REQ-APR-004 (issue #128; the receiving half — the
//! one-time tokens and their redeem routes — is [`super::approval`]
//! and #21/#136).
//!
//! When a grant request is created, the broker hands its
//! [`ApprovalPrompt`] plus the live approve/deny token paths to an
//! [`ApprovalNotifier`]. The production implementation,
//! [`NtfyApprovalNotifier`], publishes one ntfy message (JSON publish
//! API) carrying the agent, the item, the **observed** origin
//! (REQ-APR-007: the prompt struct already holds no other origin) and
//! two `http` actions: Approve and Deny, both `POST`, pointing at the
//! owner listener's `/owner/approve/<token>` /
//! `/owner/deny/<token>` routes joined onto the configured redeem
//! base (`http://` + `[owner_ui] listen`, the address the deployment
//! guide tells the owner to forward or open locally).
//!
//! Publishing is best-effort and detached: the grant path never waits
//! on ntfy and never fails because ntfy is down — the request stays
//! pending for the CLI / web UI channels, and the 120 s token TTL
//! (REQ-APR-004) bounds the prompt's useful life either way. With no
//! `[approval].ntfy` configured the daemon installs no notifier and
//! nothing is published (the CLI path is unchanged, per #128's
//! acceptance). The notifier is likewise absent when `[owner_ui]` is
//! unconfigured: the redeem routes live on that listener, so action
//! URLs would have nowhere to land.
//!
//! `kharon panic` (REQ-REV-002) also notifies: a plain message with
//! no actions, so the owner learns the daemon locked even when they
//! did not run the command themselves.

use std::io;
use std::path::Path;
use std::sync::Arc;

use url::Url;

use super::grant::ApprovalPrompt;
use crate::audit::checkpoint::{NtfyTransport, validate_ntfy_topic};

/// The broker's hook for telling the owner about approval-channel
/// events. Implementations must be cheap to call: the broker invokes
/// them synchronously on the grant path, so a network-backed
/// implementation detaches the actual publish (see
/// [`NtfyApprovalNotifier`]).
pub trait ApprovalNotifier: Send + Sync {
    /// A new pending grant request exists. `approve_path` and
    /// `deny_path` are the live one-time token paths
    /// (`/owner/approve/<token>`, `/owner/deny/<token>`); joining
    /// them onto an absolute base is the implementation's business.
    fn notify_grant_request(&self, prompt: &ApprovalPrompt, approve_path: &str, deny_path: &str);

    /// `kharon panic` revoked every grant and locked the daemon
    /// (REQ-REV-002). Default: no notification.
    fn notify_panic(&self) {}
}

/// The detached publish state, cloned into the publish thread.
#[derive(Clone)]
struct NtfyPublisher {
    transport: Arc<NtfyTransport>,
    /// JSON-publish path: the ntfy server root under the base
    /// URL's path prefix (`/` or `/prefix/`).
    path: String,
    topic: String,
    /// Absolute base the token paths join onto
    /// (`http://127.0.0.1:8788` for `[owner_ui] listen`).
    redeem_base: String,
}

impl NtfyPublisher {
    /// The JSON-publish POST for one prompt. Synchronous; the
    /// `notify_*` wrappers detach it.
    fn publish_grant_request(
        &self,
        prompt: &ApprovalPrompt,
        approve_path: &str,
        deny_path: &str,
    ) -> io::Result<()> {
        let payload = serde_json::json!({
            "topic": self.topic,
            "title": "kharon: approval requested",
            "message": format!(
                "agent {} wants to {} item {} at {} (request {}). \
                 Approve and deny are single-use and expire in 120 s.",
                prompt.agent_id,
                prompt.action.as_str(),
                prompt.item_id,
                prompt.origin,
                prompt.request_id,
            ),
            "actions": [
                {
                    "action": "http",
                    "label": "Approve",
                    "url": format!("{}{approve_path}", self.redeem_base),
                    "method": "POST",
                    "clear": true,
                },
                {
                    "action": "http",
                    "label": "Deny",
                    "url": format!("{}{deny_path}", self.redeem_base),
                    "method": "POST",
                    "clear": true,
                },
            ],
        });
        self.transport.post(&self.path, None, &payload.to_string())
    }

    /// The JSON-publish POST for a panic lock: no actions, nothing
    /// to redeem.
    fn publish_panic(&self) -> io::Result<()> {
        let payload = serde_json::json!({
            "topic": self.topic,
            "title": "kharon: panic lock",
            "message": "kharon panic: every grant was revoked and the daemon is locked.",
        });
        self.transport.post(&self.path, None, &payload.to_string())
    }
}

/// Publishes approval prompts (and panic notices) to the configured
/// `[approval].ntfy` topic, with action URLs on the owner listener.
pub struct NtfyApprovalNotifier {
    publisher: NtfyPublisher,
}

impl NtfyApprovalNotifier {
    /// Build a notifier publishing to the ntfy server at `base`
    /// (topic `topic`, bearer token read eagerly from `token_file`
    /// when configured — fail-closed like the checkpoint sink, so a
    /// bad token file refuses startup rather than silently never
    /// prompting). `redeem_base` is the absolute origin the one-time
    /// token paths join onto, e.g. `http://127.0.0.1:8788`.
    pub fn new(
        base: &Url,
        topic: &str,
        token_file: Option<&Path>,
        redeem_base: String,
    ) -> io::Result<Self> {
        validate_ntfy_topic(topic)?;
        let transport = NtfyTransport::new(base, token_file)?;
        let prefix = transport.prefix();
        let path = if prefix.is_empty() {
            "/".to_owned()
        } else {
            format!("{prefix}/")
        };
        Ok(Self {
            publisher: NtfyPublisher {
                transport: Arc::new(transport),
                path,
                topic: topic.to_owned(),
                redeem_base: redeem_base.trim_end_matches('/').to_owned(),
            },
        })
    }

    /// Publish one prompt synchronously (the detached wrapper is
    /// [`ApprovalNotifier::notify_grant_request`]; this is the seam
    /// tests drive).
    pub fn publish_grant_request(
        &self,
        prompt: &ApprovalPrompt,
        approve_path: &str,
        deny_path: &str,
    ) -> io::Result<()> {
        self.publisher
            .publish_grant_request(prompt, approve_path, deny_path)
    }

    /// Publish one panic notice synchronously (the detached wrapper
    /// is [`ApprovalNotifier::notify_panic`]).
    pub fn publish_panic(&self) -> io::Result<()> {
        self.publisher.publish_panic()
    }
}

impl ApprovalNotifier for NtfyApprovalNotifier {
    fn notify_grant_request(&self, prompt: &ApprovalPrompt, approve_path: &str, deny_path: &str) {
        // Detached: a slow or dead ntfy must not stall the grant
        // path (the request is already durable and pending; the
        // publish is a courtesy copy to one channel). A failed
        // publish is dropped — the CLI and web UI channels still
        // show the request.
        let publisher = self.publisher.clone();
        let prompt = prompt.clone();
        let approve_path = approve_path.to_owned();
        let deny_path = deny_path.to_owned();
        let _ = std::thread::spawn(move || {
            let _ = publisher.publish_grant_request(&prompt, &approve_path, &deny_path);
        });
    }

    fn notify_panic(&self) {
        let publisher = self.publisher.clone();
        let _ = std::thread::spawn(move || {
            let _ = publisher.publish_panic();
        });
    }
}
