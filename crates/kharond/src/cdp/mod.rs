//! Chrome DevTools Protocol transport and the isolated-world atomic fill.
//!
//! The broker talks to the agent's browser over the CDP WebSocket
//! (REQ-ARCH-002: tunneled as configured, `ws://` only on loopback
//! unless the endpoint is remote), enables **no** CDP domains
//! (REQ-ARCH-003), and writes credentials only through the spec's
//! four-step isolated-world recipe (SPEC §6), which lives in
//! [`fill`]. Per-target isolation of state is enforced by
//! per-agent browser contexts ([`browser`], REQ-ARCH-005).

pub mod browser;
pub mod client;
pub mod discover;
pub mod endpoint;
pub mod fill;
pub(crate) mod page_js;
pub mod tls;

pub use browser::{AgentContext, Browser, OwnershipError, TargetInfo};
pub(crate) use client::MaybeTls;
pub use client::{CdpClient, CdpError, CdpSession};
pub use endpoint::{CdpEndpoint, CertSha256, EndpointError, Tunnel};
pub use fill::{FieldFill, FieldKind, FillEngine, FillOutcome, FillPlan, LiveOrigin};
