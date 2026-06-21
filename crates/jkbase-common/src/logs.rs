//! Shared log types used across the agent (producer), control plane (store), and
//! CLI (consumer). Keeping these in one place guarantees the wire format that the
//! host shipper polls from the guest agent matches what the store persists and
//! what the CLI renders.

use serde::{Deserialize, Serialize};

/// A single captured line of output from a project's server container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    /// Name of the server/container that produced the line.
    pub server: String,
    /// `"stdout"` or `"stderr"`.
    pub stream: String,
    /// The log line text (no trailing newline).
    pub line: String,
    /// Unix timestamp (seconds) when the line was captured in the guest.
    pub timestamp: u64,
    /// Monotonic per-boot sequence number assigned by the agent. Used by the
    /// host shipper as an incremental cursor so it only fetches new lines.
    /// Older serialized lines (pre-seq) default to 0.
    #[serde(default)]
    pub seq: u64,
}

/// One function PUBLIC-egress decision, recorded by the agent's egress gate (host code the
/// guest cannot skip) and shipped as a `LogLine` with the reserved `stream == "egress"`.
/// **Metadata only** — there is deliberately NO field that can hold a path, query, header,
/// or body, so "the manifest never contains payload" is enforced by type, not discipline
/// (P0-OBS-METADATA-ONLY). The agent originates TLS (it's in the tenant VM) so it *could*
/// see plaintext; the schema forecloses recording any of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressEvent {
    /// The function that made the request.
    pub function: String,
    /// Guest-requested authority host (pre-DNS), e.g. `"api.stripe.com"`.
    pub dest_host: String,
    pub dest_port: u16,
    /// Pinned/observed IP, if known (the vetted dial target, or the first resolved address
    /// on a pre-connect deny). `None` when resolution failed.
    #[serde(default)]
    pub dest_ip: Option<String>,
    pub verdict: Verdict,
    pub method: String,
    /// How many times this exact `(function, dest_host, port, verdict)` coalesced into this
    /// row (P0-DOS-EGRESS-EVENT-BUFFER: a tight loop is one row + count, not N DoS rows).
    #[serde(default)]
    pub count: u64,
    /// ADVISORY best-effort byte counters (P0-OBS-BYTES-ADVISORY) — never billing (billing
    /// reads the kernel TAP counters). 0 until refined.
    #[serde(default)]
    pub bytes_out: u64,
    #[serde(default)]
    pub bytes_in: u64,
    /// Upstream response status, once known. `None` for a deny / pre-response.
    #[serde(default)]
    pub status: Option<u16>,
}

/// The egress decision recorded for a PUBLIC-zone outbound. (Zone-1 own-stuff is
/// informational; Zone-2 platform/internal denials are an attack signal.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Allowed public egress (default policy, or an allowlist hit).
    Allow,
    /// Denied: host not on the function's enforced allowlist.
    DenyAllowlist,
    /// Denied: the function is sandboxed (`egress = false`).
    DenySandbox,
    /// Denied: a platform/internal/IPv6 destination — the hard fence (attack signal).
    DenyPlatform,
    /// The outbound could not be evaluated/completed (DNS failure, rate/connection limit).
    Error,
}

/// The reserved `LogLine.stream` value for egress events. Only the host egress mediator
/// writes it; the guest output drains hardcode `stdout`/`stderr`, so a guest cannot forge
/// or bury egress rows (P0-OBS-STREAM-RESERVED).
pub const EGRESS_STREAM: &str = "egress";

/// Response body returned by the agent's `GET /_jkbase/logs` endpoint.
///
/// `boot_id` identifies the agent process incarnation. It is stable across
/// snapshot restore (the in-memory buffer survives) but changes on a cold boot,
/// which is how the host shipper detects that the `seq` counter has reset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogsResponse {
    pub boot_id: String,
    pub lines: Vec<LogLine>,
}
