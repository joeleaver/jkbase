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
