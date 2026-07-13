pub mod config;
/// Shared wire contract for the managed-DB reach-plane connection preamble — the ONE
/// definition used by both the `jkbase db proxy` sidecar (encode) and the edge (parse),
/// so client and server can never drift on a security seam.
pub mod db_preamble;
pub mod egress;
pub mod l4_transit;
pub mod layers;
pub mod logs;
pub mod routing;
/// SigV4 now lives in the `jkbase-sigv4` leaf crate (so the tenant object-store
/// client can depend on just the signer, not this whole crate). Re-exported here
/// unchanged so every existing `jkbase_common::sigv4::…` call site still resolves
/// and there remains exactly ONE implementation (byte-identical, no divergence).
pub use jkbase_sigv4 as sigv4;
pub mod storage;

/// In-VM agent ⇄ host control-plane protocol version, echoed by the agent on
/// `/_jkbase/health` (the [`AGENT_PROTOCOL_HEADER`] header). The host's VM re-adoption path
/// reads it at adopt time: a survivor whose agent reports a DIFFERENT version is force-
/// recycled (hibernate → cold-boot) rather than re-adopted, so a deploy that ships a
/// breaking agent-protocol change can't silently keep talking the old wire format to a
/// re-adopted old agent. **Bump this only on an incompatible change** to the unversioned
/// `/_jkbase/*` endpoints (health / sync / resync-clock / logs) the host depends on. A
/// MISSING header (a pre-versioning agent — every survivor during THIS rollout) is treated
/// by the host as compatible, so re-adoption still works; the gate is forward-looking. See
/// `docs/vm-readoption-design.md` §9.
pub const AGENT_PROTOCOL_VERSION: u32 = 1;
/// The header the agent stamps its [`AGENT_PROTOCOL_VERSION`] into on health responses.
pub const AGENT_PROTOCOL_HEADER: &str = "X-Jkbase-Agent-Proto";
