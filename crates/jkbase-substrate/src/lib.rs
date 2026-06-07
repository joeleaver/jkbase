//! `jkbase-substrate` — the vendor-neutral storage seam for the **cluster's own
//! state** (NOT the tenant-facing S3 product; that must never back the control
//! plane — see the decision record). Four narrow role traits abstract the four
//! things the platform persists, so a backend can be swapped per role without
//! privileging any vendor:
//!
//! - [`ControlStore`] (R1) — authoritative, transactional metadata KV (redb
//!   today; a replicated KV like etcd later).
//! - [`BlobStore`] (R4) — large immutable objects: VM snapshots + memory files,
//!   content images, build artifacts, base/run layers (local FS today; S3 is
//!   exactly ONE backend later, never privileged, never on the data-disk path).
//! - [`Lease`] (R2) — exclusive ownership with a monotonic [`FenceToken`], so a
//!   superseded (zombie) writer can be fenced out.
//! - [`DataDiskProvider`] (R3) — per-project read-write-once block devices with
//!   real exclusivity (loop device today; networked block later).
//!
//! Every backend honestly advertises its [`Caps`]; the `build_substrate` factory
//! (separate card) negotiates those caps against the deployment topology and
//! refuses a dishonest config (e.g. a multi-node cluster on node-local-only
//! exclusivity). **This crate is traits + types only — no implementations.**

use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::time::Duration;

// ---- Backend implementations (per-role cards) -------------------------------
pub mod flock_lease;
pub mod localfs_blob;
pub mod localloop_disk;
pub mod redb_control;
pub use flock_lease::FlockLease;
pub use localfs_blob::LocalFsBlobStore;
pub use localloop_disk::LocalLoop;
pub use redb_control::RedbControlStore;

// Cluster-grade R4 over any S3-compatible endpoint (optional, no cloud dep by default).
#[cfg(feature = "s3")]
pub mod s3_blob;
#[cfg(feature = "s3")]
pub use s3_blob::{S3CompatBlobStore, S3Config};

// Cluster-grade replicated R1 + cluster-exclusive R2 over etcd (optional, no etcd
// dep by default).
#[cfg(feature = "etcd")]
pub mod etcd_control;
#[cfg(feature = "etcd")]
pub use etcd_control::EtcdControlStore;
#[cfg(feature = "etcd")]
pub mod etcd_lease;
#[cfg(feature = "etcd")]
pub use etcd_lease::EtcdLease;

// Cluster-grade R3 (storage-enforced RWO) over Ceph RBD (optional; shells out to
// the rbd/ceph CLIs, so no extra dependency — the feature only gates the module).
#[cfg(feature = "ceph")]
pub mod ceph_rbd;
#[cfg(feature = "ceph")]
pub use ceph_rbd::CephRbd;

// ---- Config-driven factory + capability negotiation -------------------------
pub mod factory;
pub use factory::{
    BlobBackend, ControlBackend, DataDiskBackend, LeaseBackend, Substrate, SubstrateConfig,
    assert_not_self_referential, build_substrate,
};

bitflags::bitflags! {
    /// Capabilities a backend honestly advertises about itself. The factory
    /// negotiates these against the deployment topology — a >1-node cluster MUST
    /// have cluster-safe exclusivity + replicated metadata — and refuses a
    /// dishonest config at boot rather than corrupting data later.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Caps: u32 {
        /// ControlStore: ACID transactions, but only on a single node (e.g. redb).
        const SINGLE_NODE_TXN         = 1 << 0;
        /// ControlStore: transactions that survive node loss (replicated / raft).
        const REPLICATED_TXN          = 1 << 1;
        /// Lease: tokens are monotonic per issuing source.
        const MONOTONIC_FENCE         = 1 << 2;
        /// Lease: exclusion is enforced only within a single host.
        const NODE_LOCAL_EXCLUSIVE    = 1 << 3;
        /// Lease: exclusion is enforced across the whole cluster.
        const CLUSTER_EXCLUSIVE_FENCE = 1 << 4;
        /// DataDiskProvider: read-write-once enforced within a single host.
        const NODE_LOCAL_RWO          = 1 << 5;
        /// DataDiskProvider: read-write-once enforced by the storage layer itself
        /// (safe across hosts / a split brain).
        const STORAGE_ENFORCED_RWO    = 1 << 6;
        /// BlobStore: `put_if_absent` is atomic (safe content-addressed dedup).
        const ATOMIC_PUT_IF_ABSENT    = 1 << 7;
    }
}

/// Errors surfaced across the substrate seam. Backends map their vendor errors
/// onto these so callers handle storage failures uniformly.
#[derive(Debug, thiserror::Error)]
pub enum SubstrateError {
    /// Two [`FenceToken`]s from different sources (or scopes) were compared. A
    /// monotonic counter only orders tokens from the same issuing authority, so
    /// callers must treat this as "cannot safely preempt" and refuse — never as
    /// "false".
    #[error("fence tokens are not comparable (different source or scope)")]
    IncomparableToken,
    /// A write/attach/renew was rejected because a newer token has superseded the
    /// caller's — it has been fenced out.
    #[error("fenced out: a newer token holds '{scope}'")]
    Fenced { scope: String },
    /// The lease for `scope` is currently held by a live holder (not expired).
    #[error("lease for '{scope}' is held by another holder")]
    LeaseHeld { scope: String },
    /// A read-write-once attach could not prove exclusivity (e.g. the prior
    /// writer's process is still alive), so the disk was NOT attached. The caller
    /// must refuse the warm path and cold-boot instead.
    #[error("cannot prove read-write-once exclusivity for '{scope}'")]
    RwoUnsafe { scope: String },
    /// A transaction's compare-guards did not hold; nothing was written.
    #[error("transaction conflict: a compare-guard did not hold")]
    TxnConflict,
    /// The requested key / object / disk does not exist.
    #[error("not found: {0}")]
    NotFound(String),
    /// The backend cannot satisfy a capability the caller required.
    #[error("backend lacks required capability: {0:?}")]
    MissingCapability(Caps),
    /// Catch-all for a backend-specific failure (network, vendor SDK, etc.).
    #[error("backend error: {0}")]
    Backend(String),
    /// An underlying I/O error (file streaming, loop binding, …).
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience alias for substrate fallible results.
pub type Result<T> = std::result::Result<T, SubstrateError>;

/// A monotonic fencing token proving the current right to mutate `scope`. A holder
/// presents it on every write/attach so the storage layer can reject a superseded
/// (zombie) writer — the property that makes sudden-death failover safe. The
/// counter is monotonic only **within** an issuing `source_id`, so tokens from
/// different sources are deliberately not comparable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceToken {
    /// What is being fenced (e.g. a project id / data-disk id).
    pub scope: String,
    /// Monotonically increasing within (`source_id`, `scope`).
    pub epoch: u64,
    /// Who currently holds it (e.g. the host / node id).
    pub holder: String,
    /// The authority that minted the token (lease backend identity). Tokens from
    /// different sources cannot be ordered against one another.
    pub source_id: String,
}

impl FenceToken {
    /// True iff `self` strictly supersedes `other` (same source + scope, higher
    /// epoch). Comparing tokens across sources or scopes is meaningless and yields
    /// [`SubstrateError::IncomparableToken`]; callers must treat that as "cannot
    /// safely preempt" and refuse, not as a silent `false`.
    pub fn supersedes(&self, other: &FenceToken) -> Result<bool> {
        if self.source_id != other.source_id || self.scope != other.scope {
            return Err(SubstrateError::IncomparableToken);
        }
        Ok(self.epoch > other.epoch)
    }
}

/// Common to every backend: a stable name (for logs + negotiation diagnostics) and
/// an honest self-report of [`Caps`]. The factory reads [`Backend::caps`] to
/// validate a config against the topology before trusting the backend with data.
pub trait Backend: Send + Sync {
    /// Stable identifier of this backend impl, e.g. `"redb"`, `"localfs"`, `"s3"`.
    fn backend_name(&self) -> &str;
    /// The capabilities this backend actually provides.
    fn caps(&self) -> Caps;
}

/// A compare-guard that must hold for a [`ControlStore::transact`] to commit.
#[derive(Debug, Clone)]
pub enum Guard {
    /// `key` must currently be absent.
    Absent { table: String, key: Bytes },
    /// `key` must currently be present (any value).
    Present { table: String, key: Bytes },
    /// `key` must currently equal `value` (compare-and-set).
    Equals { table: String, key: Bytes, value: Bytes },
}

/// A mutation applied atomically by [`ControlStore::transact`].
#[derive(Debug, Clone)]
pub enum Write {
    Put { table: String, key: Bytes, value: Bytes },
    Delete { table: String, key: Bytes },
}

/// R1 — the authoritative, transactional metadata store (projects, deployments,
/// domains, lease-of-record, …). The transaction shape — a set of compare-guards
/// plus a set of writes, applied all-or-nothing — maps cleanly onto both a local
/// ACID store (redb write txn) and a replicated KV (etcd `Txn(compare, success)`),
/// so the control plane is written once against this seam.
#[async_trait]
pub trait ControlStore: Backend {
    /// Point read of `key` in `table`.
    async fn get(&self, table: &str, key: &[u8]) -> Result<Option<Bytes>>;
    /// Ordered scan of every `(key, value)` in `table` whose key starts with
    /// `prefix` (empty prefix = full table).
    async fn scan_prefix(&self, table: &str, prefix: &[u8]) -> Result<Vec<(Bytes, Bytes)>>;
    /// Apply every write in `writes` atomically **iff** every guard in `guards`
    /// holds; otherwise commit nothing and return [`SubstrateError::TxnConflict`].
    async fn transact(&self, guards: Vec<Guard>, writes: Vec<Write>) -> Result<()>;
}

/// Metadata for a stored blob, returned by [`BlobStore::head`] without fetching it.
#[derive(Debug, Clone)]
pub struct BlobMeta {
    pub key: String,
    pub size: u64,
    /// Backend-defined content tag (content hash / object ETag) when available.
    pub etag: Option<String>,
}

/// R4 — large immutable objects: VM snapshots + memory files, content images,
/// build artifacts, base/run layers. **Always streams via local file paths and
/// never buffers a whole blob in memory** (snapshots + images are multi-GiB; this
/// preserves the metering/OOM fixes). S3 is exactly ONE backend here — never
/// privileged, never on the data-disk path, never resolving to jkbase's own
/// tenant object store (the factory rejects that circularity).
#[async_trait]
pub trait BlobStore: Backend {
    /// Stream the local file `src` to `key`, overwriting any existing object.
    async fn put_file(&self, key: &str, src: &Path) -> Result<()>;
    /// Atomically create `key` from `src` only if it does not already exist.
    /// Returns `true` if written, `false` if `key` was already present — the
    /// primitive for content-addressed dedup.
    async fn put_if_absent_file(&self, key: &str, src: &Path) -> Result<bool>;
    /// Stream `key` down to the local file `dst`.
    async fn get_to_file(&self, key: &str, dst: &Path) -> Result<()>;
    /// Object metadata without fetching the body; `None` if absent.
    async fn head(&self, key: &str) -> Result<Option<BlobMeta>>;
    /// Keys under `prefix`.
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

/// R2 — exclusive ownership of a `scope` with a monotonic [`FenceToken`]. The token
/// is what makes sudden-death failover safe: a relocated writer acquires a higher
/// epoch, and the old (possibly still-alive) writer is fenced out of R1/R3 the
/// moment it presents its now-stale token.
#[async_trait]
pub trait Lease: Backend {
    /// Acquire the lease for `scope` on behalf of `holder` for `ttl`, or steal it
    /// if the prior holder's lease has expired. Returns a fresh token whose epoch
    /// strictly exceeds any previously issued for `scope`. Returns
    /// [`SubstrateError::LeaseHeld`] if a live holder still owns it.
    async fn acquire(&self, scope: &str, holder: &str, ttl: Duration) -> Result<FenceToken>;
    /// Extend a held lease, returning the (same-or-newer) token. Returns
    /// [`SubstrateError::Fenced`] if a newer token has superseded `token`.
    async fn renew(&self, token: &FenceToken, ttl: Duration) -> Result<FenceToken>;
    /// Release a held lease so another holder can acquire without waiting out TTL.
    async fn release(&self, token: &FenceToken) -> Result<()>;
    /// The currently valid token for `scope`, if any holder owns it.
    async fn current(&self, scope: &str) -> Result<Option<FenceToken>>;
}

/// A host block device backing a project's data disk, handed to Firecracker as a
/// drive. `path` is a host device/file (e.g. `/dev/loopN`, a networked block
/// device, or an image file) depending on the backend.
#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub path: PathBuf,
}

/// R3 — per-project persistent data disks with **read-write-once** semantics: at
/// most one host may hold a disk RW at a time. `attach_rwo` takes the caller's
/// [`FenceToken`] so the provider can preempt a prior writer and confirm the old
/// owner is gone before exposing the device — the property that makes cross-host
/// restore safe (see the restore-path-fence card). This is the highest-risk role:
/// a false "exclusive" attach is silent multi-writer corruption.
#[async_trait]
pub trait DataDiskProvider: Backend {
    /// Ensure a disk of at least `size_bytes` exists for `id` (idempotent; formats
    /// on first creation, never reformats existing data).
    async fn ensure(&self, id: &str, size_bytes: u64) -> Result<()>;
    /// Attach `id` read-write-once to this host, fencing any prior writer using
    /// `token`. Returns [`SubstrateError::Fenced`] if `token` is stale, or
    /// [`SubstrateError::RwoUnsafe`] if exclusivity cannot be proven (caller must
    /// then cold-boot rather than risk a second writer).
    async fn attach_rwo(&self, id: &str, token: &FenceToken) -> Result<BlockDevice>;
    /// Detach `id` from this host (release the exclusive hold).
    async fn detach(&self, id: &str) -> Result<()>;
    /// Destroy `id` and its data permanently.
    async fn destroy(&self, id: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(scope: &str, epoch: u64, source: &str) -> FenceToken {
        FenceToken {
            scope: scope.into(),
            epoch,
            holder: "h".into(),
            source_id: source.into(),
        }
    }

    #[test]
    fn supersedes_orders_same_source_and_scope_by_epoch() {
        assert!(tok("p", 5, "s").supersedes(&tok("p", 4, "s")).unwrap());
        assert!(!tok("p", 4, "s").supersedes(&tok("p", 5, "s")).unwrap());
        assert!(!tok("p", 5, "s").supersedes(&tok("p", 5, "s")).unwrap()); // not strict
    }

    #[test]
    fn cross_source_or_scope_is_incomparable() {
        assert!(matches!(
            tok("p", 9, "a").supersedes(&tok("p", 1, "b")),
            Err(SubstrateError::IncomparableToken)
        ));
        assert!(matches!(
            tok("p", 9, "s").supersedes(&tok("q", 1, "s")),
            Err(SubstrateError::IncomparableToken)
        ));
    }

    #[test]
    fn caps_negotiation_flags_compose() {
        let cluster = Caps::REPLICATED_TXN | Caps::CLUSTER_EXCLUSIVE_FENCE | Caps::STORAGE_ENFORCED_RWO;
        assert!(cluster.contains(Caps::CLUSTER_EXCLUSIVE_FENCE));
        assert!(!cluster.contains(Caps::NODE_LOCAL_RWO));
    }
}
